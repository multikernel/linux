// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE Multikernel Transport
 *
 * Zero-copy filesystem sharing between host and spawn kernels using
 * vsock for FUSE protocol and DAX for direct file data access.
 *
 * Architecture:
 *   Spawn Kernel                    Host Kernel
 *   +-------------+                +----------------+
 *   | mkfuse      | ---vsock-----> | mkfsd          |
 *   | (this file) |                | (userspace)    |
 *   +-------------+                +----------------+
 *
 * The vsock transport (mk_transport.c) handles IPI-based messaging.
 * mkfsd allocates shared memory for DAX and sends the address over vsock.
 *
 * Copyright (C) 2025 Multikernel Technologies, Inc.
 */

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/dax.h>
#include <linux/memremap.h>
#include <linux/io.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/vm_sockets.h>
#include <linux/sockptr.h>
#include <net/sock.h>
#include <net/af_vsock.h>
#include <linux/multikernel.h>
#include <linux/hash.h>

#include "fuse_i.h"
#include "fuse_dev_i.h"

#define MK_FUSE_MAGIC		0x4D4B4653	/* "MKFS" */
#define MK_FUSE_VERSION		1
#define MK_FUSE_DEFAULT_PORT	6789

/* Default DAX window size: 256MB */
#define MK_FUSE_DAX_DEFAULT_SIZE	(256UL << 20)

/*
 * Handshake message from mkfsd
 */
struct mk_fuse_init_msg {
	__u32 magic;
	__u32 version;
	__u64 dax_window_phys;
	__u64 dax_window_size;
	__u32 flags;
	__u32 reserved[3];
};

#define MK_FUSE_INIT_F_DAX	0x01

/*
 * Per-connection state
 */
struct mk_fuse_conn {
	struct list_head list;
	char tag[32];
	int host_cid;

	/* Vsock connection */
	struct socket *sock;
	struct task_struct *recv_thread;
	bool connected;

	/* DAX support */
	struct dax_device *dax_dev;
	void *dax_window;
	phys_addr_t dax_window_phys;
	size_t dax_window_size;
	struct dev_pagemap *pgmap;

	/* FUSE integration */
	struct fuse_dev *fud;
	struct fuse_conn *fc;
	struct fuse_mount *fm;

	/* Synchronization */
	spinlock_t lock;
	wait_queue_head_t waitq;

	/* Request tracking */
	u64 reqctr;

	/* Send queue - requests are queued here and sent from workqueue */
	struct list_head send_queue;
	spinlock_t send_lock;
	struct work_struct send_work;
};

/* Global state */
static LIST_HEAD(mk_fuse_conns);
static DEFINE_MUTEX(mk_fuse_lock);
static struct workqueue_struct *mk_fuse_wq;

/*
 * DAX operations
 */
static long mk_fuse_dax_direct_access(struct dax_device *dax_dev,
				      pgoff_t pgoff, long nr_pages,
				      enum dax_access_mode mode,
				      void **kaddr, unsigned long *pfn)
{
	struct mk_fuse_conn *mkc = dax_get_private(dax_dev);
	phys_addr_t offset = pgoff << PAGE_SHIFT;
	long avail_pages;

	if (!mkc || !mkc->dax_window)
		return -ENODEV;

	if (offset >= mkc->dax_window_size)
		return -ENODEV;

	avail_pages = (mkc->dax_window_size - offset) >> PAGE_SHIFT;
	if (nr_pages > avail_pages)
		nr_pages = avail_pages;

	if (kaddr)
		*kaddr = mkc->dax_window + offset;
	if (pfn)
		*pfn = (mkc->dax_window_phys + offset) >> PAGE_SHIFT;

	return nr_pages;
}

static const struct dax_operations mk_fuse_dax_ops = {
	.direct_access = mk_fuse_dax_direct_access,
};

static int mk_fuse_setup_dax(struct mk_fuse_conn *mkc)
{
	struct dev_pagemap *pgmap;

	if (!mkc->dax_window_phys || !mkc->dax_window_size)
		return 0;

	mkc->dax_dev = alloc_dax(mkc, &mk_fuse_dax_ops);
	if (IS_ERR(mkc->dax_dev))
		return PTR_ERR(mkc->dax_dev);

	pgmap = kzalloc(sizeof(*pgmap), GFP_KERNEL);
	if (!pgmap) {
		put_dax(mkc->dax_dev);
		mkc->dax_dev = NULL;
		return -ENOMEM;
	}

	pgmap->type = MEMORY_DEVICE_FS_DAX;
	pgmap->range.start = mkc->dax_window_phys;
	pgmap->range.end = mkc->dax_window_phys + mkc->dax_window_size - 1;
	pgmap->nr_range = 1;

	mkc->dax_window = memremap_pages(pgmap, -1);
	if (IS_ERR(mkc->dax_window)) {
		int err = PTR_ERR(mkc->dax_window);
		mkc->dax_window = NULL;
		kfree(pgmap);
		put_dax(mkc->dax_dev);
		mkc->dax_dev = NULL;
		return err;
	}

	mkc->pgmap = pgmap;
	pr_info("mkfuse: DAX window at %pa, size %zu\n",
		&mkc->dax_window_phys, mkc->dax_window_size);

	return 0;
}

static int mk_fuse_sock_send(struct socket *sock, void *buf, size_t len)
{
	struct kvec iov = { .iov_base = buf, .iov_len = len };
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };

	return kernel_sendmsg(sock, &msg, &iov, 1, len);
}

static int mk_fuse_sock_recv(struct socket *sock, void *buf, size_t len)
{
	struct kvec iov = { .iov_base = buf, .iov_len = len };
	struct msghdr msg = { .msg_flags = 0 };
	int ret, received = 0;

	while (received < len) {
		iov.iov_base = buf + received;
		iov.iov_len = len - received;

		ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
		if (ret <= 0)
			return ret ? ret : -ECONNRESET;
		received += ret;
	}

	return received;
}

static void mk_fuse_send_work(struct work_struct *work)
{
	struct mk_fuse_conn *mkc = container_of(work, struct mk_fuse_conn,
						send_work);
	struct fuse_req *req;
	struct fuse_in_header *ih;
	struct fuse_args *args;
	size_t total_len;
	void *buf;
	size_t offset;
	unsigned int i;
	int ret;

	while (mkc->connected) {
		spin_lock(&mkc->send_lock);
		if (list_empty(&mkc->send_queue)) {
			spin_unlock(&mkc->send_lock);
			break;
		}
		req = list_first_entry(&mkc->send_queue, struct fuse_req, list);
		list_del_init(&req->list);
		spin_unlock(&mkc->send_lock);

		args = req->args;
		ih = &req->in.h;

		total_len = ih->len;

		buf = kmalloc(total_len, GFP_KERNEL);
		if (!buf) {
			req->out.h.error = -ENOMEM;
			fuse_request_end(req);
			continue;
		}

		memcpy(buf, ih, sizeof(*ih));
		offset = sizeof(*ih);

		/* Copy non-paged input arguments */
		for (i = 0; i < args->in_numargs - args->in_pages; i++) {
			memcpy(buf + offset, args->in_args[i].value,
			       args->in_args[i].size);
			offset += args->in_args[i].size;
		}

		/* Copy paged input arguments from folios (e.g., WRITE data) */
		if (args->in_pages) {
			struct fuse_args_pages *ap;
			unsigned int j;
			size_t paged_len;

			ap = container_of(args, struct fuse_args_pages, args);
			paged_len = args->in_args[args->in_numargs - 1].size;

			for (j = 0; j < ap->num_folios && paged_len; j++) {
				unsigned int copy_len = min_t(size_t, paged_len,
							      ap->descs[j].length);
				void *kaddr = kmap_local_folio(ap->folios[j],
							       ap->descs[j].offset);
				memcpy(buf + offset, kaddr, copy_len);
				kunmap_local(kaddr);
				offset += copy_len;
				paged_len -= copy_len;
			}
		}

		clear_bit(FR_PENDING, &req->flags);

		spin_lock(&mkc->fud->pq.lock);
		list_add_tail(&req->list,
			      &mkc->fud->pq.processing[fuse_req_hash(ih->unique)]);
		refcount_inc(&req->count);
		set_bit(FR_SENT, &req->flags);
		spin_unlock(&mkc->fud->pq.lock);

		/* matches barrier in request_wait_answer() */
		smp_mb__after_atomic();

		ret = mk_fuse_sock_send(mkc->sock, buf, total_len);
		kfree(buf);

		/* Balance the refcount_inc above, like fuse_dev_do_read */
		refcount_dec(&req->count);

		if (ret != total_len) {
			spin_lock(&mkc->fud->pq.lock);
			list_del_init(&req->list);
			spin_unlock(&mkc->fud->pq.lock);
			req->out.h.error = (ret < 0) ? ret : -EIO;
			clear_bit(FR_SENT, &req->flags);
			fuse_request_end(req);
		}
	}

	/* Abort any remaining requests if connection was lost */
	if (!mkc->connected) {
		LIST_HEAD(abort_list);

		spin_lock(&mkc->send_lock);
		list_splice_init(&mkc->send_queue, &abort_list);
		spin_unlock(&mkc->send_lock);

		while (!list_empty(&abort_list)) {
			req = list_first_entry(&abort_list, struct fuse_req, list);
			list_del_init(&req->list);

			clear_bit(FR_PENDING, &req->flags);
			req->out.h.error = -ENOTCONN;
			fuse_request_end(req);
		}
	}
}

static void mk_fuse_send_req(struct fuse_iqueue *fiq, struct fuse_req *req)
{
	struct mk_fuse_conn *mkc = fiq->priv;

	if (!mkc || !mkc->sock || !mkc->connected) {
		clear_bit(FR_PENDING, &req->flags);
		req->out.h.error = -ENOTCONN;
		fuse_request_end(req);
		return;
	}

	fuse_request_assign_unique(fiq, req);

	spin_lock(&mkc->send_lock);
	list_add_tail(&req->list, &mkc->send_queue);
	spin_unlock(&mkc->send_lock);

	queue_work(mk_fuse_wq, &mkc->send_work);
}

static void mk_fuse_send_forget(struct fuse_iqueue *fiq,
				struct fuse_forget_link *link)
{
	struct mk_fuse_conn *mkc = fiq->priv;
	struct fuse_in_header ih;
	struct fuse_forget_in arg;
	struct {
		struct fuse_in_header h;
		struct fuse_forget_in arg;
	} msg;

	if (!mkc || !mkc->sock || !mkc->connected)
		goto out;

	ih.len = sizeof(msg);
	ih.opcode = FUSE_FORGET;
	ih.unique = 0;
	ih.nodeid = link->forget_one.nodeid;
	ih.uid = 0;
	ih.gid = 0;
	ih.pid = 0;

	arg.nlookup = link->forget_one.nlookup;

	msg.h = ih;
	msg.arg = arg;

	mk_fuse_sock_send(mkc->sock, &msg, sizeof(msg));

out:
	kfree(link);
}

static void mk_fuse_send_interrupt(struct fuse_iqueue *fiq,
				   struct fuse_req *req)
{
	struct mk_fuse_conn *mkc = fiq->priv;
	struct {
		struct fuse_in_header h;
		struct fuse_interrupt_in arg;
	} msg = {};

	if (!mkc || !mkc->sock || !mkc->connected)
		return;

	msg.h.len = sizeof(msg);
	msg.h.opcode = FUSE_INTERRUPT;
	msg.h.unique = req->in.h.unique | FUSE_INT_REQ_BIT;
	msg.arg.unique = req->in.h.unique;

	mk_fuse_sock_send(mkc->sock, &msg, sizeof(msg));
}

static const struct fuse_iqueue_ops mk_fuse_fiq_ops = {
	.send_req = mk_fuse_send_req,
	.send_forget = mk_fuse_send_forget,
	.send_interrupt = mk_fuse_send_interrupt,
};

static int mk_fuse_recv_thread(void *data)
{
	struct mk_fuse_conn *mkc = data;
	struct fuse_out_header oh;
	struct fuse_pqueue *fpq;
	struct fuse_req *req;
	void *buf = NULL;
	size_t buf_size = 0;
	int ret;

	fpq = &mkc->fud->pq;

	while (!kthread_should_stop()) {
		if (!mkc->connected)
			break;

		/* Receive header */
		ret = mk_fuse_sock_recv(mkc->sock, &oh, sizeof(oh));
		if (ret <= 0) {
			if (ret == -EAGAIN || ret == -ERESTARTSYS)
				continue;
			if (!kthread_should_stop())
				pr_err("mkfuse: recv error: %d\n", ret);
			break;
		}

		/* Receive body */
		if (oh.len > sizeof(oh)) {
			size_t body_len = oh.len - sizeof(oh);

			if (body_len > buf_size) {
				kfree(buf);
				buf_size = max(body_len, (size_t)PAGE_SIZE);
				buf = kmalloc(buf_size, GFP_KERNEL);
				if (!buf) {
					pr_err("mkfuse: OOM\n");
					break;
				}
			}

retry_body:
			ret = mk_fuse_sock_recv(mkc->sock, buf, body_len);
			if (ret <= 0) {
				if (ret == -EAGAIN || ret == -ERESTARTSYS) {
					if (kthread_should_stop())
						break;
					goto retry_body;
				}
				pr_err("mkfuse: body recv error: %d\n", ret);
				break;
			}
		}

		/* Find and complete request */
		spin_lock(&fpq->lock);
		req = fuse_request_find(fpq, oh.unique);
		if (req)
			list_del_init(&req->list);
		spin_unlock(&fpq->lock);

		if (!req) {
			pr_warn("mkfuse: no request for unique %llu\n",
				oh.unique);
			continue;
		}

		req->out.h = oh;

		/* Copy output arguments - following virtio_fs copy_args_from_argbuf */
		if (oh.error == 0 && oh.len > sizeof(oh) && req->args) {
			struct fuse_args *args = req->args;
			unsigned int remaining = oh.len - sizeof(oh);
			unsigned int num_out = args->out_numargs - args->out_pages;
			unsigned int offset = 0;
			unsigned int i;

			/* Copy non-paged output arguments */
			for (i = 0; i < num_out; i++) {
				unsigned int argsize = args->out_args[i].size;

				if (args->out_argvar &&
				    i == args->out_numargs - 1 &&
				    argsize > remaining)
					argsize = remaining;

				if (args->out_args[i].value)
					memcpy(args->out_args[i].value,
					       buf + offset, argsize);
				offset += argsize;

				if (i != args->out_numargs - 1)
					remaining -= argsize;
			}

			/* Store the actual size of the variable-length arg */
			if (args->out_argvar)
				args->out_args[args->out_numargs - 1].size = remaining;

			/* Copy paged output to folios */
			if (args->out_pages && remaining > 0) {
				struct fuse_args_pages *ap;

				ap = container_of(args, struct fuse_args_pages, args);
				for (i = 0; i < ap->num_folios && remaining > 0; i++) {
					unsigned int count = min(remaining,
								 ap->descs[i].length);
					void *kaddr = kmap_local_folio(ap->folios[i],
								       ap->descs[i].offset);
					memcpy(kaddr, buf + offset, count);
					kunmap_local(kaddr);
					offset += count;
					remaining -= count;
				}
			}
		}

		clear_bit(FR_SENT, &req->flags);
		fuse_request_end(req);
	}

	kfree(buf);
	mkc->connected = false;
	return 0;
}

static int mk_fuse_connect(struct mk_fuse_conn *mkc, int port)
{
	struct sockaddr_vm addr;
	struct mk_fuse_init_msg init_msg;
	int transport = VSOCK_TRANSPORT_MULTIKERNEL;
	sockptr_t optval = KERNEL_SOCKPTR(&transport);
	int ret;

	ret = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &mkc->sock);
	if (ret) {
		pr_err("mkfuse: failed to create vsock: %d\n", ret);
		return ret;
	}

	if (mkc->sock->ops->setsockopt) {
		ret = mkc->sock->ops->setsockopt(mkc->sock, AF_VSOCK,
						 SO_VM_SOCKETS_TRANSPORT,
						 optval, sizeof(transport));
		if (ret) {
			pr_err("mkfuse: failed to set transport: %d\n", ret);
			sock_release(mkc->sock);
			mkc->sock = NULL;
			return ret;
		}
	}

	memset(&addr, 0, sizeof(addr));
	addr.svm_family = AF_VSOCK;
	addr.svm_cid = mkc->host_cid;
	addr.svm_port = port;

	ret = kernel_connect(mkc->sock, (struct sockaddr_unsized *)&addr,
			     sizeof(addr), 0);
	if (ret) {
		pr_err("mkfuse: failed to connect to %d:%d: %d\n",
		       mkc->host_cid, port, ret);
		sock_release(mkc->sock);
		mkc->sock = NULL;
		return ret;
	}

	/* Receive init message from mkfsd */
	ret = mk_fuse_sock_recv(mkc->sock, &init_msg, sizeof(init_msg));
	if (ret < 0) {
		pr_err("mkfuse: failed to receive init: %d\n", ret);
		sock_release(mkc->sock);
		mkc->sock = NULL;
		return ret;
	}

	if (init_msg.magic != MK_FUSE_MAGIC) {
		pr_err("mkfuse: invalid magic: 0x%x\n", init_msg.magic);
		sock_release(mkc->sock);
		mkc->sock = NULL;
		return -EINVAL;
	}

	/* Setup DAX if available */
	if (init_msg.flags & MK_FUSE_INIT_F_DAX) {
		mkc->dax_window_phys = init_msg.dax_window_phys;
		mkc->dax_window_size = init_msg.dax_window_size;

		ret = mk_fuse_setup_dax(mkc);
		if (ret)
			pr_warn("mkfuse: DAX setup failed: %d\n", ret);
	}

	mkc->connected = true;

	pr_info("mkfuse: connected to cid %d port %d\n", mkc->host_cid, port);
	return 0;
}

static struct mk_fuse_conn *mk_fuse_conn_alloc(const char *tag, int host_cid,
					       int port)
{
	struct mk_fuse_conn *mkc;
	int ret;

	mkc = kzalloc(sizeof(*mkc), GFP_KERNEL);
	if (!mkc)
		return ERR_PTR(-ENOMEM);

	strscpy(mkc->tag, tag, sizeof(mkc->tag));
	mkc->host_cid = host_cid;
	spin_lock_init(&mkc->lock);
	init_waitqueue_head(&mkc->waitq);
	INIT_LIST_HEAD(&mkc->send_queue);
	spin_lock_init(&mkc->send_lock);
	INIT_WORK(&mkc->send_work, mk_fuse_send_work);

	ret = mk_fuse_connect(mkc, port);
	if (ret) {
		kfree(mkc);
		return ERR_PTR(ret);
	}

	mutex_lock(&mk_fuse_lock);
	list_add_tail(&mkc->list, &mk_fuse_conns);
	mutex_unlock(&mk_fuse_lock);

	return mkc;
}

static void mk_fuse_conn_free(struct mk_fuse_conn *mkc)
{
	if (!mkc)
		return;

	mkc->connected = false;

	/* Shutdown socket first to unblock recv thread */
	if (mkc->sock) {
		kernel_sock_shutdown(mkc->sock, SHUT_RDWR);
	}

	/* Now stop the recv thread (it should unblock from socket shutdown) */
	if (mkc->recv_thread) {
		kthread_stop(mkc->recv_thread);
		mkc->recv_thread = NULL;
	}

	/* Cancel pending send work */
	cancel_work_sync(&mkc->send_work);

	if (mkc->sock) {
		sock_release(mkc->sock);
		mkc->sock = NULL;
	}

	if (mkc->dax_dev) {
		kill_dax(mkc->dax_dev);
		put_dax(mkc->dax_dev);
	}

	if (mkc->dax_window)
		memunmap(mkc->dax_window);

	if (mkc->pgmap)
		kfree(mkc->pgmap);

	mutex_lock(&mk_fuse_lock);
	list_del(&mkc->list);
	mutex_unlock(&mk_fuse_lock);

	kfree(mkc);
}

/*
 * Filesystem mount context
 */
enum {
	OPT_TAG,
	OPT_CID,
	OPT_PORT,
	OPT_DAX,
	OPT_DAX_ENUM,
};

static const struct constant_table mk_fuse_dax_param_enums[] = {
	{ "always",	FUSE_DAX_ALWAYS },
	{ "never",	FUSE_DAX_NEVER },
	{ "inode",	FUSE_DAX_INODE_USER },
	{}
};

static const struct fs_parameter_spec mk_fuse_fs_params[] = {
	fsparam_string("tag", OPT_TAG),
	fsparam_u32("cid", OPT_CID),
	fsparam_u32("port", OPT_PORT),
	fsparam_flag("dax", OPT_DAX),
	fsparam_enum("dax", OPT_DAX_ENUM, mk_fuse_dax_param_enums),
	{}
};

struct mk_fuse_fs_context {
	char *tag;
	int host_cid;
	int port;
	struct fuse_fs_context fsc;
};

static int mk_fuse_parse_param(struct fs_context *fsc,
			       struct fs_parameter *param)
{
	struct mk_fuse_fs_context *ctx = fsc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fsc, mk_fuse_fs_params, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case OPT_TAG:
		kfree(ctx->tag);
		ctx->tag = param->string;
		param->string = NULL;
		break;
	case OPT_CID:
		ctx->host_cid = result.uint_32;
		break;
	case OPT_PORT:
		ctx->port = result.uint_32;
		break;
	case OPT_DAX:
		ctx->fsc.dax_mode = FUSE_DAX_ALWAYS;
		break;
	case OPT_DAX_ENUM:
		ctx->fsc.dax_mode = result.uint_32;
		break;
	}

	return 0;
}

static void mk_fuse_free_fsc(struct fs_context *fsc)
{
	struct mk_fuse_fs_context *ctx = fsc->fs_private;

	if (ctx) {
		kfree(ctx->tag);
		kfree(ctx);
	}
}

static int mk_fuse_fill_super(struct super_block *sb, struct fs_context *fsc)
{
	struct mk_fuse_fs_context *ctx = fsc->fs_private;
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct fuse_conn *fc = fm->fc;
	struct mk_fuse_conn *mkc = fc->iq.priv;
	int err;

	/* Set up FUSE context for root inode */
	ctx->fsc.rootmode = S_IFDIR;
	ctx->fsc.fudptr = NULL;

	err = fuse_fill_super_common(sb, &ctx->fsc);
	if (err < 0)
		return err;

	mkc->fud = fuse_dev_alloc_install(fc);
	if (!mkc->fud)
		return -ENOMEM;

	/* Start receiver thread now that fud is available */
	mkc->recv_thread = kthread_run(mk_fuse_recv_thread, mkc,
				       "mkfuse-recv-%s", mkc->tag);
	if (IS_ERR(mkc->recv_thread)) {
		int ret = PTR_ERR(mkc->recv_thread);
		mkc->recv_thread = NULL;
		return ret;
	}

	fuse_send_init(fm);
	return 0;
}

static int mk_fuse_get_tree(struct fs_context *fsc)
{
	struct mk_fuse_fs_context *ctx = fsc->fs_private;
	struct mk_fuse_conn *mkc;
	struct fuse_conn *fc;
	struct fuse_mount *fm;
	struct super_block *sb;
	int err;

	if (!ctx->tag) {
		pr_err("mkfuse: no tag specified\n");
		return -EINVAL;
	}

	if (ctx->host_cid < 0) {
		pr_err("mkfuse: cid not specified\n");
		return -EINVAL;
	}

	if (ctx->port <= 0)
		ctx->port = MK_FUSE_DEFAULT_PORT;

	fc = kzalloc(sizeof(*fc), GFP_KERNEL);
	if (!fc)
		return -ENOMEM;

	fm = kzalloc(sizeof(*fm), GFP_KERNEL);
	if (!fm) {
		kfree(fc);
		return -ENOMEM;
	}

	mkc = mk_fuse_conn_alloc(ctx->tag, ctx->host_cid, ctx->port);
	if (IS_ERR(mkc)) {
		kfree(fm);
		kfree(fc);
		return PTR_ERR(mkc);
	}

	fuse_conn_init(fc, fm, fsc->user_ns, &mk_fuse_fiq_ops, mkc);
	fc->release = fuse_free_conn;

	if (mkc->dax_dev) {
		ctx->fsc.dax_dev = mkc->dax_dev;
		if (ctx->fsc.dax_mode == FUSE_DAX_INODE_DEFAULT)
			ctx->fsc.dax_mode = FUSE_DAX_ALWAYS;
	}

	mkc->fc = fc;
	mkc->fm = fm;

	fsc->s_fs_info = fm;

	sb = sget_fc(fsc, NULL, set_anon_super_fc);
	if (fsc->s_fs_info)
		fuse_mount_destroy(fm);
	if (IS_ERR(sb)) {
		mk_fuse_conn_free(mkc);
		return PTR_ERR(sb);
	}

	if (!sb->s_root) {
		err = mk_fuse_fill_super(sb, fsc);
		if (err) {
			deactivate_locked_super(sb);
			mk_fuse_conn_free(mkc);
			return err;
		}
		sb->s_flags |= SB_ACTIVE;
	}

	fsc->root = dget(sb->s_root);
	return 0;
}

static const struct fs_context_operations mk_fuse_context_ops = {
	.free		= mk_fuse_free_fsc,
	.parse_param	= mk_fuse_parse_param,
	.get_tree	= mk_fuse_get_tree,
};

static int mk_fuse_init_fs_context(struct fs_context *fsc)
{
	struct mk_fuse_fs_context *ctx;

	if (fsc->purpose == FS_CONTEXT_FOR_SUBMOUNT)
		return fuse_init_fs_context_submount(fsc);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->host_cid = -1;
	ctx->port = MK_FUSE_DEFAULT_PORT;
	ctx->fsc.dax_mode = FUSE_DAX_INODE_DEFAULT;

	fsc->fs_private = ctx;
	fsc->ops = &mk_fuse_context_ops;

	return 0;
}

static void mk_fuse_kill_sb(struct super_block *sb)
{
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct mk_fuse_conn *mkc = NULL;

	if (fm && fm->fc)
		mkc = fm->fc->iq.priv;

	if (fm)
		fuse_mount_destroy(fm);

	kill_anon_super(sb);

	if (mkc)
		mk_fuse_conn_free(mkc);
}

static struct file_system_type mk_fuse_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "mkfuse",
	.init_fs_context = mk_fuse_init_fs_context,
	.kill_sb	= mk_fuse_kill_sb,
};
MODULE_ALIAS_FS("mkfuse");

/*
 * Module init/exit
 */
static int __init mk_fuse_init(void)
{
	int err;

	mk_fuse_wq = alloc_workqueue("mk_fuse", WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!mk_fuse_wq)
		return -ENOMEM;

	err = register_filesystem(&mk_fuse_fs_type);
	if (err) {
		destroy_workqueue(mk_fuse_wq);
		return err;
	}

	pr_info("mkfuse: Multikernel FUSE transport registered (vsock-based)\n");
	return 0;
}

static void __exit mk_fuse_exit(void)
{
	struct mk_fuse_conn *mkc, *tmp;

	unregister_filesystem(&mk_fuse_fs_type);

	mutex_lock(&mk_fuse_lock);
	list_for_each_entry_safe(mkc, tmp, &mk_fuse_conns, list) {
		list_del(&mkc->list);
		mk_fuse_conn_free(mkc);
	}
	mutex_unlock(&mk_fuse_lock);

	if (mk_fuse_wq)
		destroy_workqueue(mk_fuse_wq);

	pr_info("mkfuse: Multikernel FUSE transport unregistered\n");
}

module_init(mk_fuse_init);
module_exit(mk_fuse_exit);

MODULE_AUTHOR("Cong Wang <cwang@multikernel.io>");
MODULE_DESCRIPTION("FUSE Multikernel Transport with DAX (vsock-based)");
MODULE_LICENSE("GPL");
