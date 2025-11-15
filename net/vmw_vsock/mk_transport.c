// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multikernel transport for vsock
 *
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved.
 *
 * This transport implements vsock over multikernel's IPI messaging and
 * shared memory infrastructure, enabling standard AF_VSOCK sockets to
 * work between different kernel instances on the same host.
 *
 * Address mapping: CID = instance_id (direct 1:1 mapping)
 * User must explicitly set SO_VM_SOCKETS_TRANSPORT to VSOCK_TRANSPORT_MULTIKERNEL
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/multikernel.h>
#include <net/sock.h>
#include <net/af_vsock.h>
#include <linux/virtio_vsock.h>


#define MK_VSOCK_MAX_PKT_SIZE	(MK_MAX_DATA_SIZE - sizeof(struct mk_message))

static struct vsock_transport mk_transport;

struct mk_vsock {
	struct workqueue_struct *workqueue;
	struct sk_buff_head pkt_queue;
	struct work_struct rx_work;
	spinlock_t rx_lock;
};

static struct mk_vsock mk_vsock_dev;

struct mk_vsock_sock {
	struct vsock_sock *vsk;

	/* RX data queue */
	struct sk_buff_head rx_queue;
	spinlock_t rx_lock;

	/* TX state */
	spinlock_t tx_lock;

	/* Flow control */
	u32 buf_alloc;          /* Local buffer space */
	u32 fwd_cnt;            /* Bytes consumed */
	u32 peer_buf_alloc;     /* Peer's buffer space */
	u32 peer_fwd_cnt;       /* Peer's consumed bytes */
	u32 rx_bytes;           /* Total RX bytes */
	u32 tx_bytes;           /* Total TX bytes */
};

static struct mk_vsock_sock *mk_vsock_sk(struct vsock_sock *vsk)
{
	/* We store our private data in vsk->trans */
	return (struct mk_vsock_sock *)vsk->trans;
}

static int mk_send_pkt(struct sk_buff *skb)
{
	struct virtio_vsock_hdr *hdr;
	int instance_id;
	int ret;
	size_t total_len;

	if (!skb)
		return -EINVAL;

	hdr = (struct virtio_vsock_hdr *)skb->data;
	instance_id = (int)le64_to_cpu(hdr->dst_cid);

	total_len = sizeof(*hdr) + le32_to_cpu(hdr->len);

	if (total_len > MK_VSOCK_MAX_PKT_SIZE)
		return -EMSGSIZE;

	ret = mk_send_message(instance_id, MK_MSG_NETWORK, MK_NET_VSOCK_PKT,
			     skb->data, total_len);

	return ret < 0 ? ret : total_len;
}

static void mk_queue_rx_pkt(struct sk_buff *skb)
{
	struct mk_vsock *mk = &mk_vsock_dev;

	spin_lock(&mk->rx_lock);
	skb_queue_tail(&mk->pkt_queue, skb);
	spin_unlock(&mk->rx_lock);

	queue_work(mk->workqueue, &mk->rx_work);
}

static void mk_vsock_rx_pkt(struct sk_buff *skb)
{
	struct virtio_vsock_hdr *hdr = (struct virtio_vsock_hdr *)skb->data;
	struct sockaddr_vm src, dst;
	struct vsock_sock *vsk;
	struct sock *sk;

	vsock_addr_init(&src, le64_to_cpu(hdr->src_cid), le32_to_cpu(hdr->src_port));
	vsock_addr_init(&dst, le64_to_cpu(hdr->dst_cid), le32_to_cpu(hdr->dst_port));

	sk = vsock_find_connected_socket(&src, &dst);
	if (!sk) {
		sk = vsock_find_bound_socket(&dst);
		if (!sk) {
			kfree_skb(skb);
			return;
		}
	}


	vsk = vsock_sk(sk);

	switch (le16_to_cpu(hdr->op)) {
	case VIRTIO_VSOCK_OP_RW: {
		struct mk_vsock_sock *mk_vsk = mk_vsock_sk(vsk);

		VIRTIO_VSOCK_SKB_CB(skb)->offset = 0;
		spin_lock_bh(&mk_vsk->rx_lock);
		skb_queue_tail(&mk_vsk->rx_queue, skb);
		mk_vsk->rx_bytes += le32_to_cpu(hdr->len);
		spin_unlock_bh(&mk_vsk->rx_lock);

		vsock_data_ready(sk);
		sock_put(sk);
		return;  /* Don't free skb, it's queued */
	}

    case VIRTIO_VSOCK_OP_REQUEST: {
        struct virtio_vsock_hdr *rsp_hdr;
        struct vsock_sock *vchild;
        struct sk_buff *rsp_skb;
        struct sock *child;
        int ret;

		if (sk->sk_state != TCP_LISTEN)
			goto reset;

		if (sk_acceptq_is_full(sk))
			goto reset;

		if (sk->sk_shutdown == SHUTDOWN_MASK)
			goto reset;

		child = vsock_create_connected(sk);
		if (!child) {
			pr_err("mk_vsock: failed to create child socket\n");
			goto reset;
		}

		sk_acceptq_added(sk);

		lock_sock_nested(child, SINGLE_DEPTH_NESTING);

		child->sk_state = TCP_ESTABLISHED;

		vchild = vsock_sk(child);
		vsock_addr_init(&vchild->local_addr, le64_to_cpu(hdr->dst_cid),
				le32_to_cpu(hdr->dst_port));
		vsock_addr_init(&vchild->remote_addr, le64_to_cpu(hdr->src_cid),
				le32_to_cpu(hdr->src_port));

		vchild->transport = &mk_transport;
		if (!try_module_get(mk_transport.module)) {
			pr_err("mk_vsock: failed to get transport module\n");
			release_sock(child);
			sock_put(child);
			goto reset;
		}

		if (mk_transport.init) {
			ret = mk_transport.init(vchild, vsk);
			if (ret) {
				pr_err("mk_vsock: transport init failed: %d\n", ret);
				module_put(mk_transport.module);
				vchild->transport = NULL;
				release_sock(child);
				sock_put(child);
				goto reset;
			}
		}

		vsock_insert_connected(vchild);
		vsock_enqueue_accept(sk, child);

		rsp_skb = alloc_skb(sizeof(*rsp_hdr), GFP_KERNEL);
		if (rsp_skb) {
			rsp_hdr = (struct virtio_vsock_hdr *)skb_put(rsp_skb, sizeof(*rsp_hdr));
			rsp_hdr->op = cpu_to_le16(VIRTIO_VSOCK_OP_RESPONSE);
			rsp_hdr->src_cid = hdr->dst_cid;
			rsp_hdr->dst_cid = hdr->src_cid;
			rsp_hdr->src_port = hdr->dst_port;
			rsp_hdr->dst_port = hdr->src_port;
			rsp_hdr->type = cpu_to_le16(VIRTIO_VSOCK_TYPE_STREAM);
			rsp_hdr->flags = 0;
			rsp_hdr->len = 0;
			rsp_hdr->buf_alloc = cpu_to_le32(64 * 1024);
			rsp_hdr->fwd_cnt = 0;

			mk_send_pkt(rsp_skb);
			kfree_skb(rsp_skb);
		}

		release_sock(child);

		sk->sk_data_ready(sk);

		sock_put(sk);
		kfree_skb(skb);
		return;

reset:
		rsp_skb = alloc_skb(sizeof(*rsp_hdr), GFP_KERNEL);
		if (rsp_skb) {
			rsp_hdr = (struct virtio_vsock_hdr *)skb_put(rsp_skb, sizeof(*rsp_hdr));
			rsp_hdr->op = cpu_to_le16(VIRTIO_VSOCK_OP_RST);
			rsp_hdr->src_cid = hdr->dst_cid;
			rsp_hdr->dst_cid = hdr->src_cid;
			rsp_hdr->src_port = hdr->dst_port;
			rsp_hdr->dst_port = hdr->src_port;
			rsp_hdr->type = cpu_to_le16(VIRTIO_VSOCK_TYPE_STREAM);
			rsp_hdr->flags = 0;
			rsp_hdr->len = 0;
			rsp_hdr->buf_alloc = 0;
			rsp_hdr->fwd_cnt = 0;

			mk_send_pkt(rsp_skb);
			kfree_skb(rsp_skb);
		}
		break;
	}

	case VIRTIO_VSOCK_OP_RESPONSE:
		sk->sk_state = TCP_ESTABLISHED;
		sk->sk_state_change(sk);
		break;

	case VIRTIO_VSOCK_OP_SHUTDOWN:
		vsk->peer_shutdown = SHUTDOWN_MASK;
		sk->sk_state_change(sk);
		break;

	case VIRTIO_VSOCK_OP_RST:
		sk->sk_state = TCP_CLOSE;
		sk->sk_err = ECONNRESET;
		sk->sk_error_report(sk);
		break;

	default:
		break;
	}

	sock_put(sk);
	kfree_skb(skb);
}

static void mk_vsock_rx_work(struct work_struct *work)
{
	struct mk_vsock *mk = container_of(work, struct mk_vsock, rx_work);
	struct sk_buff_head pkts;
	struct sk_buff *skb;
	unsigned long flags;

	skb_queue_head_init(&pkts);

	spin_lock_irqsave(&mk->rx_lock, flags);
	skb_queue_splice_init(&mk->pkt_queue, &pkts);
	spin_unlock_irqrestore(&mk->rx_lock, flags);

	while ((skb = __skb_dequeue(&pkts)))
		mk_vsock_rx_pkt(skb);
}

static void mk_vsock_ipi_handler(u32 msg_type, u32 subtype,
				 void *payload, u32 payload_len, void *ctx)
{
	struct sk_buff *skb;
	struct virtio_vsock_hdr *hdr;

	if (msg_type != MK_MSG_NETWORK || subtype != MK_NET_VSOCK_PKT)
		return;

	if (payload_len < sizeof(struct virtio_vsock_hdr)) {
		pr_warn("mk_vsock: packet too small (%u bytes)\n", payload_len);
		return;
	}

	skb = alloc_skb(payload_len, GFP_ATOMIC);
	if (!skb) {
		pr_err("mk_vsock: failed to allocate skb\n");
		return;
	}

	skb_put_data(skb, payload, payload_len);

	hdr = (struct virtio_vsock_hdr *)skb->data;
	mk_queue_rx_pkt(skb);
}

/*
 * Transport operations
 */

static u32 mk_transport_get_local_cid(void)
{
	if (!root_instance)
		return VMADDR_CID_ANY;

	return (u32)root_instance->id;
}

static int mk_transport_init(struct vsock_sock *vsk, struct vsock_sock *psk)
{
	struct mk_vsock_sock *mk_vsk;

	mk_vsk = kzalloc(sizeof(*mk_vsk), GFP_KERNEL);
	if (!mk_vsk)
		return -ENOMEM;

	mk_vsk->vsk = vsk;
	skb_queue_head_init(&mk_vsk->rx_queue);
	spin_lock_init(&mk_vsk->rx_lock);
	spin_lock_init(&mk_vsk->tx_lock);

	mk_vsk->buf_alloc = 64 * 1024;  /* 64KB local buffer */
	mk_vsk->fwd_cnt = 0;
	mk_vsk->peer_buf_alloc = 0;
	mk_vsk->peer_fwd_cnt = 0;
	mk_vsk->rx_bytes = 0;
	mk_vsk->tx_bytes = 0;

	vsk->trans = mk_vsk;

	return 0;
}

static void mk_transport_destruct(struct vsock_sock *vsk)
{
	struct mk_vsock_sock *mk_vsk = mk_vsock_sk(vsk);

	if (mk_vsk) {
		skb_queue_purge(&mk_vsk->rx_queue);
		kfree(mk_vsk);
		vsk->trans = NULL;
	}
}

static void mk_transport_release(struct vsock_sock *vsk)
{
	if (vsk->sk.sk_state == TCP_ESTABLISHED) {
		struct sk_buff *skb;
		struct virtio_vsock_hdr *hdr;
		u32 local_cid = mk_transport_get_local_cid();

		skb = alloc_skb(sizeof(*hdr), GFP_KERNEL);
		if (skb) {
			hdr = (struct virtio_vsock_hdr *)skb_put(skb, sizeof(*hdr));
			hdr->op = cpu_to_le16(VIRTIO_VSOCK_OP_SHUTDOWN);
			hdr->src_cid = cpu_to_le64(local_cid);
			hdr->dst_cid = cpu_to_le64(vsk->remote_addr.svm_cid);
			hdr->src_port = cpu_to_le32(vsk->local_addr.svm_port);
			hdr->dst_port = cpu_to_le32(vsk->remote_addr.svm_port);
			hdr->type = cpu_to_le16(VIRTIO_VSOCK_TYPE_STREAM);
			hdr->flags = cpu_to_le32(VIRTIO_VSOCK_SHUTDOWN_RCV | VIRTIO_VSOCK_SHUTDOWN_SEND);
			hdr->len = 0;
			hdr->buf_alloc = 0;
			hdr->fwd_cnt = 0;

			mk_send_pkt(skb);
			kfree_skb(skb);
		}
	}
}

static int mk_transport_connect(struct vsock_sock *vsk)
{
	struct sk_buff *skb;
	struct virtio_vsock_hdr *hdr;
	u32 local_cid;
	int ret;

	local_cid = mk_transport_get_local_cid();
	if (vsk->local_addr.svm_cid == VMADDR_CID_ANY ||
	    vsk->local_addr.svm_cid != local_cid) {
		vsk->local_addr.svm_cid = local_cid;
	}

	skb = alloc_skb(sizeof(*hdr), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	hdr = (struct virtio_vsock_hdr *)skb_put(skb, sizeof(*hdr));
	hdr->op = cpu_to_le16(VIRTIO_VSOCK_OP_REQUEST);
	hdr->src_cid = cpu_to_le64(vsk->local_addr.svm_cid);
	hdr->dst_cid = cpu_to_le64(vsk->remote_addr.svm_cid);
	hdr->src_port = cpu_to_le32(vsk->local_addr.svm_port);
	hdr->dst_port = cpu_to_le32(vsk->remote_addr.svm_port);
	hdr->type = cpu_to_le16(VIRTIO_VSOCK_TYPE_STREAM);
	hdr->flags = 0;
	hdr->len = 0;
	hdr->buf_alloc = cpu_to_le32(64 * 1024);
	hdr->fwd_cnt = 0;

	ret = mk_send_pkt(skb);
	kfree_skb(skb);

	if (ret < 0) {
		pr_err("mk_vsock: failed to send connection request: %d\n", ret);
		return ret;
	}

	return 0;
}

static int mk_transport_shutdown(struct vsock_sock *vsk, int mode)
{
	u32 local_cid = mk_transport_get_local_cid();
	struct virtio_vsock_hdr *hdr;
	struct sk_buff *skb;
	int ret;

	skb = alloc_skb(sizeof(*hdr), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	hdr = (struct virtio_vsock_hdr *)skb_put(skb, sizeof(*hdr));
	hdr->op = cpu_to_le16(VIRTIO_VSOCK_OP_SHUTDOWN);
	hdr->src_cid = cpu_to_le64(local_cid);
	hdr->dst_cid = cpu_to_le64(vsk->remote_addr.svm_cid);
	hdr->src_port = cpu_to_le32(vsk->local_addr.svm_port);
	hdr->dst_port = cpu_to_le32(vsk->remote_addr.svm_port);
	hdr->type = cpu_to_le16(VIRTIO_VSOCK_TYPE_STREAM);
	hdr->flags = cpu_to_le32(mode);
	hdr->len = 0;
	hdr->buf_alloc = 0;
	hdr->fwd_cnt = 0;

	ret = mk_send_pkt(skb);
	kfree_skb(skb);

	return ret < 0 ? ret : 0;
}

static int mk_transport_cancel_pkt(struct vsock_sock *vsk)
{
	struct mk_vsock_sock *mk_vsk = mk_vsock_sk(vsk);

	skb_queue_purge(&mk_vsk->rx_queue);
	return 0;
}

/*
 * Stream operations
 */

static ssize_t mk_transport_stream_enqueue(struct vsock_sock *vsk,
					   struct msghdr *msg, size_t len)
{
	struct mk_vsock_sock *mk_vsk = mk_vsock_sk(vsk);
	struct sk_buff *skb;
	struct virtio_vsock_hdr *hdr;
	u32 local_cid = mk_transport_get_local_cid();
	size_t to_send;
	int ret;

	to_send = min(len, (size_t)(MK_VSOCK_MAX_PKT_SIZE - sizeof(*hdr)));

	skb = alloc_skb(sizeof(*hdr) + to_send, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	hdr = (struct virtio_vsock_hdr *)skb_put(skb, sizeof(*hdr));
	hdr->op = cpu_to_le16(VIRTIO_VSOCK_OP_RW);
	hdr->src_cid = cpu_to_le64(local_cid);
	hdr->dst_cid = cpu_to_le64(vsk->remote_addr.svm_cid);
	hdr->src_port = cpu_to_le32(vsk->local_addr.svm_port);
	hdr->dst_port = cpu_to_le32(vsk->remote_addr.svm_port);
	hdr->type = cpu_to_le16(VIRTIO_VSOCK_TYPE_STREAM);
	hdr->flags = 0;
	hdr->len = cpu_to_le32(to_send);
	hdr->buf_alloc = cpu_to_le32(mk_vsk->buf_alloc);
	hdr->fwd_cnt = cpu_to_le32(mk_vsk->fwd_cnt);

	ret = copy_from_iter(skb_put(skb, to_send), to_send, &msg->msg_iter);
	if (ret != to_send) {
		kfree_skb(skb);
		return -EFAULT;
	}

	ret = mk_send_pkt(skb);
	kfree_skb(skb);
	if (ret < 0)
		return ret;

	spin_lock_bh(&mk_vsk->tx_lock);
	mk_vsk->tx_bytes += to_send;
	spin_unlock_bh(&mk_vsk->tx_lock);

	return to_send;
}

static ssize_t mk_transport_stream_dequeue(struct vsock_sock *vsk,
					   struct msghdr *msg,
					   size_t len, int flags)
{
	struct mk_vsock_sock *mk_vsk = mk_vsock_sk(vsk);
	struct sk_buff *skb;
	struct virtio_vsock_hdr *hdr;
	size_t to_copy, off;
	int err;

	spin_lock_bh(&mk_vsk->rx_lock);

	skb = __skb_dequeue(&mk_vsk->rx_queue);
	if (!skb) {
		spin_unlock_bh(&mk_vsk->rx_lock);
		return -EAGAIN;
	}

	hdr = (struct virtio_vsock_hdr *)skb->data;
	off = VIRTIO_VSOCK_SKB_CB(skb)->offset;
	to_copy = min(len, (size_t)le32_to_cpu(hdr->len) - off);

	mk_vsk->fwd_cnt += to_copy;
	spin_unlock_bh(&mk_vsk->rx_lock);

	err = skb_copy_datagram_msg(skb, sizeof(*hdr) + off, msg, to_copy);
	if (err) {
		spin_lock_bh(&mk_vsk->rx_lock);
		__skb_queue_head(&mk_vsk->rx_queue, skb);
		mk_vsk->fwd_cnt -= to_copy;
		spin_unlock_bh(&mk_vsk->rx_lock);
		return err;
	}

	if (to_copy + off < le32_to_cpu(hdr->len)) {
		VIRTIO_VSOCK_SKB_CB(skb)->offset = off + to_copy;
		spin_lock_bh(&mk_vsk->rx_lock);
		__skb_queue_head(&mk_vsk->rx_queue, skb);
		spin_unlock_bh(&mk_vsk->rx_lock);
	} else {
		kfree_skb(skb);
	}

	return to_copy;
}

static s64 mk_transport_stream_has_data(struct vsock_sock *vsk)
{
	struct mk_vsock_sock *mk_vsk = mk_vsock_sk(vsk);
	struct sk_buff *skb;
	struct virtio_vsock_hdr *hdr;
	s64 data = 0;

	spin_lock_bh(&mk_vsk->rx_lock);
	skb_queue_walk(&mk_vsk->rx_queue, skb) {
		hdr = (struct virtio_vsock_hdr *)skb->data;
		data += le32_to_cpu(hdr->len) - VIRTIO_VSOCK_SKB_CB(skb)->offset;
	}
	spin_unlock_bh(&mk_vsk->rx_lock);

	return data;
}

static s64 mk_transport_stream_has_space(struct vsock_sock *vsk)
{
	/* Simplified: return available space */
	return 64 * 1024;  /* 64KB */
}

static u64 mk_transport_stream_rcvhiwat(struct vsock_sock *vsk)
{
	return sk_vsock(vsk)->sk_rcvbuf;
}

static bool mk_transport_stream_is_active(struct vsock_sock *vsk)
{
	return true;
}

static bool mk_transport_stream_allow(u32 cid, u32 port)
{
	/* Allow connections to any multikernel instance */
	return true;
}

/*
 * Notification callbacks
 */

static int mk_transport_notify_poll_in(struct vsock_sock *vsk, size_t target,
				       bool *data_ready_now)
{
	*data_ready_now = mk_transport_stream_has_data(vsk) > 0;
	return 0;
}

static int mk_transport_notify_poll_out(struct vsock_sock *vsk, size_t target,
					bool *space_avail_now)
{
	*space_avail_now = true;
	return 0;
}

static int mk_transport_notify_recv_init(struct vsock_sock *vsk, size_t target,
					struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int mk_transport_notify_recv_pre_block(struct vsock_sock *vsk, size_t target,
					     struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int mk_transport_notify_recv_pre_dequeue(struct vsock_sock *vsk, size_t target,
					       struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int mk_transport_notify_recv_post_dequeue(struct vsock_sock *vsk, size_t target,
						ssize_t copied, bool data_read,
						struct vsock_transport_recv_notify_data *data)
{
	return 0;
}

static int mk_transport_notify_send_init(struct vsock_sock *vsk,
					struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int mk_transport_notify_send_pre_block(struct vsock_sock *vsk,
					     struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int mk_transport_notify_send_pre_enqueue(struct vsock_sock *vsk,
					       struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static int mk_transport_notify_send_post_enqueue(struct vsock_sock *vsk, ssize_t written,
						struct vsock_transport_send_notify_data *data)
{
	return 0;
}

static void mk_transport_notify_buffer_size(struct vsock_sock *vsk, u64 *val)
{
	*val = 64 * 1024;
}

static int mk_transport_notify_set_rcvlowat(struct vsock_sock *vsk, int val)
{
	return 0;
}

/*
 * Transport structure
 */

static struct vsock_transport mk_transport = {
	.module                     = THIS_MODULE,

	/* Lifecycle */
	.init                       = mk_transport_init,
	.destruct                   = mk_transport_destruct,
	.release                    = mk_transport_release,

	/* Connection management */
	.connect                    = mk_transport_connect,
	.cancel_pkt                 = mk_transport_cancel_pkt,

	/* Stream operations */
	.stream_dequeue             = mk_transport_stream_dequeue,
	.stream_enqueue             = mk_transport_stream_enqueue,
	.stream_has_data            = mk_transport_stream_has_data,
	.stream_has_space           = mk_transport_stream_has_space,
	.stream_rcvhiwat            = mk_transport_stream_rcvhiwat,
	.stream_is_active           = mk_transport_stream_is_active,
	.stream_allow               = mk_transport_stream_allow,

	/* Addressing */
	.get_local_cid              = mk_transport_get_local_cid,

	/* Notifications */
	.notify_poll_in             = mk_transport_notify_poll_in,
	.notify_poll_out            = mk_transport_notify_poll_out,
	.notify_recv_init           = mk_transport_notify_recv_init,
	.notify_recv_pre_block      = mk_transport_notify_recv_pre_block,
	.notify_recv_pre_dequeue    = mk_transport_notify_recv_pre_dequeue,
	.notify_recv_post_dequeue   = mk_transport_notify_recv_post_dequeue,
	.notify_send_init           = mk_transport_notify_send_init,
	.notify_send_pre_block      = mk_transport_notify_send_pre_block,
	.notify_send_pre_enqueue    = mk_transport_notify_send_pre_enqueue,
	.notify_send_post_enqueue   = mk_transport_notify_send_post_enqueue,
	.notify_buffer_size         = mk_transport_notify_buffer_size,
	.notify_set_rcvlowat        = mk_transport_notify_set_rcvlowat,

	/* Shutdown */
	.shutdown                   = mk_transport_shutdown,
};

/*
 * Module initialization
 */

static int __init mk_vsock_transport_init(void)
{
	struct mk_vsock *mk = &mk_vsock_dev;
	int ret;

	spin_lock_init(&mk->rx_lock);
	skb_queue_head_init(&mk->pkt_queue);
	INIT_WORK(&mk->rx_work, mk_vsock_rx_work);

	mk->workqueue = alloc_workqueue("mk_vsock_wq", WQ_UNBOUND, 0);
	if (!mk->workqueue) {
		pr_err("mk_vsock: failed to create workqueue\n");
		return -ENOMEM;
	}

	ret = mk_register_msg_handler(MK_MSG_NETWORK, mk_vsock_ipi_handler, NULL);
	if (ret < 0) {
		pr_err("mk_vsock: failed to register message handler: %d\n", ret);
		destroy_workqueue(mk->workqueue);
		return ret;
	}

	ret = vsock_core_register(&mk_transport, VSOCK_TRANSPORT_F_MULTIKERNEL);
	if (ret < 0) {
		pr_err("mk_vsock: failed to register transport: %d\n", ret);
		mk_unregister_msg_handler(MK_MSG_NETWORK, mk_vsock_ipi_handler);
		destroy_workqueue(mk->workqueue);
		return ret;
	}

	pr_info("Multikernel vsock transport registered\n");
	return 0;
}

static void __exit mk_vsock_transport_exit(void)
{
	struct mk_vsock *mk = &mk_vsock_dev;

	vsock_core_unregister(&mk_transport);
	mk_unregister_msg_handler(MK_MSG_NETWORK, mk_vsock_ipi_handler);

	if (mk->workqueue) {
		cancel_work_sync(&mk->rx_work);
		destroy_workqueue(mk->workqueue);
	}

	skb_queue_purge(&mk->pkt_queue);
	pr_info("Multikernel vsock transport unregistered\n");
}

module_init(mk_vsock_transport_init);
module_exit(mk_vsock_transport_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cong Wang <cwang@multikernel.io>");
MODULE_DESCRIPTION("Multikernel transport for vsock");
MODULE_ALIAS_NETPROTO(PF_VSOCK);
