// SPDX-License-Identifier: GPL-2.0-only
/* Real receive/init/worker functions; FIFO, sockets and scheduling modeled. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>
#include <linux/types.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef int raw_spinlock_t;
#include "vsock-wire.h"
#define le32_to_cpu(x) le32toh(x)
#define MK_MAX_DATA_SIZE 4096
#define MK_IPI_RING_SIZE 64
#define MK_MSG_NETWORK 1
#define MK_NET_VSOCK_PKT 1
#define GFP_KERNEL 1
#define WQ_UNBOUND 1
#define VSOCK_TRANSPORT_F_MULTIKERNEL 1
#define __init
#define __exit
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
struct mk_message { u64 id; u32 fields[4]; };
static unsigned int checks, failures, raw_depth, allocs, delivered, runs;
static bool in_irq, core_live, handler_live, queue_live;
static bool fail_queue, fail_alloc, tail_inject, inject_on_unlock, short_copy;
static int fail_core, fail_handler;
static void (*allocation_hook)(void), (*unregister_hook)(void);
static void send_packet(unsigned int seq, unsigned int len, u32 claimed);
#define EXPECT(x) do { checks++; if (!(x)) { \
	fprintf(stderr, "line %d: %s\n", __LINE__, #x); failures++; \
} } while (0)
#define raw_spin_lock_init(p) (*(p) = 0)
#define raw_spin_lock_irqsave(p, f) do { \
	assert(!*(p)); *(p) = 1; raw_depth++; (f) = 0; \
} while (0)
static void raw_unlock(raw_spinlock_t *p)
{
	assert(*p && raw_depth);
	*p = 0;
	raw_depth--;
	if (inject_on_unlock) {
		inject_on_unlock = false;
		send_packet(99, sizeof(struct virtio_vsock_hdr), 0);
	}
}
#define raw_spin_unlock_irqrestore(p, f) do { (void)(f); raw_unlock(p); } while (0)

/* Record FIFO API boundary: atomic whole-record insert, one consumer. */
struct fifo {
	unsigned char data[MK_IPI_RING_SIZE * MK_MAX_DATA_SIZE];
	unsigned int in, out;
};
#define STRUCT_KFIFO_REC_2(n) struct fifo
#define INIT_KFIFO(f) memset(&(f), 0, sizeof(f))
#define kfifo_is_empty(f) ((f)->in == (f)->out)
static unsigned int kfifo_peek_len(struct fifo *f)
{
	assert(raw_depth);
	if (kfifo_is_empty(f)) {
		if (tail_inject) {
			tail_inject = false;
			inject_on_unlock = true;
		}
		return 0;
	}
	return f->data[f->out % sizeof(f->data)] |
	       (f->data[(f->out + 1) % sizeof(f->data)] << 8);
}
static unsigned int kfifo_in(struct fifo *f, const void *p, unsigned int n)
{
	const unsigned char *data = p;
	unsigned int i;

	assert(raw_depth && n && n <= UINT16_MAX);
	if (n + 2 > sizeof(f->data) - (f->in - f->out))
		return 0;
	f->data[f->in++ % sizeof(f->data)] = n;
	f->data[f->in++ % sizeof(f->data)] = n >> 8;
	for (i = 0; i < n; i++)
		f->data[f->in++ % sizeof(f->data)] = data[i];
	return n;
}
static unsigned int kfifo_out(struct fifo *f, void *p, unsigned int n)
{
	unsigned char *data = p;
	unsigned int i;

	assert(n == kfifo_peek_len(f));
	f->out += 2;
	for (i = 0; i < n; i++)
		data[i] = f->data[f->out++ % sizeof(f->data)];
	if (short_copy) {
		short_copy = false;
		return n - 1;
	}
	return n;
}
static void kfifo_skip(struct fifo *f)
{
	unsigned int n = kfifo_peek_len(f);

	assert(n);
	f->out += n + 2;
}

struct work_struct { void (*fn)(struct work_struct *); bool pending; };
struct workqueue_struct { int unused; };
static struct workqueue_struct queue;
static struct work_struct *queued;
#define INIT_WORK(w, cb) do { (w)->fn = (cb); (w)->pending = false; } while (0)
static bool queue_work(struct workqueue_struct *q, struct work_struct *w)
{
	bool fresh = !w->pending;

	assert(raw_depth && queue_live && q == &queue);
	w->pending = true;
	queued = w;
	return fresh;
}
static void run_one(void)
{
	assert(queued && queued->pending && !in_irq && !raw_depth);
	queued->pending = false;
	runs++;
	queued->fn(queued);
}
static void drain(void)
{
	unsigned int budget = 100;

	while (queued && queued->pending) {
		assert(budget--);
		run_one();
	}
}
static struct workqueue_struct *alloc_workqueue(const char *s, int f, int n)
{
	assert(!in_irq && !raw_depth && !queue_live);
	queue_live = !fail_queue;
	return queue_live ? &queue : NULL;
}
static void cancel_work_sync(struct work_struct *w)
{
	assert(!in_irq && !raw_depth && !handler_live && core_live);
	w->pending = false;
}
static void destroy_workqueue(struct workqueue_struct *q)
{
	assert(!handler_live && (!queued || !queued->pending));
	queue_live = false;
}
static int mk_transport;
static int vsock_core_register(void *t, int flags)
{
	assert(queue_live && !core_live);
	core_live = !fail_core;
	return fail_core;
}
static void vsock_core_unregister(void *t)
{
	assert(core_live && !handler_live && (!queued || !queued->pending));
	core_live = false;
}
typedef void (*handler_t)(u32, u32, u64, void *, u32, void *);
static int mk_register_msg_handler(u32 type, handler_t fn, void *ctx)
{
	assert(core_live && queue_live && !handler_live);
	handler_live = !fail_handler;
	return fail_handler;
}
static int mk_unregister_msg_handler(u32 type, handler_t fn)
{
	assert(handler_live && core_live && queue_live);
	if (unregister_hook)
		unregister_hook();
	handler_live = false;
	return 0;
}

struct sk_buff { unsigned int len; unsigned char data[MK_MAX_DATA_SIZE]; };
static struct sk_buff *alloc_skb(unsigned int len, int flags)
{
	assert(!in_irq && !raw_depth && flags == GFP_KERNEL && core_live);
	assert(len <= MK_MAX_DATA_SIZE);
	allocs++;
	if (allocation_hook) {
		void (*hook)(void) = allocation_hook;

		allocation_hook = NULL;
		hook();
	}
	if (fail_alloc) {
		fail_alloc = false;
		return NULL;
	}
	return calloc(1, sizeof(struct sk_buff));
}
static void *skb_put(struct sk_buff *skb, unsigned int n)
{
	assert(!skb->len && n <= sizeof(skb->data));
	skb->len = n;
	return skb->data;
}
static void kfree_skb(struct sk_buff *skb)
{
	assert(!in_irq && !raw_depth);
	free(skb);
}
static unsigned int received[1024], lengths[1024];
static void mk_vsock_rx_pkt(struct sk_buff *skb)
{
	struct virtio_vsock_hdr *h = (void *)skb->data;
	unsigned int seq = le32toh(h->src_port), i;

	assert(!in_irq && !raw_depth && core_live && delivered < 1024);
	for (i = sizeof(*h); i < skb->len; i++)
		assert(skb->data[i] == (unsigned char)seq);
	received[delivered] = seq;
	lengths[delivered++] = skb->len;
	free(skb);
}
#include "vsock-production.h"

static void send_packet(unsigned int seq, unsigned int len, u32 claimed)
{
	unsigned char buffer[MK_MAX_DATA_SIZE + 1];
	struct virtio_vsock_hdr h = { .src_port = htole32(seq),
				   .len = htole32(claimed) };

	assert(handler_live && !in_irq && !raw_depth && len <= MK_MAX_DATA_SIZE);
	memset(buffer, seq, sizeof(buffer));
	memcpy(buffer + 1, &h, sizeof(h));
	in_irq = true;
	mk_vsock_ipi_handler(MK_MSG_NETWORK, MK_NET_VSOCK_PKT, 0,
			     buffer + 1, len, NULL);
	in_irq = false;
	memset(buffer, 0xff, sizeof(buffer));
}
static void inject(void)
{
	send_packet(42, sizeof(struct virtio_vsock_hdr), 0);
}
static void start(void)
{
	allocs = delivered = runs = 0;
	queued = NULL;
	EXPECT(!mk_vsock_transport_init());
}

int main(void)
{
	unsigned int i, header = sizeof(struct virtio_vsock_hdr);

	fail_queue = true;
	EXPECT(mk_vsock_transport_init() == -ENOMEM);
	EXPECT(!queue_live && !core_live && !handler_live);
	fail_queue = false;
	fail_core = -EIO;
	EXPECT(mk_vsock_transport_init() == -EIO);
	EXPECT(!queue_live && !core_live && !handler_live);
	fail_core = 0;
	fail_handler = -EINVAL;
	EXPECT(mk_vsock_transport_init() == -EINVAL);
	EXPECT(!queue_live && !core_live && !handler_live);
	fail_handler = 0;
	start();
	send_packet(1, header, 0);
	send_packet(2, MK_VSOCK_MAX_PKT_SIZE, MK_VSOCK_MAX_PKT_SIZE - header);
	EXPECT(!allocs && !delivered);
	drain();
	EXPECT(delivered == 2 && allocs == 2);
	EXPECT(received[0] == 1 && received[1] == 2);
	EXPECT(lengths[0] == header && lengths[1] == MK_VSOCK_MAX_PKT_SIZE);
	mk_vsock_transport_exit();

	start();
	mk_vsock_ipi_handler(99, MK_NET_VSOCK_PKT, 0, NULL, UINT32_MAX, NULL);
	mk_vsock_ipi_handler(MK_MSG_NETWORK, 99, 0, NULL, UINT32_MAX, NULL);
	send_packet(1, 0, 0);
	send_packet(2, header - 1, 0);
	send_packet(3, MK_VSOCK_MAX_PKT_SIZE + 1, 0);
	send_packet(4, header, UINT32_MAX);
	send_packet(5, header + 1, 2);
	EXPECT(!allocs && !queued);
	send_packet(6, header + 8, 0);
	drain();
	EXPECT(delivered == 1 && received[0] == 6);
	mk_vsock_transport_exit();

	start();
	for (i = 0; i < 65; i++)
		send_packet(i, MK_VSOCK_MAX_PKT_SIZE, MK_VSOCK_MAX_PKT_SIZE - header);
	EXPECT(!allocs);
	drain();
	EXPECT(delivered == 64 && allocs == 64);
	for (i = 0; i < 64; i++)
		EXPECT(received[i] == i);
	send_packet(70, MK_VSOCK_MAX_PKT_SIZE, MK_VSOCK_MAX_PKT_SIZE - header);
	drain();
	EXPECT(delivered == 65 && received[64] == 70);
	mk_vsock_transport_exit();

	start();
	for (i = 0; i < 130; i++)
		send_packet(i, header, 0);
	run_one();
	EXPECT(delivered == 64 && queued->pending);
	drain();
	EXPECT(delivered == 130 && runs == 3);
	for (i = 0; i < 130; i++)
		EXPECT(received[i] == i);
	mk_vsock_transport_exit();

	start();
	fail_alloc = true;
	send_packet(1, header, 0);
	send_packet(2, header, 0);
	drain();
	EXPECT(allocs == 2 && delivered == 1 && received[0] == 2);
	mk_vsock_transport_exit();
	start();
	short_copy = true;
	send_packet(1, header, 0);
	send_packet(2, header, 0);
	drain();
	EXPECT(allocs == 2 && delivered == 1 && received[0] == 2);
	mk_vsock_transport_exit();
	start();
	allocation_hook = inject;
	send_packet(1, header, 0);
	drain();
	EXPECT(delivered == 2 && received[0] == 1 && received[1] == 42);
	tail_inject = true;
	send_packet(3, header, 0);
	drain();
	EXPECT(delivered == 4 && received[2] == 3 && received[3] == 99);
	mk_vsock_transport_exit();

	start();
	send_packet(1, header, 0);
	unregister_hook = inject;
	mk_vsock_transport_exit();
	unregister_hook = NULL;
	EXPECT(!allocs && !delivered && !queue_live && !core_live && !handler_live);
	start();
	send_packet(7, header, 0);
	drain();
	EXPECT(delivered == 1 && received[0] == 7);
	mk_vsock_transport_exit();
	printf("VSOCK receive: %u checks, %u failures (FIFO, socket and IRQ boundaries modeled)\n",
	       checks, failures);
	return failures != 0;
}
