// SPDX-License-Identifier: GPL-2.0-only
/* See README.ack: real pending/dispatch code, deterministic kernel boundaries. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/list.h>
#include <linux/err.h>

/* tools/ uses uint64_t; production printk formats use the kernel's __u64. */
#define u64 __u64
#define U64_MAX (~(u64)0)
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
static bool allocation_fails;
#define kzalloc(n, flags) ((void)(flags), allocation_fails ? NULL : calloc(1, n))
#define kmalloc(n, flags) ((void)(flags), allocation_fails ? NULL : malloc(n))
#define kfree free
#define pr_err(...) fprintf(stderr, __VA_ARGS__)
#define pr_warn(...) fprintf(stderr, __VA_ARGS__)
#define pr_info(...) do { } while (0)
#define pr_debug(...) do { } while (0)
static bool test_hardirq;
#define DEFINE_SPINLOCK(name) bool name
#define spin_lock_irqsave(lock, flags) \
	do { assert(!test_hardirq); assert(!*(lock)); *(lock) = true; (flags) = 0; } while (0)
#define spin_unlock_irqrestore(lock, flags) \
	do { assert(*(lock)); *(lock) = false; (void)(flags); } while (0)
typedef struct { bool held; } test_raw_lock_t;
#define DEFINE_RAW_SPINLOCK(name) test_raw_lock_t name
static void test_raw_lock(test_raw_lock_t *lock) { assert(!lock->held); lock->held = true; }
static void test_raw_unlock(test_raw_lock_t *lock) { assert(lock->held); lock->held = false; }
#define raw_spin_lock_irqsave(lock, flags) \
	do { test_raw_lock(lock); (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(lock, flags) \
	do { test_raw_unlock(lock); (void)(flags); } while (0)
#define msecs_to_jiffies(ms) (ms)
#define DECLARE_WAIT_QUEUE_HEAD(name) int name
#define wake_up_all(wait) ((void)(wait))
/* This fixture executes one job at a time; the multi-job drain is tested separately. */
#define wait_event(wait, condition) do { (void)(wait); assert(condition); } while (0)

struct completion {
	unsigned int done;
};

static void (*at_timeout)(void);
static void (*at_completion)(void);

static void init_completion(struct completion *c)
{
	c->done = 0;
}

static void complete(struct completion *c)
{
	c->done++;
}

static unsigned long wait_for_completion_timeout(struct completion *c,
						 unsigned long timeout)
{
	if (c->done) {
		c->done--;
		if (at_completion) {
			void (*hook)(void) = at_completion;

			at_completion = NULL;
			hook();
		}
		return timeout ? timeout : 1;
	}
	/* Inject an ACK after timeout is decided, before pending list removal. */
	if (at_timeout) {
		void (*hook)(void) = at_timeout;

		at_timeout = NULL;
		hook();
	}
	return 0;
}

#include "ack-types.h"

static struct mk_ipi_data sent;
static int sent_to;
static int send_error;

/* Transport boundary: capture real mk_send_message() output for replay. */
static int multikernel_send_ipi_data(int instance_id, void *data,
				     size_t size, unsigned long type)
{
	assert(size <= sizeof(sent.buffer));
	sent_to = instance_id;
	sent.type = type;
	sent.data_size = size;
	memcpy(sent.buffer, data, size);
	return send_error;
}

#include "ack-messaging.h"

/* Only the hardware mutation, scheduler and final parking are substituted. */
struct work_struct {
	void (*func)(struct work_struct *work);
};
struct workqueue_struct { int unused; };
static struct workqueue_struct cpu_queue;

static struct work_struct *queued;
static int mutation_result, mutations;
static jmp_buf parked;
static struct { int id; } self = { .id = 65537 }, *mk_self = &self;

static int mutate(void)
{
	mutations++;
	return mutation_result;
}

static bool mk_overlay_mutex;
#define mutex_lock(m) do { assert(!*(m)); *(m) = true; } while (0)
#define mutex_trylock(m) (*(m) ? false : (*(m) = true))
#define mutex_unlock(m) do { assert(*(m)); *(m) = false; } while (0)

#define mk_do_cpu_add(...) mutate()
#define mk_do_cpu_remove(...) mutate()
#define mk_do_mem_add(...) mutate()
#define mk_do_mem_remove(...) mutate()
#define mk_do_device_add(...) mutate()
#define mk_do_device_remove(...) mutate()
#define PCI_SLOT(devfn) (((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn) ((devfn) & 7)
#define strscpy(dst, src, size) snprintf(dst, size, "%s", src)
typedef u64 mk_phys_cpu_t;

static void __noreturn mk_enter_pool_state(void *unused)
{
	longjmp(parked, 1);
}

static void smp_call_function(void (*fn)(void *), void *arg, int wait)
{
	assert(fn == mk_enter_pool_state && !wait);
}

static void schedule_work(struct work_struct *work)
{
	assert(!queued);
	queued = work;
}

static bool queue_work(struct workqueue_struct *wq, struct work_struct *work)
{
	assert(wq == &cpu_queue);
	schedule_work(work);
	return true;
}

static void unexpected_work(struct work_struct *work)
{
	abort();
}

#define INIT_WORK(work, fn) ((work)->func = (fn))
#define mk_halted_work_fn unexpected_work

#include "ack-resource.h"
#include "ack-system.h"

static int failures;

static void expect(const char *kind, const char *name, int got, int want)
{
	if (got != want) {
		fprintf(stderr, "FAIL %s: %s: got %d, want %d\n",
			kind, name, got, want);
		failures++;
	} else {
		printf("PASS %s: %s\n", kind, name);
	}
}

static u64 current_id;

static struct mk_pending_msg *pending(u32 type, u32 op)
{
	struct mk_pending_msg *p = mk_msg_pending_add(type, op, 65537);

	assert(!IS_ERR(p));
	current_id = mk_msg_pending_id(p);
	assert(current_id);
	return p;
}

static int finish(struct mk_pending_msg *p)
{
	int result = mk_msg_pending_wait(p, 0);

	assert(list_empty(&mk_pending_msgs));
	assert(!mk_pending_msgs_lock.held);
	return result;
}

static void dispatch(struct mk_ipi_data *data)
{
	struct mk_msg_type_handler handler = {
		.msg_type = data->type,
		.msg_handler = data->type == MK_MSG_SYSTEM ?
			mk_system_msg_handler : mk_resource_msg_handler,
	};

	mk_message_type_ipi_callback(data, &handler);
}

static void reply(u32 type, u32 op, u64 resource, int result, u64 id, bool short_ack)
{
	struct mk_resource_ack ack = {
		.operation = op, .result = result, .resource_id = resource,
	};
	struct mk_ipi_data data = { .sender_cpu = 7, .type = type };
	struct mk_message *msg = (struct mk_message *)data.buffer;

	msg->msg_type = type;
	msg->msg_subtype = type == MK_MSG_SYSTEM ? MK_SYS_SHUTDOWN_ACK : MK_RES_ACK;
	msg->msg_id = id;
	msg->payload_len = sizeof(ack) - short_ack;
	memcpy(msg->payload, &ack, sizeof(ack));
	data.data_size = sizeof(*msg) + msg->payload_len;
	dispatch(&data);
}

static void cpu_ack(void)
{
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, 0, current_id, false);
}

static void cpu_error_ack(void)
{
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, -EIO, current_id, false);
}

static unsigned int callbacks;

static void count_callback(u32 type, u32 subtype, u64 id, void *payload, u32 len, void *ctx)
{
	callbacks++;
}

static void completion_regressions(void)
{
	struct mk_pending_msg *p;
	struct mk_ipi_data data = { .type = MK_MSG_RESOURCE };
	struct mk_message *msg = (struct mk_message *)data.buffer;
	struct mk_msg_type_handler handler = {
		.msg_type = MK_MSG_RESOURCE, .msg_handler = count_callback,
	};

	/* A completion token is consumed by the waiter, not by duplicates. */
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_ack();
	cpu_error_ack();
	expect("REGRESSION", "duplicate must preserve first success", finish(p), 0);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_error_ack();
	cpu_ack();
	expect("REGRESSION", "duplicate must preserve first error", finish(p), -EIO);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_ack();
	at_completion = cpu_error_ack;
	expect("REGRESSION", "duplicate after waiter consumes token", finish(p), 0);

	p = pending(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN);
	reply(MK_MSG_SYSTEM, MK_RES_CPU_ADD, 65537, 0, current_id, false);
	expect("REGRESSION", "shutdown operation mismatch", finish(p), -ETIMEDOUT);

	/* Reject a confused outer/inner family before calling any handler. */
	msg->msg_type = MK_MSG_SYSTEM;
	msg->payload_len = 0;
	data.data_size = sizeof(*msg);
	mk_message_type_ipi_callback(&data, &handler);
	expect("REGRESSION", "outer/inner family mismatch", callbacks, 0);
	callbacks = 0;
	msg->msg_type = MK_MSG_RESOURCE;
	mk_message_type_ipi_callback(&data, &handler);
	expect("REGRESSION", "matching family reaches handler", callbacks, 1);
}

static void regressions(void)
{
	const struct {
		const char *name;
		u32 type, op;
	} stale[] = {
		{ "delayed CPU_ADD A must not complete B", MK_MSG_RESOURCE, MK_RES_CPU_ADD },
		{ "delayed CPU_REMOVE A must not complete B", MK_MSG_RESOURCE, MK_RES_CPU_REMOVE },
		{ "delayed SHUTDOWN A must not complete B", MK_MSG_SYSTEM, MK_SYS_SHUTDOWN },
	};
	struct mk_pending_msg *p;
	u64 old_id;
	size_t i;

	/* Fix: allocate and echo distinct request IDs, then match them. */
	for (i = 0; i < ARRAY_SIZE(stale); i++) {
		p = pending(stale[i].type, stale[i].op);
		assert(!mk_send_message_id(1, stale[i].type, stale[i].op, current_id, NULL, 0));
		old_id = ((struct mk_message *)sent.buffer)->msg_id;
		assert(finish(p) == -ETIMEDOUT);
		p = pending(stale[i].type, stale[i].op);
		assert(!mk_send_message_id(1, stale[i].type, stale[i].op, current_id, NULL, 0));
		reply(stale[i].type, stale[i].op, 65537, 0, old_id, false);
		expect("REGRESSION", stale[i].name, finish(p), -ETIMEDOUT);
	}

	/* Zero replies from an older responder cannot complete a new request. */
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, 0, 0, false);
	expect("REGRESSION", "zero msg_id must not authorize", finish(p), -ETIMEDOUT);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, 0, U64_MAX, false);
	expect("REGRESSION", "unissued msg_id must not authorize", finish(p), -ETIMEDOUT);

}

static void characterizations(void)
{
	const struct {
		const char *name;
		u32 type, op;
		u64 resource;
		bool short_ack;
	} reject[] = {
		{ "resource operation mismatch", MK_MSG_RESOURCE, MK_RES_CPU_REMOVE, 65537, false },
		{ "resource ID mismatch", MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65538, false },
		{ "short resource ACK", MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, true },
	};
	struct mk_pending_msg *p;
	size_t i;

	/* Isolate type from dispatch validation. */
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	mk_msg_pending_complete(MK_MSG_SYSTEM, MK_RES_CPU_ADD, 65537, current_id, 0);
	expect("CHARACTERIZATION", "message type mismatch", finish(p), -ETIMEDOUT);

	/* Breaks if matching loses a tuple check or short-ACK validation. */
	for (i = 0; i < ARRAY_SIZE(reject); i++) {
		p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
		reply(reject[i].type, reject[i].op, reject[i].resource,
		      0, current_id, reject[i].short_ack);
		expect("CHARACTERIZATION", reject[i].name, finish(p), -ETIMEDOUT);
	}
	p = pending(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN);
	reply(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN, 65537, 0, current_id, true);
	expect("CHARACTERIZATION", "short shutdown ACK", finish(p), -ETIMEDOUT);

	/* Breaks if wait forgets cleanup, ignores completion or changes its result. */
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	expect("CHARACTERIZATION", "timeout removes pending A", finish(p), -ETIMEDOUT);
	cpu_ack(); /* Late reply after free, with no replacement: must be harmless. */
	assert(list_empty(&mk_pending_msgs));
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	expect("CHARACTERIZATION", "ACK after cleanup is not saved for B", finish(p), -ETIMEDOUT);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	at_timeout = cpu_ack;
	expect("CHARACTERIZATION", "ACK after timeout decision still cleans up",
	       finish(p), -ETIMEDOUT);
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	cpu_ack();
	cpu_ack();
	expect("CHARACTERIZATION", "identical duplicate returns success", finish(p), 0);
	cpu_ack(); /* Also harmless after a successful wait frees the request. */
	assert(list_empty(&mk_pending_msgs));
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, -EIO, current_id, false);
	expect("CHARACTERIZATION", "matching error is returned", finish(p), -EIO);
}

/* Keep longjmp at the parking boundary, outside the test-case loop. */
static void run_work(struct work_struct *work, bool parks)
{
	if (!setjmp(parked)) {
		if (work)
			work->func(work);
		else
			mk_halt_to_pool();
		assert(!parks);
	} else {
		assert(parks);
		/* The parked fixture kernel is discarded before the next case. */
		mk_overlay_mutex = false;
	}
}

static void worker_regressions(void)
{
	const struct {
		const char *name;
		u32 type, op;
	} cases[] = {
		{ "CPU add worker echo", MK_MSG_RESOURCE, MK_RES_CPU_ADD },
		{ "CPU remove worker echo", MK_MSG_RESOURCE, MK_RES_CPU_REMOVE },
		{ "memory add worker echo", MK_MSG_RESOURCE, MK_RES_MEM_ADD },
		{ "memory remove worker echo", MK_MSG_RESOURCE, MK_RES_MEM_REMOVE },
		{ "device add worker echo", MK_MSG_RESOURCE, MK_RES_DEVICE_ADD },
		{ "device remove worker echo", MK_MSG_RESOURCE, MK_RES_DEVICE_REMOVE },
		{ "shutdown worker echo", MK_MSG_SYSTEM, MK_SYS_SHUTDOWN },
	};
	const u64 ids[] = { 0, 0x123456789abcdef0ULL, 0 /* allocated below */ };
	struct mk_cpu_resource_payload cpu = { .cpu_id = 65537, .sender_instance_id = 3 };
	struct mk_mem_resource_payload mem = { .start_pfn = 65537, .sender_instance_id = 3 };
	struct mk_device_resource_payload dev = {
		.domain = 1, .devfn = 1, .sender_instance_id = 3,
	};
	struct mk_shutdown_payload shutdown = { .sender_instance_id = 3 };
	size_t i, j;

	/* The existing 64-bit wire ABI has an unaligned flexible payload. */
	assert(sizeof(struct mk_message) == 24);
	assert(offsetof(struct mk_message, payload) == 20);
	assert(sizeof(cpu) == 24 && sizeof(mem) == 32 && sizeof(dev) == 76);
	assert(sizeof(struct mk_resource_ack) == 16 && sizeof(shutdown) == 8);

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		for (j = 0; j < ARRAY_SIZE(ids); j++) {
			struct mk_ipi_data request = { .type = cases[i].type };
			struct mk_ipi_data before;
			struct mk_message *msg = (void *)request.buffer;
			struct mk_resource_ack ack;
			struct work_struct *work;
			struct mk_pending_msg *p = NULL;
			void *payload;
			u32 len;
			u64 id = ids[j];
			int result;

			/* Each case represents a fresh receiver, before shutdown closes it. */
			mk_hotplug_accepting = true;

			if (i < 2) {
				payload = &cpu;
				len = sizeof(cpu);
			} else if (i < 4) {
				payload = &mem;
				len = sizeof(mem);
			} else if (i < 6) {
				payload = &dev;
				len = sizeof(dev);
			} else {
				payload = &shutdown;
				len = sizeof(shutdown);
			}
			if (j == 2) {
				p = pending(cases[i].type, cases[i].op);
				id = mk_msg_pending_id(p);
			}
			assert(!mk_send_message_id(1, cases[i].type, cases[i].op,
						   id, payload, len));
			request = sent;
			if (j == 1) {
				/* A large extension must not overrun the local decoder. */
				msg = (void *)request.buffer;
				memset(msg->payload + len, 0xa5,
				       MK_MAX_DATA_SIZE - sizeof(*msg) - len);
				msg->payload_len = MK_MAX_DATA_SIZE - sizeof(*msg);
				request.data_size = MK_MAX_DATA_SIZE;
			}
			before = request;
			mutations = 0;
			mutation_result = j ? -EIO : 0;
			result = i == 6 ? 0 : mutation_result;
			dispatch(&request);
			assert(queued);
			expect("DECODE", "receive buffer unchanged",
			       memcmp(&request, &before, sizeof(request)) == 0, 1);
			work = queued;
			queued = NULL;
			/* A worker must retain the ID after the receive buffer is reused. */
			memset(&request, 0xa5, sizeof(request));
			memset(&sent, 0, sizeof(sent));
			run_work(work, i == 6);
			msg = (void *)sent.buffer;
			/* Test code must also decode the wire without unaligned reads. */
			memcpy(&ack, msg->payload, sizeof(ack));
			assert(sent_to == 3 && msg->msg_type == cases[i].type);
			assert(msg->msg_subtype == (i == 6 ? MK_SYS_SHUTDOWN_ACK : MK_RES_ACK));
			assert(msg->payload_len == sizeof(ack));
			assert(ack.operation == cases[i].op && ack.resource_id == 65537);
			assert((int)ack.result == result);
			assert(mutations == (i == 6 ? 0 : 1));
			expect("WORKER", cases[i].name, msg->msg_id == id, 1);
			if (p) {
				dispatch(&sent);
				expect("ROUNDTRIP", cases[i].name, finish(p), result);
			}
		}
		/* Short and empty requests must not queue work or read missing fields. */
		for (j = 0; j < 2; j++) {
			u8 bytes[sizeof(mem)] = {};

			assert(!queued);
			assert(!mk_send_message_id(1, cases[i].type, cases[i].op,
						   1, bytes, j));
			dispatch(&sent);
			expect("DECODE", "short request queues no work", queued == NULL, 1);
		}
	}
	run_work(NULL, true);
	expect("WORKER", "voluntary HALTED remains a zero-ID notification",
	       ((struct mk_message *)sent.buffer)->msg_id == 0 && sent_to == 0 &&
	       ((struct mk_message *)sent.buffer)->msg_subtype == MK_SYS_HALTED, 1);
}

static void pci_key_regressions(void)
{
	const u16 domains[] = { 0x8000, 0xffff };
	const u32 ops[] = { MK_RES_DEVICE_ADD, MK_RES_DEVICE_REMOVE };
	struct mk_device_resource_payload payload = { .devfn = 1, .sender_instance_id = 3 };
	size_t i, j;

	for (i = 0; i < ARRAY_SIZE(domains); i++) {
		for (j = 0; j < ARRAY_SIZE(ops); j++) {
			struct mk_pending_msg *p;
			struct work_struct *work;
			u32 resource_id = ((u32)domains[i] << 16) | payload.devfn;

			payload.domain = domains[i];
			p = mk_msg_pending_add(MK_MSG_RESOURCE, ops[j], resource_id);
			assert(!IS_ERR(p));
			assert(!mk_send_message_id(1, MK_MSG_RESOURCE, ops[j],
						   mk_msg_pending_id(p), &payload,
						   sizeof(payload)));
			dispatch(&sent);
			assert(queued);
			work = queued;
			queued = NULL;
			mutation_result = 0;
			run_work(work, false);
			dispatch(&sent);
			expect("REGRESSION", "high PCI domain round trip", finish(p), 0);
		}
	}
}

static void halted_decode_regression(void)
{
	struct mk_resource_ack ack = { .resource_id = 65537 };
	struct mk_ipi_data before;
	struct mk_halted_work *work;
	size_t len;

	assert(!mk_send_message(0, MK_MSG_SYSTEM, MK_SYS_HALTED, &ack, sizeof(ack)));
	before = sent;
	dispatch(&sent);
	assert(queued);
	work = container_of(queued, struct mk_halted_work, work);
	expect("DECODE", "HALTED retains instance ID", work->instance_id, 65537);
	expect("DECODE", "HALTED receive buffer unchanged",
	       memcmp(&sent, &before, sizeof(sent)) == 0, 1);
	queued = NULL;
	free(work);

	for (len = 0; len < sizeof(ack); len++) {
		assert(!mk_send_message(0, MK_MSG_SYSTEM, MK_SYS_HALTED, &ack, len));
		dispatch(&sent);
		assert(!queued);
	}
	expect("DECODE", "short HALTED queues no work", queued == NULL, 1);
}

static void failure_regressions(void)
{
	struct mk_pending_msg *p, *other;
	u64 old_id;
	int ret;

	allocation_fails = true;
	p = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537);
	assert(IS_ERR(p));
	expect("FAILURE", "pending allocation error", PTR_ERR(p), -ENOMEM);
	allocation_fails = false;
	assert(list_empty(&mk_pending_msgs));

	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	old_id = current_id;
	other = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	assert(current_id != old_id);
	reply(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537, 0, old_id, false);
	expect("REGRESSION", "same-tuple outstanding requests are distinct",
	       mk_msg_pending_wait(p, 0), 0);
	expect("REGRESSION", "other outstanding request remains pending",
	       finish(other), -ETIMEDOUT);

	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	allocation_fails = true;
	ret = mk_send_message_id(1, MK_MSG_RESOURCE, MK_RES_CPU_ADD, current_id, NULL, 0);
	expect("FAILURE", "send allocation error", ret, -ENOMEM);
	allocation_fails = false;
	mk_msg_pending_cancel(p);
	cpu_ack();
	assert(list_empty(&mk_pending_msgs));

	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	send_error = -EIO;
	ret = mk_send_message_id(1, MK_MSG_RESOURCE, MK_RES_CPU_ADD, current_id, NULL, 0);
	expect("FAILURE", "transport error", ret, -EIO);
	/* Even a reply racing local cleanup must not leave a dangling entry. */
	cpu_ack();
	mk_msg_pending_cancel(p);
	cpu_ack();
	assert(list_empty(&mk_pending_msgs) && !mk_pending_msgs_lock.held);
	send_error = 0;
	assert(!mk_send_message(1, MK_MSG_NETWORK, MK_NET_VSOCK_PKT, NULL, 0));
	expect("REGRESSION", "uncorrelated sender keeps zero ID",
	       ((struct mk_message *)sent.buffer)->msg_id == 0, 1);

	/* Last: forcing exhaustion intentionally prevents all subsequent adds. */
	mk_last_msg_id = U64_MAX - 1;
	p = pending(MK_MSG_RESOURCE, MK_RES_CPU_ADD);
	expect("FAILURE", "last representable ID is usable", current_id == U64_MAX, 1);
	cpu_ack();
	expect("FAILURE", "full-width ID matches", finish(p), 0);
	p = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 65537);
	assert(IS_ERR(p));
	expect("FAILURE", "ID exhaustion refuses reuse", PTR_ERR(p), -EOVERFLOW);
	assert(mk_last_msg_id == U64_MAX);
	assert(list_empty(&mk_pending_msgs) && !mk_pending_msgs_lock.held);
}

int main(int argc, char **argv)
{
	struct mk_pending_msg *irq_pending;

	/* Real ACK completion is dispatched by a hard IPI, not a threaded IRQ. */
	irq_pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 7);
	assert(!IS_ERR(irq_pending));
	test_hardirq = true;
	mk_msg_pending_complete(MK_MSG_RESOURCE, MK_RES_CPU_ADD, 7,
				mk_msg_pending_id(irq_pending), 0);
	test_hardirq = false;
	assert(mk_msg_pending_wait(irq_pending, 1) == 0);
	assert(list_empty(&mk_pending_msgs) && !mk_pending_msgs_lock.held);

	/* Queue creation/lifetime is exercised by cpu_work_test, not this fixture. */
	mk_cpu_hotplug_wq = &cpu_queue;
	mk_hotplug_accepting = true;

	if (argc > 2 || (argc == 2 && strcmp(argv[1], "regression") &&
			strcmp(argv[1], "characterization") &&
			strcmp(argv[1], "completion") && strcmp(argv[1], "workers") &&
			strcmp(argv[1], "failure"))) {
		fprintf(stderr, "usage: ack_test [mode] (see README.ack)\n");
		return 2;
	}
	if (argc == 1 || !strcmp(argv[1], "regression") ||
	    !strcmp(argv[1], "completion"))
		completion_regressions();
	if (argc == 1 || !strcmp(argv[1], "regression"))
		regressions();
	if (argc == 1 || !strcmp(argv[1], "regression"))
		pci_key_regressions();
	if (argc == 1 || !strcmp(argv[1], "characterization"))
		characterizations();
	if (argc == 1 || !strcmp(argv[1], "workers"))
		worker_regressions();
	if (argc == 1 || !strcmp(argv[1], "workers"))
		halted_decode_regression();
	if (argc == 1 || !strcmp(argv[1], "failure"))
		failure_regressions();
	return failures ? 1 : 0;
}
