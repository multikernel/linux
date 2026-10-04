// SPDX-License-Identifier: GPL-2.0-only
/* Production CPU receive/worker/init/cleanup paths; controlled scheduler. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/list.h>

#define u64 __u64
typedef u64 mk_phys_cpu_t;
#define __init
#define GFP_ATOMIC 0
#define WQ_MEM_RECLAIM 1
#define pr_err(...) do { } while (0)
#define pr_warn(...) do { } while (0)
#define pr_info(...) do { } while (0)
#define DEFINE_MUTEX(name) bool name
struct irq_lock { bool held; };
#define DEFINE_SPINLOCK(name) struct irq_lock name
#define DEFINE_RAW_SPINLOCK(name) struct irq_lock name
#define mutex_lock(m) do { assert(!*(m)); *(m) = true; } while (0)
#define mutex_unlock(m) do { assert(*(m)); *(m) = false; } while (0)
#define spin_lock_irqsave(m, flags) \
	do { lock_irq(m, false); (flags) = 0; } while (0)
#define spin_unlock_irqrestore(m, flags) \
	do { unlock_irq(m); (void)(flags); } while (0)
#define raw_spin_lock_irqsave(m, flags) \
	do { lock_irq(m, true); (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(m, flags) spin_unlock_irqrestore(m, flags)

#include "work-types.h"

static unsigned int checks, failures, allocations, queues_live, destroyed;
static bool allocation_fails, queue_allocation_fails, registered, closing_probe;
static int register_error, close_result;
static bool online[2];
static int add_error, remove_error;
static int send_error;
static bool hard_irq;
static unsigned int rt_atomic_lock_errors;
static mk_phys_cpu_t ids[] = { 65537, 0x123456789abcdef0ULL };

static void expect(const char *name, int got, int want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: got %d, want %d\n", name, got, want);
		failures++;
	}
}

/* Model PREEMPT_RT: ordinary spin locks can sleep; raw locks cannot. */
static void lock_irq(struct irq_lock *lock, bool raw)
{
	if (hard_irq && !raw)
		rt_atomic_lock_errors++;
	assert(!lock->held);
	lock->held = true;
}

static void unlock_irq(struct irq_lock *lock)
{
	assert(lock->held);
	lock->held = false;
}

static void *kmalloc(size_t n, unsigned int flags)
{
	void *p;

	if (allocation_fails)
		return NULL;
	p = malloc(n);
	assert(p);
	allocations++;
	return p;
}

static void kfree(void *p)
{
	if (p) {
		assert(allocations);
		allocations--;
		free(p);
	}
}

struct work_struct { void (*func)(struct work_struct *work); };
struct workqueue_struct {
	bool ordered;
	unsigned int nr;
	struct work_struct *jobs[8];
};
static struct workqueue_struct system_queue;
static struct workqueue_struct *cpu_queue;
#define INIT_WORK(work, fn) ((work)->func = (fn))

static __maybe_unused struct workqueue_struct *alloc_ordered_workqueue(const char *name,
						       unsigned int flags)
{
	if (queue_allocation_fails)
		return NULL;
	cpu_queue = calloc(1, sizeof(*cpu_queue));
	assert(cpu_queue);
	cpu_queue->ordered = true;
	queues_live++;
	return cpu_queue;
}

static bool queue_work(struct workqueue_struct *queue, struct work_struct *work)
{
	assert(queue && queue->nr < 8);
	queue->jobs[queue->nr++] = work;
	return true;
}

static __maybe_unused void schedule_work(struct work_struct *work)
{
	queue_work(&system_queue, work);
}

/* A legal adverse schedule for unordered work; ordered queues must use FIFO. */
static void run_one(struct workqueue_struct *queue)
{
	unsigned int i, selected;
	struct work_struct *work;

	assert(queue->nr);
	selected = queue->ordered ? 0 : queue->nr - 1;
	work = queue->jobs[selected];
	for (i = selected; i + 1 < queue->nr; i++)
		queue->jobs[i] = queue->jobs[i + 1];
	queue->nr--;
	work->func(work);
}

static void drain(struct workqueue_struct *queue)
{
	while (queue && queue->nr)
		run_one(queue);
}

static __maybe_unused void destroy_workqueue(struct workqueue_struct *queue)
{
	drain(queue);
	assert(queues_live && queue == cpu_queue);
	queues_live--;
	destroyed++;
	cpu_queue = NULL;
	free(queue);
}

static unsigned int cpu_index(mk_phys_cpu_t id)
{
	assert(id == ids[0] || id == ids[1]);
	return id == ids[0] ? 0 : 1;
}

static int mk_do_cpu_add(mk_phys_cpu_t id, u32 numa, u32 flags)
{
	if (!add_error)
		online[cpu_index(id)] = true;
	return add_error;
}

static int mk_do_cpu_remove(mk_phys_cpu_t id)
{
	if (!remove_error)
		online[cpu_index(id)] = false;
	return remove_error;
}

struct reply {
	int to;
	u64 id;
	struct mk_resource_ack ack;
};
static struct reply replies[8];
static unsigned int nr_replies;

static int mk_send_message_id(int to, u32 type, u32 subtype, u64 id,
			     const void *payload, u32 len)
{
	struct reply *reply = &replies[nr_replies++];

	assert(type == MK_MSG_RESOURCE && subtype == MK_RES_ACK);
	assert(len == sizeof(reply->ack) && nr_replies <= 8);
	reply->to = to;
	reply->id = id;
	memcpy(&reply->ack, payload, len);
	return send_error;
}

static void mk_resource_msg_handler(u32 type, u32 subtype, u64 id,
				    void *payload, u32 len, void *ctx)
{
	abort(); /* Dispatch is tested separately; this test calls receive handlers. */
}

static int mk_handle_cpu_add(struct mk_cpu_resource_payload *payload, u32 len, u64 id);
static int mk_register_msg_handler(u32 type,
		void (*fn)(u32, u32, u64, void *, u32, void *), void *ctx)
{
	registered = !register_error;
	return register_error;
}

static int mk_unregister_msg_handler(u32 type,
		void (*fn)(u32, u32, u64, void *, u32, void *))
{
	struct mk_cpu_resource_payload payload = { .cpu_id = 65537 };

	/* Model an already-entered callback attempting to queue during cleanup. */
	if (closing_probe) {
		hard_irq = true;
		close_result = mk_handle_cpu_add(&payload, sizeof(payload), 99);
		hard_irq = false;
	}
	registered = false;
	return 0;
}

#include "work-production.h"

static int receive_cpu(bool add, struct mk_cpu_resource_payload *payload, u32 len, u64 id)
{
	int ret;

	hard_irq = true;
	ret = add ? mk_handle_cpu_add(payload, len, id) : mk_handle_cpu_remove(payload, len, id);
	hard_irq = false;
	return ret;
}

/* Test calls enter the real receive handlers with hard-IPI context modeled. */
#define mk_handle_cpu_add(p, len, id) receive_cpu(true, p, len, id)
#define mk_handle_cpu_remove(p, len, id) receive_cpu(false, p, len, id)

static struct workqueue_struct *active_queue(void)
{
	return cpu_queue ? cpu_queue : &system_queue;
}

static void reset(void)
{
	drain(&system_queue);
	assert(!cpu_queue && !allocations && !queues_live);
	allocation_fails = queue_allocation_fails = registered = closing_probe = false;
	register_error = close_result = add_error = remove_error = send_error = 0;
	nr_replies = destroyed = 0;
	online[0] = online[1] = false;
}

int main(void)
{
	struct mk_cpu_resource_payload payload = {
		.cpu_id = 65537, .sender_instance_id = 3,
	};
	unsigned int i;

	reset();
	expect("init", mk_hotplug_init(), 0);
	/* Leave the older add queued while its requester can time out. */
	expect("receive older add", mk_handle_cpu_add(&payload, sizeof(payload), 11), 0);
	expect("receive newer remove", mk_handle_cpu_remove(&payload, sizeof(payload), 12), 0);
	send_error = -EIO;
	run_one(active_queue());
	expect("older add completes before remove", nr_replies && replies[0].id == 11, 1);
	send_error = 0;
	drain(active_queue());
	expect("newer remove leaves CPU offline", online[0], 0);
	expect("remove ACK follows completed add", replies[1].id == 12, 1);
	expect("workers release both allocations", allocations, 0);
	mk_hotplug_cleanup();
	expect("cleanup destroys CPU queue", destroyed, 1);
	expect("cleanup releases queue", queues_live, 0);
	reset();

	expect("init for remove/add", mk_hotplug_init(), 0);
	online[0] = true;
	expect("receive older remove", mk_handle_cpu_remove(&payload, sizeof(payload), 13), 0);
	expect("receive newer add", mk_handle_cpu_add(&payload, sizeof(payload), 14), 0);
	drain(active_queue());
	expect("newer add leaves CPU online", online[0], 1);
	expect("older remove ACK first", replies[0].id == 13, 1);
	remove_error = -EBUSY;
	expect("queue failed remove", mk_handle_cpu_remove(&payload, sizeof(payload), 15), 0);
	drain(active_queue());
	expect("failed remove leaves CPU online", online[0], 1);
	expect("remove error echoed", (int)replies[2].ack.result, -EBUSY);
	mk_hotplug_cleanup();
	reset();

	expect("init for independent CPUs", mk_hotplug_init(), 0);
	for (i = 0; i < 2; i++) {
		payload.cpu_id = ids[i];
		expect("receive full-width CPU add",
		       mk_handle_cpu_add(&payload, sizeof(payload), 21 + i), 0);
	}
	drain(active_queue());
	expect("CPU additions both execute", online[0] && online[1], 1);
	expect("first ACK preserves ID", replies[0].id == 21, 1);
	expect("second ACK preserves sparse resource", replies[1].ack.resource_id == ids[1], 1);
	expect("ACK targets requester", replies[1].to, 3);
	payload.cpu_id = ids[0];
	allocation_fails = true;
	expect("work allocation error", mk_handle_cpu_add(&payload, sizeof(payload), 23), -ENOMEM);
	allocation_fails = false;
	expect("short add", mk_handle_cpu_add(&payload, 0, 24), -EINVAL);
	expect("short remove", mk_handle_cpu_remove(&payload, 0, 25), -EINVAL);
	add_error = -EPERM;
	expect("queue failed add", mk_handle_cpu_add(&payload, sizeof(payload), 26), 0);
	drain(active_queue());
	expect("worker error echoed", (int)replies[2].ack.result, -EPERM);
	expect("worker error preserves request ID", replies[2].id == 26, 1);
	mk_hotplug_cleanup();
	reset();

	expect("init for teardown", mk_hotplug_init(), 0);
	expect("queue before cleanup", mk_handle_cpu_add(&payload, sizeof(payload), 31), 0);
	closing_probe = true;
	mk_hotplug_cleanup();
	expect("cleanup closes admission before unregister", close_result, -ESHUTDOWN);
	expect("cleanup drains already admitted CPU work", online[0], 1);
	expect("cleanup releases admitted/rejected work", allocations, 0);
	expect("cleanup leaves no CPU queue", queues_live, 0);
	expect("late callback refused",
	       mk_handle_cpu_add(&payload, sizeof(payload), 32), -ESHUTDOWN);
	expect("late callback releases allocation", allocations, 0);
	reset();

	queue_allocation_fails = true;
	expect("queue allocation failure", mk_hotplug_init(), -ENOMEM);
	expect("failed queue never registers handler", registered, 0);
	mk_hotplug_cleanup();
	reset();
	register_error = -EIO;
	expect("handler registration failure", mk_hotplug_init(), -EIO);
	expect("registration failure frees queue", queues_live, 0);
	expect("registration failure closes CPU admission",
	       mk_handle_cpu_remove(&payload, sizeof(payload), 41), -ESHUTDOWN);
	mk_hotplug_cleanup();
	reset();
	expect("hard-IPI admission never takes an RT sleeping lock", rt_atomic_lock_errors, 0);
	printf("CPU work ordering: %u checks, %u failures\n", checks, failures);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
