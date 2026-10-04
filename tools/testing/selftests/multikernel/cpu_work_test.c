// SPDX-License-Identifier: GPL-2.0-only
/* Production CPU receive/worker/init/cleanup paths; controlled scheduler. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <setjmp.h>
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
#define mutex_trylock(m) (*(m) ? false : (*(m) = true))
static bool mk_overlay_mutex;
#define spin_lock_irqsave(m, flags) \
	do { lock_irq(m, false); (flags) = 0; } while (0)
#define spin_unlock_irqrestore(m, flags) \
	do { unlock_irq(m); (void)(flags); } while (0)
#define raw_spin_lock_irqsave(m, flags) \
	do { lock_irq(m, true); (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(m, flags) spin_unlock_irqrestore(m, flags)
#define DECLARE_WAIT_QUEUE_HEAD(name) int name
#define wake_up_all(wait) ((void)(wait))
#define wait_event(wait, condition) \
	do { (void)(wait); while (!(condition)) run_wait_jobs(); } while (0)
#define PCI_SLOT(devfn) (((devfn) >> 3) & 0x1f)
#define PCI_FUNC(devfn) ((devfn) & 7)
#define strscpy(dst, src, size) snprintf(dst, size, "%s", src)

#include "work-types.h"

static unsigned int checks, failures, allocations, queues_live, destroyed;
static bool allocation_fails, queue_allocation_fails, registered, closing_probe;
static int register_error, close_result;
static int system_register_error, kernfs_error;
static unsigned int messaging_cleanups;
static bool online[2];
static int add_error, remove_error;
static int send_error;
static bool hard_irq;
static unsigned int rt_atomic_lock_errors;
static unsigned int unlocked_mutations;
static mk_phys_cpu_t ids[] = { 65537, 0x123456789abcdef0ULL };
static bool memory_added, device_added, shutdown_sent, parked_cpus;
static unsigned int shutdown_jobs_pending;
static bool probe_at_wait, probe_system_registration;
static int wait_probe_results[3], system_probe_result;
static jmp_buf parked;
static struct { int id; } self = { .id = 7 }, *mk_self = &self;

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
#define kmalloc_obj(obj, flags) kmalloc(sizeof(obj), flags)

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
	unlocked_mutations += !mk_overlay_mutex;
	if (!add_error)
		online[cpu_index(id)] = true;
	return add_error;
}

static int mk_do_cpu_remove(mk_phys_cpu_t id)
{
	unlocked_mutations += !mk_overlay_mutex;
	if (!remove_error)
		online[cpu_index(id)] = false;
	return remove_error;
}

static int mk_do_mem_add(u64 pfn, u64 pages, u32 node, u32 type)
{
	unlocked_mutations += !mk_overlay_mutex;
	memory_added = true;
	return 0;
}

static int mk_do_mem_remove(u64 pfn, u64 pages)
{
	unlocked_mutations += !mk_overlay_mutex;
	memory_added = false;
	return 0;
}

static int mk_do_device_add(u16 domain, u8 bus, u8 devfn, const char *driver, u32 flags)
{
	unlocked_mutations += !mk_overlay_mutex;
	device_added = true;
	return 0;
}

static int mk_do_device_remove(u16 domain, u8 bus, u8 devfn)
{
	unlocked_mutations += !mk_overlay_mutex;
	device_added = false;
	return 0;
}

struct reply {
	int to;
	u64 id;
	struct mk_resource_ack ack;
};
static struct reply replies[32];
static unsigned int nr_replies;

static int mk_send_message_id(int to, u32 type, u32 subtype, u64 id,
			     const void *payload, u32 len)
{
	struct reply *reply;

	if (type == MK_MSG_SYSTEM) {
		assert(subtype == MK_SYS_SHUTDOWN_ACK && id == 51 && to == 3);
		shutdown_sent = true;
		shutdown_jobs_pending = (cpu_queue ? cpu_queue->nr : 0) + system_queue.nr;
		return send_error;
	}
	reply = &replies[nr_replies++];
	assert(type == MK_MSG_RESOURCE && subtype == MK_RES_ACK);
	assert(len == sizeof(reply->ack) && nr_replies <= 32);
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
static int mk_handle_mem_add(struct mk_mem_resource_payload *payload, u32 len, u64 id);
static int mk_handle_device_add(struct mk_device_resource_payload *payload, u32 len, u64 id);
static void run_wait_jobs(void);
static int mk_register_msg_handler(u32 type,
		void (*fn)(u32, u32, u64, void *, u32, void *), void *ctx)
{
	if (type == MK_MSG_SYSTEM && probe_system_registration) {
		struct mk_cpu_resource_payload payload = { .cpu_id = 65537 };

		system_probe_result = mk_handle_cpu_add(&payload, sizeof(payload), 61);
	}
	if (type == MK_MSG_RESOURCE)
		registered = !register_error;
	return type == MK_MSG_RESOURCE ? register_error : system_register_error;
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

static __maybe_unused void run_wait_jobs(void)
{
	struct mk_cpu_resource_payload cpu = { .cpu_id = 65537 };
	struct mk_mem_resource_payload mem = { .start_pfn = 65537 };
	struct mk_device_resource_payload dev = { .domain = 1 };

	/* An already-entered receive callback submits after admission closes. */
	if (probe_at_wait) {
		probe_at_wait = false;
		hard_irq = true;
		wait_probe_results[0] = mk_handle_cpu_add(&cpu, sizeof(cpu), 91);
		wait_probe_results[1] = mk_handle_mem_add(&mem, sizeof(mem), 92);
		wait_probe_results[2] = mk_handle_device_add(&dev, sizeof(dev), 93);
		hard_irq = false;
	}
	assert((cpu_queue && cpu_queue->nr) || system_queue.nr);
	drain(cpu_queue);
	drain(&system_queue);
}

static void __noreturn mk_enter_pool_state(void *arg)
{
	parked_cpus = true;
	longjmp(parked, 1);
}

static void smp_call_function(void (*fn)(void *), void *arg, int wait)
{
	assert(fn == mk_enter_pool_state && !wait);
}

static int mk_messaging_init(void)
{
	return 0;
}

static void mk_messaging_cleanup(void)
{
	messaging_cleanups++;
}

static int mk_kernfs_init(void)
{
	return kernfs_error;
}

static void mk_system_msg_handler(u32 type, u32 subtype, u64 id,
				 void *payload, u32 len, void *ctx)
{
}

#include "work-shutdown.h"

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
	system_register_error = kernfs_error = 0;
	messaging_cleanups = 0;
	nr_replies = destroyed = 0;
	online[0] = online[1] = false;
	memory_added = device_added = shutdown_sent = parked_cpus = false;
	probe_at_wait = probe_system_registration = false;
	shutdown_jobs_pending = 0;
	system_probe_result = 0;
	memset(wait_probe_results, 0, sizeof(wait_probe_results));
}

static void shutdown_regressions(void)
{
	struct mk_cpu_resource_payload cpu = { .cpu_id = 65537, .sender_instance_id = 3 };
	struct mk_mem_resource_payload mem = { .start_pfn = 65537, .sender_instance_id = 3 };
	struct mk_device_resource_payload dev = { .domain = 1, .sender_instance_id = 3 };
	struct mk_shutdown_work *sw;

	reset();
	expect("init for shutdown", mk_hotplug_init(), 0);
	expect("CPU accepted before shutdown", mk_handle_cpu_add(&cpu, sizeof(cpu), 48), 0);
	expect("memory accepted before shutdown", mk_handle_mem_add(&mem, sizeof(mem), 49), 0);
	expect("device accepted before shutdown", mk_handle_device_add(&dev, sizeof(dev), 50), 0);
	sw = kmalloc_obj(*sw, GFP_ATOMIC);
	INIT_WORK(&sw->work, mk_shutdown_work_fn);
	sw->sender_instance_id = 3;
	sw->msg_id = 51;
	schedule_work(&sw->work);
	probe_at_wait = true;
	/* Newest system job is shutdown; older resource jobs still exist. */
	if (!setjmp(parked))
		run_one(&system_queue);
	expect("shutdown reaches parking boundary", parked_cpus, 1);
	expect("shutdown ACK sent", shutdown_sent, 1);
	expect("shutdown excludes local controllers until all CPUs park", mk_overlay_mutex, 1);
	/* longjmp models disposal of this stopped kernel, not mutex unlocking. */
	mk_overlay_mutex = false;
	expect("no accepted resource job remains at shutdown ACK", shutdown_jobs_pending, 0);
	expect("CPU work completed before parking", online[0], 1);
	expect("memory work completed before parking", memory_added, 1);
	expect("device work completed before parking", device_added, 1);
	expect("all resource ACKs precede shutdown", nr_replies, 3);
	expect("accepted work freed before parking", allocations, 0);
	expect("late CPU callback rejected during drain", wait_probe_results[0], -ESHUTDOWN);
	expect("late memory callback rejected during drain", wait_probe_results[1], -ESHUTDOWN);
	expect("late device callback rejected during drain", wait_probe_results[2], -ESHUTDOWN);
	expect("post-shutdown CPU rejected", mk_handle_cpu_add(&cpu, sizeof(cpu), 52), -ESHUTDOWN);
	expect("post-shutdown memory rejected",
	       mk_handle_mem_add(&mem, sizeof(mem), 53), -ESHUTDOWN);
	expect("post-shutdown device rejected",
	       mk_handle_device_add(&dev, sizeof(dev), 54), -ESHUTDOWN);
	expect("post-shutdown CPU remove rejected",
	       mk_handle_cpu_remove(&cpu, sizeof(cpu), 55), -ESHUTDOWN);
	expect("post-shutdown memory remove rejected",
	       mk_handle_mem_remove(&mem, sizeof(mem), 56), -ESHUTDOWN);
	expect("post-shutdown device remove rejected",
	       mk_handle_device_remove(&dev, sizeof(dev), 57), -ESHUTDOWN);
	/* Keep baseline RED cleanup recoverable without claiming those jobs safe. */
	drain(cpu_queue);
	drain(&system_queue);
	mk_hotplug_cleanup();
	expect("shutdown cleanup releases allocations", allocations, 0);
	reset();
	probe_system_registration = true;
	expect("core init", multikernel_init(), 0);
	expect("hotplug ready when system handler becomes visible", system_probe_result, 0);
	mk_hotplug_cleanup();
	reset();
	/* Init unwinds both sides of the changed registration order. */
	system_register_error = -EIO;
	expect("system registration error", multikernel_init(), -EIO);
	expect("system failure destroys CPU queue", queues_live, 0);
	expect("system failure closes resource admission",
	       mk_handle_mem_add(&mem, sizeof(mem), 62), -ESHUTDOWN);
	expect("system failure unregisters resource handler", registered, 0);
	expect("system failure cleans messaging", messaging_cleanups, 1);
	reset();
	kernfs_error = -ENOMEM;
	expect("kernfs init error", multikernel_init(), -ENOMEM);
	expect("kernfs failure destroys CPU queue", queues_live, 0);
	expect("kernfs failure cleans messaging", messaging_cleanups, 1);
	expect("kernfs failure leaves no allocation", allocations, 0);
	reset();

	/* Cleanup must account for system-queue jobs as well as ordered CPU jobs. */
	expect("init for mixed cleanup", mk_hotplug_init(), 0);
	expect("accept memory before cleanup", mk_handle_mem_add(&mem, sizeof(mem), 63), 0);
	expect("accept device before cleanup", mk_handle_device_add(&dev, sizeof(dev), 64), 0);
	send_error = -EIO;
	mk_hotplug_cleanup();
	expect("cleanup completes memory despite lost ACK", memory_added, 1);
	expect("cleanup completes device despite lost ACK", device_added, 1);
	expect("cleanup releases mixed work despite lost ACK", allocations, 0);
	expect("cleanup leaves no system jobs", system_queue.nr, 0);
	expect("cleanup releases CPU queue", queues_live, 0);
	reset();
}

static void controller_regressions(void)
{
	struct mk_cpu_resource_payload cpu = { .cpu_id = 65537, .sender_instance_id = 3 };
	struct mk_mem_resource_payload mem = { .start_pfn = 65537, .sender_instance_id = 3 };
	struct mk_device_resource_payload dev = { .domain = 1, .sender_instance_id = 3 };
	unsigned int i;

	reset();
	expect("init for controller contention", mk_hotplug_init(), 0);
	expect("queue busy CPU add", mk_handle_cpu_add(&cpu, sizeof(cpu), 71), 0);
	expect("queue busy CPU remove", mk_handle_cpu_remove(&cpu, sizeof(cpu), 72), 0);
	expect("queue busy memory add", mk_handle_mem_add(&mem, sizeof(mem), 73), 0);
	expect("queue busy memory remove", mk_handle_mem_remove(&mem, sizeof(mem), 74), 0);
	expect("queue busy device add", mk_handle_device_add(&dev, sizeof(dev), 75), 0);
	expect("queue busy device remove", mk_handle_device_remove(&dev, sizeof(dev), 76), 0);
	mutex_lock(&mk_overlay_mutex);
	drain(cpu_queue);
	drain(&system_queue);
	expect("busy workers leave controller lock held", mk_overlay_mutex, 1);
	expect("busy workers do not mutate resources", online[0] || memory_added || device_added, 0);
	expect("every busy worker attempts an ACK", nr_replies, 6);
	for (i = 0; i < nr_replies; i++)
		expect("busy ACK never claims success", replies[i].ack.result, -EBUSY);
	mutex_unlock(&mk_overlay_mutex);
	expect("retry admitted after controller unlock", mk_handle_cpu_add(&cpu, sizeof(cpu), 77), 0);
	drain(cpu_queue);
	expect("retry mutates after unlock", online[0], 1);
	expect("retry ACK succeeds", replies[6].ack.result, 0);
	mk_hotplug_cleanup();
	reset();
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
	shutdown_regressions();
	controller_regressions();
	expect("incoming mutation excludes direct controller/pool changes", unlocked_mutations, 0);
	expect("hard-IPI admission never takes an RT sleeping lock", rt_atomic_lock_errors, 0);
	printf("CPU work ordering: %u checks, %u failures\n", checks, failures);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
