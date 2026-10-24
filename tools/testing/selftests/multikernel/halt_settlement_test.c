// SPDX-License-Identifier: GPL-2.0-only
/* Real host settlement paths; transport and physical stop boundaries injected. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef unsigned long long u64;
typedef unsigned int u32;
typedef u64 mk_phys_cpu_t;
#define MK_STATE_ACTIVE 3
#define MK_STATE_LOADED 2
#define MK_STATE_FAILED 4
#define MK_SYS_SHUTDOWN 0x1001
#define MK_MSG_SYSTEM 1
#define MK_SHUTDOWN_GRACEFUL 1
#define CONFIG_ARCH_HAS_MK_FORCE_STOP 1
#define IS_ENABLED(config) force_supported
#define GFP_KERNEL 0
#define pr_info(...) do { if (0) printf(__VA_ARGS__); } while (0)
#define pr_warn(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define IS_ERR(p) false
#define PTR_ERR(p) (-ENOMEM)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
struct mk_cpu_set { unsigned int nr; mk_phys_cpu_t ids[2]; };
#define mk_cpu_set_for_each(i, cpu, set) \
	for ((i) = 0; (i) < (set)->nr && (((cpu) = (set)->ids[i]), true); (i)++)
#define mk_cpu_set_empty(p) (!(p)->nr)
struct work_struct { int unused; };
struct mk_instance {
	int id, state;
	const char *name;
	unsigned int refs;
	struct work_struct halted_work;
	int halted_pending;
};
#define atomic_set(p, v) (*(p) = (v))
static int atomic_cmpxchg(int *p, int old, int new)
{
	int value = *p;

	if (value == old)
		*p = new;
	return value;
}
struct mk_shutdown_payload { u32 flags; int sender_instance_id; };
struct mk_pending_msg { int unused; };
static struct mk_instance instance = { .id = 7, .state = MK_STATE_ACTIVE, .name = "spawn" };
static struct mk_instance replacement = { .id = 7, .state = MK_STATE_ACTIVE, .name = "new" };
static struct mk_instance *lookup_instance = &instance;
static struct mk_instance self = { .id = 0, .state = MK_STATE_ACTIVE, .name = "host" };
static struct mk_instance *mk_self = &self;
static struct mk_instance *host_instance;
static struct mk_pending_msg pending;
static struct mk_cpu_set targets;
static bool force_supported = true, mk_overlay_mutex;
static int confirm_error, send_error, wait_error, arm_error, fence_error;
static unsigned int refs, stopped, confirms, unlocked_confirms, failures, checks;
static unsigned int host_fenced;
static struct work_struct *queued;
static bool queue_rejected, duplicate_during_confirm;
static void mk_queue_halted(int id);
static bool schedule_work(struct work_struct *work)
{
	if (queue_rejected)
		return false;
	assert(!queued);
	queued = work;
	return true;
}
#define mutex_lock(m) do { assert(!*(m)); *(m) = true; } while (0)
#define mutex_unlock(m) do { assert(*(m)); *(m) = false; } while (0)
#define lockdep_assert_held(m) assert(*(m))
static __attribute__((unused)) bool *scoped_lock(bool *m) { mutex_lock(m); return m; }
static __attribute__((unused)) void scoped_unlock(bool **m) { mutex_unlock(*m); }
#define guard(kind) \
	bool *scope_##kind __attribute__((cleanup(scoped_unlock), unused)) = scoped_lock

static struct mk_instance *mk_instance_find(int id)
{
	if (!lookup_instance || id != lookup_instance->id)
		return NULL;
	refs++;
	lookup_instance->refs++;
	return lookup_instance;
}
static void mk_instance_put(struct mk_instance *p)
{
	assert(refs && p->refs);
	refs--;
	p->refs--;
}
static void mk_instance_set_state(struct mk_instance *p, int state) { p->state = state; }
static int mk_instance_confirm_parked(struct mk_instance *p)
{
	confirms++;
	unlocked_confirms += !mk_overlay_mutex;
	if (duplicate_during_confirm) {
		assert(p->halted_pending);
		mk_queue_halted(p->id);
		assert(!queued && p->refs == 1);
	}
	return confirm_error;
}
static struct mk_pending_msg *mk_msg_pending_add(u32 type, u32 op, int id) { return &pending; }
static u64 mk_msg_pending_id(struct mk_pending_msg *p) { return 31; }
static int mk_send_message_id(int id, u32 type, u32 op, u64 msg_id,
			      void *buf, size_t size)
{
	return send_error;
}
static void mk_msg_pending_cancel(struct mk_pending_msg *p) { }
static int mk_msg_pending_wait(struct mk_pending_msg *p, int ms) { return wait_error; }
static struct mk_cpu_set *mk_cpu_set_alloc(void) { return &targets; }
static void mk_cpu_set_free(struct mk_cpu_set *p) { }
static int mk_force_halt_targets(struct mk_instance *p, struct mk_cpu_set *set)
{
	*set = (struct mk_cpu_set) { 2, { 65537, 0x100010001ULL } };
	return 0;
}
static int mk_arm_force_halt(struct mk_instance *p) { return arm_error; }
static void mk_force_stop_cpu(mk_phys_cpu_t cpu) { stopped++; }
static int mk_confirm_fenced(struct mk_instance *p, struct mk_cpu_set *set) { return fence_error; }
static void mk_pcifront_host_fenced(void) { host_fenced++; }
#define kfree(p) ((void)(p))
#include "halt-production.h"

static void expect(const char *name, int got, int want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: %d != %d\n", name, got, want);
		failures++;
	}
}
static void reset(void)
{
	assert(!refs && !mk_overlay_mutex && !queued);
	instance.state = MK_STATE_ACTIVE;
	instance.halted_pending = 0;
	lookup_instance = &instance;
	queue_rejected = duplicate_during_confirm = false;
	confirm_error = send_error = wait_error = arm_error = fence_error = 0;
	stopped = confirms = host_fenced = 0;
	force_supported = true;
	host_instance = NULL;
}
static void run_halted(void)
{
	struct work_struct *work = queued;

	assert(work);
	queued = NULL;
	mk_halted_work_fn(work);
}

int main(void)
{
	reset();
	confirm_error = -EBUSY;
	expect("shutdown ACK is not stop proof", multikernel_halt_by_id(7), -EBUSY);
	expect("failed requested confirmation retains active state", instance.state, MK_STATE_ACTIVE);
	reset();
	expect("confirmed requested halt", multikernel_halt_by_id(7), 0);
	expect("confirmed halt becomes loaded", instance.state, MK_STATE_LOADED);
	reset();
	wait_error = -ETIMEDOUT;
	expect("lost shutdown ACK", multikernel_halt_by_id(7), -ETIMEDOUT);
	expect("lost ACK retains active state", instance.state, MK_STATE_ACTIVE);
	reset();
	confirm_error = -EBUSY;
	mk_queue_halted(7);
	run_halted();
	expect("voluntary HALTED must confirm", confirms, 1);
	expect("failed voluntary confirmation retains active state", instance.state, MK_STATE_ACTIVE);
	reset();
	mk_queue_halted(7);
	run_halted();
	expect("confirmed voluntary halt", instance.state, MK_STATE_LOADED);
	expect("completed notice releases restart gate", instance.halted_pending, 0);
	reset();
	mk_queue_halted(7);
	mk_queue_halted(7);
	expect("duplicate notice keeps one reference", refs, 1);
	expect("notice excludes restart until retirement", instance.halted_pending, 1);
	duplicate_during_confirm = true;
	run_halted();
	expect("duplicates do not add confirmations", confirms, 1);
	expect("worker releases its reference", refs, 0);
	reset();
	mk_queue_halted(7);
	lookup_instance = &replacement;
	run_halted();
	expect("queued notice retains original identity", instance.state, MK_STATE_LOADED);
	expect("ID reuse cannot settle replacement", replacement.state, MK_STATE_ACTIVE);
	expect("replacement gets no stale reference", replacement.refs, 0);
	reset();
	queue_rejected = true;
	mk_queue_halted(7);
	expect("queue rejection drops admission reference", refs, 0);
	expect("queue rejection releases restart gate", instance.halted_pending, 0);
	expect("queue rejection cannot publish reusable state", instance.state, MK_STATE_ACTIVE);
	reset();
	lookup_instance = NULL;
	mk_queue_halted(7);
	expect("removed ID queues nothing", queued == NULL && !refs, 1);
	reset();
	instance.state = MK_STATE_LOADED;
	mk_queue_halted(7);
	run_halted();
	expect("already settled notice does not reconfirm", confirms, 0);
	reset();
	confirm_error = -EBUSY;
	expect("force halt must confirm", multikernel_force_halt_by_id(7), -EBUSY);
	expect("force halt sends both physical targets", stopped, 2);
	expect("failed force confirmation retains active state", instance.state, MK_STATE_ACTIVE);
	reset();
	arm_error = -ENODEV;
	expect("missing force marker fails closed", multikernel_force_halt_by_id(7), -ENODEV);
	expect("failed marker does not send unqualified NMIs", stopped, 0);
	reset();
	host_instance = &instance;
	fence_error = -ETIMEDOUT;
	expect("failed host fencing", multikernel_force_halt_by_id(7), -ETIMEDOUT);
	expect("failed host fencing retains PCI frontend", host_fenced, 0);
	fence_error = 0;
	expect("confirmed host fencing", multikernel_force_halt_by_id(7), 0);
	expect("confirmed host fencing notifies PCI frontend", host_fenced, 1);
	reset();
	force_supported = false;
	expect("unsupported remote force stop", multikernel_force_halt_by_id(7), -EOPNOTSUPP);
	expect("unsupported force stop sends nothing", stopped, 0);
	expect("every settlement is resource serialized", unlocked_confirms, 0);
	assert(!refs && !mk_overlay_mutex);
	printf("Halt settlement: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
