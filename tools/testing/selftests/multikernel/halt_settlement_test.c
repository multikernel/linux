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
struct mk_instance { int id, state; const char *name; };
struct work_struct { int unused; };
struct mk_shutdown_payload { u32 flags; int sender_instance_id; };
struct mk_pending_msg { int unused; };
static struct mk_instance instance = { 7, MK_STATE_ACTIVE, "spawn" };
static struct mk_instance self = { 0, MK_STATE_ACTIVE, "host" }, *mk_self = &self;
static struct mk_instance *host_instance;
static struct mk_pending_msg pending;
static struct mk_cpu_set targets;
static bool force_supported = true, mk_overlay_mutex;
static int confirm_error, send_error, wait_error, arm_error, fence_error;
static unsigned int refs, stopped, confirms, unlocked_confirms, failures, checks;
#define mutex_lock(m) do { assert(!*(m)); *(m) = true; } while (0)
#define mutex_unlock(m) do { assert(*(m)); *(m) = false; } while (0)
#define lockdep_assert_held(m) assert(*(m))
static __attribute__((unused)) bool *scoped_lock(bool *m) { mutex_lock(m); return m; }
static __attribute__((unused)) void scoped_unlock(bool **m) { mutex_unlock(*m); }
#define guard(kind) \
	bool *scope_##kind __attribute__((cleanup(scoped_unlock), unused)) = scoped_lock

static struct mk_instance *mk_instance_find(int id)
{
	if (id != 7)
		return NULL;
	refs++;
	return &instance;
}
static void mk_instance_put(struct mk_instance *p) { assert(refs); refs--; }
static void mk_instance_set_state(struct mk_instance *p, int state) { p->state = state; }
static int mk_instance_confirm_parked(struct mk_instance *p)
{
	confirms++;
	unlocked_confirms += !mk_overlay_mutex;
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
	assert(!refs && !mk_overlay_mutex);
	instance.state = MK_STATE_ACTIVE;
	confirm_error = send_error = wait_error = arm_error = fence_error = 0;
	stopped = confirms = 0;
	force_supported = true;
	host_instance = NULL;
}
int main(void)
{
	struct mk_halted_work event = { .instance_id = 7 };

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
	mk_halted_work_fn(&event.work);
	expect("voluntary HALTED must confirm", confirms, 1);
	expect("failed voluntary confirmation retains active state", instance.state, MK_STATE_ACTIVE);
	reset();
	mk_halted_work_fn(&event.work);
	expect("confirmed voluntary halt", instance.state, MK_STATE_LOADED);
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
	force_supported = false;
	expect("unsupported remote force stop", multikernel_force_halt_by_id(7), -EOPNOTSUPP);
	expect("unsupported force stop sends nothing", stopped, 0);
	expect("every settlement is resource serialized", unlocked_confirms, 0);
	assert(!refs && !mk_overlay_mutex);
	printf("Halt settlement: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
