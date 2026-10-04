// SPDX-License-Identifier: GPL-2.0-only
/* Real ownership/handoff code; firmware, pending waits and allocation injected. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <linux/err.h>

#define u64 __u64
#define GFP_KERNEL 0
static bool fail_alloc, fail_set_alloc, fail_after_wake;
#define kzalloc(n, flags) ((void)(flags), fail_alloc ? NULL : calloc(1, n))
#define krealloc_array(p, n, s, flags) \
	((void)(flags), fail_alloc || fail_set_alloc ? NULL : realloc(p, (n) * (s)))
#define kfree free
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
#define pr_err(...) fprintf(stderr, __VA_ARGS__)
#define pr_warn(...) fprintf(stderr, __VA_ARGS__)
#define pr_info(...) do { } while (0)

static int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	return n < 0 ? n : (size_t)n < size ? n : size ? (int)size - 1 : 0;
}

#include "cpu-types.h"
#include "cpu-set.h"

struct mk_spawn_context {
	unsigned long repark_park_phys, repark_park_cr3, repark_slot_phys;
	unsigned long park_phys, park_cr3, identity_cr3, kernel_entry;
	unsigned long trampoline_phys, self_phys, flags;
};

/* Only fields reached by the extracted functions; no alternate ownership model. */
struct mk_instance {
	int id, state;
	const char *name;
	struct mk_cpu_set *cpus, *cpus_on_slot;
	mk_phys_cpu_t ipi_target;
	bool ipi_lock;
	struct {
		struct mk_spawn_context *spawn_ctx;
		unsigned long spawn_ctx_phys;
	} arch;
};

struct mk_pool {
	struct mk_cpu_set *cpus;
	bool park_lock;
	struct {
		struct mk_spawn_context *slot;
		unsigned long park_phys, cr3, slot_phys;
	} arch;
};

#define MK_STATE_ACTIVE 2
#define MK_STATE_LOADED 1
#define MK_STATE_FAILED 3
#define MK_SPAWN_F_REPARK 1
#define virt_to_phys(p) ((unsigned long)(p))
#define per_cpu(name, cpu) name(cpu)

static u32 x86_cpu_to_apicid(int cpu)
{
	return cpu;
}
static struct mk_instance self = { .id = 1 }, target;
static struct mk_instance *mk_self = &self;
static struct mk_instance *host_instance;
static bool mk_overlay_mutex = true;
static struct mk_pool pool, *mk_pool = &pool;
static struct mk_spawn_context host_slot, spawn_ctx;
static int references, wakes, wake_fail_at, send_error, wait_error;
static unsigned int live_pending, sends;
static bool owned_at_wake, tracked_at_wake, owned_at_send;
static bool confirm_mode;
static unsigned int running_probes;
static mk_phys_cpu_t test_cpu;

/* Deterministic lock boundary, not a concurrency test. */
static void unlock(bool **lock)
{
	assert(**lock);
	**lock = false;
}

static bool *lock(bool *held)
{
	assert(!*held);
	*held = true;
	return held;
}

#define guard(kind) bool *held_##kind __attribute__((cleanup(unlock))) = lock
#define lockdep_assert_held(held) assert(*(held))
#define raw_spin_lock_irqsave(m, flags) \
	do { assert(!*(m)); *(m) = true; (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(m, flags) \
	do { assert(*(m)); *(m) = false; (void)(flags); } while (0)
#include "cpu-retarget.h"

static int arch_cpu_from_physical_id(mk_phys_cpu_t cpu)
{
	return cpu == test_cpu || cpu == 7 ? 0 : -EINVAL;
}

#include "cpu-transfer.h"

/* Mailbox publication can time out after a CPU has consumed the request. */
static int mk_slot_wake(struct mk_spawn_context *ctx, u32 cpu, const char *what)
{
	assert(pool.park_lock);
	wakes++;
	owned_at_wake = mk_cpu_set_contains(target.cpus, cpu) &&
			!mk_cpu_set_contains(pool.cpus, cpu);
	tracked_at_wake = mk_cpu_set_contains(target.cpus_on_slot, cpu);
	if (confirm_mode) {
		if (cpu == 7) {
			running_probes++;
			return -ETIMEDOUT;
		}
		/* The uncertain handoff never left the host park slot. */
		return ctx == &host_slot ? 0 : -ETIMEDOUT;
	}
	if (fail_after_wake)
		fail_alloc = true;
	return wakes == wake_fail_at ? -ETIMEDOUT : 0;
}

#include "cpu-x86.h"
#include "cpu-confirm.h"

static struct mk_instance *mk_instance_find(int id)
{
	if (id != target.id)
		return NULL;
	references++;
	return &target;
}

static void mk_instance_put(struct mk_instance *instance)
{
	assert(instance == &target && references > 0);
	references--;
}

struct mk_pending_msg { u64 id; };

static struct mk_pending_msg *mk_msg_pending_add(u32 type, u32 op, u64 resource)
{
	struct mk_pending_msg *p = kzalloc(sizeof(*p), GFP_KERNEL);

	if (!p)
		return ERR_PTR(-ENOMEM);
	p->id = 17;
	live_pending++;
	return p;
}

static u64 mk_msg_pending_id(struct mk_pending_msg *p)
{
	return p->id;
}

static void mk_msg_pending_cancel(struct mk_pending_msg *p)
{
	assert(live_pending == 1);
	live_pending--;
	free(p);
}

static int mk_msg_pending_wait(struct mk_pending_msg *p, unsigned long timeout)
{
	mk_msg_pending_cancel(p);
	return wait_error;
}

static int mk_send_message_id(int id, u32 type, u32 op, u64 req_id,
			      const void *data, size_t size)
{
	const struct mk_cpu_resource_payload *p = data;

	assert(id == target.id && type == MK_MSG_RESOURCE && req_id == 17);
	assert(op == MK_RES_CPU_ADD || op == MK_RES_CPU_REMOVE);
	assert(size == sizeof(*p) && p->cpu_id == test_cpu);
	owned_at_send = mk_cpu_set_contains(target.cpus, test_cpu) &&
			!mk_cpu_set_contains(pool.cpus, test_cpu);
	sends++;
	return send_error;
}

#define mk_pool_cpu_add(...) (-EOPNOTSUPP)
#define mk_pool_cpu_remove(...) (-EOPNOTSUPP)
#define mk_do_cpu_add(...) (-EOPNOTSUPP)
#define mk_do_cpu_remove(...) (-EOPNOTSUPP)
#include "cpu-send.h"

static unsigned int failures, checks;

static void expect(const char *name, int got, int want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL: %s: got %d, want %d\n", name, got, want);
		failures++;
	} else {
		printf("PASS: %s\n", name);
	}
}

static void reset(void)
{
	mk_cpu_set_free(target.cpus);
	mk_cpu_set_free(target.cpus_on_slot);
	mk_cpu_set_free(pool.cpus);
	assert(!references && !live_pending && !pool.park_lock);
	fail_alloc = fail_set_alloc = fail_after_wake = false;
	wakes = wake_fail_at = send_error = wait_error = 0;
	sends = 0;
	owned_at_wake = tracked_at_wake = owned_at_send = false;
	confirm_mode = false;
	running_probes = 0;
	test_cpu = 65537;
	target = (struct mk_instance) {
		.id = 2, .state = MK_STATE_ACTIVE, .name = "spawn",
		.cpus = mk_cpu_set_alloc(), .cpus_on_slot = mk_cpu_set_alloc(),
		.arch = { .spawn_ctx = &spawn_ctx, .spawn_ctx_phys = 0x123000 },
	};
	pool = (struct mk_pool) {
		.cpus = mk_cpu_set_alloc(),
		.arch = { .slot = &host_slot, .slot_phys = 0x456000 },
	};
	spawn_ctx = (struct mk_spawn_context) { .park_phys = 0x789000 };
	assert(!mk_cpu_set_add(pool.cpus, test_cpu));
}

static void retained(void)
{
	expect("CPU remains owned by target",
	       mk_cpu_set_contains(target.cpus, test_cpu), 1);
	expect("uncertain CPU is not assignable",
	       mk_cpu_set_contains(pool.cpus, test_cpu), 0);
	expect("uncertain handoff remains tracked",
	       mk_cpu_set_contains(target.cpus_on_slot, test_cpu), 1);
	expect("pending waiter cleaned up", live_pending, 0);
	expect("instance reference released", references, 0);
}

int main(void)
{
	reset();
	expect("initial add", mk_send_cpu_add(2, test_cpu, 0, 0), 0);
	expect("ownership precedes handoff", owned_at_wake, 1);
	expect("tracking precedes handoff", tracked_at_wake, 1);
	expect("ownership precedes remote start request", owned_at_send, 1);
	expect("CPU addition refreshes physical doorbell", target.ipi_target == test_cpu, 1);
	retained();
	expect("repeat add is rejected", mk_send_cpu_add(2, test_cpu, 0, 0), -EBUSY);
	expect("repeat add publishes nothing", sends, 1);

	reset();
	fail_alloc = true;
	expect("pending allocation fails before handoff",
	       mk_send_cpu_add(2, test_cpu, 0, 0), -ENOMEM);
	expect("allocation failure never wakes CPU", wakes, 0);
	expect("allocation failure leaves pool ownership",
	       mk_cpu_set_contains(pool.cpus, test_cpu), 1);
	expect("allocation failure leaves target empty", target.cpus->nr, 0);

	reset();
	fail_set_alloc = true;
	expect("ownership reservation fails before handoff",
	       mk_send_cpu_add(2, test_cpu, 0, 0), -ENOMEM);
	expect("reservation failure never wakes CPU", wakes, 0);
	expect("reservation failure leaves pool ownership",
	       mk_cpu_set_contains(pool.cpus, test_cpu), 1);
	expect("reservation failure cleans pending", live_pending, 0);

	reset();
	assert(!mk_cpu_set_reserve(target.cpus, 1));
	fail_set_alloc = true;
	expect("tracking allocation fails before publication",
	       mk_send_cpu_add(2, test_cpu, 0, 0), -ENOMEM);
	expect("tracking allocation failure never wakes CPU", wakes, 0);
	expect("preowned CPU retained on tracking failure",
	       mk_cpu_set_contains(target.cpus, test_cpu), 1);
	expect("tracking failure does not make CPU assignable",
	       mk_cpu_set_contains(pool.cpus, test_cpu), 0);
	expect("tracking failure cancels pending", live_pending, 0);

	reset();
	wake_fail_at = 1;
	expect("handoff timeout", mk_send_cpu_add(2, test_cpu, 0, 0), -ETIMEDOUT);
	retained();
	expect("failed handoff sends no start request", sends, 0);

	reset();
	send_error = -ENOSPC;
	expect("transport failure after handoff",
	       mk_send_cpu_add(2, test_cpu, 0, 0), -ENOSPC);
	retained();
	expect("transport failure does not guess rollback", wakes, 1);

	reset();
	wait_error = -ETIMEDOUT;
	expect("lost start ACK", mk_send_cpu_add(2, test_cpu, 0, 0), -ETIMEDOUT);
	retained();
	expect("lost ACK does not guess rollback", wakes, 1);

	reset();
	wait_error = -EIO;
	expect("error ACK retains ownership", mk_send_cpu_add(2, test_cpu, 0, 0), -EIO);
	retained();

	reset();
	fail_after_wake = true;
	expect("no late ownership or waiter allocation",
	       mk_send_cpu_add(2, test_cpu, 0, 0), 0);
	retained();

	reset();
	assert(!mk_instance_transfer_cpus(&target, pool.cpus));
	assert(!mk_cpu_set_add(target.cpus_on_slot, test_cpu));
	wake_fail_at = 1;
	expect("remove cannot reclaim on repark timeout",
	       mk_send_cpu_remove(2, test_cpu), -ETIMEDOUT);
	retained();
	wake_fail_at = 0;
	expect("confirmed repark permits removal", mk_send_cpu_remove(2, test_cpu), 0);
	expect("removed CPU returned to pool",
	       mk_cpu_set_contains(pool.cpus, test_cpu), 1);
	expect("removed CPU no longer target-owned", target.cpus->nr, 0);
	expect("confirmed host return clears tracking", target.cpus_on_slot->nr, 0);
	expect("CPU return removes obsolete doorbell", target.ipi_target == MK_PHYS_CPU_INVALID, 1);

	reset();
	assert(!mk_instance_transfer_cpus(&target, pool.cpus));
	wake_fail_at = 1;
	expect("first boot wake timeout",
	       mk_spawn_cpu(&target, test_cpu, &spawn_ctx), -ETIMEDOUT);
	retained();
	expect("boot tracking precedes publication", tracked_at_wake, 1);

	reset();
	assert(!mk_instance_transfer_cpus(&target, pool.cpus));
	assert(!mk_cpu_set_add(target.cpus, 7));
	wake_fail_at = 1;
	expect("secondary handoff timeout",
	       mk_spawn_cpu(&target, 7, &spawn_ctx), -ETIMEDOUT);
	retained();
	expect("secondary tracking precedes publication", tracked_at_wake, 1);
	expect("boot is not woken after secondary failure", wakes, 1);
	expect("unpublished boot CPU is not tracked",
	       mk_cpu_set_contains(target.cpus_on_slot, 7), 0);

	reset();
	assert(!mk_instance_transfer_cpus(&target, pool.cpus));
	assert(!mk_cpu_set_add(target.cpus, test_cpu + 1));
	assert(!mk_cpu_set_add(target.cpus, 7));
	wake_fail_at = 2;
	expect("partial secondary handoff failure",
	       mk_spawn_cpu(&target, 7, &spawn_ctx), -ETIMEDOUT);
	retained();
	expect("second uncertain CPU remains tracked",
	       mk_cpu_set_contains(target.cpus_on_slot, test_cpu + 1), 1);
	expect("partial handoff does not wake boot CPU", wakes, 2);
	expect("unpublished boot stays untracked",
	       mk_cpu_set_contains(target.cpus_on_slot, 7), 0);

	reset();
	wake_fail_at = 1;
	expect("uncertain add before confirmation",
	       mk_send_cpu_add(2, test_cpu, 0, 0), -ETIMEDOUT);
	assert(!mk_cpu_set_add(target.cpus, 7));
	assert(!mk_cpu_set_add(target.cpus_on_slot, 7));
	confirm_mode = true;
	expect("host fallback deletion must not skip running CPU",
	       mk_instance_confirm_parked(&target), -EBUSY);
	expect("running CPU probed on both slots", running_probes, 2);
	expect("fallback clears only confirmed host CPU",
	       mk_cpu_set_contains(target.cpus_on_slot, test_cpu), 0);
	expect("running CPU remains tracked",
	       mk_cpu_set_contains(target.cpus_on_slot, 7), 1);
	expect("host confirmation does not return ownership",
	       mk_cpu_set_contains(target.cpus, test_cpu), 1);

	reset();
	assert(!mk_instance_transfer_cpus(&target, pool.cpus));
	assert(!mk_cpu_set_add(target.cpus, test_cpu + 1));
	assert(!mk_cpu_set_add(target.cpus_on_slot, test_cpu));
	assert(!mk_cpu_set_add(target.cpus_on_slot, test_cpu + 1));
	confirm_mode = true;
	expect("all host-slot fallbacks can remove tracking",
	       mk_instance_confirm_parked(&target), 0);
	expect("all confirmed host CPUs were visited", target.cpus_on_slot->nr, 0);
	expect("host confirmation retains both owners", target.cpus->nr, 2);
	expect("assigned CPUs confirm despite empty tracking",
	       mk_instance_confirm_parked(&target), 0);

	reset();
	assert(!mk_instance_transfer_cpus(&target, pool.cpus));
	assert(!mk_cpu_set_add(target.cpus, 7));
	confirm_mode = true;
	expect("untracked assigned CPU must not escape confirmation",
	       mk_instance_confirm_parked(&target), -EBUSY);
	expect("untracked running CPU probed", running_probes, 2);
	expect("untracked running CPU retains ownership", mk_cpu_set_contains(target.cpus, 7), 1);

	reset();
	assert(!mk_instance_transfer_cpus(&target, pool.cpus));
	target.arch.spawn_ctx = NULL;
	confirm_mode = true;
	expect("before first spawn confirm host park slot",
	       mk_instance_confirm_parked(&target), 0);

	reset();
	assert(!mk_instance_transfer_cpus(&target, pool.cpus));
	expect("successful first boot",
	       mk_spawn_cpu(&target, test_cpu, &spawn_ctx), 0);
	expect("successful re-spawn uses existing tracking",
	       mk_spawn_cpu(&target, test_cpu, &spawn_ctx), 0);
	expect("re-spawn tracking has no duplicates", target.cpus_on_slot->nr, 1);

	reset();
	mk_pool = NULL;
	expect("active add without a pool is rejected",
	       mk_send_cpu_add(2, test_cpu, 0, 0), -EBUSY);
	expect("missing pool publishes nothing", wakes, 0);
	mk_pool = &pool;

	reset();
	assert(!mk_cpu_set_add(pool.cpus, test_cpu + 1));
	expect("unmapped physical CPU is rejected",
	       mk_send_cpu_add(2, test_cpu + 1, 0, 0), -EBUSY);
	expect("mapping failure leaves CPU assignable",
	       mk_cpu_set_contains(pool.cpus, test_cpu + 1), 1);
	expect("mapping failure publishes nothing", wakes, 0);
	expect("mapping failure cleans pending", live_pending, 0);

	reset();
	mk_cpu_set_clear(pool.cpus);
	test_cpu = 0x100010001ULL;
	assert(!mk_cpu_set_add(pool.cpus, test_cpu));
	target.state = MK_STATE_LOADED;
	expect("nonrunning transfer preserves sparse 64-bit ID",
	       mk_send_cpu_add(2, test_cpu, 0, 0), 0);
	expect("full-width ID remains assigned",
	       mk_cpu_set_contains(target.cpus, 0x100010001ULL), 1);
	expect("nonrunning transfer does not wake CPU", wakes, 0);
	reset();
	mk_cpu_set_free(target.cpus);
	mk_cpu_set_free(target.cpus_on_slot);
	mk_cpu_set_free(pool.cpus);
	printf("%u checks, %u failures\n", checks, failures);
	return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
