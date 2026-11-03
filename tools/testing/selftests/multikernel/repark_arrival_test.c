// SPDX-License-Identifier: GPL-2.0-only
/* Real handoff/tracking code; mailbox claim and destination arrival controlled. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint32_t u32;
typedef uint64_t mk_phys_cpu_t;
#define MK_SPAWN_F_REPARK 1
struct mk_spawn_context {
	unsigned long repark_park_phys, repark_park_cr3, repark_slot_phys, flags;
};
struct mk_cpu_set { bool tracked; };
struct mk_instance {
	struct { struct mk_spawn_context *spawn_ctx; } arch;
	struct mk_cpu_set *cpus_on_slot;
};
struct mk_pool {
	bool park_lock;
	struct {
		struct mk_spawn_context *slot;
		unsigned long park_phys, cr3, slot_phys;
	} arch;
};
static struct mk_spawn_context source, destination;
static struct mk_pool pool = { .arch = { .slot = &destination, .park_phys = 0x9000,
	.cr3 = 0xa000, .slot_phys = (unsigned long)&destination } }, *mk_pool = &pool;
static bool destination_arrived;
static int source_error;
static unsigned int wakes, destination_wakes, checks, failures;
#define virt_to_phys(p) ((unsigned long)(p))
#define __va(p) ((void *)(unsigned long)(p))
#define lockdep_assert_held(p) assert(*(p))
static bool *lock(bool *p) { assert(!*p); *p = true; return p; }
static void unlock(bool **p)
{
	assert(**p);
	**p = false;
}
#define guard(kind) bool *held_##kind __attribute__((cleanup(unlock))) = lock
static bool mk_cpu_set_contains(struct mk_cpu_set *set, mk_phys_cpu_t cpu)
{
	assert(cpu == 17);
	return set->tracked;
}
static void mk_cpu_set_del(struct mk_cpu_set *set, mk_phys_cpu_t cpu)
{
	assert(cpu == 17);
	set->tracked = false;
}

/* Mailbox state ownership is tested separately by mailbox_test.sh. */
static int mk_slot_begin(struct mk_spawn_context *slot)
{
	return slot ? 0 : -ENODEV;
}

static bool mk_slot_idle(struct mk_spawn_context *slot)
{
	(void)slot;
	return true;
}
static int mk_slot_wake(struct mk_spawn_context *slot, u32 cpu, const char *what)
{
	(void)what;
	assert(pool.park_lock && cpu == 17);
	wakes++;
	if (slot == &source)
		return source_error;
	assert(slot == &destination);
	destination_wakes++;
	return destination_arrived ? 0 : -ETIMEDOUT;
}
#include "repark-production.h"

static void expect(const char *name, bool passed)
{
	checks++;
	if (!passed) {
		fprintf(stderr, "FAIL %s\n", name);
		failures++;
	}
}
int main(void)
{
	struct mk_cpu_set cpus = { .tracked = true };
	struct mk_instance instance = { .arch.spawn_ctx = &source, .cpus_on_slot = &cpus };
	int ret;

	ret = mk_repark_cpu_to_host(&instance, 17);
	expect("source claim without destination arrival refuses retirement", ret == -ETIMEDOUT);
	expect("delayed departure retains old-context tracking", cpus.tracked);
	expect("destination must be probed", destination_wakes == 1);
	cpus.tracked = true;
	wakes = destination_wakes = 0;
	destination_arrived = true;
	ret = mk_repark_cpu_to_host(&instance, 17);
	expect("destination arrival permits retirement", !ret && !cpus.tracked);
	expect("successful transfer claims both source and destination", wakes == 2 && destination_wakes == 1);
	cpus.tracked = true;
	wakes = destination_wakes = 0;
	source_error = -ETIMEDOUT;
	ret = mk_repark_cpu_to_host(&instance, 17);
	expect("failed source claim retains tracking", ret == -ETIMEDOUT && cpus.tracked);
	expect("failed source does not republish destination", wakes == 1 && !destination_wakes);
	source_error = 0;
	wakes = destination_wakes = 0;
	pool.park_lock = true;
	ret = mk_publish_repark(&destination, 17, pool.arch.park_phys,
				pool.arch.cr3, pool.arch.slot_phys, "self-confirm");
	pool.park_lock = false;
	expect("self-confirm needs one claim, not recursion", !ret && wakes == 1);
	printf("Repark arrival: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
