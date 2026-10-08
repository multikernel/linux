// SPDX-License-Identifier: GPL-2.0-only
/* Extracted production dispatch; mocked mapping is not native CPU proof. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
struct mk_spawn_context {
	unsigned long trampoline_phys, trampoline_virt,
		secondary_trampoline_phys;
	unsigned long identity_cr3, kernel_entry, gs_base, stack, spawn_cr3;
	u32 target_apic_id, flags, ready;
};
struct mk_cpu_set {
	bool present;
	u32 id;
};
struct mk_ident_pgtable {
	int unused;
};
static struct mk_ident_pgtable park_pgt;
struct mk_pool {
	struct mk_cpu_set *cpus;
	struct {
		unsigned long slot_phys;
		struct mk_spawn_context *slot;
		struct mk_ident_pgtable *pgt;
	} arch;
	bool park_lock, cpus_lock;
};
struct mk_instance {
	unsigned long pool_slot_phys;
	struct mk_cpu_set *cpus_on_slot;
};
static struct mk_spawn_context own, local, adopted;
static struct mk_cpu_set free_cpus = { .id = 17 }, adopted_cpus = { .id = 17 };
static struct mk_pool pool = { .cpus = &free_cpus, .arch.slot_phys = 0x9000 };
static struct mk_pool *mk_pool;
static struct mk_instance parent = { .pool_slot_phys = 0xa000,
				     .cpus_on_slot = &adopted_cpus },
			  *host_instance;
static unsigned int maps, unmaps, publishes, checks, failures;
static bool map_failure, publication_locked;
static bool park_trampoline_mapped, dispatch_fetch_mapped;
static int park_map_error;
static unsigned long mapped_phys;
static struct {
	void *pgd;
} init_mm;
static struct {
	struct {
		unsigned long sp;
	} thread;
} idle = { .thread.sp = 0x123000 };
static unsigned char trampoline_blob[32];
#define mk_secondary_trampoline (trampoline_blob + 8)
#define multikernel_relocate_kernel_start trampoline_blob
#define MEMREMAP_WB 1
#define MK_SPAWN_F_SECONDARY 2
#define __PAGE_KERNEL_LARGE_EXEC 0x123
#define _PAGE_RW 2
#define __va(p) ((void *)(p))
#define __sme_pa(p) ((unsigned long)(p))
#define pr_err(...) ((void)0)
#define lockdep_assert_held(p) assert(*(p))
static inline void mutex_lock(bool *p)
{
	assert(!*p);
	*p = true;
}
static inline void mutex_unlock(bool *p)
{
	assert(*p);
	*p = false;
}
static bool mk_cpu_set_contains(struct mk_cpu_set *set, u32 cpu)
{
	assert(set != &free_cpus || pool.cpus_lock);
	return set && set->present && set->id == cpu;
}
static void *memremap(unsigned long phys, size_t size, int flags)
{
	(void)flags;
	assert(size == sizeof(struct mk_spawn_context));
	maps++;
	mapped_phys = phys;
	if (map_failure)
		return NULL;
	return phys == 0x9000 ? &local : phys == 0xa000 ? &adopted : NULL;
}
static void memunmap(void *pointer)
{
	assert(pointer == &local || pointer == &adopted);
	unmaps++;
}
static struct mk_spawn_context *mk_own_context(void)
{
	return &own;
}
static int mk_build_trampoline_pgtable(unsigned long va, unsigned long other,
				       unsigned long phys, unsigned long *out)
{
	assert(phys == own.trampoline_phys);
	*out = 0x111000;
	return 0;
}
static int mk_add_2mb_mapping(void *pgd, unsigned long va, unsigned long phys,
			      unsigned long flags)
{
	assert(pgd == init_mm.pgd && phys == own.trampoline_phys &&
	       !(flags & _PAGE_RW));
	return 0;
}
static inline int mk_ident_map_range(struct mk_ident_pgtable *pgt,
				     unsigned long start, unsigned long end)
{
	assert(pool.park_lock && pgt == &park_pgt);
	assert(start == own.trampoline_phys && end == start + 4096);
	if (!park_map_error)
		park_trampoline_mapped = true;
	return park_map_error;
}
#define PAGE_SIZE 4096
static unsigned long per_cpu_offset(unsigned int cpu)
{
	return 0x321000 + cpu;
}
#define idle_task(cpu) (&idle)
#define multikernel_secondary_startup 0xabc000UL
#define cmpxchg(p, from, to)         \
	do {                         \
		if (*(p) == (from))  \
			*(p) = (to); \
	} while (0)
#define smp_wmb() ((void)0)
#define WRITE_ONCE(p, v)                                                \
	do {                                                            \
		publication_locked = !mk_pool || (mk_pool->park_lock && \
						  mk_pool->cpus_lock);  \
		dispatch_fetch_mapped = &(p) != &local.ready ||         \
					park_trampoline_mapped;         \
		(p) = (v);                                              \
		publishes++;                                            \
	} while (0)

/* Publication protocol itself is covered by mailbox_test.sh. */
static int mk_slot_begin(struct mk_spawn_context *slot)
{
	if (slot->ready)
		return -EBUSY;
	slot->ready = 2;
	return 0;
}

static bool mk_slot_idle(struct mk_spawn_context *slot)
{
	return !slot || !slot->ready;
}

static int mk_slot_wake(struct mk_spawn_context *slot, u32 cpu, const char *what)
{
	assert(slot->ready == 2 && slot->target_apic_id == cpu);
	WRITE_ONCE(slot->ready, 1);
	slot->ready = 0;
	return 0;
}
#include "wake-production.h"

static void expect(const char *name, bool passed)
{
	checks++;
	if (!passed) {
		fprintf(stderr, "FAIL %s\n", name);
		failures++;
	}
}
static void reset(void)
{
	assert(!pool.park_lock && !pool.cpus_lock);
	memset(&own, 0, sizeof(own));
	memset(&local, 0, sizeof(local));
	memset(&adopted, 0, sizeof(adopted));
	own.trampoline_phys = 0x222000;
	own.trampoline_virt = 0x333000;
	init_mm.pgd = (void *)0x444000;
	maps = unmaps = publishes = 0;
	mapped_phys = 0;
	publication_locked = map_failure = false;
	park_trampoline_mapped = dispatch_fetch_mapped = false;
	park_map_error = 0;
	pool.park_lock = false;
	pool.arch.slot_phys = 0x9000;
	pool.arch.slot = &local;
	pool.arch.pgt = &park_pgt;
	free_cpus.present = adopted_cpus.present = false;
	mk_pool = &pool;
	host_instance = &parent;
}
int main(void)
{
	int ret;
	reset();
	free_cpus.present = true;
	adopted_cpus.present =
		true; /* Local donation supersedes old parent tracking. */
	ret = multikernel_wakeup_secondary_cpu_64(17, 0, 2);
	expect("local free CPU wakes on local pool slot",
	       !ret && publishes == 1 && !local.ready && !own.ready && !adopted.ready);
	expect("local mapping paired",
	       maps == 1 && unmaps == 1 && mapped_phys == 0x9000);
	expect("dispatch is child kernel, not park kernel",
	       local.trampoline_phys == own.trampoline_phys &&
		       local.kernel_entry == multikernel_secondary_startup &&
		       local.stack == idle.thread.sp &&
		       local.spawn_cr3 == (unsigned long)init_mm.pgd &&
		       local.gs_base == per_cpu_offset(2));
	expect("complete dispatch targets selected CPU and trampoline continuation",
	       local.target_apic_id == 17 &&
		       local.flags == MK_SPAWN_F_SECONDARY &&
		       local.secondary_trampoline_phys ==
			       own.trampoline_phys + 8 &&
		       local.identity_cr3 == 0x111000);
	expect("initial instruction fetch mapped in old park table before publication",
	       dispatch_fetch_mapped);
	expect("publication holds park lifetime lock",
	       publication_locked && !pool.park_lock);
	reset();
	adopted_cpus.present = true;
	ret = multikernel_wakeup_secondary_cpu_64(17, 0, 2);
	expect("adopted parent-slot path preserved",
	       !ret && publishes == 1 && !adopted.ready && !local.ready && maps == unmaps);
	reset();
	ret = multikernel_wakeup_secondary_cpu_64(17, 0, 2);
	expect("ordinary secondary uses own context",
	       !ret && publishes == 1 && !own.ready && !maps && !unmaps);
	reset();
	mk_pool = NULL;
	ret = multikernel_wakeup_secondary_cpu_64(17, 0, 2);
	expect("initial secondary works before baseline", !ret && publishes == 1 && !own.ready);
	reset();
	free_cpus.present = true;
	map_failure = true;
	ret = multikernel_wakeup_secondary_cpu_64(17, 0, 2);
	expect("failed local mapping does not publish or change free ownership",
	       ret == -ENODEV && !publishes && !unmaps && free_cpus.present &&
		       !pool.park_lock);
	reset();
	free_cpus.present = true;
	pool.arch.slot_phys = 0;
	ret = multikernel_wakeup_secondary_cpu_64(17, 0, 2);
	expect("missing local slot cannot fall back to wrong mailbox",
	       ret == -ENODEV && !publishes && !own.ready &&
		       free_cpus.present && !pool.park_lock);
	reset();
	free_cpus.present = true;
	park_map_error = -ENOMEM;
	ret = multikernel_wakeup_secondary_cpu_64(17, 0, 2);
	expect("park mapping failure leaves free ownership and publishes nothing",
	       ret == -ENOMEM && !publishes && free_cpus.present &&
		       !pool.park_lock);
	reset();
	free_cpus.present = true;
	pool.arch.pgt = NULL;
	ret = multikernel_wakeup_secondary_cpu_64(17, 0, 2);
	expect("missing park table refuses dispatch without changing ownership",
	       ret == -ENODEV && !publishes && free_cpus.present &&
		       !pool.park_lock);
	printf("Wake slot: %u checks, %u failures (non-native mapping boundaries)\n",
	       checks, failures);
	return failures ? 1 : 0;
}
