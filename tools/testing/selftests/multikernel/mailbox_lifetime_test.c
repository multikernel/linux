// SPDX-License-Identifier: GPL-2.0-only
/* Real retirement entry points, empty CPU tracking, counted allocator calls. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "mailbox-states.h"

#define PAGE_SIZE 4096
#define ALIGN(n, a) (((n) + (a) - 1) & ~((a) - 1))
#define READ_ONCE(x) (x)
#define WARN_ON_ONCE(x) ((void)(x))
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
typedef unsigned long mk_phys_cpu_t;
typedef unsigned int u32;

struct mk_spawn_context {
	u32 ready;
};

struct mk_cpu_set {
	unsigned int nr;
	mk_phys_cpu_t *ids;
};

struct mk_instance {
	int id;
	const char *name;
	struct mk_cpu_set *cpus_on_slot;
	struct {
		struct mk_spawn_context *spawn_ctx;
		unsigned long spawn_ctx_phys;
		void *ident_pgt, *trampoline_va, *park_va;
	} arch;
};

struct mk_pool {
	bool park_lock;
	struct {
		struct mk_spawn_context *slot;
		unsigned long slot_phys, park_phys, cr3;
		void *park_va, *pgt;
	} arch;
};

static struct mk_pool pool, *mk_pool = &pool;
static struct mk_spawn_context ctx, pool_slot;
static unsigned int frees, checks;
#define mk_cpu_set_empty(p) (!(p) || !(p)->nr)
#define mk_cpu_set_count(p) ((p) ? (p)->nr : 0)
#define mk_cpu_set_format(buf, len, set) ((void)(buf), (void)(len), (void)(set))
#define mk_cpu_set_free(p) ((void)(p), frees++)
#define mk_cpu_set_del(p, cpu) ((void)(cpu), (p)->nr = 0)
#define multikernel_free(phys, size) ((void)(phys), (void)(size), frees++)
#define mk_free_identity_pgtable(p) ((void)(p), frees++)
#define set_memory_nx(virt, pages) ((void)(virt), (void)(pages), 0)
static bool mk_pool_cpus_returned(void)
{
	return true;
}

static struct mk_spawn_context *mk_own_context(void)
{
	return &pool_slot;
}

static int mk_publish_repark(struct mk_spawn_context *p, u32 cpu,
			     unsigned long park, unsigned long cr3,
			     unsigned long slot, const char *what)
{
	return -ETIMEDOUT;
}

static bool *lock(bool *p)
{
	assert(!*p);
	*p = true;
	return p;
}

static void unlock(bool **p)
{
	assert(**p);
	**p = false;
}

#define guard(name) bool *held_##name __attribute__((cleanup(unlock))) = lock
int mk_repark_instance_to_host(struct mk_instance *instance);
#include "lifetime-production.h"

static void reset(struct mk_instance *instance, struct mk_cpu_set *cpus)
{
	assert(!pool.park_lock);
	memset(instance, 0, sizeof(*instance));
	memset(&pool, 0, sizeof(pool));
	cpus->nr = 0;
	ctx.ready = MK_SLOT_IDLE;
	pool_slot.ready = MK_SLOT_IDLE;
	instance->cpus_on_slot = cpus;
	instance->arch.spawn_ctx = &ctx;
	instance->arch.ident_pgt = (void *)1;
	pool.arch.slot = &pool_slot;
	pool.arch.pgt = (void *)2;
	frees = 0;
}

int main(void)
{
	struct mk_instance instance;
	struct mk_cpu_set cpus;
	unsigned int state;

	for (state = MK_SLOT_PENDING; state <= MK_SLOT_QUARANTINED; state++) {
		reset(&instance, &cpus);
		ctx.ready = state;
		assert(mk_arch_release_instance(&instance) == -EBUSY);
		assert(!frees && instance.arch.spawn_ctx == &ctx &&
		       instance.arch.ident_pgt);
		checks++;
		reset(&instance, &cpus);
		pool_slot.ready = state;
		assert(mk_pool_park_teardown() == -EBUSY);
		assert(!frees && pool.arch.slot == &pool_slot && pool.arch.pgt);
		checks++;
	}
	reset(&instance, &cpus);
	assert(!mk_arch_release_instance(&instance) && frees == 2 &&
	       !instance.arch.spawn_ctx);
	checks++;
	reset(&instance, &cpus);
	assert(!mk_pool_park_teardown() && frees == 3 && !pool.arch.slot);
	checks++;
	printf("Mailbox lifetime: %u checks passed (no live CPU execution)\n",
	       checks);
	return 0;
}
