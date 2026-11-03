// SPDX-License-Identifier: GPL-2.0-only
/* Real retirement predicate with retained local ownership after CPUHP failure. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
typedef unsigned long mk_phys_cpu_t;
struct mk_cpu_set {
	unsigned int nr;
	mk_phys_cpu_t ids[2];
};

struct mk_instance {
	struct mk_cpu_set *cpus, *cpus_on_slot;
	struct mk_instance *next;
};

static struct mk_cpu_set local_cpus = { .nr = 1, .ids = { 0x10001 } },
			 free_cpus;
static struct mk_instance self = { .cpus = &local_cpus }, child;
static struct mk_instance *mk_self = &self, *mk_instance_list = &self;
static struct {
	struct mk_cpu_set *cpus;
} pool = { .cpus = &free_cpus }, *mk_pool = &pool;
static bool mk_overlay_mutex = true, mk_instance_mutex, online;
static int logical_cpu = 1;
static const unsigned int nr_cpu_ids = 4;
#define mk_cpu_set_empty(p) (!(p) || !(p)->nr)
#define mk_cpu_set_for_each(i, id, set)                                  \
	for ((i) = 0;                                                    \
	     (set) && (i) < (set)->nr && (((id) = (set)->ids[i]), true); \
	     (i)++)
#define list_for_each_entry(p, head, member) \
	for ((p) = *(head); (p); (p) = (p)->next)
#define lockdep_assert_held(p) assert(*(p))
static void mutex_lock(bool *p)
{
	assert(!*p);
	*p = true;
}

static void mutex_unlock(bool *p)
{
	assert(*p);
	*p = false;
}

static int arch_cpu_from_physical_id(mk_phys_cpu_t id)
{
	assert(id == 0x10001);
	return logical_cpu;
}

static bool cpu_online(unsigned int cpu)
{
	assert(cpu < nr_cpu_ids);
	return online;
}

#include "pool-return.h"

int main(void)
{
	unsigned int failures = 0;

	if (mk_pool_cpus_returned()) {
		puts("FAIL: locally owned offline CPU must pin the pool park area");
		failures++;
	}
	online = true;
	assert(mk_pool_cpus_returned());
	logical_cpu = -1;
	if (mk_pool_cpus_returned()) {
		puts("FAIL: unmapped retained CPU must pin the pool park area");
		failures++;
	}
	logical_cpu = nr_cpu_ids;
	if (mk_pool_cpus_returned()) {
		puts("FAIL: invalid retained CPU must pin the pool park area");
		failures++;
	}
	logical_cpu = 1;
	free_cpus.nr = 1;
	assert(!mk_pool_cpus_returned());
	free_cpus.nr = 0;
	self.next = &child;
	child.cpus_on_slot = &local_cpus;
	assert(!mk_pool_cpus_returned());
	assert(!mk_instance_mutex);
	printf("Pool return: 6 scenarios, %u failures\n", failures);
	return failures ? 1 : 0;
}
