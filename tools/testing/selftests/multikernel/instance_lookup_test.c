// SPDX-License-Identifier: GPL-2.0-only
/* Execute the real lookup with hard-IPI context and lock boundaries modeled. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

struct mk_instance { unsigned int refcount; };
static struct mk_instance instance = { .refcount = 1 };
static bool mk_instance_mutex, mk_instance_lookup_lock;
static int mk_instance_idr;
static unsigned int sleeping_locks;
#define mutex_lock(m) do { assert(!*(m)); *(m) = true; sleeping_locks++; } while (0)
#define mutex_unlock(m) do { assert(*(m)); *(m) = false; } while (0)
#define raw_spin_lock_irqsave(m, flags) \
	do { assert(!*(m)); *(m) = true; (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(m, flags) \
	do { assert(*(m)); *(m) = false; (void)(flags); } while (0)

static struct mk_instance *idr_find(int *idr, int id)
{
	assert(idr == &mk_instance_idr);
	assert(mk_instance_mutex || mk_instance_lookup_lock);
	return id == 7 ? &instance : NULL;
}

static bool kref_get_unless_zero(unsigned int *ref)
{
	assert(mk_instance_mutex || mk_instance_lookup_lock);
	if (!*ref)
		return false;
	(*ref)++;
	return true;
}
#define rcu_read_lock() do { assert(!mk_instance_lookup_lock); mk_instance_lookup_lock = true; } while (0)
#define rcu_read_unlock() do { assert(mk_instance_lookup_lock); mk_instance_lookup_lock = false; } while (0)

#include "lookup-production.h"

int main(void)
{
	assert(mk_instance_find(7) == &instance && instance.refcount == 2);
	assert(!mk_instance_find(8) && instance.refcount == 2);
	instance.refcount = 0;
	assert(!mk_instance_find(7));
	assert(!mk_instance_mutex && !mk_instance_lookup_lock);
	if (sleeping_locks) {
		fprintf(stderr, "FAIL: IPI instance lookup acquired %u sleeping locks\n",
			sleeping_locks);
		return 1;
	}
	puts("Instance lookup: hard-IPI lookup pins without sleeping, PASS");
	return 0;
}
