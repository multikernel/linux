// SPDX-License-Identifier: GPL-2.0-only
/* Real registration, removal and dispatch; pthread-controlled RCU boundary. */
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>

#define __rcu
#define GFP_KERNEL 0
#define EXPORT_SYMBOL(x)
#define MK_IPI_RING_SIZE 8
#define MK_MAX_DATA_SIZE 16
#define pr_warn_once(...) do { } while (0)
#define kzalloc(n, flags) calloc(1, n)
typedef pthread_mutex_t raw_spinlock_t;
#define __RAW_SPIN_LOCK_UNLOCKED(n) PTHREAD_MUTEX_INITIALIZER
#define raw_spin_lock(m) assert(!pthread_mutex_lock(m))
#define raw_spin_unlock(m) assert(!pthread_mutex_unlock(m))
#define raw_spin_lock_irqsave(m, flags) \
	do { (flags) = 0; raw_spin_lock(m); } while (0)
#define raw_spin_unlock_irqrestore(m, flags) \
	do { (void)(flags); raw_spin_unlock(m); } while (0)
#define lockdep_is_held(m) true
#define rcu_dereference(p) __atomic_load_n(&(p), __ATOMIC_ACQUIRE)
#define rcu_dereference_protected(p, c) rcu_dereference(p)
#define rcu_assign_pointer(p, v) __atomic_store_n(&(p), (v), __ATOMIC_RELEASE)
#define RCU_INIT_POINTER(p, v) rcu_assign_pointer(p, v)
#define atomic_read(p) (*(p))
#define atomic_set(p, v) (*(p) = (v))
#define atomic_set_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define smp_load_acquire(p) (*(p))

struct mk_ipi_data { size_t data_size; unsigned long type; };
typedef void (*mk_ipi_callback_t)(struct mk_ipi_data *, void *);
#include "ipi-handler.h"
struct shared {
	struct {
		unsigned int head, tail;
		struct mk_ipi_data entries[MK_IPI_RING_SIZE];
	} ring;
};
static struct shared shared;
static struct { struct shared *ipi_data; } self = { &shared }, *mk_self = &self;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool entered, release_callback, unregister_done, grace_entered;
static unsigned int readers, callbacks;
static atomic_bool freed;
static void *retired;

static void kfree(void *p)
{
	/* Retain the bytes until threads join, recording premature reclamation. */
	if (p) {
		retired = p;
		atomic_store(&freed, true);
	}
}

static __attribute__((unused)) void rcu_read_lock(void)
{
	assert(!pthread_mutex_lock(&gate));
	readers++;
	assert(!pthread_mutex_unlock(&gate));
}

static __attribute__((unused)) void rcu_read_unlock(void)
{
	assert(!pthread_mutex_lock(&gate));
	assert(readers);
	readers--;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
}

static __attribute__((unused)) void synchronize_rcu(void)
{
	assert(!pthread_mutex_lock(&gate));
	grace_entered = true;
	assert(!pthread_cond_broadcast(&changed));
	while (readers)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
}

#include "ipi-production.h"

static void callback(struct mk_ipi_data *slot, void *ctx)
{
	assert(slot->type == 17 && ctx == &shared);
	assert(!pthread_mutex_lock(&gate));
	callbacks++;
	entered = true;
	assert(!pthread_cond_broadcast(&changed));
	while (!release_callback)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!atomic_load(&freed));
	assert(!pthread_mutex_unlock(&gate));
}

static void *dispatch(void *unused)
{
	(void)unused;
	mk_ipi_drain_ring();
	return NULL;
}

static void *unregister(void *handler)
{
	multikernel_unregister_handler(handler);
	assert(!pthread_mutex_lock(&gate));
	unregister_done = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	return NULL;
}

int main(void)
{
	struct mk_ipi_handler *handler;
	pthread_t receive, remove;
	bool premature;

	assert(!multikernel_register_handler(NULL, NULL, 17));
	multikernel_unregister_handler(NULL);
	handler = multikernel_register_handler(callback, &shared, 17);
	assert(handler);
	shared.ring.head = 1;
	shared.ring.entries[0] = (struct mk_ipi_data) { .data_size = 1, .type = 17 };
	assert(!pthread_create(&receive, NULL, dispatch, NULL));
	assert(!pthread_mutex_lock(&gate));
	while (!entered)
		assert(!pthread_cond_wait(&changed, &gate));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_create(&remove, NULL, unregister, handler));
	assert(!pthread_mutex_lock(&gate));
	while (!unregister_done && !grace_entered)
		assert(!pthread_cond_wait(&changed, &gate));
	/* Entry into a grace period alone does not prove callback protection. */
	premature = unregister_done || atomic_load(&freed) || readers != 1;
	/* Let the baseline finish without dereferencing retired context. */
	if (premature)
		atomic_store(&freed, false);
	release_callback = true;
	assert(!pthread_cond_broadcast(&changed));
	assert(!pthread_mutex_unlock(&gate));
	assert(!pthread_join(receive, NULL));
	assert(!pthread_join(remove, NULL));
	assert(callbacks == 1 && shared.ring.tail == 1 && !mk_handlers);
	free(retired);
	shared.ring.head = 2;
	shared.ring.entries[1] = (struct mk_ipi_data) { .data_size = 1, .type = 17 };
	mk_ipi_drain_ring();
	assert(callbacks == 1 && shared.ring.tail == 2);
	if (premature) {
		fprintf(stderr, "FAIL: unregister reclaimed an entered callback\n");
		return 1;
	}
	puts("IPI lifetime: entered callback drained before unregister, PASS");
	return 0;
}
