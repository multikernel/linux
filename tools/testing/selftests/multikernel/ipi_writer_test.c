// SPDX-License-Identifier: GPL-2.0-only
/* Real ring producer; allocation, physical IPI and lock boundaries modeled. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MK_IPI_RING_SIZE 8
#define MK_MAX_DATA_SIZE 16
#define MK_PHYS_CPU_INVALID (~0UL)
typedef unsigned long mk_phys_cpu_t;
struct mk_ipi_data {
	size_t data_size;
	unsigned long sender_cpu, type;
	char buffer[MK_MAX_DATA_SIZE];
};
struct mk_shared_data {
	struct {
		unsigned int head, tail;
		struct mk_ipi_data entries[MK_IPI_RING_SIZE];
	} ring;
};
struct mk_instance {
	int id;
	struct mk_shared_data *ipi_data;
	mk_phys_cpu_t ipi_target;
	void *cpus;
	bool ipi_lock;
	unsigned long ipi_phys;
};
static struct mk_shared_data shared;
static struct mk_instance instance = { .ipi_data = &shared, .ipi_target = 7 };
static unsigned int refs, ipis, unlocked_writes;
static bool mk_overlay_mutex = true;
#define lockdep_assert_held(m) assert(*(m))
#define phys_to_virt(p) ((void *)(p))
#define READ_ONCE(p) (p)
#define pr_err(...) do { } while (0)
#define KERN_WARNING ""
#define printk_deferred(...) do { if (0) printf(__VA_ARGS__); } while (0)
#define atomic_read(p) (*(p))
#define atomic_cmpxchg(p, old, new) \
	({ unsigned int _old = *(p); if (_old == (old)) *(p) = (new); _old; })
/* Publication is not concurrent in this boundary test. */
#define smp_store_release(p, v) (*(p) = (v))
#define raw_spin_lock_irqsave(m, flags) \
	do { assert(!*(m)); *(m) = true; (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(m, flags) \
	do { assert(*(m)); *(m) = false; (void)(flags); } while (0)
#define mk_cpu_set_first(p) 7UL
#define smp_processor_id() 3
#define arch_cpu_physical_id(cpu) ((unsigned long)(cpu))

static struct mk_instance *mk_instance_find(int id)
{
	assert(id == 9);
	refs++;
	return &instance;
}

static void mk_instance_put(struct mk_instance *p)
{
	assert(p == &instance && refs);
	refs--;
}

static void *copy_payload(void *dst, const void *src, size_t len)
{
	unlocked_writes += !instance.ipi_lock;
	return memcpy(dst, src, len);
}
#define memcpy copy_payload

static void mk_arch_send_ipi(mk_phys_cpu_t cpu)
{
	assert(cpu == 7 && !instance.ipi_lock);
	ipis++;
}

static void *clear_ring(void *dst, int value, size_t len)
{
	assert(mk_overlay_mutex && !instance.ipi_data && !instance.ipi_lock);
	return memset(dst, value, len);
}
#define memset clear_ring

int multikernel_send_ipi_data_to(struct mk_instance *p, void *data,
			       size_t size, unsigned long type);
#include "writer-production.h"

int main(void)
{
	char payload[] = "hello";

	assert(!multikernel_send_ipi_data(9, payload, sizeof(payload), 17));
	assert(shared.ring.head == 1 && !strcmp(shared.ring.entries[0].buffer, payload));
	assert(shared.ring.entries[0].data_size == sizeof(payload) && ipis == 1);
	assert(!refs && !instance.ipi_lock);
	mk_instance_ipi_deactivate(&instance);
	assert(multikernel_send_ipi_data(9, payload, sizeof(payload), 17) == -ENODEV);
	assert(!refs && !instance.ipi_lock && ipis == 1);
	instance.ipi_phys = (unsigned long)&shared;
	mk_instance_ipi_reset(&instance);
	assert(instance.ipi_data == &shared && !shared.ring.head);
	assert(!shared.ring.entries[0].data_size && !instance.ipi_lock);
	assert(!multikernel_send_ipi_data(9, payload, sizeof(payload), 17));
	assert(ipis == 2 && shared.ring.head == 1 && !refs);
	/* The reference route must neither acquire nor drop the caller's pin. */
	refs = 1;
	assert(!multikernel_send_ipi_data_to(&instance, payload, sizeof(payload), 17));
	assert(refs == 1 && ipis == 3 && shared.ring.head == 2);
	shared.ring.tail = 3;
	assert(multikernel_send_ipi_data_to(&instance, payload, sizeof(payload), 17) == -ENOSPC);
	assert(refs == 1 && ipis == 3 && !instance.ipi_lock);
	assert(multikernel_send_ipi_data_to(&instance, payload, MK_MAX_DATA_SIZE + 1, 17) == -EINVAL);
	mk_instance_ipi_deactivate(&instance);
	assert(multikernel_send_ipi_data_to(&instance, payload, sizeof(payload), 17) == -ENODEV);
	assert(refs == 1 && ipis == 3 && !instance.ipi_lock);
	mk_instance_put(&instance);
	if (unlocked_writes) {
		fprintf(stderr, "FAIL: ring producer bypasses reset/deactivation lock\n");
		return 1;
	}
	puts("IPI writer: producer excludes reset/deactivation, PASS");
	return 0;
}
