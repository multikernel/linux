// SPDX-License-Identifier: GPL-2.0-only
/* Actual host restore; OF, allocation and mapping boundaries controlled. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef u64 phys_addr_t;
#define __init
#define PAGE_SHIFT 12
#define MEMREMAP_WB 1
#define MK_STATE_ACTIVE 3
#define pr_warn(...) do { } while (0)
#define pr_err(...) do { } while (0)
#define pr_info(...) do { } while (0)
struct mk_instance {
	u64 ipi_target, ipi_phys, pool_slot_phys;
	u32 ipi_pages;
	void *ipi_data;
	int state;
};
static struct mk_instance record, *host_instance;
static void *of_chosen = &record;
static bool has_ring = true, has_cpu = true, fail_alloc, fail_map, fail_publish;
static u64 target = UINT64_C(0x100000001);
static unsigned int checks, failures, frees, unmaps;

static bool mk_chosen_ring(const char *name, phys_addr_t *phys, u32 *pages)
{
	assert(!strcmp(name, "host-ipi"));
	*phys = 0x90000000;
	*pages = 2;
	return has_ring;
}
static int of_property_read_u64(void *node, const char *name, u64 *value)
{
	assert(node == of_chosen);
	if (strcmp(name, "multikernel,host-ipi-cpu") || !has_cpu)
		return -EINVAL;
	*value = target;
	return 0;
}
static struct mk_instance *mk_instance_alloc(int id, const char *name)
{
	assert(id == 0 && !strcmp(name, "host"));
	memset(&record, 0, sizeof(record));
	return fail_alloc ? NULL : &record;
}
static void *memremap(phys_addr_t phys, size_t size, int mode)
{
	assert(phys == 0x90000000 && size == 8192 && mode == MEMREMAP_WB);
	return fail_map ? NULL : &record;
}
static void memunmap(void *addr) { assert(addr == &record); unmaps++; }
static int mk_instance_publish(struct mk_instance *p)
{
	assert(p == &record);
	return fail_publish ? -ENOMEM : 0;
}
static void mk_instance_set_state(struct mk_instance *p, int state) { p->state = state; }
static void mk_instance_free(struct mk_instance *p) { assert(p == &record); frees++; }
#include "host-production.h"

static void expect(const char *name, int got, int want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "FAIL %s: %d != %d\n", name, got, want);
		failures++;
	}
}

int main(void)
{
	expect("explicit sparse physical target restores", mk_restore_host_instance(), 0);
	expect("64-bit physical target preserved", record.ipi_target == target, true);
	has_cpu = false;
	host_instance = NULL;
	expect("old host ring without CPU property restores", mk_restore_host_instance(), 0);
	expect("old host uses physical CPU zero", host_instance && !host_instance->ipi_target, true);
	has_ring = false;
	expect("missing ring still refuses restore", mk_restore_host_instance(), -ENOENT);
	has_ring = true;
	has_cpu = true;
	fail_alloc = true;
	expect("allocation failure", mk_restore_host_instance(), -ENOMEM);
	fail_alloc = false;
	fail_map = true;
	expect("mapping failure", mk_restore_host_instance(), -ENOMEM);
	expect("mapping failure drops allocation", frees, 1);
	fail_map = false;
	fail_publish = true;
	expect("publication failure", mk_restore_host_instance(), -ENOMEM);
	expect("publication failure unmaps", unmaps, 1);
	expect("publication failure drops allocation", frees, 2);
	printf("Host target: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
