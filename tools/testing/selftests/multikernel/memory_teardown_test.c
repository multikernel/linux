// SPDX-License-Identifier: GPL-2.0-only
/* Real pool/metadata release; architecture release and allocator injected. */
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/list.h>

#define u64 __u64
#define MK_STATE_READY 1
#define MK_STATE_ACTIVE 3
#define MK_STATE_FAILED 4
#define MK_CTRL_BLOCK_SIZE 4096
#define pr_debug(...) do { } while (0)
#define pr_info(...) do { if (0) printf(__VA_ARGS__); } while (0)
#define pr_err(...) do { } while (0)
#define pr_warn(...) do { } while (0)
struct resource { u64 start, end; void *parent; char *name; };
struct mk_memory_region { struct list_head list; struct resource res; };
struct mk_pci_device { struct list_head list; };
struct mk_platform_device { struct list_head list; };
struct mk_dt_config { int unused; };
struct mk_instance {
	int id, state, region_count;
	int resource_uncertain;
	const char *name;
	void *instance_pool, *ctrl_va, *kimage, *cpus_on_slot;
	u64 ctrl_phys;
	size_t pool_size, ctrl_used;
	struct list_head memory_regions, pci_devices, platform_devices;
	int pci_device_count, platform_device_count;
	bool pci_devices_valid, platform_devices_valid;
};
static struct mk_instance *mk_self;
#define mk_cpu_set_empty(p) (!(p))
static int arch_error, unmap_error;
static unsigned int frees, removals, pools, controls, unmaps, checks, failures;
static unsigned int arch_calls;
#define resource_size(p) ((p)->end - (p)->start + 1)
static int mk_arch_release_instance(struct mk_instance *p)
{
	(void)p;
	arch_calls++;
	return arch_error;
}
static void remove_resource(struct resource *p) { (void)p; removals++; }
static void kfree(void *p)
{
	if (p) {
		frees++;
		free(p);
	}
}
static void mk_instance_mem_free(struct mk_instance *p, void *ptr, size_t size)
{
	assert(ptr == p->ctrl_va && size == MK_CTRL_BLOCK_SIZE);
	assert(unmaps == 1);
	controls++;
}
static int mk_pool_unmap(u64 start, size_t size)
{
	assert(start == 0x1000 && size == MK_CTRL_BLOCK_SIZE && !controls);
	unmaps++;
	return unmap_error;
}
static void multikernel_destroy_instance_pool(void *p) { assert(p); pools++; }
static unsigned int reservations;
static int mk_instance_reserve_memory(struct mk_instance *p, const struct mk_dt_config *c)
{
	(void)p;
	(void)c;
	reservations++;
	return 0;
}
#define mk_instance_reserve_cpus mk_instance_reserve_memory
#define mk_instance_reserve_pci_devices mk_instance_reserve_memory
#define mk_instance_reserve_platform_devices mk_instance_reserve_memory
#include "memory-production.h"

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
	struct mk_instance p;
	struct mk_memory_region *region;
	unsigned int i;
	int control, ret;
	struct mk_dt_config config = { 0 };
	struct mk_pci_device *pci;

	/* The running host has no reserved memory at first baseline admission. */
	for (i = 0; i < 10; i++) {
		struct mk_memory_region owned = { 0 };

		p = (struct mk_instance) { .state = MK_STATE_READY };
		INIT_LIST_HEAD(&p.memory_regions);
		INIT_LIST_HEAD(&p.pci_devices);
		INIT_LIST_HEAD(&p.platform_devices);
		mk_self = i == 9 ? NULL : &p;
		if (i == 1)
			p.state = MK_STATE_ACTIVE;
		if (i == 2)
			p.state = MK_STATE_FAILED;
		if (i == 3)
			p.kimage = &p;
		if (i == 4)
			p.resource_uncertain = 1;
		if (i == 5)
			p.instance_pool = &p;
		if (i == 6)
			p.ctrl_va = &control;
		if (i == 7)
			list_add(&owned.list, &p.memory_regions);
		if (i == 8)
			p.cpus_on_slot = &p;
		arch_error = -EBUSY;
		arch_calls = frees = removals = pools = controls = unmaps = 0;
		expect("baseline admission", mk_baseline_clear_resources(&p),
		       i == 0 ? 0 : -EBUSY);
		expect("only owned or child memory needs stop proof", arch_calls, i >= 5);
		expect("running host loses no allocation", frees + removals + pools + controls, 0);
	}
	mk_self = NULL;

	for (i = 0; i < 7; i++) {
		p = (struct mk_instance) { .id = 7, .name = "spawn", .state = MK_STATE_READY,
			.instance_pool = &p, .pool_size = 4096, .ctrl_va = &control,
			.ctrl_phys = 0x1000, .ctrl_used = 64, .region_count = 1 };
		INIT_LIST_HEAD(&p.memory_regions);
		region = calloc(1, sizeof(*region));
		assert(region);
		region->res = (struct resource) { .start = 0x1000, .end = 0x1fff,
			.parent = &p, .name = strdup("memory") };
		assert(region->res.name);
		list_add(&region->list, &p.memory_regions);
		frees = removals = pools = controls = unmaps = 0;
		arch_error = i == 0 ? -EBUSY : 0;
		unmap_error = i == 6 ? -EIO : 0;
		if (i == 1)
			p.state = MK_STATE_ACTIVE;
		if (i == 2)
			p.state = MK_STATE_FAILED;
		if (i == 3)
			p.kimage = &p;
		if (i == 5)
			p.resource_uncertain = 1;
		ret = mk_instance_free_memory(&p);
		expect("release status", ret, i == 4 ? 0 : i == 6 ? -EIO : -EBUSY);
		if (i != 4) {
			expect("unsafe release retains allocation", p.instance_pool != NULL, 1);
			expect("unsafe release retains region metadata", p.region_count, 1);
			expect("unsafe release retains control address", p.ctrl_va == &control, 1);
			expect("unsafe release retains control accounting", p.ctrl_used, 64);
			expect("unsafe release detaches nothing", frees + removals + pools + controls, 0);
			expect("only stopped memory reaches unmap", unmaps, i == 6);
			/* Dispose only fixture objects, including the baseline's broken case. */
			if (!frees) {
				free(region->res.name);
				free(region);
			}
		} else {
			expect("confirmed release returns pool", p.instance_pool == NULL, 1);
			expect("confirmed release clears metadata", list_empty(&p.memory_regions), 1);
			expect("confirmed release frees metadata", frees, 2);
			expect("confirmed release returns control allocation", controls, 1);
			expect("confirmed release returns pool once", pools, 1);
		}
	}
	/* Re-reservation and baseline replacement must not bypass unmap refusal. */
	p = (struct mk_instance) { .state = MK_STATE_READY, .ctrl_va = &control,
		.ctrl_phys = 0x1000, .instance_pool = &p, .pci_device_count = 1,
		.pci_devices_valid = true };
	INIT_LIST_HEAD(&p.memory_regions);
	INIT_LIST_HEAD(&p.pci_devices);
	INIT_LIST_HEAD(&p.platform_devices);
	pci = calloc(1, sizeof(*pci));
	assert(pci);
	list_add(&pci->list, &p.pci_devices);
	arch_error = 0;
	unmap_error = -EIO;
	frees = controls = 0;
	expect("re-reservation propagates failure", mk_instance_reserve_resources(&p, &config), -EIO);
	expect("no replacement reservation", reservations, 0);
	expect("baseline propagates failure", mk_baseline_clear_resources(&p), -EIO);
	expect("baseline device metadata retained", !list_empty(&p.pci_devices), 1);
	expect("baseline count retained", p.pci_device_count, 1);
	expect("baseline no free on error", frees, 0);
	free(pci);
	printf("Memory teardown: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
