// SPDX-License-Identifier: GPL-2.0-only
/* Real pool/metadata release; architecture release and allocator injected. */
#include <assert.h>
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
struct resource { u64 start, end; void *parent; char *name; };
struct mk_memory_region { struct list_head list; struct resource res; };
struct mk_instance {
	int id, state, region_count;
	const char *name;
	void *instance_pool, *ctrl_va, *kimage;
	u64 ctrl_phys;
	size_t pool_size, ctrl_used;
	struct list_head memory_regions;
};
static int arch_error;
static unsigned int frees, removals, pools, controls, checks, failures;
#define resource_size(p) ((p)->end - (p)->start + 1)
static int mk_arch_release_instance(struct mk_instance *p) { (void)p; return arch_error; }
static void remove_resource(struct resource *p) { (void)p; removals++; }
static void kfree(void *p) { if (p) { frees++; free(p); } }
static void mk_instance_mem_free(struct mk_instance *p, void *ptr, size_t size)
{
	assert(ptr == p->ctrl_va && size == MK_CTRL_BLOCK_SIZE);
	controls++;
}
static void multikernel_destroy_instance_pool(void *p) { assert(p); pools++; }
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
	int control;

	for (i = 0; i < 5; i++) {
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
		frees = removals = pools = controls = 0;
		arch_error = i == 0 ? -EBUSY : 0;
		if (i == 1)
			p.state = MK_STATE_ACTIVE;
		if (i == 2)
			p.state = MK_STATE_FAILED;
		if (i == 3)
			p.kimage = &p;
		mk_instance_free_memory(&p);
		if (i != 4) {
			expect("unsafe release retains allocation", p.instance_pool != NULL, 1);
			expect("unsafe release retains region metadata", p.region_count, 1);
			expect("unsafe release detaches nothing", frees + removals + pools + controls, 0);
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
	printf("Memory teardown: %u checks, %u failures\n", checks, failures);
	return failures ? 1 : 0;
}
