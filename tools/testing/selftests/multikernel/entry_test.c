// SPDX-License-Identifier: GPL-2.0-only
/* Real architecture hooks/secondary redirection; controlled allocator/map. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libfdt.h>

#define phys_addr_t uintptr_t
#define PAGE_SIZE 4096UL
#define MEMREMAP_WB 1
#define MK_FDT_ENTRY_STUB "multikernel,entry-stub"
#define WARN_ON_ONCE(x) (x)
#define WRITE_ONCE(x, v) ((x) = (v))
#define IS_ALIGNED(x, a) (!((x) & ((a) - 1)))
#define virt_to_phys(x) ((uintptr_t)(x))
#define pr_err_once(...) do { } while (0)
static const char stub_code[28] = { 15, 16 };
#define mk_riscv_entry_stub_start stub_code
#define mk_riscv_entry_stub_end (stub_code + sizeof(stub_code))
struct mk_riscv_spawn_context { unsigned long image_entry; };
struct mk_instance {
	struct {
		struct mk_riscv_spawn_context *ctx;
		phys_addr_t ctx_phys, stub_phys;
		const void *stub;
	} arch;
};
struct kimage { int unused; };
static void *block;
static bool fail_alloc, fail_map, spawned, ordered;
static unsigned int allocations, mappings;
static phys_addr_t manifest_stub;

static void *mk_instance_ctrl_alloc(struct mk_instance *instance, size_t size, size_t align)
{
	assert(instance && size == 2 * PAGE_SIZE && align == PAGE_SIZE);
	allocations++;
	return fail_alloc ? NULL : block;
}

static bool mk_spawned(void) { return spawned; }
static phys_addr_t mk_manifest_entry_stub_phys(void) { return manifest_stub; }
static void *memremap(phys_addr_t addr, size_t size, unsigned long flags)
{
	assert(addr == (uintptr_t)block && size == PAGE_SIZE && flags == MEMREMAP_WB);
	mappings++;
	return fail_map ? NULL : block;
}

/* Observe call ordering only; this host test cannot prove memory ordering. */
static void smp_wmb(void) { ordered = true; }
static void memunmap(void *addr) { assert(addr == block && ordered); }
#include "prepare.h"
#include "secondary.h"

int main(void)
{
	struct mk_instance instance = { 0 };
	struct kimage image = { 0 };
	unsigned long entry = 0x80402000;
	char fdt[4096];
	const fdt64_t *property;
	int len;

	block = aligned_alloc(PAGE_SIZE, 2 * PAGE_SIZE);
	assert(block);
	memset(block, 0, 2 * PAGE_SIZE);
	fail_alloc = true;
	assert(mk_arch_prepare_instance(&image, &instance) == -ENOMEM);
	assert(!instance.arch.ctx && !instance.arch.stub_phys);
	fail_alloc = false;
	assert(!mk_arch_prepare_instance(&image, &instance));
	assert(instance.arch.ctx == block && instance.arch.stub == block + PAGE_SIZE);
	assert(instance.arch.stub_phys == (uintptr_t)block + PAGE_SIZE);
	assert(!memcmp(instance.arch.stub, stub_code, sizeof(stub_code)));
	assert(!mk_arch_prepare_instance(&image, &instance) && allocations == 2);
	assert(!fdt_create(fdt, sizeof(fdt)) && !fdt_finish_reservemap(fdt));
	assert(!fdt_begin_node(fdt, "") && !fdt_begin_node(fdt, "chosen"));
	assert(!mk_arch_manifest_chosen(fdt, &image, &instance));
	assert(!fdt_end_node(fdt) && !fdt_end_node(fdt) && !fdt_finish(fdt));
	property = fdt_getprop(fdt, fdt_path_offset(fdt, "/chosen"), MK_FDT_ENTRY_STUB, &len);
	assert(property && len == 8 && fdt64_ld(property) == instance.arch.stub_phys);
	assert(!sbi_spawn_cpu_entry(&entry) && entry == 0x80402000 && !mappings);
	spawned = true;
	assert(sbi_spawn_cpu_entry(&entry) == -EINVAL && !mappings);
	manifest_stub = instance.arch.stub_phys + 1;
	assert(sbi_spawn_cpu_entry(&entry) == -EINVAL && !mappings);
	manifest_stub = instance.arch.stub_phys;
	fail_map = true;
	assert(sbi_spawn_cpu_entry(&entry) == -ENOMEM && entry == 0x80402000);
	fail_map = false;
	assert(!sbi_spawn_cpu_entry(&entry));
	assert(entry == manifest_stub && instance.arch.ctx->image_entry == 0x80402000);
	assert(ordered && mappings == 2);
	free(block);
	puts("PASS: control preparation, chosen property and secondary mapping/failure ordering");
	return 0;
}
