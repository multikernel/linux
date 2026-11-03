// SPDX-License-Identifier: GPL-2.0-only
/* Real manifest orchestration and libfdt, controlled architecture boundary. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <libfdt.h>

#define phys_addr_t uintptr_t
typedef uint32_t u32;
typedef uint64_t u64;
#define MK_MANIFEST_SIZE (256 * 1024)
#define PAGE_SHIFT 12
#define PAGE_ALIGN(x) (((x) + 4095) & ~4095UL)
#define phys_to_virt(p) ((void *)(p))
#define pr_err(...) do { } while (0)
#define pr_warn(...) do { } while (0)
#define pr_info(...) do { } while (0)
#define arch_cpu_physical_id(cpu) ((u64)(cpu))
#define mk_pool_park_slot() 0
struct mk_shared_data { char ring[4096]; };
struct mk_instance {
	void *ipi_data, *host_tree;
	phys_addr_t ipi_phys, manifest_phys;
	u32 ipi_pages;
};
struct kimage { int mk_id; struct mk_instance *mk_instance; };
static struct mk_instance host, target, *mk_self = &host;
static int prepared, prepare_error, hook_error, hook_calls, refs;
static int phase, pci_calls, host_error, pci_error;

static struct mk_instance *mk_instance_find(int id)
{
	assert(id == 1);
	refs++;
	return &target;
}

static void mk_instance_put(struct mk_instance *instance)
{
	assert(instance == &target);
	refs--;
}

static int mk_arch_prepare_instance(struct kimage *image, struct mk_instance *instance)
{
	assert(image->mk_id == 1 && instance == &target);
	if (prepare_error)
		return prepare_error;
	prepared = 1;
	phase = 1;
	return 0;
}

static int mk_arch_manifest_chosen(void *fdt, struct kimage *image,
				   struct mk_instance *instance)
{
	assert(prepared && image->mk_id == 1 && instance == &target);
	assert(phase == 1);
	phase = 2;
	hook_calls++;
	return hook_error ? hook_error :
		fdt_property_u64(fdt, "multikernel,entry-stub", 0xc0010000);
}

static int mk_manifest_add_reserved(void *fdt, struct kimage *image)
{
	(void)image;
	return fdt_property_u32(fdt, "test-reserved", 1);
}

static int mk_manifest_add_host_tree(void *fdt, struct mk_instance *instance)
{
	static const char padding[8192] = { 42 };
	int ret;

	assert(instance == &target && phase == 2);
	phase = 3;
	if (host_error)
		return host_error;
	ret = fdt_begin_node(fdt, "multikernel,host-tree");
	if (!ret)
		ret = fdt_property(fdt, "test-data", padding, sizeof(padding));
	return ret ? ret : fdt_end_node(fdt);
}

static int mk_dt_emit_pci_buses(void *fdt)
{
	int ret;

	assert(phase == 3);
	phase = 4;
	pci_calls++;
	if (pci_error)
		return pci_error;
	ret = fdt_begin_node(fdt, "test-pci");
	return ret ? ret : fdt_end_node(fdt);
}

static int mk_dt_emit_boot_tree(struct mk_instance *instance, void *fdt, size_t size,
			       int (*chosen)(void *, void *), void *ctx)
{
	int ret;

	assert(instance == &target);
	assert(!fdt_create(fdt, size));
	assert(!fdt_finish_reservemap(fdt));
	assert(!fdt_begin_node(fdt, ""));
	assert(!fdt_begin_node(fdt, "chosen"));
	ret = chosen(fdt, ctx);
	if (ret)
		return ret;
	assert(!fdt_end_node(fdt));
	assert(!fdt_end_node(fdt));
	return fdt_finish(fdt);
}

#include "under-test.h"

int main(void)
{
	void *fdt = malloc(MK_MANIFEST_SIZE);
	struct kimage image = { .mk_id = 1, .mk_instance = &target };
	const fdt64_t *entry;
	const char *data;
	int chosen, node, len;

	assert(fdt);
	target.manifest_phys = (uintptr_t)fdt;
	target.host_tree = &target;
	target.ipi_phys = 0xc0020000;
	target.ipi_pages = 1;
	assert(!mk_manifest_finalize(&image));
	assert(prepared && hook_calls == 1 && !refs && phase == 4 && pci_calls == 1);
	assert(fdt_path_offset(fdt, "/chosen/test-pci") >= 0);
	assert(!fdt_check_header(fdt));
	assert(fdt_totalsize(fdt) > 4096);
	chosen = fdt_path_offset(fdt, "/chosen");
	entry = fdt_getprop(fdt, chosen, "multikernel,entry-stub", &len);
	assert(entry && len == 8 && fdt64_ld(entry) == 0xc0010000);
	entry = fdt_getprop(fdt, chosen, "multikernel,ipi-buffer", &len);
	assert(entry && len == 8 && fdt64_ld(entry) == 0xc0020000);
	node = fdt_path_offset(fdt, "/chosen/multikernel,host-tree");
	data = fdt_getprop(fdt, node, "test-data", &len);
	assert(data && len == 8192 && data[0] == 42 && data[8191] == 0);
	prepare_error = -ENOMEM;
	prepared = 0;
	assert(mk_manifest_finalize(&image) == -ENOMEM);
	assert(!prepared && hook_calls == 1 && !refs);
	prepare_error = 0;
	hook_error = -FDT_ERR_NOSPACE;
	assert(mk_manifest_finalize(&image) == -ENOSPC && !refs);
	hook_error = -EINVAL;
	assert(mk_manifest_finalize(&image) == -EINVAL && !refs);
	hook_error = 0;
	host_error = -EIO;
	pci_calls = 0;
	assert(mk_manifest_finalize(&image) == -EIO && !refs && !pci_calls);
	host_error = 0;
	pci_error = -FDT_ERR_NOSPACE;
	assert(mk_manifest_finalize(&image) == -ENOSPC && !refs && pci_calls == 1);
	pci_error = 0;
	pci_calls = 0;
	target.host_tree = NULL;
	assert(!mk_manifest_finalize(&image) && !refs && !pci_calls && phase == 3);
	assert(fdt_path_offset(fdt, "/chosen/test-pci") == -FDT_ERR_NOTFOUND);
	free(fdt);
	puts("PASS: prepare/chosen/host/PCI ordering, optional PCI nodes, errors and references");
	return 0;
}
