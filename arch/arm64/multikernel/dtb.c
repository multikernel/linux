// SPDX-License-Identifier: GPL-2.0
/*
 * The device tree an arm64 instance boots from.
 *
 * On arm64 the tree in x0 is the only boot channel, so it carries both
 * halves of what x86 splits between boot_params and the manifest: the
 * instance tree the generic code wrote, with its /resources and /chosen,
 * is the base, and the nodes the arm64 boot path itself reads go on top:
 * /memory, /cpus, PSCI, the arch timer and the interrupt controller.
 *
 * It is rebuilt on every spawn, into the device tree segment the loader
 * left room for: the memory grant and the CPUs can change between load
 * and exec, and a tree made at load would hand the spawn what it owned
 * back then.
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/acpi.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <asm/cputype.h>

#include "internal.h"

static_assert(MK_MANIFEST_SIZE + SZ_64K <= MK_BOOT_DTB_SIZE);

/* What the loader's tree knows and nobody else does */
static const char * const mk_chosen_props[] = {
	"bootargs",
	"linux,initrd-start",
	"linux,initrd-end",
	"kaslr-seed",
	"rng-seed",
};

/* @pairs are base,size; the root of the instance tree has two cells for each */
int mk_dtb_set_reg(void *fdt, int node, const u64 *pairs, int nr)
{
	int i, ret;

	ret = fdt_delprop(fdt, node, "reg");
	if (ret && ret != -FDT_ERR_NOTFOUND)
		return ret;

	for (i = 0; i < 2 * nr; i++) {
		ret = fdt_appendprop_u64(fdt, node, "reg", pairs[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int mk_dtb_add_memory(void *fdt, struct mk_instance *instance)
{
	struct mk_memory_region *region;
	char name[32];
	int node, ret;

	list_for_each_entry(region, &instance->memory_regions, list) {
		u64 reg[2] = { region->res.start, resource_size(&region->res) };

		snprintf(name, sizeof(name), "memory@%llx", reg[0]);
		node = fdt_add_subnode(fdt, 0, name);
		if (node < 0)
			return node;
		ret = fdt_setprop_string(fdt, node, "device_type", "memory");
		if (!ret)
			ret = mk_dtb_set_reg(fdt, node, reg, 1);
		if (ret)
			return ret;
	}
	return 0;
}

static int mk_dtb_add_cpu(void *fdt, int cpus, mk_phys_cpu_t mpidr)
{
	char name[32];
	int node, ret;

	snprintf(name, sizeof(name), "cpu@%llx", mpidr);
	node = fdt_add_subnode(fdt, cpus, name);
	if (node < 0)
		return node;

	ret = fdt_setprop_string(fdt, node, "device_type", "cpu");
	if (!ret)
		ret = fdt_setprop_string(fdt, node, "compatible", "arm,armv8");
	if (!ret)
		ret = fdt_setprop_string(fdt, node, "enable-method", "psci");
	if (!ret)
		ret = fdt_setprop_u64(fdt, node, "reg", mpidr);
	return ret;
}

/*
 * The instance's own CPUs come first, the boot CPU leading as it does in
 * instance->cpus, so they get the low logical numbers. Every other CPU
 * of the machine follows: a kernel can only ever online a CPU it
 * enumerated at boot, and the generic code prunes the ones the instance
 * does not own from the present mask.
 *
 * fdt_add_subnode() puts a new node ahead of its siblings, hence the
 * walk from the last CPU to the first.
 */
static int mk_dtb_add_cpus(void *fdt, struct mk_instance *instance)
{
	mk_phys_cpu_t mpidr;
	unsigned int i;
	int cpus, cpu, ret;

	cpus = fdt_add_subnode(fdt, 0, "cpus");
	if (cpus < 0)
		return cpus;
	ret = fdt_setprop_u32(fdt, cpus, "#address-cells", 2);
	if (!ret)
		ret = fdt_setprop_u32(fdt, cpus, "#size-cells", 0);
	if (ret)
		return ret;

	for (cpu = nr_cpu_ids - 1; cpu >= 0; cpu--) {
		if (!cpu_possible(cpu))
			continue;
		mpidr = arch_cpu_physical_id(cpu);
		if (mpidr == INVALID_HWID ||
		    mk_cpu_set_contains(instance->cpus, mpidr))
			continue;
		ret = mk_dtb_add_cpu(fdt, cpus, mpidr);
		if (ret)
			return ret;
	}

	for (i = mk_cpu_set_count(instance->cpus); i-- > 0; ) {
		ret = mk_dtb_add_cpu(fdt, cpus, instance->cpus->ids[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static int mk_dtb_add_chosen(void *fdt, const void *loader_fdt)
{
	int from, to, i;

	from = fdt_path_offset(loader_fdt, "/chosen");
	if (from < 0)
		return 0;

	to = fdt_path_offset(fdt, "/chosen");
	if (to < 0)
		return to;

	for (i = 0; i < ARRAY_SIZE(mk_chosen_props); i++) {
		const void *val;
		int len, ret;

		val = fdt_getprop(loader_fdt, from, mk_chosen_props[i], &len);
		if (!val)
			continue;
		ret = fdt_setprop(fdt, to, mk_chosen_props[i], val, len);
		if (ret)
			return ret;
	}
	return 0;
}

static struct kexec_segment *mk_dtb_segment(struct kimage *image)
{
	unsigned long i;

	for (i = 0; i < image->nr_segments; i++) {
		if (image->segment[i].mem == image->arch.dtb_mem)
			return &image->segment[i];
	}
	return NULL;
}

/**
 * mk_build_boot_dtb - Write an instance's boot tree over the loader's
 * @image: Loaded kimage, its manifest already finalized for this spawn
 * @instance: Instance being spawned
 *
 * Everything that adds to the tree returns libfdt error codes, which
 * share their values with errnos and must not be mixed with them.
 *
 * Returns 0, -ENOSPC when the segment is too small, or -EINVAL.
 */
int mk_build_boot_dtb(struct kimage *image, struct mk_instance *instance)
{
	struct kexec_segment *seg = mk_dtb_segment(image);
	void *fdt;
	int ret;

	if (!seg || !image->arch.dtb || !image->mk_manifest)
		return -EINVAL;

	fdt = phys_to_virt(seg->mem);
	ret = fdt_open_into(phys_to_virt(image->mk_manifest), fdt, seg->memsz);
	if (!ret)
		ret = mk_dtb_add_memory(fdt, instance);
	if (!ret)
		ret = mk_dtb_add_cpus(fdt, instance);
	if (!ret)
		ret = mk_dtb_add_chosen(fdt, image->arch.dtb);
	if (!ret)
		ret = acpi_disabled ? mk_dtb_add_platform_of(fdt) :
				      mk_dtb_add_platform_acpi(fdt);
	if (!ret)
		ret = mk_dtb_add_devices(fdt, instance);
	if (!ret)
		ret = fdt_pack(fdt);
	if (ret) {
		pr_err("Instance %d: %s\n", instance->id, fdt_strerror(ret));
		return ret == -FDT_ERR_NOSPACE ? -ENOSPC : -EINVAL;
	}

	pr_info("Instance %d boots from a %u byte tree at %#lx\n",
		instance->id, fdt_totalsize(fdt), seg->mem);
	return 0;
}
