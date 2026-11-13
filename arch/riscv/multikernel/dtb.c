// SPDX-License-Identifier: GPL-2.0-only
/*
 * The device tree a RISC-V instance boots from.
 *
 * The tree in a1 is the only boot channel, so it carries both halves of
 * what x86 splits between boot_params and the manifest: the instance tree
 * the generic code wrote, with its /resources and /chosen, is the base,
 * and the nodes the RISC-V boot path itself reads go on top: /memory and
 * /cpus, whose nodes also hold each hart's local interrupt controller,
 * and the IMSIC that takes the instance's MSIs.
 *
 * It is rebuilt on every spawn, into the device tree segment the loader
 * left room for: the memory grant and the harts can change between load
 * and exec, and a tree made at load would hand the spawn what it owned
 * back then.
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>

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

static int mk_dtb_copy_props(void *fdt, int node, struct device_node *np)
{
	struct property *pp;
	int ret;

	for_each_property_of_node(np, pp) {
		if (!strcmp(pp->name, "name"))
			continue;
		ret = fdt_setprop(fdt, node, pp->name, pp->value, pp->length);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Copy @np with its properties and its children under @parent, and return
 * the new node's offset. The phandles come along, so references between
 * copied nodes, an interrupt controller's interrupts-extended naming the
 * harts' local controllers for one, keep working.
 */
int mk_dtb_copy_node(void *fdt, int parent, struct device_node *np)
{
	struct device_node *child;
	int node, ret;

	node = fdt_add_subnode(fdt, parent, np->full_name);
	if (node < 0)
		return node;

	ret = mk_dtb_copy_props(fdt, node, np);
	if (ret)
		return ret;

	for_each_child_of_node(np, child) {
		ret = mk_dtb_copy_node(fdt, node, child);
		if (ret < 0) {
			of_node_put(child);
			return ret;
		}
	}
	return node;
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

static struct device_node *mk_of_hart_node(mk_phys_cpu_t hartid)
{
	struct device_node *np;

	for_each_of_cpu_node(np) {
		if (of_get_cpu_hwid(np, 0) == hartid)
			return np;
	}
	return NULL;
}

/*
 * The instance's own harts come first, the boot hart leading as it does
 * in instance->cpus, so they get the low logical numbers. Every other
 * hart of the machine follows: a kernel can only ever online a hart it
 * enumerated at boot, and the generic code prunes the ones the instance
 * does not own from the present mask.
 *
 * The host's nodes are copied verbatim: the ISA strings, the MMU type and
 * the cache block sizes describe that hart as firmware set it up, and a
 * spawn probing an extension firmware left off on a hart would trap.
 *
 * fdt_add_subnode() puts a new node ahead of its siblings, hence the
 * instance's harts last and from the last to the first.
 */
static int mk_dtb_add_cpus(void *fdt, struct mk_instance *instance)
{
	struct device_node *cpus, *np;
	unsigned int i;
	int node, ret;

	cpus = of_find_node_by_path("/cpus");
	if (!cpus) {
		pr_err("The host tree has no /cpus\n");
		return -FDT_ERR_NOTFOUND;
	}

	node = fdt_add_subnode(fdt, 0, "cpus");
	ret = node < 0 ? node : mk_dtb_copy_props(fdt, node, cpus);
	of_node_put(cpus);
	if (ret)
		return ret;

	for_each_of_cpu_node(np) {
		if (mk_cpu_set_contains(instance->cpus, of_get_cpu_hwid(np, 0)))
			continue;
		ret = mk_dtb_copy_node(fdt, node, np);
		if (ret < 0) {
			of_node_put(np);
			return ret;
		}
	}

	for (i = mk_cpu_set_count(instance->cpus); i-- > 0; ) {
		mk_phys_cpu_t hartid = instance->cpus->ids[i];

		np = mk_of_hart_node(hartid);
		if (!np) {
			pr_err("The host tree has no hart %llu\n", hartid);
			return -FDT_ERR_NOTFOUND;
		}
		ret = mk_dtb_copy_node(fdt, node, np);
		of_node_put(np);
		if (ret < 0)
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

	/* BARs and bridge windows are the host's to assign, for every kernel */
	return fdt_setprop_u32(fdt, to, "linux,pci-probe-only", 1);
}

static struct kexec_segment *mk_dtb_segment(struct kimage *image)
{
	unsigned long i;

	for (i = 0; i < image->nr_segments; i++) {
		if (image->segment[i].mem == image->arch.fdt_addr)
			return &image->segment[i];
	}
	return NULL;
}

/**
 * mk_build_boot_dtb - Write an instance's boot tree over the loader's
 * @image: Loaded kimage, its manifest already finalized for this spawn
 * @instance: Instance being spawned
 *
 * Returns 0, -ENOSPC when the segment is too small, -ENOMEM when it cannot
 * be mapped, or -EINVAL.
 */
int mk_build_boot_dtb(struct kimage *image, struct mk_instance *instance)
{
	struct kexec_segment *seg = mk_dtb_segment(image);
	void *fdt;
	int ret;

	if (!seg || !image->arch.fdt || !instance->manifest_phys)
		return -EINVAL;

	/* Instance memory is not in this kernel's linear map */
	fdt = memremap(seg->mem, seg->memsz, MEMREMAP_WB);
	if (!fdt)
		return -ENOMEM;
	ret = fdt_open_into(phys_to_virt(instance->manifest_phys), fdt, seg->memsz);
	if (!ret)
		ret = mk_dtb_add_memory(fdt, instance);
	if (!ret)
		ret = mk_dtb_add_cpus(fdt, instance);
	if (!ret)
		ret = mk_dtb_add_imsic(fdt);
	if (!ret)
		ret = mk_dtb_add_chosen(fdt, image->arch.fdt);
	if (!ret)
		ret = fdt_pack(fdt);
	if (ret) {
		pr_err("Instance %d: %s\n", instance->id, fdt_strerror(ret));
		ret = ret == -FDT_ERR_NOSPACE ? -ENOSPC : -EINVAL;
	} else {
		pr_info("Instance %d boots from a %u byte tree at %#lx\n",
			instance->id, fdt_totalsize(fdt), seg->mem);
	}
	memunmap(fdt);
	return ret;
}
