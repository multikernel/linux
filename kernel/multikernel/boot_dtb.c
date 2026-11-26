// SPDX-License-Identifier: GPL-2.0-only
/*
 * The device tree an instance boots from, where that tree is the only
 * boot channel.
 *
 * It carries both halves of what x86 splits between boot_params and the
 * manifest: the instance tree the generic code wrote, with its /resources
 * and /chosen, is the base, and the nodes the architecture's boot path
 * itself reads go on top. /memory and what the loader put in /chosen are
 * the same everywhere and added here; the CPUs, the interrupt controller
 * and the rest of the platform are the architecture's.
 *
 * It is rebuilt on every spawn, into the device tree segment the loader
 * left room for: the memory grant and the CPUs can change between load
 * and exec, and a tree made at load would hand the spawn what it owned
 * back then.
 *
 * The other end is here too: what a kernel booted from such a tree takes
 * from it before it lays out memory.
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/init.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/minmax.h>
#include <linux/multikernel.h>
#include <linux/multikernel_fw_park.h>
#include <linux/of_fdt.h>

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

static int mk_dtb_add_chosen(void *fdt, const void *loader_fdt,
			     struct mk_instance *instance)
{
	int from, to, i, ret;

	from = fdt_path_offset(loader_fdt, "/chosen");
	if (from < 0)
		return 0;

	to = fdt_path_offset(fdt, "/chosen");
	if (to < 0)
		return to;

	for (i = 0; i < ARRAY_SIZE(mk_chosen_props); i++) {
		const void *val;
		int len;

		val = fdt_getprop(loader_fdt, from, mk_chosen_props[i], &len);
		if (!val)
			continue;
		ret = fdt_setprop(fdt, to, mk_chosen_props[i], val, len);
		if (ret)
			return ret;
	}

	/* This run was started with a command line of its own */
	if (instance->cmdline) {
		ret = fdt_setprop(fdt, to, "bootargs", instance->cmdline,
				  instance->cmdline_len);
		if (ret)
			return ret;
	}

	/* BARs and bridge windows are the host's to assign, for every kernel */
	return fdt_setprop_u32(fdt, to, "linux,pci-probe-only", 1);
}

static struct kexec_segment *mk_dtb_segment(struct kimage *image,
					    unsigned long dtb_mem)
{
	unsigned long i;

	for (i = 0; dtb_mem && i < image->nr_segments; i++) {
		if (image->segment[i].mem == dtb_mem)
			return &image->segment[i];
	}
	return NULL;
}

/**
 * mk_build_boot_dtb - Write an instance's boot tree over the loader's
 * @image: Loaded kimage, its manifest already finalized for this spawn
 * @instance: Instance being spawned
 * @dtb_mem: Where the loader placed the device tree segment
 * @loader_fdt: The tree the loader made, for what only it knows
 * @arch_nodes: Adds the nodes the architecture's boot path reads, and
 *              returns a libfdt error code
 *
 * Returns 0, -ENOSPC when the segment is too small, -ENOMEM when it cannot
 * be mapped, or -EINVAL.
 */
int mk_build_boot_dtb(struct kimage *image, struct mk_instance *instance,
		      unsigned long dtb_mem, const void *loader_fdt,
		      int (*arch_nodes)(void *fdt, struct mk_instance *instance))
{
	struct kexec_segment *seg = mk_dtb_segment(image, dtb_mem);
	void *fdt;
	int ret;

	if (!seg || !loader_fdt || !instance->manifest_phys) {
		pr_err("Instance %d has no boot device tree\n", instance->id);
		return -EINVAL;
	}

	/* Instance memory is not in this kernel's linear map */
	fdt = memremap(seg->mem, seg->memsz, MEMREMAP_WB);
	if (!fdt)
		return -ENOMEM;
	ret = fdt_open_into(phys_to_virt(instance->manifest_phys), fdt, seg->memsz);
	if (!ret)
		ret = mk_dtb_add_memory(fdt, instance);
	if (!ret)
		ret = arch_nodes(fdt, instance);
	if (!ret)
		ret = mk_dtb_add_chosen(fdt, loader_fdt, instance);
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

static phys_addr_t mk_ram_start __initdata = PHYS_ADDR_MAX;

/* Hot-added RAM must fall inside the linear map, which starts at boot */
void __init mk_register_ram(phys_addr_t start, u64 size)
{
	if (size)
		mk_ram_start = min(mk_ram_start, start);
}

phys_addr_t __init mk_linear_map_start(phys_addr_t dram_start)
{
	return min(dram_start, mk_ram_start);
}

void __init mk_spawn_accept_boot_tree(phys_addr_t dt_phys)
{
	if (!initial_boot_params ||
	    !of_flat_dt_is_compatible(of_get_flat_dt_root(), MK_FDT_COMPATIBLE))
		return;

	mk_manifest_populate(dt_phys, fdt_totalsize(initial_boot_params));
}
