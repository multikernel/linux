// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * The multikernel manifest: the device tree a spawn kernel boots from.
 * It is the instance's tree as the host generates it, with a /chosen
 * node carrying what only the boot handoff knows: the pool CPUs the
 * instance may receive later and the message ring addresses in both
 * directions. The spawn's OF core unflattens it like a tree from a
 * bootloader, so everything in it is read with the usual of_* helpers.
 *
 * The manifest travels on multikernel's own boot channel (a dedicated
 * setup_data type on x86, pointing at the tree), separate from KHO: a
 * spawn kernel may use the real KHO channel for its own live update
 * within its partition.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/ioport.h>
#include <linux/libfdt.h>
#include <linux/sort.h>
#include <linux/multikernel.h>

#include "internal.h"

/* Physical address of the manifest this kernel booted with, 0 if none */
static phys_addr_t mk_manifest_fdt_phys;

phys_addr_t mk_manifest_phys(void)
{
	return mk_manifest_fdt_phys;
}

/**
 * mk_manifest_populate() - Accept the manifest handed over at boot
 * @fdt_phys: Physical address of the manifest FDT
 * @fdt_len: Size of the manifest FDT
 *
 * Called during early boot from the arch's boot data parsing (x86
 * setup_data) or the generic device tree scan. Validates the blob and
 * records its location for the instance restore path.
 */
void __init mk_manifest_populate(phys_addr_t fdt_phys, u64 fdt_len)
{
	void *fdt = NULL;
	int err = 0;

	pr_info("multikernel: processing manifest at 0x%llx (size: %llu)\n",
		fdt_phys, fdt_len);

	fdt = early_memremap(fdt_phys, fdt_len);
	if (!fdt) {
		pr_warn("multikernel: failed to memremap manifest (0x%llx)\n",
			fdt_phys);
		goto out;
	}

	err = fdt_check_header(fdt);
	if (err) {
		pr_warn("multikernel: manifest (0x%llx) is invalid: %d\n",
			fdt_phys, err);
		goto out;
	}

	err = fdt_node_check_compatible(fdt, 0, MK_FDT_COMPATIBLE);
	if (err) {
		pr_warn("multikernel: manifest (0x%llx) is incompatible with '%s': %d\n",
			fdt_phys, MK_FDT_COMPATIBLE, err);
		goto out;
	}

	mk_manifest_fdt_phys = fdt_phys;

	pr_info("multikernel: manifest accepted\n");

out:
	if (fdt)
		early_memunmap(fdt, fdt_len);
	if (err)
		pr_warn("multikernel: ignoring invalid manifest\n");
}

/*
 * Collect every CPU the instance might receive through hotplug later:
 * the unassigned pool plus every other kernel's CPUs (the host's and
 * other instances'), minus the instance's own (those are already in its
 * DTB). The spawn kernel can only online a CPU whose physical ID it
 * enumerated at boot, so the whole pool must be in its topology from
 * the start.
 */
static int mk_phys_cpu_cmp(const void *a, const void *b)
{
	const mk_phys_cpu_t *x = a, *y = b;

	return *x < *y ? -1 : *x > *y;
}

static int mk_manifest_add_pool_cpus(void *fdt, struct mk_instance *target)
{
	struct mk_cpu_set *pool;
	struct mk_instance *other;
	mk_phys_cpu_t id;
	fdt64_t *cells;
	unsigned int i, count;
	int ret = 0;

	pool = mk_cpu_set_alloc();
	if (!pool)
		return -ENOMEM;

	mutex_lock(&mk_instance_mutex);
	list_for_each_entry(other, &mk_instance_list, list) {
		/*
		 * Skip the self instance: its set is the CPUs the host
		 * itself runs on, and enumerating a big host's full CPU set
		 * in every spawn bloats the spawn's possible map and percpu
		 * allocations.
		 */
		if (other == target || other == mk_self)
			continue;
		mk_cpu_set_for_each(i, id, other->cpus) {
			ret = mk_cpu_set_add(pool, id);
			if (ret)
				break;
		}
		if (ret)
			break;
	}
	if (!ret && mk_pool) {
		mk_cpu_set_for_each(i, id, mk_pool->cpus) {
			ret = mk_cpu_set_add(pool, id);
			if (ret)
				break;
		}
	}
	mutex_unlock(&mk_instance_mutex);

	count = mk_cpu_set_count(pool);
	if (ret || count == 0)
		goto out;

	cells = kmalloc_array(count, sizeof(*cells), GFP_KERNEL);
	if (!cells) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * The spawn assigns logical CPU ids in this list's order, and the
	 * pool set's insertion order churns with every instance create,
	 * delete and pool resize. Sort so a spawn's numbering does not
	 * depend on the host's operation history.
	 */
	sort(pool->ids, count, sizeof(*pool->ids), mk_phys_cpu_cmp, NULL);
	mk_cpu_set_for_each(i, id, pool)
		cells[i] = cpu_to_fdt64(id);

	ret = fdt_property(fdt, "multikernel,pool-cpus", cells, count * sizeof(*cells));
	kfree(cells);
out:
	mk_cpu_set_free(pool);
	return ret;
}

#define MK_NOTE_PAIRS 80

struct mk_note_ranges {
	u64 *pair;
	int n;
};

static int mk_note_add(struct mk_note_ranges *r, u64 base, u64 size)
{
	if (r->n == MK_NOTE_PAIRS)
		return -E2BIG;
	r->pair[2 * r->n] = base;
	r->pair[2 * r->n + 1] = size;
	r->n++;
	return 0;
}

static int mk_note_add_res(struct resource *res, void *arg)
{
	return mk_note_add(arg, res->start, resource_size(res));
}

static int mk_note_emit_reg(void *fdt, const char *name, u64 base, u64 size)
{
	fdt64_t reg[2] = { cpu_to_fdt64(base), cpu_to_fdt64(size) };
	char node[40];
	int ret;

	snprintf(node, sizeof(node), "%s@%llx", name, base);
	ret = fdt_begin_node(fdt, node);
	if (!ret && !strcmp(name, "memory"))
		ret = fdt_property_string(fdt, "device_type", "memory");
	if (!ret)
		ret = fdt_property(fdt, "reg", reg, sizeof(reg));
	if (!ret)
		ret = fdt_end_node(fdt);
	return ret;
}

/*
 * The takeover note: the host's own device tree, compiled at spawn
 * exec time and embedded verbatim in the spawn's boot tree. The spawn
 * never interprets it; it sits in /proc/device-tree like a sealed
 * note until the host stops answering, when the backup's user space
 * reads it and drives the takeover: every memory@ range minus its own
 * RAM minus /reserved-memory is takeable, and the fenced CPUs wait at
 * multikernel,pool-slot. /reserved-memory is the memory the takeover
 * machinery itself lives in (both ends' message rings, boot tree
 * pages, the pool park set): claiming it would corrupt the slot the
 * fenced CPUs spin on and the ring the backup still reads.
 */
static int mk_note_build(void *fdt, size_t size, struct kimage *image,
			 const void *pool_tree, size_t pool_tree_len)
{
	struct mk_note_ranges r;
	struct mk_instance *other;
	int ret, i;

	r.pair = kmalloc_array(2 * MK_NOTE_PAIRS, sizeof(*r.pair),
			       GFP_KERNEL);
	if (!r.pair)
		return -ENOMEM;

	ret = fdt_create(fdt, size);
	if (!ret)
		ret = fdt_finish_reservemap(fdt);
	if (!ret)
		ret = fdt_begin_node(fdt, "");
	if (!ret)
		ret = fdt_property_string(fdt, "compatible",
					  "multikernel-host-v1");
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 2);
	if (!ret && mk_pool && mk_pool->arch.slot_phys)
		ret = fdt_property_u64(fdt, "multikernel,pool-slot",
				       mk_pool->arch.slot_phys);
	if (ret)
		goto out;

	/* The machine's RAM, before any kernel's view of it */
	r.n = 0;
	ret = walk_system_ram_res(0, (u64)-1, &r, mk_note_add_res);
	for (i = 0; i < r.n && !ret; i++)
		ret = mk_note_emit_reg(fdt, "memory", r.pair[2 * i],
				       r.pair[2 * i + 1]);
	if (ret)
		goto out;

	r.n = 0;
	if (mk_self->ipi_data)
		ret = mk_note_add(&r, mk_self->ipi_phys,
				  (u64)mk_self->ipi_pages << PAGE_SHIFT);
	/*
	 * This image's ring and boot tree; the instance record points
	 * at them only after finalization, so take them from the image.
	 */
	if (!ret && image->mk_ipi)
		ret = mk_note_add(&r, image->mk_ipi,
				  PAGE_ALIGN(sizeof(struct mk_shared_data)));
	if (!ret && image->mk_manifest)
		ret = mk_note_add(&r, image->mk_manifest, MK_MANIFEST_SIZE);

	mutex_lock(&mk_instance_mutex);
	list_for_each_entry(other, &mk_instance_list, list) {
		if (ret)
			break;
		if (other == mk_self || !other->ipi_data)
			continue;
		ret = mk_note_add(&r, other->ipi_phys,
				  (u64)other->ipi_pages << PAGE_SHIFT);
		if (!ret && other->kimage && other->kimage->mk_manifest)
			ret = mk_note_add(&r, other->kimage->mk_manifest,
					  MK_MANIFEST_SIZE);
	}
	mutex_unlock(&mk_instance_mutex);
	if (!ret) {
		int pairs = mk_pool_park_regions(r.pair + 2 * r.n,
						 MK_NOTE_PAIRS - r.n);

		if (pairs < 0)
			ret = pairs;
		else
			r.n += pairs;
	}
	if (ret)
		goto out;

	if (pool_tree) {
		ret = fdt_property(fdt, "multikernel,pool-tree", pool_tree,
				   pool_tree_len);
		if (ret)
			goto out;
	}

	ret = fdt_begin_node(fdt, "reserved-memory");
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 2);
	if (!ret)
		ret = fdt_property(fdt, "ranges", NULL, 0);
	for (i = 0; i < r.n && !ret; i++)
		ret = mk_note_emit_reg(fdt, "region", r.pair[2 * i],
				       r.pair[2 * i + 1]);
	if (!ret)
		ret = fdt_end_node(fdt);	/* /reserved-memory */
	if (!ret)
		ret = fdt_end_node(fdt);	/* root */
	if (!ret)
		ret = fdt_finish(fdt);
out:
	kfree(r.pair);
	return ret;
}

#define MK_NOTE_MAX (MK_MANIFEST_SIZE - SZ_4K)

static int mk_manifest_add_note(void *fdt, struct kimage *image)
{
	void *note, *pool_tree = NULL;
	size_t pool_tree_len = 0;
	int ret;

	note = kmalloc(MK_NOTE_MAX, GFP_KERNEL);
	if (!note)
		return -ENOMEM;

	/*
	 * The host's own generated device tree rides along for richer
	 * takeover (CPU membership, chunk layout, device inventory). It
	 * is an extra, not a requirement: a pool tree too large for the
	 * note drops out rather than failing the exec.
	 */
	if (mk_dt_generate_instance_dtb(mk_self, &pool_tree, &pool_tree_len))
		pool_tree = NULL;

	ret = mk_note_build(note, MK_NOTE_MAX, image, pool_tree,
			    pool_tree_len);
	if (ret == -FDT_ERR_NOSPACE && pool_tree) {
		pr_warn("Pool tree (%zu bytes) too large for the takeover note, omitted\n",
			pool_tree_len);
		ret = mk_note_build(note, MK_NOTE_MAX, image, NULL, 0);
	}
	if (!ret)
		ret = fdt_property(fdt, "multikernel,host-tree", note,
				   fdt_totalsize(note));

	kfree(pool_tree);
	kfree(note);
	return ret;
}

struct mk_manifest_ctx {
	struct kimage *image;
	struct mk_instance *instance;
};

static int mk_manifest_chosen(void *fdt, void *data)
{
	struct mk_manifest_ctx *ctx = data;
	struct kimage *image = ctx->image;
	int ret;

	ret = mk_manifest_add_pool_cpus(fdt, ctx->instance);
	if (ret)
		return ret;

	ret = mk_manifest_add_note(fdt, image);
	if (ret)
		return ret;

	if (mk_self->ipi_data) {
		ret = fdt_property_u64(fdt, "multikernel,host-ipi-buffer",
				       mk_self->ipi_phys);
		if (!ret)
			ret = fdt_property_u32(fdt, "multikernel,host-ipi-pages",
					       mk_self->ipi_pages);
		if (ret)
			return ret;
	}

	if (image->mk_ipi) {
		u32 pages = PAGE_ALIGN(sizeof(struct mk_shared_data)) >> PAGE_SHIFT;

		ret = fdt_property_u64(fdt, "multikernel,ipi-buffer",
				       (u64)image->mk_ipi);
		if (!ret)
			ret = fdt_property_u32(fdt, "multikernel,ipi-pages", pages);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * mk_manifest_finalize - Write the boot tree for a spawn
 * @image: The multikernel kimage being executed
 *
 * Generates the instance's device tree into the manifest page allocated
 * at load time, with /chosen carrying the boot handoff.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_manifest_finalize(struct kimage *image)
{
	struct mk_manifest_ctx ctx = { .image = image };
	struct mk_instance *instance;
	void *fdt;
	int ret;

	if (image->mk_id <= 0) {
		pr_warn("%s: called without valid multikernel target\n", __func__);
		return -EINVAL;
	}

	if (!image->mk_manifest) {
		pr_err("No manifest page allocated for multikernel kimage\n");
		return -EINVAL;
	}

	instance = mk_instance_find(image->mk_id);
	if (!instance) {
		pr_err("Target multikernel instance %d not found\n", image->mk_id);
		return -ENOENT;
	}

	ctx.instance = instance;
	fdt = phys_to_virt(image->mk_manifest);
	ret = mk_dt_emit_boot_tree(instance, fdt, MK_MANIFEST_SIZE, mk_manifest_chosen,
				   &ctx);
	if (ret) {
		pr_err("Failed to write the boot tree for instance %d: %d\n",
		       image->mk_id, ret);
		mk_instance_put(instance);
		return ret == -FDT_ERR_NOSPACE ? -ENOSPC : ret;
	}

	pr_info("multikernel: boot tree for instance %d written (%u bytes)\n",
		image->mk_id, fdt_totalsize(fdt));
	mk_instance_put(instance);
	return 0;
}
