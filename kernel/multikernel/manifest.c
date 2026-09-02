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
 * The host tree a spawn boots with: the multikernel,host-tree node of
 * its /chosen. User space hands it over at instance-create (the
 * machine's CPUs, RAM and PCI devices as the loader sees them); a spawn
 * created without one gets a node this kernel makes, naming only the
 * CPUs the spawn might receive through hotplug later: the unassigned
 * pool plus every other kernel's CPUs, minus the spawn's own. The spawn
 * enumerates its possible CPUs from the node's cpus property, since it
 * can only online a CPU whose physical ID it registered at boot.
 */
static int mk_phys_cpu_cmp(const void *a, const void *b)
{
	const mk_phys_cpu_t *x = a, *y = b;

	return *x < *y ? -1 : *x > *y;
}

static int mk_manifest_collect_cpus(struct mk_instance *target,
				    struct mk_cpu_set *pool)
{
	struct mk_instance *other;
	mk_phys_cpu_t id;
	unsigned int i;
	int ret = 0;

	mutex_lock(&mk_instance_mutex);
	list_for_each_entry(other, &mk_instance_list, list) {
		if (other == target)
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

	/*
	 * The spawn assigns logical CPU ids in this list's order, and the
	 * pool set's insertion order churns with every instance create,
	 * delete and pool resize. Sort so a spawn's numbering does not
	 * depend on the host's operation history.
	 */
	if (!ret)
		sort(pool->ids, mk_cpu_set_count(pool), sizeof(*pool->ids),
		     mk_phys_cpu_cmp, NULL);
	return ret;
}

static int mk_manifest_add_host_tree(void *fdt, struct mk_instance *target)
{
	struct mk_cpu_set *pool;
	fdt64_t *cells;
	mk_phys_cpu_t id;
	unsigned int i, count;
	int ret;

	if (target->host_tree)
		return mk_dt_emit_host_tree(fdt, target);

	pool = mk_cpu_set_alloc();
	if (!pool)
		return -ENOMEM;
	ret = mk_manifest_collect_cpus(target, pool);
	if (ret)
		goto out;
	count = mk_cpu_set_count(pool);
	cells = kmalloc_array(count + 1, sizeof(*cells), GFP_KERNEL);
	if (!cells) {
		ret = -ENOMEM;
		goto out;
	}
	mk_cpu_set_for_each(i, id, pool)
		cells[i] = cpu_to_fdt64(id);

	ret = fdt_begin_node(fdt, "multikernel,host-tree");
	if (!ret && count)
		ret = fdt_property(fdt, "cpus", cells, count * sizeof(*cells));
	if (!ret)
		ret = fdt_end_node(fdt);
	kfree(cells);
out:
	mk_cpu_set_free(pool);
	return ret;
}

/*
 * The memory the takeover machinery itself lives in, which a backup
 * must never treat as free after fencing the host: both ends' message
 * rings, each image's boot tree page, and the pool park set. Fenced
 * CPUs execute the park page and spin watching the slot on the pool
 * page table, and mk_has_pending_shutdown() reads the IPI area for as
 * long as the backup runs. Published as (base, size) pairs.
 */
#define MK_RESERVED_PAIRS 80

struct mk_reserved_ranges {
	u64 *pair;
	int n;
};

static int mk_reserved_add(struct mk_reserved_ranges *r, u64 base, u64 size)
{
	if (r->n == MK_RESERVED_PAIRS)
		return -E2BIG;
	r->pair[2 * r->n] = base;
	r->pair[2 * r->n + 1] = size;
	r->n++;
	return 0;
}

static int mk_manifest_add_reserved(void *fdt, struct kimage *image)
{
	struct mk_reserved_ranges r;
	struct mk_instance *other;
	fdt64_t *cells;
	int ret = 0, i;

	r.pair = kmalloc_array(2 * MK_RESERVED_PAIRS, sizeof(*r.pair),
			       GFP_KERNEL);
	if (!r.pair)
		return -ENOMEM;
	r.n = 0;

	if (mk_self->ipi_data)
		ret = mk_reserved_add(&r, mk_self->ipi_phys,
				      (u64)mk_self->ipi_pages << PAGE_SHIFT);
	/*
	 * This image's ring and boot tree; the instance record points
	 * at them only after finalization, so take them from the image.
	 */
	if (!ret && image->mk_ipi)
		ret = mk_reserved_add(&r, image->mk_ipi,
				      PAGE_ALIGN(sizeof(struct mk_shared_data)));
	if (!ret && image->mk_manifest)
		ret = mk_reserved_add(&r, image->mk_manifest, MK_MANIFEST_SIZE);

	mutex_lock(&mk_instance_mutex);
	list_for_each_entry(other, &mk_instance_list, list) {
		if (ret)
			break;
		if (other == mk_self || !other->ipi_data)
			continue;
		ret = mk_reserved_add(&r, other->ipi_phys,
				      (u64)other->ipi_pages << PAGE_SHIFT);
		if (!ret && other->kimage && other->kimage->mk_manifest)
			ret = mk_reserved_add(&r, other->kimage->mk_manifest,
					      MK_MANIFEST_SIZE);
	}
	mutex_unlock(&mk_instance_mutex);
	if (!ret) {
		int pairs = mk_pool_park_regions(r.pair + 2 * r.n,
						 MK_RESERVED_PAIRS - r.n);

		if (pairs < 0)
			ret = pairs;
		else
			r.n += pairs;
	}
	if (ret)
		goto out;

	cells = (fdt64_t *)r.pair;
	for (i = 0; i < 2 * r.n; i++)
		cells[i] = cpu_to_fdt64(r.pair[i]);
	ret = fdt_property(fdt, "multikernel,reserved-memory", cells,
			   2 * r.n * sizeof(*cells));
out:
	kfree(r.pair);
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

	ret = mk_manifest_add_reserved(fdt, image);
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

	/*
	 * Where this host's pool CPUs park. A backup adopts this as its
	 * own pool slot after fencing, to wake the fenced CPUs from it.
	 */
	if (mk_pool && mk_pool->arch.slot_phys) {
		ret = fdt_property_u64(fdt, "multikernel,pool-slot",
				       mk_pool->arch.slot_phys);
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

	/* A node's properties precede its subnodes: the host tree closes /chosen */
	return mk_manifest_add_host_tree(fdt, ctx->instance);
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
