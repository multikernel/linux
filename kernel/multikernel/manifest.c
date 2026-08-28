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
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/smp.h>

#include "internal.h"

/* Physical address of the manifest this kernel booted with, 0 if none */
static phys_addr_t mk_manifest_fdt_phys;
static phys_addr_t mk_manifest_entry_stub;
static bool mk_spawn_kernel;

phys_addr_t mk_manifest_phys(void)
{
	return mk_manifest_fdt_phys;
}

bool mk_is_spawn_kernel(void)
{
	return READ_ONCE(mk_spawn_kernel);
}

phys_addr_t mk_manifest_entry_stub_phys(void)
{
	return mk_manifest_entry_stub;
}

int mk_manifest_set_entry_stub(struct kimage *image, phys_addr_t entry)
{
	void *fdt;
	int ret;

	if (!image || !image->mk_manifest || !entry)
		return -EINVAL;

	fdt = phys_to_virt(image->mk_manifest);
	ret = fdt_open_into(fdt, fdt, PAGE_SIZE);
	if (!ret)
		ret = fdt_setprop_u64(fdt, 0, MK_FDT_ENTRY_STUB, entry);
	if (!ret)
		ret = fdt_pack(fdt);
	if (!ret)
		return 0;

	pr_err("multikernel: failed to publish entry stub: %s\n",
	       fdt_strerror(ret));
	return ret == -FDT_ERR_NOSPACE ? -E2BIG : -EINVAL;
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
	const fdt64_t *entry_stub;
	void *fdt = NULL;
	int len;
	int err = 0;

	/* A malformed spawn handoff must still never gain host-wide reset. */
	WRITE_ONCE(mk_spawn_kernel, true);

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

	entry_stub = fdt_getprop(fdt, 0, MK_FDT_ENTRY_STUB, &len);
	if (entry_stub) {
		if (len != sizeof(*entry_stub)) {
			err = -EINVAL;
			pr_warn("multikernel: manifest has invalid entry stub\n");
			goto out;
		}
		mk_manifest_entry_stub = fdt64_to_cpu(*entry_stub);
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
		 * Skip the root instance: its set is the CPUs the host
		 * itself runs on, and enumerating a big host's full CPU set
		 * in every spawn bloats the spawn's possible map and percpu
		 * allocations.
		 */
		if (other == target || other == root_instance)
			continue;
		mk_cpu_set_for_each(i, id, other->cpus) {
			ret = mk_cpu_set_add(pool, id);
			if (ret)
				break;
		}
		if (ret)
			break;
	}
	if (!ret) {
		mk_cpu_set_for_each(i, id, mk_cpu_pool) {
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

	mk_cpu_set_for_each(i, id, pool)
		cells[i] = cpu_to_fdt64(id);

	ret = fdt_property(fdt, "multikernel,pool-cpus", cells, count * sizeof(*cells));
	kfree(cells);
out:
	mk_cpu_set_free(pool);
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

	if (root_instance->ipi_data) {
		mk_phys_cpu_t doorbell_cpu;

		doorbell_cpu = arch_cpu_physical_id(get_boot_cpu_id());
		ret = fdt_property_u64(fdt, "multikernel,host-ipi-buffer",
				       root_instance->ipi_phys);
		if (!ret)
			ret = fdt_property_u32(fdt, "multikernel,host-ipi-pages",
					       root_instance->ipi_pages);
		if (!ret)
			ret = fdt_property_u64(fdt, "multikernel,host-ipi-cpu",
					       doorbell_cpu);
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
	ret = mk_dt_emit_boot_tree(instance, fdt, PAGE_SIZE, mk_manifest_chosen,
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
