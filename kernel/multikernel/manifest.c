// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * The multikernel manifest: an FDT the host hands to a spawn kernel,
 * carrying the instance's identity and resources (the instance DTB),
 * the pool CPUs it may receive later, and the message ring addresses.
 *
 * The manifest travels on multikernel's own boot channel (a dedicated
 * setup_data type on x86, the linux,multikernel-fdt /chosen property on
 * device tree architectures), separate from KHO: a spawn kernel may use
 * the real KHO channel for its own live update within its partition.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>

#include "internal.h"

/* Physical address of the manifest this kernel booted with, 0 if none */
static phys_addr_t mk_manifest_fdt_phys;
static bool mk_manifest_fdt_rejected;

phys_addr_t mk_manifest_phys(void)
{
	return mk_manifest_fdt_phys;
}

bool mk_manifest_rejected(void)
{
	return READ_ONCE(mk_manifest_fdt_rejected);
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
		err = -ENOMEM;
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
	mk_manifest_fdt_rejected = false;

	pr_info("multikernel: manifest accepted\n");

out:
	if (fdt)
		early_memunmap(fdt, fdt_len);
	if (err) {
		mk_manifest_fdt_rejected = true;
		pr_warn("multikernel: supplied manifest rejected: %d\n", err);
	}
}

/**
 * mk_manifest_finalize - Build the manifest for a spawn
 * @image: The multikernel kimage being executed
 *
 * Creates the manifest FDT in the page allocated at load time: the
 * instance DTB, the pool CPUs the instance may receive later, and the
 * message ring addresses for both directions.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_manifest_finalize(struct kimage *image)
{
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

	/* Use the pre-allocated manifest page */
	fdt = phys_to_virt(image->mk_manifest);

	ret = fdt_create(fdt, PAGE_SIZE);
	ret |= fdt_finish_reservemap(fdt);
	ret |= fdt_begin_node(fdt, "");
	ret |= fdt_property_string(fdt, "compatible", MK_FDT_COMPATIBLE);
	if (ret) {
		pr_err("Failed to create manifest FDT structure: %d\n", ret);
		return ret;
	}

	ret = mk_manifest_add_instance_dtb(image, fdt, image->mk_id);
	if (ret) {
		pr_err("Failed to preserve multikernel DTB: %d\n", ret);
		fdt_end_node(fdt);
		fdt_finish(fdt);
		return ret;
	}

	ret = mk_manifest_add_host_ipi(image, fdt);
	if (ret) {
		pr_err("Failed to preserve host IPI buffer: %d\n", ret);
		fdt_end_node(fdt);
		fdt_finish(fdt);
		return ret;
	}

	/* Add IPI buffer information if allocated */
	if (image->mk_ipi) {
		u64 ipi_phys = (u64)image->mk_ipi;
		size_t ipi_buffer_size = sizeof(struct mk_shared_data);
		u32 ipi_pages = (u32)(PAGE_ALIGN(ipi_buffer_size) >> PAGE_SHIFT);

		ret = fdt_begin_node(fdt, "ipi-buffer");
		ret |= fdt_property_u64(fdt, "phys-addr", ipi_phys);
		ret |= fdt_property_u32(fdt, "pages", ipi_pages);
		ret |= fdt_end_node(fdt);

		if (ret) {
			pr_err("Failed to add IPI buffer to manifest: %d\n", ret);
			fdt_end_node(fdt);
			fdt_finish(fdt);
			return ret;
		}

		pr_info("multikernel: added IPI buffer to manifest: phys=0x%llx, pages=%u (%zu bytes)\n",
			ipi_phys, ipi_pages, ipi_buffer_size);
	}

	ret = fdt_end_node(fdt);
	ret |= fdt_finish(fdt);
	if (ret) {
		pr_err("Failed to finalize manifest FDT: %d\n", ret);
		return ret;
	}

	if (fdt_totalsize(fdt) > PAGE_SIZE) {
		pr_err("Manifest FDT size (%d bytes) exceeds allocated page size (%lu bytes)\n",
		       fdt_totalsize(fdt), PAGE_SIZE);
		return -ENOSPC;
	}

	pr_info("multikernel: finalized manifest for instance %d (size: %d bytes)\n",
		image->mk_id, fdt_totalsize(fdt));
	return 0;
}
