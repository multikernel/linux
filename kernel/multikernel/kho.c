// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * Multikernel KHO (Kexec HandOver)
 *
 * Provides KHO support for preserving and restoring multikernel instance
 * device trees across kexec boundaries using shared memory.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/multikernel.h>
#include <linux/io.h>
#ifdef CONFIG_KEXEC_HANDOVER
#include <linux/kexec_handover.h>
#include <linux/libfdt.h>
#include <linux/sizes.h>
#include <asm/apic.h>
#include "internal.h"

#define PROP_SUB_FDT "fdt"
#endif

#ifdef CONFIG_KEXEC_HANDOVER

/*
 * Global root instance representing the current kernel.
 *
 * Initialization (in mk_kho_restore_dtbs at early_initcall):
 *   - For host kernels (no KHO): Created with id=0, name="/"
 *   - For spawn kernels (KHO present): Restored from KHO DTB
 *
 * The root instance is used by overlay operations to specify the host/current
 * kernel as a source or target for resource transfers (e.g., mk,instance="/").
 */
struct mk_instance *root_instance = NULL;

/**
 * mk_kho_preserve_dtb() - Preserve multikernel DTB for kexec
 * @image: Target kimage
 * @fdt: FDT being built for KHO
 * @mk_id: Multikernel instance ID
 *
 * Called by mk_kexec_finalize() to preserve the multikernel DTB
 * in the KHO FDT for the target kernel.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_kho_preserve_dtb(struct kimage *image, void *fdt, int mk_id)
{
	struct mk_instance *instance;
	int ret = 0;

	pr_info("Preserving multikernel DTB for instance %d\n", mk_id);

	/* Find the target multikernel instance */
	instance = mk_instance_find(mk_id);
	if (!instance) {
		pr_err("Target multikernel instance %d not found\n", mk_id);
		return -ENOENT;
	}

	if (!instance->dtb_data || instance->dtb_size == 0) {
		pr_err("Target multikernel instance %d has no DTB data - did you write to device_tree file?\n", mk_id);
		mk_instance_put(instance);
		return -EINVAL;
	}

	ret |= fdt_begin_node(fdt, "multikernel");
	ret |= fdt_property(fdt, "dtb-data", instance->dtb_data, instance->dtb_size);
	ret |= fdt_end_node(fdt);

	if (ret) {
		pr_err("Failed to add DTB for instance %d to FDT: %d\n", mk_id, ret);
		mk_instance_put(instance);
		return ret;
	}

	pr_info("Preserved DTB for instance %d (%zu bytes)\n", mk_id, instance->dtb_size);
	mk_instance_put(instance);
	return 0;
}

/**
 * mk_kho_preserve_host_ipi() - Preserve host's IPI buffer address in KHO
 * @image: Target kimage
 * @fdt: FDT being built for KHO
 *
 * Called during kexec preparation to pass the host's IPI receive buffer
 * address to the spawn kernel so it can send messages back to the host.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_kho_preserve_host_ipi(struct kimage *image, void *fdt)
{
	int ret = 0;

	if (!root_instance->ipi_data) {
		pr_debug("No host IPI buffer to preserve\n");
		return 0;
	}

	pr_info("Preserving host IPI buffer: phys=0x%llx, pages=%u\n",
		(unsigned long long)root_instance->ipi_phys, root_instance->ipi_pages);

	ret |= fdt_begin_node(fdt, "host-ipi-buffer");
	ret |= fdt_property_u64(fdt, "phys-addr", root_instance->ipi_phys);
	ret |= fdt_property_u32(fdt, "pages", root_instance->ipi_pages);
	ret |= fdt_end_node(fdt);

	if (ret) {
		pr_err("Failed to add host IPI buffer to KHO FDT: %d\n", ret);
		return ret;
	}

	pr_info("Preserved host IPI buffer in KHO\n");
	return 0;
}

/**
 * mk_dt_extract_instance_info() - Extract instance ID and name from DTB
 * @dtb_data: Device tree blob data
 * @dtb_size: Size of DTB data
 * @instance_id: Output parameter for instance ID
 * @instance_name: Output parameter for instance name (caller must free)
 *
 * Parses the DTB in the new flat format where the root node IS the instance:
 * /<instance-name> { compatible = "multikernel-v1"; id = <N>; resources {...}; }
 *
 * Returns: 0 on success, negative error code on failure
 */
static int mk_dt_extract_instance_info(const void *dtb_data, size_t dtb_size,
				       int *instance_id, const char **instance_name)
{
	const void *fdt = dtb_data;
	int root_node;
	const fdt32_t *id_prop;
	const char *name;

	if (!dtb_data || !instance_id || !instance_name) {
		return -EINVAL;
	}

	root_node = fdt_path_offset(fdt, "/");
	if (root_node < 0) {
		pr_err("Failed to get root node from DTB\n");
		return -EINVAL;
	}

	name = fdt_get_name(fdt, root_node, NULL);
	if (!name) {
		pr_err("Failed to get instance name from root DTB node\n");
		return -EINVAL;
	}

	id_prop = fdt_getprop(fdt, root_node, "id", NULL);
	if (!id_prop) {
		pr_err("No 'id' property found in instance '%s'\n", name);
		return -ENOENT;
	}

	*instance_id = fdt32_to_cpu(*id_prop);
	*instance_name = name;

	return 0;
}

static int __init mk_kho_restore_cpus(struct mk_dt_config *config)
{
	int phys_cpu_id;
	cpumask_var_t new_possible;

	if (!config->cpus || bitmap_empty(config->cpus, NR_CPUS)) {
		pr_debug("No CPU configuration in DTB\n");
		return 0;
	}

	pr_info("Before restriction: cpu_possible=%*pbl, cpu_present=%*pbl\n",
		cpumask_pr_args(cpu_possible_mask),
		cpumask_pr_args(cpu_present_mask));

	if (!alloc_cpumask_var(&new_possible, GFP_KERNEL)) {
		pr_err("Failed to allocate CPU mask\n");
		return -ENOMEM;
	}

	cpumask_clear(new_possible);
	for_each_set_bit(phys_cpu_id, config->cpus, NR_CPUS) {
		int logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);

		if (logical_cpu < 0) {
			topology_register_apic(phys_cpu_id, CPU_ACPIID_INVALID, false);
			logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);
		}

		if (logical_cpu >= 0) {
			cpumask_set_cpu(logical_cpu, new_possible);
			pr_debug("Static CPU: physical %d -> logical %d\n",
				 phys_cpu_id, logical_cpu);
		} else {
			pr_warn("Failed to register physical CPU %d\n", phys_cpu_id);
		}
	}

	/* cpu_possible_mask stays large to allow per-CPU data allocation
	 * Devices will only be registered for present CPUs, but we'll register
	 * them on-demand during hotplug
	 */
	cpumask_and(&__cpu_present_mask, &__cpu_present_mask, new_possible);
	free_cpumask_var(new_possible);

	pr_info("After restriction: cpu_possible=%*pbl, cpu_present=%*pbl\n",
		cpumask_pr_args(cpu_possible_mask),
		cpumask_pr_args(cpu_present_mask));

	return 0;
}

static struct mk_instance * __init alloc_mk_instance(int instance_id, const char *name,
						     bool alloc_ipi)
{
	struct mk_instance *instance;
	int ret;

	instance = kzalloc(sizeof(*instance), GFP_KERNEL);
	if (!instance)
		return NULL;

	instance->id = instance_id;
	instance->name = kstrdup(name, GFP_KERNEL);
	if (!instance->name)
		goto err_free_instance;

	if (alloc_ipi) {
		instance->ipi_data = (struct mk_shared_data *)__get_free_pages(
			GFP_KERNEL | __GFP_ZERO, get_order(sizeof(struct mk_shared_data)));
		if (!instance->ipi_data) {
			pr_err("Failed to allocate IPI buffer for instance %d\n", instance_id);
			goto err_free_name;
		}
		instance->ipi_phys = virt_to_phys(instance->ipi_data);
		instance->ipi_pages = (sizeof(struct mk_shared_data) + PAGE_SIZE - 1) / PAGE_SIZE;

		pr_info("Allocated IPI buffer for instance %d: phys=0x%llx, virt=%px, pages=%u\n",
			instance_id, (unsigned long long)instance->ipi_phys,
			instance->ipi_data, instance->ipi_pages);
	}

	instance->cpus = kzalloc(BITS_TO_LONGS(NR_CPUS) * sizeof(unsigned long),
				 GFP_KERNEL);
	if (!instance->cpus)
		goto err_free_ipi;

	instance->state = MK_STATE_READY;
	INIT_LIST_HEAD(&instance->memory_regions);
	INIT_LIST_HEAD(&instance->list);
	kref_init(&instance->refcount);

	mutex_lock(&mk_instance_mutex);
	ret = idr_alloc(&mk_instance_idr, instance, instance_id, instance_id + 1, GFP_KERNEL);
	if (ret < 0) {
		mutex_unlock(&mk_instance_mutex);
		goto err_free_cpus;
	}
	list_add(&instance->list, &mk_instance_list);
	mutex_unlock(&mk_instance_mutex);

	mk_instance_set_state(instance, MK_STATE_READY);
	return instance;

err_free_cpus:
	kfree(instance->cpus);
err_free_ipi:
	if (alloc_ipi)
		free_pages((unsigned long)instance->ipi_data,
			   get_order(sizeof(struct mk_shared_data)));
err_free_name:
	kfree(instance->name);
err_free_instance:
	kfree(instance);
	return NULL;
}

static int __init mk_kho_restore_ipi(const void *kho_fdt, struct mk_instance *instance)
{
	int ipi_node;
	const fdt64_t *phys_prop;
	const fdt32_t *pages_prop;
	int len;
	phys_addr_t ipi_phys = 0;
	u32 ipi_pages = 0;
	size_t ipi_size = 0;

	ipi_node = fdt_subnode_offset(kho_fdt, 0, "ipi-buffer");
	if (ipi_node < 0) {
		instance->ipi_data = NULL;
		pr_debug("No IPI buffer available from KHO\n");
		return 0;
	}

	phys_prop = fdt_getprop(kho_fdt, ipi_node, "phys-addr", &len);
	if (phys_prop && len == sizeof(*phys_prop))
		ipi_phys = (phys_addr_t)fdt64_to_cpu(*phys_prop);

	pages_prop = fdt_getprop(kho_fdt, ipi_node, "pages", &len);
	if (pages_prop && len == sizeof(*pages_prop)) {
		ipi_pages = fdt32_to_cpu(*pages_prop);
		ipi_size = (size_t)ipi_pages << PAGE_SHIFT;
	}

	if (!ipi_phys || !ipi_pages) {
		instance->ipi_data = NULL;
		pr_debug("IPI buffer node exists but incomplete info (phys=0x%llx, pages=%u)\n",
			 (unsigned long long)ipi_phys, ipi_pages);
		return 0;
	}

	instance->ipi_data = memremap(ipi_phys, ipi_size, MEMREMAP_WB);
	if (!instance->ipi_data) {
		pr_err("Failed to map IPI buffer at 0x%llx (pages: %u, size: %zu)\n",
		       (unsigned long long)ipi_phys, ipi_pages, ipi_size);
		return -ENOMEM;
	}

	instance->ipi_phys = ipi_phys;
	instance->ipi_pages = ipi_pages;
	pr_info("Restored IPI buffer for root instance: phys=0x%llx, virt=%px, pages=%u, size=%zu\n",
		(unsigned long long)ipi_phys, instance->ipi_data, ipi_pages, ipi_size);

	return 0;
}

static struct mk_instance * __init mk_kho_restore_host_instance(const void *kho_fdt)
{
	struct mk_instance *host_instance;
	int host_ipi_node;
	const fdt64_t *phys_prop;
	const fdt32_t *pages_prop;
	phys_addr_t host_ipi_phys = 0;
	u32 host_ipi_pages = 0;
	size_t host_ipi_size = 0;
	int len;

	host_ipi_node = fdt_subnode_offset(kho_fdt, 0, "host-ipi-buffer");
	if (host_ipi_node < 0) {
		pr_warn("No host-ipi-buffer node in KHO (spawn won't be able to send to host)\n");
		return NULL;
	}

	phys_prop = fdt_getprop(kho_fdt, host_ipi_node, "phys-addr", &len);
	if (phys_prop && len == sizeof(*phys_prop))
		host_ipi_phys = (phys_addr_t)fdt64_to_cpu(*phys_prop);

	pages_prop = fdt_getprop(kho_fdt, host_ipi_node, "pages", &len);
	if (pages_prop && len == sizeof(*pages_prop)) {
		host_ipi_pages = fdt32_to_cpu(*pages_prop);
		host_ipi_size = (size_t)host_ipi_pages << PAGE_SHIFT;
	}

	if (!host_ipi_phys || !host_ipi_pages) {
		pr_warn("Incomplete host IPI buffer info (phys=0x%llx, pages=%u)\n",
			(unsigned long long)host_ipi_phys, host_ipi_pages);
		return NULL;
	}

	host_instance = alloc_mk_instance(0, "/", false);
	if (!host_instance)
		return NULL;

	/* Set CPU 0 as default target for host IPIs (physical ID) */
	set_bit(0, host_instance->cpus);

	host_instance->ipi_data = memremap(host_ipi_phys, host_ipi_size, MEMREMAP_WB);
	if (!host_instance->ipi_data) {
		pr_err("Failed to map host IPI buffer at 0x%llx\n",
		       (unsigned long long)host_ipi_phys);
		kfree(host_instance->name);
		kfree(host_instance);
		return NULL;
	}
	host_instance->ipi_phys = host_ipi_phys;
	host_instance->ipi_pages = host_ipi_pages;
	pr_info("Restored host IPI buffer: phys=0x%llx, virt=%px, pages=%u\n",
		(unsigned long long)host_ipi_phys, host_instance->ipi_data,
		host_ipi_pages);
	pr_info("Registered host instance (ID 0) for spawn→host communication\n");

	return host_instance;
}

/**
 * mk_kho_restore_dtbs() - Restore DTB from KHO shared memory
 *
 * Called during multikernel initialization in the spawned kernel to restore
 * the single DTB that was preserved by the host kernel via KHO. The spawned
 * kernel receives exactly one DTB and parses the instance ID from it.
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init mk_kho_restore_dtbs(void)
{
	void *dtb_virt;
	int dtb_len;
	int ret, cpu;
	struct mk_instance *instance, *host_instance;
	struct mk_dt_config config;
	int instance_id;
	const char *instance_name;
	const void *kho_fdt = NULL;
	phys_addr_t fdt_phys;

	fdt_phys = kho_get_fdt_phys();
	if (!fdt_phys) {
		pr_info("No KHO FDT available for multikernel DTB restoration\n");

		instance = alloc_mk_instance(0, "/", true);
		if (!instance) {
			pr_err("Failed to allocate root instance\n");
			return -ENOMEM;
		}
		/* Initially, root has all online CPUs (physical IDs) */
		for_each_online_cpu(cpu) {
			u32 phys_cpu_id = arch_cpu_physical_id(cpu);
			set_bit(phys_cpu_id, instance->cpus);
		}
		pr_info("Root instance initialized with CPUs (physical): %*pbl\n",
			NR_CPUS, instance->cpus);

		root_instance = instance;

		pr_info("Initialized root instance (id=0, name='/')\n");
		return 0;
	}

	pr_info("Restoring multikernel DTB from KHO (phys: 0x%llx)\n", fdt_phys);

	/* Map the FDT for early boot access */
	kho_fdt = early_memremap(fdt_phys, PAGE_SIZE);
	if (!kho_fdt) {
		pr_err("Failed to map KHO FDT at 0x%llx\n", fdt_phys);
		return -EFAULT;
	}

	int mk_node = fdt_subnode_offset(kho_fdt, 0, "multikernel");
	if (mk_node < 0) {
		pr_info("No multikernel node found in KHO FDT\n");
		ret = 0;
		goto cleanup_fdt;
	}

	const void *dtb_data = fdt_getprop(kho_fdt, mk_node, "dtb-data", &dtb_len);
	if (!dtb_data || dtb_len <= 0) {
		pr_info("No dtb-data property found in multikernel node\n");
		ret = 0;
		goto cleanup_fdt;
	}

	pr_info("Found preserved multikernel DTB (%d bytes)\n", dtb_len);

	/* Validate DTB header */
	ret = fdt_check_header(dtb_data);
	if (ret) {
		pr_err("Invalid DTB header from KHO: %d\n", ret);
		ret = -EINVAL;
		goto cleanup_fdt;
	}

	if (dtb_len > SZ_1M) {
		pr_err("DTB size too large: %d bytes\n", dtb_len);
		ret = -EINVAL;
		goto cleanup_fdt;
	}

	dtb_virt = kmalloc(dtb_len, GFP_KERNEL);
	if (!dtb_virt) {
		pr_err("Failed to allocate memory for DTB (%d bytes)\n", dtb_len);
		ret = -ENOMEM;
		goto cleanup_fdt;
	}
	memcpy(dtb_virt, dtb_data, dtb_len);

	/* Parse DTB to get the actual instance ID and name */
	ret = mk_dt_extract_instance_info(dtb_virt, dtb_len, &instance_id, &instance_name);
	if (ret) {
		pr_err("Failed to extract instance info from DTB: %d\n", ret);
		goto cleanup_dtb;
	}

	pr_info("DTB contains instance ID %d, name '%s'\n", instance_id, instance_name);

	mk_dt_config_init(&config);

	/* In the new flat format, the root node IS the instance node */
	ret = mk_dt_parse(dtb_virt, dtb_len, &config);
	if (ret) {
		pr_err("Failed to parse DTB from KHO: %d\n", ret);
		goto config_free;
	}

	ret = mk_kho_restore_cpus(&config);
	if (ret) {
		pr_err("Failed to restore CPU restrictions: %d\n", ret);
		goto config_free;
	}

	/* Create a new instance for this DTB */
	instance = alloc_mk_instance(instance_id, instance_name, false);
	if (!instance) {
		ret = -ENOMEM;
		goto config_free;
	}

	if (config.cpus)
		bitmap_copy(instance->cpus, config.cpus, NR_CPUS);

	instance->dtb_data = kmalloc(dtb_len, GFP_KERNEL);
	if (!instance->dtb_data) {
		pr_err("Failed to allocate memory for DTB restoration\n");
		ret = -ENOMEM;
		goto cleanup_instance_name;
	}

	memcpy(instance->dtb_data, dtb_virt, dtb_len);
	instance->dtb_size = dtb_len;

	ret = mk_kho_restore_ipi(kho_fdt, instance);
	if (ret) {
		pr_err("Failed to restore IPI buffer: %d\n", ret);
		goto cleanup_dtb_data;
	}

	root_instance = instance;

	host_instance = mk_kho_restore_host_instance(kho_fdt);
	if (!host_instance)
		pr_warn("Failed to restore host instance (spawn→host communication unavailable)\n");

	pr_info("Successfully restored multikernel root instance %d ('%s') from KHO (%d bytes)\n",
		instance_id, instance_name, dtb_len);
	mk_dt_config_free(&config);
	kfree(dtb_virt);
	early_memunmap((void *)kho_fdt, PAGE_SIZE);
	return 0;

cleanup_dtb_data:
	kfree(instance->dtb_data);
cleanup_instance_name:
	kfree(instance->name);
	kfree(instance->dtb_data);
	kfree(instance);
config_free:
	mk_dt_config_free(&config);
cleanup_dtb:
	kfree(dtb_virt);
cleanup_fdt:
	early_memunmap((void *)kho_fdt, PAGE_SIZE);
	return ret;
}

/* Run at early_initcall to enforce CPU restrictions before per-CPU allocations */
early_initcall(mk_kho_restore_dtbs);

#else /* !CONFIG_KEXEC_HANDOVER */

/* No root instance when KHO is not enabled */
struct mk_instance *root_instance = NULL;

/* Stub functions when KHO is not enabled */
int __init mk_kho_restore_dtbs(void)
{
	return 0;
}

#endif /* CONFIG_KEXEC_HANDOVER */
