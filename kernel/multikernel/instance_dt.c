// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * Multikernel instance device trees
 *
 * Builds the instance device tree the host hands to a spawn kernel in the
 * manifest, and restores an instance from the manifest on the spawn side.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/multikernel.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/libfdt.h>
#include <linux/sizes.h>
#include <linux/smp.h>
#include "internal.h"

#define PROP_SUB_FDT "fdt"

/*
 * Global root instance representing the current kernel.
 *
 * Initialization (in mk_instance_restore_from_manifest at early_initcall):
 *   - For host kernels (no manifest): Created with id=0, name="/"
 *   - For spawn kernels: Restored from the manifest's instance DTB
 *
 * Overlay operations reach this kernel through an /instances/<name> fragment
 * naming it, or through an /resources fragment when it manages a pool.
 */
struct mk_instance *root_instance = NULL;
EXPORT_SYMBOL_GPL(root_instance);

static void __init __noreturn mk_manifest_reject_and_park(int error)
{
	int ret;

	ret = mk_arch_prepare_park();
	if (ret || !mk_arch_park_ready())
		panic("multikernel: rejected manifest before park path became ready");
	ret = mk_register_stop_nmi_handler();
	if (ret)
		pr_emerg("multikernel: stop-NMI registration failed while rejecting manifest: %d\n",
			 ret);
	pr_emerg("multikernel: parking CPUs after rejecting supplied manifest: %d\n",
		 error);
	smp_call_function(mk_enter_pool_state, NULL, 0);
	mk_enter_pool_state(NULL);
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

	ret = fdt_property(fdt, "pool-cpus", cells, count * sizeof(*cells));
	kfree(cells);
out:
	mk_cpu_set_free(pool);
	return ret;
}

/**
 * mk_manifest_add_instance_dtb() - Preserve multikernel DTB for kexec
 * @image: Target kimage
 * @fdt: The manifest FDT being built
 * @mk_id: Multikernel instance ID
 *
 * Called by mk_manifest_finalize() to preserve the multikernel DTB
 * in the manifest for the target kernel.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_manifest_add_instance_dtb(struct kimage *image, void *fdt, int mk_id)
{
	struct mk_instance *instance;
	void *fresh_dtb = NULL;
	size_t fresh_dtb_size = 0;
	int ret = 0;

	pr_info("Preserving multikernel DTB for instance %d\n", mk_id);

	/* Find the target multikernel instance */
	instance = mk_instance_find(mk_id);
	if (!instance) {
		pr_err("Target multikernel instance %d not found\n", mk_id);
		return -ENOENT;
	}

	ret = mk_dt_generate_instance_dtb(instance, &fresh_dtb, &fresh_dtb_size);
	if (ret) {
		pr_err("Failed to generate fresh DTB for instance %d: %d\n", mk_id, ret);
		mk_instance_put(instance);
		return ret;
	}

	kfree(instance->dtb_data);
	instance->dtb_data = fresh_dtb;
	instance->dtb_size = fresh_dtb_size;

	ret |= fdt_begin_node(fdt, "multikernel");
	ret |= fdt_property(fdt, "dtb-data", instance->dtb_data, instance->dtb_size);
	ret |= mk_manifest_add_pool_cpus(fdt, instance);
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
 * mk_manifest_add_host_ipi() - Add the host's IPI buffer address to the manifest
 * @image: Target kimage
 * @fdt: The manifest FDT being built
 *
 * Called during kexec preparation to pass the host's IPI receive buffer
 * address to the spawn kernel so it can send messages back to the host.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_manifest_add_host_ipi(struct kimage *image, void *fdt)
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
		pr_err("Failed to add host IPI buffer to manifest: %d\n", ret);
		return ret;
	}

	pr_info("Added host IPI buffer to manifest\n");
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

/*
 * Register CPUs from the manifest during SMP config phase.
 * Called from multikernel_parse_smp_config() before topology is finalized.
 */
void __init mk_register_cpus_from_manifest(void)
{
	phys_addr_t fdt_phys;
	const void *manifest;
	int mk_node, resources_node;
	const fdt64_t *cpus_prop;
	int cpus_len, i;
	const void *dtb_data;
	int dtb_len;

	fdt_phys = mk_manifest_phys();
	if (!fdt_phys)
		return;

	manifest = early_memremap(fdt_phys, PAGE_SIZE);
	if (!manifest)
		return;

	mk_node = fdt_subnode_offset(manifest, 0, "multikernel");
	if (mk_node < 0)
		goto out;

	/* Get the embedded DTB */
	dtb_data = fdt_getprop(manifest, mk_node, "dtb-data", &dtb_len);
	if (!dtb_data || dtb_len <= 0)
		goto out;

	/* Find /resources node in the embedded DTB */
	resources_node = fdt_subnode_offset(dtb_data, 0, "resources");
	if (resources_node < 0)
		goto out;

	/* Get the cpus property (64-bit physical IDs) from resources node */
	cpus_prop = fdt_getprop(dtb_data, resources_node, "cpus", &cpus_len);
	if (!cpus_prop || cpus_len < sizeof(fdt64_t) ||
	    cpus_len % sizeof(fdt64_t))
		goto out;

	/* Register each CPU from the DTB */
	for (i = 0; i < cpus_len / sizeof(fdt64_t); i++) {
		mk_phys_cpu_t phys_id = fdt64_to_cpu(cpus_prop[i]);

		mk_arch_register_cpu(phys_id);
		pr_debug("Registered CPU physical ID %llu from manifest\n", phys_id);
	}

	/*
	 * Register the rest of the pool so those CPUs can be hot-added
	 * later: the topology rejects post-boot APIC IDs it did not see
	 * during enumeration. They are registered present and pruned from
	 * the present mask in mk_restore_instance_cpus(), which keeps a logical
	 * CPU assigned to each and avoids the hot-pluggable-APIC checks.
	 */
	cpus_prop = fdt_getprop(manifest, mk_node, "pool-cpus", &cpus_len);
	if (cpus_prop && cpus_len >= sizeof(fdt64_t) &&
	    cpus_len % sizeof(fdt64_t) == 0) {
		for (i = 0; i < cpus_len / sizeof(fdt64_t); i++) {
			mk_phys_cpu_t phys_id = fdt64_to_cpu(cpus_prop[i]);

			mk_arch_register_cpu(phys_id);
			pr_debug("Registered pool CPU physical ID %llu from manifest\n",
				 phys_id);
		}
	}

out:
	early_memunmap((void *)manifest, PAGE_SIZE);
}

/*
 * Restrict CPU masks to only include CPUs assigned to this instance.
 * CPUs are already registered during multikernel_parse_smp_config() via
 * topology_register_apic(), so we just need to restrict the present mask.
 */
static int __init mk_restore_instance_cpus(struct mk_dt_config *config)
{
	mk_phys_cpu_t phys_cpu_id;
	unsigned int i;
	cpumask_var_t new_present;

	if (mk_cpu_set_empty(config->cpus)) {
		pr_debug("No CPU configuration in DTB\n");
		return 0;
	}

	pr_info("Before restriction: cpu_possible=%*pbl, cpu_present=%*pbl\n",
		cpumask_pr_args(cpu_possible_mask),
		cpumask_pr_args(cpu_present_mask));

	if (!alloc_cpumask_var(&new_present, GFP_KERNEL)) {
		pr_err("Failed to allocate CPU mask\n");
		return -ENOMEM;
	}

	cpumask_clear(new_present);
	mk_cpu_set_for_each(i, phys_cpu_id, config->cpus) {
		int logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);

		if (logical_cpu >= 0) {
			cpumask_set_cpu(logical_cpu, new_present);
			pr_debug("Instance CPU: physical %llu -> logical %d\n",
				 phys_cpu_id, logical_cpu);
		} else {
			pr_warn("Physical CPU %llu not found in topology\n",
				phys_cpu_id);
		}
	}

	/* Restrict present mask to only CPUs assigned to this instance */
	cpumask_and(&__cpu_present_mask, &__cpu_present_mask, new_present);
	free_cpumask_var(new_present);

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
		mk_shared_data_reset(instance->ipi_data);
		instance->ipi_phys = virt_to_phys(instance->ipi_data);
		instance->ipi_pages = (sizeof(struct mk_shared_data) + PAGE_SIZE - 1) / PAGE_SIZE;

		pr_info("Allocated IPI buffer for instance %d: phys=0x%llx, virt=%px, pages=%u\n",
			instance_id, (unsigned long long)instance->ipi_phys,
			instance->ipi_data, instance->ipi_pages);
	}

	instance->cpus = mk_cpu_set_alloc();
	if (!instance->cpus)
		goto err_free_ipi;

	instance->state = MK_STATE_READY;
	INIT_LIST_HEAD(&instance->memory_regions);
	INIT_LIST_HEAD(&instance->list);
	kref_init(&instance->refcount);
	INIT_LIST_HEAD(&instance->pci_devices);
	instance->pci_devices_valid = false;
	instance->pci_device_count = 0;
	INIT_LIST_HEAD(&instance->platform_devices);
	instance->platform_devices_valid = false;
	instance->platform_device_count = 0;

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
	mk_cpu_set_free(instance->cpus);
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

static int __init mk_copy_pci_devices(const struct mk_dt_config *config,
					  struct mk_instance *instance)
{
	struct mk_pci_device *src_dev, *dst_dev;

	if (!config->pci_devices_valid || config->pci_device_count == 0) {
		INIT_LIST_HEAD(&instance->pci_devices);
		instance->pci_device_count = 0;
		instance->pci_devices_valid = false;
		pr_debug("No PCI devices in DTB\n");
		return 0;
	}

	INIT_LIST_HEAD(&instance->pci_devices);
	instance->pci_device_count = 0;
	instance->pci_devices_valid = true;

	list_for_each_entry(src_dev, &config->pci_devices, list) {
		dst_dev = kzalloc(sizeof(*dst_dev), GFP_KERNEL);
		if (!dst_dev) {
			pr_err("Failed to allocate PCI device entry\n");
			return -ENOMEM;
		}

		dst_dev->vendor = src_dev->vendor;
		dst_dev->device = src_dev->device;
		dst_dev->domain = src_dev->domain;
		dst_dev->bus = src_dev->bus;
		dst_dev->slot = src_dev->slot;
		dst_dev->func = src_dev->func;

		list_add_tail(&dst_dev->list, &instance->pci_devices);
		instance->pci_device_count++;
	}

	pr_info("Copied %d PCI devices to root instance\n", instance->pci_device_count);
	return 0;
}

static int __init mk_copy_platform_devices(const struct mk_dt_config *config,
					       struct mk_instance *instance)
{
	struct mk_platform_device *src_dev, *dst_dev;

	if (!config->platform_devices_valid || config->platform_device_count == 0) {
		INIT_LIST_HEAD(&instance->platform_devices);
		instance->platform_device_count = 0;
		instance->platform_devices_valid = false;
		pr_debug("No platform devices in DTB\n");
		return 0;
	}

	INIT_LIST_HEAD(&instance->platform_devices);
	instance->platform_device_count = 0;
	instance->platform_devices_valid = true;

	list_for_each_entry(src_dev, &config->platform_devices, list) {
		dst_dev = kzalloc(sizeof(*dst_dev), GFP_KERNEL);
		if (!dst_dev) {
			pr_err("Failed to allocate platform device entry\n");
			return -ENOMEM;
		}

		strncpy(dst_dev->hid, src_dev->hid, MK_PLATFORM_DEVICE_ID_LEN - 1);
		dst_dev->hid[MK_PLATFORM_DEVICE_ID_LEN - 1] = '\0';
		strncpy(dst_dev->name, src_dev->name, MK_PLATFORM_DEVICE_NAME_LEN - 1);
		dst_dev->name[MK_PLATFORM_DEVICE_NAME_LEN - 1] = '\0';

		list_add_tail(&dst_dev->list, &instance->platform_devices);
		instance->platform_device_count++;
	}

	pr_info("Copied %d platform devices to root instance\n", instance->platform_device_count);
	return 0;
}

static int __init mk_restore_instance_ipi(const void *manifest, struct mk_instance *instance)
{
	int ipi_node;
	const fdt64_t *phys_prop;
	const fdt32_t *pages_prop;
	int len;
	phys_addr_t ipi_phys = 0;
	u32 ipi_pages = 0;
	size_t ipi_size = 0;

	ipi_node = fdt_subnode_offset(manifest, 0, "ipi-buffer");
	if (ipi_node < 0) {
		instance->ipi_data = NULL;
		pr_debug("No IPI buffer available in manifest\n");
		return 0;
	}

	phys_prop = fdt_getprop(manifest, ipi_node, "phys-addr", &len);
	if (phys_prop && len == sizeof(*phys_prop))
		ipi_phys = (phys_addr_t)fdt64_to_cpu(*phys_prop);

	pages_prop = fdt_getprop(manifest, ipi_node, "pages", &len);
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
	if (ipi_size < sizeof(struct mk_shared_data)) {
		pr_err("IPI buffer is too small for ABI %u: %zu < %zu\n",
		       MK_IPI_ABI_VERSION, ipi_size,
		       sizeof(struct mk_shared_data));
		return -EPROTO;
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

static struct mk_instance * __init mk_restore_host_instance(const void *manifest)
{
	struct mk_instance *host_instance;
	int host_ipi_node;
	const fdt64_t *phys_prop;
	const fdt32_t *pages_prop;
	phys_addr_t host_ipi_phys = 0;
	u32 host_ipi_pages = 0;
	size_t host_ipi_size = 0;
	int len;

	host_ipi_node = fdt_subnode_offset(manifest, 0, "host-ipi-buffer");
	if (host_ipi_node < 0) {
		pr_warn("No host-ipi-buffer node in manifest (spawn won't be able to send to host)\n");
		return NULL;
	}

	phys_prop = fdt_getprop(manifest, host_ipi_node, "phys-addr", &len);
	if (phys_prop && len == sizeof(*phys_prop))
		host_ipi_phys = (phys_addr_t)fdt64_to_cpu(*phys_prop);

	pages_prop = fdt_getprop(manifest, host_ipi_node, "pages", &len);
	if (pages_prop && len == sizeof(*pages_prop)) {
		host_ipi_pages = fdt32_to_cpu(*pages_prop);
		host_ipi_size = (size_t)host_ipi_pages << PAGE_SHIFT;
	}

	if (!host_ipi_phys || !host_ipi_pages) {
		pr_warn("Incomplete host IPI buffer info (phys=0x%llx, pages=%u)\n",
			(unsigned long long)host_ipi_phys, host_ipi_pages);
		return NULL;
	}
	if (host_ipi_size < sizeof(struct mk_shared_data)) {
		pr_err("Host IPI buffer is too small for ABI %u: %zu < %zu\n",
		       MK_IPI_ABI_VERSION, host_ipi_size,
		       sizeof(struct mk_shared_data));
		return NULL;
	}

	host_instance = alloc_mk_instance(0, "", false);
	if (!host_instance)
		return NULL;

	/* Set physical CPU 0 as default target for host IPIs */
	if (mk_cpu_set_add(host_instance->cpus, 0)) {
		kfree(host_instance->name);
		mk_cpu_set_free(host_instance->cpus);
		kfree(host_instance);
		return NULL;
	}

	host_instance->ipi_data = memremap(host_ipi_phys, host_ipi_size, MEMREMAP_WB);
	if (!host_instance->ipi_data) {
		pr_err("Failed to map host IPI buffer at 0x%llx\n",
		       (unsigned long long)host_ipi_phys);
		kfree(host_instance->name);
		mk_cpu_set_free(host_instance->cpus);
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
 * mk_instance_restore_from_manifest() - Restore this instance from the manifest
 *
 * Called during multikernel initialization in the spawned kernel to restore
 * the single DTB the host kernel placed in the manifest. The spawned
 * kernel receives exactly one DTB and parses the instance ID from it.
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init mk_instance_restore_from_manifest(void)
{
	void *dtb_virt;
	int dtb_len;
	int ret, cpu;
	char cpus_buf[256];
	struct mk_instance *instance, *host_instance;
	struct mk_dt_config config;
	int instance_id;
	const char *instance_name;
	const void *manifest = NULL;
	phys_addr_t fdt_phys;

	if (mk_manifest_rejected())
		mk_manifest_reject_and_park(-EPROTO);

	fdt_phys = mk_manifest_phys();
	if (!fdt_phys) {
		pr_info("No manifest available for multikernel DTB restoration\n");

		instance = alloc_mk_instance(0, "", true);
		if (!instance) {
			pr_err("Failed to allocate root instance\n");
			return -ENOMEM;
		}
		/* Initially, root owns all online CPUs (physical IDs) */
		for_each_online_cpu(cpu) {
			if (mk_cpu_set_add(instance->cpus,
					   arch_cpu_physical_id(cpu)))
				pr_warn("Failed to add CPU %d to root instance\n",
					cpu);
		}
		mk_cpu_set_format(cpus_buf, sizeof(cpus_buf), instance->cpus);
		pr_info("Root instance initialized with CPUs (physical): %s\n",
			cpus_buf);

		root_instance = instance;

		pr_info("Initialized root instance (id=0, name='/')\n");
		return 0;
	}

	pr_info("Restoring multikernel DTB from manifest (phys: 0x%llx)\n", fdt_phys);

	/* Map the FDT for early boot access */
	manifest = early_memremap(fdt_phys, PAGE_SIZE);
	if (!manifest) {
		pr_err("Failed to map manifest at 0x%llx\n", fdt_phys);
		return -EFAULT;
	}

	int mk_node = fdt_subnode_offset(manifest, 0, "multikernel");
	if (mk_node < 0) {
		pr_err("No multikernel node found in supplied manifest\n");
		ret = -EINVAL;
		goto cleanup_fdt;
	}

	const void *dtb_data = fdt_getprop(manifest, mk_node, "dtb-data", &dtb_len);
	if (!dtb_data || dtb_len <= 0) {
		pr_err("No dtb-data property found in multikernel node\n");
		ret = -EINVAL;
		goto cleanup_fdt;
	}

	pr_info("Found preserved multikernel DTB (%d bytes)\n", dtb_len);

	/* Validate DTB header */
	ret = fdt_check_header(dtb_data);
	if (ret) {
		pr_err("Invalid DTB header in manifest: %d\n", ret);
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

	/* Parse DTB configuration - skip validation since host already validated */
	mk_dt_config_init(&config);

	/* In the new flat format, the root node IS the instance node */
	ret = mk_dt_parse(dtb_virt, dtb_len, &config);
	if (ret) {
		pr_err("Failed to parse DTB from manifest: %d\n", ret);
		goto config_free;
	}

	ret = mk_restore_instance_cpus(&config);
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

	if (config.cpus && mk_cpu_set_copy(instance->cpus, config.cpus)) {
		ret = -ENOMEM;
		goto cleanup_instance_name;
	}

	instance->dtb_data = kmalloc(dtb_len, GFP_KERNEL);
	if (!instance->dtb_data) {
		pr_err("Failed to allocate memory for DTB restoration\n");
		ret = -ENOMEM;
		goto cleanup_instance_name;
	}

	memcpy(instance->dtb_data, dtb_virt, dtb_len);
	instance->dtb_size = dtb_len;

	ret = mk_copy_pci_devices(&config, instance);
	if (ret) {
		pr_err("Failed to copy PCI devices: %d\n", ret);
		goto cleanup_devices;
	}

	ret = mk_copy_platform_devices(&config, instance);
	if (ret) {
		pr_err("Failed to copy platform devices: %d\n", ret);
		goto cleanup_devices;
	}

	ret = mk_restore_instance_ipi(manifest, instance);
	if (ret) {
		pr_err("Failed to restore IPI buffer: %d\n", ret);
		goto cleanup_devices;
	}

	root_instance = instance;

	host_instance = mk_restore_host_instance(manifest);
	if (!host_instance)
		mk_manifest_reject_and_park(-ENODEV);

	ret = mk_ipi_shared_validate(instance->ipi_data);
	if (ret)
		mk_manifest_reject_and_park(ret);
	ret = mk_ipi_shared_validate(host_instance->ipi_data);
	if (ret)
		mk_manifest_reject_and_park(ret);
	if (!atomic_read_acquire(&host_instance->ipi_data->ready) ||
	    READ_ONCE(host_instance->ipi_data->ready_instance_id) !=
		    host_instance->id)
		mk_manifest_reject_and_park(-EHOSTDOWN);
	ret = mk_arch_prepare_park();
	if (ret)
		mk_manifest_reject_and_park(ret);
	if (!mk_arch_park_ready())
		mk_manifest_reject_and_park(-EIO);
	ret = mk_register_stop_nmi_handler();
	if (ret)
		mk_manifest_reject_and_park(ret);
	pr_info("Successfully restored multikernel root instance %d ('%s') from manifest (%d bytes)\n",
		instance_id, instance_name, dtb_len);
	mk_dt_config_free(&config);
	kfree(dtb_virt);
	early_memunmap((void *)manifest, PAGE_SIZE);
	return 0;

cleanup_devices:
	if (instance->pci_devices_valid) {
		struct mk_pci_device *pci_dev, *tmp_pci;
		list_for_each_entry_safe(pci_dev, tmp_pci, &instance->pci_devices, list) {
			list_del(&pci_dev->list);
			kfree(pci_dev);
		}
	}
	if (instance->platform_devices_valid) {
		struct mk_platform_device *plat_dev, *tmp_plat;
		list_for_each_entry_safe(plat_dev, tmp_plat, &instance->platform_devices, list) {
			list_del(&plat_dev->list);
			kfree(plat_dev);
		}
	}
cleanup_instance_name:
	kfree(instance->name);
	mk_cpu_set_free(instance->cpus);
	kfree(instance->dtb_data);
	kfree(instance);
config_free:
	mk_dt_config_free(&config);
cleanup_dtb:
	kfree(dtb_virt);
cleanup_fdt:
	early_memunmap((void *)manifest, PAGE_SIZE);
	if (ret)
		mk_manifest_reject_and_park(ret);
	return ret;
}

/* Run at early_initcall to enforce CPU restrictions before per-CPU allocations */
early_initcall(mk_instance_restore_from_manifest);

/**
 * mk_pci_should_probe - Check if PCI probing should occur at all
 * @bus: PCI bus
 * @devfn: device/function number
 *
 * Called BEFORE any PCI config space reads to determine if probing
 * should proceed. This prevents config space accesses to devices
 * that are not in the whitelist.
 *
 * Returns: true if probing should proceed, false to skip entirely
 */
bool mk_pci_should_probe(struct pci_bus *bus, int devfn)
{
	struct mk_pci_device *pci_dev;
	u16 domain = pci_domain_nr(bus);
	u8 bus_num = bus->number;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);
	u8 hdr_type;

	if (!root_instance)
		return true;

	if (!root_instance->dtb_data)
		return true;

	if (!root_instance->pci_devices_valid || root_instance->pci_device_count == 0)
		return false;

	list_for_each_entry(pci_dev, &root_instance->pci_devices, list) {
		if (pci_dev->domain != domain)
			continue;

		/* Exact location match - always allow */
		if (pci_dev->bus == bus_num &&
		    pci_dev->slot == slot &&
		    pci_dev->func == func)
			return true;
	}

	/*
	 * Check if any whitelisted device is on a downstream bus.
	 * If so, this might be a bridge in the path to that device.
	 */
	list_for_each_entry(pci_dev, &root_instance->pci_devices, list) {
		if (pci_dev->domain == domain && pci_dev->bus > bus_num)
			goto check_bridge;
	}
	return false;

check_bridge:
	/*
	 * There's a whitelisted device on a downstream bus. Check if this
	 * is a bridge that serves it.
	 */
	if (pci_bus_read_config_byte(bus, devfn, PCI_HEADER_TYPE, &hdr_type) == 0) {
		bool is_bridge = ((hdr_type & PCI_HEADER_TYPE_MASK) == PCI_HEADER_TYPE_BRIDGE);

		if (is_bridge) {
			u8 secondary_bus = 0, subordinate_bus = 0;

			pci_bus_read_config_byte(bus, devfn, PCI_SECONDARY_BUS, &secondary_bus);
			pci_bus_read_config_byte(bus, devfn, PCI_SUBORDINATE_BUS, &subordinate_bus);

			/*
			 * Allow bridge if there's a whitelisted device on any bus
			 * between secondary and subordinate (inclusive).
			 */
			if (secondary_bus > 0 && subordinate_bus >= secondary_bus) {
				list_for_each_entry(pci_dev, &root_instance->pci_devices, list) {
					if (pci_dev->domain == domain &&
					    pci_dev->bus >= secondary_bus &&
					    pci_dev->bus <= subordinate_bus)
						return true;
				}
			}
		}
	}

	return false;
}
EXPORT_SYMBOL_GPL(mk_pci_should_probe);

bool mk_platform_device_allowed(const char *name, const char *hid)
{
	struct mk_platform_device *plat_dev;

	if (!root_instance->dtb_data)
		return true;

	if (!root_instance->platform_devices_valid)
		return false;

	if (list_empty(&root_instance->platform_devices) || root_instance->platform_device_count == 0)
		return false;

	list_for_each_entry(plat_dev, &root_instance->platform_devices, list) {
		if (hid && plat_dev->hid[0] && strcmp(plat_dev->hid, hid) == 0) {
			pr_info("Platform device '%s' allowed by HID match: hid='%s'\n",
				name ? name : "(none)", hid);
			return true;
		}

		if (name && plat_dev->name[0] && strcmp(plat_dev->name, name) == 0) {
			pr_info("Platform device '%s' allowed by name match\n", name);
			return true;
		}
	}

	return false;
}
EXPORT_SYMBOL_GPL(mk_platform_device_allowed);
