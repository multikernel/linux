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
#include <linux/netdevice.h>
#include <linux/libfdt.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_pci.h>
#include <linux/sizes.h>
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
struct mk_instance *mk_parent_instance;

/**
 * mk_dt_extract_instance_info() - Extract instance ID and name from DTB
 * @dtb_data: Device tree blob data
 * @dtb_size: Size of DTB data
 * @instance_id: Output parameter for instance ID
 * @instance_name: Output parameter for instance name (caller must free)
 *
 * The root node is the instance, named by its model property:
 * / { compatible = "multikernel-v1"; model = "web"; id = <N>; resources {...}; }
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

	name = fdt_getprop(fdt, root_node, "model", NULL);
	if (!name) {
		pr_err("No 'model' property naming the instance in the DTB\n");
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

static void __init mk_register_cpus_from(struct device_node *np,
					 const char *prop)
{
	int i, n = of_property_count_u64_elems(np, prop);

	for (i = 0; i < n; i++) {
		u64 phys_id;

		if (of_property_read_u64_index(np, prop, i, &phys_id))
			break;
		mk_arch_register_cpu(phys_id);
	}
}

/*
 * Register CPUs from the boot tree during SMP config phase. Called from
 * multikernel_parse_smp_config(), after the tree has been unflattened
 * and before the topology is finalized.
 */
void __init mk_register_cpus_from_manifest(void)
{
	struct device_node *np;

	if (!mk_manifest_phys())
		return;

	np = of_find_node_by_path("/resources");
	if (np) {
		mk_register_cpus_from(np, "cpus");
		of_node_put(np);
	}

	/*
	 * Register the rest of the pool so those CPUs can be hot-added
	 * later: the topology rejects post-boot APIC IDs it did not see
	 * during enumeration. They are registered present and pruned from
	 * the present mask in mk_restore_instance_cpus(), which keeps a logical
	 * CPU assigned to each and avoids the hot-pluggable-APIC checks.
	 */
	if (of_chosen)
		mk_register_cpus_from(of_chosen, "multikernel,pool-cpus");
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

/* A message ring the host describes in /chosen: its address and size */
static bool __init mk_chosen_ring(const char *what, phys_addr_t *phys,
				  u32 *pages)
{
	char name[48];
	u64 addr;

	if (!of_chosen)
		return false;

	snprintf(name, sizeof(name), "multikernel,%s-buffer", what);
	if (of_property_read_u64(of_chosen, name, &addr))
		return false;
	snprintf(name, sizeof(name), "multikernel,%s-pages", what);
	if (of_property_read_u32(of_chosen, name, pages))
		return false;

	*phys = addr;
	return *phys && *pages;
}

static int __init mk_restore_instance_ipi(struct mk_instance *instance)
{
	phys_addr_t ipi_phys;
	u32 ipi_pages;
	size_t ipi_size;

	if (!mk_chosen_ring("ipi", &ipi_phys, &ipi_pages)) {
		instance->ipi_data = NULL;
		pr_debug("No IPI buffer in the boot tree\n");
		return 0;
	}
	ipi_size = (size_t)ipi_pages << PAGE_SHIFT;

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

static struct mk_instance * __init mk_restore_host_instance(void)
{
	struct mk_instance *host_instance;
	phys_addr_t host_ipi_phys;
	u64 host_doorbell_cpu;
	u32 host_ipi_pages;
	size_t host_ipi_size;

	if (!mk_chosen_ring("host-ipi", &host_ipi_phys, &host_ipi_pages)) {
		pr_warn("No host IPI buffer in the boot tree (spawn won't be able to send to host)\n");
		return NULL;
	}
	if (of_property_read_u64(of_chosen, "multikernel,host-ipi-cpu",
				 &host_doorbell_cpu)) {
		pr_warn("No host doorbell CPU; defaulting to physical CPU 0\n");
		host_doorbell_cpu = 0;
	}
	host_ipi_size = (size_t)host_ipi_pages << PAGE_SHIFT;

	host_instance = alloc_mk_instance(0, "", false);
	if (!host_instance)
		return NULL;

	if (mk_cpu_set_add(host_instance->cpus, host_doorbell_cpu)) {
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
	const void *dtb_virt;
	int dtb_len;
	int ret, cpu;
	char cpus_buf[256];
	struct mk_instance *instance, *host_instance;
	struct mk_dt_config config;
	int instance_id;
	const char *instance_name;

	if (!mk_manifest_phys()) {
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

	/*
	 * The manifest is this kernel's boot device tree; the OF core keeps
	 * the flattened copy it unflattened, so parse that one.
	 */
	dtb_virt = initial_boot_params;
	if (!dtb_virt || !of_have_populated_dt()) {
		pr_err("Boot device tree from the manifest was not unflattened\n");
		return -ENOENT;
	}
	dtb_len = fdt_totalsize(dtb_virt);

	pr_info("Restoring instance from the boot device tree (%d bytes)\n", dtb_len);

	ret = mk_dt_extract_instance_info(dtb_virt, dtb_len, &instance_id, &instance_name);
	if (ret) {
		pr_err("Failed to extract instance info from DTB: %d\n", ret);
		return ret;
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

	/* The tree is the record of this kernel's PCI devices; the list stays empty */
	instance->pci_devices_valid = true;

	ret = mk_copy_platform_devices(&config, instance);
	if (ret) {
		pr_err("Failed to copy platform devices: %d\n", ret);
		goto cleanup_devices;
	}

	ret = mk_restore_instance_ipi(instance);
	if (ret) {
		pr_err("Failed to restore IPI buffer: %d\n", ret);
		goto cleanup_devices;
	}

	root_instance = instance;

	host_instance = mk_restore_host_instance();
	if (!host_instance)
		pr_warn("Failed to restore host instance (spawn→host communication unavailable)\n");
	else
		mk_parent_instance = host_instance;

	pr_info("Successfully restored multikernel root instance %d ('%s') from the boot tree (%d bytes)\n",
		instance_id, instance_name, dtb_len);
	mk_dt_config_free(&config);
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
	kfree(instance);
config_free:
	mk_dt_config_free(&config);
	return ret;
}

/* Run at early_initcall to enforce CPU restrictions before per-CPU allocations */
early_initcall(mk_instance_restore_from_manifest);

/**
 * mk_pci_should_probe - Whether a PCI slot is this kernel's to probe
 * @bus: PCI bus
 * @devfn: device/function number
 *
 * Called before any config space read of the slot. A spawn kernel owns
 * exactly the devices its device tree describes under the bus's node,
 * bridges on the way down included, and must not touch any other slot
 * on the fabric it shares. A host probes everything: what it gives away
 * leaves it by explicit hot-unplug.
 *
 * Returns: true if probing should proceed, false to skip entirely
 */
bool mk_pci_should_probe(struct pci_bus *bus, int devfn)
{
	struct device_node *np;
	bool available;

	if (!mk_manifest_phys())
		return true;

	if (!bus->dev.of_node)
		return false;

	np = of_pci_find_child_device(bus->dev.of_node, devfn);
	available = np && of_device_is_available(np);
	of_node_put(np);
	return available;
}
EXPORT_SYMBOL_GPL(mk_pci_should_probe);

/*
 * A netdev's alias is its interface name, the one the device had in the
 * kernel that gave it away, found from the node its device is bound to,
 * so rename it once it is registered through the same path as a rename
 * from userspace. netif_change_name() rejects
 * a name that is too long or already in use, and the driver's name then
 * stands.
 */
static int mk_netdev_alias_event(struct notifier_block *nb,
				 unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct device *parent;
	const char *alias;
	int ret;

	if (event != NETDEV_REGISTER)
		return NOTIFY_DONE;

	/* A virtio or USB netdev hangs off its bus device, not the function */
	for (parent = dev->dev.parent; parent; parent = parent->parent)
		if (parent->of_node)
			break;
	if (!parent)
		return NOTIFY_DONE;

	alias = of_alias_from_node(parent->of_node);
	if (!alias)
		return NOTIFY_DONE;

	ret = netif_change_name(dev, alias);
	if (ret)
		netdev_warn(dev, "alias %s not applied: %d\n", alias, ret);

	return NOTIFY_DONE;
}

static struct notifier_block mk_netdev_alias_nb = {
	.notifier_call = mk_netdev_alias_event,
};

static int __init mk_netdev_alias_init(void)
{
	return register_netdevice_notifier(&mk_netdev_alias_nb);
}
/* Before device_initcall, where the drivers that register netdevs run */
subsys_initcall(mk_netdev_alias_init);

/**
 * mk_platform_device_allowed - Whether a platform device is this kernel's
 * @name: Platform device name, or NULL
 * @hid: ACPI hardware id, or NULL
 *
 * A spawn kernel has the platform devices its device tree lists under
 * /resources/devices, each named by device-name or acpi-hid. A host
 * has them all.
 *
 * Returns: true if the device may be registered
 */
bool mk_platform_device_allowed(const char *name, const char *hid)
{
	struct device_node *devices, *np;
	bool allowed = false;

	if (!mk_manifest_phys())
		return true;

	devices = of_find_node_by_path("/resources/devices");
	if (!devices)
		return false;

	for_each_child_of_node(devices, np) {
		const char *want;

		if (of_property_match_string(np, "device-type", "platform") < 0)
			continue;
		if (hid && !of_property_read_string(np, "acpi-hid", &want) &&
		    !strcmp(want, hid))
			allowed = true;
		if (name && !of_property_read_string(np, "device-name", &want) &&
		    !strcmp(want, name))
			allowed = true;
		if (allowed) {
			pr_info("Platform device '%s' is described by %pOF\n",
				name ? name : hid, np);
			of_node_put(np);
			break;
		}
	}

	of_node_put(devices);
	return allowed;
}
EXPORT_SYMBOL_GPL(mk_platform_device_allowed);
