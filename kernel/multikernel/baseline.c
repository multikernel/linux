// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * Multikernel baseline DTB validation and initialization
 *
 * This module handles the baseline device tree that defines the multikernel
 * resource pool. The baseline specifies which CPUs, memory, and devices are
 * available for assignment to multikernel instances.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/libfdt.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/multikernel.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <asm/smp.h>

#include "internal.h"

static int mk_baseline_parse_cpus(const void *fdt, int resources_node,
				  struct mk_instance *instance)
{
	const fdt32_t *prop;
	int len, i, cpu_count;

	prop = fdt_getprop(fdt, resources_node, "cpus", &len);
	if (!prop) {
		pr_err("No 'cpus' property in baseline /resources node\n");
		return -EINVAL;
	}

	if (len % 4 != 0) {
		pr_err("Invalid 'cpus' property length: %d (must be multiple of 4)\n", len);
		return -EINVAL;
	}

	cpu_count = len / 4;
	if (cpu_count == 0) {
		pr_err("Empty CPU list in baseline\n");
		return -EINVAL;
	}

	if (!instance->cpus) {
		pr_err("Instance CPU bitmap not allocated\n");
		return -ENOMEM;
	}

	bitmap_zero(instance->cpus, NR_CPUS);

	for (i = 0; i < cpu_count; i++) {
		u32 cpu_id = fdt32_to_cpu(prop[i]);

		if (cpu_id >= NR_CPUS) {
			pr_err("CPU ID %u exceeds NR_CPUS (%d)\n", cpu_id, NR_CPUS);
			return -EINVAL;
		}

		set_bit(cpu_id, instance->cpus);
		pr_debug("Baseline CPU pool: added physical CPU %u\n", cpu_id);
	}

	pr_info("Baseline CPU pool: %d CPUs specified: %*pbl\n",
		cpu_count, NR_CPUS, instance->cpus);

	return 0;
}

static int mk_baseline_parse_memory(const void *fdt, int resources_node,
				    struct mk_instance *instance)
{
	const fdt32_t *prop;
	struct mk_memory_region *region;
	u64 memory_base, memory_size;
	int len;

	prop = fdt_getprop(fdt, resources_node, "memory-base", &len);
	if (!prop) {
		pr_err("No 'memory-base' property in baseline\n");
		return -EINVAL;
	}

	if (len != 8) {
		pr_err("Invalid 'memory-base' property length: %d (must be 8 bytes)\n", len);
		return -EINVAL;
	}
	memory_base = fdt64_to_cpu(*(const fdt64_t *)prop);

	prop = fdt_getprop(fdt, resources_node, "memory-bytes", &len);
	if (!prop) {
		pr_err("No 'memory-bytes' property in baseline\n");
		return -EINVAL;
	}

	if (len != 8) {
		pr_err("Invalid 'memory-bytes' property length: %d (must be 8 bytes)\n", len);
		return -EINVAL;
	}
	memory_size = fdt64_to_cpu(*(const fdt64_t *)prop);

	if (memory_size == 0) {
		pr_err("Invalid memory size 0 in baseline\n");
		return -EINVAL;
	}

	if (memory_size & (PAGE_SIZE - 1)) {
		pr_err("Memory size 0x%llx not page-aligned\n", memory_size);
		return -EINVAL;
	}

	if (memory_base & (PAGE_SIZE - 1)) {
		pr_err("Memory base 0x%llx not page-aligned\n", memory_base);
		return -EINVAL;
	}

	/* Create memory region for root instance pool */
	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region) {
		pr_err("Failed to allocate memory region for baseline pool\n");
		return -ENOMEM;
	}

	region->res.name = kasprintf(GFP_KERNEL, "mk_pool");
	if (!region->res.name) {
		kfree(region);
		return -ENOMEM;
	}

	region->res.start = memory_base;
	region->res.end = memory_base + memory_size - 1;
	region->res.flags = IORESOURCE_MEM;
	INIT_LIST_HEAD(&region->list);

	list_add_tail(&region->list, &instance->memory_regions);

	pr_info("Baseline memory pool: 0x%llx-0x%llx (%llu MB)\n",
		memory_base,
		memory_base + memory_size - 1,
		memory_size >> 20);

	return 0;
}

static void mk_baseline_clear_resources(struct mk_instance *instance)
{
	struct mk_pci_device *pci_dev, *pci_tmp;
	struct mk_platform_device *plat_dev, *plat_tmp;

	if (!instance)
		return;

	mk_instance_free_memory(instance);
	bitmap_zero(instance->cpus, NR_CPUS);
	list_for_each_entry_safe(pci_dev, pci_tmp, &instance->pci_devices, list) {
		list_del(&pci_dev->list);
		kfree(pci_dev);
	}
	instance->pci_device_count = 0;
	instance->pci_devices_valid = false;

	list_for_each_entry_safe(plat_dev, plat_tmp, &instance->platform_devices, list) {
		list_del(&plat_dev->list);
		kfree(plat_dev);
	}
	instance->platform_device_count = 0;
	instance->platform_devices_valid = false;
}

static int mk_baseline_validate_cpus(const struct mk_instance *instance)
{
	int phys_cpu_id, logical_cpu;
	int validated = 0;

	for_each_set_bit(phys_cpu_id, instance->cpus, NR_CPUS) {
		logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);
		if (logical_cpu < 0) {
			pr_err("Baseline CPU %u not found in system (not present)\n",
			       phys_cpu_id);
			return -ENODEV;
		}

		if (!cpu_present(logical_cpu)) {
			pr_err("Baseline CPU %u (logical %d) is not present\n",
			       phys_cpu_id, logical_cpu);
			return -ENODEV;
		}

		if (logical_cpu == 0 || phys_cpu_id == 0) {
			pr_warn("Baseline includes boot CPU (phys %u, logical %d) - "
				"this may cause system instability\n",
				phys_cpu_id, logical_cpu);
		}

		validated++;
	}

	pr_info("Baseline CPUs validated: %d CPUs available for multikernel pool\n",
		validated);

	return 0;
}

static int mk_baseline_parse_devices(const void *fdt, int resources_node,
				     struct mk_instance *instance)
{
	int devices_node, dev_node;
	const char *dev_name, *device_type;
	int len;

	INIT_LIST_HEAD(&instance->pci_devices);
	instance->pci_device_count = 0;
	instance->pci_devices_valid = false;

	INIT_LIST_HEAD(&instance->platform_devices);
	instance->platform_device_count = 0;
	instance->platform_devices_valid = false;

	devices_node = fdt_subnode_offset(fdt, resources_node, "devices");
	if (devices_node < 0) {
		pr_debug("No 'devices' node in baseline /resources - skipping device parsing\n");
		return 0;
	}

	fdt_for_each_subnode(dev_node, fdt, devices_node) {
		dev_name = fdt_get_name(fdt, dev_node, NULL);
		if (!dev_name) {
			pr_warn("Unnamed device node in baseline, skipping\n");
			continue;
		}

		device_type = fdt_getprop(fdt, dev_node, "device-type", &len);
		if (!device_type) {
			pr_warn("Device '%s' has no device-type property, skipping\n",
				dev_name);
			continue;
		}

		if (strcmp(device_type, "pci") == 0) {
			struct mk_pci_device *pci_dev;
			const char *pci_id_str;
			const fdt32_t *vendor_prop, *device_prop;
			unsigned int domain, bus, slot, func;

			pci_id_str = fdt_getprop(fdt, dev_node, "pci-id", &len);
			if (!pci_id_str) {
				pr_err("PCI device '%s' missing pci-id property\n",
				       dev_name);
				return -EINVAL;
			}

			if (sscanf(pci_id_str, "%x:%x:%x.%x", &domain, &bus, &slot, &func) != 4) {
				pr_err("Invalid pci-id format '%s' for device '%s'\n",
				       pci_id_str, dev_name);
				return -EINVAL;
			}

			vendor_prop = fdt_getprop(fdt, dev_node, "vendor-id", &len);
			if (!vendor_prop || len != 4) {
				pr_err("PCI device '%s' missing or invalid vendor-id\n",
				       dev_name);
				return -EINVAL;
			}

			device_prop = fdt_getprop(fdt, dev_node, "device-id", &len);
			if (!device_prop || len != 4) {
				pr_err("PCI device '%s' missing or invalid device-id\n",
				       dev_name);
				return -EINVAL;
			}

			pci_dev = kzalloc(sizeof(*pci_dev), GFP_KERNEL);
			if (!pci_dev) {
				pr_err("Failed to allocate memory for PCI device\n");
				return -ENOMEM;
			}

			strncpy(pci_dev->name, dev_name, sizeof(pci_dev->name) - 1);
			pci_dev->name[sizeof(pci_dev->name) - 1] = '\0';
			pci_dev->vendor = (u16)fdt32_to_cpu(*vendor_prop);
			pci_dev->device = (u16)fdt32_to_cpu(*device_prop);
			pci_dev->domain = (u16)domain;
			pci_dev->bus = (u8)bus;
			pci_dev->slot = (u8)slot;
			pci_dev->func = (u8)func;

			list_add_tail(&pci_dev->list, &instance->pci_devices);
			instance->pci_device_count++;

			pr_debug("Baseline device pool: added PCI device '%s' %04x:%04x@%04x:%02x:%02x.%x\n",
				 dev_name, pci_dev->vendor, pci_dev->device,
				 pci_dev->domain, pci_dev->bus, pci_dev->slot,
				 pci_dev->func);
		} else if (strcmp(device_type, "platform") == 0) {
			struct mk_platform_device *plat_dev;
			const char *device_name_str;

			plat_dev = kzalloc(sizeof(*plat_dev), GFP_KERNEL);
			if (!plat_dev) {
				pr_err("Failed to allocate memory for platform device\n");
				return -ENOMEM;
			}

			strncpy(plat_dev->name, dev_name, sizeof(plat_dev->name) - 1);
			plat_dev->name[sizeof(plat_dev->name) - 1] = '\0';

			device_name_str = fdt_getprop(fdt, dev_node, "device-name", &len);
			if (device_name_str) {
				strncpy(plat_dev->name, device_name_str,
					sizeof(plat_dev->name) - 1);
				plat_dev->name[sizeof(plat_dev->name) - 1] = '\0';
			}

			list_add_tail(&plat_dev->list, &instance->platform_devices);
			instance->platform_device_count++;

			pr_debug("Baseline device pool: added platform device '%s'\n",
				 plat_dev->name);
		} else {
			pr_warn("Unknown device-type '%s' for device '%s', skipping\n",
				device_type, dev_name);
		}
	}

	if (instance->pci_device_count > 0) {
		instance->pci_devices_valid = true;
		pr_info("Baseline device pool: %d PCI devices specified\n",
			instance->pci_device_count);
	}

	if (instance->platform_device_count > 0) {
		instance->platform_devices_valid = true;
		pr_info("Baseline device pool: %d platform devices specified\n",
			instance->platform_device_count);
	}

	return 0;
}

static int mk_baseline_validate_memory(const struct mk_instance *instance)
{
	struct resource *pool_res;
	struct mk_memory_region *region;
	u64 pool_start, pool_end;
	u64 total_size = 0;

	pool_res = multikernel_get_pool_resource();
	if (!pool_res) {
		pr_err("No multikernel pool configured (use mkkernel_pool= parameter)\n");
		return -ENODEV;
	}

	pool_start = pool_res->start;
	pool_end = pool_res->end;

	if (list_empty(&instance->memory_regions)) {
		pr_err("No memory regions in baseline\n");
		return -EINVAL;
	}

	list_for_each_entry(region, &instance->memory_regions, list) {
		u64 region_size = resource_size(&region->res);

		if (region->res.start < pool_start || region->res.end > pool_end) {
			pr_err("Baseline memory (0x%llx-0x%llx) outside multikernel pool (0x%llx-0x%llx)\n",
			       (u64)region->res.start, (u64)region->res.end,
			       pool_start, pool_end);
			return -EINVAL;
		}

		total_size += region_size;
	}

	if (total_size > (pool_end - pool_start + 1)) {
		pr_err("Baseline memory size (0x%llx) exceeds pool size (0x%llx)\n",
		       total_size, pool_end - pool_start + 1);
		return -ERANGE;
	}

	pr_info("Baseline memory validated: using 0x%llx bytes from pool\n",
		total_size);

	return 0;
}

static int mk_baseline_initialize_cpus(const struct mk_instance *instance)
{
	int phys_cpu_id, logical_cpu;
	int ret, failed = 0, offlined = 0;
	int cpu_count = bitmap_weight(instance->cpus, NR_CPUS);

	pr_info("Offlining %d CPUs for multikernel pool\n", cpu_count);

	for_each_set_bit(phys_cpu_id, instance->cpus, NR_CPUS) {
		logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);
		if (logical_cpu < 0)
			continue;

		if (!cpu_online(logical_cpu)) {
			pr_debug("CPU %u (logical %d) already offline\n",
				 phys_cpu_id, logical_cpu);
			offlined++;
			continue;
		}

		if (logical_cpu == 0) {
			pr_err("Cannot offline boot CPU for multikernel pool\n");
			failed++;
			continue;
		}

		mk_set_pool_cpu(logical_cpu, true);

		ret = remove_cpu(logical_cpu);
		if (ret) {
			pr_err("Failed to offline CPU %u (logical %d): %d\n",
			       phys_cpu_id, logical_cpu, ret);
			mk_set_pool_cpu(logical_cpu, false);
			failed++;
		} else {
			pr_info("Offlined CPU %u (logical %d) for multikernel pool\n",
				phys_cpu_id, logical_cpu);
			offlined++;
		}
	}

	if (failed > 0) {
		pr_err("Failed to offline %d CPUs - baseline initialization incomplete\n",
		       failed);
		return -EBUSY;
	}

	pr_info("Successfully offlined %d CPUs for multikernel pool\n", offlined);

	for_each_set_bit(phys_cpu_id, instance->cpus, NR_CPUS) {
		logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);
		if (logical_cpu > 0 && !cpu_online(logical_cpu))
			set_cpu_present(logical_cpu, false);
	}

	return 0;
}

static int mk_baseline_initialize_devices(const struct mk_instance *instance)
{
	struct mk_pci_device *pci_dev;
	struct pci_dev *dev;
	int failed = 0, unbound = 0;

	if (instance->pci_device_count == 0) {
		pr_debug("No PCI devices in baseline to unbind\n");
		return 0;
	}

	pr_info("Unbinding %d PCI devices for multikernel pool\n",
		instance->pci_device_count);

	list_for_each_entry(pci_dev, &instance->pci_devices, list) {
		dev = pci_get_domain_bus_and_slot(pci_dev->domain, pci_dev->bus,
						  PCI_DEVFN(pci_dev->slot, pci_dev->func));
		if (!dev) {
			pr_warn("PCI device %04x:%04x@%04x:%02x:%02x.%x not found in system\n",
				pci_dev->vendor, pci_dev->device, pci_dev->domain,
				pci_dev->bus, pci_dev->slot, pci_dev->func);
			failed++;
			continue;
		}

		if (!dev->driver) {
			pr_debug("PCI device %04x:%04x@%04x:%02x:%02x.%x already unbound\n",
				 pci_dev->vendor, pci_dev->device, pci_dev->domain,
				 pci_dev->bus, pci_dev->slot, pci_dev->func);
			pci_dev_put(dev);
			unbound++;
			continue;
		}

		const char *driver_name = dev->driver->name;

		device_release_driver(&dev->dev);

		pr_info("Unbound PCI device %04x:%04x@%04x:%02x:%02x.%x (was: %s) for multikernel pool\n",
			pci_dev->vendor, pci_dev->device, pci_dev->domain,
			pci_dev->bus, pci_dev->slot, pci_dev->func,
			driver_name);

		pci_dev_put(dev);
		unbound++;
	}

	if (failed > 0) {
		pr_warn("Failed to find %d PCI devices in system\n", failed);
	}

	pr_info("Successfully unbound %d PCI devices for multikernel pool\n", unbound);
	return 0;
}

int mk_baseline_validate_and_initialize(const void *fdt, size_t fdt_size)
{
	int resources_node;
	int ret;

	if (!fdt || fdt_size == 0) {
		pr_err("Invalid baseline DTB parameters\n");
		return -EINVAL;
	}

	if (!root_instance) {
		pr_err("root_instance not initialized\n");
		return -EINVAL;
	}

	if (!root_instance->cpus) {
		pr_err("root_instance CPUs bitmap not allocated\n");
		return -ENOMEM;
	}

	ret = fdt_check_header(fdt);
	if (ret) {
		pr_err("Invalid baseline DTB header: %d\n", ret);
		return -EINVAL;
	}

	if (fdt_totalsize(fdt) != fdt_size) {
		pr_err("Baseline DTB size mismatch: header=%u, provided=%zu\n",
		       fdt_totalsize(fdt), fdt_size);
		return -EINVAL;
	}

	resources_node = fdt_path_offset(fdt, "/resources");
	if (resources_node < 0) {
		pr_err("No /resources node found in baseline DTB\n");
		return -EINVAL;
	}

	mk_baseline_clear_resources(root_instance);

	ret = mk_baseline_parse_cpus(fdt, resources_node, root_instance);
	if (ret) {
		pr_err("Failed to parse baseline CPUs: %d\n", ret);
		return ret;
	}

	ret = mk_baseline_parse_memory(fdt, resources_node, root_instance);
	if (ret) {
		pr_err("Failed to parse baseline memory: %d\n", ret);
		return ret;
	}

	ret = mk_baseline_parse_devices(fdt, resources_node, root_instance);
	if (ret) {
		pr_err("Failed to parse baseline devices: %d\n", ret);
		return ret;
	}

	ret = mk_baseline_validate_cpus(root_instance);
	if (ret) {
		pr_err("Baseline CPU validation failed: %d\n", ret);
		return ret;
	}

	ret = mk_baseline_validate_memory(root_instance);
	if (ret) {
		pr_err("Baseline memory validation failed: %d\n", ret);
		return ret;
	}

	ret = mk_baseline_initialize_cpus(root_instance);
	if (ret) {
		pr_err("Baseline CPU initialization failed: %d\n", ret);
		return ret;
	}

	ret = mk_baseline_initialize_devices(root_instance);
	if (ret) {
		pr_err("Baseline device initialization failed: %d\n", ret);
		return ret;
	}

	if (root_instance->dtb_data) {
		pr_info("Replacing existing DTB (%zu bytes) with baseline DTB\n", root_instance->dtb_size);
		kfree(root_instance->dtb_data);
	}

	root_instance->dtb_data = kmalloc(fdt_size, GFP_KERNEL);
	if (root_instance->dtb_data) {
		memcpy(root_instance->dtb_data, fdt, fdt_size);
		root_instance->dtb_size = fdt_size;
	} else {
		pr_err("Failed to allocate memory for baseline DTB\n");
		return -ENOMEM;
	}

	pr_info("Multikernel baseline initialized successfully:\n");
	return 0;
}
