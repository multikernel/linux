// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * Multikernel device tree support
 *
 * Provides device tree parsing and validation for multikernel instances.
 * Designed to be extensible for future enhancements like CPU affinity,
 * I/O resource allocation, NUMA topology, etc.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ioport.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/cpumask.h>
#include <linux/hex.h>
#include <linux/numa.h>
#include <linux/multikernel.h>

#include "internal.h"
static int mk_pci_parse_hex(const char *str, size_t digits, u32 *value)
{
	size_t i;
	u32 parsed = 0;

	for (i = 0; i < digits; i++) {
		int digit = hex_to_bin(str[i]);

		if (digit < 0)
			return -EINVAL;
		parsed = (parsed << 4) | digit;
	}

	*value = parsed;
	return 0;
}

int mk_pci_parse_bdf(const char *pci_id, int len, u16 *domain, u8 *bus,
		     u8 *slot, u8 *func)
{
	u32 parsed_domain, parsed_bus, parsed_slot, parsed_func;

	if (len != (int)sizeof("0000:00:00.0") || pci_id[12] != '\0' ||
	    pci_id[4] != ':' || pci_id[7] != ':' || pci_id[10] != '.')
		return -EINVAL;

	if (mk_pci_parse_hex(pci_id, 4, &parsed_domain) ||
	    mk_pci_parse_hex(pci_id + 5, 2, &parsed_bus) ||
	    mk_pci_parse_hex(pci_id + 8, 2, &parsed_slot) ||
	    mk_pci_parse_hex(pci_id + 11, 1, &parsed_func))
		return -EINVAL;
	if (parsed_domain > U16_MAX || parsed_bus > U8_MAX ||
	    parsed_slot > 31 || parsed_func > 7)
		return -ERANGE;

	*domain = (u16)parsed_domain;
	*bus = (u8)parsed_bus;
	*slot = (u8)parsed_slot;
	*func = (u8)parsed_func;
	return 0;
}

static const void *mk_dt_get_base_fdt(void)
{
	if (!root_instance || !root_instance->dtb_data) {
		pr_err("No base DTB available (root_instance not initialized)\n");
		return NULL;
	}

	if (fdt_check_header(root_instance->dtb_data) != 0) {
		pr_err("Base DTB has invalid header\n");
		return NULL;
	}

	return root_instance->dtb_data;
}

/**
 * Configuration initialization and cleanup
 */
void mk_dt_config_init(struct mk_dt_config *config)
{
	memset(config, 0, sizeof(*config));
	config->version = MK_DT_CONFIG_CURRENT;
	config->memory_size = 0;
	config->numa_node = NUMA_NO_NODE;

	config->cpus = mk_cpu_set_alloc();
	if (!config->cpus)
		pr_warn("Failed to allocate CPU set, CPU assignment disabled\n");

	INIT_LIST_HEAD(&config->pci_devices);
	config->pci_device_count = 0;
	config->pci_devices_valid = true;

	INIT_LIST_HEAD(&config->platform_devices);
	config->platform_device_count = 0;
	config->platform_devices_valid = true;
}

void mk_dt_config_free(struct mk_dt_config *config)
{
	struct mk_pci_device *pci_dev, *tmp_pci;
	struct mk_platform_device *plat_dev, *tmp_plat;

	if (!config)
		return;

	mk_cpu_set_free(config->cpus);
	config->cpus = NULL;

	/* Free PCI device list */
	if (config->pci_devices_valid) {
		list_for_each_entry_safe(pci_dev, tmp_pci, &config->pci_devices, list) {
			list_del(&pci_dev->list);
			kfree(pci_dev);
		}
		config->pci_device_count = 0;
		config->pci_devices_valid = false;
	}

	/* Free platform device list */
	if (config->platform_devices_valid) {
		list_for_each_entry_safe(plat_dev, tmp_plat, &config->platform_devices, list) {
			list_del(&plat_dev->list);
			kfree(plat_dev);
		}
		config->platform_device_count = 0;
		config->platform_devices_valid = false;
	}

	/* Reset memory size */
	config->memory_size = 0;

	/* Note: We don't free dtb_data here as it's managed by the caller */
}

/**
 * Function prototypes
 */
static int mk_dt_parse_memory(const void *fdt, int chosen_node,
			      struct mk_dt_config *config);
static int mk_dt_parse_cpus(const void *fdt, int chosen_node,
			    struct mk_dt_config *config);
static int mk_dt_parse_numa(const void *fdt, int chosen_node,
			    struct mk_dt_config *config);
static int mk_dt_parse_devices(const void *fdt, int chosen_node,
			       struct mk_dt_config *config);
static int mk_dt_validate_memory(const struct mk_dt_config *config);
static int mk_dt_validate_cpus(const struct mk_dt_config *config);

/**
 * Memory region parsing
 */
static int mk_dt_parse_memory(const void *fdt, int chosen_node,
			      struct mk_dt_config *config)
{
	const fdt32_t *prop;
	int len;
	size_t total_size = 0;

	/* Look for memory-bytes property */
	prop = fdt_getprop(fdt, chosen_node, MK_DT_RESOURCE_MEMORY, &len);
	if (!prop) {
		pr_debug("No %s property found\n", MK_DT_RESOURCE_MEMORY);
		return 0; /* Not an error - property is optional */
	}

	if (len != 8) {
		pr_err("Invalid %s property length: %d (must be 8 bytes for u64 size)\n",
		       MK_DT_RESOURCE_MEMORY, len);
		return -EINVAL;
	}

	total_size = fdt64_to_cpu(*(const fdt64_t *)prop);
	if (total_size == 0) {
		pr_err("Invalid memory size 0 in %s\n", MK_DT_RESOURCE_MEMORY);
		return -EINVAL;
	}

	/* Validate size alignment */
	if (total_size & (PAGE_SIZE - 1)) {
		pr_err("Memory size 0x%zx not page-aligned\n", total_size);
		return -EINVAL;
	}

	config->memory_size = total_size;
	pr_info("Successfully parsed memory size: %zu bytes (%zu MB)\n",
		total_size, total_size >> 20);
	return 0;
}

/**
 * NUMA node parsing
 *
 * The instance grant comes from a single node pool, so of the nodes listed
 * only the first one selects where the memory is taken from.
 */
static int mk_dt_parse_numa(const void *fdt, int chosen_node,
			    struct mk_dt_config *config)
{
	const fdt32_t *prop;
	u32 node;
	int len;

	prop = fdt_getprop(fdt, chosen_node, MK_DT_RESOURCE_NUMA, &len);
	if (!prop) {
		pr_debug("No %s property found\n", MK_DT_RESOURCE_NUMA);
		return 0; /* Not an error - property is optional */
	}

	if (len < (int)sizeof(fdt32_t) || len % sizeof(fdt32_t) != 0) {
		pr_err("Invalid %s property length: %d (must be an array of 32-bit node IDs)\n",
		       MK_DT_RESOURCE_NUMA, len);
		return -EINVAL;
	}

	node = fdt32_to_cpu(prop[0]);
	if (node >= MAX_NUMNODES) {
		pr_err("Invalid NUMA node %u in %s\n", node, MK_DT_RESOURCE_NUMA);
		return -EINVAL;
	}

	config->numa_node = node;
	pr_debug("Successfully parsed NUMA node: %d\n", config->numa_node);
	return 0;
}

/**
 * CPU resource parsing
 */
static int mk_dt_parse_cpus(const void *fdt, int chosen_node,
			    struct mk_dt_config *config)
{
	const fdt64_t *prop;
	int len, i, cpu_count;
	char buf[256];

	if (!config->cpus) {
		pr_debug("CPU set allocation failed, skipping CPU parsing\n");
		return 0;
	}

	/* Look for cpus property */
	prop = fdt_getprop(fdt, chosen_node, MK_DT_RESOURCE_CPUS, &len);
	if (!prop) {
		pr_debug("No %s property found\n", MK_DT_RESOURCE_CPUS);
		return 0; /* Not an error - property is optional */
	}

	if (len % sizeof(fdt64_t) != 0) {
		pr_err("Invalid %s property length: %d (must be an array of 64-bit physical CPU IDs)\n",
		       MK_DT_RESOURCE_CPUS, len);
		return -EINVAL;
	}

	cpu_count = len / sizeof(fdt64_t);
	if (cpu_count == 0) {
		pr_err("Empty CPU list in %s\n", MK_DT_RESOURCE_CPUS);
		return -EINVAL;
	}

	pr_debug("Parsing %d CPUs\n", cpu_count);

	mk_cpu_set_clear(config->cpus);

	for (i = 0; i < cpu_count; i++) {
		mk_phys_cpu_t phys_cpu_id = fdt64_to_cpu(prop[i]);
		int ret = mk_cpu_set_add(config->cpus, phys_cpu_id);

		if (ret)
			return ret;
		pr_debug("Added physical CPU ID: %llu\n", phys_cpu_id);
	}

	mk_cpu_set_format(buf, sizeof(buf), config->cpus);
	pr_info("Successfully parsed %d physical CPUs: %s\n", cpu_count, buf);
	return 0;
}

static int mk_dt_parse_single_pci_device(const void *source_fdt, int dev_node,
					 struct mk_dt_config *config,
					 const char *device_name)
{
	const char *pci_id_str;
	const fdt32_t *vendor_prop, *device_prop;
	const fdt64_t *resources_prop;
	struct mk_pci_device *existing;
	struct mk_pci_device *pci_dev;
	u32 vendor, device;
	u16 domain;
	u8 bus, slot, func;
	const char *node_name;
	int len, i, ret;

	node_name = fdt_get_name(source_fdt, dev_node, NULL);

	pci_id_str = fdt_getprop(source_fdt, dev_node, "pci-id", &len);
	if (!pci_id_str) {
		pr_err("No pci-id property in device '%s' (node '%s')\n",
		       device_name, node_name ? node_name : "<unnamed>");
		return -EINVAL;
	}

	ret = mk_pci_parse_bdf(pci_id_str, len, &domain, &bus, &slot, &func);
	if (ret) {
		pr_err("Invalid or out-of-range pci-id: '%.*s' (expected domain:bus:slot.func)\n",
		       len, pci_id_str);
		return ret;
	}

	vendor_prop = fdt_getprop(source_fdt, dev_node, "vendor-id", &len);
	if (!vendor_prop || len != 4) {
		pr_err("Missing or invalid vendor-id in device '%s' (node '%s')\n",
		       device_name, node_name ? node_name : "<unnamed>");
		return -EINVAL;
	}

	device_prop = fdt_getprop(source_fdt, dev_node, "device-id", &len);
	if (!device_prop || len != 4) {
		pr_err("Missing or invalid device-id in device '%s' (node '%s')\n",
		       device_name, node_name ? node_name : "<unnamed>");
		return -EINVAL;
	}
	vendor = fdt32_to_cpu(*vendor_prop);
	device = fdt32_to_cpu(*device_prop);
	if (vendor > U16_MAX || device > U16_MAX) {
		pr_err("Out-of-range vendor-id or device-id in device '%s'\n",
		       device_name);
		return -ERANGE;
	}
	list_for_each_entry(existing, &config->pci_devices, list) {
		if (existing->domain == domain && existing->bus == bus &&
		    existing->slot == slot && existing->func == func) {
			pr_err("Duplicate assigned PCI BDF %04x:%02x:%02x.%x\n",
			       domain, bus, slot, func);
			return -EEXIST;
		}
	}

	pci_dev = kzalloc(sizeof(*pci_dev), GFP_KERNEL);
	if (!pci_dev) {
		pr_err("Failed to allocate memory for PCI device\n");
		return -ENOMEM;
	}

	strscpy(pci_dev->name, device_name, sizeof(pci_dev->name));
	pci_dev->vendor = (u16)vendor;
	pci_dev->device = (u16)device;
	pci_dev->domain = domain;
	pci_dev->bus = bus;
	pci_dev->slot = slot;
	pci_dev->func = func;
	resources_prop = fdt_getprop(source_fdt, dev_node, "bar-resources", &len);
	if (resources_prop) {
		if (len != MK_PCI_RESOURCE_COUNT * 3 * sizeof(*resources_prop)) {
			pr_err("Invalid bar-resources in device '%s'\n", device_name);
			kfree(pci_dev);
			return -EINVAL;
		}
		for (i = 0; i < MK_PCI_RESOURCE_COUNT; i++) {
			u64 start = fdt64_to_cpu(resources_prop[i * 3]);
			u64 end = fdt64_to_cpu(resources_prop[i * 3 + 1]);
			u64 flags = fdt64_to_cpu(resources_prop[i * 3 + 2]);

			if ((start || end) &&
			    (end < start || !(flags & (IORESOURCE_IO | IORESOURCE_MEM)))) {
				pr_err("Invalid PCI BAR %d range in device '%s'\n",
				       i, device_name);
				kfree(pci_dev);
				return -EINVAL;
			}
			pci_dev->resources[i].start = start;
			pci_dev->resources[i].end = end;
			pci_dev->resources[i].flags = flags;
		}
		pci_dev->resources_valid = true;
	}

	list_add_tail(&pci_dev->list, &config->pci_devices);
	config->pci_device_count++;

	pr_info("Added PCI device '%s': %04x:%04x@%04x:%02x:%02x.%x\n",
		device_name, pci_dev->vendor, pci_dev->device,
		pci_dev->domain, pci_dev->bus, pci_dev->slot, pci_dev->func);

	return 0;
}

static int mk_dt_parse_single_platform_device(const void *source_fdt, int dev_node,
					      struct mk_dt_config *config,
					      const char *device_name)
{
	const char *hid_str = NULL, *name_str = NULL;
	struct mk_platform_device *plat_dev;
	const char *node_name;
	int len;

	node_name = fdt_get_name(source_fdt, dev_node, NULL);

	hid_str = fdt_getprop(source_fdt, dev_node, "acpi-hid", &len);

	name_str = fdt_getprop(source_fdt, dev_node, "device-name", &len);

	if (!hid_str && !name_str) {
		pr_err("Platform device '%s' (node '%s') has neither acpi-hid nor device-name\n",
		       device_name, node_name ? node_name : "<unnamed>");
		return -EINVAL;
	}

	plat_dev = kzalloc(sizeof(*plat_dev), GFP_KERNEL);
	if (!plat_dev) {
		pr_err("Failed to allocate memory for platform device\n");
		return -ENOMEM;
	}

	if (hid_str) {
		strncpy(plat_dev->hid, hid_str, MK_PLATFORM_DEVICE_ID_LEN - 1);
		plat_dev->hid[MK_PLATFORM_DEVICE_ID_LEN - 1] = '\0';
	}

	if (name_str) {
		strncpy(plat_dev->name, name_str, MK_PLATFORM_DEVICE_NAME_LEN - 1);
		plat_dev->name[MK_PLATFORM_DEVICE_NAME_LEN - 1] = '\0';
	}

	list_add_tail(&plat_dev->list, &config->platform_devices);
	config->platform_device_count++;

	pr_info("Added platform device '%s': name='%s' hid='%s'\n",
		device_name,
		plat_dev->name[0] ? plat_dev->name : "(none)",
		plat_dev->hid[0] ? plat_dev->hid : "(none)");

	return 0;
}

static int mk_dt_parse_embedded_devices(const void *fdt, int resources_node,
					struct mk_dt_config *config)
{
	int devices_node, dev_node, ret;
	const char *device_name, *device_type;
	int len;

	devices_node = fdt_subnode_offset(fdt, resources_node, "devices");
	if (devices_node < 0) {
		pr_debug("No devices node found in resources\n");
		return 0;
	}

	fdt_for_each_subnode(dev_node, fdt, devices_node) {
		device_name = fdt_get_name(fdt, dev_node, NULL);
		if (!device_name)
			continue;

		device_type = fdt_getprop(fdt, dev_node, "device-type", &len);
		if (!device_type)
			continue; /* Not a device node, skip */

		if (strcmp(device_type, "pci") == 0) {
			if (!config->pci_devices_valid)
				continue;
			ret = mk_dt_parse_single_pci_device(fdt, dev_node, config, device_name);
			if (ret) {
				pr_err("Failed to parse embedded PCI device '%s': %d\n",
				       device_name, ret);
				return ret;
			}
		} else if (strcmp(device_type, "platform") == 0) {
			if (!config->platform_devices_valid)
				continue;
			ret = mk_dt_parse_single_platform_device(fdt, dev_node, config, device_name);
			if (ret) {
				pr_err("Failed to parse embedded platform device '%s': %d\n",
				       device_name, ret);
				return ret;
			}
		}
	}

	return 0;
}

/**
 * Device parsing using string array with device-type dispatching
 *
 * Format: device-names = "dev1", "dev2", ...;
 *
 * This approach:
 * - Uses simple string names instead of phandles
 * - No need for dtc -@ compilation
 * - No __symbols__ or __fixups__ complexity
 * - Just looks up /resources/devices/{name} in base DTB
 * - Reads device-type property first to dispatch to correct parser
 *
 * Example base DTB:
 *   resources {
 *       devices {
 *           enp9s0_dev {
 *               device-type = "pci";
 *               pci-id = "0000:09:00.0";
 *               vendor-id = <0x1af4>;
 *               device-id = <0x1041>;
 *           };
 *           serial_console {
 *               device-type = "platform";
 *               device-name = "serial8250";
 *           };
 *           keyboard {
 *               device-type = "platform";
 *               acpi-hid = "PNP0303";
 *           };
 *       };
 *   };
 *
 * Example overlay:
 *   resources {
 *       device-names = "enp9s0_dev", "serial_console", "keyboard";
 *   };
 */
static int mk_dt_parse_devices(const void *fdt, int chosen_node,
			       struct mk_dt_config *config)
{
	const void *base_fdt;
	const char *prop_data;
	const char *device_name;
	const char *device_type;
	char device_path[256];
	int len, offset, dev_node, ret;
	int device_count = 0;

	/* First try device-names property (overlay format) */
	prop_data = fdt_getprop(fdt, chosen_node, "device-names", &len);
	if (!prop_data) {
		return mk_dt_parse_embedded_devices(fdt, chosen_node, config);
	}

	if (len == 0) {
		pr_debug("Empty device-names property\n");
		return 0;
	}

	base_fdt = mk_dt_get_base_fdt();
	if (!base_fdt) {
		pr_err("No base DTB available - cannot resolve device names\n");
		return -ENOENT;
	}

	offset = 0;
	while (offset < len) {
		device_name = prop_data + offset;

		if (device_name[0] == '\0')
			break;

		device_count++;

		snprintf(device_path, sizeof(device_path),
			 "/resources/devices/%s", device_name);

		dev_node = fdt_path_offset(base_fdt, device_path);
		if (dev_node < 0) {
			pr_err("Device '%s' not found in base DTB at path '%s'\n",
			       device_name, device_path);
			return -ENOENT;
		}

		device_type = fdt_getprop(base_fdt, dev_node, "device-type", NULL);
		if (!device_type) {
			pr_err("Missing device-type property in device '%s'\n",
			       device_name);
			return -EINVAL;
		}

		if (strcmp(device_type, "pci") == 0) {
			if (!config->pci_devices_valid) {
				pr_warn("PCI device '%s' found but PCI device list not available\n",
					device_name);
				offset += strlen(device_name) + 1;
				continue;
			}
			ret = mk_dt_parse_single_pci_device(base_fdt, dev_node,
							    config, device_name);
			if (ret) {
				pr_err("Failed to parse PCI device '%s': %d\n",
				       device_name, ret);
				return ret;
			}
		} else if (strcmp(device_type, "platform") == 0) {
			if (!config->platform_devices_valid) {
				pr_warn("Platform device '%s' found but platform device list not available\n",
					device_name);
				offset += strlen(device_name) + 1;
				continue;
			}
			ret = mk_dt_parse_single_platform_device(base_fdt, dev_node,
								 config, device_name);
			if (ret) {
				pr_err("Failed to parse platform device '%s': %d\n",
				       device_name, ret);
				return ret;
			}
		} else {
			pr_err("Unknown device-type '%s' for device '%s'\n",
			       device_type, device_name);
			return -EINVAL;
		}

		offset += strlen(device_name) + 1;
	}

	if (device_count == 0) {
		pr_debug("No device names found in property\n");
		return 0;
	}

	return 0;
}

/**
 * Main device tree parsing function
 */
int mk_dt_parse(const void *dtb_data, size_t dtb_size,
		struct mk_dt_config *config)
{
	const void *fdt = dtb_data;
	int ret;

	if (!dtb_data || !config) {
		pr_err("Invalid parameters to mk_dt_parse\n");
		return -EINVAL;
	}

	/* Validate FDT header */
	ret = fdt_check_header(fdt);
	if (ret) {
		pr_err("Invalid device tree blob: %d\n", ret);
		return -EINVAL;
	}

	/* Verify size matches */
	if (fdt_totalsize(fdt) > dtb_size) {
		pr_err("DTB size mismatch: header=%u, provided=%zu\n",
		       fdt_totalsize(fdt), dtb_size);
		return -EINVAL;
	}

	/* Flat format: root node is the instance, find resources subnode */
	int instance_node = fdt_path_offset(fdt, "/");
	if (instance_node < 0) {
		pr_err("Failed to get root node from DTB\n");
		return -EINVAL;
	}

	/* Find the resources subnode */
	int resources_node = fdt_subnode_offset(fdt, instance_node, "resources");
	if (resources_node < 0) {
		pr_err("No resources node found in instance\n");
		return -ENOENT;
	}

	/* Store raw DTB reference */
	config->dtb_data = (void *)dtb_data;
	config->dtb_size = dtb_size;

	/* Parse memory regions */
	ret = mk_dt_parse_memory(fdt, resources_node, config);
	if (ret) {
		pr_err("Failed to parse memory regions: %d\n", ret);
		mk_dt_config_free(config);
		return ret;
	}

	/* Parse CPU resources */
	ret = mk_dt_parse_cpus(fdt, resources_node, config);
	if (ret) {
		pr_err("Failed to parse CPU resources: %d\n", ret);
		mk_dt_config_free(config);
		return ret;
	}

	ret = mk_dt_parse_numa(fdt, resources_node, config);
	if (ret) {
		pr_err("Failed to parse NUMA nodes: %d\n", ret);
		mk_dt_config_free(config);
		return ret;
	}

	ret = mk_dt_parse_devices(fdt, resources_node, config);
	if (ret) {
		pr_err("Failed to parse device resources: %d\n", ret);
		mk_dt_config_free(config);
		return ret;
	}

	pr_info("Successfully parsed multikernel device tree with %zu bytes memory, %d CPUs, %d PCI devices, and %d platform devices\n",
		config->memory_size, mk_cpu_set_count(config->cpus),
		config->pci_device_count, config->platform_device_count);
	return 0;
}

/**
 * mk_dt_parse_resources() - Parse resources from a resources node
 * @fdt: Device tree blob
 * @resources_node: Offset of the resources node
 * @instance_name: Name of the instance (for logging)
 * @config: Output configuration structure
 *
 * Parses all resources (memory, CPUs) from a resources node.
 * This is the core parsing logic used by both full DTB parsing and
 * overlay instance creation.
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_dt_parse_resources(const void *fdt, int resources_node,
			  const char *instance_name, struct mk_dt_config *config)
{
	int ret;

	if (!fdt || resources_node < 0 || !instance_name || !config) {
		pr_err("Invalid parameters to mk_dt_parse_resources\n");
		return -EINVAL;
	}

	ret = mk_dt_parse_memory(fdt, resources_node, config);
	if (ret) {
		pr_err("Failed to parse memory regions for '%s': %d\n", instance_name, ret);
		mk_dt_config_free(config);
		return ret;
	}

	ret = mk_dt_parse_cpus(fdt, resources_node, config);
	if (ret) {
		pr_err("Failed to parse CPU resources for '%s': %d\n", instance_name, ret);
		mk_dt_config_free(config);
		return ret;
	}

	ret = mk_dt_parse_numa(fdt, resources_node, config);
	if (ret) {
		pr_err("Failed to parse NUMA nodes for '%s': %d\n", instance_name, ret);
		mk_dt_config_free(config);
		return ret;
	}

	ret = mk_dt_parse_devices(fdt, resources_node, config);
	if (ret) {
		pr_err("Failed to parse device resources for '%s': %d\n", instance_name, ret);
		mk_dt_config_free(config);
		return ret;
	}

	pr_info("Successfully parsed instance '%s': %zu bytes memory, %d CPUs, %d PCI devices, %d platform devices\n",
		instance_name, config->memory_size,
		mk_cpu_set_count(config->cpus), config->pci_device_count,
		config->platform_device_count);
	return 0;
}

/**
 * Configuration validation
 */
int mk_dt_validate(const struct mk_dt_config *config)
{
	int ret;

	if (!config) {
		pr_err("NULL configuration\n");
		return -EINVAL;
	}

	if (config->version != MK_DT_CONFIG_CURRENT) {
		pr_err("Unsupported configuration version: %u\n", config->version);
		return -ENOTSUPP;
	}

	/* Validate memory regions */
	ret = mk_dt_validate_memory(config);
	if (ret)
		return ret;

	/* Validate CPU resources */
	ret = mk_dt_validate_cpus(config);
	if (ret)
		return ret;

	return 0;
}

/**
 * Memory region validation
 */
static int mk_dt_validate_memory(const struct mk_dt_config *config)
{
	size_t pool_size = mk_pool_total_bytes();

	if (!pool_size && config->memory_size > 0) {
		pr_err("No multikernel pool available for memory allocation\n");
		return -ENODEV;
	}

	/* Validate memory size */
	if (config->memory_size > 0) {
		/* Basic sanity checks */
		if (config->memory_size < PAGE_SIZE) {
			pr_err("Memory size too small: %zu bytes\n", config->memory_size);
			return -EINVAL;
		}

		if (config->memory_size > SZ_1G) {
			pr_warn("Large memory size requested: %zu bytes\n", config->memory_size);
		}

		if (config->memory_size > pool_size) {
			pr_err("Requested memory size %zu bytes exceeds pool size %zu bytes\n",
			       config->memory_size, pool_size);
			return -ERANGE;
		}
	}

	return 0;
}

/**
 * CPU resource validation
 */
static int mk_dt_validate_cpus(const struct mk_dt_config *config)
{
	mk_phys_cpu_t phys_cpu_id;
	unsigned int i;
	int logical_cpu;

	/* Skip validation if CPU assignment is not available or empty */
	if (mk_cpu_set_empty(config->cpus))
		return 0;

	/* Check that all physical CPU IDs can be found in present CPUs */
	mk_cpu_set_for_each(i, phys_cpu_id, config->cpus) {
		logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);
		if (logical_cpu < 0) {
			pr_err("Physical CPU ID %llu not found in present CPUs\n",
			       phys_cpu_id);
			return -EINVAL;
		}

		if (!cpu_online(logical_cpu)) {
			pr_warn("CPU with physical ID %llu (logical CPU %d) is not online, multikernel may fail to start\n",
				phys_cpu_id, logical_cpu);
		}
	}

	/* Check for reasonable CPU count */
	if (mk_cpu_set_count(config->cpus) > num_online_cpus()) {
		pr_warn("Requested %u CPUs but only %d are online\n",
			mk_cpu_set_count(config->cpus), num_online_cpus());
	}

	if (mk_cpu_set_contains(config->cpus, 0))
		pr_warn("Physical CPU ID 0 (boot CPU) assigned to multikernel instance - this may affect system stability\n");

	return 0;
}

/**
 * Resource availability checking
 */
bool mk_dt_resources_available(const struct mk_dt_config *config)
{
	size_t pool_size;

	if (!config)
		return false;

	pool_size = mk_pool_total_bytes();
	if (!pool_size && config->memory_size > 0) {
		pr_debug("No multikernel pool available\n");
		return false;
	}

	/* Check if requested memory size is available */
	if (config->memory_size > pool_size) {
		pr_debug("Pool too small: need %zu, have %zu\n",
			 config->memory_size, pool_size);
		return false;
	}

	/* Check CPU availability - config->cpus contains physical CPU IDs */
	if (!mk_cpu_set_empty(config->cpus)) {
		mk_phys_cpu_t phys_cpu_id;
		unsigned int i;

		mk_cpu_set_for_each(i, phys_cpu_id, config->cpus) {
			if (arch_cpu_from_physical_id(phys_cpu_id) < 0) {
				pr_debug("Physical CPU ID %llu is not present\n",
					 phys_cpu_id);
				return false;
			}
		}
	}

	/* TODO: More sophisticated checking:
	 * - Check for fragmentation
	 * - Honor specific start address requests
	 * - Check for conflicts with existing allocations
	 * - Check for CPU conflicts with other instances
	 */

	return true;
}

/**
 * Property size helper
 */
int mk_dt_get_property_size(const void *dtb_data, size_t dtb_size,
			    const char *property)
{
	const void *fdt = dtb_data;
	int chosen_node;
	const void *prop;
	int len;

	if (!dtb_data || !property)
		return -EINVAL;

	if (fdt_check_header(fdt))
		return -EINVAL;

	chosen_node = fdt_path_offset(fdt, "/chosen");
	if (chosen_node < 0)
		return -ENOENT;

	prop = fdt_getprop(fdt, chosen_node, property, &len);
	if (!prop)
		return -ENOENT;

	return len;
}

/**
 * Debug and information functions
 */
void mk_dt_print_config(const struct mk_dt_config *config)
{
	struct mk_pci_device *pci_dev;
	struct mk_platform_device *plat_dev;

	if (!config) {
		pr_info("Multikernel DT config: (null)\n");
		return;
	}

	pr_info("Multikernel DT config (version %u):\n", config->version);

	if (config->memory_size > 0) {
		pr_info("  Memory size: %zu bytes (%zu MB)\n",
			config->memory_size, config->memory_size >> 20);
	} else {
		pr_info("  Memory size: none specified\n");
	}

	if (config->cpus) {
		if (mk_cpu_set_empty(config->cpus)) {
			pr_info("  CPU assignment: none specified\n");
		} else {
			char buf[256];

			mk_cpu_set_format(buf, sizeof(buf), config->cpus);
			pr_info("  CPU assignment: %s (%u CPUs)\n",
				buf, mk_cpu_set_count(config->cpus));
		}
	} else {
		pr_info("  CPU assignment: unavailable (allocation failed)\n");
	}

	if (config->pci_devices_valid) {
		if (config->pci_device_count == 0) {
			pr_info("  PCI devices: none specified\n");
		} else {
			pr_info("  PCI devices: %d device(s)\n", config->pci_device_count);
			list_for_each_entry(pci_dev, &config->pci_devices, list) {
				pr_info("    - %04x:%04x@%04x:%02x:%02x.%x\n",
					pci_dev->vendor, pci_dev->device,
					pci_dev->domain, pci_dev->bus,
					pci_dev->slot, pci_dev->func);
			}
		}
	} else {
		pr_info("  PCI devices: unavailable\n");
	}

	if (config->platform_devices_valid) {
		if (config->platform_device_count == 0) {
			pr_info("  Platform devices: none specified\n");
		} else {
			pr_info("  Platform devices: %d device(s)\n", config->platform_device_count);
			list_for_each_entry(plat_dev, &config->platform_devices, list) {
				pr_info("    - name='%s' hid='%s'\n",
					plat_dev->name[0] ? plat_dev->name : "(none)",
					plat_dev->hid[0] ? plat_dev->hid : "(none)");
			}
		}
	} else {
		pr_info("  Platform devices: unavailable\n");
	}

	pr_info("  DTB: %zu bytes\n", config->dtb_size);
}

#define MK_DT_FDT_MIN_SIZE	SZ_4K
#define MK_DT_FDT_MAX_SIZE	SZ_64K

static int mk_dt_emit_cpu_prop(void *fdt, const char *name,
			       const struct mk_cpu_set *set)
{
	unsigned int idx, count = mk_cpu_set_count(set);
	mk_phys_cpu_t phys_cpu_id;
	fdt64_t *array;
	int ret;

	if (!count)
		return 0;

	array = kmalloc_array(count, sizeof(*array), GFP_KERNEL);
	if (!array)
		return -ENOMEM;

	mk_cpu_set_for_each(idx, phys_cpu_id, set)
		array[idx] = cpu_to_fdt64(phys_cpu_id);

	ret = fdt_property(fdt, name, array, count * sizeof(*array));
	kfree(array);
	return ret;
}

/**
 * mk_dt_emit_pool_members() - Emit every CPU the pool owns
 *
 * A CPU lent to an instance is still a pool member, so the set is the
 * union of the free CPUs and the ones the instances hold.
 */
static int mk_dt_emit_pool_members(void *fdt)
{
	struct mk_instance *instance;
	struct mk_cpu_set *members;
	mk_phys_cpu_t phys_cpu_id;
	unsigned int i;
	int ret;

	members = mk_cpu_set_alloc();
	if (!members)
		return -ENOMEM;

	/*
	 * The root device tree is only generated from kernfs reads, which
	 * hold no instance lock; instance creation generates a device tree
	 * for the new instance, never for the root. mk_cpu_pool itself is
	 * mutated under no lock, so a concurrent move can still make this
	 * snapshot stale.
	 */
	lockdep_assert_not_held(&mk_instance_mutex);

	mutex_lock(&mk_instance_mutex);
	ret = mk_cpu_set_copy(members, mk_cpu_pool);
	list_for_each_entry(instance, &mk_instance_list, list) {
		if (ret)
			break;
		if (instance == root_instance)
			continue;
		mk_cpu_set_for_each(i, phys_cpu_id, instance->cpus) {
			ret = mk_cpu_set_add(members, phys_cpu_id);
			if (ret)
				break;
		}
	}
	mutex_unlock(&mk_instance_mutex);

	if (!ret)
		ret = mk_dt_emit_cpu_prop(fdt, "cpus", members);

	mk_cpu_set_free(members);
	return ret;
}

/* Runs under the pool mutex, so it only writes into the caller's buffer */
static int mk_dt_emit_pool_chunk(struct mk_pool_chunk *chunk, void *data)
{
	u64 base = chunk->res.start;
	u64 size = resource_size(&chunk->res);
	void *fdt = data;
	char name[32];
	fdt64_t reg[2];
	int ret;

	snprintf(name, sizeof(name), "memory@%llx", base);
	reg[0] = cpu_to_fdt64(base);
	reg[1] = cpu_to_fdt64(size);

	ret = fdt_begin_node(fdt, name);
	if (!ret)
		ret = fdt_property_string(fdt, "device_type", "memory");
	if (!ret)
		ret = fdt_property(fdt, "reg", reg, sizeof(reg));
	if (!ret)
		ret = fdt_property_u32(fdt, "numa-node-id", chunk->node);
	if (!ret)
		ret = fdt_end_node(fdt);

	return ret;
}

static int mk_dt_emit_instance_memory(struct mk_instance *instance, void *fdt)
{
	struct mk_memory_region *region;
	u64 total_size = 0;
	u64 base_addr = 0;
	bool first = true;
	int ret;

	list_for_each_entry(region, &instance->memory_regions, list) {
		if (first) {
			base_addr = region->res.start;
			first = false;
		}
		total_size += resource_size(&region->res);
	}

	if (!total_size)
		return 0;

	ret = fdt_property_u64(fdt, "memory-base", base_addr);
	if (ret)
		return ret;

	return fdt_property_u64(fdt, "memory-bytes", total_size);
}

static int mk_dt_emit_devices(struct mk_instance *instance, void *fdt)
{
	struct mk_platform_device *plat_dev;
	struct mk_pci_device *pci_dev;
	bool has_pci, has_platform;
	int ret;

	has_pci = instance->pci_devices_valid && instance->pci_device_count > 0;
	has_platform = instance->platform_devices_valid &&
		       instance->platform_device_count > 0;
	if (!has_pci && !has_platform)
		return 0;

	ret = fdt_begin_node(fdt, "devices");
	if (ret)
		return ret;

	if (has_pci) {
		list_for_each_entry(pci_dev, &instance->pci_devices, list) {
			char pci_id_str[32];
			fdt64_t resources[MK_PCI_RESOURCE_COUNT * 3];
			struct pci_dev *live_dev = NULL;
			unsigned int devfn;
			int i;

			if (!pci_dev->resources_valid) {
				devfn = PCI_DEVFN(pci_dev->slot, pci_dev->func);
				live_dev = pci_get_domain_bus_and_slot(pci_dev->domain,
								       pci_dev->bus, devfn);
				if (!live_dev) {
					pr_err("PCI device %04x:%02x:%02x.%x disappeared before resource snapshot\n",
					       pci_dev->domain, pci_dev->bus,
					       pci_dev->slot, pci_dev->func);
					return -ENODEV;
				}
			}
			for (i = 0; i < MK_PCI_RESOURCE_COUNT; i++) {
				u64 start, end, flags;

				if (live_dev) {
					start = pci_resource_start(live_dev, i);
					end = pci_resource_end(live_dev, i);
					flags = pci_resource_flags(live_dev, i);
				} else {
					start = pci_dev->resources[i].start;
					end = pci_dev->resources[i].end;
					flags = pci_dev->resources[i].flags;
				}
				resources[i * 3] = cpu_to_fdt64(start);
				resources[i * 3 + 1] = cpu_to_fdt64(end);
				resources[i * 3 + 2] = cpu_to_fdt64(flags);
			}
			if (live_dev)
				pci_dev_put(live_dev);

			snprintf(pci_id_str, sizeof(pci_id_str),
				 "%04x:%02x:%02x.%x", pci_dev->domain,
				 pci_dev->bus, pci_dev->slot, pci_dev->func);

			ret = fdt_begin_node(fdt, pci_dev->name[0] ?
					     pci_dev->name : "unnamed_pci");
			if (!ret)
				ret = fdt_property_string(fdt, "device-type",
							  "pci");
			if (!ret)
				ret = fdt_property_string(fdt, "pci-id",
							  pci_id_str);
			if (!ret)
				ret = fdt_property_u32(fdt, "vendor-id",
						       pci_dev->vendor);
			if (!ret)
				ret = fdt_property_u32(fdt, "device-id",
						       pci_dev->device);
			if (!ret)
				ret = fdt_property(fdt, "bar-resources", resources,
						   sizeof(resources));
			if (!ret)
				ret = fdt_end_node(fdt);
			if (ret)
				return ret;
		}
	}

	if (has_platform) {
		list_for_each_entry(plat_dev, &instance->platform_devices, list) {
			ret = fdt_begin_node(fdt, plat_dev->name);
			if (!ret)
				ret = fdt_property_string(fdt, "device-type",
							  "platform");
			if (!ret && plat_dev->name[0])
				ret = fdt_property_string(fdt, "device-name",
							  plat_dev->name);
			if (!ret)
				ret = fdt_end_node(fdt);
			if (ret)
				return ret;
		}
	}

	return fdt_end_node(fdt);
}

/**
 * mk_dt_emit_instance() - Write one instance device tree into @fdt
 * @instance: Instance to describe
 * @fdt: Buffer to write the sequential-write FDT into
 * @size: Size of @fdt
 *
 * The root device tree of a kernel that manages a pool describes the
 * pool itself: its CPU members, the free subset, and one standard
 * memory node per chunk. Sequential writes demand that every /resources
 * property precede its first child node.
 *
 * Returns: 0 on success, a libfdt error (-FDT_ERR_NOSPACE for a buffer
 * that is too small) or a negative error code on failure.
 */
static int mk_dt_emit_instance(struct mk_instance *instance, void *fdt,
			       size_t size)
{
	bool pool = instance == root_instance && mk_cpu_pool;
	int ret;

	ret = fdt_create(fdt, size);
	if (!ret)
		ret = fdt_finish_reservemap(fdt);
	if (!ret)
		ret = fdt_begin_node(fdt, instance->name);
	if (!ret)
		ret = fdt_property_string(fdt, "compatible", "multikernel-v1");
	if (!ret)
		ret = fdt_property_u32(fdt, "id", instance->id);
	if (!ret)
		ret = fdt_begin_node(fdt, "resources");
	if (ret)
		return ret;

	if (pool) {
		ret = mk_dt_emit_pool_members(fdt);
		if (!ret)
			ret = mk_dt_emit_cpu_prop(fdt, "cpus-available",
						  mk_cpu_pool);
	} else {
		ret = mk_dt_emit_instance_memory(instance, fdt);
		if (!ret)
			ret = mk_dt_emit_cpu_prop(fdt, "cpus", instance->cpus);
	}
	if (ret)
		return ret;

	if (pool) {
		ret = mk_pool_for_each_chunk(mk_dt_emit_pool_chunk, fdt);
		if (ret)
			return ret;
	}

	ret = mk_dt_emit_devices(instance, fdt);
	if (!ret)
		ret = fdt_end_node(fdt);	/* /resources */
	if (!ret)
		ret = fdt_end_node(fdt);	/* root */
	if (!ret)
		ret = fdt_finish(fdt);

	return ret;
}

/**
 * mk_dt_generate_instance_dtb() - Generate instance DTB from kernel data structures
 * @instance: Instance with transferred resources (CPUs, memory, devices)
 * @out_dtb: Output pointer for generated DTB (caller must kfree)
 * @out_size: Output size of generated DTB
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_dt_generate_instance_dtb(struct mk_instance *instance,
				 void **out_dtb, size_t *out_size)
{
	size_t fdt_size = MK_DT_FDT_MIN_SIZE;
	void *fdt;
	int ret;

	if (!instance || !out_dtb || !out_size)
		return -EINVAL;

	if (!instance->name)
		return -EINVAL;

	for (;;) {
		fdt = kmalloc(fdt_size, GFP_KERNEL);
		if (!fdt)
			return -ENOMEM;

		ret = mk_dt_emit_instance(instance, fdt, fdt_size);
		if (!ret)
			break;

		kfree(fdt);

		if (ret != -FDT_ERR_NOSPACE || fdt_size >= MK_DT_FDT_MAX_SIZE) {
			pr_err("Failed to generate DTB for '%s': %d\n",
			       instance->name, ret);
			return ret;
		}

		fdt_size *= 2;
	}

	*out_dtb = fdt;
	*out_size = fdt_totalsize(fdt);

	pr_info("Generated instance DTB for '%s' (ID %d): %zu bytes\n",
		instance->name, instance->id, *out_size);
	return 0;
}
