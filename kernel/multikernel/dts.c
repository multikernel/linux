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
#include <linux/sizes.h>
#include <linux/pci.h>
#include <linux/cpumask.h>
#if defined(CONFIG_X86) && defined(CONFIG_PCI_MMCONFIG)
#include <asm/pci_x86.h>
#endif
#include <linux/numa.h>
#include <linux/multikernel.h>

#include "internal.h"

/**
 * mk_dt_node_alias() - Find the /aliases entry naming a node
 * @fdt: Device tree blob
 * @node: Offset of the node
 *
 * Returns: the alias name, valid as long as @fdt is, or NULL if none
 */
const char *mk_dt_node_alias(const void *fdt, int node)
{
	int aliases, prop;

	aliases = fdt_path_offset(fdt, "/aliases");
	if (aliases < 0)
		return NULL;

	fdt_for_each_property_offset(prop, fdt, aliases) {
		const char *name, *path;

		path = fdt_getprop_by_offset(fdt, prop, &name, NULL);
		if (path && path[0] == '/' && fdt_path_offset(fdt, path) == node)
			return name;
	}

	return NULL;
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

	config->memory_size = 0;
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
static int mk_dt_pci_node_path(const struct mk_pci_device *dev, char *buf,
			       size_t size);
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

static int mk_dt_add_pci_device(const void *source_fdt, int dev_node,
				struct mk_dt_config *config,
				const char *device_name, unsigned int domain,
				unsigned int bus, unsigned int slot,
				unsigned int func)
{
	const fdt32_t *vendor_prop, *device_prop;
	struct mk_pci_device *pci_dev;
	const char *node_name, *alias;
	int len;

	node_name = fdt_get_name(source_fdt, dev_node, NULL);

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

	pci_dev = kzalloc(sizeof(*pci_dev), GFP_KERNEL);
	if (!pci_dev) {
		pr_err("Failed to allocate memory for PCI device\n");
		return -ENOMEM;
	}

	pci_dev->vendor = (u16)fdt32_to_cpu(*vendor_prop);
	pci_dev->device = (u16)fdt32_to_cpu(*device_prop);
	pci_dev->domain = (u16)domain;
	pci_dev->bus = (u8)bus;
	pci_dev->slot = (u8)slot;
	pci_dev->func = (u8)func;
	alias = mk_dt_node_alias(source_fdt, dev_node);
	if (alias)
		strscpy(pci_dev->alias, alias, sizeof(pci_dev->alias));

	list_add_tail(&pci_dev->list, &config->pci_devices);
	config->pci_device_count++;

	pr_info("Added PCI device '%s': %04x:%04x@%04x:%02x:%02x.%x\n",
		device_name, pci_dev->vendor, pci_dev->device,
		pci_dev->domain, pci_dev->bus, pci_dev->slot, pci_dev->func);

	return 0;
}

static int mk_dt_parse_single_pci_device(const void *source_fdt, int dev_node,
					 struct mk_dt_config *config,
					 const char *device_name)
{
	unsigned int domain, bus, slot, func;
	const char *pci_id_str;
	int len;

	pci_id_str = fdt_getprop(source_fdt, dev_node, "pci-id", &len);
	if (!pci_id_str) {
		pr_err("No pci-id property in device '%s'\n", device_name);
		return -EINVAL;
	}

	if (sscanf(pci_id_str, "%x:%x:%x.%x", &domain, &bus, &slot, &func) != 4) {
		pr_err("Invalid pci-id format: '%s' (expected domain:bus:slot.func)\n",
		       pci_id_str);
		return -EINVAL;
	}

	return mk_dt_add_pci_device(source_fdt, dev_node, config, device_name,
				    domain, bus, slot, func);
}

/*
 * The devices below a PCI bus node in the tree this kernel was given:
 * a leaf carries vendor-id, a bridge is recursed into. The unit address
 * in reg names the bus, device and function.
 */
static int mk_dt_parse_pci_bus(const void *fdt, int node, unsigned int domain,
			       struct mk_dt_config *config)
{
	int child, len, ret;

	fdt_for_each_subnode(child, fdt, node) {
		const fdt32_t *reg = fdt_getprop(fdt, child, "reg", &len);
		u32 hi;

		if (!reg || len < (int)sizeof(*reg))
			continue;

		if (!fdt_getprop(fdt, child, "vendor-id", NULL)) {
			ret = mk_dt_parse_pci_bus(fdt, child, domain, config);
			if (ret)
				return ret;
			continue;
		}

		hi = fdt32_to_cpu(reg[0]);
		ret = mk_dt_add_pci_device(fdt, child, config,
					   fdt_get_name(fdt, child, NULL),
					   domain, (hi >> 16) & 0xff,
					   PCI_SLOT((hi >> 8) & 0xff),
					   PCI_FUNC((hi >> 8) & 0xff));
		if (ret)
			return ret;
	}

	return 0;
}

static int mk_dt_parse_pci_tree(const void *fdt, struct mk_dt_config *config)
{
	int node, len, ret;

	if (!config->pci_devices_valid)
		return 0;

	fdt_for_each_subnode(node, fdt, 0) {
		const char *compat = fdt_getprop(fdt, node, "compatible", NULL);
		const fdt32_t *prop;
		unsigned int domain = 0;

		if (!compat || strcmp(compat, "multikernel,pci-host-bridge"))
			continue;

		prop = fdt_getprop(fdt, node, "linux,pci-domain", &len);
		if (prop && len == sizeof(fdt32_t))
			domain = fdt32_to_cpu(*prop);

		ret = mk_dt_parse_pci_bus(fdt, node, domain, config);
		if (ret)
			return ret;
	}

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

/*
 * An instance's devices are the child nodes of resources/devices, each
 * described in full. A device-names string list naming nodes of the
 * baseline was resolved against a copy of that baseline taken at init,
 * which never learned of devices pooled later; an overlay hands devices
 * to an instance with device-add by PCI address instead.
 */
static int mk_dt_parse_devices(const void *fdt, int resources_node,
			       struct mk_dt_config *config)
{
	if (fdt_getprop(fdt, resources_node, "device-names", NULL)) {
		pr_err("device-names is not supported; assign devices with device-add\n");
		return -EINVAL;
	}

	return mk_dt_parse_embedded_devices(fdt, resources_node, config);
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
	if (!ret)
		ret = mk_dt_parse_pci_tree(fdt, config);
	if (ret) {
		pr_err("Failed to parse device resources: %d\n", ret);
		mk_dt_config_free(config);
		return ret;
	}

	pr_info("Successfully parsed multikernel device tree with %zu bytes memory, %u CPUs, %d PCI devices, and %d platform devices\n",
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

	pr_info("Successfully parsed instance '%s': %zu bytes memory, %u CPUs, %d PCI devices, %d platform devices\n",
		instance_name, config->memory_size,
		mk_cpu_set_count(config->cpus),
		config->pci_device_count, config->platform_device_count);
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
}

#define MK_DT_FDT_MIN_SIZE	SZ_4K
#define MK_DT_FDT_MAX_SIZE	MK_MANIFEST_SIZE

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
	 * for the new instance, never for the root. The pool set itself is
	 * mutated under no lock, so a concurrent move can still make this
	 * snapshot stale.
	 */
	lockdep_assert_not_held(&mk_instance_mutex);

	mutex_lock(&mk_instance_mutex);
	ret = mk_cpu_set_copy(members, mk_pool->cpus);
	list_for_each_entry(instance, &mk_instance_list, list) {
		if (ret)
			break;
		if (instance == mk_self)
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
	int ret;

	if (!instance->platform_devices_valid ||
	    instance->platform_device_count == 0)
		return 0;

	ret = fdt_begin_node(fdt, "devices");
	if (ret)
		return ret;

	list_for_each_entry(plat_dev, &instance->platform_devices, list) {
		ret = fdt_begin_node(fdt, plat_dev->name);
		if (!ret)
			ret = fdt_property_string(fdt, "device-type", "platform");
		if (!ret && plat_dev->name[0])
			ret = fdt_property_string(fdt, "device-name",
						  plat_dev->name);
		if (!ret && plat_dev->hid[0])
			ret = fdt_property_string(fdt, "acpi-hid", plat_dev->hid);
		if (!ret)
			ret = fdt_end_node(fdt);
		if (ret)
			return ret;
	}

	return fdt_end_node(fdt);
}

static int mk_dt_emit_aliases(struct mk_instance *instance, void *fdt)
{
	struct mk_pci_device *pci_dev;
	bool open = false;
	int ret;

	if (!instance->pci_devices_valid)
		return 0;

	list_for_each_entry(pci_dev, &instance->pci_devices, list) {
		char path[128];

		if (!pci_dev->alias[0])
			continue;

		if (!open) {
			ret = fdt_begin_node(fdt, "aliases");
			if (ret)
				return ret;
			open = true;
		}

		if (mk_dt_pci_node_path(pci_dev, path, sizeof(path)))
			continue;
		ret = fdt_property_string(fdt, pci_dev->alias, path);
		if (ret)
			return ret;
	}

	return open ? fdt_end_node(fdt) : 0;
}

#ifdef CONFIG_PCI
#define MK_PCI_BRIDGE_MAX_WINDOWS 16

/* phys.hi of a PCI unit address: bbbbbbbb dddddfff 00000000 */
static u32 mk_dt_pci_phys_hi(u8 bus, u8 devfn)
{
	return (u32)bus << 16 | (u32)devfn << 8;
}

/*
 * The path of a device's node in the tree this kernel generates: the
 * host bridge of its root bus, then one node per bridge on the way
 * down, as pci_set_of_node() expects to find a device under its bus.
 */
static int mk_dt_pci_node_path(const struct mk_pci_device *dev, char *buf,
			       size_t size)
{
	struct pci_bus *bus = pci_find_bus(dev->domain, dev->bus);
	u8 devfns[8];
	int depth = 0, pos, i;

	if (!bus)
		return -ENODEV;

	while (bus->parent) {
		if (depth == ARRAY_SIZE(devfns))
			return -E2BIG;
		devfns[depth++] = bus->self->devfn;
		bus = bus->parent;
	}

	pos = scnprintf(buf, size, "/pci@%llx",
			(unsigned long long)bus->busn_res.start);
	for (i = depth - 1; i >= 0; i--)
		pos += scnprintf(buf + pos, size - pos, "/pci@%x,%x",
				 PCI_SLOT(devfns[i]), PCI_FUNC(devfns[i]));
	scnprintf(buf + pos, size - pos, "/pci@%x,%x", dev->slot, dev->func);
	return 0;
}

static int mk_dt_emit_pci_reg(void *fdt, u8 bus, u8 devfn)
{
	fdt32_t reg[5] = { cpu_to_fdt32(mk_dt_pci_phys_hi(bus, devfn)) };

	return fdt_property(fdt, "reg", reg, sizeof(reg));
}

/* The bus directly below @parent on the way to bus @busnr, or NULL */
static struct pci_bus *mk_dt_bus_toward(struct pci_bus *parent, u16 domain,
					u8 busnr)
{
	struct pci_bus *bus = pci_find_bus(domain, busnr);

	while (bus && bus->parent != parent)
		bus = bus->parent;
	return bus;
}

/*
 * Describe what @instance owns below @bus: its devices on this bus as
 * leaves, and one bridge node, recursed into, per child bus that leads
 * to a device further down. The topology comes from the bus structures,
 * which outlive a leaf device that has been detached from this kernel.
 */
static int mk_dt_emit_pci_bus(struct mk_instance *instance,
			      struct pci_bus *bus, void *fdt)
{
	struct pci_bus *children[16];
	struct mk_pci_device *dev;
	u16 domain = pci_domain_nr(bus);
	char name[16];
	int nr = 0, i, ret;

	list_for_each_entry(dev, &instance->pci_devices, list) {
		if (dev->domain != domain || dev->bus != bus->number)
			continue;

		snprintf(name, sizeof(name), "pci@%x,%x", dev->slot, dev->func);
		ret = fdt_begin_node(fdt, name);
		if (!ret)
			ret = mk_dt_emit_pci_reg(fdt, dev->bus,
						 PCI_DEVFN(dev->slot, dev->func));
		if (!ret)
			ret = fdt_property_u32(fdt, "vendor-id", dev->vendor);
		if (!ret)
			ret = fdt_property_u32(fdt, "device-id", dev->device);
		if (!ret)
			ret = fdt_end_node(fdt);
		if (ret)
			return ret;
	}

	list_for_each_entry(dev, &instance->pci_devices, list) {
		struct pci_bus *child;
		fdt32_t bus_range[2];

		if (dev->domain != domain || dev->bus == bus->number)
			continue;

		child = mk_dt_bus_toward(bus, domain, dev->bus);
		if (!child || !child->self)
			continue;
		for (i = 0; i < nr; i++)
			if (children[i] == child)
				break;
		if (i < nr)
			continue;
		if (nr == ARRAY_SIZE(children)) {
			pr_warn("Bus %04x:%02x has more than %zu child buses in use, rest not described\n",
				domain, bus->number, ARRAY_SIZE(children));
			break;
		}
		children[nr++] = child;

		snprintf(name, sizeof(name), "pci@%x,%x",
			 PCI_SLOT(child->self->devfn), PCI_FUNC(child->self->devfn));
		bus_range[0] = cpu_to_fdt32(child->busn_res.start);
		bus_range[1] = cpu_to_fdt32(child->busn_res.end);
		ret = fdt_begin_node(fdt, name);
		if (!ret)
			ret = fdt_property_string(fdt, "device_type", "pci");
		if (!ret)
			ret = fdt_property_u32(fdt, "#address-cells", 3);
		if (!ret)
			ret = fdt_property_u32(fdt, "#size-cells", 2);
		if (!ret)
			ret = mk_dt_emit_pci_reg(fdt, bus->number,
						 child->self->devfn);
		if (!ret)
			ret = fdt_property(fdt, "bus-range", bus_range,
					   sizeof(bus_range));
		if (!ret)
			ret = mk_dt_emit_pci_bus(instance, child, fdt);
		if (!ret)
			ret = fdt_end_node(fdt);
		if (ret)
			return ret;
	}

	return 0;
}

static u32 mk_dt_window_flags(const struct resource *res)
{
	u32 hi;

	if (res->flags & IORESOURCE_IO)
		hi = 0x01000000;
	else if ((res->flags & IORESOURCE_MEM_64) || res->end > U32_MAX)
		hi = 0x03000000;
	else
		hi = 0x02000000;

	if (res->flags & IORESOURCE_PREFETCH)
		hi |= 0x40000000;

	return hi;
}

static struct pci_bus *mk_dt_root_bus_of(u32 domain, u32 busn)
{
	struct pci_bus *bus;

	list_for_each_entry(bus, &pci_root_buses, node) {
		if (pci_domain_nr(bus) == domain &&
		    bus->busn_res.start <= busn && busn <= bus->busn_res.end)
			return bus;
	}

	return NULL;
}

/*
 * The ECAM window covering the bridge's bus range, so a spawn kernel can
 * generate config cycles without the MCFG table only ACPI provides.
 * This kernel's own window came either from its ACPI or from the tree
 * that spawned it, so the description propagates down spawn chains.
 */
static u64 mk_dt_bridge_ecam(struct pci_bus *root, u64 *size)
{
#if defined(CONFIG_X86) && defined(CONFIG_PCI_MMCONFIG)
	struct pci_mmcfg_region *cfg;

	cfg = pci_mmconfig_lookup(pci_domain_nr(root), root->busn_res.start);
	if (!cfg || cfg->end_bus < root->busn_res.end)
		return 0;

	*size = (u64)(root->busn_res.end - root->busn_res.start + 1) << 20;
	return cfg->address + ((u64)root->busn_res.start << 20);
#else
	return 0;
#endif
}

static int mk_dt_emit_one_host_bridge(struct mk_instance *instance,
				      struct pci_bus *root, void *fdt)
{
	struct pci_host_bridge *bridge = pci_find_host_bridge(root);
	fdt32_t ranges[MK_PCI_BRIDGE_MAX_WINDOWS * 7];
	fdt32_t bus_range[2];
	struct resource_entry *entry;
	u64 ecam_base, ecam_size = 0;
	char name[16];
	int cells = 0;
	int ret;

	snprintf(name, sizeof(name), "pci@%llx",
		 (unsigned long long)root->busn_res.start);

	ret = fdt_begin_node(fdt, name);
	if (!ret)
		ret = fdt_property_string(fdt, "compatible",
					  "multikernel,pci-host-bridge");
	if (!ret)
		ret = fdt_property_string(fdt, "device_type", "pci");
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 3);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "linux,pci-domain",
				       pci_domain_nr(root));
	if (ret)
		return ret;

	bus_range[0] = cpu_to_fdt32(root->busn_res.start);
	bus_range[1] = cpu_to_fdt32(root->busn_res.end);
	ret = fdt_property(fdt, "bus-range", bus_range, sizeof(bus_range));
	if (ret)
		return ret;

	ecam_base = mk_dt_bridge_ecam(root, &ecam_size);
	if (ecam_base) {
		fdt32_t reg[4];

		reg[0] = cpu_to_fdt32(upper_32_bits(ecam_base));
		reg[1] = cpu_to_fdt32(lower_32_bits(ecam_base));
		reg[2] = cpu_to_fdt32(upper_32_bits(ecam_size));
		reg[3] = cpu_to_fdt32(lower_32_bits(ecam_size));
		ret = fdt_property(fdt, "reg", reg, sizeof(reg));
		if (ret)
			return ret;
	}

	resource_list_for_each_entry(entry, &bridge->windows) {
		const struct resource *res = entry->res;
		u64 pci_addr, size;

		if (resource_type(res) != IORESOURCE_IO &&
		    resource_type(res) != IORESOURCE_MEM)
			continue;

		if (cells + 7 > ARRAY_SIZE(ranges)) {
			pr_warn("Host bridge %s has more than %d windows, rest not described\n",
				name, MK_PCI_BRIDGE_MAX_WINDOWS);
			break;
		}

		pci_addr = res->start - entry->offset;
		size = resource_size(res);
		ranges[cells++] = cpu_to_fdt32(mk_dt_window_flags(res));
		ranges[cells++] = cpu_to_fdt32(upper_32_bits(pci_addr));
		ranges[cells++] = cpu_to_fdt32(lower_32_bits(pci_addr));
		ranges[cells++] = cpu_to_fdt32(upper_32_bits(res->start));
		ranges[cells++] = cpu_to_fdt32(lower_32_bits(res->start));
		ranges[cells++] = cpu_to_fdt32(upper_32_bits(size));
		ranges[cells++] = cpu_to_fdt32(lower_32_bits(size));
	}

	if (cells) {
		ret = fdt_property(fdt, "ranges", ranges,
				   cells * sizeof(fdt32_t));
		if (ret)
			return ret;
	}

	ret = mk_dt_emit_pci_bus(instance, root, fdt);
	if (ret)
		return ret;

	return fdt_end_node(fdt);
}

/*
 * mk_dt_emit_host_bridges() - Describe the root buses under an instance's devices
 *
 * A spawn kernel boots without ACPI, so nothing tells it where its PCI
 * root buses are or which windows they decode; this kernel knows both
 * exactly. One node per distinct root bus:
 *
 *   pci@4f {
 *       compatible = "multikernel,pci-host-bridge";
 *       device_type = "pci";
 *       #address-cells = <3>;
 *       #size-cells = <2>;
 *       linux,pci-domain = <0>;
 *       bus-range = <0x4f 0x50>;
 *       reg = <ecam.hi ecam.lo size.hi size.lo>;	(when known)
 *       ranges = <flags pci.hi pci.lo cpu.hi cpu.lo size.hi size.lo ...>;
 *       pci@2,7 {				a bridge on the way down
 *           device_type = "pci";
 *           #address-cells = <3>;
 *           #size-cells = <2>;
 *           reg = <phys.hi 0 0 0 0>;
 *           bus-range = <0x50 0x50>;
 *           pci@0,0 {				a device the instance owns
 *               reg = <phys.hi 0 0 0 0>;
 *               vendor-id = <0x1af4>;
 *               device-id = <0x1041>;
 *           };
 *       };
 *   };
 *
 * This is the devicetree PCI bus binding, with a device under the bus
 * it sits on, so the tree can be handed to the OF core as is and
 * pci_set_of_node() will find each device by its unit address.
 */
static int mk_dt_emit_host_bridges(struct mk_instance *instance, void *fdt)
{
	struct pci_bus *roots[8];
	struct mk_pci_device *pci_dev;
	int nr = 0, i, ret;

	if (!instance->pci_devices_valid)
		return 0;

	list_for_each_entry(pci_dev, &instance->pci_devices, list) {
		struct pci_bus *root;

		root = mk_dt_root_bus_of(pci_dev->domain, pci_dev->bus);
		if (!root) {
			pr_warn("No root bus covers %04x:%02x, device %04x:%02x:%02x.%x not reachable in the instance\n",
				pci_dev->domain, pci_dev->bus, pci_dev->domain,
				pci_dev->bus, pci_dev->slot, pci_dev->func);
			continue;
		}

		for (i = 0; i < nr; i++)
			if (roots[i] == root)
				break;
		if (i < nr)
			continue;
		if (nr == ARRAY_SIZE(roots)) {
			pr_warn("Instance %s spans more than %zu root buses, rest not described\n",
				instance->name, ARRAY_SIZE(roots));
			break;
		}
		roots[nr++] = root;
	}

	for (i = 0; i < nr; i++) {
		ret = mk_dt_emit_one_host_bridge(instance, roots[i], fdt);
		if (ret)
			return ret;
	}

	return 0;
}
#else /* !CONFIG_PCI */
static int mk_dt_pci_node_path(const struct mk_pci_device *dev, char *buf,
			       size_t size)
{
	return -ENODEV;
}

static int mk_dt_emit_host_bridges(struct mk_instance *instance, void *fdt)
{
	return 0;
}
#endif

#ifdef CONFIG_OF
static int mk_dt_emit_of_node(void *fdt, struct device_node *np)
{
	struct device_node *child;
	struct property *pp;
	int ret;

	ret = fdt_begin_node(fdt, np->full_name);
	if (ret)
		return ret;

	for_each_property_of_node(np, pp) {
		if (!strcmp(pp->name, "name"))
			continue;
		ret = fdt_property(fdt, pp->name, pp->value, pp->length);
		if (ret)
			return ret;
	}

	for_each_child_of_node(np, child) {
		if (!of_device_is_available(child))
			continue;
		ret = mk_dt_emit_of_node(fdt, child);
		if (ret) {
			of_node_put(child);
			return ret;
		}
	}

	return fdt_end_node(fdt);
}

/*
 * A spawn's devices are the nodes of its boot tree, with a lent device
 * marked reserved there, so the tree it serves is a projection of that
 * tree: its aliases and host bridges with the reserved devices left out.
 */
static int mk_dt_emit_own_devices(void *fdt)
{
	struct device_node *np;
	struct property *pp;
	int ret;

	if (of_aliases) {
		ret = fdt_begin_node(fdt, "aliases");
		if (ret)
			return ret;
		for_each_property_of_node(of_aliases, pp) {
			struct device_node *target;

			if (!strcmp(pp->name, "name") || !strcmp(pp->name, "phandle"))
				continue;
			target = of_find_node_by_path(pp->value);
			if (!target)
				continue;
			ret = of_device_is_available(target) ?
			      fdt_property(fdt, pp->name, pp->value, pp->length) : 0;
			of_node_put(target);
			if (ret)
				return ret;
		}
		ret = fdt_end_node(fdt);
		if (ret)
			return ret;
	}

	for_each_compatible_node(np, NULL, "multikernel,pci-host-bridge") {
		ret = mk_dt_emit_of_node(fdt, np);
		if (ret) {
			of_node_put(np);
			return ret;
		}
	}

	return 0;
}
#else
static int mk_dt_emit_own_devices(void *fdt)
{
	return 0;
}
#endif

/**
 * mk_dt_emit_tree() - Write one instance device tree into @fdt
 * @instance: Instance to describe
 * @fdt: Buffer to write the sequential-write FDT into
 * @size: Size of @fdt
 * @chosen: Writes the /chosen node's properties, or NULL for no /chosen
 * @data: Passed to @chosen
 *
 * The root device tree of a kernel that manages a pool describes the
 * pool itself: its CPU members, the free subset, and one standard
 * memory node per chunk. Sequential writes demand that every /resources
 * property precede its first child node.
 *
 * Returns: 0 on success, a libfdt error (-FDT_ERR_NOSPACE for a buffer
 * that is too small) or a negative error code on failure.
 */
static int mk_dt_emit_tree(struct mk_instance *instance, void *fdt,
			   size_t size, int (*chosen)(void *fdt, void *data),
			   void *data)
{
	bool pool = instance == mk_self && mk_pool;
	int ret;

	ret = fdt_create(fdt, size);
	if (!ret)
		ret = fdt_finish_reservemap(fdt);
	if (!ret)
		ret = fdt_begin_node(fdt, "");
	if (!ret)
		ret = fdt_property_string(fdt, "compatible", "multikernel-v1");
	if (!ret && instance->name[0])
		ret = fdt_property_string(fdt, "model", instance->name);
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 2);
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
						  mk_pool->cpus);
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
	if (!ret) {
		if (instance == mk_self && mk_manifest_phys()) {
			ret = mk_dt_emit_own_devices(fdt);
		} else {
			ret = mk_dt_emit_aliases(instance, fdt);
			if (!ret)
				ret = mk_dt_emit_host_bridges(instance, fdt);
		}
	}
	if (!ret && chosen) {
		ret = fdt_begin_node(fdt, "chosen");
		if (!ret)
			ret = chosen(fdt, data);
		if (!ret)
			ret = fdt_end_node(fdt);
	}
	if (!ret)
		ret = fdt_end_node(fdt);	/* root */
	if (!ret)
		ret = fdt_finish(fdt);

	return ret;
}

/* Write @node of @src, properties then subnodes, into the tree open on @fdt. */
static int mk_dt_copy_node(const void *src, int node, void *fdt)
{
	int prop, sub, ret;

	fdt_for_each_property_offset(prop, src, node) {
		const char *name;
		const void *val;
		int len;

		val = fdt_getprop_by_offset(src, prop, &name, &len);
		if (!val)
			return -EINVAL;
		ret = fdt_property(fdt, name, val, len);
		if (ret)
			return ret;
	}
	fdt_for_each_subnode(sub, src, node) {
		ret = fdt_begin_node(fdt, fdt_get_name(src, sub, NULL));
		if (!ret)
			ret = mk_dt_copy_node(src, sub, fdt);
		if (!ret)
			ret = fdt_end_node(fdt);
		if (ret)
			return ret;
	}
	return 0;
}

/* Keep @node of @src as a tree of its own, rooted at the node's contents. */
static int mk_dt_store_host_tree(const void *src, int node,
				 struct mk_instance *instance)
{
	size_t size = SZ_1K;
	void *fdt;
	int ret;

	for (;;) {
		fdt = kmalloc(size, GFP_KERNEL);
		if (!fdt)
			return -ENOMEM;
		ret = fdt_create(fdt, size);
		if (!ret)
			ret = fdt_finish_reservemap(fdt);
		if (!ret)
			ret = fdt_begin_node(fdt, "");
		if (!ret)
			ret = mk_dt_copy_node(src, node, fdt);
		if (!ret)
			ret = fdt_end_node(fdt);
		if (!ret)
			ret = fdt_finish(fdt);
		if (!ret)
			break;
		kfree(fdt);
		if (ret != -FDT_ERR_NOSPACE || size >= MK_HOST_TREE_MAX)
			return -EINVAL;
		size *= 2;
	}
	fdt_pack(fdt);

	kfree(instance->host_tree);
	instance->host_tree = fdt;
	instance->host_tree_len = fdt_totalsize(fdt);
	/* A backup that will take a core of us says so with this node. */
	instance->dumps_host = fdt_subnode_offset(fdt, 0, "vmcore") >= 0;
	return 0;
}

/*
 * The boot handoff user space asked for: a chosen node holding a
 * multikernel,host-tree subtree, which the spawn boots with under its
 * own /chosen.
 */
int mk_dt_parse_chosen(const void *fdt, int chosen_node,
		       struct mk_instance *instance)
{
	int node;

	if (fdt_first_property_offset(fdt, chosen_node) >= 0) {
		pr_err("Instance '%s': chosen carries properties; only a multikernel,host-tree node is accepted\n",
		       instance->name);
		return -EINVAL;
	}
	fdt_for_each_subnode(node, fdt, chosen_node) {
		const char *name = fdt_get_name(fdt, node, NULL);
		int ret;

		if (!name || strcmp(name, "multikernel,host-tree")) {
			pr_err("Instance '%s': unsupported chosen node '%s'\n",
			       instance->name, name ? name : "?");
			return -EINVAL;
		}
		ret = mk_dt_store_host_tree(fdt, node, instance);
		if (ret) {
			pr_err("Instance '%s': cannot keep multikernel,host-tree (limit %d bytes): %d\n",
			       instance->name, MK_HOST_TREE_MAX, ret);
			return ret;
		}
	}
	return 0;
}

/* The stored host tree, as the multikernel,host-tree node of an open /chosen. */
int mk_dt_emit_host_tree(void *fdt, const struct mk_instance *instance)
{
	int ret;

	ret = fdt_begin_node(fdt, "multikernel,host-tree");
	if (!ret)
		ret = mk_dt_copy_node(instance->host_tree, 0, fdt);
	if (!ret)
		ret = fdt_end_node(fdt);
	return ret;
}

static int mk_dt_emit_requested_chosen(void *fdt, void *data)
{
	return mk_dt_emit_host_tree(fdt, data);
}

static int mk_dt_emit_instance(struct mk_instance *instance, void *fdt,
			       size_t size)
{
	if (instance->host_tree)
		return mk_dt_emit_tree(instance, fdt, size,
				       mk_dt_emit_requested_chosen, instance);
	return mk_dt_emit_tree(instance, fdt, size, NULL, NULL);
}

/**
 * mk_dt_emit_boot_tree() - Write the tree a spawn of @instance boots from
 * @instance: Instance to describe
 * @fdt: Buffer to write into
 * @size: Size of @fdt
 * @chosen: Writes the boot-time handoff properties of /chosen
 * @data: Passed to @chosen
 *
 * The instance's device tree with a /chosen node, as a bootloader would
 * hand it to a kernel.
 *
 * Returns: 0 on success, a libfdt error (-FDT_ERR_NOSPACE for a buffer
 * that is too small) or a negative error code on failure.
 */
int mk_dt_emit_boot_tree(struct mk_instance *instance, void *fdt, size_t size,
			 int (*chosen)(void *fdt, void *data), void *data)
{
	return mk_dt_emit_tree(instance, fdt, size, chosen, data);
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
