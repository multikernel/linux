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
#include <asm/smp.h>
#include <linux/cpumask.h>
#include <linux/multikernel.h>

#include "internal.h"

/**
 * Configuration initialization and cleanup
 */
void mk_dt_config_init(struct mk_dt_config *config)
{
	memset(config, 0, sizeof(*config));
	config->version = MK_DT_CONFIG_CURRENT;
	config->memory_size = 0;

	config->cpus = kzalloc(BITS_TO_LONGS(NR_CPUS) * sizeof(unsigned long), GFP_KERNEL);
	if (!config->cpus)
		pr_warn("Failed to allocate CPU bitmap, CPU assignment disabled\n");
}

void mk_dt_config_free(struct mk_dt_config *config)
{
	if (!config)
		return;

	kfree(config->cpus);

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
 * CPU resource parsing
 */
static int mk_dt_parse_cpus(const void *fdt, int chosen_node,
			    struct mk_dt_config *config)
{
	const fdt32_t *prop;
	int len, i, cpu_count;

	if (!config->cpus) {
		pr_debug("CPU bitmap allocation failed, skipping CPU parsing\n");
		return 0;
	}

	/* Look for cpus property */
	prop = fdt_getprop(fdt, chosen_node, MK_DT_RESOURCE_CPUS, &len);
	if (!prop) {
		pr_debug("No %s property found\n", MK_DT_RESOURCE_CPUS);
		return 0; /* Not an error - property is optional */
	}

	if (len % 4 != 0) {
		pr_err("Invalid %s property length: %d (must be multiple of 4)\n",
		       MK_DT_RESOURCE_CPUS, len);
		return -EINVAL;
	}

	cpu_count = len / 4; /* Each CPU is a u32 value */
	if (cpu_count == 0) {
		pr_err("Empty CPU list in %s\n", MK_DT_RESOURCE_CPUS);
		return -EINVAL;
	}

	pr_debug("Parsing %d CPUs\n", cpu_count);

	bitmap_zero(config->cpus, NR_CPUS);

	for (i = 0; i < cpu_count; i++) {
		u32 phys_cpu_id = fdt32_to_cpu(prop[i]);

		if (phys_cpu_id >= NR_CPUS) {
			pr_err("Physical CPU ID %u exceeds NR_CPUS (%d) in %s\n",
			       phys_cpu_id, NR_CPUS, MK_DT_RESOURCE_CPUS);
			return -EINVAL;
		}

		set_bit(phys_cpu_id, config->cpus);
		pr_debug("Added physical CPU ID: %u\n", phys_cpu_id);
	}

	pr_info("Successfully parsed %d physical CPUs: %*pbl\n",
		cpu_count, NR_CPUS, config->cpus);
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

	pr_info("Successfully parsed multikernel device tree with %zu bytes memory, %d CPUs\n",
		config->memory_size, config->cpus ? bitmap_weight(config->cpus, NR_CPUS) : 0);
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

	pr_info("Successfully parsed instance '%s': %zu bytes memory, %d CPUs\n",
		instance_name, config->memory_size,
		config->cpus ? bitmap_weight(config->cpus, NR_CPUS) : 0);
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
	struct resource *pool_res;

	/* Get multikernel pool resource for validation */
	pool_res = multikernel_get_pool_resource();
	if (!pool_res && config->memory_size > 0) {
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

		/* Check if size fits within multikernel pool */
		if (pool_res) {
			resource_size_t pool_size = resource_size(pool_res);
			if (config->memory_size > pool_size) {
				pr_err("Requested memory size %zu bytes exceeds pool size %llu bytes\n",
				       config->memory_size, pool_size);
				return -ERANGE;
			}
		}
	}

	return 0;
}

/**
 * CPU resource validation
 */
static int mk_dt_validate_cpus(const struct mk_dt_config *config)
{
	int phys_cpu_id, logical_cpu;

	/* Skip validation if CPU assignment is not available or empty */
	if (!config->cpus || bitmap_empty(config->cpus, NR_CPUS))
		return 0;

	/* Check that all physical APIC IDs can be found in present CPUs */
	for_each_set_bit(phys_cpu_id, config->cpus, NR_CPUS) {
		logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);
		if (logical_cpu < 0) {
			pr_err("Physical APIC ID %d not found in present CPUs\n", phys_cpu_id);
			return -EINVAL;
		}

		if (!cpu_online(logical_cpu)) {
			pr_warn("CPU with physical APIC ID %d (logical CPU %d) is not online, multikernel may fail to start\n",
				phys_cpu_id, logical_cpu);
		}
	}

	/* Check for reasonable CPU count */
	if (bitmap_weight(config->cpus, NR_CPUS) > num_online_cpus()) {
		pr_warn("Requested %d CPUs but only %d are online\n",
			(int)bitmap_weight(config->cpus, NR_CPUS), num_online_cpus());
	}

	if (test_bit(0, config->cpus)) {
		pr_warn("Physical APIC ID 0 (boot CPU) assigned to multikernel instance - this may affect system stability\n");
	}

	return 0;
}

/**
 * Resource availability checking
 */
bool mk_dt_resources_available(const struct mk_dt_config *config)
{
	struct resource *pool_res;

	if (!config)
		return false;

	/* Check if multikernel pool is available */
	pool_res = multikernel_get_pool_resource();
	if (!pool_res) {
		pr_debug("No multikernel pool available\n");
		return false;
	}

	/* Check if requested memory size is available */
	if (config->memory_size > 0) {
		resource_size_t pool_size = resource_size(pool_res);
		if (pool_size < config->memory_size) {
			pr_debug("Pool too small: need %zu, have %llu\n",
				 config->memory_size, pool_size);
			return false;
		}
	}

	/* Check CPU availability - config->cpus contains physical APIC IDs */
	if (config->cpus && !bitmap_empty(config->cpus, NR_CPUS)) {
		int phys_cpu_id, logical_cpu;

		for_each_set_bit(phys_cpu_id, config->cpus, NR_CPUS) {
			logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);
			if (logical_cpu < 0) {
				pr_debug("Physical APIC ID %d is not present\n", phys_cpu_id);
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
		if (bitmap_empty(config->cpus, NR_CPUS)) {
			pr_info("  CPU assignment: none specified\n");
		} else {
			pr_info("  CPU assignment: %*pbl (%d CPUs)\n",
				NR_CPUS, config->cpus, (int)bitmap_weight(config->cpus, NR_CPUS));
		}
	} else {
		pr_info("  CPU assignment: unavailable (allocation failed)\n");
	}

	pr_info("  DTB: %zu bytes\n", config->dtb_size);
}

/**
 * mk_dt_generate_instance_dtb() - Generate a proper instance DTB from config
 * @name: Instance name
 * @id: Instance ID
 * @config: Configuration with parsed resources
 * @out_dtb: Output pointer for generated DTB (caller must kfree)
 * @out_size: Output size of generated DTB
 *
 * Generates a full device tree with /instances/<name>/resources structure
 * suitable for passing to spawn kernel via KHO.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_dt_generate_instance_dtb(const char *name, int id,
				 const struct mk_dt_config *config,
				 void **out_dtb, size_t *out_size)
{
	void *fdt;
	int ret;
	size_t fdt_size = 4096; /* Start with 4K, will grow if needed */

	if (!name || !config || !out_dtb || !out_size)
		return -EINVAL;

	fdt = kmalloc(fdt_size, GFP_KERNEL);
	if (!fdt)
		return -ENOMEM;

	ret = fdt_create(fdt, fdt_size);
	if (ret) {
		pr_err("Failed to create FDT: %d\n", ret);
		goto err_free;
	}

	ret = fdt_finish_reservemap(fdt);
	if (ret) {
		pr_err("Failed to finish reservemap: %d\n", ret);
		goto err_free;
	}

	/* Begin root node */
	ret = fdt_begin_node(fdt, "");
	if (ret) goto err_free;

	ret = fdt_property_string(fdt, "compatible", "multikernel-v1");
	if (ret) goto err_free;

	/* Create /instances node */
	ret = fdt_begin_node(fdt, "instances");
	if (ret) goto err_free;

	/* Create /instances/<name> node */
	ret = fdt_begin_node(fdt, name);
	if (ret) goto err_free;

	ret = fdt_property_u32(fdt, "id", id);
	if (ret) goto err_free;

	ret = fdt_property_string(fdt, "compatible", "multikernel-v1");
	if (ret) goto err_free;

	/* Create /instances/<name>/resources node */
	ret = fdt_begin_node(fdt, "resources");
	if (ret) goto err_free;

	if (config->memory_size > 0) {
		ret = fdt_property_u64(fdt, "memory-bytes", config->memory_size);
		if (ret) goto err_free;
	}

	if (config->cpus && !bitmap_empty(config->cpus, NR_CPUS)) {
		int cpu;
		u32 *cpu_array;
		int cpu_count = bitmap_weight(config->cpus, NR_CPUS);
		int idx = 0;

		cpu_array = kmalloc(cpu_count * sizeof(u32), GFP_KERNEL);
		if (!cpu_array) {
			ret = -ENOMEM;
			goto err_free;
		}

		for_each_set_bit(cpu, config->cpus, NR_CPUS) {
			cpu_array[idx++] = cpu_to_fdt32(cpu);
		}

		ret = fdt_property(fdt, "cpus", cpu_array, cpu_count * sizeof(u32));
		kfree(cpu_array);
		if (ret) goto err_free;
	}

	/* End resources node */
	ret = fdt_end_node(fdt);
	if (ret) goto err_free;

	/* End instance node */
	ret = fdt_end_node(fdt);
	if (ret) goto err_free;

	/* End instances node */
	ret = fdt_end_node(fdt);
	if (ret) goto err_free;

	/* End root node */
	ret = fdt_end_node(fdt);
	if (ret) goto err_free;

	/* Finish FDT */
	ret = fdt_finish(fdt);
	if (ret) {
		pr_err("Failed to finish FDT: %d\n", ret);
		goto err_free;
	}

	*out_dtb = fdt;
	*out_size = fdt_totalsize(fdt);

	pr_info("Generated instance DTB for '%s' (ID %d): %zu bytes\n",
		name, id, *out_size);
	return 0;

err_free:
	kfree(fdt);
	return ret;
}
