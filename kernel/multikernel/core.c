// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <asm/page.h>
#include "internal.h"

/**
 * Instance reference counting
 */
static void mk_instance_release(struct kref *kref)
{
	struct mk_instance *instance = container_of(kref, struct mk_instance, refcount);

	pr_debug("Releasing multikernel instance %d (%s)\n", instance->id, instance->name);

	mk_instance_free_memory(instance);

	/* Free CPU bitmap */
	kfree(instance->cpus);

	kfree(instance->dtb_data);
	kfree(instance->name);
	kfree(instance);
}

struct mk_instance *mk_instance_get(struct mk_instance *instance)
{
	if (instance)
		kref_get(&instance->refcount);
	return instance;
}

void mk_instance_put(struct mk_instance *instance)
{
	if (instance)
		kref_put(&instance->refcount, mk_instance_release);
}

/**
 * Instance state management
 */
void mk_instance_set_state(struct mk_instance *instance,
			   enum mk_instance_state state)
{
	enum mk_instance_state old_state = instance->state;

	if (old_state == state)
		return;

	instance->state = state;
	pr_debug("Instance %d (%s) state: %s -> %s\n",
		 instance->id, instance->name,
		 mk_state_to_string(old_state),
		 mk_state_to_string(state));

	/* TODO: Notify status file of state change
	 * We should store a reference to the status file's kernfs node
	 * and call kernfs_notify() on that specific file, not the directory.
	 */
}

struct mk_instance *mk_instance_find_by_name(const char *name)
{
	struct mk_instance *instance;

	lockdep_assert_held(&mk_instance_mutex);

	if (!name)
		return NULL;

	list_for_each_entry(instance, &mk_instance_list, list) {
		if (instance->name && strcmp(instance->name, name) == 0)
			return instance;
	}

	return NULL;
}

struct mk_instance *mk_instance_find(int mk_id)
{
	struct mk_instance *instance;

	mutex_lock(&mk_instance_mutex);
	instance = idr_find(&mk_instance_idr, mk_id);
	if (instance)
		mk_instance_get(instance);
	mutex_unlock(&mk_instance_mutex);

	return instance;
}

int mk_instance_set_kexec_active(int mk_id)
{
	struct mk_instance *instance;

	instance = mk_instance_find(mk_id);
	if (!instance) {
		pr_err("No sysfs instance found for multikernel ID %d\n", mk_id);
		return -ENOENT;
	}

	mk_instance_set_state(instance, MK_STATE_ACTIVE);
	mk_instance_put(instance);
	pr_info("Multikernel instance %d is now active\n", mk_id);

	return 0;
}

int mk_instance_set_kexec_loading(int mk_id)
{
	struct mk_instance *instance;

	instance = mk_instance_find(mk_id);
	if (!instance) {
		pr_err("No sysfs instance found for multikernel ID %d\n", mk_id);
		return -ENOENT;
	}

	mk_instance_set_state(instance, MK_STATE_LOADING);
	mk_instance_put(instance);
	pr_info("Multikernel instance %d is now loading\n", mk_id);

	return 0;
}


/**
 * CPU management functions for instances
 */

static int mk_instance_offline_cpus(struct mk_instance *instance)
{
	int phys_cpu, logical_cpu, ret = 0, failed_count = 0;

	pr_info("Bringing CPUs offline for multikernel instance %d (%s): %*pbl\n",
		instance->id, instance->name, NR_CPUS, instance->cpus);

	for_each_set_bit(phys_cpu, instance->cpus, NR_CPUS) {
		logical_cpu = arch_cpu_from_physical_id(phys_cpu);
		if (logical_cpu < 0) {
			pr_debug("Physical CPU %d not found in logical CPU map\n", phys_cpu);
			continue;
		}

		if (!cpu_online(logical_cpu)) {
			pr_debug("CPU %d (phys %d) already offline for instance %d\n",
				 logical_cpu, phys_cpu, instance->id);
			continue;
		}

		pr_info("Taking CPU %d offline for multikernel instance %d\n", logical_cpu, instance->id);

		ret = remove_cpu(logical_cpu);
		if (ret) {
			pr_err("Failed to take CPU %d offline for instance %d: %d\n",
				logical_cpu, instance->id, ret);
			failed_count++;
		} else {
			pr_info("Successfully took CPU %d offline for instance %d\n",
				logical_cpu, instance->id);
		}
	}

	if (failed_count > 0) {
		pr_warn("Failed to take %d CPUs offline for instance %d (%s)\n",
			 failed_count, instance->id, instance->name);
		return -EBUSY;
	}

	pr_info("Successfully took all assigned CPUs offline for instance %d (%s)\n",
		instance->id, instance->name);
	return 0;
}

/**
 * mk_instance_reserve_cpus() - Assign CPU resources to an instance
 * @instance: Instance to assign CPU resources to
 * @config: Device tree configuration with CPU assignment
 *
 * Copies CPU assignment from config to instance. This is the actual
 * "reservation" function that assigns CPUs to the instance.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int mk_instance_reserve_cpus(struct mk_instance *instance,
				    const struct mk_dt_config *config)
{
	int ret;

	if (config->cpus && instance->cpus) {
		bitmap_copy(instance->cpus, config->cpus, NR_CPUS);

		pr_info("CPU assignment for instance %d (%s): %*pbl (%d CPUs)\n",
			instance->id, instance->name,
			NR_CPUS, instance->cpus, bitmap_weight(instance->cpus, NR_CPUS));

		ret = mk_instance_offline_cpus(instance);
		if (ret) {
			pr_warn("Failed to bring some CPUs offline for instance %d (%s): %d\n",
				instance->id, instance->name, ret);
			return ret;
		}
	} else {
		pr_warn("Cannot reserve CPU resources to instance %d (%s) - instance CPU mask not available\n",
			instance->id, instance->name);
		return -EINVAL;
	}

	return 0;
}

/**
 * Memory management functions for instances
 */

/**
 * mk_instance_reserve_memory() - Reserve memory regions for an instance
 * @instance: Instance to reserve memory for
 * @config: Device tree configuration with memory size
 *
 * Creates an instance pool from the specified memory size and creates
 * memory regions from the pool chunks for resource hierarchy management.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int mk_instance_reserve_memory(struct mk_instance *instance,
				      const struct mk_dt_config *config)
{
	struct gen_pool *pool;
	struct gen_pool_chunk *chunk;
	struct mk_memory_region *region;
	int ret = 0;
	int region_num = 0;

	/* Handle case where no memory size is specified */
	if (config->memory_size == 0) {
		pr_info("No memory size specified for instance %d (%s)\n",
		       instance->id, instance->name);
		return 0;
	}

	/* Create instance memory pool */
	instance->instance_pool = multikernel_create_instance_pool(instance->id,
								   config->memory_size,
								   PAGE_SHIFT);
	if (!instance->instance_pool) {
		pr_err("Failed to create instance pool for instance %d (%s)\n",
		       instance->id, instance->name);
		return -ENOMEM;
	}

	instance->pool_size = config->memory_size;
	pool = (struct gen_pool *)instance->instance_pool;

	/* Create memory regions from pool chunks for resource hierarchy */
	list_for_each_entry(chunk, &pool->chunks, next_chunk) {
		resource_size_t size = chunk->end_addr - chunk->start_addr + 1;

		/* Allocate a new region structure for the instance */
		region = kzalloc(sizeof(*region), GFP_KERNEL);
		if (!region) {
			ret = -ENOMEM;
			goto cleanup;
		}

		/* Set up the resource structure from chunk */
		region->res.start = chunk->start_addr;
		region->res.end = chunk->end_addr;
		region->res.flags = IORESOURCE_MEM | IORESOURCE_BUSY;
		region->res.name = kasprintf(GFP_KERNEL, "mk-instance-%d-%s-region-%d",
					     instance->id, instance->name, region_num);
		if (!region->res.name) {
			kfree(region);
			ret = -ENOMEM;
			goto cleanup;
		}

		/* Link region to its chunk */
		region->chunk = chunk;

		/* Insert as child of multikernel_res */
		ret = insert_resource(&multikernel_res, &region->res);
		if (ret) {
			pr_err("Failed to insert memory region as child resource: %d\n", ret);
			kfree(region->res.name);
			kfree(region);
			goto cleanup;
		}

		/* Add to instance's memory region list */
		INIT_LIST_HEAD(&region->list);
		list_add_tail(&region->list, &instance->memory_regions);
		instance->region_count++;
		region_num++;

		pr_debug("Created memory region for instance %d (%s): 0x%llx-0x%llx (%llu bytes)\n",
			 instance->id, instance->name,
			 (unsigned long long)region->res.start,
			 (unsigned long long)region->res.end,
			 (unsigned long long)size);
	}

	pr_info("Successfully created %d memory regions from pool for instance %d (%s), total %zu bytes\n",
		instance->region_count, instance->id, instance->name, config->memory_size);
	return 0;

cleanup:
	/* Clean up any regions we managed to allocate */
	mk_instance_free_memory(instance);

	if (instance->instance_pool) {
		multikernel_destroy_instance_pool(instance->instance_pool);
		instance->instance_pool = NULL;
		instance->pool_size = 0;
	}
	return ret;
}

/**
 * mk_instance_free_memory() - Free all reserved memory regions
 * @instance: Instance to free memory for
 *
 * Returns all reserved memory regions back to the multikernel pool
 * and removes them from the resource hierarchy.
 */
void mk_instance_free_memory(struct mk_instance *instance)
{
	struct mk_memory_region *region, *tmp;

	if (!instance)
		return;

	list_for_each_entry_safe(region, tmp, &instance->memory_regions, list) {
		pr_debug("Freeing memory region for instance %d (%s): 0x%llx-0x%llx\n",
			 instance->id, instance->name,
			 (unsigned long long)region->res.start,
			 (unsigned long long)region->res.end);

		/* Remove from instance list */
		list_del(&region->list);

		/* Remove from resource hierarchy */
		remove_resource(&region->res);

		/* Free the resource name and region structure */
		kfree(region->res.name);
		kfree(region);
	}

	instance->region_count = 0;
	if (instance->instance_pool) {
		multikernel_destroy_instance_pool(instance->instance_pool);
		instance->instance_pool = NULL;
		instance->pool_size = 0;
	}

	pr_debug("Freed all memory regions and pool for instance %d (%s)\n",
		 instance->id, instance->name);
}

/**
 * mk_instance_reserve_resources() - Reserve memory and CPU resources for an instance
 * @instance: Instance to reserve resources for
 * @config: Device tree configuration with memory regions and CPU assignment
 *
 * Reserves all memory regions specified in the device tree configuration,
 * makes them children of the main multikernel_res, and copies CPU assignment.
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_instance_reserve_resources(struct mk_instance *instance,
			       const struct mk_dt_config *config)
{
	int ret;

	if (!config || !instance) {
		pr_err("Invalid parameters to mk_instance_reserve_resources\n");
		return -EINVAL;
	}

	/* Free any existing memory regions first */
	mk_instance_free_memory(instance);

	/* Reserve memory regions */
	ret = mk_instance_reserve_memory(instance, config);
	if (ret) {
		pr_err("Failed to reserve memory regions for instance %d (%s): %d\n",
		       instance->id, instance->name, ret);
		return ret;
	}

	/* Reserve CPU resources */
	ret = mk_instance_reserve_cpus(instance, config);
	if (ret) {
		pr_err("Failed to reserve CPU resources for instance %d (%s): %d\n",
		       instance->id, instance->name, ret);
		/* Don't fail the whole operation for CPU reservation failure */
		pr_warn("Continuing without CPU assignment\n");
	}

	return 0;
}

/**
 * Per-instance memory pool management
 */

/**
 * mk_instance_alloc() - Allocate memory from instance pool
 * @instance: Instance to allocate from
 * @size: Size to allocate
 * @align: Alignment requirement (must be power of 2)
 *
 * Returns virtual address of allocated memory, or NULL on failure.
 */
void *mk_instance_alloc(struct mk_instance *instance, size_t size, size_t align)
{
	phys_addr_t phys_addr;
	void *virt_addr;

	if (!instance || !instance->instance_pool) {
		pr_debug("mk_instance_alloc: instance %p has no pool\n", instance);
		return NULL;
	}

	/* Allocate from instance pool with alignment */
	phys_addr = multikernel_instance_alloc(instance->instance_pool, size, align);
	if (!phys_addr) {
		pr_debug("Failed to allocate %zu bytes from instance pool (align=0x%zx)\n", size, align);
		return NULL;
	}

	/* Map to virtual address space */
	//virt_addr = memremap(phys_addr, size, MEMREMAP_WB); // EO -> actuelement
	virt_addr = phys_to_virt(phys_addr); // EO -> ajout patch
	if (!virt_addr) {
		pr_err("Failed to map instance memory at 0x%llx\n", (unsigned long long)phys_addr);
		multikernel_instance_free(instance->instance_pool, phys_addr, size);
		return NULL;
	}

	return virt_addr;
}

/**
 * mk_instance_free() - Free memory back to instance pool
 * @instance: Instance to free to
 * @virt_addr: Virtual address to free
 * @size: Size to free
 */
void mk_instance_free(struct mk_instance *instance, void *virt_addr, size_t size)
{
	phys_addr_t phys_addr;

	if (!instance || !instance->instance_pool || !virt_addr)
		return;

	phys_addr = virt_to_phys(virt_addr);
	//memunmap(virt_addr); // EO -> actuelement
	multikernel_instance_free(instance->instance_pool, phys_addr, size);
}

/**
 * Kimage-based memory pool access functions
 *
 * These provide convenient wrappers for accessing instance memory pools
 * through the kimage structure, commonly used in kexec code paths.
 */

/**
 * mk_kimage_alloc() - Allocate memory from kimage's instance pool
 * @image: kimage with associated mk_instance
 * @size: Size to allocate
 * @align: Alignment requirement (must be power of 2)
 *
 * Returns virtual address of allocated memory, or NULL on failure.
 */
void *mk_kimage_alloc(struct kimage *image, size_t size, size_t align)
{
	if (!image || !image->mk_instance)
		return NULL;

	return mk_instance_alloc(image->mk_instance, size, align);
}

/**
 * mk_kimage_free() - Free memory back to kimage's instance pool
 * @image: kimage with associated mk_instance
 * @virt_addr: Virtual address to free
 * @size: Size to free
 */
void mk_kimage_free(struct kimage *image, void *virt_addr, size_t size)
{
	if (!image || !image->mk_instance)
		return;

	mk_instance_free(image->mk_instance, virt_addr, size);
}

static int __init multikernel_init(void)
{
	int ret;

	ret = mk_kernfs_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel sysfs interface: %d\n", ret);
		return ret;
	}

	pr_info("Multikernel support initialized\n");
	return 0;
}

/* Initialize multikernel after core kernel subsystems are ready */
subsys_initcall(multikernel_init);
