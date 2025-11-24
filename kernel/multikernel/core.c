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
#include <linux/pci.h>
#include <asm/page.h>
#include "internal.h"

/**
 * Instance reference counting
 */
static void mk_instance_release(struct kref *kref)
{
	struct mk_instance *instance = container_of(kref, struct mk_instance, refcount);
	struct mk_pci_device *pci_dev, *pci_tmp;

	pr_debug("Releasing multikernel instance %d (%s)\n", instance->id, instance->name);

	mk_instance_free_memory(instance);

	/* Free CPU bitmap */
	kfree(instance->cpus);

	/* Free PCI device list */
	if (instance->pci_devices_valid) {
		list_for_each_entry_safe(pci_dev, pci_tmp, &instance->pci_devices, list) {
			list_del(&pci_dev->list);
			kfree(pci_dev);
		}
		instance->pci_device_count = 0;
		instance->pci_devices_valid = false;
	}

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

bool multikernel_allow_emergency_restart(void)
{
	struct mk_instance *instance;
	bool has_active_spawn = false;

	mutex_lock(&mk_instance_mutex);
	list_for_each_entry(instance, &mk_instance_list, list) {
		/* Skip root/host instance (ID 0) */
		if (instance->id == 0)
			continue;

		if (instance->state == MK_STATE_ACTIVE ||
		    instance->state == MK_STATE_LOADED) {
			pr_emerg("Found active spawn instance %d (%s) in state %d\n",
				 instance->id, instance->name, instance->state);
			has_active_spawn = true;
			break;
		}
	}
	mutex_unlock(&mk_instance_mutex);

	if (has_active_spawn) {
		pr_emerg("emergency_restart() BLOCKED: spawn kernel instance(s) active\n");
	} else {
		pr_emerg("emergency_restart() ALLOWED: no active spawn instances\n");
	}

	return !has_active_spawn;
}

/**
 * CPU management functions for instances
 */

static int mk_instance_transfer_cpus(struct mk_instance *instance,
				     const unsigned long *cpus)
{
	int phys_cpu, logical_cpu;
	int unavailable = 0;
	int requested_count;

	if (!cpus || !instance->cpus || !root_instance || !root_instance->cpus) {
		pr_err("Invalid CPU bitmaps for transfer\n");
		return -EINVAL;
	}

	requested_count = bitmap_weight(cpus, NR_CPUS);
	if (requested_count == 0) {
		pr_info("No CPUs requested for instance %d (%s)\n",
			instance->id, instance->name);
		return 0;
	}

	for_each_set_bit(phys_cpu, cpus, NR_CPUS) {
		if (!test_bit(phys_cpu, root_instance->cpus)) {
			pr_err("CPU %u not available in root instance pool\n", phys_cpu);
			unavailable++;
			continue;
		}

		logical_cpu = arch_cpu_from_physical_id(phys_cpu);
		if (logical_cpu < 0) {
			pr_err("Physical CPU %d not found in logical CPU map\n", phys_cpu);
			unavailable++;
			continue;
		}

		if (cpu_online(logical_cpu)) {
			pr_err("CPU %u (logical %d) is still online - not properly offlined\n",
			       phys_cpu, logical_cpu);
			unavailable++;
		}
	}

	if (unavailable > 0) {
		pr_err("Instance %d (%s): %d CPUs are not available\n",
		       instance->id, instance->name, unavailable);
		return -EBUSY;
	}

	for_each_set_bit(phys_cpu, cpus, NR_CPUS) {
		clear_bit(phys_cpu, root_instance->cpus);
		set_bit(phys_cpu, instance->cpus);
	}

	pr_info("Transferred %d CPUs from root to instance %d (%s): %*pbl\n",
		requested_count, instance->id, instance->name,
		NR_CPUS, instance->cpus);

	return 0;
}

static int mk_instance_reserve_cpus(struct mk_instance *instance,
				    const struct mk_dt_config *config)
{
	if (!config->cpus) {
		pr_warn("No CPU configuration for instance %d (%s)\n",
			instance->id, instance->name);
		return 0;
	}

	return mk_instance_transfer_cpus(instance, config->cpus);
}

static int mk_instance_transfer_pci_devices(struct mk_instance *instance,
					     const struct list_head *requested_devices,
					     int requested_count)
{
	struct mk_pci_device *req_dev, *root_dev, *tmp;
	int transferred = 0;
	int not_found = 0;
	bool found;

	if (!root_instance || !root_instance->pci_devices_valid) {
		pr_err("No root instance or PCI devices not initialized\n");
		return -EINVAL;
	}

	if (requested_count == 0 || list_empty(requested_devices)) {
		pr_info("No PCI devices requested for instance %d (%s)\n",
			instance->id, instance->name);
		instance->pci_devices_valid = true;
		return 0;
	}

	list_for_each_entry(req_dev, requested_devices, list) {
		found = false;
		list_for_each_entry(root_dev, &root_instance->pci_devices, list) {
			if (root_dev->vendor == req_dev->vendor &&
			    root_dev->device == req_dev->device &&
			    root_dev->domain == req_dev->domain &&
			    root_dev->bus == req_dev->bus &&
			    root_dev->slot == req_dev->slot &&
			    root_dev->func == req_dev->func) {
				found = true;
				break;
			}
		}
		if (!found) {
			pr_err("PCI device %04x:%04x@%04x:%02x:%02x.%x not available in root pool\n",
			       req_dev->vendor, req_dev->device, req_dev->domain,
			       req_dev->bus, req_dev->slot, req_dev->func);
			not_found++;
		}
	}

	if (not_found > 0) {
		pr_err("Instance %d (%s): %d PCI devices not available\n",
		       instance->id, instance->name, not_found);
		return -ENOENT;
	}

	list_for_each_entry(req_dev, requested_devices, list) {
		list_for_each_entry_safe(root_dev, tmp, &root_instance->pci_devices, list) {
			if (root_dev->vendor == req_dev->vendor &&
			    root_dev->device == req_dev->device &&
			    root_dev->domain == req_dev->domain &&
			    root_dev->bus == req_dev->bus &&
			    root_dev->slot == req_dev->slot &&
			    root_dev->func == req_dev->func) {

				list_del(&root_dev->list);
				list_add_tail(&root_dev->list, &instance->pci_devices);
				root_instance->pci_device_count--;
				instance->pci_device_count++;
				transferred++;

				pr_debug("Transferred PCI device %04x:%04x@%04x:%02x:%02x.%x to instance %d\n",
					 root_dev->vendor, root_dev->device, root_dev->domain,
					 root_dev->bus, root_dev->slot, root_dev->func,
					 instance->id);
				break;
			}
		}
	}

	instance->pci_devices_valid = true;
	pr_info("Transferred %d PCI devices from root to instance %d (%s), root pool remaining: %d devices\n",
		transferred, instance->id, instance->name, root_instance->pci_device_count);

	return 0;
}

static int mk_instance_reserve_pci_devices(struct mk_instance *instance,
					   const struct mk_dt_config *config)
{
	if (!config->pci_devices_valid || config->pci_device_count == 0) {
		instance->pci_devices_valid = true;
		instance->pci_device_count = 0;
		pr_debug("No PCI devices to reserve for instance %d (%s)\n",
			 instance->id, instance->name);
		return 0;
	}

	return mk_instance_transfer_pci_devices(instance,
						&config->pci_devices,
						config->pci_device_count);
}

/**
 * Memory management functions for instances
 */

static int mk_instance_transfer_memory(struct mk_instance *instance, u64 size)
{
	struct gen_pool *pool;
	struct gen_pool_chunk *chunk;
	struct mk_memory_region *region;
	int ret = 0;
	int region_num = 0;

	if (size == 0) {
		pr_info("No memory requested for instance %d (%s)\n",
			instance->id, instance->name);
		return 0;
	}

	if (!root_instance) {
		pr_err("No root instance - cannot transfer memory\n");
		return -EINVAL;
	}

	/* Calculate available memory from root_instance regions */
	u64 available = 0;
	struct mk_memory_region *root_region;
	list_for_each_entry(root_region, &root_instance->memory_regions, list) {
		available += resource_size(&root_region->res);
	}

	if (size > available) {
		pr_err("Requested memory (0x%llx) exceeds available pool (0x%llx)\n",
		       size, available);
		return -ENOMEM;
	}

	instance->instance_pool = multikernel_create_instance_pool(instance->id,
								   size,
								   PAGE_SHIFT);
	if (!instance->instance_pool) {
		pr_err("Failed to create instance pool for instance %d (%s)\n",
		       instance->id, instance->name);
		return -ENOMEM;
	}

	instance->pool_size = size;
	pool = (struct gen_pool *)instance->instance_pool;

	list_for_each_entry(chunk, &pool->chunks, next_chunk) {
		resource_size_t chunk_size = chunk->end_addr - chunk->start_addr + 1;

		region = kzalloc(sizeof(*region), GFP_KERNEL);
		if (!region) {
			pr_err("Failed to allocate memory region structure\n");
			ret = -ENOMEM;
			goto cleanup;
		}

		region->res.name = kasprintf(GFP_KERNEL, "mk-instance-%d-%s-region-%d",
					     instance->id, instance->name, region_num);
		if (!region->res.name) {
			kfree(region);
			ret = -ENOMEM;
			goto cleanup;
		}

		region->res.start = chunk->start_addr;
		region->res.end = chunk->end_addr;
		region->res.flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;
		region->chunk = chunk;

		ret = insert_resource(&multikernel_res, &region->res);
		if (ret) {
			pr_err("Failed to insert resource for instance %d region %d: %d\n",
			       instance->id, region_num, ret);
			kfree(region->res.name);
			kfree(region);
			goto cleanup;
		}

		INIT_LIST_HEAD(&region->list);
		list_add_tail(&region->list, &instance->memory_regions);
		instance->region_count++;
		region_num++;

		pr_debug("Created region %d for instance %d: 0x%llx-0x%llx (%llu bytes)\n",
			 region_num - 1, instance->id,
			 (unsigned long long)region->res.start,
			 (unsigned long long)region->res.end,
			 chunk_size);
	}

	pr_info("Transferred 0x%llx bytes from root to instance %d (%s)\n",
		size, instance->id, instance->name);

	pr_info("Created instance pool %d: %d chunks, total size=%zu bytes\n",
		instance->id, instance->region_count, instance->pool_size);

	return 0;

cleanup:
	mk_instance_free_memory(instance);
	return ret;
}

static int mk_instance_reserve_memory(struct mk_instance *instance,
				      const struct mk_dt_config *config)
{
	return mk_instance_transfer_memory(instance, config->memory_size);
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

		list_del(&region->list);
		if (region->res.parent)
			remove_resource(&region->res);
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

	/* Reserve PCI device resources */
	ret = mk_instance_reserve_pci_devices(instance, config);
	if (ret) {
		pr_err("Failed to reserve PCI device resources for instance %d (%s): %d\n",
		       instance->id, instance->name, ret);
		/* Don't fail the whole operation for PCI reservation failure */
		pr_warn("Continuing without PCI device assignment\n");
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
 * The returned address is a direct-mapped kernel virtual address,
 * which can be converted back to physical using virt_to_phys().
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

	virt_addr = phys_to_virt(phys_addr);
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

	ret = mk_messaging_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel messaging: %d\n", ret);
		return ret;
	}

	ret = mk_hotplug_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel hotplug: %d\n", ret);
		mk_messaging_cleanup();
		return ret;
	}

	ret = mk_kernfs_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel sysfs interface: %d\n", ret);
		mk_hotplug_cleanup();
		mk_messaging_cleanup();
		return ret;
	}

	pr_info("Multikernel support initialized\n");
	return 0;
}

/* Initialize multikernel after core kernel subsystems are ready */
subsys_initcall(multikernel_init);
