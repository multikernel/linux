// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include "internal.h"

static void mk_instance_return_all_cpus(struct mk_instance *instance)
{
	if (!instance || mk_cpu_set_empty(instance->cpus))
		return;

	if (instance == root_instance || instance->id == 0)
		return;

	mk_instance_return_cpus(instance, instance->cpus);
}

static void mk_instance_return_pci_devices(struct mk_instance *instance)
{
	struct mk_pci_device *pci_dev, *pci_tmp;
	int returned_count = 0;

	if (!instance || !instance->pci_devices_valid)
		return;

	if (instance == root_instance || instance->id == 0)
		return;

	if (!root_instance) {
		pr_warn("Cannot return PCI devices from instance %d (%s): no root instance\n",
			instance->id, instance->name);
		goto cleanup;
	}

	list_for_each_entry_safe(pci_dev, pci_tmp, &instance->pci_devices, list) {
		struct mk_pci_device *root_dev;

		root_dev = kzalloc(sizeof(*root_dev), GFP_KERNEL);
		if (!root_dev) {
			pr_warn("Failed to allocate PCI device entry for root instance\n");
			continue;
		}

		*root_dev = *pci_dev;
		INIT_LIST_HEAD(&root_dev->list);

		list_add_tail(&root_dev->list, &root_instance->pci_devices);
		root_instance->pci_device_count++;
		root_instance->pci_devices_valid = true;

		pr_debug("Returned PCI device %04x:%02x:%02x.%d from instance %d to root\n",
			 root_dev->domain, root_dev->bus, root_dev->slot,
			 root_dev->func, instance->id);

		returned_count++;
	}

	if (returned_count > 0) {
		pr_info("Returned %d PCI devices from instance %d (%s) to root instance\n",
			returned_count, instance->id, instance->name);
	}

cleanup:
	list_for_each_entry_safe(pci_dev, pci_tmp, &instance->pci_devices, list) {
		list_del(&pci_dev->list);
		kfree(pci_dev);
	}
	instance->pci_device_count = 0;
	instance->pci_devices_valid = false;
}

static void mk_instance_return_platform_devices(struct mk_instance *instance)
{
	struct mk_platform_device *plat_dev, *plat_tmp;
	int returned_count = 0;

	if (!instance || !instance->platform_devices_valid)
		return;

	if (instance == root_instance || instance->id == 0)
		return;

	if (!root_instance) {
		pr_warn("Cannot return platform devices from instance %d (%s): no root instance\n",
			instance->id, instance->name);
		goto cleanup;
	}

	list_for_each_entry_safe(plat_dev, plat_tmp, &instance->platform_devices, list) {
		struct mk_platform_device *root_dev;

		root_dev = kzalloc(sizeof(*root_dev), GFP_KERNEL);
		if (!root_dev) {
			pr_warn("Failed to allocate platform device entry for root instance\n");
			continue;
		}

		*root_dev = *plat_dev;
		INIT_LIST_HEAD(&root_dev->list);

		list_add_tail(&root_dev->list, &root_instance->platform_devices);
		root_instance->platform_device_count++;
		root_instance->platform_devices_valid = true;

		pr_debug("Returned platform device '%s' from instance %d to root\n",
			 root_dev->name, instance->id);

		returned_count++;
	}

	if (returned_count > 0) {
		pr_info("Returned %d platform devices from instance %d (%s) to root instance\n",
			returned_count, instance->id, instance->name);
	}

cleanup:
	list_for_each_entry_safe(plat_dev, plat_tmp, &instance->platform_devices, list) {
		list_del(&plat_dev->list);
		kfree(plat_dev);
	}
	instance->platform_device_count = 0;
	instance->platform_devices_valid = false;
}

static void mk_instance_release(struct kref *kref)
{
	struct mk_instance *instance = container_of(kref, struct mk_instance, refcount);

	pr_info("Releasing multikernel instance %d (%s), returning resources to root\n",
		instance->id, instance->name);

	mk_instance_return_all_cpus(instance);
	mk_instance_return_pci_devices(instance);
	mk_instance_return_platform_devices(instance);
	mk_instance_free_memory(instance);

	mk_cpu_set_free(instance->cpus);
	kfree(instance->dtb_data);
	kfree(instance->name);
	kfree(instance);
}

/**
 * Instance reference counting
 */
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
			pr_info("Found active spawn instance %d (%s) in state %d\n",
				 instance->id, instance->name, instance->state);
			has_active_spawn = true;
			break;
		}
	}
	mutex_unlock(&mk_instance_mutex);

	if (has_active_spawn) {
		pr_info("emergency_restart() BLOCKED: spawn kernel instance(s) active\n");
	} else {
		pr_info("emergency_restart() ALLOWED: no active spawn instances\n");
	}

	return !has_active_spawn;
}

/**
 * CPU management functions for instances
 */

/**
 * mk_instance_confirm_parked() - Wait for an instance's CPUs to park
 * @instance: Instance that has been shut down
 *
 * A halted instance acknowledges the shutdown before its CPUs have
 * actually reached the park page: they still have to run the rest of the
 * shutdown path, which lives in the instance's own kernel image. Loading
 * a new image over that memory while a CPU is still executing it kills
 * the machine, so callers that are about to rewrite the image wait here
 * first.
 *
 * Returns 0 when every CPU is parked, -EBUSY if any did not get there.
 */
int mk_instance_confirm_parked(struct mk_instance *instance)
{
	struct mk_cpu_set *snapshot;
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret, failed = 0;

	/* Never started, so nothing of it is running */
	if (!instance->spawn_ctx)
		return 0;
	if (!instance->cpus_on_slot) {
		pr_err("Instance %d (%s): missing parked-CPU tracking for a started instance\n",
		       instance->id, instance->name);
		return -EINVAL;
	}

	snapshot = mk_cpu_set_alloc();
	if (!snapshot)
		return -ENOMEM;
	ret = mk_cpu_set_copy(snapshot, instance->cpus_on_slot);
	if (ret) {
		mk_cpu_set_free(snapshot);
		return ret;
	}

	mk_cpu_set_for_each(i, phys_cpu, snapshot) {
		ret = mk_arch_confirm_parked(instance, phys_cpu);
		if (ret) {
			pr_err("Instance %d (%s): CPU %llu is not parked: %d\n",
			       instance->id, instance->name, phys_cpu, ret);
			failed++;
		}
	}
	if (!failed) {
		ret = mk_ipi_ring_recover_halted(snapshot);
		if (ret) {
			pr_err("Instance %d (%s): failed to recover halted IPI producer: %d\n",
			       instance->id, instance->name, ret);
			failed++;
		}
	}
	mk_cpu_set_free(snapshot);

	return failed ? -EBUSY : 0;
}

/**
 * mk_instance_transfer_cpus() - Transfer CPUs from root to instance
 * @instance: Target instance
 * @cpus: Set of physical CPU IDs to transfer
 *
 * Transfers CPUs from root instance to the target instance.
 * Validates that CPUs are available in root.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_transfer_cpus(struct mk_instance *instance,
			       const struct mk_cpu_set *cpus)
{
	unsigned int i, requested_count;
	mk_phys_cpu_t phys_cpu;
	int unavailable = 0;
	char buf[256];
	int ret;

	if (!cpus || !instance->cpus || !mk_cpu_pool) {
		pr_err("Invalid CPU sets for transfer\n");
		return -EINVAL;
	}

	requested_count = mk_cpu_set_count(cpus);
	if (requested_count == 0) {
		pr_info("No CPUs requested for instance %d (%s)\n",
			instance->id, instance->name);
		return 0;
	}

	mk_cpu_set_for_each(i, phys_cpu, cpus) {
		if (!mk_cpu_set_contains(mk_cpu_pool, phys_cpu)) {
			pr_err("CPU %llu not available in the pool\n",
			       phys_cpu);
			unavailable++;
			continue;
		}

		if (arch_cpu_from_physical_id(phys_cpu) < 0) {
			pr_err("Physical CPU %llu not found in logical CPU map\n",
			       phys_cpu);
			unavailable++;
		}
	}

	if (unavailable > 0) {
		pr_err("Instance %d (%s): %d CPUs are not available\n",
		       instance->id, instance->name, unavailable);
		return -EBUSY;
	}

	ret = mk_cpu_set_reserve(instance->cpus, requested_count);
	if (ret)
		return ret;

	mk_cpu_set_for_each(i, phys_cpu, cpus) {
		mk_cpu_set_del(mk_cpu_pool, phys_cpu);
		mk_cpu_set_add(instance->cpus, phys_cpu);
	}

	mk_cpu_set_format(buf, sizeof(buf), instance->cpus);
	pr_info("Transferred %u CPUs from pool to instance %d (%s): %s\n",
		requested_count, instance->id, instance->name, buf);

	return 0;
}

/**
 * mk_instance_return_cpus() - Return CPUs from instance back to root
 * @instance: Source instance
 * @cpus: Set of physical CPU IDs to return (may be instance->cpus itself)
 *
 * Transfers CPUs from the instance back to root instance.
 * Validates that CPUs are assigned to the source instance.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_return_cpus(struct mk_instance *instance,
			     const struct mk_cpu_set *cpus)
{
	unsigned int i, requested_count;
	mk_phys_cpu_t phys_cpu;
	int not_found = 0;
	char buf[256];
	int ret;

	if (!cpus || !instance->cpus || !mk_cpu_pool) {
		pr_err("Invalid CPU sets for return\n");
		return -EINVAL;
	}

	requested_count = mk_cpu_set_count(cpus);
	if (requested_count == 0) {
		pr_info("No CPUs requested to return from instance %d (%s)\n",
			instance->id, instance->name);
		return 0;
	}

	/* Validate all CPUs are assigned to this instance */
	mk_cpu_set_for_each(i, phys_cpu, cpus) {
		if (!mk_cpu_set_contains(instance->cpus, phys_cpu)) {
			pr_err("CPU %llu not assigned to instance %d (%s)\n",
			       phys_cpu, instance->id, instance->name);
			not_found++;
		}
	}

	if (not_found > 0) {
		pr_err("Instance %d (%s): %d CPUs are not assigned to this instance\n",
		       instance->id, instance->name, not_found);
		return -EINVAL;
	}

	ret = mk_cpu_set_reserve(mk_cpu_pool, requested_count);
	if (ret)
		return ret;

	mk_cpu_set_format(buf, sizeof(buf), cpus);

	/*
	 * @cpus may alias instance->cpus (returning everything on
	 * teardown), so walk it back-to-front: a deletion then never
	 * shifts entries the walk has yet to visit.
	 */
	for (i = requested_count; i-- > 0; ) {
		phys_cpu = cpus->ids[i];
		mk_cpu_set_add(mk_cpu_pool, phys_cpu);
		mk_cpu_set_del(instance->cpus, phys_cpu);
	}

	pr_info("Returned %u CPUs from instance %d (%s) to the pool: %s\n",
		requested_count, instance->id, instance->name, buf);

	return 0;
}

/**
 * mk_pool_cpus_returned() - Is every pool CPU back in this kernel?
 *
 * True when the pool holds no free CPU and no instance owns one, so
 * nothing can be sitting in a park loop. Pool memory that parked CPUs
 * execute from may only be freed once this holds. The answer is only as
 * good as the invariant that a CPU is recorded in the pool set or in an
 * instance's set before it parks, which is why the move paths reserve
 * room in the destination set up front.
 */
bool mk_pool_cpus_returned(void)
{
	struct mk_instance *instance;
	bool returned = true;

	if (mk_cpu_pool && !mk_cpu_set_empty(mk_cpu_pool))
		return false;

	mutex_lock(&mk_instance_mutex);
	list_for_each_entry(instance, &mk_instance_list, list) {
		if (instance == root_instance)
			continue;

		if (!mk_cpu_set_empty(instance->cpus) ||
		    !mk_cpu_set_empty(instance->cpus_on_slot)) {
			returned = false;
			break;
		}
	}
	mutex_unlock(&mk_instance_mutex);

	return returned;
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

static int mk_instance_transfer_platform_devices(struct mk_instance *instance,
						 const struct list_head *requested_devices,
						 int requested_count)
{
	struct mk_platform_device *req_dev, *root_dev, *tmp;
	int transferred = 0;
	int not_found = 0;
	bool found;

	if (!root_instance || !root_instance->platform_devices_valid) {
		pr_err("No root instance or platform devices not initialized\n");
		return -EINVAL;
	}

	if (requested_count == 0 || list_empty(requested_devices)) {
		pr_info("No platform devices requested for instance %d (%s)\n",
			instance->id, instance->name);
		instance->platform_devices_valid = true;
		return 0;
	}

	list_for_each_entry(req_dev, requested_devices, list) {
		found = false;
		list_for_each_entry(root_dev, &root_instance->platform_devices, list) {
			if (strcmp(root_dev->name, req_dev->name) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			pr_err("Platform device '%s' not available in root pool\n",
			       req_dev->name);
			not_found++;
		}
	}

	if (not_found > 0) {
		pr_err("Instance %d (%s): %d platform devices not available\n",
		       instance->id, instance->name, not_found);
		return -ENOENT;
	}

	list_for_each_entry(req_dev, requested_devices, list) {
		list_for_each_entry_safe(root_dev, tmp, &root_instance->platform_devices, list) {
			if (strcmp(root_dev->name, req_dev->name) == 0) {
				list_del(&root_dev->list);
				list_add_tail(&root_dev->list, &instance->platform_devices);
				root_instance->platform_device_count--;
				instance->platform_device_count++;
				transferred++;

				pr_debug("Transferred platform device '%s' to instance %d\n",
					 root_dev->name, instance->id);
				break;
			}
		}
	}

	instance->platform_devices_valid = true;
	pr_info("Transferred %d platform devices from root to instance %d (%s), root pool remaining: %d devices\n",
		transferred, instance->id, instance->name, root_instance->platform_device_count);

	return 0;
}

static int mk_instance_reserve_platform_devices(struct mk_instance *instance,
						const struct mk_dt_config *config)
{
	if (!config->platform_devices_valid || config->platform_device_count == 0) {
		instance->platform_devices_valid = true;
		instance->platform_device_count = 0;
		pr_debug("No platform devices to reserve for instance %d (%s)\n",
			 instance->id, instance->name);
		return 0;
	}

	return mk_instance_transfer_platform_devices(instance,
						     &config->platform_devices,
						     config->platform_device_count);
}

/**
 * mk_instance_add_pci_device - Add a single PCI device to an instance
 * @instance: Target instance
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * Transfers a single PCI device from root instance to the specified instance.
 * Used for dynamic PCI device hotplug to non-running instances.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_add_pci_device(struct mk_instance *instance,
			       u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *root_dev, *tmp;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);

	if (!root_instance || !root_instance->pci_devices_valid) {
		pr_err("No root instance or PCI devices not initialized\n");
		return -EINVAL;
	}

	list_for_each_entry_safe(root_dev, tmp, &root_instance->pci_devices, list) {
		if (root_dev->domain == domain &&
		    root_dev->bus == bus &&
		    root_dev->slot == slot &&
		    root_dev->func == func) {

			list_del(&root_dev->list);
			list_add_tail(&root_dev->list, &instance->pci_devices);
			root_instance->pci_device_count--;
			instance->pci_device_count++;
			instance->pci_devices_valid = true;

			pr_info("Transferred PCI device %04x:%04x@%04x:%02x:%02x.%x to instance %d\n",
				root_dev->vendor, root_dev->device, domain, bus, slot, func,
				instance->id);
			return 0;
		}
	}

	pr_err("PCI device %04x:%02x:%02x.%x not found in root pool\n",
	       domain, bus, slot, func);
	return -ENOENT;
}

/**
 * mk_instance_remove_pci_device - Remove a single PCI device from an instance
 * @instance: Target instance
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * Returns a single PCI device from the specified instance back to root instance.
 * Used for dynamic PCI device hotplug from non-running instances.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_remove_pci_device(struct mk_instance *instance,
				  u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *inst_dev, *tmp;
	struct mk_pci_device *root_dev;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);

	if (!instance->pci_devices_valid) {
		pr_err("Instance %d PCI devices not initialized\n", instance->id);
		return -EINVAL;
	}

	if (!root_instance) {
		pr_err("Cannot return PCI device: no root instance\n");
		return -EINVAL;
	}

	list_for_each_entry_safe(inst_dev, tmp, &instance->pci_devices, list) {
		if (inst_dev->domain == domain &&
		    inst_dev->bus == bus &&
		    inst_dev->slot == slot &&
		    inst_dev->func == func) {

			root_dev = kzalloc(sizeof(*root_dev), GFP_KERNEL);
			if (!root_dev) {
				pr_err("Failed to allocate PCI device entry for root instance\n");
				return -ENOMEM;
			}

			*root_dev = *inst_dev;
			INIT_LIST_HEAD(&root_dev->list);

			list_add_tail(&root_dev->list, &root_instance->pci_devices);
			root_instance->pci_device_count++;
			root_instance->pci_devices_valid = true;

			list_del(&inst_dev->list);
			kfree(inst_dev);
			instance->pci_device_count--;

			pr_info("Returned PCI device %04x:%04x@%04x:%02x:%02x.%x from instance %d to root\n",
				root_dev->vendor, root_dev->device, domain, bus, slot, func,
				instance->id);
			return 0;
		}
	}

	pr_err("PCI device %04x:%02x:%02x.%x not found in instance %d\n",
	       domain, bus, slot, func, instance->id);
	return -ENOENT;
}

/**
 * mk_root_has_pci_device - Test whether a PCI device is free in the root pool
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * Returns: true when the device is listed on the root instance
 */
bool mk_root_has_pci_device(u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *root_dev;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);

	if (!root_instance || !root_instance->pci_devices_valid)
		return false;

	list_for_each_entry(root_dev, &root_instance->pci_devices, list) {
		if (root_dev->domain == domain &&
		    root_dev->bus == bus &&
		    root_dev->slot == slot &&
		    root_dev->func == func)
			return true;
	}

	return false;
}

/**
 * mk_root_add_pci_device - List a PCI device as free in the root pool
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * Returns: 0 on success, -EINVAL if there is no root instance, -EEXIST if
 * already listed, -ENODEV if the device does not exist, -ENOMEM on allocation
 * failure
 */
int mk_root_add_pci_device(u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *root_dev;
	struct pci_dev *pdev;

	if (!root_instance)
		return -EINVAL;

	if (mk_root_has_pci_device(domain, bus, devfn))
		return -EEXIST;

	pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
	if (!pdev)
		return -ENODEV;

	root_dev = kzalloc_obj(*root_dev, GFP_KERNEL);
	if (!root_dev) {
		pci_dev_put(pdev);
		return -ENOMEM;
	}

	root_dev->domain = domain;
	root_dev->bus = bus;
	root_dev->slot = PCI_SLOT(devfn);
	root_dev->func = PCI_FUNC(devfn);
	root_dev->vendor = pdev->vendor;
	root_dev->device = pdev->device;
	snprintf(root_dev->name, sizeof(root_dev->name), "pci_%04x_%02x_%02x_%x",
		 domain, bus, root_dev->slot, root_dev->func);
	INIT_LIST_HEAD(&root_dev->list);
	pci_dev_put(pdev);

	list_add_tail(&root_dev->list, &root_instance->pci_devices);
	root_instance->pci_device_count++;
	root_instance->pci_devices_valid = true;

	pr_info("PCI device %04x:%04x@%04x:%02x:%02x.%x is free in the root pool\n",
		root_dev->vendor, root_dev->device, domain, bus,
		root_dev->slot, root_dev->func);
	return 0;
}

/**
 * mk_root_del_pci_device - Drop a PCI device from the root pool list
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * Returns: 0 on success, -ENOENT if the device is not listed
 */
int mk_root_del_pci_device(u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *root_dev, *tmp;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);

	if (!root_instance || !root_instance->pci_devices_valid)
		return -ENOENT;

	list_for_each_entry_safe(root_dev, tmp, &root_instance->pci_devices, list) {
		if (root_dev->domain == domain &&
		    root_dev->bus == bus &&
		    root_dev->slot == slot &&
		    root_dev->func == func) {
			list_del(&root_dev->list);
			kfree(root_dev);
			root_instance->pci_device_count--;
			return 0;
		}
	}

	return -ENOENT;
}

/**
 * Memory management functions for instances
 */

static int mk_instance_transfer_memory(struct mk_instance *instance, u64 size,
				       int node)
{
	struct gen_pool *pool;
	struct gen_pool_chunk *chunk;
	struct mk_memory_region *region;
	struct resource *parent;
	size_t available;
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

	available = mk_pool_avail_bytes();

	if (size > available) {
		pr_err("Requested memory (0x%llx) exceeds available pool (0x%zx)\n",
		       size, available);
		return -ENOMEM;
	}

	instance->instance_pool = multikernel_create_instance_pool(instance->id,
								   size,
								   PAGE_SHIFT,
								   node);
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

		parent = mk_pool_chunk_resource(chunk->start_addr);
		ret = parent ? insert_resource(parent, &region->res) : -ENODEV;
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
	return mk_instance_transfer_memory(instance, config->memory_size,
					   config->numa_node);
}

/**
 * mk_instance_free_memory() - Free all reserved memory regions
 * @instance: Instance to free memory for
 *
 * Returns all reserved memory regions back to the multikernel pool
 * and removes them from the resource hierarchy.
 *
 * Note: The memory is returned to the global multikernel pool by
 * multikernel_destroy_instance_pool(), which makes it available for
 * future instance allocations (including root_instance).
 */
void mk_instance_free_memory(struct mk_instance *instance)
{
	struct mk_memory_region *region, *tmp;
	u64 total_freed = 0;

	if (!instance)
		return;

	list_for_each_entry_safe(region, tmp, &instance->memory_regions, list) {
		u64 region_size = resource_size(&region->res);

		pr_debug("Freeing memory region for instance %d (%s): 0x%llx-0x%llx (%llu bytes)\n",
			 instance->id, instance->name,
			 (unsigned long long)region->res.start,
			 (unsigned long long)region->res.end,
			 region_size);

		list_del(&region->list);
		if (region->res.parent)
			remove_resource(&region->res);
		kfree(region->res.name);
		kfree(region);

		total_freed += region_size;
	}

	instance->region_count = 0;
	if (instance->instance_pool) {
		pr_info("Returning 0x%llx bytes from instance %d (%s) back to multikernel pool\n",
			total_freed, instance->id, instance->name);

		/*
		 * The spawn context, trampoline, park page and identity page
		 * tables are all carved from the control block, so they are
		 * returned to the pool as one allocation rather than
		 * individually. Freeing them piecemeal would punch holes in
		 * the block's bitmap and leave the rest of it allocated.
		 * The arch reparks CPUs still watching this instance's
		 * context back to the host slot before the block goes away.
		 */
		if (mk_arch_release_instance(instance)) {
			/*
			 * A CPU never claimed its repark: it is still parked
			 * on this instance's context, executing from the park
			 * page inside this pool. Handing the memory back
			 * would let the next instance overwrite code a CPU is
			 * running, so leak the whole pool instead.
			 */
			pr_err("Instance %d (%s): leaking its %zu byte pool, a lost CPU still parks in it\n",
			       instance->id, instance->name,
			       instance->pool_size);
			instance->instance_pool = NULL;
			instance->pool_size = 0;
			return;
		}

		if (instance->ctrl_va) {
			mk_instance_free(instance, instance->ctrl_va,
					 MK_CTRL_BLOCK_SIZE);
			instance->ctrl_va = NULL;
			instance->ctrl_phys = 0;
			instance->ctrl_used = 0;
		}

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
 * makes them children of their pool chunks, and copies CPU assignment.
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

	/* Reserve platform device resources */
	ret = mk_instance_reserve_platform_devices(instance, config);
	if (ret) {
		pr_err("Failed to reserve platform device resources for instance %d (%s): %d\n",
		       instance->id, instance->name, ret);
		/* Don't fail the whole operation for platform reservation failure */
		pr_warn("Continuing without platform device assignment\n");
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
/**
 * mk_instance_ctrl_alloc() - Allocate from the instance control block
 * @instance: Instance to allocate from
 * @size: Allocation size
 * @align: Required alignment
 *
 * Control structures (spawn context, trampoline, park page, identity page
 * tables) live in instance memory, which the spawn kernel sees as RAM. They
 * are carved from one contiguous block so it can be reserved in the spawn
 * kernel's e820; otherwise the spawn kernel's page allocator recycles them
 * while it runs, and the CPUs have nothing valid left to park on when it
 * shuts down.
 *
 * The block lives as long as the instance; individual allocations are never
 * freed, since all of them are reused across re-spawns anyway.
 */
void *mk_instance_ctrl_alloc(struct mk_instance *instance, size_t size,
			     size_t align)
{
	size_t off;

	if (!instance)
		return NULL;

	if (!instance->ctrl_va) {
		void *va = mk_instance_alloc(instance, MK_CTRL_BLOCK_SIZE,
					     PAGE_SIZE);

		if (!va) {
			pr_err("Failed to allocate control block for instance %d\n",
			       instance->id);
			return NULL;
		}

		memset(va, 0, MK_CTRL_BLOCK_SIZE);
		instance->ctrl_va = va;
		instance->ctrl_phys = virt_to_phys(va);
		instance->ctrl_used = 0;
	}

	off = ALIGN(instance->ctrl_used, align);
	if (off + size > MK_CTRL_BLOCK_SIZE) {
		pr_err("Instance %d control block exhausted (%zu used, %zu requested)\n",
		       instance->id, instance->ctrl_used, size);
		return NULL;
	}

	instance->ctrl_used = off + size;
	return instance->ctrl_va + off;
}

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

/*
 * Instance Shutdown
 *
 * Two shutdown methods are provided:
 *
 * 1. Graceful shutdown (MK_SYS_SHUTDOWN via MULTIKERNEL_VECTOR):
 *    - Host sends shutdown message to spawn kernel
 *    - Spawn kernel receives message, sends ACK while still able to communicate
 *    - Spawn kernel parks all its CPUs in the pool wait loop
 *    - Works when spawn kernel is responsive
 *
 * 2. Forcible shutdown (NMI-based, multikernel_force_halt_by_id):
 *    - Host sets shutdown flag in shared memory for target CPUs
 *    - Host sends NMI directly to spawn CPUs
 *    - NMI handler checks shared memory marker and stops if flagged
 *    - Works when spawn kernel is stuck or crashed
 */

struct mk_shutdown_work {
	struct work_struct work;
	u32 flags;
	int sender_instance_id;
};


/*
 * Notify @target_id that this kernel is going down, while messaging
 * still works, then park every CPU in the pool wait loop. The subtype
 * distinguishes a reply to a host-requested shutdown (SHUTDOWN_ACK)
 * from a voluntary halt the parent never asked for (HALTED); both mean
 * "my CPUs are about to park on my context".
 */
static void __noreturn mk_notify_down_and_park(int target_id, u32 subtype)
{
	struct mk_resource_ack ack;

	ack.operation = MK_SYS_SHUTDOWN;
	ack.result = 0;
	ack.resource_id = root_instance->id;

	mk_send_message(target_id, MK_MSG_SYSTEM, subtype, &ack, sizeof(ack));

	pr_info("Multikernel instance %d shutting down\n", root_instance->id);

	/*
	 * Enter pool state: CPUs wait in HLT with APIC enabled, checking
	 * for spawn signals. This allows CPUs to be re-spawned later.
	 *
	 * Use wait=0 since mk_enter_pool_state() never returns.
	 */
	smp_call_function(mk_enter_pool_state, NULL, 0);
	mk_enter_pool_state(NULL);
}

/**
 * mk_halt_to_pool - Halt this spawn kernel, returning its CPUs to the pool
 *
 * Called from the spawn kernel's machine halt path. A voluntary exit
 * cannot stay contained in this kernel: the parent owns the instance's
 * lifecycle, and without notice it would consider the instance running
 * forever. Send the parent (instance 0) a HALTED event, then park every
 * CPU in the pool wait loop.
 */
void __noreturn mk_halt_to_pool(void)
{
	mk_notify_down_and_park(0, MK_SYS_HALTED);
}

static void mk_shutdown_work_fn(struct work_struct *work)
{
	struct mk_shutdown_work *sw = container_of(work, struct mk_shutdown_work, work);
	int sender_instance_id = sw->sender_instance_id;

	kfree(sw);
	mk_notify_down_and_park(sender_instance_id, MK_SYS_SHUTDOWN_ACK);
}

/*
 * Mark a halted instance re-spawnable. No wakeups are published here:
 * the instance's CPUs may still be on their way to the park loop, and
 * poking its context while its (old or next) kernel also publishes on
 * it corrupts the single-producer mailbox. The kexec path confirms the
 * CPUs are parked before it rewrites the image.
 */
static void mk_instance_settle_halted(struct mk_instance *instance)
{
	pr_info("Instance %d (%s) halted, CPUs parking in pool\n",
		instance->id, instance->name);
	mk_instance_set_state(instance, MK_STATE_LOADED);
}

struct mk_halted_work {
	struct work_struct work;
	int instance_id;
};

static void mk_halted_work_fn(struct work_struct *work)
{
	struct mk_halted_work *aw =
		container_of(work, struct mk_halted_work, work);
	struct mk_instance *instance;

	instance = mk_instance_find(aw->instance_id);
	if (instance) {
		mk_instance_settle_halted(instance);
		mk_instance_put(instance);
	} else {
		pr_warn("Shutdown ACK from unknown instance %d\n",
			aw->instance_id);
	}

	kfree(aw);
}

static void mk_system_msg_handler(u32 msg_type, u32 subtype,
				  void *payload, u32 payload_len, void *ctx)
{
	if (msg_type != MK_MSG_SYSTEM)
		return;

	switch (subtype) {
	case MK_SYS_SHUTDOWN: {
		struct mk_shutdown_payload *req = payload;
		struct mk_shutdown_work *sw;

		if (payload_len < sizeof(*req))
			return;

		pr_info("Shutdown requested by instance %d\n", req->sender_instance_id);

		sw = kmalloc(sizeof(*sw), GFP_ATOMIC);
		if (!sw)
			return;

		INIT_WORK(&sw->work, mk_shutdown_work_fn);
		sw->flags = req->flags;
		sw->sender_instance_id = req->sender_instance_id;
		schedule_work(&sw->work);
		break;
	}
	case MK_SYS_SHUTDOWN_ACK: {
		struct mk_resource_ack *ack = payload;

		if (payload_len < sizeof(*ack))
			return;
		/*
		 * Reply to a shutdown this kernel requested: wake the
		 * requester, which waits for the instance's CPUs to park
		 * and settles its state itself.
		 */
		mk_msg_pending_complete(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN,
					ack->resource_id, ack->result);
		break;
	}
	case MK_SYS_HALTED: {
		struct mk_resource_ack *ack = payload;
		struct mk_halted_work *aw;

		if (payload_len < sizeof(*ack))
			return;

		/*
		 * The instance halted itself; nobody is waiting on it, so
		 * settle its state from here. Deferred to a workqueue
		 * because instance lookup takes a mutex and the CPUs still
		 * need time to reach the park loop, while this runs in IPI
		 * context.
		 */
		aw = kmalloc(sizeof(*aw), GFP_ATOMIC);
		if (!aw)
			break;

		INIT_WORK(&aw->work, mk_halted_work_fn);
		aw->instance_id = ack->resource_id;
		schedule_work(&aw->work);
		break;
	}
	default:
		break;
	}
}

/**
 * multikernel_halt_by_id - Graceful shutdown of a multikernel instance
 * @mk_id: Instance ID to halt
 *
 * Sends a shutdown message to the spawn kernel and waits for acknowledgment.
 * The spawn kernel will stop its own CPUs using native mechanisms.
 *
 * Use when: The spawn kernel is responsive and able to process messages.
 *
 * Returns: 0 on success, negative error code on failure or timeout
 */
int multikernel_halt_by_id(int mk_id)
{
	struct mk_instance *instance;
	struct mk_shutdown_payload payload;
	struct mk_pending_msg *pending;
	int ret;

	instance = mk_instance_find(mk_id);
	if (!instance)
		return -ENOENT;

	if (instance->state != MK_STATE_ACTIVE) {
		mk_instance_put(instance);
		return -EINVAL;
	}

	payload.flags = MK_SHUTDOWN_GRACEFUL;
	payload.sender_instance_id = root_instance->id;

	pending = mk_msg_pending_add(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN, mk_id);
	if (!pending) {
		mk_instance_put(instance);
		return -ENOMEM;
	}

	ret = mk_send_message(mk_id, MK_MSG_SYSTEM, MK_SYS_SHUTDOWN,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);
		mk_instance_put(instance);
		return ret;
	}

	ret = mk_msg_pending_wait(pending, 30000);
	if (ret == 0) {
		if (mk_instance_confirm_parked(instance))
			pr_warn("Multikernel instance %d halted with CPUs unaccounted for\n",
				mk_id);

		mk_instance_set_state(instance, MK_STATE_LOADED);
		pr_info("Multikernel instance %d halted (graceful)\n", mk_id);
	}

	mk_instance_put(instance);
	return ret;
}

static int __mk_instance_force_halt(struct mk_instance *instance,
				    bool allow_loaded)
{
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int cpu_count = 0;
	int ret;

	if (!instance)
		return -EINVAL;

	/*
	 * LOADED is allowed for the retry case: a previous halt already
	 * settled the state, but a CPU that missed its NMI is still
	 * running the old image and kexec refuses to reload it. Without
	 * a rerun the instance is stuck for good.
	 */
	if (instance->state != MK_STATE_ACTIVE &&
	    (!allow_loaded || instance->state != MK_STATE_LOADED)) {
		pr_err("Instance %d not running (state=%d), nothing to force halt\n",
			instance->id, instance->state);
		return -EINVAL;
	}

	if (mk_cpu_set_empty(instance->cpus)) {
		pr_err("Instance %d has no CPUs assigned\n", instance->id);
		return -EINVAL;
	}

	pr_info("Force halting multikernel instance %d via NMI\n",
		instance->id);

	ret = mk_arm_force_halt(instance);
	if (ret)
		pr_err("Failed to arm force-halt marker: %d (sending NMI anyway)\n", ret);

	/* Send NMI to each CPU in the instance */
	mk_cpu_set_for_each(i, phys_cpu, instance->cpus) {
		mk_force_stop_cpu(phys_cpu);
		cpu_count++;
	}

	pr_info("Sent NMI to %d CPUs in instance %d\n",
		cpu_count, instance->id);

	ret = mk_instance_confirm_parked(instance);
	if (ret) {
		pr_err("Instance %d CPUs did not park after force halt: %d\n",
		       instance->id, ret);
		return ret;
	}

	mk_instance_settle_halted(instance);
	return 0;
}

int mk_instance_abort_spawn(struct mk_instance *instance)
{
	int ret;

	ret = __mk_instance_force_halt(instance, true);
	if (ret && instance)
		mk_instance_set_state(instance, MK_STATE_FAILED);
	return ret;
}

/**
 * mk_instance_force_halt - Forcibly stop an instance via NMI
 * @instance: Instance to stop
 *
 * Forces a spawn kernel's CPUs to stop by arming the persistent force-halt
 * marker and sending NMIs directly to each CPU. The NMI handler checks the
 * marker and parks the CPU if it is set.
 *
 * Use when: The spawn kernel is stuck/crashed and not responding to graceful
 * shutdown, or when graceful shutdown has failed.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_force_halt(struct mk_instance *instance)
{
	return __mk_instance_force_halt(instance, false);
}

int multikernel_force_halt_by_id(int mk_id)
{
	struct mk_instance *instance;
	int ret;

	instance = mk_instance_find(mk_id);
	if (!instance)
		return -ENOENT;
	ret = mk_instance_force_halt(instance);
	mk_instance_put(instance);
	return ret;
}

static int __init multikernel_init(void)
{
	int ret;

	if (!root_instance) {
		pr_err("Multikernel root instance is unavailable\n");
		return -ENODEV;
	}

	/* Register NMI handler for forcible shutdown */
	ret = mk_register_stop_nmi_handler();
	if (ret < 0) {
		pr_warn("Failed to register NMI stop handler: %d (force halt unavailable)\n", ret);
		/* Continue anyway - graceful shutdown still works */
	}

	ret = mk_messaging_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel messaging: %d\n", ret);
		return ret;
	}

	ret = mk_register_msg_handler(MK_MSG_SYSTEM, mk_system_msg_handler, NULL);
	if (ret < 0) {
		pr_err("Failed to register system message handler: %d\n", ret);
		mk_messaging_cleanup();
		return ret;
	}

	ret = mk_hotplug_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel hotplug: %d\n", ret);
		mk_unregister_msg_handler(MK_MSG_SYSTEM, mk_system_msg_handler);
		mk_messaging_cleanup();
		return ret;
	}

	ret = mk_kernfs_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel sysfs interface: %d\n", ret);
		mk_hotplug_cleanup();
		mk_unregister_msg_handler(MK_MSG_SYSTEM, mk_system_msg_handler);
		mk_messaging_cleanup();
		return ret;
	}

	ret = mk_ipi_shared_mark_ready(root_instance->ipi_data,
				       root_instance->id);
	if (ret < 0) {
		pr_err("Failed to publish multikernel IPI readiness: %d\n", ret);
		mk_kernfs_cleanup();
		mk_hotplug_cleanup();
		mk_unregister_msg_handler(MK_MSG_SYSTEM, mk_system_msg_handler);
		mk_messaging_cleanup();
		return ret;
	}

	pr_info("Multikernel support initialized\n");
	return 0;
}

/* Initialize multikernel after core kernel subsystems are ready */
subsys_initcall(multikernel_init);
