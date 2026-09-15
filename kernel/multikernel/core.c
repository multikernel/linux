// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bitmap.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/iopoll.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/ratelimit.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include "internal.h"

/* Lock order: transaction -> route write -> ownership -> resources. */
static DEFINE_MUTEX(mk_cpu_transaction_mutex);
static DEFINE_MUTEX(mk_cpu_ownership_mutex);

void mk_cpu_transaction_lock(void)
{
	mutex_lock(&mk_cpu_transaction_mutex);
}

void mk_cpu_transaction_unlock(void)
{
	mutex_unlock(&mk_cpu_transaction_mutex);
}

void mk_cpu_ownership_lock(void)
{
	mutex_lock(&mk_cpu_ownership_mutex);
}

void mk_cpu_ownership_unlock(void)
{
	mutex_unlock(&mk_cpu_ownership_mutex);
}

void mk_cpu_ownership_assert_held(void)
{
	lockdep_assert_held(&mk_cpu_ownership_mutex);
}

static int __mk_instance_migrate_irq_route(struct mk_instance *instance,
					   const struct mk_cpu_set *removing)
{
	mk_phys_cpu_t replacement = MK_PHYS_CPU_INVALID;
	mk_phys_cpu_t route_cpu;
	mk_phys_cpu_t phys_cpu;
	unsigned int i;

	lockdep_assert_held_write(&instance->control_route_sem);
	route_cpu = mk_instance_irq_route_load(instance);
	if (route_cpu == MK_PHYS_CPU_INVALID ||
	    !mk_cpu_set_contains(removing, route_cpu))
		return 0;

	mk_cpu_ownership_lock();
	mk_cpu_set_for_each(i, phys_cpu, instance->cpus) {
		if (!mk_cpu_set_contains(removing, phys_cpu)) {
			replacement = phys_cpu;
			break;
		}
	}
	mk_cpu_ownership_unlock();
	if (replacement == MK_PHYS_CPU_INVALID &&
	    READ_ONCE(instance->state) == MK_STATE_ACTIVE)
		return -EBUSY;

	mutex_lock(&instance->resource_mutex);
	if (replacement != MK_PHYS_CPU_INVALID)
		mk_instance_irq_route_store(instance, replacement);
	mk_pci_sync_instance_irq_route(instance);
	if (replacement == MK_PHYS_CPU_INVALID)
		mk_instance_irq_route_store(instance, MK_PHYS_CPU_INVALID);
	mutex_unlock(&instance->resource_mutex);
	return 0;
}

int mk_instance_migrate_irq_route(struct mk_instance *instance,
				  const struct mk_cpu_set *removing)
{
	int ret;

	if (!instance || !removing)
		return -EINVAL;
	down_write(&instance->control_route_sem);
	ret = __mk_instance_migrate_irq_route(instance, removing);
	up_write(&instance->control_route_sem);
	return ret;
}

static void mk_instance_return_all_cpus(struct mk_instance *instance)
{
	if (!instance || mk_cpu_set_empty(instance->cpus))
		return;

	if (!instance || instance == mk_self || instance->id == 0)
		return;

	mk_instance_return_cpus(instance, instance->cpus);
}

static int mk_instance_return_pci_devices(struct mk_instance *instance)
{
	struct mk_pci_device *pci_dev, *pci_tmp;
	int returned_count = 0;
	int ret;

	if (!instance || instance == mk_self || instance->id == 0)
		return 0;

	ret = mk_pci_release_assignments(instance);
	if (ret)
		return ret;
	if (!instance || !instance->pci_devices_valid)
		return 0;

	if (!mk_self) {
		pr_warn("Cannot return PCI devices from instance %d (%s): no self instance\n",
			instance->id, instance->name);
		goto cleanup;
	}

	/* A spawn's pool is its tree; the device just loses its reserved status */
	if (mk_manifest_phys()) {
		list_for_each_entry(pci_dev, &instance->pci_devices, list) {
			mk_of_pci_take_back(pci_dev->domain, pci_dev->bus,
					    PCI_DEVFN(pci_dev->slot, pci_dev->func));
			returned_count++;
		}
		goto done;
	}

	list_for_each_entry_safe(pci_dev, pci_tmp, &instance->pci_devices, list) {
		struct mk_pci_device *self_dev;

		self_dev = kzalloc_obj(*self_dev, GFP_KERNEL);
		if (!self_dev)
			continue;

		*self_dev = *pci_dev;
		INIT_LIST_HEAD(&self_dev->list);

		list_add_tail(&self_dev->list, &mk_self->pci_devices);
		mk_self->pci_device_count++;
		mk_self->pci_devices_valid = true;

		pr_debug("Returned PCI device %04x:%02x:%02x.%d from instance %d to root\n",
			 self_dev->domain, self_dev->bus, self_dev->slot,
			 self_dev->func, instance->id);

		returned_count++;
	}

done:
	if (returned_count > 0) {
		pr_info("Returned %d PCI devices from instance %d (%s) to self instance\n",
			returned_count, instance->id, instance->name);
	}

cleanup:
	list_for_each_entry_safe(pci_dev, pci_tmp, &instance->pci_devices, list) {
		list_del(&pci_dev->list);
		kfree(pci_dev);
	}
	instance->pci_device_count = 0;
	instance->pci_devices_valid = false;
	return 0;
}

static void mk_instance_return_platform_devices(struct mk_instance *instance)
{
	struct mk_platform_device *device, *tmp;
	int returned = 0;

	if (!instance || instance == mk_self || instance->id == 0)
		return;
	if (!instance->platform_devices_valid &&
	    list_empty(&instance->platform_devices))
		return;

	if (!mk_self) {
		pr_warn("Cannot return platform devices from instance %d (%s): no self instance\n",
			instance->id, instance->name);
		goto cleanup;
	}

	list_for_each_entry_safe(device, tmp, &instance->platform_devices, list) {
		list_move_tail(&device->list, &mk_self->platform_devices);
		mk_self->platform_device_count++;
		mk_self->platform_devices_valid = true;
		returned++;
	}

	if (returned)
		pr_info("Returned %d platform devices from instance %d (%s) to self instance\n",
			returned, instance->id, instance->name);

cleanup:
	list_for_each_entry_safe(device, tmp, &instance->platform_devices, list) {
		list_del(&device->list);
		kfree(device);
	}
	instance->platform_device_count = 0;
	instance->platform_devices_valid = false;
}

/*
 * While a backup that will take a core of this kernel is active, a CPU
 * that stops here saves its registers for it; a plain park needs none.
 */
static atomic_t mk_dump_backups = ATOMIC_INIT(0);

bool mk_crash_notes_wanted(void)
{
	return atomic_read(&mk_dump_backups) > 0;
}
EXPORT_SYMBOL_GPL(mk_crash_notes_wanted);

static void mk_instance_track_dump(struct mk_instance *instance,
				   enum mk_instance_state old,
				   enum mk_instance_state new)
{
	if (!instance->dumps_host)
		return;
	if (new == MK_STATE_ACTIVE)
		atomic_inc(&mk_dump_backups);
	else if (old == MK_STATE_ACTIVE)
		atomic_dec(&mk_dump_backups);
}

int mk_instance_release_resources(struct mk_instance *instance)
{
	int ret;

	if (!instance || instance == mk_self || instance->id == 0)
		return 0;
	ret = mk_instance_return_pci_devices(instance);
	if (ret)
		return ret;
	mk_instance_return_platform_devices(instance);
	mk_instance_return_all_cpus(instance);
	mk_instance_free_memory(instance);
	return 0;
}

static void mk_instance_release(struct kref *kref)
{
	struct mk_instance *instance = container_of(kref, struct mk_instance, refcount);
	int ret;

	pr_info("Releasing multikernel instance %d (%s), returning resources to root\n",
		instance->id, instance->name);
	ret = mk_instance_release_resources(instance);
	if (WARN_ON_ONCE(ret)) {
		pr_crit("Retaining multikernel instance %d (%s) after resource release failed: %d\n",
			instance->id, instance->name, ret);
		return;
	}
	mk_ipi_endpoint_unregister(instance);

	mk_instance_track_dump(instance, instance->state, MK_STATE_READY);
	if (instance->halt_data)
		memunmap(instance->halt_data);
	kfree(instance->host_tree);
	mk_cpu_set_free(instance->cpus);
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
 * mk_instance_alloc - Construct an unpublished instance record
 * @id: Instance ID to record (a later publish may reassign it)
 * @name: Instance name, copied
 *
 * The record is fully initialized but owns no resources and is not
 * yet visible: not in the IDR, the instance list, or kernfs. Until
 * it is published, dispose of it with mk_instance_free(); afterwards
 * it is shared and must go through mk_instance_put().
 *
 * Returns the instance, or NULL on allocation failure.
 */
struct mk_instance *mk_instance_alloc(int id, const char *name)
{
	struct mk_instance *instance;

	instance = kzalloc_obj(*instance, GFP_KERNEL);
	if (!instance)
		return NULL;

	instance->id = id;
	instance->name = kstrdup(name, GFP_KERNEL);
	if (!instance->name)
		goto err_free_instance;

	instance->cpus = mk_cpu_set_alloc();
	if (!instance->cpus)
		goto err_free_name;

	instance->state = MK_STATE_READY;
	init_rwsem(&instance->control_route_sem);
	raw_spin_lock_init(&instance->control_route_lock);
	instance->irq_route_cpu = MK_PHYS_CPU_INVALID;
	instance->ipi_target = MK_PHYS_CPU_INVALID;
	raw_spin_lock_init(&instance->ipi_endpoint.tx_lock);
	raw_spin_lock_init(&instance->ipi_endpoint.rx_lock);
	INIT_LIST_HEAD(&instance->ipi_endpoint.rx_node);
	INIT_LIST_HEAD(&instance->memory_regions);
	INIT_LIST_HEAD(&instance->list);
	INIT_LIST_HEAD(&instance->pci_devices);
	mutex_init(&instance->resource_mutex);
	INIT_LIST_HEAD(&instance->pci_assignments);
	INIT_LIST_HEAD(&instance->platform_devices);
	mk_pci_lease_instance_init(instance);
	kref_init(&instance->refcount);

	return instance;

err_free_name:
	kfree(instance->name);
err_free_instance:
	kfree(instance);
	return NULL;
}

/**
 * mk_instance_publish - Make a constructed instance findable
 * @instance: Instance from mk_instance_alloc()
 *
 * Registers the instance in the IDR under its exact id and adds it
 * to the instance list. On failure the instance is untouched and
 * still owned by the caller.
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_instance_publish(struct mk_instance *instance)
{
	int ret;

	mutex_lock(&mk_instance_mutex);
	ret = idr_alloc(&mk_instance_idr, instance, instance->id,
			instance->id + 1, GFP_KERNEL);
	if (ret < 0) {
		mutex_unlock(&mk_instance_mutex);
		return ret;
	}
	list_add(&instance->list, &mk_instance_list);
	mutex_unlock(&mk_instance_mutex);

	mk_instance_set_state(instance, MK_STATE_READY);
	return 0;
}

/**
 * mk_instance_free - Dispose of a never-published instance record
 * @instance: Instance from mk_instance_alloc(), or NULL
 *
 * Frees the record without returning resources anywhere; a published
 * instance must be dropped with mk_instance_put() instead.
 */
void mk_instance_free(struct mk_instance *instance)
{
	struct mk_pci_device *pci_dev, *pci_tmp;
	struct mk_platform_device *plat_dev, *plat_tmp;

	if (!instance)
		return;

	list_for_each_entry_safe(pci_dev, pci_tmp, &instance->pci_devices, list) {
		list_del(&pci_dev->list);
		kfree(pci_dev);
	}
	list_for_each_entry_safe(plat_dev, plat_tmp, &instance->platform_devices, list) {
		list_del(&plat_dev->list);
		kfree(plat_dev);
	}
	if (instance->halt_data)
		memunmap(instance->halt_data);
	kfree(instance->host_tree);
	mk_cpu_set_free(instance->cpus);
	kfree(instance->name);
	kfree(instance);
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
	mk_instance_track_dump(instance, old_state, state);
	pr_debug("Instance %d (%s) state: %s -> %s\n",
		 instance->id, instance->name,
		 mk_state_to_string(old_state),
		 mk_state_to_string(state));

	/* TODO: Notify status file of state change
	 * We should store a reference to the status file's kernfs node
	 * and call kernfs_notify() on that specific file, not the directory.
	 */
}

void mk_instance_mark_failed(struct mk_instance *instance)
{
	if (!instance)
		return;
	mk_cpu_transaction_lock();
	down_write(&instance->control_route_sem);
	mutex_lock(&instance->resource_mutex);
	mk_instance_set_state(instance, MK_STATE_FAILED);
	mutex_unlock(&instance->resource_mutex);
	up_write(&instance->control_route_sem);
	mk_cpu_transaction_unlock();
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

	/* Empty until the instance first ran, so nothing of it is executing */
	if (!instance->cpus_on_slot)
		return 0;

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
	mk_cpu_set_free(snapshot);

	return failed ? -EBUSY : 0;
}

/**
 * mk_instance_transfer_cpus() - Transfer CPUs from root to instance
 * @instance: Target instance
 * @cpus: Set of physical CPU IDs to transfer
 *
 * Transfers CPUs from self instance to the target instance.
 * Validates that CPUs are available in root.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_transfer_cpus(struct mk_instance *instance,
			       const struct mk_cpu_set *cpus)
{
	struct mk_cpu_set *requested;
	unsigned int i, requested_count;
	mk_phys_cpu_t phys_cpu;
	int unavailable = 0;
	char buf[256];
	int ret;

	if (!cpus || !instance->cpus || !mk_pool) {
		pr_err("Invalid CPU sets for transfer\n");
		return -EINVAL;
	}

	requested = mk_cpu_set_alloc();
	if (!requested)
		return -ENOMEM;

	mk_cpu_transaction_lock();
	down_write(&instance->control_route_sem);
	mk_cpu_ownership_lock();
	ret = mk_cpu_set_copy(requested, cpus);
	if (ret)
		goto out_unlock;

	requested_count = mk_cpu_set_count(requested);
	if (requested_count == 0) {
		pr_info("No CPUs requested for instance %d (%s)\n",
			instance->id, instance->name);
		ret = 0;
		goto out_unlock;
	}

	mk_cpu_set_for_each(i, phys_cpu, requested) {
		if (!mk_cpu_set_contains(mk_pool->cpus, phys_cpu)) {
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
	if (mk_instance_irq_route_load(instance) == MK_PHYS_CPU_INVALID)
		mk_instance_irq_route_store(instance,
					    mk_cpu_set_first(instance->cpus));

	if (unavailable > 0) {
		pr_err("Instance %d (%s): %d CPUs are not available\n",
			instance->id, instance->name, unavailable);
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = mk_cpu_set_reserve(instance->cpus, requested_count);
	if (ret)
		goto out_unlock;

	mk_cpu_set_for_each(i, phys_cpu, requested) {
		mk_cpu_set_del(mk_pool->cpus, phys_cpu);
		mk_cpu_set_add(instance->cpus, phys_cpu);
	}

	mk_cpu_set_format(buf, sizeof(buf), instance->cpus);
	pr_info("Transferred %u CPUs from pool to instance %d (%s): %s\n",
		requested_count, instance->id, instance->name, buf);

	ret = 0;
out_unlock:
	mk_cpu_ownership_unlock();
	up_write(&instance->control_route_sem);
	mk_cpu_transaction_unlock();
	mk_cpu_set_free(requested);
	return ret;
}

/**
 * mk_instance_return_cpus() - Return CPUs from instance back to root
 * @instance: Source instance
 * @cpus: Set of physical CPU IDs to return (may be instance->cpus itself)
 *
 * Transfers CPUs from the instance back to self instance.
 * Validates that CPUs are assigned to the source instance.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_return_cpus(struct mk_instance *instance,
			     const struct mk_cpu_set *cpus)
{
	struct mk_cpu_set *requested;
	unsigned int i, requested_count;
	mk_phys_cpu_t phys_cpu;
	int not_found = 0;
	char buf[256];
	int ret;

	if (!cpus || !instance->cpus || !mk_pool) {
		pr_err("Invalid CPU sets for return\n");
		return -EINVAL;
	}

	requested = mk_cpu_set_alloc();
	if (!requested)
		return -ENOMEM;

	mk_cpu_transaction_lock();
	down_write(&instance->control_route_sem);
	mk_cpu_ownership_lock();
	ret = mk_cpu_set_copy(requested, cpus);
	if (ret)
		goto out_unlock;

	requested_count = mk_cpu_set_count(requested);
	if (requested_count == 0) {
		pr_info("No CPUs requested to return from instance %d (%s)\n",
			instance->id, instance->name);
		ret = 0;
		goto out_unlock;
	}

	/* Validate all CPUs are assigned to this instance */
	mk_cpu_set_for_each(i, phys_cpu, requested) {
		if (!mk_cpu_set_contains(instance->cpus, phys_cpu)) {
			pr_err("CPU %llu not assigned to instance %d (%s)\n",
			       phys_cpu, instance->id, instance->name);
			not_found++;
		}
	}

	if (not_found > 0) {
		pr_err("Instance %d (%s): %d CPUs are not assigned to this instance\n",
			instance->id, instance->name, not_found);
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = mk_cpu_set_reserve(mk_pool->cpus, requested_count);
	if (ret)
		goto out_unlock;

	mk_cpu_set_format(buf, sizeof(buf), requested);
	mk_cpu_ownership_unlock();
	ret = __mk_instance_migrate_irq_route(instance, requested);
	if (ret)
		goto out_route;
	mk_cpu_ownership_lock();

	mk_cpu_set_for_each(i, phys_cpu, requested) {
		mk_cpu_set_add(mk_pool->cpus, phys_cpu);
		mk_cpu_set_del(instance->cpus, phys_cpu);
	}

	pr_info("Returned %u CPUs from instance %d (%s) to the pool: %s\n",
		requested_count, instance->id, instance->name, buf);

	ret = 0;
out_unlock:
	mk_cpu_ownership_unlock();
out_route:
	up_write(&instance->control_route_sem);
	mk_cpu_transaction_unlock();
	mk_cpu_set_free(requested);
	return ret;
}

/**
 * mk_pool_cpus_returned_locked() - Is every pool CPU back in this kernel?
 *
 * True when the pool holds no free CPU and no instance owns one, so
 * nothing can be sitting in a park loop. Pool memory that parked CPUs
 * execute from may only be freed once this holds. The answer is only as
 * good as the invariant that a CPU is recorded in the pool set or in an
 * instance's set before it parks, which is why the move paths reserve
 * room in the destination set up front.
 */
static bool mk_pool_cpus_returned_locked(void)
{
	struct mk_instance *instance;
	bool returned = true;

	lockdep_assert_held(&mk_instance_mutex);
	lockdep_assert_held(&mk_cpu_transaction_mutex);

	if (mk_pool && !mk_cpu_set_empty(mk_pool->cpus))
		return false;

	list_for_each_entry(instance, &mk_instance_list, list) {
		if (instance == mk_self)
			continue;

		if (!mk_cpu_set_empty(instance->cpus) ||
		    !mk_cpu_set_empty(instance->cpus_on_slot)) {
			returned = false;
			break;
		}
	}

	return returned;
}

/**
 * mk_pool_park_teardown() - Safely return the architecture park area
 *
 * Freeze instance membership and CPU ownership while checking that every
 * CPU is home, and keep both frozen until the architecture has returned the
 * executable park area to ordinary pool memory.
 *
 * Returns 0 on success, or -EBUSY while a pool CPU remains assigned or parked.
 */
int mk_pool_park_teardown(void)
{
	int ret;

	mutex_lock(&mk_instance_mutex);
	mk_cpu_transaction_lock();
	if (!mk_pool_cpus_returned_locked())
		ret = -EBUSY;
	else
		ret = mk_arch_pool_park_teardown();
	mk_cpu_transaction_unlock();
	mutex_unlock(&mk_instance_mutex);

	return ret;
}

static int mk_instance_reserve_cpus(struct mk_instance *instance,
				    const struct mk_dt_config *config)
{
	if (!config->cpus) {
		pr_err("No CPU configuration for instance %d (%s)\n",
		       instance->id, instance->name);
		return -EINVAL;
	}

	return mk_instance_transfer_cpus(instance, config->cpus);
}

static int mk_instance_transfer_pci_devices(struct mk_instance *instance,
					     const struct list_head *requested_devices,
					     int requested_count)
{
	if (!mk_self || !mk_self->pci_devices_valid) {
		pr_err("No self instance or PCI devices not initialized\n");
		return -EINVAL;
	}

	if (requested_count == 0 || list_empty(requested_devices)) {
		pr_info("No PCI devices requested for instance %d (%s)\n",
			instance->id, instance->name);
		instance->pci_devices_valid = true;
		return 0;
	}

	/* Nested kernels cannot establish the host-owned VF lifecycle. */
	if (mk_manifest_phys())
		return -EOPNOTSUPP;

	return mk_pci_assign_devices(instance, requested_devices,
				     requested_count);
}

static int mk_instance_reserve_pci_devices(struct mk_instance *instance,
					   const struct mk_dt_config *config)
{
	if (!config->pci_devices_valid) {
		if (config->pci_device_count || !list_empty(&config->pci_devices))
			return -EINVAL;
		instance->pci_devices_valid = true;
		return 0;
	}
	if (!config->pci_device_count) {
		if (!list_empty(&config->pci_devices))
			return -EINVAL;
		instance->pci_devices_valid = true;
		instance->pci_device_count = 0;
		pr_debug("No PCI devices to reserve for instance %d (%s)\n",
			 instance->id, instance->name);
		return 0;
	}
	if (list_empty(&config->pci_devices))
		return -EINVAL;

	return mk_instance_transfer_pci_devices(instance,
						&config->pci_devices,
						config->pci_device_count);
}

static int mk_instance_transfer_platform_devices(struct mk_instance *instance,
						 const struct list_head *requested_devices,
						 int requested_count)
{
	struct mk_platform_device *requested, *other, *self_device;
	int actual_count = 0;
	int transferred = 0;

	if (!mk_self || !mk_self->platform_devices_valid) {
		pr_err("No self instance or platform devices not initialized\n");
		return -EINVAL;
	}

	if (requested_count <= 0 || list_empty(requested_devices))
		return -EINVAL;

	list_for_each_entry(requested, requested_devices, list) {
		actual_count++;
		list_for_each_entry(other, requested_devices, list) {
			if (other == requested)
				break;
			if (!strcmp(other->name, requested->name))
				return -EINVAL;
		}
		self_device = NULL;
		list_for_each_entry(other, &mk_self->platform_devices, list) {
			if (!strcmp(other->name, requested->name)) {
				self_device = other;
				break;
			}
		}
		if (!self_device)
			return -ENOENT;
	}
	if (actual_count != requested_count)
		return -EINVAL;

	list_for_each_entry(requested, requested_devices, list) {
		self_device = NULL;
		list_for_each_entry(other, &mk_self->platform_devices, list) {
			if (!strcmp(other->name, requested->name)) {
				self_device = other;
				break;
			}
		}
		if (!self_device)
			goto rollback;
		list_move_tail(&self_device->list, &instance->platform_devices);
		mk_self->platform_device_count--;
		instance->platform_device_count++;
		transferred++;
	}

	instance->platform_devices_valid = true;
	pr_info("Transferred %d platform devices from self to instance %d (%s)\n",
		transferred, instance->id, instance->name);

	return 0;

rollback:
	mk_instance_return_platform_devices(instance);
	return -EIO;
}

static int mk_instance_reserve_platform_devices(struct mk_instance *instance,
						const struct mk_dt_config *config)
{
	if (!config->platform_devices_valid) {
		if (config->platform_device_count ||
		    !list_empty(&config->platform_devices))
			return -EINVAL;
		instance->platform_devices_valid = true;
		return 0;
	}
	if (!config->platform_device_count) {
		if (!list_empty(&config->platform_devices))
			return -EINVAL;
		instance->platform_devices_valid = true;
		instance->platform_device_count = 0;
		pr_debug("No platform devices to reserve for instance %d (%s)\n",
			 instance->id, instance->name);
		return 0;
	}
	if (list_empty(&config->platform_devices))
		return -EINVAL;

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
 * Transfers a single PCI device from self instance to the specified instance.
 * Used for dynamic PCI device hotplug to non-running instances.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_add_pci_device(struct mk_instance *instance,
			       u16 domain, u8 bus, u8 devfn)
{
	if (mk_manifest_phys())
		return -EOPNOTSUPP;
	return mk_pci_assign_device(instance, domain, bus, devfn);
}

/**
 * mk_instance_remove_pci_device - Remove a single PCI device from an instance
 * @instance: Target instance
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * Returns a single PCI device from the specified instance back to self instance.
 * Used for dynamic PCI device hotplug from non-running instances.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_remove_pci_device(struct mk_instance *instance,
				  u16 domain, u8 bus, u8 devfn)
{
	if (mk_manifest_phys())
		return -EOPNOTSUPP;
	return mk_pci_unassign_device(instance, domain, bus, devfn);
}

/**
 * mk_root_has_pci_device - Test whether a PCI device is free in the root pool
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * Returns: true when the device is listed on the self instance
 */
bool mk_root_has_pci_device(u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *self_dev;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);

	if (mk_manifest_phys())
		return mk_of_pci_available(domain, bus, devfn);

	if (!mk_self || !mk_self->pci_devices_valid)
		return false;

	list_for_each_entry(self_dev, &mk_self->pci_devices, list) {
		if (self_dev->domain == domain &&
		    self_dev->bus == bus &&
		    self_dev->slot == slot &&
		    self_dev->func == func)
			return true;
	}

	return false;
}

/**
 * mk_root_add_pci_device - List a PCI device as free in the root pool
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 * @alias: Stable name for the device tree /aliases node, NULL or "" for none
 *
 * Returns: 0 on success, -EINVAL if there is no self instance, -EEXIST if
 * already listed, -ENODEV if the device does not exist, -ENOMEM on allocation
 * failure
 */
int mk_root_add_pci_device(u16 domain, u8 bus, u8 devfn, const char *alias)
{
	struct mk_pci_device *self_dev;
	struct pci_dev *pdev;

	if (!mk_self)
		return -EINVAL;

	if (mk_root_has_pci_device(domain, bus, devfn))
		return -EEXIST;

	pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
	if (!pdev)
		return -ENODEV;

	self_dev = kzalloc_obj(*self_dev, GFP_KERNEL);
	if (!self_dev) {
		pci_dev_put(pdev);
		return -ENOMEM;
	}

	self_dev->domain = domain;
	self_dev->bus = bus;
	self_dev->slot = PCI_SLOT(devfn);
	self_dev->func = PCI_FUNC(devfn);
	self_dev->vendor = pdev->vendor;
	self_dev->device = pdev->device;
	if (alias)
		strscpy(self_dev->alias, alias, sizeof(self_dev->alias));
	INIT_LIST_HEAD(&self_dev->list);
	pci_dev_put(pdev);

	list_add_tail(&self_dev->list, &mk_self->pci_devices);
	mk_self->pci_device_count++;
	mk_self->pci_devices_valid = true;

	pr_info("PCI device %04x:%04x@%04x:%02x:%02x.%x is free in the root pool\n",
		self_dev->vendor, self_dev->device, domain, bus,
		self_dev->slot, self_dev->func);
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
	struct mk_pci_device *self_dev, *tmp;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);

	if (!mk_self || !mk_self->pci_devices_valid)
		return -ENOENT;

	list_for_each_entry_safe(self_dev, tmp, &mk_self->pci_devices, list) {
		if (self_dev->domain == domain &&
		    self_dev->bus == bus &&
		    self_dev->slot == slot &&
		    self_dev->func == func) {
			list_del(&self_dev->list);
			kfree(self_dev);
			mk_self->pci_device_count--;
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

	if (!mk_self) {
		pr_err("No self instance - cannot transfer memory\n");
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
 * future instance allocations (including mk_self).
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
		 * The arch's boot structures are all carved from the control
		 * block, so they are returned to the pool as one allocation
		 * rather than individually. Freeing them piecemeal would punch
		 * holes in the block's bitmap and leave the rest of it
		 * allocated. The arch moves CPUs still parked in this
		 * instance's memory back to the host pool before the block
		 * goes away.
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
			mk_instance_mem_free(instance, instance->ctrl_va,
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

static bool mk_instance_resources_empty(const struct mk_instance *instance)
{
	return list_empty(&instance->memory_regions) &&
	       !instance->instance_pool && !instance->region_count &&
	       mk_cpu_set_empty(instance->cpus) &&
	       list_empty(&instance->pci_devices) &&
	       list_empty(&instance->pci_assignments) &&
	       !instance->pci_device_count &&
	       list_empty(&instance->platform_devices) &&
	       !instance->platform_device_count;
}

/**
 * mk_instance_reserve_resources() - Atomically reserve instance resources
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
	const char *failed_resource;
	int release_ret;
	int ret;

	if (!config || !instance || !instance->cpus) {
		pr_err("Invalid parameters to mk_instance_reserve_resources\n");
		return -EINVAL;
	}
	if (!mk_instance_resources_empty(instance))
		return -EBUSY;

	/* Reserve memory regions */
	failed_resource = "memory";
	ret = mk_instance_reserve_memory(instance, config);
	if (ret)
		goto rollback;

	/* Reserve CPU resources */
	failed_resource = "CPU";
	ret = mk_instance_reserve_cpus(instance, config);
	if (ret)
		goto rollback;

	/* Reserve platform device resources */
	failed_resource = "platform device";
	ret = mk_instance_reserve_platform_devices(instance, config);
	if (ret)
		goto rollback;

	/* Commit fallible exclusive VF leases last. */
	failed_resource = "PCI device";
	ret = mk_instance_reserve_pci_devices(instance, config);
	if (ret)
		goto rollback;

	return 0;

rollback:
	pr_err("Failed to reserve %s resources for instance %d (%s): %d\n",
	       failed_resource, instance->id, instance->name, ret);
	release_ret = mk_instance_release_resources(instance);
	if (release_ret) {
		mk_instance_set_state(instance, MK_STATE_FAILED);
		return release_ret;
	}
	if (WARN_ON_ONCE(!mk_instance_resources_empty(instance))) {
		mk_instance_set_state(instance, MK_STATE_FAILED);
		return -EIO;
	}
	return ret;
}

/**
 * Per-instance memory pool management
 */

/**
 * mk_instance_ctrl_alloc() - Allocate from the instance control block
 * @instance: Instance to allocate from
 * @size: Allocation size
 * @align: Required alignment
 *
 * The arch's boot structures (spawn context, trampolines, park area) live
 * in instance memory, which the spawn kernel sees as RAM. They are carved
 * from one contiguous block so the spawn kernel can reserve it from its
 * allocator with a single entry; otherwise its page allocator recycles them
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
		void *va = mk_instance_mem_alloc(instance, MK_CTRL_BLOCK_SIZE,
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

/**
 * mk_instance_mem_alloc() - Allocate memory from instance pool
 * @instance: Instance to allocate from
 * @size: Size to allocate
 * @align: Alignment requirement (must be power of 2)
 *
 * Returns virtual address of allocated memory, or NULL on failure.
 * The returned address is a direct-mapped kernel virtual address,
 * which can be converted back to physical using virt_to_phys().
 */
void *mk_instance_mem_alloc(struct mk_instance *instance, size_t size, size_t align)
{
	phys_addr_t phys_addr;
	void *virt_addr;

	if (!instance || !instance->instance_pool) {
		pr_debug("%s: instance %p has no pool\n", __func__, instance);
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
 * mk_instance_mem_free() - Free memory back to instance pool
 * @instance: Instance to free to
 * @virt_addr: Virtual address to free
 * @size: Size to free
 */
void mk_instance_mem_free(struct mk_instance *instance, void *virt_addr, size_t size)
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

	return mk_instance_mem_alloc(image->mk_instance, size, align);
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

	mk_instance_mem_free(image->mk_instance, virt_addr, size);
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
	int sender_instance_id;
};

static struct mk_shutdown_work mk_shutdown_work;
static atomic_t mk_shutdown_work_pending = ATOMIC_INIT(0);


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
	ack.resource_id = mk_self->id;

	mk_send_message(target_id, MK_MSG_SYSTEM, subtype, &ack, sizeof(ack));

	pr_info("Multikernel instance %d shutting down\n", mk_self->id);

	/*
	 * Enter pool state: every CPU parks where the host can re-spawn
	 * it later. Use wait=0 since mk_enter_pool_state() never returns.
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
	int parent_id;

	if (!host_instance)
		panic("multikernel: spawned kernel has no parent instance");
	parent_id = READ_ONCE(host_instance->id);
	mk_notify_down_and_park(parent_id, MK_SYS_HALTED);
}

static void mk_shutdown_work_fn(struct work_struct *work)
{
	struct mk_shutdown_work *sw =
		container_of(work, struct mk_shutdown_work, work);
	int sender_instance_id = sw->sender_instance_id;

	mk_notify_down_and_park(sender_instance_id, MK_SYS_SHUTDOWN_ACK);
}

/*
 * Mark a halted instance re-spawnable. No wakeups are published here:
 * the instance's CPUs may still be on their way to the park loop, and
 * poking its context while its (old or next) kernel also publishes on
 * it corrupts the single-producer mailbox. The kexec path confirms the
 * CPUs are parked before it rewrites the image.
 */
static int mk_instance_settle_halted(struct mk_instance *instance)
{
	int ret;

	pr_info("Instance %d (%s) halted, CPUs parking in pool\n",
		instance->id, instance->name);
	ret = mk_instance_confirm_parked(instance);
	if (ret)
		return ret;
	mk_cpu_transaction_lock();
	down_write(&instance->control_route_sem);
	mutex_lock(&instance->resource_mutex);
	ret = mk_pci_quiesce_instance_irqs(instance, true);
	mk_instance_irq_route_store(instance, MK_PHYS_CPU_INVALID);
	mk_instance_set_state(instance, ret ? MK_STATE_FAILED : MK_STATE_LOADED);
	mutex_unlock(&instance->resource_mutex);
	up_write(&instance->control_route_sem);
	mk_cpu_transaction_unlock();
	return ret;
}

struct mk_halted_work {
	struct work_struct work;
	unsigned int pool_slot;
	int instance_id;
};

static struct mk_halted_work *mk_halted_work_pool;
static unsigned long *mk_halted_work_pool_busy;
static unsigned int mk_halted_work_pool_size;
static atomic_t mk_halted_work_pool_cursor = ATOMIC_INIT(0);
static struct workqueue_struct *mk_system_workqueue;
static atomic64_t mk_system_work_dropped = ATOMIC64_INIT(0);
static DEFINE_RATELIMIT_STATE(mk_system_work_rs,
			     DEFAULT_RATELIMIT_INTERVAL,
			     DEFAULT_RATELIMIT_BURST);

static void mk_system_work_drop(void)
{
	atomic64_inc(&mk_system_work_dropped);
	if (__ratelimit(&mk_system_work_rs))
		printk_deferred("WARNING: Multikernel system work request dropped\n");
}

static struct mk_halted_work *mk_halted_work_get(void)
{
	unsigned int start;
	unsigned int slot;
	unsigned int i;

	start = (unsigned int)atomic_inc_return(&mk_halted_work_pool_cursor);
	for (i = 0; i < mk_halted_work_pool_size; i++) {
		slot = (start + i) % mk_halted_work_pool_size;
		if (!test_and_set_bit_lock(slot, mk_halted_work_pool_busy))
			return &mk_halted_work_pool[slot];
	}

	mk_system_work_drop();
	return NULL;
}

static void mk_halted_work_put(struct mk_halted_work *aw)
{
	clear_bit_unlock(aw->pool_slot, mk_halted_work_pool_busy);
}

static void mk_halted_work_fn(struct work_struct *work)
{
	struct mk_halted_work *aw =
		container_of(work, struct mk_halted_work, work);
	struct mk_instance *instance;

	instance = mk_instance_find(aw->instance_id);
	if (instance) {
		if (mk_instance_settle_halted(instance))
			pr_err("Instance %d halted but could not be made reusable\n",
			       instance->id);
		mk_instance_put(instance);
	} else {
		pr_warn("Shutdown ACK from unknown instance %d\n",
			aw->instance_id);
	}

	mk_halted_work_put(aw);
}

static void mk_system_msg_handler(u32 msg_type, u32 subtype,
				  void *payload, u32 payload_len,
				  s32 sender_instance_id, void *ctx)
{
	if (msg_type != MK_MSG_SYSTEM)
		return;

	switch (subtype) {
	case MK_SYS_SHUTDOWN: {
		if (payload_len < sizeof(struct mk_shutdown_payload))
			return;

		pr_info("Shutdown requested by instance %d\n", sender_instance_id);

		if (atomic_cmpxchg(&mk_shutdown_work_pending, 0, 1)) {
			mk_system_work_drop();
			return;
		}

		mk_shutdown_work.sender_instance_id = sender_instance_id;
		if (!queue_work(mk_system_workqueue, &mk_shutdown_work.work))
			mk_system_work_drop();
		break;
	}
	case MK_SYS_SHUTDOWN_ACK: {
		struct mk_resource_ack *ack = payload;

		if (payload_len < sizeof(*ack))
			return;
		if (ack->resource_id != sender_instance_id)
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
		if (ack->resource_id != sender_instance_id)
			return;

		/*
		 * The instance halted itself; nobody is waiting on it, so
		 * settle its state from here. Deferred to a workqueue
		 * because instance lookup takes a mutex and the CPUs still
		 * need time to reach the park loop, while this runs in IPI
		 * context.
		 */
		aw = mk_halted_work_get();
		if (!aw)
			break;

		aw->instance_id = sender_instance_id;
		if (!queue_work(mk_system_workqueue, &aw->work)) {
			mk_halted_work_put(aw);
			mk_system_work_drop();
		}
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
	payload.sender_instance_id = mk_self->id;

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
		ret = mk_instance_settle_halted(instance);
		if (!ret)
			pr_info("Multikernel instance %d halted (graceful)\n", mk_id);
	}

	mk_instance_put(instance);
	return ret;
}

/*
 * multikernel_force_halt_by_id - Forcible shutdown of a multikernel instance via NMI
 * @mk_id: Instance ID to halt
 *
 * Forces a spawn kernel's CPUs to stop by arming the force-halt marker
 * in the instance's shared IPI area and sending NMIs directly to each
 * CPU. The NMI handler tests the marker and parks the CPU in the pool.
 *
 * No message is queued and no doorbell is rung: a ring message is
 * consumed by the instance's ordinary interrupt path, which on a
 * responsive kernel races the NMIs for it and can leave them with
 * nothing to act on. The marker is host-owned and survives until the
 * instance is re-executed, so the NMIs act on it regardless of timing.
 *
 * Use when: The spawn kernel is stuck/crashed and not responding to graceful
 * shutdown, or when graceful shutdown has failed. May be repeated: an
 * already-halted instance absorbs the NMIs in the park loop, so a rerun
 * only rescues CPUs an earlier halt missed.
 *
 * Returns: 0 on success, negative error code on failure
 */
/*
 * Build the set of physical CPUs a force halt should NMI. For a child
 * it is exactly what the child owns. For the parent we do not know the
 * split between the parent's own CPUs and its free pool, and do not
 * need to: every CPU this kernel does not own is a target, and one
 * already parked in the pool absorbs the extra NMI harmlessly.
 */
static int mk_force_halt_targets(struct mk_instance *instance,
				 struct mk_cpu_set *targets)
{
	int cpu;

	if (instance != host_instance)
		return mk_cpu_set_copy(targets, instance->cpus);

	for_each_possible_cpu(cpu) {
		mk_phys_cpu_t phys = arch_cpu_physical_id(cpu);
		int ret;

		if (mk_cpu_set_contains(mk_self->cpus, phys))
			continue;
		ret = mk_cpu_set_add(targets, phys);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * A CPU's dense index into the presence table: its rank in the sorted
 * list of every possible physical CPU id. Both the parking CPU and the
 * kernel confirming the fence compute it from the same cpu_possible
 * set, so they agree without sharing an APIC-id-to-slot map, and the
 * table stays CPU-count sized whatever the ids are.
 */
int mk_cpu_rank(mk_phys_cpu_t phys)
{
	int cpu, rank = 0;

	for_each_possible_cpu(cpu)
		if (arch_cpu_physical_id(cpu) < phys)
			rank++;
	return rank;
}
EXPORT_SYMBOL_GPL(mk_cpu_rank);

/* How many fence targets have not yet recorded presence */
static int mk_fence_missing(struct mk_instance *instance,
			    struct mk_cpu_set *targets)
{
	struct mk_shared_data *sd = mk_instance_halt_data(instance);
	mk_phys_cpu_t phys;
	unsigned int i;
	int missing = 0;

	mk_cpu_set_for_each(i, phys, targets) {
		int rank = mk_cpu_rank(phys);

		if (rank >= MK_PARKED_MAX || !READ_ONCE(sd->parked[rank]))
			missing++;
	}
	return missing;
}

/*
 * After NMIing the fence targets, confirm each reached the park loop
 * by the presence byte it sets there, and record the arrivals in
 * cpus_on_slot. A target still missing after the timeout never took
 * the NMI (wedged in NMI context) and leaves the fence incomplete:
 * -ETIMEDOUT, so no foreign baseline claims a machine with a CPU
 * possibly still running the dead host.
 */
static int mk_confirm_fenced(struct mk_instance *instance,
			     struct mk_cpu_set *targets)
{
	struct mk_shared_data *sd = mk_instance_halt_data(instance);
	mk_phys_cpu_t phys;
	unsigned int i;
	int missing, ret;

	if (!sd)
		return -ENODEV;

	if (!instance->cpus_on_slot) {
		instance->cpus_on_slot = mk_cpu_set_alloc();
		if (!instance->cpus_on_slot)
			return -ENOMEM;
	}

	ret = read_poll_timeout(mk_fence_missing, missing, !missing,
				20 * USEC_PER_MSEC, 5 * USEC_PER_SEC, false,
				instance, targets);

	mk_cpu_set_for_each(i, phys, targets) {
		int rank = mk_cpu_rank(phys);

		if (rank < MK_PARKED_MAX && READ_ONCE(sd->parked[rank]))
			mk_cpu_set_add(instance->cpus_on_slot, phys);
	}

	if (ret)
		pr_err("Fence incomplete: %d of the host's CPUs never parked\n",
		       missing);
	else
		pr_info("Host fenced: %u CPUs confirmed parked\n",
			mk_cpu_set_count(instance->cpus_on_slot));
	return ret;
}

static int __mk_instance_force_halt(struct mk_instance *instance,
				    bool allow_loaded)
{
	struct mk_cpu_set *targets;
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int cpu_count = 0;
	int ret;

	if (!instance)
		return -EINVAL;

	if (instance == mk_self) {
		pr_err("Cannot force halt this kernel (id %d)\n", instance->id);
		return -EINVAL;
	}

	/*
	 * LOADED is allowed for the retry case: a previous halt already
	 * settled the state, but a CPU that missed its NMI is still
	 * running the old image and kexec refuses to reload it. Without
	 * a rerun the instance is stuck for good. The parent is ACTIVE.
	 */
	if (instance->state != MK_STATE_ACTIVE &&
	    (!allow_loaded || instance->state != MK_STATE_LOADED)) {
		pr_err("Instance %d not running (state=%d), nothing to force halt\n",
			instance->id, instance->state);
		return -EINVAL;
	}

	targets = mk_cpu_set_alloc();
	if (!targets)
		return -ENOMEM;
	ret = mk_force_halt_targets(instance, targets);
	if (!ret && mk_cpu_set_empty(targets))
		ret = -EINVAL;
	if (ret) {
		pr_err("Instance %d: no force-halt targets: %d\n",
		       instance->id, ret);
		mk_cpu_set_free(targets);
		return ret;
	}

	pr_info("Force halting multikernel instance %d via NMI\n",
		instance->id);

	ret = mk_arm_force_halt(instance);
	if (ret)
		pr_err("Failed to arm force-halt marker: %d (sending NMI anyway)\n", ret);

	mk_cpu_set_for_each(i, phys_cpu, targets) {
		mk_force_stop_cpu(phys_cpu);
		cpu_count++;
	}

	pr_info("Sent NMI to %d CPUs in instance %d\n",
		cpu_count, instance->id);

	/*
	 * A child instance parks on its own context, so wait for it to
	 * settle exactly as the graceful path does. Fencing the host has
	 * no such settle: confirm each target actually reached the park
	 * loop through the presence it records in the shared area, and
	 * record the ones that did in cpus_on_slot, the gate a later
	 * foreign baseline checks. A target that never parks fails the
	 * fence, so a baseline cannot claim a machine with a CPU still
	 * running the dead host.
	 */
	if (instance == host_instance) {
		ret = mk_confirm_fenced(instance, targets);
	} else {
		ret = mk_instance_confirm_parked(instance);
		if (ret)
			pr_err("Instance %d CPUs did not park after force halt: %d\n",
			       instance->id, ret);
		else
			ret = mk_instance_settle_halted(instance);
	}

	mk_cpu_set_free(targets);
	return ret;
}

int mk_instance_abort_spawn(struct mk_instance *instance)
{
	int ret;

	mk_ipi_endpoint_close(instance);
	ret = __mk_instance_force_halt(instance, true);
	if (ret && instance)
		mk_instance_mark_failed(instance);
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

static int __init mk_system_work_init(void)
{
	unsigned int pool_size;
	unsigned int i;

	INIT_WORK(&mk_shutdown_work.work, mk_shutdown_work_fn);
	atomic_set(&mk_shutdown_work_pending, 0);

	/* Allow every possible CPU to have all reply slots in flight. */
	pool_size = max_t(unsigned int, num_possible_cpus(), 1) *
			MK_REPLY_SLOTS;
	mk_halted_work_pool = kcalloc(pool_size, sizeof(*mk_halted_work_pool),
				      GFP_KERNEL);
	if (!mk_halted_work_pool)
		return -ENOMEM;

	mk_halted_work_pool_busy = bitmap_zalloc(pool_size, GFP_KERNEL);
	if (!mk_halted_work_pool_busy)
		goto free_pool;
	mk_halted_work_pool_size = pool_size;
	atomic_set(&mk_halted_work_pool_cursor, 0);
	for (i = 0; i < pool_size; i++) {
		INIT_WORK(&mk_halted_work_pool[i].work, mk_halted_work_fn);
		mk_halted_work_pool[i].pool_slot = i;
	}

	mk_system_workqueue =
		alloc_workqueue("mk-system", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!mk_system_workqueue)
		goto free_pool_bitmap;

	return 0;

free_pool_bitmap:
	bitmap_free(mk_halted_work_pool_busy);
	mk_halted_work_pool_busy = NULL;
	mk_halted_work_pool_size = 0;
free_pool:
	kfree(mk_halted_work_pool);
	mk_halted_work_pool = NULL;
	return -ENOMEM;
}

static void mk_system_work_cleanup(void)
{
	if (mk_system_workqueue) {
		destroy_workqueue(mk_system_workqueue);
		mk_system_workqueue = NULL;
	}
	WARN_ON_ONCE(mk_halted_work_pool_busy &&
		     !bitmap_empty(mk_halted_work_pool_busy,
				   mk_halted_work_pool_size));
	bitmap_free(mk_halted_work_pool_busy);
	mk_halted_work_pool_busy = NULL;
	mk_halted_work_pool_size = 0;
	kfree(mk_halted_work_pool);
	mk_halted_work_pool = NULL;
}

static int __init multikernel_init(void)
{
	int ret;

	ret = mk_pci_lease_system_init();
	if (ret)
		return ret;

	ret = mk_messaging_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel messaging: %d\n", ret);
		mk_pci_lease_system_cleanup();
		return ret;
	}

	ret = mk_system_work_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel system work: %d\n", ret);
		mk_messaging_cleanup();
		mk_pci_lease_system_cleanup();
		return ret;
	}

	ret = mk_register_msg_handler(MK_MSG_SYSTEM, mk_system_msg_handler, NULL);
	if (ret < 0) {
		pr_err("Failed to register system message handler: %d\n", ret);
		mk_system_work_cleanup();
		mk_messaging_cleanup();
		mk_pci_lease_system_cleanup();
		return ret;
	}

	ret = mk_hotplug_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel hotplug: %d\n", ret);
		mk_unregister_msg_handler(MK_MSG_SYSTEM, mk_system_msg_handler);
		mk_system_work_cleanup();
		mk_messaging_cleanup();
		mk_pci_lease_system_cleanup();
		return ret;
	}

	ret = mk_kernfs_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel sysfs interface: %d\n", ret);
		mk_hotplug_cleanup();
		mk_unregister_msg_handler(MK_MSG_SYSTEM, mk_system_msg_handler);
		mk_system_work_cleanup();
		mk_messaging_cleanup();
		mk_pci_lease_system_cleanup();
		return ret;
	}

	mk_ipi_handlers_enable();

	pr_info("Multikernel support initialized\n");
	return 0;
}

/* Initialize multikernel after core kernel subsystems are ready */
subsys_initcall(multikernel_init);
