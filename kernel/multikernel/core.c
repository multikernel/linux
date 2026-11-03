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
#include <linux/iopoll.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/rcupdate.h>
#include "internal.h"

int mk_instance_idr_add(struct mk_instance *instance, int start, int end)
{
	int id;

	lockdep_assert_held(&mk_instance_mutex);
	/* Reserve an empty slot; RCU readers must see the initialized ID. */
	id = idr_alloc(&mk_instance_idr, NULL, start, end, GFP_KERNEL);
	if (id >= 0) {
		instance->id = id;
		idr_replace(&mk_instance_idr, instance, id);
	}
	return id;
}

void mk_instance_idr_remove(int id)
{
	lockdep_assert_held(&mk_instance_mutex);
	idr_remove(&mk_instance_idr, id);
}

int mk_instance_prepare_destroy(struct mk_instance *instance)
{
	int ret;

	lockdep_assert_held(&mk_overlay_mutex);
	ret = mk_instance_confirm_parked(instance);
	if (ret)
		return ret;
	ret = mk_arch_release_instance(instance);
	if (ret)
		return ret;

	if (mk_cpu_set_empty(instance->cpus))
		return 0;
	/* Bookkeeping only: no firmware/park waits under the registry mutex. */
	mutex_lock(&mk_instance_mutex);
	ret = mk_instance_return_cpus(instance, instance->cpus);
	mutex_unlock(&mk_instance_mutex);
	return ret;
}

static void mk_instance_return_pci_devices(struct mk_instance *instance)
{
	struct mk_pci_device *pci_dev, *pci_tmp;
	int returned_count = 0;

	if (!instance || !instance->pci_devices_valid)
		return;

	if (instance == mk_self || instance->id == 0)
		return;

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
}

static void mk_instance_return_platform_devices(struct mk_instance *instance)
{
	struct mk_platform_device *plat_dev, *plat_tmp;
	int returned_count = 0;

	if (!instance || !instance->platform_devices_valid)
		return;

	if (instance == mk_self || instance->id == 0)
		return;

	if (!mk_self) {
		pr_warn("Cannot return platform devices from instance %d (%s): no self instance\n",
			instance->id, instance->name);
		goto cleanup;
	}

	list_for_each_entry_safe(plat_dev, plat_tmp, &instance->platform_devices, list) {
		struct mk_platform_device *self_dev;

		self_dev = kzalloc_obj(*self_dev, GFP_KERNEL);
		if (!self_dev)
			continue;

		*self_dev = *plat_dev;
		INIT_LIST_HEAD(&self_dev->list);

		list_add_tail(&self_dev->list, &mk_self->platform_devices);
		mk_self->platform_device_count++;
		mk_self->platform_devices_valid = true;

		pr_debug("Returned platform device '%s' from instance %d to root\n",
			 self_dev->name, instance->id);

		returned_count++;
	}

	if (returned_count > 0) {
		pr_info("Returned %d platform devices from instance %d (%s) to self instance\n",
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

/**
 * mk_instance_alloc_boot_pages() - Allocate the pages a spawn boots with
 * @instance: Host-side instance being loaded
 *
 * The manifest page and the IPI ring live as long as the instance, across
 * loads, unloads and re-spawns. Allocating them again is a no-op.
 *
 * Returns 0 on success, -ENOMEM on failure.
 */
int mk_instance_alloc_boot_pages(struct mk_instance *instance)
{
	struct page *manifest, *ring;
	unsigned int ring_order = get_order(sizeof(struct mk_shared_data));

	if (instance->manifest_phys)
		return 0;

	manifest = alloc_pages(GFP_KERNEL | __GFP_ZERO, get_order(MK_MANIFEST_SIZE));
	if (!manifest)
		return -ENOMEM;
	ring = alloc_pages(GFP_KERNEL | __GFP_ZERO, ring_order);
	if (!ring) {
		__free_pages(manifest, get_order(MK_MANIFEST_SIZE));
		return -ENOMEM;
	}

	instance->ipi_phys = page_to_phys(ring);
	instance->ipi_pages = PAGE_ALIGN(sizeof(struct mk_shared_data)) >> PAGE_SHIFT;
	instance->manifest_phys = page_to_phys(manifest);
	return 0;
}

static void mk_instance_free_boot_pages(struct mk_instance *instance)
{
	if (!instance->manifest_phys)
		return;

	__free_pages(phys_to_page(instance->ipi_phys),
		     get_order(sizeof(struct mk_shared_data)));
	__free_pages(phys_to_page(instance->manifest_phys),
		     get_order(MK_MANIFEST_SIZE));
	instance->ipi_data = NULL;
	instance->ipi_phys = 0;
	instance->manifest_phys = 0;
}

int mk_instance_retire_resources(struct mk_instance *instance)
{
	lockdep_assert_held(&mk_overlay_mutex);
	mk_instance_return_pci_devices(instance);
	mk_instance_return_platform_devices(instance);
	return mk_instance_free_memory(instance);
}

static void mk_instance_release_work(struct work_struct *work)
{
	struct mk_instance *instance = container_of(work, struct mk_instance, release_work);
	int ret;

	/* Drain lookups that saw this record but did not acquire a reference. */
	synchronize_rcu();
	mutex_lock(&mk_overlay_mutex);
	if (instance->state != MK_STATE_READY || instance->kimage) {
		pr_err("Instance %d final release refused: not reusable; retaining allocations\n",
		       instance->id);
		mutex_unlock(&mk_overlay_mutex);
		return;
	}

	pr_info("Releasing multikernel instance %d (%s), returning resources to root\n",
		instance->id, instance->name);

	ret = mk_instance_prepare_destroy(instance);
	if (ret) {
		pr_err("Instance %d final release refused: %d; retaining allocations\n",
		       instance->id, ret);
		mutex_unlock(&mk_overlay_mutex);
		return;
	}
	ret = mk_instance_retire_resources(instance);
	if (ret) {
		pr_err("Instance %d final retirement failed: %d; retaining allocations\n",
		       instance->id, ret);
		mutex_unlock(&mk_overlay_mutex);
		return;
	}
	mk_instance_free_boot_pages(instance);

	mk_instance_track_dump(instance, instance->state, MK_STATE_READY);
	kfree(instance->host_tree);
	mk_cpu_set_free(instance->cpus);
	kfree(instance->name);
	kfree(instance);
	mutex_unlock(&mk_overlay_mutex);
}

static void mk_instance_release(struct kref *kref)
{
	struct mk_instance *instance = container_of(kref, struct mk_instance, refcount);

	/* A ring sender can drop the last reference from hard-IPI context. */
	INIT_WORK(&instance->release_work, mk_instance_release_work);
	schedule_work(&instance->release_work);
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

static void mk_halted_work_fn(struct work_struct *work);

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
	instance->ipi_target = MK_PHYS_CPU_INVALID;
	raw_spin_lock_init(&instance->ipi_lock);
	INIT_LIST_HEAD(&instance->memory_regions);
	INIT_LIST_HEAD(&instance->list);
	INIT_LIST_HEAD(&instance->pci_devices);
	INIT_LIST_HEAD(&instance->platform_devices);
	kref_init(&instance->refcount);
	INIT_WORK(&instance->halted_work, mk_halted_work_fn);
	atomic_set(&instance->halted_pending, 0);

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

	/* Self inboxes must also be usable without walking their CPU set in IRQ. */
	if (instance->ipi_target == MK_PHYS_CPU_INVALID)
		instance->ipi_target = mk_cpu_set_first(instance->cpus);
	mutex_lock(&mk_instance_mutex);
	ret = mk_instance_idr_add(instance, instance->id, instance->id + 1);
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

	/* FAILED retains devices; callers settle execution before READY/LOADED. */
	if ((old_state == MK_STATE_ACTIVE || old_state == MK_STATE_FAILED) &&
	    (state == MK_STATE_READY || state == MK_STATE_LOADED))
		mk_pciback_unlend(instance);
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

	rcu_read_lock();
	instance = idr_find(&mk_instance_idr, mk_id);
	if (instance && !kref_get_unless_zero(&instance->refcount))
		instance = NULL;
	rcu_read_unlock();

	return instance;
}

/**
 * mk_instance_start - Start an instance from its freshly copied image
 * @instance: The instance, not running
 * @image: Its kernel image, ready to boot
 * @cpu: Logical CPU it boots on
 *
 * Gives the instance what it reaches from its first instruction on, its
 * rings and the config space of its PCI functions, then starts it. A start
 * error can leave CPUs executing, so FAILED retains its lent functions until
 * the caller settles execution and publishes READY or LOADED.
 *
 * Returns 0 once the instance runs, or a negative error code.
 */
int mk_instance_start(struct mk_instance *instance, struct kimage *image,
		      int cpu)
{
	int ret;

	lockdep_assert_held(&mk_overlay_mutex);
	/* A delayed halt notice must retire before this record runs a new Image. */
	if (instance->resource_uncertain || atomic_read(&instance->halted_pending))
		return -EBUSY;

	/*
	 * Start the instance with an empty ring. It outlives the kernel
	 * that was using it, so a new instance would otherwise inherit that
	 * kernel's indices and any slot it left half written - which stalls
	 * the reader, since an unpublished slot means "the sender is still
	 * filling this one". Anything left in there was addressed to a
	 * kernel that is gone.
	 */
	mk_instance_ipi_reset(instance);

	/*
	 * Do not reset the host receive ring: it is shared with live peers
	 * and its IRQ consumer. Stopped instance CPUs do not quiesce either.
	 * An abandoned unpublished slot needs a separate ownership protocol.
	 */

	ret = mk_pciback_lend(instance);
	if (ret) {
		pr_err("Instance %d: its PCI functions cannot be lent: %d\n",
		       instance->id, ret);
		return ret;
	}

	/* A failed start may already have released CPUs into this Image. */
	mk_instance_set_state(instance, MK_STATE_ACTIVE);
	ret = mk_arch_spawn_instance(image, instance, cpu);
	if (ret) {
		mk_instance_set_state(instance, MK_STATE_FAILED);
		return ret;
	}

	pr_info("Multikernel instance %d is now active\n", instance->id);
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
		    instance->state == MK_STATE_LOADED ||
		    instance->state == MK_STATE_FAILED) {
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
 * first. Then dispatch the already-queued inbox prefix before old grants can
 * be retired or an instance ID reused. An abandoned slot must retain resources.
 *
 * Returns 0 when every CPU is parked and resource ownership is settled,
 * -EBUSY if CPU or resource retirement remains uncertain.
 */
int mk_instance_confirm_parked(struct mk_instance *instance)
{
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret, failed = 0;

	/*
	 * CPU stop does not settle remote resource rollback or PCI/DMA state.
	 * shortcut: quarantine lasts until controller reboot; recovery needs a
	 * protocol that proves every admitted resource operation has retired.
	 */
	if (instance->resource_uncertain)
		return -EBUSY;

	/* Ownership is authoritative; tracking may be incomplete after a failure. */
	mk_cpu_set_for_each(i, phys_cpu, instance->cpus) {
		ret = mk_arch_confirm_parked(instance, phys_cpu);
		if (ret) {
			pr_err("Instance %d (%s): CPU %llu is not parked: %d\n",
			       instance->id, instance->name, phys_cpu, ret);
			failed++;
		}
	}

	/* Also retain/probe orphan tracking; confirmation may delete its entry. */
	for (i = mk_cpu_set_count(instance->cpus_on_slot); i-- > 0; ) {
		phys_cpu = instance->cpus_on_slot->ids[i];
		if (mk_cpu_set_contains(instance->cpus, phys_cpu))
			continue;
		ret = mk_arch_confirm_parked(instance, phys_cpu);
		if (ret) {
			pr_err("Instance %d (%s): CPU %llu is not parked: %d\n",
			       instance->id, instance->name, phys_cpu, ret);
			failed++;
		}
	}

	return failed ? -EBUSY : mk_ipi_poll();
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
	unsigned int i, requested_count;
	mk_phys_cpu_t phys_cpu;
	int unavailable = 0;
	char buf[256];
	int ret;

	if (!cpus || !instance->cpus || !mk_pool) {
		pr_err("Invalid CPU sets for transfer\n");
		return -EINVAL;
	}

	guard(mutex)(&mk_pool->cpus_lock);
	requested_count = mk_cpu_set_count(cpus);
	if (requested_count == 0) {
		pr_info("No CPUs requested for instance %d (%s)\n",
			instance->id, instance->name);
		return 0;
	}

	mk_cpu_set_for_each(i, phys_cpu, cpus) {
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

	if (unavailable > 0) {
		pr_err("Instance %d (%s): %d CPUs are not available\n",
		       instance->id, instance->name, unavailable);
		return -EBUSY;
	}

	ret = mk_cpu_set_reserve(instance->cpus, requested_count);
	if (ret)
		return ret;

	mk_cpu_set_for_each(i, phys_cpu, cpus) {
		mk_cpu_set_del(mk_pool->cpus, phys_cpu);
		mk_cpu_set_add(instance->cpus, phys_cpu);
	}
	mk_instance_ipi_retarget(instance);

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
 * Transfers CPUs from the instance back to self instance.
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

	if (!cpus || !instance->cpus || !mk_pool) {
		pr_err("Invalid CPU sets for return\n");
		return -EINVAL;
	}

	guard(mutex)(&mk_pool->cpus_lock);
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

	ret = mk_cpu_set_reserve(mk_pool->cpus, requested_count);
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
		mk_cpu_set_add(mk_pool->cpus, phys_cpu);
		mk_cpu_set_del(instance->cpus, phys_cpu);
	}
	mk_instance_ipi_retarget(instance);

	pr_info("Returned %u CPUs from instance %d (%s) to the pool: %s\n",
		requested_count, instance->id, instance->name, buf);

	return 0;
}

/**
 * mk_pool_cpus_returned() - Is every pool CPU back in this kernel?
 *
 * True when the pool holds no free CPU, no child instance owns one, and
 * locally owned CPUs are online. Pool memory that parked CPUs
 * execute from may only be freed once this holds. The answer is only as
 * good as the invariant that a CPU is recorded in the pool set or in an
 * instance's set before it parks, which is why the move paths reserve
 * room in the destination set up front.
 */
bool mk_pool_cpus_returned(void)
{
	struct mk_instance *instance;
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	bool returned = true;

	lockdep_assert_held(&mk_overlay_mutex);
	if (mk_pool && !mk_cpu_set_empty(mk_pool->cpus))
		return false;

	/*
	 * A failed CPUHP handback remains locally owned, even after mailbox ACK.
	 * Ownership alone cannot prove it left the pool code and page tables.
	 * Native offlining after an online observation stays in this kernel;
	 * donation to the pool is excluded by the resource controller lock.
	 */
	if (!mk_self || !mk_self->cpus)
		return false;
	mk_cpu_set_for_each(i, phys_cpu, mk_self->cpus) {
		int cpu = arch_cpu_from_physical_id(phys_cpu);

		if (cpu < 0 || (unsigned int)cpu >= nr_cpu_ids || !cpu_online(cpu))
			return false;
	}

	mutex_lock(&mk_instance_mutex);
	list_for_each_entry(instance, &mk_instance_list, list) {
		if (instance == mk_self)
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
	struct mk_pci_device *req_dev, *self_dev, *tmp;
	int transferred = 0;
	int not_found = 0;
	bool found;

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

	/* A spawn lends out of its tree */
	if (mk_manifest_phys()) {
		list_for_each_entry(req_dev, requested_devices, list) {
			u8 devfn = PCI_DEVFN(req_dev->slot, req_dev->func);

			if (!mk_of_pci_available(req_dev->domain, req_dev->bus, devfn)) {
				pr_err("PCI device %04x:%02x:%02x.%x is not this kernel's to lend\n",
				       req_dev->domain, req_dev->bus, req_dev->slot,
				       req_dev->func);
				not_found++;
			}
		}
		if (not_found)
			return -ENOENT;
		list_for_each_entry(req_dev, requested_devices, list) {
			int ret = mk_of_pci_lend(instance, req_dev->domain, req_dev->bus,
						 PCI_DEVFN(req_dev->slot, req_dev->func));

			if (ret)
				return ret;
			transferred++;
		}
		instance->pci_devices_valid = true;
		pr_info("Lent %d PCI devices to instance %d (%s)\n",
			transferred, instance->id, instance->name);
		return 0;
	}

	list_for_each_entry(req_dev, requested_devices, list) {
		found = false;
		list_for_each_entry(self_dev, &mk_self->pci_devices, list) {
			if (self_dev->vendor == req_dev->vendor &&
			    self_dev->device == req_dev->device &&
			    self_dev->domain == req_dev->domain &&
			    self_dev->bus == req_dev->bus &&
			    self_dev->slot == req_dev->slot &&
			    self_dev->func == req_dev->func) {
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
		list_for_each_entry_safe(self_dev, tmp, &mk_self->pci_devices, list) {
			if (self_dev->vendor == req_dev->vendor &&
			    self_dev->device == req_dev->device &&
			    self_dev->domain == req_dev->domain &&
			    self_dev->bus == req_dev->bus &&
			    self_dev->slot == req_dev->slot &&
			    self_dev->func == req_dev->func) {

				list_del(&self_dev->list);
				list_add_tail(&self_dev->list, &instance->pci_devices);
				mk_self->pci_device_count--;
				instance->pci_device_count++;
				transferred++;

				pr_debug("Transferred PCI device %04x:%04x@%04x:%02x:%02x.%x to instance %d\n",
					 self_dev->vendor, self_dev->device, self_dev->domain,
					 self_dev->bus, self_dev->slot, self_dev->func,
					 instance->id);
				break;
			}
		}
	}

	instance->pci_devices_valid = true;
	pr_info("Transferred %d PCI devices from root to instance %d (%s), root pool remaining: %d devices\n",
		transferred, instance->id, instance->name, mk_self->pci_device_count);

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
	struct mk_platform_device *req_dev, *self_dev, *tmp;
	int transferred = 0;
	int not_found = 0;
	bool found;

	if (!mk_self || !mk_self->platform_devices_valid) {
		pr_err("No self instance or platform devices not initialized\n");
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
		list_for_each_entry(self_dev, &mk_self->platform_devices, list) {
			if (strcmp(self_dev->name, req_dev->name) == 0) {
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
		list_for_each_entry_safe(self_dev, tmp, &mk_self->platform_devices, list) {
			if (strcmp(self_dev->name, req_dev->name) == 0) {
				list_del(&self_dev->list);
				list_add_tail(&self_dev->list, &instance->platform_devices);
				mk_self->platform_device_count--;
				instance->platform_device_count++;
				transferred++;

				pr_debug("Transferred platform device '%s' to instance %d\n",
					 self_dev->name, instance->id);
				break;
			}
		}
	}

	instance->platform_devices_valid = true;
	pr_info("Transferred %d platform devices from root to instance %d (%s), root pool remaining: %d devices\n",
		transferred, instance->id, instance->name, mk_self->platform_device_count);

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
 * Transfers a single PCI device from self instance to the specified instance.
 * Reserve ownership before lending config access or publishing a hotplug request.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_add_pci_device(struct mk_instance *instance,
			       u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *self_dev, *tmp;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);

	if (!mk_self || !mk_self->pci_devices_valid) {
		pr_err("No self instance or PCI devices not initialized\n");
		return -EINVAL;
	}

	if (mk_manifest_phys()) {
		int ret = mk_of_pci_lend(instance, domain, bus, devfn);

		if (ret)
			pr_err("PCI device %04x:%02x:%02x.%x is not this kernel's to lend\n",
			       domain, bus, slot, func);
		else
			pr_info("Lent PCI device %04x:%02x:%02x.%x to instance %d\n",
				domain, bus, slot, func, instance->id);
		return ret;
	}

	list_for_each_entry_safe(self_dev, tmp, &mk_self->pci_devices, list) {
		if (self_dev->domain == domain &&
		    self_dev->bus == bus &&
		    self_dev->slot == slot &&
		    self_dev->func == func) {

			list_del(&self_dev->list);
			list_add_tail(&self_dev->list, &instance->pci_devices);
			mk_self->pci_device_count--;
			instance->pci_device_count++;
			instance->pci_devices_valid = true;

			pr_info("Transferred PCI device %04x:%04x@%04x:%02x:%02x.%x to instance %d\n",
				self_dev->vendor, self_dev->device, domain, bus, slot, func,
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
 * Returns a single PCI device from the specified instance back to self instance.
 * Used for dynamic PCI device hotplug from non-running instances.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_remove_pci_device(struct mk_instance *instance,
				  u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *inst_dev, *tmp;
	struct mk_pci_device *self_dev;
	u8 slot = PCI_SLOT(devfn);
	u8 func = PCI_FUNC(devfn);

	if (!instance->pci_devices_valid) {
		pr_err("Instance %d PCI devices not initialized\n", instance->id);
		return -EINVAL;
	}

	if (!mk_self) {
		pr_err("Cannot return PCI device: no self instance\n");
		return -EINVAL;
	}

	list_for_each_entry_safe(inst_dev, tmp, &instance->pci_devices, list) {
		if (inst_dev->domain == domain &&
		    inst_dev->bus == bus &&
		    inst_dev->slot == slot &&
		    inst_dev->func == func) {

			if (mk_manifest_phys()) {
				mk_of_pci_take_back(domain, bus, devfn);
				list_del(&inst_dev->list);
				kfree(inst_dev);
				instance->pci_device_count--;
				pr_info("Took PCI device %04x:%02x:%02x.%x back from instance %d\n",
					domain, bus, slot, func, instance->id);
				return 0;
			}

			self_dev = kzalloc_obj(*self_dev, GFP_KERNEL);
			if (!self_dev)
				return -ENOMEM;

			*self_dev = *inst_dev;
			INIT_LIST_HEAD(&self_dev->list);

			list_add_tail(&self_dev->list, &mk_self->pci_devices);
			mk_self->pci_device_count++;
			mk_self->pci_devices_valid = true;

			list_del(&inst_dev->list);
			kfree(inst_dev);
			instance->pci_device_count--;

			pr_info("Returned PCI device %04x:%04x@%04x:%02x:%02x.%x from instance %d to root\n",
				self_dev->vendor, self_dev->device, domain, bus, slot, func,
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

/* The free-pool path must not duplicate another instance's retained grant. */
bool mk_pci_device_assigned(u16 domain, u8 bus, u8 devfn)
{
	struct mk_instance *instance;
	struct mk_pci_device *device;

	lockdep_assert_held(&mk_overlay_mutex);
	guard(mutex)(&mk_instance_mutex);
	list_for_each_entry(instance, &mk_instance_list, list) {
		if (instance == mk_self || !instance->pci_devices_valid)
			continue;
		list_for_each_entry(device, &instance->pci_devices, list) {
			if (device->domain == domain && device->bus == bus &&
			    device->slot == PCI_SLOT(devfn) &&
			    device->func == PCI_FUNC(devfn))
				return true;
		}
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
		region->res.flags = IORESOURCE_MEM | IORESOURCE_BUSY;

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
	return mk_instance_free_memory(instance) ?: ret;
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
 * Return: 0 on success, or an error with memory and metadata retained.
 */
int mk_instance_free_memory(struct mk_instance *instance)
{
	struct mk_memory_region *region, *tmp;
	u64 total_freed = 0;
	int ret;

	if (!instance)
		return 0;
	/* Never detach metadata or forget the pool when execution is uncertain. */
	if (instance->resource_uncertain ||
	    instance->state == MK_STATE_ACTIVE || instance->state == MK_STATE_FAILED ||
	    instance->kimage)
		goto busy;

	/* First host baseline has no allocation to retire; its CPUs are running. */
	if (instance == mk_self && !instance->instance_pool && !instance->ctrl_va &&
	    list_empty(&instance->memory_regions) &&
	    mk_cpu_set_empty(instance->cpus_on_slot))
		return 0;

	if (mk_arch_release_instance(instance))
		goto busy;

	/* Unmap can fail; keep the entire allocation and its metadata on error. */
	if (instance->ctrl_va) {
		ret = mk_pool_unmap(instance->ctrl_phys, MK_CTRL_BLOCK_SIZE);
		if (ret) {
			pr_err("Instance %d control unmap failed: %d; retaining memory\n",
			       instance->id, ret);
			return ret;
		}
	}

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
	return 0;

busy:
	pr_err("Instance %d memory release refused; retaining pool and metadata\n",
	       instance->id);
	return -EBUSY;
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

	/* Do not overwrite ownership when the old allocation cannot retire. */
	ret = mk_instance_free_memory(instance);
	if (ret)
		return ret;

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
		if (mk_pool_map(virt_to_phys(va), MK_CTRL_BLOCK_SIZE)) {
			mk_instance_mem_free(instance, va, MK_CTRL_BLOCK_SIZE);
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
	u64 msg_id;
	u32 flags;
	int sender_instance_id;
};

/* Shutdown parks forever; one slot avoids slab allocation under mk_drain_lock. */
static struct mk_shutdown_work mk_shutdown;
static atomic_t mk_shutdown_requested = ATOMIC_INIT(0);

/*
 * Notify @target_id that this kernel is going down, while messaging
 * still works, then park every CPU in the pool wait loop. The subtype
 * distinguishes a reply to a host-requested shutdown (SHUTDOWN_ACK)
 * from a voluntary halt the parent never asked for (HALTED); both mean
 * "my CPUs are about to park on my context".
 */
static void __noreturn mk_notify_down_and_park(int target_id, u32 subtype,
					       u64 msg_id, bool notify)
{
	struct mk_resource_ack ack;

	ack.operation = MK_SYS_SHUTDOWN;
	ack.result = 0;
	ack.resource_id = mk_self->id;

	/* An unqualified exit still parks, but cannot authorize host reuse. */
	if (notify)
		mk_send_message_id(target_id, MK_MSG_SYSTEM, subtype, msg_id,
				   &ack, sizeof(ack));

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
 * @notify: Caller has excluded new resource operations through final parking
 *
 * Called from the spawn kernel's machine halt path. Only a qualified normal
 * shutdown may send the parent (instance 0) a HALTED event. Panic, unqualified
 * emergency and contended exits still park every CPU, but leave the parent retaining
 * the instance because a parked snapshot alone cannot prove quiescence.
 */
void __noreturn mk_halt_to_pool(bool notify)
{
	mk_notify_down_and_park(0, MK_SYS_HALTED, 0, notify);
}

static void mk_shutdown_work_fn(struct work_struct *work)
{
	struct mk_shutdown_work *sw = container_of(work, struct mk_shutdown_work, work);
	int sender_instance_id = sw->sender_instance_id;
	u64 msg_id = sw->msg_id;

	/* This worker may sleep; the voluntary machine-halt path may not. */
	mk_hotplug_quiesce();
	/* Drain native CPU hotplug and prevent new starts before the ACK. */
	cpu_hotplug_disable();
	/* Finish local controllers, then exclude them until this kernel stops. */
	mutex_lock(&mk_overlay_mutex);
	mk_notify_down_and_park(sender_instance_id, MK_SYS_SHUTDOWN_ACK, msg_id, true);
}

/*
 * A notice is not stop proof. Keep the old state and allocations until every
 * owned/tracked CPU is confirmed parked. The resource lock excludes exec,
 * ownership changes and teardown throughout confirmation and publication.
 */
static int mk_instance_settle_halted(struct mk_instance *instance)
{
	int ret;

	lockdep_assert_held(&mk_overlay_mutex);
	ret = mk_instance_confirm_parked(instance);
	if (ret)
		return ret;
	pr_info("Instance %d (%s) halted, all CPUs confirmed parked\n",
		instance->id, instance->name);
	mk_instance_set_state(instance, MK_STATE_LOADED);
	return 0;
}

static void mk_halted_work_fn(struct work_struct *work)
{
	struct mk_instance *instance =
		container_of(work, struct mk_instance, halted_work);
	int ret;

	guard(mutex)(&mk_overlay_mutex);

	if (instance->state == MK_STATE_ACTIVE || instance->state == MK_STATE_FAILED) {
		ret = mk_instance_settle_halted(instance);
		if (ret)
			pr_warn("Instance %d halt remains unconfirmed: %d\n",
				instance->id, ret);
	}

	atomic_set(&instance->halted_pending, 0);
	mk_instance_put(instance);
}

static void mk_queue_halted(int id)
{
	struct mk_instance *instance = mk_instance_find(id);

	if (!instance)
		return;
	/* Pin identity and coalesce notices without allocating under mk_drain_lock. */
	if (atomic_cmpxchg(&instance->halted_pending, 0, 1)) {
		mk_instance_put(instance);
		return;
	}
	if (!schedule_work(&instance->halted_work)) {
		atomic_set(&instance->halted_pending, 0);
		mk_instance_put(instance);
	}
}

static void mk_system_msg_handler(u32 msg_type, u32 subtype, u64 msg_id,
				  void *payload, u32 payload_len, void *ctx)
{
	union {
		struct mk_shutdown_payload shutdown;
		struct mk_resource_ack ack;
	} decoded;

	if (msg_type != MK_MSG_SYSTEM)
		return;

	/* Preserve the wire layout while providing aligned typed accesses. */
	if (payload_len) {
		memcpy(&decoded, payload, min_t(size_t, payload_len, sizeof(decoded)));
		payload = &decoded;
	}

	switch (subtype) {
	case MK_SYS_SHUTDOWN: {
		struct mk_shutdown_payload *req = payload;
		struct mk_shutdown_work *sw = &mk_shutdown;

		if (payload_len < sizeof(*req))
			return;
		if (atomic_cmpxchg(&mk_shutdown_requested, 0, 1))
			return;

		pr_info("Shutdown requested by instance %d\n", req->sender_instance_id);

		INIT_WORK(&sw->work, mk_shutdown_work_fn);
		sw->msg_id = msg_id;
		sw->flags = req->flags;
		sw->sender_instance_id = req->sender_instance_id;
		schedule_work(&sw->work);
		break;
	}
	case MK_SYS_SHUTDOWN_ACK: {
		struct mk_resource_ack *ack = payload;

		if (payload_len < sizeof(*ack) || ack->operation != MK_SYS_SHUTDOWN)
			return;
		/*
		 * Reply to a shutdown this kernel requested: wake the
		 * requester, which waits for the instance's CPUs to park
		 * and settles its state itself.
		 */
		mk_msg_pending_complete(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN,
					ack->resource_id, msg_id, ack->result);
		break;
	}
	case MK_SYS_HALTED: {
		struct mk_resource_ack *ack = payload;

		if (payload_len < sizeof(*ack) || ack->operation != MK_SYS_SHUTDOWN ||
		    ack->result || ack->resource_id > INT_MAX)
			return;

		/* Lookup is IRQ-safe; stop confirmation still needs process context. */
		mk_queue_halted(ack->resource_id);
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

	guard(mutex)(&mk_overlay_mutex);

	instance = mk_instance_find(mk_id);
	if (!instance)
		return -ENOENT;

	if (instance == mk_self || (instance->state != MK_STATE_ACTIVE &&
				    instance->state != MK_STATE_FAILED)) {
		mk_instance_put(instance);
		return -EINVAL;
	}

	payload.flags = MK_SHUTDOWN_GRACEFUL;
	payload.sender_instance_id = mk_self->id;

	pending = mk_msg_pending_add(MK_MSG_SYSTEM, MK_SYS_SHUTDOWN, mk_id);
	if (IS_ERR(pending)) {
		mk_instance_put(instance);
		return PTR_ERR(pending);
	}

	ret = mk_send_message_id(mk_id, MK_MSG_SYSTEM, MK_SYS_SHUTDOWN,
				 mk_msg_pending_id(pending), &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_cancel(pending);
		mk_instance_put(instance);
		return ret;
	}

	ret = mk_msg_pending_wait(pending, 30000);
	if (!ret)
		ret = mk_instance_settle_halted(instance);

	mk_instance_put(instance);
	return ret;
}

/**
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
	struct mk_shared_data *sd = instance->ipi_data;
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
	struct mk_shared_data *sd = instance->ipi_data;
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

int multikernel_force_halt_by_id(int mk_id)
{
	struct mk_instance *instance;
	struct mk_cpu_set *targets;
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int cpu_count = 0;
	int ret;

	if (!IS_ENABLED(CONFIG_ARCH_HAS_MK_FORCE_STOP))
		return -EOPNOTSUPP;

	guard(mutex)(&mk_overlay_mutex);

	instance = mk_instance_find(mk_id);
	if (!instance)
		return -ENOENT;

	if (instance == mk_self) {
		pr_err("Cannot force halt this kernel (id %d)\n", mk_id);
		mk_instance_put(instance);
		return -EINVAL;
	}

	/*
	 * FAILED permits recovery after an uncertain partial start. LOADED
	 * permits an explicit retry, but is never stop proof: settlement
	 * must still confirm every assigned CPU before publishing it again.
	 */
	if (instance->state != MK_STATE_ACTIVE &&
	    instance->state != MK_STATE_LOADED &&
	    instance->state != MK_STATE_FAILED) {
		pr_err("Instance %d not running (state=%d), nothing to force halt\n",
			mk_id, instance->state);
		mk_instance_put(instance);
		return -EINVAL;
	}

	targets = mk_cpu_set_alloc();
	if (!targets) {
		mk_instance_put(instance);
		return -ENOMEM;
	}
	ret = mk_force_halt_targets(instance, targets);
	if (!ret && mk_cpu_set_empty(targets))
		ret = -EINVAL;
	if (ret) {
		pr_err("Instance %d: no force-halt targets: %d\n", mk_id, ret);
		mk_cpu_set_free(targets);
		mk_instance_put(instance);
		return ret;
	}

	pr_info("Force halting multikernel instance %d via NMI\n", mk_id);

	ret = mk_arm_force_halt(instance);
	if (ret) {
		pr_err("Failed to arm force-halt marker: %d\n", ret);
		goto out_targets;
	}

	mk_cpu_set_for_each(i, phys_cpu, targets) {
		mk_force_stop_cpu(phys_cpu);
		cpu_count++;
	}

	pr_info("Sent NMI to %d CPUs in instance %d\n", cpu_count, mk_id);

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
		if (!ret)
			mk_pcifront_host_fenced();
	} else {
		ret = mk_instance_settle_halted(instance);
	}

out_targets:
	mk_cpu_set_free(targets);
	mk_instance_put(instance);
	return ret;
}

static int __init multikernel_init(void)
{
	int ret;

	ret = mk_messaging_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel messaging: %d\n", ret);
		return ret;
	}

	/* Resource admission must be ready before a shutdown can be received. */
	ret = mk_hotplug_init();
	if (ret < 0) {
		pr_err("Failed to initialize multikernel hotplug: %d\n", ret);
		mk_messaging_cleanup();
		return ret;
	}

	ret = mk_register_msg_handler(MK_MSG_SYSTEM, mk_system_msg_handler, NULL);
	if (ret < 0) {
		pr_err("Failed to register system message handler: %d\n", ret);
		mk_hotplug_cleanup();
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

	pr_info("Multikernel support initialized\n");
	return 0;
}

/* Initialize multikernel after core kernel subsystems are ready */
subsys_initcall(multikernel_init);
