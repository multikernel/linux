// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multikernel PCI assignment policy
 *
 * Keeps assigned-device discovery, identity presentation, bridge traversal,
 * and resource restoration independent from the manifest that populated
 * the current instance.
 *
 * Configuration-space filtering constrains normal PCI access by a cooperative
 * spawn kernel. It is not a security boundary: a privileged kernel can issue
 * configuration cycles or map physical configuration windows directly. The
 * host-owned IOMMU domain separately constrains DMA initiated by an assigned
 * device.
 */

#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/device/bus.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/interrupt.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "internal.h"
#include "pci_internal.h"

DEFINE_MUTEX(mk_pci_lease_mutex);
DEFINE_SPINLOCK(mk_pci_active_lock);
LIST_HEAD(mk_pci_active_assignments);
bool mk_pci_device_live(struct pci_dev *pdev)
{
	return device_is_registered(&pdev->dev) &&
	       !pci_dev_is_disconnected(pdev) &&
	       pci_device_is_present(pdev);
}

static bool mk_pci_device_matches_bdf(const struct mk_pci_device *device,
				      u16 domain, u8 bus, u8 devfn)
{
	return device->domain == domain && device->bus == bus &&
	       device->slot == PCI_SLOT(devfn) &&
	       device->func == PCI_FUNC(devfn);
}

struct mk_pci_device *
mk_pci_find_device_bdf(struct list_head *devices, u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *device;

	list_for_each_entry(device, devices, list) {
		if (mk_pci_device_matches_bdf(device, domain, bus, devfn))
			return device;
	}

	return NULL;
}

static bool mk_pci_inventory_matches(const struct mk_pci_device *left,
				     const struct mk_pci_device *right)
{
	return left->vendor == right->vendor &&
	       left->device == right->device &&
	       mk_pci_device_matches_bdf(left, right->domain, right->bus,
					 PCI_DEVFN(right->slot, right->func));
}

static struct mk_pci_device *
mk_pci_find_root_inventory(const struct mk_pci_device *requested)
{
	struct mk_pci_device *device;

	list_for_each_entry(device, &root_instance->pci_devices, list) {
		if (mk_pci_inventory_matches(device, requested))
			return device;
	}

	return NULL;
}

static struct mk_pci_device *
mk_pci_find_root_bdf(u16 domain, u8 bus, u8 devfn)
{
	return mk_pci_find_device_bdf(&root_instance->pci_devices, domain, bus,
				      devfn);
}

struct mk_pci_assignment *
mk_pci_find_assignment(struct mk_instance *instance, u16 domain, u8 bus,
		       u8 devfn)
{
	struct mk_pci_assignment *assignment;

	list_for_each_entry(assignment, &instance->pci_assignments,
			    instance_node) {
		if (mk_pci_device_matches_bdf(assignment->inventory, domain, bus,
					      devfn))
			return assignment;
	}

	return NULL;
}

static int
mk_pci_prepare_assignment(struct mk_instance *instance,
			  const struct mk_pci_device *requested,
			  struct list_head *transaction)
{
	struct mk_pci_assignment *assignment;
	struct mk_pci_device *inventory;
	struct pci_dev *vf;
	struct pci_dev *pf;
	struct pci_dev *physfn;
	int ret;

	inventory = mk_pci_find_root_inventory(requested);
	if (!inventory) {
		pr_err("PCI device %04x:%04x@%04x:%02x:%02x.%x is not available in the root pool\n",
		       requested->vendor, requested->device, requested->domain,
		       requested->bus, requested->slot, requested->func);
		return -ENOENT;
	}

	vf = pci_get_domain_bus_and_slot(inventory->domain,
					 inventory->bus,
					 PCI_DEVFN(inventory->slot,
						   inventory->func));
	if (!vf)
		return -ENODEV;

	if (vf->vendor != inventory->vendor ||
	    vf->device != inventory->device) {
		pr_err("PCI identity changed for %s: expected %04x:%04x, found %04x:%04x\n",
		       pci_name(vf), inventory->vendor, inventory->device,
		       vf->vendor, vf->device);
		pci_dev_put(vf);
		return -ENODEV;
	}

	physfn = pci_physfn(vf);
	if (!vf->is_virtfn || physfn == vf) {
		pr_err("PCI assignment only supports SR-IOV VFs, rejecting %s\n",
		       pci_name(vf));
		pci_dev_put(vf);
		return -EOPNOTSUPP;
	}

	if (!mk_pci_device_live(vf) || !mk_pci_device_live(physfn)) {
		pci_dev_put(vf);
		return -ENODEV;
	}
	ret = pcie_reset_flr(vf, true);
	if (ret) {
		pr_err("PCI assignment requires FLR for safe instance restart, rejecting %s\n",
		       pci_name(vf));
		pci_dev_put(vf);
		return -EOPNOTSUPP;
	}

	if (pci_is_dev_assigned(vf) ||
	    mk_pci_find_assignment(instance, inventory->domain,
				   inventory->bus,
				   PCI_DEVFN(inventory->slot,
					     inventory->func))) {
		pci_dev_put(vf);
		return -EBUSY;
	}

	pf = pci_dev_get(physfn);
	assignment = kzalloc_obj(*assignment, GFP_KERNEL);
	if (!assignment) {
		pci_dev_put(pf);
		pci_dev_put(vf);
		return -ENOMEM;
	}

	assignment->instance = instance;
	assignment->inventory = inventory;
	assignment->vf = vf;
	assignment->pf = pf;
	assignment->host_driver = vf->dev.driver;
	if (assignment->host_driver && assignment->host_driver->owner &&
	    !try_module_get(assignment->host_driver->owner)) {
		kfree(assignment);
		pci_dev_put(pf);
		pci_dev_put(vf);
		return -ENODEV;
	}

	INIT_LIST_HEAD(&assignment->instance_node);
	INIT_LIST_HEAD(&assignment->active_node);
	INIT_LIST_HEAD(&assignment->transaction_node);
	mutex_init(&assignment->iommu_mutex);
	INIT_WORK(&assignment->failure_work, mk_pci_assignment_failure_work);
	atomic_set(&assignment->failure_pending, 0);

	ret = mk_pci_iommu_prepare_assignment(assignment);
	if (ret)
		goto err_module;

	list_add_tail(&assignment->instance_node, &instance->pci_assignments);
	list_add_tail(&assignment->transaction_node, transaction);

	return 0;

err_module:
	if (assignment->host_driver && assignment->host_driver->owner)
		module_put(assignment->host_driver->owner);
	kfree(assignment);
	pci_dev_put(pf);
	pci_dev_put(vf);
	return ret;
}

static int mk_pci_commit_assignment(struct mk_pci_assignment *assignment)
{
	struct pci_dev *vf = assignment->vf;
	unsigned long flags;
	int ret;
	int i;

	if (!mk_pci_device_live(vf) || !mk_pci_device_live(assignment->pf))
		return -ENODEV;

	if (vf->dev.driver != assignment->host_driver ||
	    pci_is_dev_assigned(vf))
		return -EBUSY;

	pci_set_dev_assigned(vf);
	assignment->assigned = true;

	spin_lock_irqsave(&mk_pci_active_lock, flags);
	list_add_tail(&assignment->active_node, &mk_pci_active_assignments);
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);

	if (assignment->host_driver)
		mk_pci_release_bound_driver(assignment);

	if (vf->dev.driver)
		return -EBUSY;

	ret = mk_pci_iommu_commit_assignment(assignment);
	if (ret)
		return ret;

	for (i = 0; i < MK_PCI_RESOURCE_COUNT; i++) {
		assignment->inventory->resources[i].start =
			vf->resource[i].start;
		assignment->inventory->resources[i].end =
			vf->resource[i].end;
		assignment->inventory->resources[i].flags =
			vf->resource[i].flags;
	}
	assignment->inventory->resources_valid = true;

	list_move_tail(&assignment->inventory->list,
		       &assignment->instance->pci_devices);
	root_instance->pci_device_count--;
	assignment->instance->pci_device_count++;
	assignment->instance->pci_devices_valid = true;
	assignment->inventory_moved = true;

	pr_info("Leased SR-IOV VF %s to instance %d (%s)\n",
		pci_name(vf), assignment->instance->id,
		assignment->instance->name);
	return 0;
}

static int mk_pci_release_assignment(struct mk_pci_assignment *assignment,
				     struct list_head *released)
{
	struct mk_instance *instance = assignment->instance;
	struct pci_dev *vf = assignment->vf;
	unsigned long flags;
	int ret;

	if (!assignment->assigned)
		goto release_resources;

	ret = mk_pci_quiesce_assignment(assignment);
	if (ret)
		return ret;

	ret = mk_pci_restore_host_binding(assignment);
	if (ret)
		return ret;

	spin_lock_irqsave(&mk_pci_active_lock, flags);
	if (!list_empty(&assignment->active_node))
		list_del_init(&assignment->active_node);
	assignment->expected_unbind = false;
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);

	if (assignment->assigned) {
		pci_clear_dev_assigned(vf);
		assignment->assigned = false;
	}

release_resources:
	mk_pci_iommu_release_assignment(assignment);

	if (assignment->inventory_moved && root_instance) {
		assignment->inventory->resources_valid = false;
		list_move_tail(&assignment->inventory->list,
			       &root_instance->pci_devices);
		instance->pci_device_count--;
		root_instance->pci_device_count++;
		root_instance->pci_devices_valid = true;
		assignment->inventory_moved = false;
	}

	if (!list_empty(&assignment->transaction_node))
		list_del_init(&assignment->transaction_node);
	list_del_init(&assignment->instance_node);
	list_add_tail(&assignment->transaction_node, released);

	return 0;
}

static void mk_pci_finalize_releases(struct list_head *released)
{
	struct mk_pci_assignment *assignment, *tmp;

	list_for_each_entry_safe(assignment, tmp, released, transaction_node) {
		list_del_init(&assignment->transaction_node);
		cancel_work_sync(&assignment->failure_work);
		kfree(assignment->host_driver_override);
		if (assignment->host_driver && assignment->host_driver->owner)
			module_put(assignment->host_driver->owner);
		pci_dev_put(assignment->pf);
		pci_dev_put(assignment->vf);
		kfree(assignment);
	}
}

static int mk_pci_rollback_transaction(struct list_head *transaction,
				       struct list_head *released)
{
	struct mk_pci_assignment *assignment, *tmp;
	int rollback_ret = 0;
	int ret;

	list_for_each_entry_safe_reverse(assignment, tmp, transaction,
					 transaction_node) {
		ret = mk_pci_release_assignment(assignment, released);
		if (!ret)
			continue;
		pr_crit("Failed to roll back PCI assignment for %s: %d\n",
			pci_name(assignment->vf), ret);
		list_del_init(&assignment->transaction_node);
		if (!rollback_ret)
			rollback_ret = ret;
	}

	return rollback_ret;
}

static int mk_pci_commit_transaction(struct list_head *transaction)
{
	struct mk_pci_assignment *assignment;
	int ret;

	list_for_each_entry(assignment, transaction, transaction_node) {
		ret = mk_pci_commit_assignment(assignment);
		if (ret)
			return ret;
	}

	while (!list_empty(transaction)) {
		assignment = list_first_entry(transaction,
					      struct mk_pci_assignment,
					      transaction_node);
		list_del_init(&assignment->transaction_node);
	}

	return 0;
}

void mk_pci_lease_instance_init(struct mk_instance *instance)
{
	mutex_init(&instance->resource_mutex);
	INIT_LIST_HEAD(&instance->pci_assignments);
	INIT_DELAYED_WORK(&instance->irq_retry_work, mk_pci_irq_retry_workfn);
}

bool mk_pci_iommu_lease_active_locked(struct mk_instance *instance)
{
	if (!instance)
		return false;

	lockdep_assert_held(&instance->resource_mutex);
	return !list_empty(&instance->pci_assignments);
}

int mk_pci_assign_devices(struct mk_instance *instance,
			  const struct list_head *requested_devices,
			  int requested_count)
{
	struct mk_pci_device *requested;
	LIST_HEAD(released);
	LIST_HEAD(transaction);
	int prepared = 0;
	int ret = 0;
	int rollback_ret;

	if (!instance || instance == root_instance || !requested_devices ||
	    requested_count < 0)
		return -EINVAL;
	if (!root_instance || !root_instance->pci_devices_valid)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();

	list_for_each_entry(requested, requested_devices, list) {
		ret = mk_pci_prepare_assignment(instance, requested,
						&transaction);
		if (ret)
			goto rollback;
		prepared++;
	}

	if (prepared != requested_count) {
		ret = -EINVAL;
		goto rollback;
	}

	ret = mk_pci_commit_transaction(&transaction);
	if (ret)
		goto rollback;
	goto out;

rollback:
	rollback_ret = mk_pci_rollback_transaction(&transaction, &released);
	if (rollback_ret)
		ret = rollback_ret;
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	mk_pci_finalize_releases(&released);
	return ret;
}

int mk_pci_assign_device(struct mk_instance *instance, u16 domain, u8 bus,
			 u8 devfn)
{
	struct mk_pci_device *inventory;
	LIST_HEAD(released);
	LIST_HEAD(transaction);
	int ret;
	int rollback_ret;

	if (!instance || instance == root_instance)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();

	if (instance->state != MK_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}
	if (!root_instance || !root_instance->pci_devices_valid) {
		ret = -EINVAL;
		goto out;
	}

	inventory = mk_pci_find_root_bdf(domain, bus, devfn);
	if (!inventory) {
		ret = -ENOENT;
		goto out;
	}

	ret = mk_pci_prepare_assignment(instance, inventory, &transaction);
	if (ret)
		goto rollback;
	ret = mk_pci_commit_transaction(&transaction);
	if (ret)
		goto rollback;
	goto out;

rollback:
	rollback_ret = mk_pci_rollback_transaction(&transaction, &released);
	if (rollback_ret)
		ret = rollback_ret;
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	mk_pci_finalize_releases(&released);
	return ret;
}

int mk_pci_unassign_device(struct mk_instance *instance, u16 domain, u8 bus,
			   u8 devfn)
{
	struct mk_pci_assignment *assignment;
	LIST_HEAD(released);
	int ret;

	if (!instance || instance == root_instance)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();

	if (instance->state != MK_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	assignment = mk_pci_find_assignment(instance, domain, bus, devfn);
	if (!assignment) {
		ret = -ENOENT;
		goto out;
	}

	ret = mk_pci_release_assignment(assignment, &released);
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	mk_pci_finalize_releases(&released);
	return ret;
}

int mk_pci_release_assignments(struct mk_instance *instance)
{
	struct mk_pci_assignment *assignment;
	LIST_HEAD(released);
	int ret = 0;

	if (!instance || instance == root_instance)
		return 0;

	mk_cpu_transaction_lock();
	down_write(&instance->control_route_sem);
	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	while (!list_empty(&instance->pci_assignments)) {
		assignment = list_last_entry(&instance->pci_assignments,
					     struct mk_pci_assignment,
					     instance_node);
		ret = mk_pci_release_assignment(assignment, &released);
		if (ret) {
			pr_crit("Instance %d retains unsafe PCI lease for %s: %d\n",
				instance->id, pci_name(assignment->vf), ret);
			break;
		}
	}
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	up_write(&instance->control_route_sem);
	mk_cpu_transaction_unlock();
	/*
	 * The assignment is no longer reachable by routed requests.  Cancel its
	 * failure work after dropping the route and transaction locks because the
	 * worker may itself force-halt the instance and take both locks.
	 */
	mk_pci_finalize_releases(&released);
	if (!ret)
		cancel_delayed_work_sync(&instance->irq_retry_work);
	return ret;
}

int mk_pci_prepare_instance_start(struct mk_instance *instance)
{
	struct mk_pci_assignment *assignment;
	int ret = 0;

	if (!instance || instance == root_instance)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	list_for_each_entry(assignment, &instance->pci_assignments,
			    instance_node) {
		ret = mk_pci_reset_assignment_for_start(assignment);
		if (ret)
			break;
	}
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	return ret;
}

int mk_pci_lease_system_init(void)
{
	int ret;

	ret = mk_pci_iommu_system_init();
	if (ret)
		return ret;
	ret = mk_pci_control_system_init();
	if (ret)
		mk_pci_iommu_system_cleanup();
	return ret;
}

void mk_pci_lease_system_cleanup(void)
{
	mk_pci_control_system_cleanup();
	mk_pci_iommu_system_cleanup();
}
