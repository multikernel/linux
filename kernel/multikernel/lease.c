// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * PCI functions this kernel has let go of, for instances to use.
 *
 * A function moves between kernels by hotplug: mk_do_device_remove()
 * when this kernel stops driving it, mk_do_device_add() when it drives
 * it again. In between, the function is bound to mk_pciback, a driver
 * that does nothing with it but hold it. No other driver of this kernel
 * can bind it, and where an IOMMU confines the DMA of instances,
 * mk_pciback owns the function's DMA, which leaves it in the IOMMU's
 * blocking domain whenever no instance is using it.
 *
 * An instance uses a function under a lease, from the instance's start,
 * or the function's hot add, to the instance's halt, or the function's
 * hot remove. Whatever this kernel sets up for the instance's use of the
 * function, config access, an IOMMU domain, MSI routes, is a devres
 * action in a group of the lease's own, opened when it is granted. Ending
 * the lease resets the function, so that it stops whatever the instance
 * left it doing while its DMA is still confined, and then releases the
 * group, last set up first. That returns the function to how it was
 * before the lease, held and blocked.
 */

#define pr_fmt(fmt) "mk_lease: " fmt

#include <linux/device.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "internal.h"

#define MK_LEASE_DRIVER	"mk_pciback"

struct mk_lease {
	struct pci_dev *pdev;
	struct mutex lock;		/* grant and end, and what hangs off a lease */
	struct mk_instance *holder;	/* NULL outside a lease */
};

static struct pci_driver mk_lease_driver;

static struct mk_lease *mk_lease_of(struct pci_dev *pdev)
{
	if (!pdev->dev.driver ||
	    to_pci_driver(pdev->dev.driver) != &mk_lease_driver)
		return NULL;
	return pci_get_drvdata(pdev);
}

static int mk_lease_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct mk_lease *lease;
	int ret;

	lease = kzalloc_obj(*lease);
	if (!lease)
		return -ENOMEM;
	lease->pdev = pdev;
	mutex_init(&lease->lock);

	/* The owner is this record: no instance, which may be freed and reused */
	ret = mk_iommu_claim(pdev, lease);
	if (ret) {
		kfree(lease);
		return ret;
	}

	pci_set_drvdata(pdev, lease);
	return 0;
}

static void mk_lease_end(struct mk_lease *lease, bool reset)
{
	lockdep_assert_held(&lease->lock);

	if (!lease->holder)
		return;

	/* Only tries for the device lock: remove holds it while it waits for ours */
	if (reset && pci_try_reset_function(lease->pdev))
		pci_clear_master(lease->pdev);

	devres_release_group(&lease->pdev->dev, lease);
	mk_instance_put(lease->holder);
	lease->holder = NULL;
}

/* The function went away, a lease or not: there is nothing left to reset */
static void mk_lease_remove(struct pci_dev *pdev)
{
	struct mk_lease *lease = pci_get_drvdata(pdev);

	scoped_guard(mutex, &lease->lock)
		mk_lease_end(lease, false);
	mk_iommu_unclaim(pdev);
	mutex_destroy(&lease->lock);
	kfree(lease);
}

static struct pci_driver mk_lease_driver = {
	.name			= MK_LEASE_DRIVER,
	.probe			= mk_lease_probe,
	.remove			= mk_lease_remove,
	/* The claim is ours, not the default domain the driver core would take */
	.driver_managed_dma	= true,
	.driver = {
		/* A sysfs unbind would hand the function back under an instance */
		.suppress_bind_attrs = true,
	},
};

/**
 * mk_lease_bind - Hold a function this kernel no longer drives
 * @pdev: The function, with no driver bound
 *
 * Returns: 0 on success, -EBUSY if another driver has it, or another
 * negative error code
 */
int mk_lease_bind(struct pci_dev *pdev)
{
	int ret;

	if (mk_lease_of(pdev))
		return 0;
	if (pdev->dev.driver)
		return -EBUSY;

	ret = driver_set_override(&pdev->dev, &pdev->driver_override,
				  MK_LEASE_DRIVER, strlen(MK_LEASE_DRIVER));
	if (ret)
		return ret;

	return device_driver_attach(&mk_lease_driver.driver, &pdev->dev);
}

/**
 * mk_lease_unbind - Let go of a function for this kernel to drive again
 * @pdev: The function
 *
 * The caller clears the driver override as it binds a driver of its own.
 *
 * Returns: 0 on success, or a negative error code
 */
int mk_lease_unbind(struct pci_dev *pdev)
{
	struct mk_lease *lease = mk_lease_of(pdev);

	if (!lease)
		return 0;

	scoped_guard(mutex, &lease->lock) {
		if (lease->holder)
			return -EBUSY;
	}

	device_release_driver(&pdev->dev);
	return 0;
}

/**
 * mk_lease_grant - Give an instance a function until mk_lease_fence()
 * @instance: The instance, about to start or running
 * @pdev: The function, which this kernel does not drive
 *
 * Returns: 0 on success, -EBUSY if a driver of this kernel or another
 * instance has the function, or another negative error code
 */
int mk_lease_grant(struct mk_instance *instance, struct pci_dev *pdev)
{
	struct mk_lease *lease;
	int ret;

	ret = mk_lease_bind(pdev);
	if (ret)
		return ret;
	lease = mk_lease_of(pdev);

	guard(mutex)(&lease->lock);

	if (lease->holder)
		return -EBUSY;

	if (!devres_open_group(&pdev->dev, lease, GFP_KERNEL))
		return -ENOMEM;

	ret = mk_pciback_lend(instance, pdev);
	if (!ret)
		ret = mk_iommu_confine(instance, pdev);
	if (ret) {
		devres_release_group(&pdev->dev, lease);
		return ret;
	}

	lease->holder = mk_instance_get(instance);
	return 0;
}

/**
 * mk_lease_fence - End an instance's lease on a function
 * @instance: The instance, which stopped or no longer has the function
 * @pdev: The function
 *
 * Nothing happens unless @instance holds a lease on @pdev.
 */
void mk_lease_fence(struct mk_instance *instance, struct pci_dev *pdev)
{
	struct mk_lease *lease = mk_lease_of(pdev);

	if (!lease)
		return;

	guard(mutex)(&lease->lock);
	if (lease->holder == instance)
		mk_lease_end(lease, true);
}

static struct pci_dev *mk_lease_find_pdev(const struct mk_pci_device *mine)
{
	return pci_get_domain_bus_and_slot(mine->domain, mine->bus,
					   PCI_DEVFN(mine->slot, mine->func));
}

/**
 * mk_instance_grant_devices - Lease an instance about to start its functions
 * @instance: The instance
 *
 * Returns: 0 on success, or a negative error code, in which case nothing
 * is leased and the instance must not be started
 */
int mk_instance_grant_devices(struct mk_instance *instance)
{
	struct mk_pci_device *mine;
	int ret = 0;

	if (!instance->pci_devices_valid)
		return 0;

	list_for_each_entry(mine, &instance->pci_devices, list) {
		struct pci_dev *pdev = mk_lease_find_pdev(mine);

		if (!pdev) {
			pr_warn("Instance %d: no PCI function %04x:%02x:%02x.%x here to lend\n",
				instance->id, mine->domain, mine->bus, mine->slot,
				mine->func);
			ret = -ENODEV;
			break;
		}

		ret = mk_lease_grant(instance, pdev);
		if (ret)
			pci_err(pdev, "not lent to instance %d: %d\n",
				instance->id, ret);
		pci_dev_put(pdev);
		if (ret)
			break;
	}

	if (ret)
		mk_instance_fence_devices(instance);
	return ret;
}

/**
 * mk_instance_fence_devices - End every lease an instance holds
 * @instance: The instance, which halted, or is about to be started afresh
 */
void mk_instance_fence_devices(struct mk_instance *instance)
{
	struct mk_pci_device *mine;

	if (!instance->pci_devices_valid)
		return;

	list_for_each_entry(mine, &instance->pci_devices, list) {
		struct pci_dev *pdev = mk_lease_find_pdev(mine);

		if (pdev) {
			mk_lease_fence(instance, pdev);
			pci_dev_put(pdev);
		}
	}
}

static int __init mk_lease_init(void)
{
	return pci_register_driver(&mk_lease_driver);
}
fs_initcall(mk_lease_init);
