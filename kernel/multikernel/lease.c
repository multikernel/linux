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
 */

#define pr_fmt(fmt) "mk_lease: " fmt

#include <linux/device.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "internal.h"

#define MK_LEASE_DRIVER	"mk_pciback"

struct mk_lease {
	struct pci_dev *pdev;
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

	/* The owner is this record: no instance, which may be freed and reused */
	ret = mk_iommu_claim(pdev, lease);
	if (ret) {
		kfree(lease);
		return ret;
	}

	pci_set_drvdata(pdev, lease);
	return 0;
}

static void mk_lease_remove(struct pci_dev *pdev)
{
	struct mk_lease *lease = pci_get_drvdata(pdev);

	mk_iommu_unclaim(pdev);
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
	if (!mk_lease_of(pdev))
		return 0;

	device_release_driver(&pdev->dev);
	return 0;
}

static int __init mk_lease_init(void)
{
	return pci_register_driver(&mk_lease_driver);
}
fs_initcall(mk_lease_init);
