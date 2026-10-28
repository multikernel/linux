// SPDX-License-Identifier: GPL-2.0-only
/*
 * DMA containment for the PCI devices of an instance.
 *
 * An instance drives its devices without an IOMMU of its own: the IOMMU
 * stays with the host, the instance tree does not mention it, and the
 * instance hands physical addresses to its devices. Behind a translating
 * IOMMU that DMA faults, and behind a bypassing one a buggy driver in the
 * instance can reach all of the host.
 *
 * So while an instance holds a lease on a device (lease.c), the device is
 * attached to a domain of its own that maps the instance's memory grant
 * onto itself, and once the instance maps an MSI, the doorbell of the ITS
 * behind the device. The device works untranslated, and cannot reach
 * anything else.
 * The domain follows the grant as memory is added and removed, and goes
 * away with the lease. Everything here is called with the lease held, so
 * the domain attached to the device is the lease's.
 *
 * Outside a lease the device's DMA belongs to mk_pciback, which holds
 * every function this kernel let go of, and the device sits in the
 * IOMMU's blocking domain.
 *
 * A device without an IOMMU is left alone: its DMA is unrestricted, as
 * it always was.
 */

#define pr_fmt(fmt) "mk_iommu: " fmt

#include <linux/dma-map-ops.h>
#include <linux/iommu.h>
#include <linux/multikernel.h>
#include <linux/pci.h>

#include "internal.h"

static int mk_iommu_prot(struct pci_dev *pdev)
{
	return IOMMU_READ | IOMMU_WRITE |
	       (dev_is_dma_coherent(&pdev->dev) ? IOMMU_CACHE : 0);
}

/* The domain of the lease on @pdev, or NULL for a device without an IOMMU */
static struct iommu_domain *mk_iommu_domain(struct pci_dev *pdev)
{
	struct iommu_domain *domain;

	if (!device_iommu_mapped(&pdev->dev))
		return NULL;

	domain = iommu_get_domain_for_dev(&pdev->dev);
	if (WARN_ON_ONCE(!domain || domain->type != IOMMU_DOMAIN_UNMANAGED))
		return NULL;
	return domain;
}

/**
 * mk_iommu_claim - Take the DMA of a function this kernel let go of
 * @pdev: The function
 * @owner: Its holder, which is never an instance
 *
 * Leaves the function in the blocking domain until a lease attaches a
 * domain of its own.
 *
 * Returns: 0 on success, or a negative error code
 */
int mk_iommu_claim(struct pci_dev *pdev, void *owner)
{
	if (!device_iommu_mapped(&pdev->dev))
		return 0;
	return iommu_device_claim_dma_owner(&pdev->dev, owner);
}

/**
 * mk_iommu_unclaim - Return a function's DMA to this kernel
 * @pdev: The function, which mk_iommu_claim() took
 */
void mk_iommu_unclaim(struct pci_dev *pdev)
{
	if (device_iommu_mapped(&pdev->dev))
		iommu_device_release_dma_owner(&pdev->dev);
}

/* The claim keeps the device in the blocking domain from here on */
static void mk_iommu_unconfine(void *data)
{
	struct pci_dev *pdev = data;
	struct iommu_domain *domain = mk_iommu_domain(pdev);

	if (!domain)
		return;
	iommu_detach_device(domain, &pdev->dev);
	iommu_domain_free(domain);
}

/**
 * mk_iommu_confine - Confine a leased device's DMA to its instance's memory
 * @instance: Instance being granted the device
 * @pdev: The device, which mk_iommu_claim() took
 *
 * Confined until the lease ends.
 *
 * Returns: 0, or a negative error code, in which case the instance must
 * not have the device: it would either fault or roam
 */
int mk_iommu_confine(struct mk_instance *instance, struct pci_dev *pdev)
{
	struct mk_memory_region *region;
	struct iommu_domain *domain;
	int ret;

	if (!device_iommu_mapped(&pdev->dev)) {
		pr_info_once("%s has no IOMMU, DMA of instance devices is unrestricted\n",
			     pci_name(pdev));
		return 0;
	}

	domain = iommu_paging_domain_alloc(&pdev->dev);
	if (IS_ERR(domain)) {
		ret = PTR_ERR(domain);
		goto err;
	}

	list_for_each_entry(region, &instance->memory_regions, list) {
		ret = iommu_map(domain, region->res.start, region->res.start,
				resource_size(&region->res), mk_iommu_prot(pdev),
				GFP_KERNEL);
		if (ret)
			goto free;
	}

	ret = iommu_attach_device(domain, &pdev->dev);
	if (ret)
		goto free;

	return devm_add_action_or_reset(&pdev->dev, mk_iommu_unconfine, pdev);

free:
	iommu_domain_free(domain);
err:
	pci_err(pdev, "DMA not confined to instance %d: %d\n", instance->id, ret);
	return ret;
}

/**
 * mk_iommu_allow_msi - Let a leased device write to an MSI doorbell
 * @pdev: The device
 * @doorbell: Address the device writes its MSIs to
 *
 * Allowed until the lease ends, with the domain.
 *
 * Returns: 0 on success, or a negative error code
 */
int mk_iommu_allow_msi(struct pci_dev *pdev, phys_addr_t doorbell)
{
	struct iommu_domain *domain = mk_iommu_domain(pdev);
	phys_addr_t page = doorbell & PAGE_MASK;

	/* A MAP that failed after opening it opened it already */
	if (!domain || iommu_iova_to_phys(domain, page) == page)
		return 0;

	return iommu_map(domain, page, page, PAGE_SIZE,
			 IOMMU_WRITE | IOMMU_MMIO, GFP_KERNEL);
}

/**
 * mk_iommu_map - Let a leased device reach memory its instance gains
 * @pdev: The device
 * @start: Physical address of the range
 * @size: Size of the range
 *
 * Returns: 0 on success, or a negative error code
 */
int mk_iommu_map(struct pci_dev *pdev, phys_addr_t start, size_t size)
{
	struct iommu_domain *domain = mk_iommu_domain(pdev);

	if (!domain)
		return 0;
	return iommu_map(domain, start, start, size, mk_iommu_prot(pdev),
			 GFP_KERNEL);
}

/**
 * mk_iommu_unmap - Cut a leased device off memory its instance lost
 * @pdev: The device
 * @start: Physical address of the range
 * @size: Size of the range
 */
void mk_iommu_unmap(struct pci_dev *pdev, phys_addr_t start, size_t size)
{
	struct iommu_domain *domain = mk_iommu_domain(pdev);

	if (domain)
		iommu_unmap(domain, start, size);
}
