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
 * onto itself, and with it the MSI doorbell of the ITS behind that
 * device. The device works untranslated, and cannot reach anything else.
 * The domain follows the grant as memory is added and removed, and goes
 * away with the lease.
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
#include <linux/slab.h>

struct mk_iommu_dev {
	struct list_head list;
	struct mk_instance *instance;
	struct pci_dev *pdev;
	struct iommu_domain *domain;
};

static LIST_HEAD(mk_iommu_devs);
static DEFINE_MUTEX(mk_iommu_lock);

static int mk_iommu_prot(struct mk_iommu_dev *d)
{
	return IOMMU_READ | IOMMU_WRITE |
	       (dev_is_dma_coherent(&d->pdev->dev) ? IOMMU_CACHE : 0);
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
	struct mk_iommu_dev *d = data;

	scoped_guard(mutex, &mk_iommu_lock)
		list_del(&d->list);
	iommu_detach_device(d->domain, &d->pdev->dev);
	iommu_domain_free(d->domain);
	kfree(d);
}

static int mk_iommu_confine_locked(struct mk_iommu_dev *d)
{
	phys_addr_t doorbell = mk_arch_msi_doorbell(d->pdev);
	struct mk_memory_region *region;
	int ret;

	lockdep_assert_held(&mk_iommu_lock);

	list_for_each_entry(region, &d->instance->memory_regions, list) {
		ret = iommu_map(d->domain, region->res.start, region->res.start,
				resource_size(&region->res), mk_iommu_prot(d),
				GFP_KERNEL);
		if (ret)
			return ret;
	}

	if (doorbell) {
		ret = iommu_map(d->domain, doorbell & PAGE_MASK,
				doorbell & PAGE_MASK, PAGE_SIZE,
				IOMMU_WRITE | IOMMU_MMIO, GFP_KERNEL);
		if (ret)
			return ret;
	}

	ret = iommu_attach_device(d->domain, &d->pdev->dev);
	if (!ret)
		list_add(&d->list, &mk_iommu_devs);
	return ret;
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
	struct mk_iommu_dev *d;
	int ret;

	if (!device_iommu_mapped(&pdev->dev)) {
		pr_info_once("%s has no IOMMU, DMA of instance devices is unrestricted\n",
			     pci_name(pdev));
		return 0;
	}

	d = kzalloc_obj(*d);
	if (!d)
		return -ENOMEM;
	d->instance = instance;
	d->pdev = pdev;

	d->domain = iommu_paging_domain_alloc(&pdev->dev);
	if (IS_ERR(d->domain)) {
		ret = PTR_ERR(d->domain);
		goto err;
	}

	scoped_guard(mutex, &mk_iommu_lock)
		ret = mk_iommu_confine_locked(d);
	if (ret) {
		iommu_domain_free(d->domain);
		goto err;
	}

	return devm_add_action_or_reset(&pdev->dev, mk_iommu_unconfine, d);

err:
	pci_err(pdev, "DMA not confined to instance %d: %d\n", instance->id, ret);
	kfree(d);
	return ret;
}

/**
 * mk_iommu_map - Let a running instance's devices reach memory it gains
 * @instance: Instance the memory is being added to
 * @start: Physical address of the range
 * @size: Size of the range
 *
 * To be called before the instance is told about the memory.
 */
int mk_iommu_map(struct mk_instance *instance, phys_addr_t start, size_t size)
{
	struct mk_iommu_dev *d;
	int ret = 0;

	mutex_lock(&mk_iommu_lock);
	list_for_each_entry(d, &mk_iommu_devs, list) {
		if (d->instance != instance)
			continue;
		ret = iommu_map(d->domain, start, start, size, mk_iommu_prot(d),
				GFP_KERNEL);
		if (ret)
			break;
	}
	mutex_unlock(&mk_iommu_lock);

	if (ret)
		mk_iommu_unmap(instance, start, size);
	return ret;
}

/**
 * mk_iommu_unmap - Cut a running instance's devices off memory it lost
 * @instance: Instance the memory was removed from
 * @start: Physical address of the range
 * @size: Size of the range
 */
void mk_iommu_unmap(struct mk_instance *instance, phys_addr_t start, size_t size)
{
	struct mk_iommu_dev *d;

	mutex_lock(&mk_iommu_lock);
	list_for_each_entry(d, &mk_iommu_devs, list) {
		if (d->instance == instance)
			iommu_unmap(d->domain, start, size);
	}
	mutex_unlock(&mk_iommu_lock);
}
