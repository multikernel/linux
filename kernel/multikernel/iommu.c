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
 * So while an instance runs, each of its devices is attached to a domain
 * of its own that maps the instance's memory grant onto itself, and with
 * it the MSI doorbell of the ITS behind that device. The device works
 * untranslated, and cannot reach anything else. The domain follows the
 * grant as memory is added and removed, and goes away when the instance
 * halts, which returns the device to the host's default domain for a host
 * driver to bind.
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

static void mk_iommu_free_dev(struct mk_iommu_dev *d)
{
	if (d->domain) {
		iommu_detach_device(d->domain, &d->pdev->dev);
		iommu_domain_free(d->domain);
	}
	iommu_device_release_dma_owner(&d->pdev->dev);
	pci_dev_put(d->pdev);
	list_del(&d->list);
	kfree(d);
}

static int mk_iommu_contain_dev(struct mk_instance *instance,
				struct pci_dev *pdev)
{
	phys_addr_t doorbell = mk_msi_proxy_doorbell(pdev);
	struct mk_memory_region *region;
	struct mk_iommu_dev *d;
	int ret;

	d = kzalloc_obj(*d);
	if (!d)
		return -ENOMEM;
	d->instance = instance;
	d->pdev = pci_dev_get(pdev);
	list_add(&d->list, &mk_iommu_devs);

	/* Fails while a host driver is bound, which must not share the device */
	ret = iommu_device_claim_dma_owner(&pdev->dev, instance);
	if (ret) {
		pci_dev_put(d->pdev);
		list_del(&d->list);
		kfree(d);
		return ret;
	}

	d->domain = iommu_paging_domain_alloc(&pdev->dev);
	if (IS_ERR(d->domain)) {
		ret = PTR_ERR(d->domain);
		d->domain = NULL;
		goto err;
	}

	list_for_each_entry(region, &instance->memory_regions, list) {
		ret = iommu_map(d->domain, region->res.start, region->res.start,
				resource_size(&region->res), mk_iommu_prot(d),
				GFP_KERNEL);
		if (ret)
			goto err_domain;
	}

	if (doorbell) {
		ret = iommu_map(d->domain, doorbell & PAGE_MASK,
				doorbell & PAGE_MASK, PAGE_SIZE,
				IOMMU_WRITE | IOMMU_MMIO, GFP_KERNEL);
		if (ret)
			goto err_domain;
	}

	ret = iommu_attach_device(d->domain, &pdev->dev);
	if (!ret)
		return 0;

err_domain:
	iommu_domain_free(d->domain);
	d->domain = NULL;
err:
	mk_iommu_free_dev(d);
	return ret;
}

/**
 * mk_iommu_contain - Confine the DMA of an instance's devices to its memory
 * @instance: Instance about to be started
 *
 * Returns 0, or a negative error code, in which case nothing is attached
 * and the instance must not be started: its devices would either fault
 * or roam.
 */
int mk_iommu_contain(struct mk_instance *instance)
{
	struct mk_pci_device *mine;
	int ret = 0;

	mk_iommu_release(instance);

	if (!instance->pci_devices_valid)
		return 0;

	mutex_lock(&mk_iommu_lock);
	list_for_each_entry(mine, &instance->pci_devices, list) {
		struct pci_dev *pdev;

		pdev = pci_get_domain_bus_and_slot(mine->domain, mine->bus,
						   PCI_DEVFN(mine->slot, mine->func));
		if (!pdev)
			continue;

		if (device_iommu_mapped(&pdev->dev))
			ret = mk_iommu_contain_dev(instance, pdev);
		else
			pr_info_once("%s has no IOMMU, DMA of instance devices is unrestricted\n",
				     pci_name(pdev));
		if (ret)
			pci_err(pdev, "DMA not confined to instance %d: %d\n",
				instance->id, ret);
		pci_dev_put(pdev);
		if (ret)
			break;
	}
	mutex_unlock(&mk_iommu_lock);

	if (ret)
		mk_iommu_release(instance);
	return ret;
}

/**
 * mk_iommu_release - Return an instance's devices to the host's domain
 * @instance: Instance that has halted, or is about to be started afresh
 */
void mk_iommu_release(struct mk_instance *instance)
{
	struct mk_iommu_dev *d, *tmp;

	mutex_lock(&mk_iommu_lock);
	list_for_each_entry_safe(d, tmp, &mk_iommu_devs, list) {
		if (d->instance == instance)
			mk_iommu_free_dev(d);
	}
	mutex_unlock(&mk_iommu_lock);
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
