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
 * onto itself, the MSI doorbells of the instance's CPUs where they have
 * their own, and once the instance maps an MSI, the doorbell of the ITS
 * behind the device. The device works untranslated, and cannot reach
 * anything else.
 * The domain follows the grant as memory and CPUs are added and removed,
 * and goes away with the lease.
 *
 * The IOMMU cannot tell the functions of an IOMMU group apart, so they
 * share one domain and one instance. The first lease to be granted
 * attaches the domain, once every function of the group that mk_pciback
 * holds is the instance's, and the first lease to end takes it away,
 * which blocks the whole group before any function of it is reset. Each
 * lease has a lock of its own, so mk_iommu_lock is what keeps the domain
 * in place here.
 *
 * What this kernel keeps in a group, the bridge above its functions for
 * one, is never lent and does not count.
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
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "internal.h"

static DEFINE_MUTEX(mk_iommu_lock);

static int mk_iommu_prot(struct pci_dev *pdev)
{
	return IOMMU_READ | IOMMU_WRITE |
	       (dev_is_dma_coherent(&pdev->dev) ? IOMMU_CACHE : 0);
}

/*
 * The domain the leases on the group of @pdev share, or NULL while the
 * group is blocked: before the first of them, and once one of them ended.
 */
static struct iommu_domain *mk_iommu_domain(struct pci_dev *pdev)
{
	struct iommu_domain *domain = iommu_get_domain_for_dev(&pdev->dev);

	lockdep_assert_held(&mk_iommu_lock);

	if (!domain || domain->type != IOMMU_DOMAIN_UNMANAGED)
		return NULL;
	return domain;
}

/**
 * mk_iommu_claim - Take the DMA of a function this kernel let go of
 * @pdev: The function
 * @owner: Its holder, which is never an instance, and is the same for
 *	   every function of an IOMMU group
 *
 * Leaves the function in the blocking domain until a lease attaches a
 * domain.
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

static int mk_iommu_count(struct device *dev, void *data)
{
	unsigned int *count = data;

	++*count;
	return 0;
}

static int mk_iommu_other_held(struct device *dev, void *data)
{
	return dev != data && dev_is_pci(dev) && mk_lease_held(to_pci_dev(dev));
}

/**
 * mk_iommu_group_shared - Whether a function shares its DMA with others
 * that can be lent
 * @pdev: The function
 *
 * One that does is lent with them or not at all, which leaves no way to
 * add it to a running instance, or to take it back from one.
 */
bool mk_iommu_group_shared(struct pci_dev *pdev)
{
	struct iommu_group *group = iommu_group_get(&pdev->dev);
	bool shared;

	if (!group)
		return false;
	shared = iommu_group_for_each_dev(group, &pdev->dev, mk_iommu_other_held);
	iommu_group_put(group);
	return shared;
}

struct mk_iommu_members {
	struct device *but;
	struct device **devs;
	unsigned int nr;
	unsigned int max;
};

static int mk_iommu_collect_unbound(struct device *dev, void *data)
{
	struct mk_iommu_members *members = data;

	if (members->nr == members->max)
		return -ENOSPC;
	if (dev != members->but && !dev->driver)
		members->devs[members->nr++] = get_device(dev);
	return 0;
}

/**
 * mk_iommu_reprobe_group - Let the rest of a function's IOMMU group find
 * its drivers
 * @pdev: A function mk_pciback just took, or just let go of
 *
 * An IOMMU group has one DMA owner, while its functions change hands one
 * at a time. One that went ahead of the owner was left without a driver:
 * mk_pciback could not claim it next to a driver of this kernel, nor a
 * driver of this kernel use it next to the claim.
 */
void mk_iommu_reprobe_group(struct pci_dev *pdev)
{
	struct iommu_group *group = iommu_group_get(&pdev->dev);
	struct mk_iommu_members members = { .but = &pdev->dev };
	unsigned int i;

	if (!group)
		return;

	iommu_group_for_each_dev(group, &members.max, mk_iommu_count);
	members.devs = kzalloc_objs(*members.devs, members.max);
	if (members.devs) {
		iommu_group_for_each_dev(group, &members, mk_iommu_collect_unbound);
		/* Probing takes the group's lock */
		for (i = 0; i < members.nr; i++) {
			if (device_attach(members.devs[i]) < 0)
				dev_warn(members.devs[i], "no driver took it with its IOMMU group\n");
			put_device(members.devs[i]);
		}
		kfree(members.devs);
	}
	iommu_group_put(group);
}

struct mk_iommu_grant {
	struct mk_instance *instance;
	struct pci_dev *pdev;
};

/*
 * What this kernel kept in the group does no DMA, or mk_pciback could
 * not have claimed the group: a bridge under its port driver, a function
 * without a driver. Only what mk_pciback holds can be another
 * instance's.
 *
 * A hot added function is not in its instance's list until the instance
 * took it.
 */
static int mk_iommu_check_member(struct device *dev, void *data)
{
	const struct mk_iommu_grant *grant = data;
	const struct mk_pci_device *mine;
	struct pci_dev *pdev;

	if (dev == &grant->pdev->dev || !dev_is_pci(dev))
		return 0;
	pdev = to_pci_dev(dev);
	if (!mk_lease_held(pdev))
		return 0;

	list_for_each_entry(mine, &grant->instance->pci_devices, list) {
		if (mine->domain == pci_domain_nr(pdev->bus) &&
		    mine->bus == pdev->bus->number &&
		    PCI_DEVFN(mine->slot, mine->func) == pdev->devfn)
			return 0;
	}
	return -EXDEV;
}

static struct iommu_domain *mk_iommu_domain_alloc(struct mk_instance *instance,
						  struct pci_dev *pdev)
{
	struct mk_memory_region *region;
	struct iommu_domain *domain;
	int ret;

	domain = iommu_paging_domain_alloc(&pdev->dev);
	if (IS_ERR(domain))
		return domain;

	list_for_each_entry(region, &instance->memory_regions, list) {
		ret = iommu_map(domain, region->res.start, region->res.start,
				resource_size(&region->res), mk_iommu_prot(pdev),
				GFP_KERNEL);
		if (ret) {
			iommu_domain_free(domain);
			return ERR_PTR(ret);
		}
	}
	return domain;
}

/*
 * A function that joins the group later cannot be told apart either. The
 * claim keeps the drivers of this kernel that do DMA off it.
 */
static int mk_iommu_attach(struct mk_instance *instance, struct pci_dev *pdev,
			   struct iommu_group *group)
{
	struct mk_iommu_grant grant = { .instance = instance, .pdev = pdev };
	struct iommu_domain *domain;
	int ret;

	guard(mutex)(&mk_iommu_lock);

	ret = iommu_group_for_each_dev(group, &grant, mk_iommu_check_member);
	if (ret)
		return ret;

	/* The rest of the group is the instance's, and so is its domain */
	if (mk_iommu_domain(pdev))
		return 0;

	domain = mk_iommu_domain_alloc(instance, pdev);
	if (IS_ERR(domain))
		return PTR_ERR(domain);

	ret = iommu_attach_group(domain, group);
	if (ret)
		iommu_domain_free(domain);
	return ret;
}

/* The claim keeps the group in the blocking domain from here on */
static void mk_iommu_unconfine(void *data)
{
	struct pci_dev *pdev = data;
	struct iommu_group *group = iommu_group_get(&pdev->dev);
	struct iommu_domain *domain;

	scoped_guard(mutex, &mk_iommu_lock) {
		domain = mk_iommu_domain(pdev);
		if (domain) {
			iommu_detach_group(domain, group);
			iommu_domain_free(domain);
		}
	}
	iommu_group_put(group);
}

/**
 * mk_iommu_confine - Confine a leased device's DMA to its instance's memory
 * @instance: Instance being granted the device
 * @pdev: The device, which mk_iommu_claim() took
 *
 * Confined until the lease ends, or the lease of another function of its
 * IOMMU group does.
 *
 * Returns: 0, or a negative error code, in which case the instance must
 * not have the device: it would either fault or roam. -EXDEV if
 * mk_pciback holds a function of the device's IOMMU group that is not the
 * instance's.
 */
int mk_iommu_confine(struct mk_instance *instance, struct pci_dev *pdev)
{
	struct iommu_group *group;
	mk_phys_cpu_t cpu;
	phys_addr_t doorbell;
	unsigned int i;
	int ret;

	if (!device_iommu_mapped(&pdev->dev)) {
		pr_info_once("%s has no IOMMU, DMA of instance devices is unrestricted\n",
			     pci_name(pdev));
		return 0;
	}

	group = iommu_group_get(&pdev->dev);
	ret = mk_iommu_attach(instance, pdev, group);
	iommu_group_put(group);
	if (ret) {
		pci_err(pdev, "DMA not confined to instance %d: %d\n",
			instance->id, ret);
		return ret;
	}

	ret = devm_add_action_or_reset(&pdev->dev, mk_iommu_unconfine, pdev);
	if (ret)
		return ret;

	mk_cpu_set_for_each(i, cpu, instance->cpus) {
		doorbell = mk_arch_cpu_msi_doorbell(cpu);
		if (!doorbell)
			continue;
		ret = mk_iommu_allow_msi(pdev, doorbell);
		if (ret)
			return ret;
	}
	return 0;
}

/**
 * mk_iommu_allow_msi - Let a leased device write to an MSI doorbell
 * @pdev: The device
 * @doorbell: Address the device writes its MSIs to
 *
 * Allowed until the lease ends, with the domain.
 *
 * Returns: 0 on success, or a negative error code, -ENODEV if the lease of
 * another function of the IOMMU group ended and took the domain away
 */
int mk_iommu_allow_msi(struct pci_dev *pdev, phys_addr_t doorbell)
{
	phys_addr_t page = doorbell & PAGE_MASK;
	struct iommu_domain *domain;

	if (!device_iommu_mapped(&pdev->dev))
		return 0;

	guard(mutex)(&mk_iommu_lock);
	domain = mk_iommu_domain(pdev);
	if (!domain)
		return -ENODEV;

	/* A MAP that failed after opening it, or another function, opened it already */
	if (iommu_iova_to_phys(domain, page) == page)
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
 * Returns: 0 on success, or a negative error code, -ENODEV if the lease of
 * another function of the IOMMU group ended and took the domain away
 */
int mk_iommu_map(struct pci_dev *pdev, phys_addr_t start, size_t size)
{
	struct iommu_domain *domain;

	if (!device_iommu_mapped(&pdev->dev))
		return 0;

	guard(mutex)(&mk_iommu_lock);
	domain = mk_iommu_domain(pdev);
	if (!domain)
		return -ENODEV;

	/* Ranges are mapped whole, this one for another function of the group */
	if (iommu_iova_to_phys(domain, start) == start)
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
	struct iommu_domain *domain;

	if (!device_iommu_mapped(&pdev->dev))
		return;

	guard(mutex)(&mk_iommu_lock);
	domain = mk_iommu_domain(pdev);
	if (domain)
		iommu_unmap(domain, start, size);
}
