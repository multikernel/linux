// SPDX-License-Identifier: GPL-2.0-only
/* Host IOMMU lifecycle for multikernel PCI assignments. */
#include <linux/delay.h>
#include <linux/device/bus.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "pci_internal.h"
#include "internal.h"

void
mk_pci_release_bound_driver(struct mk_pci_assignment *assignment)
{
	unsigned long flags;

	spin_lock_irqsave(&mk_pci_active_lock, flags);
	assignment->expected_unbind = true;
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);
	device_release_driver(&assignment->vf->dev);
	spin_lock_irqsave(&mk_pci_active_lock, flags);
	assignment->expected_unbind = false;
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);
}

#if IS_ENABLED(CONFIG_IOMMU_API)
#define MK_PCI_ASSIGNMENT_DRIVER_NAME "multikernel-pci-assignment"

static int mk_pci_iommu_assignment_probe(struct pci_dev *pdev,
					 const struct pci_device_id *id);
static void mk_pci_iommu_assignment_remove(struct pci_dev *pdev);

static struct pci_driver mk_pci_assignment_driver = {
	.name = MK_PCI_ASSIGNMENT_DRIVER_NAME,
	.probe = mk_pci_iommu_assignment_probe,
	.remove = mk_pci_iommu_assignment_remove,
	.driver_managed_dma = true,
};

struct mk_pci_iommu_group_check {
	struct device *vf;
	unsigned int count;
};

static int mk_pci_iommu_check_group_device(struct device *dev, void *data)
{
	struct mk_pci_iommu_group_check *check = data;

	check->count++;
	return dev == check->vf ? 0 : -EXDEV;
}

static void mk_pci_iommu_free_resv_regions(struct list_head *regions)
{
	struct iommu_resv_region *region, *tmp;

	list_for_each_entry_safe(region, tmp, regions, list) {
		list_del(&region->list);
		kfree(region);
	}
}

static int mk_pci_iommu_validate_group(struct mk_pci_assignment *assignment)
{
	struct mk_pci_iommu_group_check check = {
		.vf = &assignment->vf->dev,
	};
	int ret;

	ret = iommu_group_for_each_dev(assignment->iommu_group, &check,
				       mk_pci_iommu_check_group_device);
	if (ret || check.count != 1) {
		pr_err("IOMMU group %d for %s is not an isolated singleton group\n",
		       iommu_group_id(assignment->iommu_group),
		       pci_name(assignment->vf));
		return ret ?: -EXDEV;
	}

	if (!iommu_group_has_isolated_msi(assignment->iommu_group)) {
		pr_err("IOMMU group %d for %s lacks isolated MSI delivery\n",
		       iommu_group_id(assignment->iommu_group),
		       pci_name(assignment->vf));
		return -EPERM;
	}

	return 0;
}

static int
mk_pci_iommu_validate_resv_regions(struct mk_pci_assignment *assignment)
{
	struct iommu_resv_region *region;
	struct mk_memory_region *memory;
	LIST_HEAD(resv_regions);
	u64 memory_end, resv_end;
	int ret;

	ret = iommu_get_group_resv_regions(assignment->iommu_group,
					   &resv_regions);
	if (ret)
		goto out;

	list_for_each_entry(region, &resv_regions, list) {
		if (region->type == IOMMU_RESV_DIRECT_RELAXABLE)
			continue;
		if (!region->length ||
		    check_add_overflow((u64)region->start,
				       (u64)region->length - 1, &resv_end)) {
			pr_err("IOMMU group %d for %s has invalid reserved region at %#llx\n",
			       iommu_group_id(assignment->iommu_group),
			       pci_name(assignment->vf),
			       (unsigned long long)region->start);
			ret = -EOVERFLOW;
			goto out;
		}

		list_for_each_entry(memory,
				    &assignment->instance->memory_regions, list) {
			resource_size_t size = resource_size(&memory->res);

			if (!size ||
			    check_add_overflow((u64)memory->res.start,
					       (u64)size - 1, &memory_end)) {
				ret = -EOVERFLOW;
				goto out;
			}
			if ((u64)memory->res.start > resv_end ||
			    memory_end < (u64)region->start)
				continue;

			pr_err("Instance %d IOVA %#llx-%#llx overlaps IOMMU reserved region %#llx-%#llx type %u for %s\n",
			       assignment->instance->id,
			       (unsigned long long)memory->res.start,
			       (unsigned long long)memory_end,
			       (unsigned long long)region->start,
			       (unsigned long long)resv_end, region->type,
			       pci_name(assignment->vf));
			ret = -EPERM;
			goto out;
		}
	}

	ret = 0;
out:
	mk_pci_iommu_free_resv_regions(&resv_regions);
	return ret;
}

static int
mk_pci_iommu_validate_region(struct mk_pci_assignment *assignment,
			     const struct mk_memory_region *region)
{
	struct iommu_domain *domain = assignment->iommu_domain;
	resource_size_t start = region->res.start;
	resource_size_t size = resource_size(&region->res);
	u64 dma_mask = dma_get_mask(&assignment->vf->dev);
	u64 end;
	unsigned long min_page_size;

	if (!size || check_add_overflow((u64)start, (u64)size - 1, &end))
		return -EOVERFLOW;
	if (!domain->pgsize_bitmap)
		return -EOPNOTSUPP;

	min_page_size = 1UL << __ffs(domain->pgsize_bitmap);
	if (!IS_ALIGNED(start, min_page_size) ||
	    !IS_ALIGNED(size, min_page_size)) {
		pr_err("Instance %d memory %#llx-%#llx is not aligned to IOMMU page size %#lx\n",
		       assignment->instance->id, (unsigned long long)start,
		       (unsigned long long)end, min_page_size);
		return -EINVAL;
	}
	if (start > ULONG_MAX || end > ULONG_MAX || end > dma_mask) {
		pr_err("Instance %d memory %#llx-%#llx exceeds DMA addressability of %s\n",
		       assignment->instance->id, (unsigned long long)start,
		       (unsigned long long)end, pci_name(assignment->vf));
		return -ERANGE;
	}
	if (domain->geometry.force_aperture &&
	    (start < domain->geometry.aperture_start ||
	     end > domain->geometry.aperture_end)) {
		pr_err("Instance %d memory %#llx-%#llx is outside the IOMMU aperture for %s\n",
		       assignment->instance->id, (unsigned long long)start,
		       (unsigned long long)end, pci_name(assignment->vf));
		return -ERANGE;
	}

	return 0;
}

static void mk_pci_iommu_unmap_regions(struct mk_pci_assignment *assignment)
{
	struct mk_memory_region *region;
	unsigned int remaining = assignment->iommu_mapped_regions;

	list_for_each_entry(region, &assignment->instance->memory_regions, list) {
		resource_size_t size;
		size_t unmapped;

		if (!remaining)
			break;
		size = resource_size(&region->res);
		unmapped = iommu_unmap(assignment->iommu_domain,
				       region->res.start, size);
		if (unmapped != size)
			pr_err("IOMMU unmapped only %#zx of %#llx bytes for instance %d at %#llx\n",
			       unmapped, (unsigned long long)size,
			       assignment->instance->id,
			       (unsigned long long)region->res.start);
		remaining--;
	}
	if (remaining)
		pr_err("IOMMU lease for %s lost %u mapped instance regions\n",
		       pci_name(assignment->vf), remaining);
	assignment->iommu_mapped_regions = 0;
}

int
mk_pci_quiesce_assignment(struct mk_pci_assignment *assignment)
{
	struct pci_dev *vf = assignment->vf;
	bool transactions_drained;
	int ret;

	ret = mk_pci_release_irqs(assignment, false);
	if (ret)
		return ret;
	if (!mk_pci_device_live(vf))
		return 0;

	/*
	 * Releasing DMA ownership restores the group's default domain. Stop new
	 * DMA first, drain requests already issued, and reset the VF while the
	 * assignment domain still contains any stragglers.
	 */
	pci_clear_master(vf);
	transactions_drained = pci_wait_for_pending_transaction(vf);
	ret = pcie_reset_flr(vf, false);
	if (!ret)
		return 0;
	if (ret == -ENOTTY && transactions_drained)
		return 0;

	if (!transactions_drained)
		pr_err("Timed out draining DMA from assigned VF %s\n",
		       pci_name(vf));
	if (ret != -ENOTTY)
		pr_err("Failed to reset assigned VF %s: %d\n",
		       pci_name(vf), ret);

	/*
	 * Keep the assignment domain attached when the device cannot be made
	 * safe. The lease owner can retry teardown after the instance halts.
	 */
	return ret == -ENOTTY ? -ETIMEDOUT : ret;
}

int
mk_pci_reset_assignment_for_start(struct mk_pci_assignment *assignment)
{
	struct pci_dev *vf = assignment->vf;
	int ret;

	ret = mk_pci_release_irqs(assignment, true);
	if (ret)
		return ret;
	assignment->irq_epoch = 0;
	assignment->irq_generation = 0;
	assignment->reset_generation = 0;
	assignment->irq_state = MK_PCI_MSI_IDLE;
	if (!assignment->assigned || !assignment->iommu_attached)
		return -EINVAL;
	if (!mk_pci_device_live(vf))
		return -ENODEV;

	/*
	 * A stopped instance may have left DMA active. Keep its restrictive
	 * domain attached while stopping new requests, draining old ones, and
	 * resetting device state before the instance image is reused.
	 */
	pci_clear_master(vf);
	if (!pci_wait_for_pending_transaction(vf)) {
		pr_err("Timed out draining assigned VF %s before instance restart\n",
		       pci_name(vf));
		return -ETIMEDOUT;
	}

	ret = pcie_reset_flr(vf, false);
	if (ret) {
		pr_err("Failed to reset assigned VF %s before instance restart: %d\n",
		       pci_name(vf), ret);
		return ret == -ENOTTY ? -EOPNOTSUPP : ret;
	}
	return 0;
}

static void
__mk_pci_iommu_deactivate_assignment(struct mk_pci_assignment *assignment)
{
	if (assignment->iommu_attached) {
		iommu_detach_group(assignment->iommu_domain,
				   assignment->iommu_group);
		assignment->iommu_attached = false;
	}
	if (assignment->iommu_dma_owner) {
		iommu_device_release_dma_owner(&assignment->vf->dev);
		assignment->iommu_dma_owner = false;
	}
}

void
mk_pci_iommu_deactivate_assignment(struct mk_pci_assignment *assignment)
{
	mutex_lock(&assignment->iommu_mutex);
	__mk_pci_iommu_deactivate_assignment(assignment);
	mutex_unlock(&assignment->iommu_mutex);
}

void mk_pci_iommu_release_assignment(struct mk_pci_assignment *assignment)
{
	mutex_lock(&assignment->iommu_mutex);
	__mk_pci_iommu_deactivate_assignment(assignment);

	if (assignment->iommu_domain) {
		mk_pci_iommu_unmap_regions(assignment);
		iommu_domain_free(assignment->iommu_domain);
		assignment->iommu_domain = NULL;
	}
	if (assignment->iommu_group) {
		iommu_group_put(assignment->iommu_group);
		assignment->iommu_group = NULL;
	}
	mutex_unlock(&assignment->iommu_mutex);
}

int mk_pci_iommu_prepare_assignment(struct mk_pci_assignment *assignment)
{
	struct mk_memory_region *region;
	int ret;

	if (!device_iommu_mapped(&assignment->vf->dev)) {
		pr_err("Cannot assign %s without an active hardware IOMMU\n",
		       pci_name(assignment->vf));
		return -EOPNOTSUPP;
	}
	if (!device_iommu_capable(&assignment->vf->dev,
				  IOMMU_CAP_CACHE_COHERENCY)) {
		pr_err("Cannot assign %s without coherent IOMMU mappings\n",
		       pci_name(assignment->vf));
		return -EOPNOTSUPP;
	}
	if (!assignment->instance->region_count ||
	    list_empty(&assignment->instance->memory_regions))
		return -EINVAL;

	assignment->iommu_group = iommu_group_get(&assignment->vf->dev);
	if (!assignment->iommu_group)
		return -ENODEV;

	ret = mk_pci_iommu_validate_group(assignment);
	if (ret)
		goto err_release;
	ret = mk_pci_iommu_validate_resv_regions(assignment);
	if (ret)
		goto err_release;

	assignment->iommu_domain =
		iommu_paging_domain_alloc(&assignment->vf->dev);
	if (IS_ERR(assignment->iommu_domain)) {
		ret = PTR_ERR(assignment->iommu_domain);
		assignment->iommu_domain = NULL;
		goto err_release;
	}

	list_for_each_entry(region, &assignment->instance->memory_regions, list) {
		resource_size_t size = resource_size(&region->res);

		ret = mk_pci_iommu_validate_region(assignment, region);
		if (ret)
			goto err_release;
		ret = iommu_map(assignment->iommu_domain, region->res.start,
				region->res.start, size,
				IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE, GFP_KERNEL);
		if (ret)
			goto err_release;
		assignment->iommu_mapped_regions++;
	}

	/*
	 * The domain blocks DMA outside these mappings, but translation-fault
	 * notification is not portable. In particular, Intel VT-d reports primary
	 * faults through dmar_fault() without invoking a legacy domain handler.
	 * Do not claim automatic instance failure on an IOMMU fault here.
	 */
	pr_info("Prepared host IOMMU domain for %s with %u instance regions\n",
		pci_name(assignment->vf), assignment->iommu_mapped_regions);
	return 0;

err_release:
	mk_pci_iommu_release_assignment(assignment);
	return ret;
}

int mk_pci_iommu_commit_assignment(struct mk_pci_assignment *assignment)
{
	int ret;

	if (!assignment->iommu_domain)
		return 0;

	if (assignment->vf->driver_override) {
		assignment->host_driver_override =
			kstrdup(assignment->vf->driver_override, GFP_KERNEL);
		if (!assignment->host_driver_override)
			return -ENOMEM;
	}

	ret = driver_set_override(&assignment->vf->dev,
				  &assignment->vf->driver_override,
				  MK_PCI_ASSIGNMENT_DRIVER_NAME,
				  strlen(MK_PCI_ASSIGNMENT_DRIVER_NAME));
	if (ret)
		return ret;
	assignment->iommu_override_active = true;
	pci_set_drvdata(assignment->vf, assignment);
	ret = device_driver_attach(&mk_pci_assignment_driver.driver,
				   &assignment->vf->dev);
	if (ret)
		return ret;
	if (assignment->vf->dev.driver != &mk_pci_assignment_driver.driver)
		return -ENODEV;
	return 0;
}

static int mk_pci_iommu_assignment_probe(struct pci_dev *pdev,
					 const struct pci_device_id *id)
{
	struct mk_pci_assignment *assignment = pci_get_drvdata(pdev);
	int ret;

	if (!assignment || assignment->vf != pdev || !assignment->iommu_domain)
		return -ENODEV;
	ret = iommu_device_claim_dma_owner(&assignment->vf->dev, assignment);
	if (ret)
		return ret;
	assignment->iommu_dma_owner = true;

	ret = iommu_attach_group(assignment->iommu_domain,
				 assignment->iommu_group);
	if (ret) {
		iommu_device_release_dma_owner(&assignment->vf->dev);
		assignment->iommu_dma_owner = false;
		return ret;
	}
	assignment->iommu_attached = true;
	ret = pci_enable_device(pdev);
	if (ret) {
		iommu_detach_group(assignment->iommu_domain,
				   assignment->iommu_group);
		assignment->iommu_attached = false;
		iommu_device_release_dma_owner(&assignment->vf->dev);
		assignment->iommu_dma_owner = false;
		return ret;
	}
	assignment->device_enabled = true;
	pr_info("Attached %s to host-owned IOMMU domain for instance %d\n",
		pci_name(assignment->vf), assignment->instance->id);
	return 0;
}

static void mk_pci_iommu_assignment_remove(struct pci_dev *pdev)
{
	struct mk_pci_assignment *assignment = pci_get_drvdata(pdev);
	int ret;

	if (!assignment || assignment->vf != pdev)
		return;

	if (READ_ONCE(assignment->expected_unbind)) {
		if (assignment->device_enabled) {
			pci_disable_device(pdev);
			assignment->device_enabled = false;
		}
		pci_set_drvdata(pdev, NULL);
		return;
	}

	ret = mk_pci_quiesce_assignment(assignment);
	if (ret) {
		pr_crit("Keeping IOMMU containment for %s after unsafe driver removal: %d\n",
			pci_name(pdev), ret);
		mk_pci_schedule_failure(assignment);
	} else {
		mk_pci_iommu_deactivate_assignment(assignment);
	}
	if (assignment->device_enabled) {
		pci_disable_device(pdev);
		assignment->device_enabled = false;
	}
	pci_set_drvdata(pdev, NULL);
}

int mk_pci_restore_host_binding(struct mk_pci_assignment *assignment)
{
	struct pci_dev *vf = assignment->vf;
	const char *override = assignment->host_driver_override ?: "";
	int ret = 0;

	if (vf->dev.driver == &mk_pci_assignment_driver.driver) {
		mk_pci_release_bound_driver(assignment);
	} else if (vf->dev.driver) {
		pr_err("Cannot release assignment driver from %s: device is bound to %s\n",
		       pci_name(vf), vf->dev.driver->name);
		return -EBUSY;
	}

	pci_set_drvdata(vf, NULL);
	if (assignment->iommu_override_active) {
		ret = driver_set_override(&vf->dev, &vf->driver_override,
					  override, strlen(override));
		if (ret)
			return ret;
		assignment->iommu_override_active = false;
	}

	mk_pci_iommu_deactivate_assignment(assignment);
	if (assignment->host_driver && mk_pci_device_live(vf)) {
		if (!vf->dev.driver) {
			ret = device_driver_attach(assignment->host_driver, &vf->dev);
			if (ret) {
				pr_err("Failed to restore driver %s to %s: %d\n",
				       assignment->host_driver->name,
				       pci_name(vf), ret);
				return ret;
			}
		} else if (vf->dev.driver != assignment->host_driver) {
			pr_err("Cannot restore driver %s to %s: device is bound to %s\n",
			       assignment->host_driver->name, pci_name(vf),
			       vf->dev.driver->name);
			return -EBUSY;
		}
	}
	return 0;
}

int mk_pci_iommu_system_init(void)
{
	return pci_register_driver(&mk_pci_assignment_driver);
}

void mk_pci_iommu_system_cleanup(void)
{
	pci_unregister_driver(&mk_pci_assignment_driver);
}
#else
int
mk_pci_reset_assignment_for_start(struct mk_pci_assignment *assignment)
{
	return -EOPNOTSUPP;
}

int
mk_pci_quiesce_assignment(struct mk_pci_assignment *assignment)
{
	return 0;
}

void
mk_pci_iommu_deactivate_assignment(struct mk_pci_assignment *assignment)
{
}

int mk_pci_iommu_prepare_assignment(struct mk_pci_assignment *assignment)
{
	pr_err("Cannot assign %s without CONFIG_IOMMU_API\n",
	       pci_name(assignment->vf));
	return -EOPNOTSUPP;
}

int mk_pci_iommu_commit_assignment(struct mk_pci_assignment *assignment)
{
	return 0;
}

void mk_pci_iommu_release_assignment(struct mk_pci_assignment *assignment)
{
}

int mk_pci_restore_host_binding(struct mk_pci_assignment *assignment)
{
	return 0;
}

int mk_pci_iommu_system_init(void)
{
	return 0;
}

void mk_pci_iommu_system_cleanup(void)
{
}
#endif
