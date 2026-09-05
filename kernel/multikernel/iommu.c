// SPDX-License-Identifier: GPL-2.0-only
/*
 * IOMMU units and the devices this kernel hands to a spawn.
 *
 * With interrupt remapping active, the units drop the compatibility
 * format interrupts a spawn kernel programs into its devices, since it
 * owns no remapping table. A unit that covers nothing this kernel still
 * drives can simply be left unused: the devices behind it then deliver
 * plain interrupts. The catch-all unit and any unit serving the IOAPIC
 * or HPET can never be spared, nor can one with a driver still bound
 * to a device behind it.
 */
#include <linux/dmar.h>
#include <linux/multikernel.h>
#include <linux/pci.h>

#include "internal.h"

#if IS_ENABLED(CONFIG_INTEL_IOMMU) && IS_ENABLED(CONFIG_IRQ_REMAP)

struct mk_iommu_check {
	struct pci_dev *self;
	char *reason;
	size_t len;
};

static int mk_iommu_check_dev(struct pci_dev *pdev, void *arg)
{
	struct mk_iommu_check *c = arg;

	if (pdev == c->self || !pdev->dev.driver)
		return 0;
	snprintf(c->reason, c->len, "%s (%s) shares the IOMMU unit with %s",
		 pci_name(pdev), pdev->dev.driver->name, pci_name(c->self));
	return -EBUSY;
}

static int mk_iommu_log_dev(struct pci_dev *pdev, void *arg)
{
	if (pdev != arg)
		pr_info("multikernel: the spared IOMMU unit also covers %s\n",
			pci_name(pdev));
	return 0;
}

int mk_iommu_spare(struct pci_dev *pdev, char *reason, size_t len)
{
	struct mk_iommu_check check = { pdev, reason, len };
	struct dmar_drhd_unit *unit;
	int ret;

	if (!dmar_remapping_active())
		return 1;
	unit = dmar_unit_for_pci_dev(pdev);
	if (!unit) {
		snprintf(reason, len,
			 "no remapping unit lists %s, yet remapping is active: its interrupts would be dropped",
			 pci_name(pdev));
		return -ENODEV;
	}
	if (unit->spared) {
		unit->spared_count++;
		return 0;
	}
	if (dmar_unit_serves_legacy(unit)) {
		snprintf(reason, len,
			 "%s is behind the IOMMU unit that also serves the IOAPIC and this kernel's own devices",
			 pci_name(pdev));
		return -EBUSY;
	}
	ret = dmar_unit_walk(unit, mk_iommu_check_dev, &check);
	if (ret)
		return ret;
	ret = dmar_unit_spare(unit);
	if (ret) {
		snprintf(reason, len, "cannot spare the IOMMU unit behind %s: %d",
			 pci_name(pdev), ret);
		return ret;
	}
	unit->spared_count = 1;
	pr_info("multikernel: spared the IOMMU unit behind %s\n", pci_name(pdev));
	dmar_unit_walk(unit, mk_iommu_log_dev, pdev);
	return 0;
}

void mk_iommu_restore(struct pci_dev *pdev)
{
	struct dmar_drhd_unit *unit = dmar_unit_for_pci_dev(pdev);

	if (!unit || !unit->spared)
		return;
	if (--unit->spared_count > 0)
		return;
	dmar_unit_restore(unit);
	pr_info("multikernel: the IOMMU unit behind %s is back in use\n", pci_name(pdev));
}

bool mk_iommu_remapping_active(void)
{
	return dmar_remapping_active();
}

#else

int mk_iommu_spare(struct pci_dev *pdev, char *reason, size_t len)
{
	return 1;
}

void mk_iommu_restore(struct pci_dev *pdev)
{
}

bool mk_iommu_remapping_active(void)
{
	return false;
}

#endif
