/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ARCH_X86_MULTIKERNEL_IOMMU_H
#define _ARCH_X86_MULTIKERNEL_IOMMU_H

#include <linux/errno.h>
#include <linux/types.h>

struct mk_instance;
struct pci_dev;

#define MK_IOMMUS_PATH		"/chosen/multikernel,iommus"

/*
 * MK_IO_IRTE_WRITE and its MK_IO_IRTE_ACK: have the host write an interrupt
 * remapping entry of a unit. What @low and @high hold is the vendor's.
 */
struct mk_irte_payload {
	u64 seq;
	u64 unit;		/* register base of the unit */
	u64 low;
	u64 high;
	u32 index;
	u32 mask;		/* with a zero entry: clear 1 << mask entries */
	int result;		/* ACK: 0 or -errno */
	int sender_instance_id;
};

int mk_irte_write(u64 unit, u32 index, u32 mask, u64 low, u64 high);

#ifdef CONFIG_DMAR_TABLE
int mk_dmar_emit_units(void *fdt, struct mk_instance *instance);
int mk_dmar_irte_apply(struct mk_instance *instance,
		       const struct mk_irte_payload *req);
int mk_dmar_lease_grant(struct mk_instance *instance, struct pci_dev *pdev);
int mk_dmar_claim(u64 base);
#else
static inline int mk_dmar_emit_units(void *fdt, struct mk_instance *instance)
{
	return 0;
}
static inline int mk_dmar_irte_apply(struct mk_instance *instance,
				     const struct mk_irte_payload *req)
{
	return -ENODEV;
}
static inline int mk_dmar_lease_grant(struct mk_instance *instance,
				      struct pci_dev *pdev)
{
	return 0;
}
static inline int mk_dmar_claim(u64 base)
{
	return -ENODEV;
}
#endif

#ifdef CONFIG_AMD_IOMMU
bool mk_amd_vi_units(void);
int mk_amd_vi_emit_units(void *fdt);
int mk_amd_vi_irte_apply(struct mk_instance *instance,
			 const struct mk_irte_payload *req);
int mk_amd_vi_lease_grant(struct pci_dev *pdev);
#else
static inline bool mk_amd_vi_units(void)
{
	return false;
}
static inline int mk_amd_vi_emit_units(void *fdt)
{
	return 0;
}
static inline int mk_amd_vi_irte_apply(struct mk_instance *instance,
				       const struct mk_irte_payload *req)
{
	return -ENODEV;
}
static inline int mk_amd_vi_lease_grant(struct pci_dev *pdev)
{
	return 0;
}
#endif

#endif /* _ARCH_X86_MULTIKERNEL_IOMMU_H */
