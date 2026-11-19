/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2007-2010 Advanced Micro Devices, Inc.
 * Author: Joerg Roedel <joerg.roedel@amd.com>
 *         Leo Duran <leo.duran@amd.com>
 */

#ifndef _ASM_X86_AMD_IOMMU_H
#define _ASM_X86_AMD_IOMMU_H

#include <linux/errno.h>
#include <linux/types.h>

struct amd_iommu;
struct pci_dev;

/* An IOMMU this kernel drives, as another kernel needs to know it */
struct amd_iommu_unit_desc {
	u64	base;		/* register base	*/
	u64	size;		/* size of register set */
	u16	segment;	/* PCI segment		*/
	bool	irq_remap;	/* remaps the interrupts of the devices behind it */
	u32	cap;		/* capability header of its PCI function */
};

/* @count functions from @rid on, whose interrupts are remapped as @devid on */
struct amd_iommu_unit_map {
	u16	rid;
	u16	devid;
	u16	count;
};

/* How a kernel learns of the IOMMUs another kernel drives, and writes to them */
struct amd_iommu_foreign_ops {
	/* The @i-th IOMMU, or -ENOENT past the last */
	int (*unit)(int i, struct amd_iommu_unit_desc *desc);
	/* The @i-th range of functions behind the IOMMU at @base, or -ENOENT */
	int (*map)(u64 base, int i, struct amd_iommu_unit_map *range);
	/* Have the owner deliver an entry of @devid to @vector, or clear it with 0 */
	int (*irte_write)(u64 base, u16 devid, u32 index, u8 vector, u32 apicid);
};

#ifdef CONFIG_AMD_IOMMU

struct task_struct;

extern void amd_iommu_detect(void);
int amd_iommu_unit_get(int i, struct amd_iommu_unit_desc *desc);
int amd_iommu_device_unit(struct pci_dev *pdev, u64 *base, u16 *devid);
void amd_iommu_set_foreign_ops(const struct amd_iommu_foreign_ops *ops);
int amd_iommu_claim(u64 base);

#else /* CONFIG_AMD_IOMMU */

static inline void amd_iommu_detect(void) { }

static inline int amd_iommu_unit_get(int i, struct amd_iommu_unit_desc *desc)
{
	return -ENOENT;
}

static inline int amd_iommu_device_unit(struct pci_dev *pdev, u64 *base,
					u16 *devid)
{
	return -ENODEV;
}

static inline void amd_iommu_set_foreign_ops(const struct amd_iommu_foreign_ops *ops)
{
}

static inline int amd_iommu_claim(u64 base)
{
	return -ENODEV;
}

#endif /* CONFIG_AMD_IOMMU */

#if defined(CONFIG_AMD_IOMMU) && defined(CONFIG_IRQ_REMAP)

/* IOMMU AVIC Function */
extern int amd_iommu_register_ga_log_notifier(int (*notifier)(u32));

extern int amd_iommu_update_ga(void *data, int cpu, bool ga_log_intr);
extern int amd_iommu_activate_guest_mode(void *data, int cpu, bool ga_log_intr);
extern int amd_iommu_deactivate_guest_mode(void *data);

/* Remapping entries of a function lent to another kernel */
int amd_iommu_irte_write(struct pci_dev *pdev, unsigned int index, u8 vector,
			 u32 apicid);
void amd_iommu_irte_release(struct pci_dev *pdev);

#else /* defined(CONFIG_AMD_IOMMU) && defined(CONFIG_IRQ_REMAP) */

static inline int
amd_iommu_register_ga_log_notifier(int (*notifier)(u32))
{
	return 0;
}

static inline int amd_iommu_update_ga(void *data, int cpu, bool ga_log_intr)
{
	return 0;
}

static inline int amd_iommu_activate_guest_mode(void *data, int cpu, bool ga_log_intr)
{
	return 0;
}

static inline int amd_iommu_deactivate_guest_mode(void *data)
{
	return 0;
}

static inline int amd_iommu_irte_write(struct pci_dev *pdev, unsigned int index,
				       u8 vector, u32 apicid)
{
	return -ENODEV;
}

static inline void amd_iommu_irte_release(struct pci_dev *pdev)
{
}
#endif /* defined(CONFIG_AMD_IOMMU) && defined(CONFIG_IRQ_REMAP) */

int amd_iommu_get_num_iommus(void);
bool amd_iommu_pc_supported(void);
u8 amd_iommu_pc_get_max_banks(unsigned int idx);
u8 amd_iommu_pc_get_max_counters(unsigned int idx);
int amd_iommu_pc_set_reg(struct amd_iommu *iommu, u8 bank, u8 cntr, u8 fxn,
		u64 *value);
int amd_iommu_pc_get_reg(struct amd_iommu *iommu, u8 bank, u8 cntr, u8 fxn,
		u64 *value);
struct amd_iommu *get_amd_iommu(unsigned int idx);

#ifdef CONFIG_KVM_AMD_SEV
int amd_iommu_snp_disable(void);
extern bool amd_iommu_sev_tio_supported(void);
#else
static inline int amd_iommu_snp_disable(void) { return 0; }
static inline bool amd_iommu_sev_tio_supported(void) { return false; }
#endif

#endif /* _ASM_X86_AMD_IOMMU_H */
