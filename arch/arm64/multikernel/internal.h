/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ARM64_MULTIKERNEL_INTERNAL_H
#define _ARM64_MULTIKERNEL_INTERNAL_H

#include <linux/libfdt.h>
#include <linux/types.h>

struct kimage;
struct mk_instance;

/* GIC interrupt specifier cells, as in dt-bindings/interrupt-controller/arm-gic.h */
#define MK_GIC_PPI		1
#define MK_GIC_PHANDLE		1

int mk_build_boot_dtb(struct kimage *image, struct mk_instance *instance);

int mk_dtb_set_reg(void *fdt, int node, const u64 *pairs, int nr);

/* The MSI proxy of the instance's PCI root buses */
int mk_dtb_add_pci(void *fdt);

struct irq_domain;
struct pci_dev;
#ifdef CONFIG_MULTIKERNEL_ITS_PROXY
int mk_its_lookup(u32 domain, u32 rid, struct irq_domain **its, u32 *dev_id);
void mk_msi_proxy_rebind(void);
void mk_msi_resolve(struct pci_dev *pdev, struct irq_domain **its, u32 *dev_id);
#else
static inline void mk_msi_resolve(struct pci_dev *pdev, struct irq_domain **its,
				  u32 *dev_id)
{
	*its = NULL;
}
#endif

/*
 * The part of the machine every kernel drives for itself: PSCI, the arch
 * timer and the interrupt controller. Taken from whichever description
 * this kernel booted with.
 */
int mk_dtb_add_platform_of(void *fdt);
#ifdef CONFIG_ACPI
int mk_dtb_add_platform_acpi(void *fdt);
#else
static inline int mk_dtb_add_platform_acpi(void *fdt)
{
	return -FDT_ERR_NOTFOUND;
}
#endif

/* Force halt through SDEI, where firmware has it */
#ifdef CONFIG_ARM_SDE_INTERFACE
int mk_dtb_add_sdei(void *fdt);
int mk_sdei_stop_cpu(struct mk_instance *instance, u64 mpidr);
void mk_sdei_unreachable(void);
#else
static inline int mk_dtb_add_sdei(void *fdt)
{
	return 0;
}

static inline int mk_sdei_stop_cpu(struct mk_instance *instance, u64 mpidr)
{
	return -ENODEV;
}

static inline void mk_sdei_unreachable(void)
{
}
#endif

#endif /* _ARM64_MULTIKERNEL_INTERNAL_H */
