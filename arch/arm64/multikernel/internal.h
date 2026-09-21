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

#endif /* _ARM64_MULTIKERNEL_INTERNAL_H */
