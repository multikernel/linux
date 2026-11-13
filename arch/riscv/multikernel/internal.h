/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _RISCV_MULTIKERNEL_INTERNAL_H
#define _RISCV_MULTIKERNEL_INTERNAL_H

#include <linux/types.h>

struct device_node;
struct kimage;
struct mk_instance;

int mk_build_boot_dtb(struct kimage *image, struct mk_instance *instance);

/*
 * Helpers that add to a boot tree return libfdt error codes only, which
 * share their values with errnos and must not be mixed with them.
 */
int mk_dtb_set_reg(void *fdt, int node, const u64 *pairs, int nr);
int mk_dtb_copy_node(void *fdt, int parent, struct device_node *np);

#endif /* _RISCV_MULTIKERNEL_INTERNAL_H */
