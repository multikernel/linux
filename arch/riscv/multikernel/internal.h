/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _RISCV_MULTIKERNEL_INTERNAL_H
#define _RISCV_MULTIKERNEL_INTERNAL_H

#include <linux/multikernel.h>
#include <linux/types.h>

struct device_node;
struct kimage;
struct mk_instance;

/* A disabled node is still found: only a failed one is skipped */
struct device_node *mk_of_hart_node(mk_phys_cpu_t hartid);

/* A hart this kernel never booted, as it described itself */
struct mk_hart {
	struct list_head node;
	mk_phys_cpu_t hartid;
	unsigned long mvendorid;
	unsigned long marchid;
	unsigned long mimpid;
	unsigned int kind;	/* 0 if alike this kernel's harts */
	u64 passed;		/* MK_PROBE_* bits */
	phys_addr_t file;	/* Its IMSIC interrupt file, 0 for none */
	u32 phandle;		/* Of its local interrupt controller */
};

unsigned int mk_hart_isa_extensions(const struct mk_hart *hart,
				    const char **names);
/* Sets the hart's phandle. One caller at a time. */
int mk_hart_add_node(struct mk_hart *hart);

extern struct list_head mk_unclaimed_harts;

#define mk_for_each_unclaimed_hart(hart) \
	list_for_each_entry_lockless(hart, &mk_unclaimed_harts, node)

int mk_hsm_start(mk_phys_cpu_t hartid, phys_addr_t entry, phys_addr_t opaque);
int mk_wait_hart_stopped(mk_phys_cpu_t hartid);
int mk_sse_stop_hart(mk_phys_cpu_t hartid);

bool mk_imsic_file_taken(phys_addr_t file);
unsigned int mk_imsic_free_files(u64 *files, unsigned int max,
				 unsigned int nr_harts);

int mk_build_boot_dtb(struct kimage *image, struct mk_instance *instance);

/*
 * Helpers that add to a boot tree return libfdt error codes only, which
 * share their values with errnos and must not be mixed with them.
 */
int mk_dtb_set_reg(void *fdt, int node, const u64 *pairs, int nr);
int mk_dtb_copy_node(void *fdt, int parent, struct device_node *np);
int mk_dtb_add_imsic(void *fdt);

#endif /* _RISCV_MULTIKERNEL_INTERNAL_H */
