/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Multikernel on architectures whose firmware holds parked CPUs (PSCI,
 * SBI HSM) and whose kernels boot from a device tree: what their boot,
 * halt and memory setup paths call, and what builds an instance's boot
 * tree.
 */
#ifndef _LINUX_MULTIKERNEL_FW_PARK_H
#define _LINUX_MULTIKERNEL_FW_PARK_H

#include <linux/sizes.h>
#include <linux/types.h>

struct kimage;
struct mk_instance;

/*
 * Room for an instance's boot device tree, a segment of its kimage: the
 * manifest (MK_MANIFEST_SIZE) with the architecture's boot nodes on top.
 * The tree is rebuilt in place on every spawn, as the memory grant can
 * have changed since the load.
 */
#define MK_BOOT_DTB_SIZE	SZ_512K

#ifdef CONFIG_MULTIKERNEL_FW_PARK
/* The boot tree is the manifest when another kernel wrote it */
void mk_spawn_accept_boot_tree(phys_addr_t dt_phys);

/* Machine RAM this kernel may be handed later, before memory is laid out */
void mk_register_ram(phys_addr_t start, u64 size);

/* Where the linear map starts: @dram_start, or lower for RAM registered to come */
phys_addr_t mk_linear_map_start(phys_addr_t dram_start);

/*
 * The ways down. A stock kernel resets or powers off the whole machine
 * and leaves stopped CPUs in a WFI loop inside its image; a multikernel
 * kernel returns them to firmware instead, where another kernel can
 * start them. The halt returns on a host.
 */
void mk_spawn_machine_halt(void);
void mk_stop_this_cpu(void);

/*
 * Helpers that add to a boot tree return libfdt error codes only, which
 * share their values with errnos and must not be mixed with them.
 */
int mk_dtb_set_reg(void *fdt, int node, const u64 *pairs, int nr);

int mk_build_boot_dtb(struct kimage *image, struct mk_instance *instance,
		      unsigned long dtb_mem, const void *loader_fdt,
		      int (*arch_nodes)(void *fdt, struct mk_instance *instance));
#else
static inline void mk_spawn_accept_boot_tree(phys_addr_t dt_phys)
{
}

static inline void mk_register_ram(phys_addr_t start, u64 size)
{
}

static inline phys_addr_t mk_linear_map_start(phys_addr_t dram_start)
{
	return dram_start;
}

static inline void mk_spawn_machine_halt(void)
{
}

static inline void mk_stop_this_cpu(void)
{
}
#endif

#endif /* _LINUX_MULTIKERNEL_FW_PARK_H */
