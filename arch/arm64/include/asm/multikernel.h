/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MULTIKERNEL_H
#define _ASM_ARM64_MULTIKERNEL_H

#include <linux/sizes.h>
#include <linux/types.h>
#include <asm/page-def.h>
#include <asm/smp_plat.h>

/*
 * Pool CPUs are held by firmware in the PSCI OFF state and started with
 * CPU_ON, so an instance needs no trampoline, park page or page tables:
 * only the host's record of what it handed to CPU_ON.
 */
struct mk_instance_arch {
	void *dtb;			/* Boot device tree, in the control block */
	phys_addr_t dtb_phys;
};

struct mk_pool_arch {
};

/* Physical CPU IDs are MPIDR affinity values, as in the logical map */
static inline u64 arch_cpu_physical_id(int cpu)
{
	return cpu_logical_map(cpu);
}

static inline int arch_cpu_from_physical_id(u64 phys_id)
{
	return get_logical_index(phys_id);
}

/* Control block: the boot device tree, reserved from the spawn's allocator */
#define MK_BOOT_DTB_SIZE	SZ_64K
#define MK_CTRL_BLOCK_SIZE	ALIGN(MK_BOOT_DTB_SIZE, PAGE_SIZE)

#endif /* _ASM_ARM64_MULTIKERNEL_H */
