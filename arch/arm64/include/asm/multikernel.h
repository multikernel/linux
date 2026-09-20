/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_ARM64_MULTIKERNEL_H
#define _ASM_ARM64_MULTIKERNEL_H

#include <linux/sizes.h>
#include <linux/types.h>
#include <asm/page-def.h>
#include <asm/smp_plat.h>

#ifdef CONFIG_MULTIKERNEL
/*
 * Pool CPUs are held by firmware in the PSCI OFF state and started with
 * CPU_ON, so an instance needs no trampoline, park page or page tables,
 * and what CPU_ON is given lives in the kimage.
 */
struct mk_instance_arch {
};

struct mk_pool_arch {
};
#endif

/* Physical CPU IDs are MPIDR affinity values, as in the logical map */
static inline u64 arch_cpu_physical_id(int cpu)
{
	return cpu_logical_map(cpu);
}

static inline int arch_cpu_from_physical_id(u64 phys_id)
{
	return get_logical_index(phys_id);
}

/*
 * The ways down of a spawn kernel. Stock arm64 leaves stopped CPUs in a
 * WFI loop inside the kernel image, which the host is about to overwrite;
 * a spawn returns them to firmware instead. Both return on a host.
 */
#ifdef CONFIG_MULTIKERNEL
void mk_spawn_machine_halt(void);
void mk_spawn_stop_this_cpu(void);
#else
static inline void mk_spawn_machine_halt(void)
{
}

static inline void mk_spawn_stop_this_cpu(void)
{
}
#endif

/*
 * Room for an instance's boot device tree, a segment of its kimage. The
 * tree is rebuilt in place on every spawn, as the memory grant can have
 * changed since the load.
 */
#define MK_BOOT_DTB_SIZE	SZ_64K

/* Nothing of arm64's lives in the control block, so it is never allocated */
#define MK_CTRL_BLOCK_SIZE	PAGE_SIZE

#endif /* _ASM_ARM64_MULTIKERNEL_H */
