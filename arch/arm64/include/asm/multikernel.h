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

/* CPUs a table indexed by a CPU's rank among the possible CPUs has room for */
#define MK_CPU_RANK_MAX 512

struct mk_shared_arch {
	/*
	 * CPUs that SDEI can stop, written by each CPU for itself: set once
	 * the stop event can reach it, cleared before it stops being
	 * reachable. A force halt only signals the event to the CPUs set
	 * here, because a request to any other CPU may leave it unable to
	 * take the stop interrupt as well. See sdei.c.
	 */
	u8 fw_stop[MK_CPU_RANK_MAX];
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

#ifdef CONFIG_MULTIKERNEL
/* A stop IPI from another kernel: its force halt, or not ours to obey */
void mk_foreign_cpu_stop(void);
#else
static inline void mk_foreign_cpu_stop(void)
{
}
#endif

/*
 * Ask the host to route a device's MSI to one of this kernel's CPUs, and to
 * move it to another later, for the instance's MSI domain
 * (irq-gic-v3-its-mk.c). Mapping sleeps; moving works in any context and
 * is done when it returns.
 */
#ifdef CONFIG_MULTIKERNEL_ITS_PROXY
int mk_msi_proxy_map(u32 domain, u32 rid, u32 event, u64 phys_cpu,
		     phys_addr_t *doorbell);
int mk_msi_proxy_move(u32 domain, u32 rid, u32 event, u64 phys_cpu);
void mk_msi_proxy_unmap(u32 domain, u32 rid);
#endif

/* Nothing of arm64's lives in the control block, so it is never allocated */
#define MK_CTRL_BLOCK_SIZE	PAGE_SIZE

/* The node an instance reaches its host's ITSs through, for its MSIs */
#define MK_ITS_PROXY_COMPATIBLE	"multikernel,gic-v3-its"

#endif /* _ASM_ARM64_MULTIKERNEL_H */
