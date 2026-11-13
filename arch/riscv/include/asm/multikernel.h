/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_MULTIKERNEL_H
#define _ASM_RISCV_MULTIKERNEL_H

#ifndef __ASSEMBLY__

#include <linux/errno.h>
#include <linux/sizes.h>
#include <linux/types.h>

#include <asm/page.h>
#include <asm/smp.h>

/*
 * Hart IDs are sparse firmware identifiers and may exceed NR_CPUS. Keep
 * them as values and always translate through the architecture CPU maps.
 */
static inline u64 arch_cpu_physical_id(int cpu)
{
	return cpuid_to_hartid_map(cpu);
}

static inline int arch_cpu_from_physical_id(u64 hartid)
{
	if (hartid == INVALID_HARTID)
		return -ENOENT;

	return riscv_hartid_to_cpuid(hartid);
}

/*
 * What a hart started through mk_hart_entry finds in a1: the a1 it is to
 * enter with and where to enter. mk_hart_entry reads it as data.
 */
struct mk_boot_record {
	u64 a1;
	u64 entry;
};

#ifdef CONFIG_MULTIKERNEL
/*
 * Pool harts are held by firmware in the SBI HSM STOPPED state and
 * started with HART_START, so an instance needs no trampoline, park page
 * or page tables: what its boot hart is started with is all there is.
 */
struct mk_instance_arch {
	struct mk_boot_record boot;
};

/* Have a hart this kernel starts for itself enter through mk_hart_entry */
void mk_wrap_hart_entry(unsigned int cpu, unsigned long *entry,
			unsigned long *opaque);

/*
 * The ways down. Stock RISC-V resets the whole machine through SBI SRST
 * and leaves stopped harts in a WFI loop inside the kernel image; a
 * multikernel kernel stops its harts through SBI HSM instead, where
 * another kernel can start them. The halt returns on a host.
 */
void mk_spawn_machine_halt(void);
void mk_stop_this_cpu(void);
#else
static inline void mk_wrap_hart_entry(unsigned int cpu, unsigned long *entry,
				      unsigned long *opaque)
{
}

static inline void mk_spawn_machine_halt(void)
{
}

static inline void mk_stop_this_cpu(void)
{
}
#endif

/* Nothing of RISC-V's lives in the control block, so it is never allocated */
#define MK_CTRL_BLOCK_SIZE	PAGE_SIZE

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_MULTIKERNEL_H */
