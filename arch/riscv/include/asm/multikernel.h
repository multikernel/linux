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
 * The RISC-V spawn path will use one page for its context, up to 64 KiB
 * for the generated DTB, and one page for the fence.i entry stub. SBI HSM
 * starts a hart in the existing address space, so no trampoline page tables
 * are needed.
 */
#define MK_CTRL_BLOCK_SIZE	(SZ_64K + 2 * PAGE_SIZE)

/*
 * Architecture-private spawn state is added with the SBI HSM and Image
 * loader support. The compile-only skeleton intentionally has none.
 */
struct mk_instance_arch {
};

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_MULTIKERNEL_H */
