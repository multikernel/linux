/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MULTIKERNEL_H
#define _ASM_X86_MULTIKERNEL_H

#include <linux/types.h>
#include <linux/bits.h>
#include <asm/bootparam.h>

/* Spawn context flags */
#define MK_SPAWN_F_SECONDARY	BIT(0)	/* Secondary CPU joining existing kernel */

/*
 * Spawn context - combines boot_params with spawn-specific fields.
 * Lives in shared memory (multikernel pool), reused for both primary
 * boot and secondary CPU wakeup.
 *
 * IMPORTANT: Fixed-size fields must come FIRST, before struct boot_params.
 * The size of struct boot_params can vary between kernel builds, so if it
 * comes first, the offsets of subsequent fields would differ between host
 * and spawn kernels built with different configs.
 */
struct mk_spawn_context {
	/* Fixed-size fields first - offsets are same regardless of kernel config */
	unsigned long self_phys;	/* Physical address of this struct (for spawn to find itself) */
	unsigned long identity_cr3;	/* Identity-mapped page tables */
	unsigned long kernel_entry;	/* Entry point */
	unsigned long trampoline_virt;	/* Trampoline virtual address */
	unsigned long trampoline_phys;	/* Trampoline physical address (base) */
	unsigned long secondary_trampoline_phys;  /* Secondary CPU trampoline physical address */
	unsigned long gs_base;		/* Per-CPU GS base (for secondary) */
	unsigned long stack;		/* Stack pointer (for secondary) */
	unsigned long spawn_cr3;	/* Spawn kernel's CR3 (for secondary CPU final switch) */
	u32 target_apic_id;		/* Target CPU's APIC ID */
	u32 flags;			/* MK_SPAWN_F_* flags */
	u32 ready;			/* Signal flag */
	u32 reserved;			/* Padding for alignment */
	/* Variable-size struct last - size depends on kernel config */
	struct boot_params bp;		/* Standard x86 boot params */
} __aligned(PAGE_SIZE);

#endif /* _ASM_X86_MULTIKERNEL_H */
