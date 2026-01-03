/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/x86/multikernel/direct_boot.S - Trampoline for 64-bit to 64-bit transition
 *
 * Copyright (C) 2025 Multikernel Technologies, Inc.
 *
 * Position-independent code copied to pool memory for:
 *   1. Initial spawn boot (multikernel_relocate_kernel)
 *   2. Secondary CPU wakeup (mk_secondary_trampoline)
 */

#include <linux/linkage.h>
#include <linux/annotate.h>
#include <asm/page_types.h>
#include <asm/processor-flags.h>
#include <asm/msr.h>
#include <asm/segment.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>

.section .text..multikernel_relocate,"ax"
.code64

.globl multikernel_relocate_kernel_start

multikernel_relocate_kernel_start:
/*
 * multikernel_relocate_kernel - Initial spawn boot trampoline
 *
 * Args: %rdi=identity_cr3, %rsi=boot_params, %rdx=entry, %rcx=trampoline_phys
 * Exit: RDI=identity_cr3, RSI=boot_params, jumps to spawn kernel entry
 */
SYM_CODE_START_NOALIGN(multikernel_relocate_kernel)
	UNWIND_HINT_END_OF_STACK
	ENDBR

	movq	%rdi, %r13
	movq	%rsi, %r15
	movq	%rdx, %r14
	movq	%rcx, %r12

	cli

	/* Disable PGE for clean TLB invalidation */
	movq	%cr4, %rax
	andq	$~X86_CR4_PGE, %rax
	movq	%rax, %cr4

	movq	%r13, %cr3
	movq	%cr3, %rax
	movq	%rax, %cr3

	/* Jump to identity-mapped physical address */
0:	addq	$mk_identity_mapped - 0b, %r12
	subq	$multikernel_relocate_kernel - 0b, %r12
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%r12
SYM_CODE_END(multikernel_relocate_kernel)

SYM_CODE_START_LOCAL_NOALIGN(mk_identity_mapped)
	UNWIND_HINT_END_OF_STACK
	ENDBR

	/* Temporary stack at top of this page - R12 has our physical address */
	movq	%r12, %rsp
	andq	$~(PAGE_SIZE-1), %rsp
	addq	$PAGE_SIZE, %rsp
	subq	$16, %rsp

	/* GDT base must be patched - code is position-independent */
	leaq	mk_gdt_entries(%rip), %rbx
	leaq	mk_gdt_64(%rip), %rax
	movq	%rbx, 2(%rax)
	lgdt	(%rax)

	pushq	$__KERNEL_CS
	leaq	.Lcs_reloaded(%rip), %rax
	pushq	%rax
	lretq

.Lcs_reloaded:
	ANNOTATE_NOENDBR
	UNWIND_HINT_END_OF_STACK

	movl	$__KERNEL_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %ss
	xorl	%eax, %eax
	movl	%eax, %fs
	movl	%eax, %gs

	xorl	%eax, %eax
	xorl	%edx, %edx
	movl	$MSR_GS_BASE, %ecx
	wrmsr
	movl	$MSR_KERNEL_GS_BASE, %ecx
	wrmsr
	movl	$MSR_FS_BASE, %ecx
	wrmsr

	movq	%cr0, %rax
	andq	$~(X86_CR0_AM | X86_CR0_WP | X86_CR0_TS | X86_CR0_EM), %rax
	orl	$(X86_CR0_PG | X86_CR0_PE), %eax
	movq	%rax, %cr0

	movq	%cr4, %rax
	andl	$(X86_CR4_PAE | X86_CR4_LA57), %eax
	movq	%rax, %cr4

	movq	%cr3, %rax
	movq	%rax, %cr3

	cld
	movq	%r13, %rdi
	movq	%r15, %rsi
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%ebp, %ebp

	ANNOTATE_RETPOLINE_SAFE
	jmp	*%r14
SYM_CODE_END(mk_identity_mapped)

/*
 * mk_secondary_trampoline - Secondary CPU wakeup trampoline
 *
 * Two-stage CR3 switch: identity_cr3 -> jump to phys addr -> spawn_cr3
 * This avoids needing identity mapping in spawn_cr3.
 *
 * Args: %rdi=identity_cr3, %rsi=entry, %rdx=gs_base, %rcx=stack,
 *       %r8=trampoline_phys, %r9=spawn_cr3
 */
	.globl mk_secondary_trampoline
SYM_CODE_START_NOALIGN(mk_secondary_trampoline)
	UNWIND_HINT_END_OF_STACK
	ENDBR

	movq	%r9, %r12
	movq	%rsi, %r13
	movq	%rdx, %r14
	movq	%rcx, %r15
	movq	%r8, %rbp

	cli

	movq	%cr4, %rax
	movq	%rax, %rbx
	andq	$~X86_CR4_PGE, %rax
	movq	%rax, %cr4

	/* First CR3 switch: to identity page table */
	movq	%rdi, %cr3
	movq	%cr3, %rax
	movq	%rax, %cr3

0:	addq	$mk_secondary_identity - mk_secondary_trampoline, %rbp
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%rbp
SYM_CODE_END(mk_secondary_trampoline)

/*
 * mk_secondary_identity - Continuation at identity-mapped address
 *
 * Registers: R12=spawn_cr3, R13=entry, R14=gs_base, R15=stack, RBX=saved_cr4
 */
SYM_CODE_START_LOCAL_NOALIGN(mk_secondary_identity)
	UNWIND_HINT_END_OF_STACK
	ENDBR

	/* Second CR3 switch: to spawn kernel's full page tables */
	movq	%r12, %cr3
	movq	%cr3, %rax
	movq	%rax, %cr3

	movq	%rbx, %cr4

	movl	$MSR_GS_BASE, %ecx
	movq	%r14, %rax
	movq	%r14, %rdx
	shrq	$32, %rdx
	wrmsr

	/* Stack now accessible (vmalloc mapped in spawn_cr3) */
	movq	%r15, %rsp
	xorq	%rbp, %rbp

	ANNOTATE_RETPOLINE_SAFE
	jmp	*%r13
SYM_CODE_END(mk_secondary_identity)

	.section .data..multikernel_relocate, "a"
	.balign 16

mk_gdt_64:
	.word	mk_gdt_entries_end - mk_gdt_entries - 1
	.quad	mk_gdt_entries

	.balign 16
mk_gdt_entries:
	.quad	0x0000000000000000
	.quad	0x0000000000000000
	.quad	0x00af9a000000ffff
	.quad	0x00cf92000000ffff
mk_gdt_entries_end:

	.globl multikernel_relocate_kernel_end
multikernel_relocate_kernel_end:
