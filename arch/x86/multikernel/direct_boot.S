/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/x86/multikernel/direct_boot.S - Trampoline for 64-bit to 64-bit transition
 *
 * Copyright (C) 2025 Multikernel Technologies, Inc.
 *
 * Position-independent code copied to pool memory for:
 *   1. Initial spawn boot (multikernel_relocate_kernel)
 *   2. Secondary CPU wakeup (mk_secondary_trampoline)
 *   3. The park table's wait loop (mk_cell_park)
 */

#include <linux/linkage.h>
#include <linux/annotate.h>
#include <asm/asm-offsets.h>
#include <asm/multikernel.h>
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

	/*
	 * Clearing CR0.WP below is a #GP while CR4.CET is set, and this CPU
	 * inherits CR4 from whichever kernel parked it.
	 */
	movq	%cr4, %rax
	andq	$~(X86_CR4_CET), %rax
	movq	%rax, %cr4

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

	/*
	 * Restore CR4 minus CET: a CPU parked by a spawn kernel carries that
	 * kernel's IBT arming, and the jump below lands on a NOENDBR entry.
	 * The spawn kernel re-enables CET for this CPU in cpu_init(), the
	 * same as after the boot trampoline's CET clear.
	 */
	andq	$~X86_CR4_CET, %rbx
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

/*
 * mk_cell_park - Wait in this CPU's park table cell
 *
 * Copied once into the park table's code page, which no kernel ever
 * rewrites, and entered by any kernel through its direct map. Runs with
 * interrupts disabled on the park table's page table, which maps the
 * table and nothing else, so nothing of the kernel that parked us is in
 * use once the cell reads PARKED.
 *
 * A command is claimed by swapping the cell word from (PARKED, cmd) to
 * (RUNNING, NONE), after its arguments are in registers. The CPU then
 * switches to the waker's identity page table, which maps this page
 * too, and jumps to the waker's trampoline.
 *
 * Args: %rdi=park_cr3, %rsi=cell_phys, %rdx=code_phys, %rcx=mwait_usable
 */
	.balign 16
	.globl mk_cell_park_start
mk_cell_park_start:
SYM_CODE_START_NOALIGN(mk_cell_park)
	UNWIND_HINT_END_OF_STACK
	ENDBR

	cli

	movq	%rsi, %r12		/* cell */
	movq	%rdx, %rbx		/* code page */
	movq	%rcx, %r15		/* MWAIT usable */

	movq	%cr4, %rax
	andq	$~X86_CR4_PGE, %rax
	movq	%rax, %cr4

	movq	%rdi, %cr3
	movq	%cr3, %rax
	movq	%rax, %cr3

	leaq	mk_cell_park_identity - mk_cell_park(%rbx), %rax
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%rax
SYM_CODE_END(mk_cell_park)

/* Registers: R12=cell, RBX=code page, R15=mwait_usable, all identity */
SYM_CODE_START_LOCAL_NOALIGN(mk_cell_park_identity)
	UNWIND_HINT_END_OF_STACK
	ENDBR

	/*
	 * The descriptor tables of the kernel that parked us are not
	 * mapped here. Use the cell's own, so that a stray fault stops
	 * this CPU and an NMI returns to the wait loop.
	 */
	leaq	PAGE_SIZE - 64(%r12), %rsp

	leaq	MK_CELL_gdt_entries(%r12), %rdi
	movq	$0, (%rdi)
	movq	$0, 8(%rdi)
	movabsq	$0x00af9b000000ffff, %rax	/* __KERNEL_CS, accessed */
	movq	%rax, 16(%rdi)
	movabsq	$0x00cf93000000ffff, %rax	/* __KERNEL_DS, accessed */
	movq	%rax, 24(%rdi)
	leaq	MK_CELL_gdt(%r12), %rdx
	movw	$(4 * 8 - 1), (%rdx)
	movq	%rdi, 2(%rdx)
	lgdt	(%rdx)

	leaq	mk_cell_park_fault - mk_cell_park(%rbx), %rax
	leaq	MK_CELL_idt_entries(%r12), %rdi
	movl	$32, %ecx
1:	movw	%ax, (%rdi)		/* offset 15:0 */
	movw	$__KERNEL_CS, 2(%rdi)
	movb	$0, 4(%rdi)		/* no IST */
	movb	$0x8e, 5(%rdi)		/* present, DPL0, interrupt gate */
	movq	%rax, %rdx
	shrq	$16, %rdx
	movw	%dx, 6(%rdi)		/* offset 31:16 */
	shrq	$16, %rdx
	movl	%edx, 8(%rdi)		/* offset 63:32 */
	movl	$0, 12(%rdi)
	addq	$16, %rdi
	decl	%ecx
	jnz	1b

	leaq	mk_cell_park_nmi - mk_cell_park(%rbx), %rax
	leaq	MK_CELL_idt_entries + 2 * 16(%r12), %rdi
	movw	%ax, (%rdi)
	movq	%rax, %rdx
	shrq	$16, %rdx
	movw	%dx, 6(%rdi)
	shrq	$16, %rdx
	movl	%edx, 8(%rdi)

	leaq	MK_CELL_idt_entries(%r12), %rax
	leaq	MK_CELL_idt(%r12), %rdx
	movw	$(32 * 16 - 1), (%rdx)
	movq	%rax, 2(%rdx)
	lidt	(%rdx)

	movq	$MK_PARK_PARKED, MK_CELL_word(%r12)

.Lcell_wait:
	movl	MK_CELL_cmd(%r12), %eax
	testl	%eax, %eax
	jnz	.Lcell_pending

	testq	%r15, %r15
	jz	.Lcell_relax

	leaq	MK_CELL_word(%r12), %rax
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	monitor
	movl	MK_CELL_cmd(%r12), %eax
	testl	%eax, %eax
	jnz	.Lcell_pending
	xorl	%eax, %eax
	xorl	%ecx, %ecx
	mwait
	jmp	.Lcell_wait

.Lcell_relax:
	pause
	jmp	.Lcell_wait

.Lcell_pending:
	cmpl	$MK_PARK_CMD_BOOT, %eax
	je	.Lcell_boot
	cmpl	$MK_PARK_CMD_SECONDARY, %eax
	je	.Lcell_secondary
	jmp	.Lcell_relax

.Lcell_boot:
	/*
	 * multikernel_relocate_kernel(identity_cr3, boot_params, entry,
	 *                             trampoline_phys)
	 */
	movq	MK_CELL_arg + 0 * 8(%r12), %rdi
	movq	MK_CELL_arg + 1 * 8(%r12), %rsi
	movq	MK_CELL_arg + 2 * 8(%r12), %rdx
	movq	MK_CELL_arg + 3 * 8(%r12), %rcx
	movq	%rcx, %r11
	movabsq	$((MK_PARK_CMD_BOOT << 32) | MK_PARK_PARKED), %rax
	jmp	.Lcell_claim

.Lcell_secondary:
	/*
	 * mk_secondary_trampoline(identity_cr3, entry, gs_base, stack,
	 *                         trampoline_phys, spawn_cr3)
	 */
	movq	MK_CELL_arg + 0 * 8(%r12), %rdi
	movq	MK_CELL_arg + 1 * 8(%r12), %rsi
	movq	MK_CELL_arg + 2 * 8(%r12), %rdx
	movq	MK_CELL_arg + 3 * 8(%r12), %rcx
	movq	MK_CELL_arg + 4 * 8(%r12), %r8
	movq	MK_CELL_arg + 5 * 8(%r12), %r9
	movq	%r8, %r11
	movabsq	$((MK_PARK_CMD_SECONDARY << 32) | MK_PARK_PARKED), %rax

.Lcell_claim:
	/* (PARKED, cmd) -> (RUNNING, NONE); a waker that revoked first wins */
	xorl	%r10d, %r10d
	lock cmpxchgq %r10, MK_CELL_word(%r12)
	jnz	.Lcell_wait

	movq	%rdi, %cr3
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%r11
SYM_CODE_END(mk_cell_park_identity)

/*
 * A stray fault while parked stops this CPU; the machine keeps running.
 * Nothing else can report it, so put a marker straight on COM1.
 */
SYM_CODE_START_LOCAL_NOALIGN(mk_cell_park_fault)
	UNWIND_HINT_END_OF_STACK
	ENDBR
	cli

	leaq	mk_cell_park_msg - mk_cell_park(%rbx), %rsi
1:	lodsb
	testb	%al, %al
	jz	3f
	movb	%al, %ah
	movw	$0x3fd, %dx		/* COM1 line status */
2:	inb	%dx, %al
	testb	$0x20, %al		/* transmit holding register empty */
	jz	2b
	movw	$0x3f8, %dx
	movb	%ah, %al
	outb	%al, %dx
	jmp	1b

3:	hlt
	jmp	3b
SYM_CODE_END(mk_cell_park_fault)

/* An NMI, such as a force halt aimed at a CPU already parked, resumes the wait */
SYM_CODE_START_LOCAL_NOALIGN(mk_cell_park_nmi)
	UNWIND_HINT_END_OF_STACK
	ENDBR
	iretq
SYM_CODE_END(mk_cell_park_nmi)



	.section .data..multikernel_relocate, "a"
	.balign 16

mk_gdt_64:
	.word	mk_gdt_entries_end - mk_gdt_entries - 1
	.quad	mk_gdt_entries

	/*
	 * Descriptors come with Accessed set: setting it on first load is a
	 * locked write, a split lock (#AC) if a descriptor crosses a cache
	 * line and a fault if the table is read-only.
	 */
	.balign 16
mk_gdt_entries:
	.quad	0x0000000000000000
	.quad	0x0000000000000000
	.quad	0x00af9b000000ffff
	.quad	0x00cf93000000ffff
mk_gdt_entries_end:

	/* The park code page copy reaches this at its link-time offset */
mk_cell_park_msg:
	.asciz	"\r\nmultikernel: fault while parked, CPU halted\r\n"

	.globl mk_cell_park_end
mk_cell_park_end:

	.globl multikernel_relocate_kernel_end
multikernel_relocate_kernel_end:
