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
 * mk_pool_park - Pool wait loop for CPUs leaving a dead instance
 *
 * Copied by the HOST into a per-instance park page that no kernel image
 * load ever overwrites, and entered on the instance's preserved identity
 * page table, so a parked CPU survives re-loads of the instance it came
 * from. Runs with interrupts disabled and needs no stack, no IDT and no
 * kernel text; it waits for a wakeup published in the shared spawn
 * context and dispatches to the trampolines with arguments read from it.
 * struct mk_spawn_context offsets are a cross-kernel ABI, so this code
 * works no matter which kernel binary parked the CPU.
 *
 * Local LVT sources are masked before entry, and a park-local GDT/IDT
 * is installed so a stray exception stops only this CPU (mk_park_fault)
 * while an NMI resumes the wait loop (mk_park_nmi).
 *
 * Args: %rdi=park_cr3, %rsi=ctx_phys, %rdx=apic_id, %rcx=park_phys,
 *       %r8=mwait_usable
 */
	.globl mk_pool_park_start
mk_pool_park_start:
SYM_CODE_START_NOALIGN(mk_pool_park)
	UNWIND_HINT_END_OF_STACK
	ENDBR

	cli

	movq	%rsi, %r12		/* spawn context physical address */
	movq	%rdx, %r13		/* our APIC ID */
	movq	%rcx, %r14		/* park page physical address */
	movq	%r8, %r15		/* MWAIT usable */

	/* Disable PGE for clean TLB invalidation */
	movq	%cr4, %rax
	andq	$~X86_CR4_PGE, %rax
	movq	%rax, %cr4

	/* Switch to the preserved park page table */
	movq	%rdi, %cr3
	movq	%cr3, %rax
	movq	%rax, %cr3

	/* Continue at the identity-mapped park page */
	movq	%r14, %rbx		/* keep the park page base */
	leaq	mk_park_identity - mk_pool_park(%r14), %rax
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%rax
SYM_CODE_END(mk_pool_park)

/*
 * Registers: R12=ctx_phys (now also its identity VA), R13=apic_id,
 *            R15=mwait_usable, RBX=park page physical address
 */
SYM_CODE_START_LOCAL_NOALIGN(mk_park_identity)
	UNWIND_HINT_END_OF_STACK
	ENDBR

	/*
	 * Take over descriptor tables. We are running on the pool page
	 * table, where the GDT and IDT of the kernel that parked us are
	 * not mapped - and that kernel may be overwritten anyway. Any
	 * exception would fail to deliver and triple fault the machine,
	 * taking the host down with it. Point GDTR/IDTR at tables inside
	 * this page so a stray fault stops this CPU and nothing else.
	 *
	 * Concurrently parking CPUs write identical values here, and the
	 * fault stack is shared: a CPU that faults is halting regardless.
	 */
	leaq	PAGE_SIZE - 64(%rbx), %rsp

	leaq	mk_park_gdt_entries - mk_pool_park(%rbx), %rax
	leaq	mk_park_gdt - mk_pool_park(%rbx), %rdx
	movq	%rax, 2(%rdx)
	lgdt	(%rdx)

	/*
	 * CS keeps its cached descriptor; the GDT above only has to
	 * resolve __KERNEL_CS when an exception loads it from a gate.
	 */
	leaq	mk_park_fault - mk_pool_park(%rbx), %rax
	leaq	mk_park_idt_entries - mk_pool_park(%rbx), %rdi
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

	/* Vector 2: NMIs resume the wait loop instead of stopping the CPU */
	leaq	mk_park_nmi - mk_pool_park(%rbx), %rax
	leaq	mk_park_idt_entries + 2*16 - mk_pool_park(%rbx), %rdi
	movw	%ax, (%rdi)
	movq	%rax, %rdx
	shrq	$16, %rdx
	movw	%dx, 6(%rdi)
	shrq	$16, %rdx
	movl	%edx, 8(%rdi)

	leaq	mk_park_idt_entries - mk_pool_park(%rbx), %rax
	leaq	mk_park_idt - mk_pool_park(%rbx), %rdx
	movq	%rax, 2(%rdx)
	lidt	(%rdx)

.Lpark_wait:
	movl	MK_CTX_ready(%r12), %eax
	cmpl	$1, %eax
	je	.Lpark_pending

	testq	%r15, %r15
	jz	.Lpark_relax

	/* Arm the monitor on the ready word, re-check, then sleep */
	leaq	MK_CTX_ready(%r12), %rax
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	monitor
	movl	MK_CTX_ready(%r12), %eax
	cmpl	$1, %eax
	je	.Lpark_pending
	xorl	%eax, %eax
	xorl	%ecx, %ecx
	mwait
	jmp	.Lpark_wait

.Lpark_relax:
	pause
	jmp	.Lpark_wait

.Lpark_pending:
	/* Wakeup published; is it for us? */
	movl	MK_CTX_target_apic_id(%r12), %eax
	cmpl	%r13d, %eax
	jne	.Lpark_relax

	/* Program this LLC domain and select it before kernel code executes. */
	movl	MK_CTX_resctrl_closid(%r12), %r10d
	testl	%r10d, %r10d
	jz	.Lpark_closid_done
	movl	MK_CTX_resctrl_l3_mask(%r12), %eax
	testl	%eax, %eax
	jz	.Lpark_select_closid
	movl	%r10d, %ecx
	cmpl	$0, MK_CTX_resctrl_l3_cdp(%r12)
	je	.Lpark_write_l3
	shll	$1, %ecx
	addl	$MSR_IA32_L3_CBM_BASE, %ecx
	xorl	%edx, %edx
	wrmsr
	incl	%ecx
	wrmsr
	jmp	.Lpark_select_closid
.Lpark_write_l3:
	addl	$MSR_IA32_L3_CBM_BASE, %ecx
	xorl	%edx, %edx
	wrmsr
.Lpark_select_closid:
	movl	$MSR_IA32_PQR_ASSOC, %ecx
	rdmsr
	movl	%r10d, %edx
	wrmsr
.Lpark_closid_done:

	/*
	 * Copy the publication into registers BEFORE claiming: once the
	 * claim clears ready, the publisher may reuse the slot for the
	 * next CPU. The claim (lock cmpxchg) makes exactly one of
	 * waker-revoke and us win; on loss the staged values are dropped.
	 */
	movl	MK_CTX_flags(%r12), %r11d
	testl	$MK_SPAWN_F_REPARK, %r11d
	jnz	.Lpark_repark
	testl	$MK_SPAWN_F_SECONDARY, %r11d
	jnz	.Lpark_secondary

	/*
	 * Initial spawn boot:
	 * multikernel_relocate_kernel(identity_cr3, boot_params, entry,
	 *                             trampoline_phys)
	 * boot_params lives in the instance context, which the slot points
	 * at via self_phys (a slot watches itself when it is the context).
	 */
	movq	MK_CTX_identity_cr3(%r12), %rdi
	movq	MK_CTX_self_phys(%r12), %rsi
	addq	$MK_CTX_bp, %rsi
	movq	MK_CTX_kernel_entry(%r12), %rdx
	movq	MK_CTX_trampoline_phys(%r12), %r8
	movl	$1, %eax
	xorl	%ebp, %ebp
	lock cmpxchgl %ebp, MK_CTX_ready(%r12)
	jnz	.Lpark_wait
	movq	%r8, %rcx
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%r8

.Lpark_secondary:
	/*
	 * Secondary CPU joining a running instance:
	 * mk_secondary_trampoline(identity_cr3, entry, gs_base, stack,
	 *                         trampoline_phys, spawn_cr3)
	 */
	movq	MK_CTX_identity_cr3(%r12), %rdi
	movq	MK_CTX_kernel_entry(%r12), %rsi
	movq	MK_CTX_gs_base(%r12), %rdx
	movq	MK_CTX_stack(%r12), %rcx
	movq	MK_CTX_secondary_trampoline_phys(%r12), %r8
	movq	MK_CTX_spawn_cr3(%r12), %r9
	movl	$1, %eax
	xorl	%ebp, %ebp
	lock cmpxchgl %ebp, MK_CTX_ready(%r12)
	jnz	.Lpark_wait
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%r8

.Lpark_repark:
	/*
	 * Move to another park slot: reload the watch address, page table
	 * and park page from the publication and start over. Our APIC ID
	 * and MWAIT capability stay in R13/R15; interrupts stay off. RBX
	 * must follow to the new page: mk_park_identity anchors the fault
	 * stack, GDT and IDT to it, and the page we leave may belong to an
	 * instance whose pool is later freed and recycled.
	 *
	 * The repark_* dispatch fields are separate from the park_phys/
	 * park_cr3/self_phys anchor so that publishing a repark on a live
	 * instance context never corrupts the context's own park identity.
	 */
	movq	MK_CTX_repark_park_cr3(%r12), %r14
	movq	MK_CTX_repark_park_phys(%r12), %rcx
	movq	MK_CTX_repark_slot_phys(%r12), %r10
	movl	$1, %eax
	xorl	%ebp, %ebp
	lock cmpxchgl %ebp, MK_CTX_ready(%r12)
	jnz	.Lpark_wait
	movq	%r10, %r12
	movq	%rcx, %rbx
	movq	%r14, %cr3
	movq	%cr3, %rax
	movq	%rax, %cr3
	addq	$mk_park_identity - mk_pool_park, %rcx
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%rcx
SYM_CODE_END(mk_park_identity)

/*
 * A stray fault while parked stops this CPU; the machine keeps running.
 * Nothing else can report it: no console, no kernel, and the kernel that
 * parked us may be gone, so put a marker straight on COM1.
 */
SYM_CODE_START_LOCAL_NOALIGN(mk_park_fault)
	UNWIND_HINT_END_OF_STACK
	ENDBR
	cli

	leaq	mk_park_fault_msg - mk_pool_park(%rbx), %rsi
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
SYM_CODE_END(mk_park_fault)

/*
 * NMI must not stop a parked CPU: the host's force halt NMIs every CPU
 * of an instance without knowing which are already parked. Return into
 * the wait loop; an mwait cut short just rechecks the slot and re-arms.
 */
SYM_CODE_START_LOCAL_NOALIGN(mk_park_nmi)
	UNWIND_HINT_END_OF_STACK
	ENDBR
	iretq
SYM_CODE_END(mk_park_nmi)



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

/*
 * Park page descriptor tables. They live in the data section like the
 * trampoline GDT above; the linker places it right after the code, and
 * the park page copy spans from mk_pool_park_start to the end of this
 * blob, so the code reaches them at the same relative offsets.
 */
mk_park_fault_msg:
	.asciz	"\r\nmultikernel: fault while parked, CPU halted\r\n"

	.balign 16
mk_park_gdt:
	.word	mk_park_gdt_end - mk_park_gdt_entries - 1
	.quad	0			/* base, filled in at park time */
	.balign 16
mk_park_gdt_entries:
	.quad	0x0000000000000000
	.quad	0x0000000000000000
	.quad	0x00af9a000000ffff	/* __KERNEL_CS */
	.quad	0x00cf92000000ffff	/* __KERNEL_DS */
mk_park_gdt_end:

	.balign 16
mk_park_idt:
	.word	32 * 16 - 1
	.quad	0			/* base, filled in at park time */
	.balign 16
mk_park_idt_entries:
	.fill	32 * 16, 1, 0

	.globl mk_pool_park_end
mk_pool_park_end:

	.globl multikernel_relocate_kernel_end
multikernel_relocate_kernel_end:
