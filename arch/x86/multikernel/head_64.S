/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/x86/multikernel/head_64.S - Entry point for multikernel spawn boot
 *
 * Provides 64-bit to 64-bit boot path for spawn kernels. Uses standard
 * kernel page table initialization via __startup_64(), then continues
 * with x86_64_start_kernel() like normal boot.
 *
 * Entry conditions (set by host kernel):
 *   - CPU in 64-bit long mode, interrupts disabled
 *   - RSI = physical address of boot_params
 *   - CR3 = identity mapping covering kernel image
 *   - hardware_subarch = X86_SUBARCH_MULTIKERNEL in boot_params
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <linux/pgtable.h>
#include <asm/segment.h>
#include <asm/page.h>
#include <asm/msr.h>
#include <asm/cache.h>
#include <asm/processor-flags.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>
#include <asm/percpu.h>
#include <asm/smp.h>
#include "../entry/calling.h"

#define CR0_STATE	(X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | \
			 X86_CR0_NE | X86_CR0_WP | X86_CR0_AM | \
			 X86_CR0_PG)

	__INIT
	.code64

SYM_CODE_START_NOALIGN(multikernel_startup_64)
	UNWIND_HINT_END_OF_STACK
	ANNOTATE_NOENDBR

	movq	%rsi, %r15

	/*
	 * Calculate p2v_offset for position-independent addressing.
	 * Must load virtual address from memory (not immediate) for PIE.
	 */
	leaq	multikernel_startup_64(%rip), %rbp
	subq	.Lmultikernel_startup_64_virt(%rip), %rbp

	leaq	__top_init_kernel_stack(%rip), %rsp

	xorl	%eax, %eax
	xorl	%edx, %edx
	movl	$MSR_GS_BASE, %ecx
	wrmsr

	/* __startup_64 sets phys_base and builds early_top_pgt mappings */
	movq	%rbp, %rdi
	movq	%r15, %rsi
	call	__pi___startup_64
	movq	%rax, %rbx

	/*
	 * Switch to early_top_pgt. We rely on __startup_64's identity mapping
	 * for kernel image, and on-demand PAGE_OFFSET mapping via
	 * early_make_pgtable() for accessing boot_params and other memory.
	 */
	leaq	early_top_pgt(%rip), %rax
	addq	%rbx, %rax
	movq	%rax, %cr3

	/* Jump to kernel virtual address space */
	leaq	.Lmultikernel_virtual(%rip), %rax
	subq	%rbp, %rax
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%rax

.Lmultikernel_virtual:
	ANNOTATE_NOENDBR
	UNWIND_HINT_END_OF_STACK

	/* Now running at kernel virtual addresses */
	leaq	__top_init_kernel_stack(%rip), %rsp

	movl	$(X86_CR4_PAE | X86_CR4_LA57), %edx
#ifdef CONFIG_X86_MCE
	orl	$X86_CR4_MCE, %edx
#endif
	movq	%cr4, %rcx
	andl	%edx, %ecx
	btsl	$X86_CR4_PSE_BIT, %ecx
	movq	%rcx, %cr4
	btsl	$X86_CR4_PGE_BIT, %ecx
	movq	%rcx, %cr4

	xorl	%edx, %edx
	movq	current_task(%rdx), %rax
	movq	TASK_threadsp(%rax), %rsp

	subq	$16, %rsp
	movw	$(GDT_SIZE-1), (%rsp)
	leaq	gdt_page(%rdx), %rax
	movq	%rax, 2(%rsp)
	lgdt	(%rsp)
	addq	$16, %rsp

	xorl	%eax, %eax
	movl	%eax, %ds
	movl	%eax, %ss
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs

	movl	$MSR_GS_BASE, %ecx
	movl	%edx, %eax
	shrq	$32, %rdx
	wrmsr

	call	early_setup_idt

	movl	$0x80000001, %eax
	cpuid
	movl	%edx, %edi

	movl	$MSR_EFER, %ecx
	rdmsr
	movl	%eax, %edx
	btsl	$_EFER_SCE, %eax
	btl	$20, %edi
	jnc	1f
	btsl	$_EFER_NX, %eax
	btsq	$_PAGE_BIT_NX, early_pmd_flags(%rip)

1:	cmpl	%edx, %eax
	je	1f
	xorl	%edx, %edx
	wrmsr
1:
	movl	$CR0_STATE, %eax
	movq	%rax, %cr0

	pushq	$0
	popfq

	movq	%r15, %rdi
	xorl	%ebp, %ebp
	call	x86_64_start_kernel
SYM_CODE_END(multikernel_startup_64)

/*
 * Virtual address constant for p2v_offset calculation.
 * Must be in rodata so linker resolves to virtual (not RIP-relative).
 */
	__INITRODATA
SYM_DATA_LOCAL(.Lmultikernel_startup_64_virt, .quad multikernel_startup_64)

/*
 * multikernel_secondary_startup - Entry for secondary CPU joining spawn kernel
 *
 * Called after trampoline's two-stage CR3 switch. At entry:
 *   - CR3 = spawn kernel's swapper_pg_dir
 *   - GS_BASE = per_cpu_offset for this CPU
 *   - RSP = idle task stack
 */
	.text
SYM_CODE_START(multikernel_secondary_startup)
	ANNOTATE_NOENDBR
	UNWIND_HINT_END_OF_STACK

	/* Save per-CPU offset to callee-saved register */
	movl	$MSR_GS_BASE, %ecx
	rdmsr
	shlq	$32, %rdx
	orq	%rax, %rdx
	movq	%rdx, %r12

	/*
	 * Load spawn kernel's GDT immediately - host's GDT is unmapped
	 * after CR3 switch, any exception without valid GDT triple faults.
	 */
	subq	$16, %rsp
	movw	$(GDT_SIZE-1), (%rsp)
	leaq	gdt_page(%r12), %rax
	movq	%rax, 2(%rsp)
	lgdt	(%rsp)
	addq	$16, %rsp

	/*
	 * Reload CS via far return - CPU still uses cached CS descriptor
	 * from host kernel after lgdt.
	 */
	pushq	$__KERNEL_CS
	leaq	.Lsecondary_cs_reloaded(%rip), %rax
	pushq	%rax
	lretq

.Lsecondary_cs_reloaded:
	ANNOTATE_NOENDBR
	UNWIND_HINT_END_OF_STACK

	xorl	%eax, %eax
	movl	%eax, %ds
	movl	%eax, %ss
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs

	/* Restore GS_BASE - clearing %gs zeroed it */
	movl	$MSR_GS_BASE, %ecx
	movq	%r12, %rax
	movq	%r12, %rdx
	shrq	$32, %rdx
	wrmsr

	/*
	 * Sync EFER/CR0 with spawn kernel's expectations - CPU inherits
	 * these from host kernel where it was in play_dead.
	 */
	movl	$0x80000001, %eax
	cpuid
	movl	%edx, %edi

	movl	$MSR_EFER, %ecx
	rdmsr
	movl	%eax, %esi
	btsl	$_EFER_SCE, %eax
	btl	$20, %edi
	jnc	1f
	btsl	$_EFER_NX, %eax
1:
	cmpl	%esi, %eax
	je	1f
	xorl	%edx, %edx
	wrmsr
1:
	movl	$CR0_STATE, %eax
	movq	%rax, %cr0

	/* Early IDT for exceptions before cpu_init() */
	call	early_setup_idt

	pushq	$0
	popfq

	xorl	%edi, %edi
	xorl	%ebp, %ebp
	ANNOTATE_RETPOLINE_SAFE
	callq	*initial_code(%rip)

	ud2
SYM_CODE_END(multikernel_secondary_startup)

	.section .note.multikernel, "a"
	.balign 4
	.long	2f - 1f
	.long	4f - 3f
	.long	0x4d4b
1:	.asciz	"Linux"
2:	.balign 4
3:	.quad	multikernel_startup_64 - __START_KERNEL_map
4:	.balign 4
