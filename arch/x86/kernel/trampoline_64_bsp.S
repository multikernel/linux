/*
 *
 *	Derived from Setup.S by Linus Torvalds, then derived from Popcorn Linux
 *
 *	4 Jan 1997 Michael Chastain: changed to gnu as.
 *	15 Sept 2005 Eric Biederman: 64bit PIC support
 *
 *	Entry: CS:IP point to the start of our code, we are 
 *	in real mode with no stack, but the rest of the 
 *	trampoline page to make our stack and everything else
 *	is a mystery.
 *
 *	On entry to trampoline_data, the processor is in real mode
 *	with 16-bit addressing and 16-bit data.  CS has some value
 *	and IP is zero.  Thus, data addresses need to be absolute
 *	(no relocation) and are taken with regard to r_base.
 *
 *	With the addition of trampoline_level4_pgt this code can
 *	now enter a 64bit kernel that lives at arbitrary 64bit
 *	physical addresses.
 *
 *	If you work on this file, check the object module with objdump
 *	--full-contents --reloc to make sure there are no relocation
 *	entries.
 */

#include <linux/linkage.h>
#include <linux/init.h>
#include <asm/pgtable_types.h>
#include <asm/page_types.h>
#include <asm/msr.h>
#include <asm/segment.h>
#include <asm/processor-flags.h>

	.section ".x86_trampoline_bsp","a"
	.balign PAGE_SIZE
	.code16

SYM_CODE_START(trampoline_data_bsp)
bsp_base = .
	cli			# We should be safe anyway
	wbinvd
	mov	%cs, %ax	# Code and data in the same place
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %ss


	movl	$0xA5A5A5A5, trampoline_status_bsp - bsp_base
				# write marker for master knows we're running

					# Setup stack
	movw	$(trampoline_stack_bsp_end - bsp_base), %sp

	# call	verify_cpu		# Verify the cpu supports long mode
	# testl   %eax, %eax		# Check for return code
	# jnz	no_longmode_bsp

	mov	%cs, %ax
	movzx	%ax, %esi		# Find the 32bit trampoline location
	shll	$4, %esi

					# Fixup the absolute vectors
	leal	(startup_32_bsp - bsp_base)(%esi), %eax
	movl	%eax, startup_32_vector_bsp - bsp_base
	leal	(startup_64_bsp - bsp_base)(%esi), %eax
	movl	%eax, startup_64_vector_bsp - bsp_base
	leal	(tgdt_bsp - bsp_base)(%esi), %eax
	movl	%eax, (tgdt_bsp + 2 - bsp_base)

	/*
	 * GDT tables in non default location kernel can be beyond 16MB and
	 * lgdt will not be able to load the address as in real mode default
	 * operand size is 16bit. Use lgdtl instead to force operand size
	 * to 32 bit.
	 */

	lidtl	tidt_bsp - bsp_base	# load idt with 0, 0
	lgdtl	tgdt_bsp - bsp_base	# load gdt with whatever is appropriate

	mov	$X86_CR0_PE, %ax	# protected mode (PE) bit
	lmsw	%ax			# into protected mode

	# flush prefetch and jump to startup_32
	ljmpl	*(startup_32_vector_bsp - bsp_base)
SYM_CODE_END(trampoline_data_bsp)

	.code32
	.balign 4
startup_32_bsp:

	cli
        movl    $(__KERNEL_DS), %eax
        movl    %eax, %ds
        movl    %eax, %es
        movl    %eax, %ss

	/* Load new GDT with the 64bit segments using 32bit descriptor.
	 * The new GDT labels the entire address space as 64-bit, so we
	 * can switch into long mode later. */
        leal    (gdt_bsp_64 - bsp_base)(%esi), %eax
        movl    %eax, (gdt_bsp_64 - bsp_base + 2)(%esi)
        lgdt    (gdt_bsp_64 - bsp_base)(%esi)

	/* Enable PAE mode.  Note that this does not actually take effect
	 * until paging is enabled */
	movl	%cr4, %eax
        orl     $(X86_CR4_PAE), %eax
        movl    %eax, %cr4

        /* Initialize Page tables to 0 */
	leal    (pgtable_bsp - bsp_base)(%esi), %edi
	xorl    %eax, %eax
        movl    $((4096*6)/4), %ecx
        rep     stosl

        /* Build Level 4 */
        leal    (pgtable_bsp - bsp_base)(%esi), %edi
        leal    0x1007 (%edi), %eax
        movl    %eax, 0(%edi)

        /* Build Level 3 */
        leal    (pgtable_bsp - bsp_base + 0x1000)(%esi), %edi
        leal    0x1007(%edi), %eax
        movl    $4, %ecx
1:      movl    %eax, 0x00(%edi)
        addl    $0x00001000, %eax
        addl    $8, %edi
        decl    %ecx
        jnz     1b

        /* Build Level 2 */
        leal    (pgtable_bsp - bsp_base + 0x2000)(%esi), %edi
        movl    $0x00000183, %eax
        movl    $2048, %ecx
1:      movl    %eax, 0(%edi)
        addl    $0x00200000, %eax
        addl    $8, %edi
        decl    %ecx
        jnz     1b

        /* Enable the boot page tables */
        leal    (pgtable_bsp - bsp_base)(%esi), %eax
        movl    %eax, %cr3

        /* Enable Long mode in EFER (Extended Feature Enable Register) */
        movl    $MSR_EFER, %ecx
        rdmsr
        btsl    $_EFER_LME, %eax
        wrmsr

        /*
         * Setup for the jump to 64bit mode
         *
         * When the jump is performend we will be in long mode but
         * in 32bit compatibility mode with EFER.LME = 1, CS.L = 0, CS.D = 1
         * (and in turn EFER.LMA = 1).  To jump into 64bit mode we use
         * the new gdt/idt that has __KERNEL_CS with CS.L = 1.
         * We place all of the values on our mini stack so lret can
         * used to perform that far jump.
         */
        pushl   $__KERNEL_CS
        leal    (startup_64_bsp - bsp_base)(%esi), %eax
        pushl   %eax

	/* Enter paged protected Mode, activating Long Mode */
        movl    $(X86_CR0_PG | X86_CR0_PE), %eax /* Enable Paging and Protected mode */
        movl    %eax, %cr0

	/* Jump from 32bit compatibility mode into 64bit mode. */
        lret

	.code64
	.balign 4
startup_64_bsp:

	/* Get physical address of boot_params structure */
	movq    (boot_params_phys_addr - bsp_base)(%rsi), %r15

	/* Load kernel address into register */
	movq    (kernel_phys_addr - bsp_base)(%rsi), %r14

	/* Check whether the kernel is in the 4 GB we mapped already,
	 * and if not, add an additional mapping */
	movq	$0xffffffff00000000, %r8
	testq	%r8, %r14
	je	2f

	/* If we got here, we need to identity-map an additional 1 GB */
	
	/* Mask off to figure out what our directory pointer should be */
	movq	%r14, %r13
	movq	$0xffffffffc0000000, %r12
	andq	%r12, %r13

	/* Set our PDPTE */
	movq	%r13, %r11
	shrq	$(30-3), %r11
	leaq    (pgtable_bsp - bsp_base + 0x1000)(%rsi), %rdi
	addq	%r11, %rdi
	leaq	(pgtable_extra_bsp - bsp_base + 0x7)(%rsi), %rax
	movq	%rax, 0(%rdi)

	/* Populate the page directory */
	leaq    (pgtable_extra_bsp - bsp_base)(%rsi), %rdi
	movq    $0x00000183, %rax
	addq	%r13, %rax
	movq    $512, %rcx
1:      movq    %rax, 0(%rdi)
	addq    $0x00200000, %rax
	addq    $8, %rdi
	decq    %rcx
	jnz     1b

	/* Set esi to point to the boot_params structure */
2:	movq	%r15, %rsi
	jmp	*%r14

	.align 8
SYM_DATA(boot_params_phys_addr, .quad  0)

	.align 8
SYM_DATA(kernel_phys_addr, .quad  0)

	.code16
	.balign 4
	# Careful these need to be in the same 64K segment as the above;
tidt_bsp:
	.word	0			# idt limit = 0
	.word	0, 0			# idt base = 0L

	# Duplicate the global descriptor table
	# so the kernel can live anywhere
	.balign 4
tgdt_bsp:
	.short	tgdt_bsp_end - tgdt_bsp		# gdt limit
	.long	tgdt_bsp - bsp_base
	.short 0
	.quad	0x00cf9b000000ffff	# __KERNEL32_CS
	.quad	0x00af9b000000ffff	# __KERNEL_CS
	.quad	0x00cf93000000ffff	# __KERNEL_DS
tgdt_bsp_end:

	.code64
	.balign 4
gdt_bsp_64:
        .word   gdt_bsp_64_end - gdt_bsp_64
        .long   gdt_bsp_64 - bsp_base
        .word   0
        .quad   0x0000000000000000      /* NULL descriptor */
        .quad   0x00af9a000000ffff      /* __KERNEL_CS */
        .quad   0x00cf92000000ffff      /* __KERNEL_DS */
        .quad   0x0080890000000000      /* TS descriptor */
        .quad   0x0000000000000000      /* TS continued */
gdt_bsp_64_end:

	.code16
	.balign 4
startup_32_vector_bsp:
	.long	startup_32_bsp - bsp_base
	.word	__KERNEL32_CS, 0

	.balign 4
startup_64_vector_bsp:
	.long	startup_64_bsp - bsp_base
	.word	__KERNEL_CS, 0

	.balign 4
SYM_DATA(trampoline_status_bsp, .long	0)

	.balign 4
SYM_DATA(trampoline_location, .quad   0)

trampoline_stack_bsp:
	.fill 512,8,0
trampoline_stack_bsp_end:

SYM_DATA(trampoline_bsp_end)

/*
 * Space for page tables (not in .bss so not zeroed)
 */
        .balign 4096
pgtable_bsp:
        .fill 6*4096, 1, 0
pgtable_extra_bsp:
	.fill 1*4096, 1, 0

