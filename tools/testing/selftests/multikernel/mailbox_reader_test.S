/* SPDX-License-Identifier: GPL-2.0-only */
#include "mailbox-offsets.h"
.text
.globl mailbox_read
.type mailbox_read,@function
mailbox_read:
	pushq %rbx
	pushq %rbp
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	movq %rdi, %r12
	movq %rsi, %r13
#include "mailbox-reader.h"
.Lpark_wait:
.Lpark_relax:
	xorl %eax, %eax
	jmp .Ltest_exit
.Lpark_repark:
	/* Privileged repark dispatch is covered by kernel build/runtime gates. */
	movl $-1, %eax
	jmp .Ltest_exit
.globl mailbox_capture
mailbox_capture:
	movq %rdi, observed(%rip)
	movq %rsi, observed+8(%rip)
	movq %rdx, observed+16(%rip)
	movq %rcx, observed+24(%rip)
	movq %r8, observed+32(%rip)
	movq %r9, observed+40(%rip)
	movl $1, %eax
.Ltest_exit:
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbp
	popq %rbx
	ret
.size mailbox_read,.-mailbox_read
.section .note.GNU-stack,"",@progbits
