/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Where firmware enters a hart whose kernel is being forced down.
 *
 * The hart can have been anywhere: in user mode, halfway through the
 * exception entry with a user tp, on a stack that overflowed, under any
 * lock. Nothing of its context can be trusted, and nothing of it is
 * needed either, since the hart either stops for good or goes back as if
 * nothing had happened. Firmware saves a6 and a7 before it enters here
 * and restores them when the event completes, and both ways out are an
 * SBI call that takes its arguments in those two. So they are all this
 * uses: no stack, no tp, no gp.
 *
 * The force-halt marker is looked up through mk_self every time, as a
 * host has no ring area until it has a kernel to share one with. A spawn
 * maps its ring area in the vmalloc range, where a hart may still hold a
 * cached invalid translation of a mapping it never touched. The trap
 * that repairs that cannot be taken here, hence the sfence.vma.
 */

#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/asm-offsets.h>

#define SBI_EXT_HSM		0x48534D
#define SBI_EXT_HSM_HART_STOP	1
#define SBI_EXT_SSE		0x535345
#define SBI_SSE_EVENT_COMPLETE	6

	.section .noinstr.text, "ax"
SYM_CODE_START(mk_sse_stop)
	la	a7, mk_self
	REG_L	a7, 0(a7)
	beqz	a7, .Lignore
	REG_L	a7, MK_INSTANCE_IPI_DATA(a7)
	beqz	a7, .Lignore
	li	a6, MK_SHARED_FORCE_HALT
	add	a7, a7, a6
	sfence.vma a7, zero
	lw	a7, 0(a7)
	beqz	a7, .Lignore

	li	a7, SBI_EXT_HSM
	li	a6, SBI_EXT_HSM_HART_STOP
	ecall
	j	.Lstuck

	/* Only a kernel with a link to this one can have set the marker */
.Lignore:
	li	a7, SBI_EXT_SSE
	li	a6, SBI_SSE_EVENT_COMPLETE
	ecall

	/* Firmware refused, and there is no context left to go back to */
.Lstuck:
	wfi
	j	.Lstuck
SYM_CODE_END(mk_sse_stop)
