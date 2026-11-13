/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Where every hart a multikernel kernel starts enters.
 *
 * RISC-V has no remote instruction cache invalidation, a hart stopped
 * through SBI HSM cannot be reached by a remote fence.i, and neither
 * OpenSBI's HART_START nor _start_kernel in S-mode executes one. A hart
 * that ran a kernel image, stopped, and is started on another image
 * loaded at the same physical addresses can fetch the old image's lines.
 * The stop path itself, run after any fence.i it could execute, leaves
 * some behind.
 *
 * So a hart enters here first. These lines are host kernel text: their
 * address never holds anything else for as long as the host runs, so
 * whatever a hart has cached of them is current. The fence.i makes the
 * image the hart jumps to visible to its instruction fetch. The rest
 * comes as data through a1, which data reads see coherently: a struct
 * mk_boot_record with the a1 to enter with and the entry point.
 */

#include <linux/linkage.h>

	.text
SYM_CODE_START(mk_hart_entry)
	fence.i
	ld	t0, 8(a1)
	ld	a1, 0(a1)
	jr	t0
SYM_CODE_END(mk_hart_entry)
