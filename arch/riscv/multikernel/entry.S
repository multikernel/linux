/* SPDX-License-Identifier: GPL-2.0-only */

#include <asm/page.h>
#include <linux/linkage.h>

.section ".text", "ax"

.option push
.option norvc
.option norelax

SYM_CODE_START(mk_riscv_entry_stub_start)
	fence.i
	auipc	t0, 0
	li	t1, -PAGE_SIZE
	and	t0, t0, t1
	add	t0, t0, t1
	ld	t0, 0(t0)
	jr	t0
.globl mk_riscv_entry_stub_end
mk_riscv_entry_stub_end:
SYM_CODE_END(mk_riscv_entry_stub_start)

/*
 * Every hart executes a local fence.i immediately before entering the CPU
 * pool, so this immutable host-text entry cannot be fetched from an older
 * cache line.  Use it to make a newly copied per-instance stub visible before
 * its first fetch.
 */
SYM_CODE_START(mk_riscv_entry_fence_stop)
	fence.i
	li	a7, 0x48534d	/* SBI_EXT_HSM */
	li	a6, 1		/* SBI_EXT_HSM_HART_STOP */
	ecall
.Lmk_riscv_entry_stop_failed:
	wfi
	j	.Lmk_riscv_entry_stop_failed
SYM_CODE_END(mk_riscv_entry_fence_stop)

.option pop
