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

.option pop
