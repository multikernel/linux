/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * What a hart this kernel never booted runs to describe itself.
 *
 * RISC-V has no CPUID: a kernel is told its harts' features by the device
 * tree, and nothing tells it about a hart the tree leaves out. Such a hart
 * is started here once, in S-mode with the MMU off as HART_START leaves
 * it, with the physical address of a struct mk_hart_probe in a1. It asks
 * firmware who it is, tries one instruction or CSR of each extension with
 * a trap handler that counts a trap as "not there", finds its IMSIC
 * interrupt file among the candidates, and stops itself again.
 *
 * The instructions are spelled as words: the assembler need not know an
 * extension for a hart to be asked about it.
 */

#include <linux/linkage.h>
#include <asm/csr.h>

#include "probe.h"

#define SBI_EXT_BASE			0x10
#define SBI_EXT_BASE_GET_MVENDORID	4
#define SBI_EXT_BASE_GET_MARCHID	5
#define SBI_EXT_BASE_GET_MIMPID		6
#define SBI_EXT_HSM			0x48534D
#define SBI_EXT_HSM_HART_STOP		1

#define IMSIC_EIP0			0x80

/* A trap anywhere up to the matching passed resumes behind it */
.macro attempt
	lla	s1, 1f
.endm

.macro passed bit
	li	t0, 1 << \bit
	or	s2, s2, t0
1:
.endm

.macro machine_id fid, field
	li	a7, SBI_EXT_BASE
	li	a6, \fid
	ecall
	sd	a1, \field(s0)
.endm

	.text
	.option push
	.option norvc
	.option norelax
SYM_CODE_START(mk_hart_probe_entry)
	mv	s0, a1
	lla	t0, .Ltrap
	csrw	CSR_STVEC, t0
	addi	sp, s0, MK_PROBE_SCRATCH
	li	s2, 0

	machine_id SBI_EXT_BASE_GET_MVENDORID, MK_PROBE_MVENDORID
	machine_id SBI_EXT_BASE_GET_MARCHID, MK_PROBE_MARCHID
	machine_id SBI_EXT_BASE_GET_MIMPID, MK_PROBE_MIMPID

	attempt
	.4byte	0x025282b3		/* mul t0, t0, t0 */
	passed	MK_PROBE_M

	attempt
	.4byte	0x005132af		/* amoadd.d t0, t0, (sp) */
	passed	MK_PROBE_A

	attempt
	li	t0, SR_FS_INITIAL
	csrs	CSR_SSTATUS, t0
	csrr	t1, CSR_SSTATUS
	and	t1, t1, t0
	beqz	t1, 1f
	.4byte	0xf0000053		/* fmv.w.x ft0, zero */
	passed	MK_PROBE_F

	attempt
	.4byte	0xf2000053		/* fmv.d.x ft0, zero */
	passed	MK_PROBE_D

	attempt
	.4byte	0xf0180053		/* fli.s ft0, 1.0 */
	passed	MK_PROBE_ZFA

	attempt
	.2byte	0x0001, 0x0001		/* c.nop, twice */
	passed	MK_PROBE_C

	attempt
	li	t0, SR_VS_INITIAL
	csrs	CSR_SSTATUS, t0
	csrr	t1, CSR_VLENB
	sd	t1, MK_PROBE_VLENB(s0)
	passed	MK_PROBE_V

	attempt
	csrr	t0, CSR_HSTATUS
	passed	MK_PROBE_H

	attempt
	.4byte	0x2052a2b3		/* sh1add t0, t0, t0 */
	passed	MK_PROBE_ZBA

	attempt
	.4byte	0x4052f2b3		/* andn t0, t0, t0 */
	passed	MK_PROBE_ZBB

	attempt
	.4byte	0x0a5292b3		/* clmul t0, t0, t0 */
	passed	MK_PROBE_ZBC

	attempt
	.4byte	0x285292b3		/* bset t0, t0, t0 */
	passed	MK_PROBE_ZBS

	attempt
	.4byte	0x0e52d2b3		/* czero.eqz t0, t0, t0 */
	passed	MK_PROBE_ZICOND

	attempt
	csrr	t0, CSR_TIME
	passed	MK_PROBE_TIME

	attempt
	csrr	t0, CSR_STIMECMP
	passed	MK_PROBE_SSTC

	attempt
	csrr	t0, CSR_SISELECT
	passed	MK_PROBE_AIA

	/*
	 * An interrupt file's pending bits are set by a write to its page
	 * and read back through the CSRs of the hart it belongs to, so the
	 * candidate whose write shows up here is this hart's. A candidate
	 * that is no file at all traps or does nothing.
	 *
	 * The write takes a while to show up on real hardware, and one
	 * that is seen late would be taken for the next candidate's. So
	 * each candidate is given MK_PROBE_FILE_SPINS reads to answer.
	 */
	lla	s1, .Lfiles_done
	ld	t2, MK_PROBE_NR_FILES(s0)
	beqz	t2, .Lfiles_done
	li	t0, IMSIC_EIP0
	csrw	CSR_SISELECT, t0
	li	t3, 1 << MK_PROBE_EIID
	csrc	CSR_SIREG, t3
	addi	t4, s0, MK_PROBE_FILES
	lla	s1, .Lnext_file
.Ltry_file:
	ld	t5, 0(t4)
	li	t0, MK_PROBE_EIID
	sw	t0, 0(t5)
	li	t6, MK_PROBE_FILE_SPINS
.Lawait_file:
	csrr	t1, CSR_SIREG
	and	t1, t1, t3
	bnez	t1, .Lfound_file
	addi	t6, t6, -1
	bnez	t6, .Lawait_file
	j	.Lnext_file
.Lfound_file:
	csrc	CSR_SIREG, t3
	sd	t5, MK_PROBE_FILE(s0)
	j	.Lfiles_done
.Lnext_file:
	addi	t4, t4, 8
	addi	t2, t2, -1
	bnez	t2, .Ltry_file
.Lfiles_done:

	li	t0, SR_FS | SR_VS
	csrc	CSR_SSTATUS, t0
	sd	s2, MK_PROBE_PASSED(s0)
	li	t0, 1
	sd	t0, MK_PROBE_DONE(s0)

	li	a7, SBI_EXT_HSM
	li	a6, SBI_EXT_HSM_HART_STOP
	ecall
1:	wfi
	j	1b

	.balign	4
.Ltrap:
	csrw	CSR_SEPC, s1
	sret
SYM_CODE_END(mk_hart_probe_entry)
	.option pop
