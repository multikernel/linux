/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _RISCV_MULTIKERNEL_PROBE_H
#define _RISCV_MULTIKERNEL_PROBE_H

/* struct mk_hart_probe, as probe.S addresses it */
#define MK_PROBE_DONE		0
#define MK_PROBE_MVENDORID	8
#define MK_PROBE_MARCHID	16
#define MK_PROBE_MIMPID		24
#define MK_PROBE_PASSED		32
#define MK_PROBE_VLENB		40
#define MK_PROBE_FILE		48
#define MK_PROBE_SCRATCH	56
#define MK_PROBE_NR_FILES	64
#define MK_PROBE_FILES		72

/* Bits of mk_hart_probe.passed */
#define MK_PROBE_M		0
#define MK_PROBE_A		1
#define MK_PROBE_F		2
#define MK_PROBE_D		3
#define MK_PROBE_C		4
#define MK_PROBE_V		5
#define MK_PROBE_H		6
#define MK_PROBE_ZBA		7
#define MK_PROBE_ZBB		8
#define MK_PROBE_ZBC		9
#define MK_PROBE_ZBS		10
#define MK_PROBE_ZICOND		11
#define MK_PROBE_ZFA		12
#define MK_PROBE_TIME		13
#define MK_PROBE_SSTC		14
#define MK_PROBE_AIA		15

/* The interrupt identity a hart sets pending to recognize its own file */
#define MK_PROBE_EIID		1

#ifndef __ASSEMBLY__

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>

/* One page: what a probed hart is told, and what it answers */
struct mk_hart_probe {
	u64 done;
	u64 mvendorid;
	u64 marchid;
	u64 mimpid;
	u64 passed;
	u64 vlenb;
	u64 file;
	u64 scratch;
	u64 nr_files;
	u64 files[];
};

static_assert(offsetof(struct mk_hart_probe, done) == MK_PROBE_DONE);
static_assert(offsetof(struct mk_hart_probe, mvendorid) == MK_PROBE_MVENDORID);
static_assert(offsetof(struct mk_hart_probe, marchid) == MK_PROBE_MARCHID);
static_assert(offsetof(struct mk_hart_probe, mimpid) == MK_PROBE_MIMPID);
static_assert(offsetof(struct mk_hart_probe, passed) == MK_PROBE_PASSED);
static_assert(offsetof(struct mk_hart_probe, vlenb) == MK_PROBE_VLENB);
static_assert(offsetof(struct mk_hart_probe, file) == MK_PROBE_FILE);
static_assert(offsetof(struct mk_hart_probe, scratch) == MK_PROBE_SCRATCH);
static_assert(offsetof(struct mk_hart_probe, nr_files) == MK_PROBE_NR_FILES);
static_assert(offsetof(struct mk_hart_probe, files) == MK_PROBE_FILES);

#define MK_PROBE_MAX_FILES \
	((PAGE_SIZE - sizeof(struct mk_hart_probe)) / sizeof(u64))

#endif /* __ASSEMBLY__ */
#endif /* _RISCV_MULTIKERNEL_PROBE_H */
