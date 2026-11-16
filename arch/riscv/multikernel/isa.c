// SPDX-License-Identifier: GPL-2.0-only
/*
 * The extensions of a hart that described itself, from the probes it
 * passed.
 */

#include <linux/bits.h>
#include <linux/kernel.h>
#include <asm/cpufeature.h>
#include <asm/hwcap.h>

#include "internal.h"
#include "probe.h"

/*
 * An extension this kernel knows is one of the hart's if the probes it
 * names all passed. One the stub has no probe for, a property of the
 * page tables or of an M-mode register, is not listed here and never
 * reaches an instance: its kernel then leaves a feature unused, which is
 * always safe. No probes means the extension cannot be missing: it is
 * hints only, or part of the base the stub itself runs on.
 */
#define P(name)	BIT(MK_PROBE_##name)

static const struct {
	unsigned int ext;
	u64 probes;
} mk_probed_exts[] = {
	{ RISCV_ISA_EXT_i,		0 },
	{ RISCV_ISA_EXT_ZICSR,		0 },
	{ RISCV_ISA_EXT_ZIFENCEI,	0 },
	{ RISCV_ISA_EXT_ZIHINTPAUSE,	0 },
	{ RISCV_ISA_EXT_ZIHINTNTL,	0 },
	{ RISCV_ISA_EXT_m,		P(M) },
	{ RISCV_ISA_EXT_a,		P(A) },
	{ RISCV_ISA_EXT_ZAAMO,		P(A) },
	{ RISCV_ISA_EXT_ZALRSC,		P(A) },
	{ RISCV_ISA_EXT_f,		P(F) },
	{ RISCV_ISA_EXT_d,		P(F) | P(D) },
	{ RISCV_ISA_EXT_ZFA,		P(F) | P(ZFA) },
	{ RISCV_ISA_EXT_c,		P(C) },
	{ RISCV_ISA_EXT_ZCA,		P(C) },
	{ RISCV_ISA_EXT_ZCD,		P(C) | P(D) },
	{ RISCV_ISA_EXT_v,		P(V) },
	{ RISCV_ISA_EXT_h,		P(H) },
	{ RISCV_ISA_EXT_ZBA,		P(ZBA) },
	{ RISCV_ISA_EXT_ZBB,		P(ZBB) },
	{ RISCV_ISA_EXT_ZBC,		P(ZBC) },
	{ RISCV_ISA_EXT_ZBS,		P(ZBS) },
	{ RISCV_ISA_EXT_ZICOND,		P(ZICOND) },
	{ RISCV_ISA_EXT_ZICNTR,		P(TIME) },
	{ RISCV_ISA_EXT_SSTC,		P(SSTC) },
	{ RISCV_ISA_EXT_SSAIA,		P(AIA) },
	{ RISCV_ISA_EXT_SMAIA,		P(AIA) },
};

static bool mk_hart_has_ext(const struct mk_hart *hart, unsigned int ext)
{
	unsigned int i;

	if (!__riscv_isa_extension_available(NULL, ext))
		return false;

	for (i = 0; i < ARRAY_SIZE(mk_probed_exts); i++) {
		if (mk_probed_exts[i].ext == ext)
			return (hart->passed & mk_probed_exts[i].probes) ==
			       mk_probed_exts[i].probes;
	}
	return false;
}

/* Fill @names, which has room for every extension this kernel knows */
unsigned int mk_hart_isa_extensions(const struct mk_hart *hart,
				    const char **names)
{
	unsigned int n = 0;
	size_t i;

	for (i = 0; i < riscv_isa_ext_count; i++) {
		if (mk_hart_has_ext(hart, riscv_isa_ext[i].id))
			names[n++] = riscv_isa_ext[i].name;
	}
	return n;
}
