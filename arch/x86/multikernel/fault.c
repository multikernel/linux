// SPDX-License-Identifier: GPL-2.0-only
/*
 * A core condemned by the machine check that kills this kernel
 *
 * A fatal machine check is handled on the CPU that raised it and leaves
 * its bank registers as they were, with MCG_STATUS.MCIP still set, so the
 * panic it ends in can still see what was reported. When that says the
 * core itself is broken, its park cells are marked, for the kernel that
 * takes this machine over and every one after it.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc.
 */
#include <linux/bits.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/panic_notifier.h>
#include <linux/topology.h>
#include <asm/cpufeature.h>
#include <asm/mce.h>
#include <asm/multikernel.h>
#include <asm/msr.h>

/*
 * With SMCA a bank says what it is, whatever the model. A guest is shown
 * no SMCA and cannot ask; a Zen core has its execution unit in bank 5 and
 * its floating point unit in bank 6.
 */
static enum smca_bank_types mk_core_bank_type(int cpu, unsigned int bank)
{
	if (cpu_feature_enabled(X86_FEATURE_SMCA))
		return smca_get_bank_type(cpu, bank);
	if (bank == 5)
		return SMCA_EX;
	if (bank == 6)
		return SMCA_FP;
	return N_SMCA_BANK_TYPES;
}

/*
 * The error codes of each kind of bank that say the core itself is
 * broken, one bit per code. A bank or a code not listed condemns nothing,
 * so a model that reports something new is ignored until it is added.
 *
 * The execution and floating point banks report nothing but parity
 * errors in the core's own register files, queues and maps, each with
 * PCC set, and no memory or cache contents are involved. Two of their
 * codes point elsewhere and are left out: a watchdog timeout (EX 0x0) is
 * also what a software or firmware hang looks like, and a hardware
 * assertion (EX 0xb, FP 0x6) is a logic or microcode bug more than a
 * worn core.
 */
static const struct {
	enum smca_bank_types type;
	u64 codes;
} mk_core_faults[] = {
	{ SMCA_EX, GENMASK_ULL(0xa, 0x1) | BIT_ULL(0xc) | BIT_ULL(0xd) },
	{ SMCA_FP, GENMASK_ULL(0x5, 0x0) },
};

static bool mk_mce_condemns_core(int cpu, unsigned int bank, u64 status)
{
	u64 fatal = MCI_STATUS_VAL | MCI_STATUS_UC | MCI_STATUS_PCC;
	enum smca_bank_types type = mk_core_bank_type(cpu, bank);
	unsigned int i;

	if ((status & fatal) != fatal)
		return false;
	for (i = 0; i < ARRAY_SIZE(mk_core_faults); i++)
		if (mk_core_faults[i].type == type)
			return mk_core_faults[i].codes & BIT_ULL(XEC(status, 0x3f));
	return false;
}

static int mk_mce_panic(struct notifier_block *nb, unsigned long action, void *data)
{
	int cpu = raw_smp_processor_id(), sibling;
	u64 mcg, cap, status;
	unsigned int bank;

	if (rdmsrq_safe(MSR_IA32_MCG_STATUS, &mcg) || !(mcg & MCG_STATUS_MCIP) ||
	    rdmsrq_safe(MSR_IA32_MCG_CAP, &cap))
		return NOTIFY_DONE;

	/* The legacy MSRs reach the core's banks with or without SMCA */
	for (bank = 0; bank < min(cap & MCG_BANKCNT_MASK, 32); bank++) {
		if (rdmsrq_safe(MSR_IA32_MCx_STATUS(bank), &status))
			continue;
		if (mk_mce_condemns_core(cpu, bank, status))
			break;
	}
	if (bank == min(cap & MCG_BANKCNT_MASK, 32))
		return NOTIFY_DONE;

	/* Its SMT siblings share what failed, so they go with it */
	for_each_cpu(sibling, topology_sibling_cpumask(cpu))
		mk_park_mark_faulty(arch_cpu_physical_id(sibling));
	return NOTIFY_DONE;
}

static struct notifier_block mk_mce_panic_nb = {
	.notifier_call = mk_mce_panic,
};

static int __init mk_mce_fault_init(void)
{
	if (cpu_feature_enabled(X86_FEATURE_SMCA) || cpu_feature_enabled(X86_FEATURE_ZEN))
		atomic_notifier_chain_register(&panic_notifier_list, &mk_mce_panic_nb);
	return 0;
}
late_initcall(mk_mce_fault_init);
