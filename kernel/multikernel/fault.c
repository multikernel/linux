// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hardware a fenced host named as faulty
 *
 * A kernel that dies of a hardware error marks what the error condemns
 * where the kernels after it can see it, which is up to the architecture.
 * Once the host is fenced, the marks become a node of this kernel's
 * device tree, in the shape of the host tree it sits beside, for the user
 * space that decides what to adopt:
 *
 *	chosen {
 *		multikernel,faults {
 *			cpus = <u64 ...>;	physical ids
 *		};
 *	};
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc.
 */
#define pr_fmt(fmt) "multikernel: " fmt

#include <linux/cpumask.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/slab.h>
#include "internal.h"

#define MK_FAULTS_NODE "multikernel,faults"

bool __weak mk_arch_cpu_faulty(mk_phys_cpu_t phys_cpu)
{
	return false;
}

/**
 * mk_fault_publish - Show the machine's faulty CPUs in the device tree
 *
 * Called once the host's CPUs are confirmed parked, so the host has
 * marked all it is going to. Marks that cannot be published cost the
 * takeover nothing.
 */
void mk_fault_publish(void)
{
	struct device_node *np;
	struct of_changeset *cs;
	unsigned int nr = 0;
	u32 *cells;
	int cpu, ret;

	if (!of_chosen)
		return;
	cells = kcalloc(2 * num_possible_cpus(), sizeof(*cells), GFP_KERNEL);
	if (!cells)
		return;
	for_each_possible_cpu(cpu) {
		mk_phys_cpu_t phys = arch_cpu_physical_id(cpu);

		if (!mk_arch_cpu_faulty(phys))
			continue;
		pr_warn("Host fenced: CPU 0x%llx is marked faulty\n", phys);
		cells[nr++] = upper_32_bits(phys);
		cells[nr++] = lower_32_bits(phys);
	}
	if (!nr)
		goto out;

	/* The node is this kernel's for good: the changeset is never reverted */
	cs = kzalloc_obj(*cs, GFP_KERNEL);
	if (!cs)
		goto out;
	of_changeset_init(cs);
	np = of_changeset_create_node(cs, of_chosen, MK_FAULTS_NODE);
	ret = np ? 0 : -ENOMEM;
	if (!ret)
		ret = of_changeset_add_prop_u32_array(cs, np, "cpus", cells, nr);
	if (!ret)
		ret = of_changeset_apply(cs);
	if (ret) {
		pr_err("Faulty CPUs not published: %d\n", ret);
		of_changeset_destroy(cs);
		kfree(cs);
	}
out:
	kfree(cells);
}
