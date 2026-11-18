// SPDX-License-Identifier: GPL-2.0-only
/*
 * CPU nodes for the harts this kernel's device tree left out.
 *
 * Such a hart gets a node in the live tree, disabled, as this kernel
 * does not run on it. From then on it is a hart like any other to
 * whatever reads the tree, the making of an instance's tree first.
 */

#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <asm/cpufeature.h>

#include "internal.h"

struct device_node *mk_of_hart_node(mk_phys_cpu_t hartid)
{
	struct device_node *np;

	for_each_of_cpu_node(np) {
		if (of_get_cpu_hwid(np, 0) == hartid)
			return np;
	}
	return NULL;
}

/*
 * Above every phandle of the tree this kernel booted from. The nodes
 * made here do not count: a changeset attaches a node before its
 * properties, so the tree never learns their phandles.
 */
static u32 mk_boot_tree_phandles(void)
{
	struct device_node *np;
	u32 highest = 0;

	for_each_of_allnodes(np)
		highest = max(highest, np->phandle);
	return highest;
}

/*
 * The node a device tree would have had for the hart, less what nothing
 * needs to run on it: no model name, as errata go by the ID registers,
 * no MMU type, which a kernel then finds out by itself, and no caches.
 */
static int mk_hart_fill_node(struct of_changeset *ocs, struct device_node *cpus,
			     const struct mk_hart *hart)
{
	const char **exts __free(kfree) = kcalloc(riscv_isa_ext_count,
						  sizeof(*exts), GFP_KERNEL);
	u32 reg[] = { upper_32_bits(hart->hartid), lower_32_bits(hart->hartid) };
	struct device_node *np, *intc;
	u32 cells = 1;
	char name[32];
	int ret;

	if (!exts)
		return -ENOMEM;

	of_property_read_u32(cpus, "#address-cells", &cells);
	if (cells != 1 && cells != 2)
		return -EINVAL;

	snprintf(name, sizeof(name), "cpu@%llx", hart->hartid);
	np = of_changeset_create_node(ocs, cpus, name);
	if (!np)
		return -ENOMEM;

	ret = of_changeset_add_prop_string(ocs, np, "device_type", "cpu") ?:
	      of_changeset_add_prop_u32_array(ocs, np, "reg",
					      &reg[2 - cells], cells) ?:
	      of_changeset_add_prop_string(ocs, np, "compatible", "riscv") ?:
	      of_changeset_add_prop_string(ocs, np, "status", "disabled") ?:
	      of_changeset_add_prop_string(ocs, np, "riscv,isa-base", "rv64i") ?:
	      of_changeset_add_prop_string_array(ocs, np, "riscv,isa-extensions",
			exts, mk_hart_isa_extensions(hart, exts));
	if (ret)
		return ret;

	intc = of_changeset_create_node(ocs, np, "interrupt-controller");
	if (!intc)
		return -ENOMEM;

	return of_changeset_add_prop_u32(ocs, intc, "#interrupt-cells", 1) ?:
	       of_changeset_add_prop_bool(ocs, intc, "interrupt-controller") ?:
	       of_changeset_add_prop_string(ocs, intc, "compatible",
					    "riscv,cpu-intc") ?:
	       of_changeset_add_prop_u32(ocs, intc, "phandle", hart->phandle);
}

int mk_hart_add_node(struct mk_hart *hart)
{
	struct device_node *cpus __free(device_node) = of_find_node_by_path("/cpus");
	static u32 next_phandle;
	struct of_changeset ocs;
	int ret;

	if (!cpus)
		return -ENODEV;

	if (!next_phandle)
		next_phandle = mk_boot_tree_phandles() + 1;
	hart->phandle = next_phandle;

	of_changeset_init(&ocs);
	ret = mk_hart_fill_node(&ocs, cpus, hart) ?: of_changeset_apply(&ocs);
	of_changeset_destroy(&ocs);
	if (!ret)
		next_phandle++;
	return ret;
}
