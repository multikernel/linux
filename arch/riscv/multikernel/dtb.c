// SPDX-License-Identifier: GPL-2.0-only
/*
 * The device tree a RISC-V instance boots from.
 *
 * The tree in a1 is the only boot channel, see kernel/multikernel/boot_dtb.c.
 * On top of the instance tree and /memory, the RISC-V boot path reads
 * /cpus, whose nodes also hold each hart's local interrupt controller, and
 * the IMSIC that takes the instance's MSIs.
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>

#include "internal.h"

static int mk_dtb_copy_props(void *fdt, int node, struct device_node *np)
{
	struct property *pp;
	int ret;

	for_each_property_of_node(np, pp) {
		if (!strcmp(pp->name, "name"))
			continue;
		ret = fdt_setprop(fdt, node, pp->name, pp->value, pp->length);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Copy @np with its properties and its children under @parent, and return
 * the new node's offset. The phandles come along, so references between
 * copied nodes, an interrupt controller's interrupts-extended naming the
 * harts' local controllers for one, keep working.
 */
int mk_dtb_copy_node(void *fdt, int parent, struct device_node *np)
{
	struct device_node *child;
	int node, ret;

	node = fdt_add_subnode(fdt, parent, np->full_name);
	if (node < 0)
		return node;

	ret = mk_dtb_copy_props(fdt, node, np);
	if (ret)
		return ret;

	for_each_child_of_node(np, child) {
		ret = mk_dtb_copy_node(fdt, node, child);
		if (ret < 0) {
			of_node_put(child);
			return ret;
		}
	}
	return node;
}

/*
 * Copy a hart's node, enabled if the instance's kernel can run on the
 * hart and disabled if it is of another kind than the instance's harts.
 */
static int mk_dtb_copy_hart(void *fdt, int parent, struct device_node *np,
			    bool enabled)
{
	int node, ret;

	node = mk_dtb_copy_node(fdt, parent, np);
	if (node < 0)
		return node;

	if (!enabled)
		return fdt_setprop_string(fdt, node, "status", "disabled");

	ret = fdt_delprop(fdt, node, "status");
	return ret == -FDT_ERR_NOTFOUND ? 0 : ret;
}

/*
 * The instance's own harts come first, the boot hart leading as it does
 * in instance->cpus, so they get the low logical numbers. Every other
 * hart of the machine follows: a kernel can only ever online a hart it
 * enumerated at boot, and the generic code prunes the ones the instance
 * does not own from the present mask. A hart of another kind than the
 * instance's is one its kernel can never run on: it stays in the tree,
 * as the interrupt controllers index their harts by position, disabled.
 *
 * The nodes are otherwise copied verbatim: the ISA strings, the MMU type
 * and the cache block sizes describe that hart as firmware set it up,
 * and a spawn probing an extension firmware left off on a hart would
 * trap. The harts this kernel never booted have nodes like any other by
 * now, see discover.c.
 *
 * fdt_add_subnode() puts a new node ahead of its siblings, hence the
 * instance's harts last and from the last to the first.
 */
static int mk_dtb_add_cpus(void *fdt, struct mk_instance *instance)
{
	mk_phys_cpu_t boot = mk_cpu_set_first(instance->cpus);
	struct device_node *cpus, *np;
	unsigned int i;
	int node, ret;

	cpus = of_find_node_by_path("/cpus");
	if (!cpus) {
		pr_err("The host tree has no /cpus\n");
		return -FDT_ERR_NOTFOUND;
	}

	node = fdt_add_subnode(fdt, 0, "cpus");
	ret = node < 0 ? node : mk_dtb_copy_props(fdt, node, cpus);
	of_node_put(cpus);
	if (ret)
		return ret;

	for_each_of_cpu_node(np) {
		mk_phys_cpu_t hartid = of_get_cpu_hwid(np, 0);

		if (mk_cpu_set_contains(instance->cpus, hartid))
			continue;
		ret = mk_dtb_copy_hart(fdt, node, np,
				       mk_cpus_same_kind(hartid, boot));
		if (ret) {
			of_node_put(np);
			return ret;
		}
	}

	for (i = mk_cpu_set_count(instance->cpus); i-- > 0; ) {
		mk_phys_cpu_t hartid = instance->cpus->ids[i];

		np = mk_of_hart_node(hartid);
		if (!np) {
			pr_err("The host tree has no hart %llu\n", hartid);
			return -FDT_ERR_NOTFOUND;
		}
		ret = mk_dtb_copy_hart(fdt, node, np, true);
		of_node_put(np);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * A platform device's interrupts are wired, and every wired source goes
 * through the one PLIC or APLIC, whose priority, enable and target
 * registers stay with the host. The boot tree has no wired controller.
 */
static int mk_dtb_check_devices(struct mk_instance *instance)
{
	if (instance->platform_devices_valid &&
	    !list_empty(&instance->platform_devices)) {
		pr_err("Instance %d: platform devices cannot be given to an instance on RISC-V\n",
		       instance->id);
		return -FDT_ERR_BADSTATE;
	}
	return 0;
}

/* Everything here returns libfdt error codes */
int mk_dtb_add_arch_nodes(void *fdt, struct mk_instance *instance)
{
	int ret;

	ret = mk_dtb_check_devices(instance);
	if (!ret)
		ret = mk_dtb_add_cpus(fdt, instance);
	if (!ret)
		ret = mk_dtb_add_imsic(fdt);
	return ret;
}
