// SPDX-License-Identifier: GPL-2.0
/*
 * Platform nodes of an instance tree, on a host that booted from a
 * device tree: copies of the host's own nodes.
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/libfdt.h>
#include <linux/of.h>
#include <linux/of_address.h>

#include "internal.h"

static const struct of_device_id mk_psci_ids[] = {
	{ .compatible = "arm,psci" },
	{ .compatible = "arm,psci-0.2" },
	{ .compatible = "arm,psci-1.0" },
	{}
};

static const struct of_device_id mk_timer_ids[] = {
	{ .compatible = "arm,armv8-timer" },
	{ .compatible = "arm,armv7-timer" },
	{}
};

static bool mk_prop_is_addressing(const char *name)
{
	return !strcmp(name, "reg") || !strcmp(name, "ranges") ||
	       !strcmp(name, "#address-cells") || !strcmp(name, "#size-cells");
}

/* Addressing is only valid below @np's parent bus, so reg is translated to CPU addresses */
static int mk_dtb_copy_of_reg(void *fdt, int node, struct device_node *np)
{
	struct resource res;
	int i, ret;

	for (i = 0; !of_address_to_resource(np, i, &res); i++) {
		ret = fdt_appendprop_u64(fdt, node, "reg", res.start);
		if (!ret)
			ret = fdt_appendprop_u64(fdt, node, "reg", resource_size(&res));
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Copy @np to a new node under the root and return its offset. The
 * phandle comes along, so interrupt-parent references between copied
 * nodes keep working.
 */
static int mk_dtb_copy_of_node(void *fdt, struct device_node *np)
{
	struct property *pp;
	int node, ret;

	node = fdt_add_subnode(fdt, 0, np->full_name);
	if (node < 0)
		return node;

	for_each_property_of_node(np, pp) {
		if (!strcmp(pp->name, "name") || mk_prop_is_addressing(pp->name))
			continue;
		ret = fdt_setprop(fdt, node, pp->name, pp->value, pp->length);
		if (ret)
			return ret;
	}

	ret = mk_dtb_copy_of_reg(fdt, node, np);
	return ret ? ret : node;
}

static int mk_dtb_copy_matching(void *fdt, const struct of_device_id *ids,
				const char *what)
{
	struct device_node *np = of_find_matching_node(NULL, ids);
	int node;

	if (!np) {
		pr_err("The host tree has no %s node\n", what);
		return -FDT_ERR_NOTFOUND;
	}
	node = mk_dtb_copy_of_node(fdt, np);
	of_node_put(np);
	return node < 0 ? node : 0;
}

/*
 * The GIC's children are left behind: an ITS has one command queue,
 * which is the host's.
 */
static int mk_dtb_copy_gic(void *fdt)
{
	struct device_node *np;
	int node;

	np = of_find_compatible_node(NULL, NULL, "arm,gic-v3");
	if (!np) {
		pr_err("The host tree has no GICv3\n");
		return -FDT_ERR_NOTFOUND;
	}

	node = mk_dtb_copy_of_node(fdt, np);
	of_node_put(np);
	if (node < 0)
		return node;

	return fdt_setprop_u32(fdt, 0, "interrupt-parent",
			       fdt_get_phandle(fdt, node));
}

int mk_dtb_add_platform_of(void *fdt)
{
	int ret;

	ret = mk_dtb_copy_matching(fdt, mk_psci_ids, "PSCI");
	if (!ret)
		ret = mk_dtb_copy_matching(fdt, mk_timer_ids, "arch timer");
	if (!ret)
		ret = mk_dtb_copy_gic(fdt);
	return ret;
}
