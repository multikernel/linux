// SPDX-License-Identifier: GPL-2.0
/*
 * PCI in an instance tree.
 *
 * The generic code describes the root buses above the instance's PCI
 * devices, ECAM window included, which makes each of them an ordinary
 * ECAM host bridge; what is left is to name the driver for it. INTx is
 * not offered: the lines are SPIs that the host shares between devices.
 * MSIs go through the host's ITS, which the instance reaches through a
 * proxy node: its reg is the ITS's doorbell, the rest happens over the
 * message ring (irq-gic-v3-its-mk.c).
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/irqchip/arm-gic-v3.h>
#include <linux/libfdt.h>
#include <linux/sizes.h>

#include "internal.h"

#define MK_ITS_PROXY	"multikernel,gic-v3-its"

static int mk_dtb_add_its_proxy(void *fdt, u32 *phandle)
{
	u64 reg[2] = { its_foreign_doorbell(), sizeof(u32) };
	int node, ret;

	ret = fdt_generate_phandle(fdt, phandle);
	if (ret)
		return ret;

	node = fdt_add_subnode(fdt, 0, "msi-controller");
	if (node < 0)
		return node;

	ret = fdt_setprop_string(fdt, node, "compatible", MK_ITS_PROXY);
	if (!ret)
		ret = fdt_setprop_empty(fdt, node, "msi-controller");
	if (!ret)
		ret = fdt_setprop_u32(fdt, node, "#msi-cells", 1);
	if (!ret)
		ret = fdt_setprop_u32(fdt, node, "phandle", *phandle);
	if (!ret)
		ret = mk_dtb_set_reg(fdt, node, reg, 1);
	return ret;
}

/* Every requester ID maps to itself: the host knows the real DeviceID */
static int mk_dtb_set_msi_map(void *fdt, int node, u32 phandle)
{
	const u32 map[] = { 0, phandle, 0, SZ_64K };
	int i, ret;

	fdt_delprop(fdt, node, "msi-map");
	for (i = 0; i < ARRAY_SIZE(map); i++) {
		ret = fdt_appendprop_u32(fdt, node, "msi-map", map[i]);
		if (ret)
			return ret;
	}
	return 0;
}

int mk_dtb_add_pci(void *fdt)
{
	static const char compatible[] =
		MK_PCI_HOST_BRIDGE "\0pci-host-ecam-generic";
	bool msi = IS_ENABLED(CONFIG_MULTIKERNEL_ITS_PROXY) &&
		   its_foreign_doorbell();
	u32 phandle = 0;
	int node, ret;

	if (fdt_node_offset_by_compatible(fdt, -1, MK_PCI_HOST_BRIDGE) < 0)
		return 0;

	if (msi) {
		ret = mk_dtb_add_its_proxy(fdt, &phandle);
		if (ret)
			return ret;
	} else {
		pr_warn("No ITS to route MSIs through: PCI devices of the instance get no interrupts\n");
	}

	for (node = fdt_node_offset_by_compatible(fdt, -1, MK_PCI_HOST_BRIDGE);
	     node >= 0;
	     node = fdt_node_offset_by_compatible(fdt, node, MK_PCI_HOST_BRIDGE)) {
		if (!fdt_getprop(fdt, node, "reg", NULL)) {
			pr_warn("A PCI root bus of the instance has no ECAM window\n");
			continue;
		}
		ret = fdt_setprop(fdt, node, "compatible", compatible,
				  sizeof(compatible));
		if (!ret && msi)
			ret = mk_dtb_set_msi_map(fdt, node, phandle);
		if (ret)
			return ret;
	}
	return 0;
}
