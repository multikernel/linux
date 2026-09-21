// SPDX-License-Identifier: GPL-2.0
/*
 * PCI in an instance tree.
 *
 * The generic code describes the root buses above the instance's PCI
 * devices, ECAM window included, which makes each of them an ordinary
 * ECAM host bridge; what is left is to name the driver for it. INTx is
 * not offered: the lines are SPIs that the host shares between devices.
 * MSIs go through the host's ITSs, which the instance reaches through a
 * proxy node. The node has no address: everything, the doorbell of the
 * ITS behind a device included, comes over the message ring
 * (irq-gic-v3-its-mk.c).
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/dma-map-ops.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/libfdt.h>
#include <linux/pci.h>
#include <linux/sizes.h>

#include "internal.h"

#define MK_ITS_PROXY	"multikernel,gic-v3-its"

static int mk_dtb_add_its_proxy(void *fdt, u32 *phandle)
{
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

/*
 * What a root bus node has to say about the devices behind it, asked of a
 * device on the host's side of the same bus. Devices inherit DMA coherency
 * from their host bridge node, and a tree that is silent about it makes
 * them all non-coherent. MSIs need an ITS behind the bus; which one does
 * not matter here, the host picks it per device when an event is mapped.
 */
struct mk_root_bus_traits {
	bool coherent;
	bool msi;
};

static int mk_dtb_first_dev_traits(struct pci_dev *pdev, void *data)
{
	struct mk_root_bus_traits *traits = data;

	traits->coherent = dev_is_dma_coherent(&pdev->dev);
	traits->msi = IS_ENABLED(CONFIG_MULTIKERNEL_ITS_PROXY) &&
		      its_foreign_doorbell(dev_get_msi_domain(&pdev->dev));
	return 1;
}

static struct mk_root_bus_traits mk_dtb_root_bus_traits(void *fdt, int node)
{
	const fdt32_t *domain = fdt_getprop(fdt, node, "linux,pci-domain", NULL);
	const fdt32_t *range = fdt_getprop(fdt, node, "bus-range", NULL);
	struct mk_root_bus_traits traits = {};
	struct pci_bus *bus = NULL;

	if (range)
		bus = pci_find_bus(domain ? fdt32_to_cpu(*domain) : 0,
				   fdt32_to_cpu(range[0]));
	if (bus)
		pci_walk_bus(bus, mk_dtb_first_dev_traits, &traits);
	return traits;
}

#define mk_dtb_for_each_root_bus(fdt, node)					\
	for (node = fdt_node_offset_by_compatible(fdt, -1, MK_PCI_HOST_BRIDGE);	\
	     node >= 0;								\
	     node = fdt_node_offset_by_compatible(fdt, node, MK_PCI_HOST_BRIDGE))

int mk_dtb_add_pci(void *fdt)
{
	static const char compatible[] =
		MK_PCI_HOST_BRIDGE "\0pci-host-ecam-generic";
	struct mk_root_bus_traits traits;
	bool any_msi = false;
	u32 phandle = 0;
	int node, ret;

	/* Adding the proxy node moves the root buses, so look before writing */
	mk_dtb_for_each_root_bus(fdt, node)
		any_msi |= mk_dtb_root_bus_traits(fdt, node).msi;
	if (any_msi) {
		ret = mk_dtb_add_its_proxy(fdt, &phandle);
		if (ret)
			return ret;
	}

	mk_dtb_for_each_root_bus(fdt, node) {
		if (!fdt_getprop(fdt, node, "reg", NULL)) {
			pr_warn("A PCI root bus of the instance has no ECAM window\n");
			continue;
		}

		traits = mk_dtb_root_bus_traits(fdt, node);
		if (!traits.msi)
			pr_warn("No ITS behind a PCI root bus of the instance: its devices get no interrupts\n");

		ret = fdt_setprop(fdt, node, "compatible", compatible,
				  sizeof(compatible));
		if (!ret && traits.msi)
			ret = mk_dtb_set_msi_map(fdt, node, phandle);
		if (!ret && traits.coherent)
			ret = fdt_setprop_empty(fdt, node, "dma-coherent");
		if (ret)
			return ret;
	}
	return 0;
}
