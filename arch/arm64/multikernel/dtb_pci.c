// SPDX-License-Identifier: GPL-2.0
/*
 * PCI in an instance tree.
 *
 * The generic code describes the root buses of the instance's PCI
 * devices, whose config space the instance reaches through the host
 * (pcifront). INTx is not offered: the lines are SPIs that the host
 * shares between devices. MSIs go through the host's ITSs, which the
 * instance reaches through a proxy node. The node has no address:
 * everything, the doorbell of the ITS behind a device included, comes
 * over the message ring (irq-gic-v3-its-mk.c). Nor does the tree tie a
 * bus to it: the instance makes the proxy the MSI domain of each bridge
 * it creates, for buses it boots with and buses it is handed later alike.
 */

#include <linux/irqchip/arm-gic-v3.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/pci.h>

#include "internal.h"

static int mk_dtb_add_its_proxy(void *fdt)
{
	int node, ret;

	node = fdt_add_subnode(fdt, 0, "msi-controller");
	if (node < 0)
		return node;

	ret = fdt_setprop_string(fdt, node, "compatible", MK_ITS_PROXY_COMPATIBLE);
	if (!ret)
		ret = fdt_setprop_empty(fdt, node, "msi-controller");
	if (!ret)
		ret = fdt_setprop_u32(fdt, node, "#msi-cells", 1);
	return ret;
}

/*
 * The instance creates its MSI domain only at boot, so the proxy goes into
 * every tree an ITS of this kernel could serve, not only one whose buses
 * need it from the start.
 */
static bool mk_dtb_its_serves_pci(void)
{
	struct pci_dev *pdev = NULL;

	if (!IS_ENABLED(CONFIG_MULTIKERNEL_ITS_PROXY))
		return false;

	for_each_pci_dev(pdev) {
		if (its_foreign_doorbell(dev_get_msi_domain(&pdev->dev))) {
			pci_dev_put(pdev);
			return true;
		}
	}
	return false;
}

int mk_dtb_add_pci(void *fdt)
{
	return mk_dtb_its_serves_pci() ? mk_dtb_add_its_proxy(fdt) : 0;
}
