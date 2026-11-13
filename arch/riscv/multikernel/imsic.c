// SPDX-License-Identifier: GPL-2.0-only
/*
 * MSIs of an instance's PCI devices, taken in its own harts' IMSIC files.
 *
 * An IMSIC has one interrupt file per hart and an MSI is a write of an
 * identity into the file of the hart it targets, so a spawn composes its
 * MSI messages itself and nothing is shared that the host would have to
 * proxy: the spawn's IMSIC driver allocates identities only in the files
 * of the harts it brings online, and the host's has its own harts' files.
 *
 * The spawn gets the host's supervisor level IMSIC node. Its
 * interrupts-extended names every hart's local controller, and every hart
 * is in the spawn's /cpus, so the driver finds them all and leaves alone
 * the ones that never come online.
 */

#define pr_fmt(fmt) "mk_imsic: " fmt

#include <linux/irqdomain.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/pci.h>

#include <asm/csr.h>

#include "internal.h"

#define MK_IMSIC_COMPATIBLE	"riscv,imsics"
#define MK_IMSIC_MAX_REG	16

/* The M-level IMSIC is firmware's; the one for S-mode signals RV_IRQ_EXT */
static struct device_node *mk_of_imsic_node(void)
{
	struct of_phandle_args parent;
	struct device_node *np;
	bool smode;

	for_each_compatible_node(np, NULL, MK_IMSIC_COMPATIBLE) {
		if (!of_device_is_available(np) ||
		    of_irq_parse_one(np, 0, &parent))
			continue;
		smode = parent.args_count == 1 && parent.args[0] == RV_IRQ_EXT;
		of_node_put(parent.np);
		if (smode)
			return np;
	}
	return NULL;
}

/*
 * Under the root, with reg translated to CPU addresses: the host's node
 * can sit on a bus the instance tree does not have.
 */
static int mk_dtb_copy_device(void *fdt, struct device_node *np)
{
	u64 reg[2 * MK_IMSIC_MAX_REG];
	struct property *pp;
	struct resource res;
	int node, nr = 0, ret;

	node = fdt_add_subnode(fdt, 0, np->full_name);
	if (node < 0)
		return node;

	for_each_property_of_node(np, pp) {
		if (!strcmp(pp->name, "name") || !strcmp(pp->name, "reg") ||
		    !strcmp(pp->name, "ranges"))
			continue;
		ret = fdt_setprop(fdt, node, pp->name, pp->value, pp->length);
		if (ret)
			return ret;
	}

	while (nr < MK_IMSIC_MAX_REG && !of_address_to_resource(np, nr, &res)) {
		reg[2 * nr] = res.start;
		reg[2 * nr + 1] = resource_size(&res);
		nr++;
	}
	return mk_dtb_set_reg(fdt, node, reg, nr);
}

int mk_dtb_add_imsic(void *fdt)
{
	struct device_node *np = mk_of_imsic_node();
	int ret;

	if (!np)
		return 0;
	ret = mk_dtb_copy_device(fdt, np);
	of_node_put(np);
	return ret;
}

/*
 * Every bus of an instance is one of pcifront's, those it finds at boot
 * and those added later alike, so the IMSIC is made the MSI domain of
 * each bridge here rather than through an msi-parent bus by bus. At boot
 * the buses come up before the IMSIC driver has bound and made its
 * domain, and wait for it.
 */
int mk_arch_pcifront_prepare(struct pci_host_bridge *bridge, int domain)
{
	struct device_node *np = mk_of_imsic_node();
	struct irq_domain *msi_domain;

	if (!np) {
		pr_warn_once("No IMSIC, the PCI devices of this kernel get no interrupts\n");
		return 0;
	}

	msi_domain = irq_find_matching_fwnode(of_fwnode_handle(np),
					      DOMAIN_BUS_PCI_MSI);
	of_node_put(np);
	if (!msi_domain)
		return -EPROBE_DEFER;

	dev_set_msi_domain(&bridge->dev, msi_domain);
	return 0;
}
