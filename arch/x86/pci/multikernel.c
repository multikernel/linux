// SPDX-License-Identifier: GPL-2.0-only
/*
 * multikernel.c - PCI root buses described by the instance device tree
 *
 * A spawn kernel boots without ACPI, so nothing on the machine tells it
 * where its PCI root buses are or which windows they decode. The kernel
 * that spawned it knows both exactly and wrote them into the instance
 * device tree, which is this kernel's boot tree, so the buses are
 * created from its host bridge nodes with the devicetree PCI binding:
 * no config space probing for topology, no fabricated windows, and
 * every bus and device below binds to its node, so device probing is
 * filtered by the tree.
 *
 * A bridge whose description carries an ECAM window gets that window
 * installed the way a Jailhouse guest installs its hypervisor-provided
 * one: pci_mmconfig_add() plus pci_mmcfg_arch_init(), with none of the
 * firmware-mistrust checks a hot-added ACPI bridge goes through, since
 * the spawning kernel is the authority here. That reaches any domain
 * and extended config space; a bridge without one falls back to the
 * standard port 0xCF8 mechanism, which reaches domain 0 only.
 */
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/multikernel.h>

#include <asm/pci_x86.h>

#define MK_PCI_HOST_BRIDGE	"multikernel,pci-host-bridge"

static int __init mk_pci_domain(struct device_node *np)
{
	u32 domain;

	return of_property_read_u32(np, "linux,pci-domain", &domain) ? 0 : domain;
}

static int __init mk_pci_bus_range(struct device_node *np, struct resource *res)
{
	u32 range[2];

	if (of_property_read_u32_array(np, "bus-range", range, 2))
		return -EINVAL;

	res->start = range[0];
	res->end = range[1];
	res->flags = IORESOURCE_BUS;
	res->name = np->full_name;
	return 0;
}

static int __init mk_pci_scan_bridge(struct device_node *np)
{
	struct of_pci_range_parser parser;
	struct of_pci_range range;
	struct resource *bus_res;
	struct pci_sysdata *sd;
	struct pci_bus *bus;
	LIST_HEAD(resources);
	int domain = mk_pci_domain(np);
	int nr_windows = 0;

	bus_res = kzalloc_obj(*bus_res, GFP_KERNEL);
	sd = kzalloc_obj(*sd, GFP_KERNEL);
	if (!bus_res || !sd)
		goto err;

	if (mk_pci_bus_range(np, bus_res)) {
		pr_warn("PCI: %pOF has no valid bus-range, skipped\n", np);
		goto err;
	}

	if (domain &&
	    (!IS_ENABLED(CONFIG_PCI_DOMAINS) ||
	     !pci_mmconfig_lookup(domain, bus_res->start))) {
		pr_warn("PCI: bridge %04x:[bus %02llx-%02llx] needs ECAM, skipped\n",
			domain, (u64)bus_res->start, (u64)bus_res->end);
		goto err;
	}

	sd->node = NUMA_NO_NODE;
#ifdef CONFIG_PCI_DOMAINS
	sd->domain = domain;
#endif
	pci_add_resource(&resources, bus_res);

	if (of_pci_range_parser_init(&parser, np) == 0) {
		for_each_of_pci_range(&parser, &range) {
			struct resource *res;

			if (range.flags & IORESOURCE_TYPE_BITS &&
			    !(range.flags & (IORESOURCE_IO | IORESOURCE_MEM)))
				continue;

			res = kzalloc_obj(*res, GFP_KERNEL);
			if (!res)
				goto err;
			if (of_pci_range_to_resource(&range, np, res)) {
				kfree(res);
				continue;
			}
			res->name = "PCI Bus multikernel";
			pci_add_resource_offset(&resources, res,
						res->start - range.pci_addr);
			nr_windows++;
		}
	}

	bus = pci_scan_root_bus(NULL, bus_res->start, &pci_root_ops, sd,
				&resources);
	if (!bus)
		goto err;

	pci_bus_add_devices(bus);
	pr_info("PCI: root bus %04x:%02llx with %d windows from %pOF\n",
		domain, (u64)bus_res->start, nr_windows, np);
	return 0;

err:
	pci_free_resource_list(&resources);
	kfree(bus_res);
	kfree(sd);
	return -ENODEV;
}

#ifdef CONFIG_PCI_MMCONFIG
static void __init mk_pci_add_ecam(void)
{
	struct device_node *np;
	int added = 0;

	for_each_compatible_node(np, NULL, MK_PCI_HOST_BRIDGE) {
		struct resource bus_res, ecam;
		int domain = mk_pci_domain(np);
		u64 segment_base;

		if (mk_pci_bus_range(np, &bus_res) ||
		    of_address_to_resource(np, 0, &ecam) ||
		    pci_mmconfig_lookup(domain, bus_res.start))
			continue;

		segment_base = ecam.start - PCI_MMCFG_BUS_OFFSET(bus_res.start);
		if (!pci_mmconfig_add(domain, bus_res.start, bus_res.end,
				      segment_base)) {
			pr_warn("PCI: no memory for ECAM %04x:[bus %02llx-%02llx]\n",
				domain, (u64)bus_res.start, (u64)bus_res.end);
			continue;
		}
		added++;
	}

	if (added && !pci_mmcfg_arch_init())
		pr_warn("PCI: ECAM mapping failed, extended config space and domains beyond 0 unavailable\n");
}
#else
static void __init mk_pci_add_ecam(void)
{
}
#endif

int __init pci_multikernel_init(void)
{
	struct device_node *np;
	int scanned = 0;

	mk_pci_add_ecam();

	for_each_compatible_node(np, NULL, MK_PCI_HOST_BRIDGE)
		if (!mk_pci_scan_bridge(np))
			scanned++;

	if (!scanned)
		pr_info("PCI: no host bridges described, no PCI for this instance\n");

	/*
	 * The instance device tree is the sole source of PCI topology:
	 * never fall back to probing bus 0, which would register a
	 * phantom root bus with fabricated windows.
	 */
	return 0;
}
