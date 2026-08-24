// SPDX-License-Identifier: GPL-2.0-only
/*
 * multikernel.c - PCI root buses described by the instance device tree
 *
 * A spawn kernel boots without ACPI, so nothing on the machine tells it
 * where its PCI root buses are or which windows they decode. The kernel
 * that spawned it knows both exactly and wrote them into the instance
 * device tree, so the buses are created from that description: no
 * config space probing for topology, no fabricated windows, and device
 * probing below stays filtered by the instance's allowlist.
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
#include <linux/multikernel.h>

#include <asm/pci_x86.h>

static int __init mk_pci_scan_bridge(const struct mk_pci_host_bridge *desc)
{
	struct resource *res;
	struct pci_sysdata *sd;
	struct pci_bus *bus;
	LIST_HEAD(resources);
	int i;

	if (desc->domain &&
	    (!IS_ENABLED(CONFIG_PCI_DOMAINS) ||
	     !pci_mmconfig_lookup(desc->domain, desc->bus_start))) {
		pr_warn("PCI: bridge %04x:[bus %02x-%02x] needs ECAM, skipped\n",
			desc->domain, desc->bus_start, desc->bus_end);
		return -ENODEV;
	}

	sd = kzalloc_obj(*sd, GFP_KERNEL);
	res = kcalloc(desc->nr_windows + 1, sizeof(*res), GFP_KERNEL);
	if (!sd || !res) {
		kfree(sd);
		kfree(res);
		return -ENOMEM;
	}
	sd->node = NUMA_NO_NODE;
#ifdef CONFIG_PCI_DOMAINS
	sd->domain = desc->domain;
#endif

	res[0].start = desc->bus_start;
	res[0].end = desc->bus_end;
	res[0].flags = IORESOURCE_BUS;
	pci_add_resource(&resources, &res[0]);

	for (i = 0; i < desc->nr_windows; i++) {
		const struct mk_pci_bridge_window *win = &desc->windows[i];
		struct resource *r = &res[i + 1];
		u32 space = (win->flags >> 24) & 0x3;

		r->start = win->cpu_addr;
		r->end = win->cpu_addr + win->size - 1;
		r->flags = (space == 1) ? IORESOURCE_IO : IORESOURCE_MEM;
		if (space == 3)
			r->flags |= IORESOURCE_MEM_64;
		if (win->flags & 0x40000000)
			r->flags |= IORESOURCE_PREFETCH;
		r->name = "PCI Bus multikernel";
		pci_add_resource_offset(&resources, r,
					win->cpu_addr - win->pci_addr);
	}

	bus = pci_scan_root_bus(NULL, desc->bus_start, &pci_root_ops, sd,
				&resources);
	if (!bus) {
		pci_free_resource_list(&resources);
		kfree(res);
		kfree(sd);
		return -ENODEV;
	}

	pci_bus_add_devices(bus);
	pr_info("PCI: root bus %02x with %d windows from the instance device tree\n",
		desc->bus_start, desc->nr_windows);
	return 0;
}

#ifdef CONFIG_PCI_MMCONFIG
static void __init mk_pci_add_ecam(void)
{
	struct mk_pci_host_bridge *bridge;
	int added = 0;

	list_for_each_entry(bridge, &mk_pci_host_bridges, list) {
		u64 segment_base;

		if (!bridge->ecam_size ||
		    pci_mmconfig_lookup(bridge->domain, bridge->bus_start))
			continue;

		segment_base = bridge->ecam_base -
			       PCI_MMCFG_BUS_OFFSET(bridge->bus_start);
		if (!pci_mmconfig_add(bridge->domain, bridge->bus_start,
				      bridge->bus_end, segment_base)) {
			pr_warn("PCI: no memory for ECAM %04x:[bus %02x-%02x]\n",
				bridge->domain, bridge->bus_start,
				bridge->bus_end);
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
	struct mk_pci_host_bridge *bridge;
	int scanned = 0;

	mk_pci_add_ecam();

	list_for_each_entry(bridge, &mk_pci_host_bridges, list)
		if (!mk_pci_scan_bridge(bridge))
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
