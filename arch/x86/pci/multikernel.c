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
 * Config cycles use the standard port 0xCF8 mechanism, which reaches
 * every bus in domain 0. Bridges outside domain 0 would need an ECAM
 * window, which only ACPI's MCFG describes, and are skipped until the
 * manifest carries that too.
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

	if (desc->domain) {
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

int __init pci_multikernel_init(void)
{
	struct mk_pci_host_bridge *bridge;
	int scanned = 0;

	list_for_each_entry(bridge, &mk_pci_host_bridges, list)
		if (!mk_pci_scan_bridge(bridge))
			scanned++;

	/* Nothing described: legacy probing of bus 0 is all there is */
	return scanned ? 0 : 1;
}
