// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * A PCI bus of this kernel as another kernel needs it to make the bus a
 * root bus of its own: the windows the bus decodes, and the ECAM window
 * through which it reaches the bus's config space once this kernel is
 * lost.
 */

#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/pci.h>
#include <linux/sizes.h>

#include "internal.h"

static u32 mk_pci_window_flags(const struct resource *res)
{
	u32 hi;

	if (res->flags & IORESOURCE_IO)
		hi = 0x01000000;
	else if ((res->flags & IORESOURCE_MEM_64) || res->end > U32_MAX)
		hi = 0x03000000;
	else
		hi = 0x02000000;

	if (res->flags & IORESOURCE_PREFETCH)
		hi |= 0x40000000;

	return hi;
}

static void mk_pci_add_window(struct mk_pci_bus_desc *desc,
			      const struct resource *res, resource_size_t offset)
{
	u64 pci_addr = res->start - offset;
	u64 size = resource_size(res);
	u64 cpu_addr;
	__be32 *c;

	if (resource_type(res) != IORESOURCE_IO &&
	    resource_type(res) != IORESOURCE_MEM)
		return;
	if (!size || (res->flags & IORESOURCE_UNSET))
		return;
	if (desc->nr_ranges + 7 > ARRAY_SIZE(desc->ranges)) {
		pr_warn("A PCI bus has more than %d windows, rest not described\n",
			MK_PCI_BUS_MAX_WINDOWS);
		return;
	}

	/*
	 * Where I/O space is memory mapped, an I/O resource holds logical
	 * port numbers, not the CPU address of the window.
	 */
	cpu_addr = res->start;
	if (resource_type(res) == IORESOURCE_IO &&
	    pci_pio_to_address(res->start) != (phys_addr_t)OF_BAD_ADDR)
		cpu_addr = pci_pio_to_address(res->start);

	c = &desc->ranges[desc->nr_ranges];
	c[0] = cpu_to_be32(mk_pci_window_flags(res));
	c[1] = cpu_to_be32(upper_32_bits(pci_addr));
	c[2] = cpu_to_be32(lower_32_bits(pci_addr));
	c[3] = cpu_to_be32(upper_32_bits(cpu_addr));
	c[4] = cpu_to_be32(lower_32_bits(cpu_addr));
	c[5] = cpu_to_be32(upper_32_bits(size));
	c[6] = cpu_to_be32(lower_32_bits(size));
	desc->nr_ranges += 7;
}

/*
 * What @bus decodes: the windows of its host bridge for a root bus, of
 * the bridge above it otherwise. Either covers the BARs of every device
 * on it.
 */
static void mk_pci_bus_windows(struct pci_bus *bus, struct mk_pci_bus_desc *desc)
{
	struct resource_entry *entry;
	struct pci_bus_region region;
	struct resource *res;

	if (pci_is_root_bus(bus)) {
		resource_list_for_each_entry(entry,
					     &pci_find_host_bridge(bus)->windows)
			mk_pci_add_window(desc, entry->res, entry->offset);
		return;
	}

	pci_bus_for_each_resource(bus, res) {
		if (!res || !res->flags)
			continue;
		pcibios_resource_to_bus(bus, &region, res);
		mk_pci_add_window(desc, res, res->start - region.start);
	}
}

/**
 * mk_pci_ecam_window - The window of a bus in an ECAM region
 * @res: The region
 * @first: The bus at the start of @res
 * @busnr: The bus
 *
 * Returns: the physical address of the bus's 1MB window, or 0 if @res
 * does not cover it
 */
u64 mk_pci_ecam_window(const struct resource *res, u64 first,
		       unsigned int busnr)
{
	u64 offset;

	if (busnr < first)
		return 0;

	offset = (busnr - first) << 20;
	if (offset + SZ_1M > resource_size(res))
		return 0;

	return res->start + offset;
}

/**
 * mk_arch_pci_bus_ecam - The ECAM window of a bus firmware other than a
 * device tree describes
 * @bus: A bus of this kernel
 *
 * Returns: the physical address of the bus's 1MB window, or 0 if none
 */
u64 __weak mk_arch_pci_bus_ecam(struct pci_bus *bus)
{
	return 0;
}

/* Bridges whose reg is an ECAM region, read with the generic accessors */
static const struct of_device_id mk_pci_ecam_bridges[] = {
	{ .compatible = "pci-host-ecam-generic" },
	{ .compatible = MK_PCI_HOST_BRIDGE },
	{ }
};

/*
 * The ECAM window of a bus, for a spawn kernel to reach it directly once
 * this kernel is lost.
 */
static u64 mk_pci_bus_ecam(struct pci_bus *bus)
{
	struct device_node *np = pci_bus_to_OF_node(pci_find_host_bridge(bus)->bus);
	struct resource res;
	u32 first = 0;

	if (!np || !of_match_node(mk_pci_ecam_bridges, np) ||
	    of_address_to_resource(np, 0, &res))
		return mk_arch_pci_bus_ecam(bus);

	of_property_read_u32_index(np, "bus-range", 0, &first);
	return mk_pci_ecam_window(&res, first, bus->number);
}

/**
 * mk_pci_bus_describe - What a kernel needs to make @bus a root bus of its own
 * @bus: A bus of this kernel
 * @desc: Filled with the windows of @bus and its ECAM window
 *
 * The same description goes into an instance's boot tree and into the
 * message that hands it a device on a bus it did not boot with.
 */
void mk_pci_bus_describe(struct pci_bus *bus, struct mk_pci_bus_desc *desc)
{
	memset(desc, 0, sizeof(*desc));
	desc->ecam = mk_pci_bus_ecam(bus);
	mk_pci_bus_windows(bus, desc);
}
