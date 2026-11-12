// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * A spawn kernel's PCI devices are the nodes of its boot tree, and the
 * tree is their only record: a node without a status property is this
 * kernel's, status = "reserved" marks one lent to an instance of its
 * own, as the devicetree specification spells a device in use by another
 * entity. A device of this kernel is free to lend while none of its
 * drivers has it, as a host's pool device is. Lending and returning are
 * edits to the live tree, so every reader, the probe gate, the trees
 * served to user space and the boot tree of a nested spawn, sees the
 * same ownership.
 */

#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/multikernel.h>

#include "internal.h"

static struct device_node *mk_of_pci_child(struct device_node *bus, u8 busnr,
					   u8 devfn)
{
	struct device_node *np, *found;

	for_each_child_of_node(bus, np) {
		u32 reg;

		if (of_property_read_u32_index(np, "reg", 0, &reg))
			continue;
		if (((reg >> 16) & 0xff) == busnr && ((reg >> 8) & 0xff) == devfn)
			return np;
		found = mk_of_pci_child(np, busnr, devfn);
		if (found) {
			of_node_put(np);
			return found;
		}
	}

	return NULL;
}

/**
 * mk_of_pci_node - The node describing a PCI function in this kernel's tree
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function
 *
 * Returns: the node with a reference held, or NULL if the tree has none
 */
struct device_node *mk_of_pci_node(u16 domain, u8 bus, u8 devfn)
{
	struct device_node *bridge, *np;

	for_each_compatible_node(bridge, NULL, MK_PCI_HOST_BRIDGE) {
		u32 dom = 0;

		of_property_read_u32(bridge, "linux,pci-domain", &dom);
		if (dom != domain)
			continue;
		np = mk_of_pci_child(bridge, bus, devfn);
		if (np) {
			of_node_put(bridge);
			return np;
		}
	}

	return NULL;
}

static bool mk_of_pci_driven(struct device_node *np)
{
	struct device *dev = bus_find_device_by_of_node(&pci_bus_type, np);
	bool driven;

	if (!dev)
		return false;
	driven = mk_lease_driven(to_pci_dev(dev));
	put_device(dev);
	return driven;
}

/**
 * mk_of_pci_node_free - Whether a node's function is free to lend
 * @np: A node of this kernel's tree
 *
 * Returns: true when the function is not lent and no driver of this
 * kernel has it
 */
bool mk_of_pci_node_free(struct device_node *np)
{
	return of_device_is_available(np) && !mk_of_pci_driven(np);
}

/**
 * mk_of_pci_free - Whether a PCI function is this kernel's and free to lend
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function
 */
bool mk_of_pci_free(u16 domain, u8 bus, u8 devfn)
{
	struct device_node *np = mk_of_pci_node(domain, bus, devfn);
	bool free = np && mk_of_pci_node_free(np);

	of_node_put(np);
	return free;
}

/**
 * mk_of_pci_label - Copy the label of a PCI function in this kernel's tree
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function
 * @label: Buffer left untouched when the function has no label
 * @size: Size of @label
 */
void mk_of_pci_label(u16 domain, u8 bus, u8 devfn, char *label, size_t size)
{
	struct device_node *np = mk_of_pci_node(domain, bus, devfn);
	const char *name;

	if (np && !of_property_read_string(np, "label", &name))
		strscpy(label, name, size);
	of_node_put(np);
}

/**
 * mk_of_pci_set_lent - Record in the tree whether a device is lent out
 * @np: The device's node
 * @lent: true when handed to an instance, false when taken back
 */
static int mk_of_pci_set_lent(struct device_node *np, bool lent)
{
	struct of_changeset ocs;
	int ret;

	of_changeset_init(&ocs);
	ret = of_changeset_update_prop_string(&ocs, np, "status",
					      lent ? "reserved" : "okay");
	if (!ret)
		ret = of_changeset_apply(&ocs);
	of_changeset_destroy(&ocs);
	return ret;
}

/**
 * mk_of_pci_describe - Fill an instance's record of a device from its node
 * @np: The device's node
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function
 * @dev: The record to fill
 *
 * An instance keeps a record of what it was lent so its boot tree can
 * be written from it; the record is read off the node, never the other
 * way round.
 */
static void mk_of_pci_describe(struct device_node *np, u16 domain, u8 bus,
			       u8 devfn, struct mk_pci_device *dev)
{
	const char *label;
	u32 id;

	memset(dev, 0, sizeof(*dev));
	INIT_LIST_HEAD(&dev->list);
	dev->domain = domain;
	dev->bus = bus;
	dev->slot = PCI_SLOT(devfn);
	dev->func = PCI_FUNC(devfn);
	if (!of_property_read_u32(np, "vendor-id", &id))
		dev->vendor = id;
	if (!of_property_read_u32(np, "device-id", &id))
		dev->device = id;
	if (!of_property_read_string(np, "label", &label))
		strscpy(dev->label, label, sizeof(dev->label));
}

/**
 * mk_of_pci_lend - Hand a device of this kernel's tree to an instance
 * @instance: The instance receiving it
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function
 *
 * Returns: 0 on success, -ENOENT if the tree does not describe the device
 * or it is already lent, -EBUSY if a driver of this kernel has it, or a
 * negative error code
 */
int mk_of_pci_lend(struct mk_instance *instance, u16 domain, u8 bus, u8 devfn)
{
	struct device_node *np = mk_of_pci_node(domain, bus, devfn);
	struct mk_pci_device *dev;
	int ret;

	if (!np || !of_device_is_available(np)) {
		of_node_put(np);
		return -ENOENT;
	}
	if (mk_of_pci_driven(np)) {
		of_node_put(np);
		return -EBUSY;
	}

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		of_node_put(np);
		return -ENOMEM;
	}

	ret = mk_of_pci_set_lent(np, true);
	if (ret) {
		kfree(dev);
		of_node_put(np);
		return ret;
	}

	mk_of_pci_describe(np, domain, bus, devfn, dev);
	of_node_put(np);

	list_add_tail(&dev->list, &instance->pci_devices);
	instance->pci_device_count++;
	instance->pci_devices_valid = true;
	return 0;
}

/**
 * mk_of_pci_take_back - Mark a device an instance held as this kernel's again
 */
void mk_of_pci_take_back(u16 domain, u8 bus, u8 devfn)
{
	struct device_node *np = mk_of_pci_node(domain, bus, devfn);

	if (!np) {
		pr_warn("PCI device %04x:%02x:%02x.%x returned but not in the tree\n",
			domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
		return;
	}
	if (mk_of_pci_set_lent(np, false))
		pr_warn("PCI device %04x:%02x:%02x.%x returned but still marked reserved\n",
			domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
	of_node_put(np);
}
