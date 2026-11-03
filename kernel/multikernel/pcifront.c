// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * The PCI buses of a spawn kernel, with config space reached through
 * the kernel that lent the devices (pciback.c).
 *
 * The spawn's tree describes each bus that holds a device of its own as
 * a root bus with only those devices on it. Config space accesses on
 * these buses are requests over the message ring: the lending kernel
 * checks that the function was lent, filters the access and makes it.
 * This kernel never generates a config cycle itself, so it cannot touch
 * a function it was not given, nor share a config mechanism with
 * another kernel.
 *
 * The PCI core calls config accessors under its raw lock with interrupts
 * off, so the wait for an answer polls the ring. Config space is only
 * touched to probe, reset, power manage and recover a device, and a
 * running device costs next to none: its BARs, its DMA and its MSIs
 * are direct, and only the rare masking of a plain MSI asks.
 *
 * A spawn outlives a host that crashes. Its devices keep running, but a
 * dead host answers nothing: a request that times out fails like an
 * access to an absent function, and nothing more. Whether the host is
 * dead is not decided here. User space decides, and acts on it by
 * fencing the host; once the fence has confirmed every CPU of the host
 * parked, accesses go straight to the ECAM window of the bus, the reg of
 * its node, which is mapped at boot and unused until then, or fail at
 * once where there is none. That is safe only because a fenced host no
 * longer generates config cycles itself; the 0xCF8 ports, which other
 * surviving kernels may use, are never touched. With the host's filter
 * gone, only the functions of this kernel's tree answer: a scan finds
 * neither the bridges above nor the functions beside them.
 *
 * Once the host is fenced, nobody is left to hand this kernel a
 * function, so it takes the host's functions itself, as the host
 * described them when it booted this kernel: their IDs in the host tree
 * user space wrote, their buses in multikernel,pci-buses.
 */

#define pr_fmt(fmt) "mk_pcifront: " fmt

#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include "internal.h"

#define MK_PCIFRONT_TIMEOUT_US	(10 * USEC_PER_MSEC)

/* The private part of each host bridge, one per bus */
struct mk_pcifront_bus {
	struct list_head list;
	u16 domain;
	u8 busnr;
	phys_addr_t ecam_phys;
	void __iomem *ecam;	/* For when the host is fenced, or NULL */
	DECLARE_BITMAP(devfns, 256);	/* The functions of this kernel's tree */
};

/*
 * Only ever added to, under the PCI rescan lock. Lookups come from config
 * accessors with interrupts off and take no lock, so buses are published
 * with RCU.
 */
static LIST_HEAD(mk_pcifront_buses);

static bool mk_pcifront_direct_access;

static struct mk_pcifront_bus *mk_pcifront_of(struct pci_bus *bus)
{
	return pci_host_bridge_priv(to_pci_host_bridge(bus->bridge));
}

/* One request to the host. Returns 0 once it answered, with @result set */
static int mk_pcifront_ask(struct mk_pcifront_bus *fb, unsigned int devfn,
			   int where, int size, u32 *val, u32 subtype,
			   int *result)
{
	struct mk_pci_cfg_payload req = {
		.seq = mk_request_seq(),
		.sender_instance_id = mk_self->id,
		.domain = fb->domain,
		.bus = fb->busnr,
		.devfn = devfn,
		.where = where,
		.size = size,
		.val = *val,
	};
	struct mk_pci_cfg_payload ack;
	int ret;

	ret = mk_request_sync(host_instance, MK_MSG_PCI, subtype, req.seq,
			      &req, sizeof(req), &ack, sizeof(ack),
			      MK_PCIFRONT_TIMEOUT_US);
	if (ret)
		return ret;

	if (subtype == MK_PCI_CFG_READ)
		*val = ack.val;
	*result = ack.result;
	return 0;
}

static int mk_pcifront_direct(struct mk_pcifront_bus *fb, unsigned int devfn,
			      int where, int size, u32 *val, u32 subtype)
{
	void __iomem *addr;

	if (!fb->ecam || !test_bit(devfn, fb->devfns)) {
		if (subtype == MK_PCI_CFG_READ)
			*val = ~0U;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	addr = fb->ecam + (devfn << 12) + where;
	if (subtype == MK_PCI_CFG_READ) {
		if (size == 1)
			*val = readb(addr);
		else if (size == 2)
			*val = readw(addr);
		else
			*val = readl(addr);
	} else {
		if (size == 1)
			writeb(*val, addr);
		else if (size == 2)
			writew(*val, addr);
		else
			writel(*val, addr);
	}
	return PCIBIOS_SUCCESSFUL;
}

/**
 * mk_pcifront_host_fenced - The host can no longer touch config space
 *
 * Called once a fence has confirmed every CPU of the host parked. From
 * then on this kernel reaches the config space of its devices itself.
 */
void mk_pcifront_host_fenced(void)
{
	struct mk_pcifront_bus *fb;
	bool direct = false;

	if (READ_ONCE(mk_pcifront_direct_access) ||
	    list_empty(&mk_pcifront_buses))
		return;
	WRITE_ONCE(mk_pcifront_direct_access, true);

	rcu_read_lock();
	list_for_each_entry_rcu(fb, &mk_pcifront_buses, list)
		direct |= !!fb->ecam;
	rcu_read_unlock();
	pr_info("Host fenced: config space is reached %s\n",
		direct ? "directly through ECAM" : "nowhere");
}

static int mk_pcifront_access(struct mk_pcifront_bus *fb, unsigned int devfn,
			      int where, int size, u32 *val, u32 subtype)
{
	int result, ret;

	if (READ_ONCE(mk_pcifront_direct_access))
		return mk_pcifront_direct(fb, devfn, where, size, val, subtype);

	ret = mk_pcifront_ask(fb, devfn, where, size, val, subtype, &result);
	if (!ret)
		return result;

	pr_err_ratelimited("%04x:%02x:%02x.%x: no answer for config offset %#x: %d\n",
			   fb->domain, fb->busnr, PCI_SLOT(devfn),
			   PCI_FUNC(devfn), where, ret);
	if (subtype == MK_PCI_CFG_READ)
		*val = ~0U;
	return PCIBIOS_DEVICE_NOT_FOUND;
}

static int mk_pcifront_read(struct pci_bus *bus, unsigned int devfn,
			    int where, int size, u32 *val)
{
	return mk_pcifront_access(mk_pcifront_of(bus), devfn, where, size, val,
				  MK_PCI_CFG_READ);
}

static int mk_pcifront_write(struct pci_bus *bus, unsigned int devfn,
			     int where, int size, u32 val)
{
	return mk_pcifront_access(mk_pcifront_of(bus), devfn, where, size,
				  &val, MK_PCI_CFG_WRITE);
}

/**
 * mk_pcifront_config - Config space access by address, outside the PCI core
 * @domain: PCI domain
 * @bus: Bus number
 * @devfn: Device and function
 * @where: Offset in config space
 * @size: 1, 2 or 4 bytes
 * @val: Value to write, or where the value read goes
 * @write: Whether to write
 *
 * For architecture code that reaches config space by address, such as
 * the x86 raw accessors. Only the buses of this kernel's tree exist.
 *
 * Returns: a PCIBIOS_* code, or -ENODEV for a bus this kernel does not have
 */
int mk_pcifront_config(unsigned int domain, unsigned int bus,
		       unsigned int devfn, int where, int size, u32 *val,
		       bool write)
{
	struct mk_pcifront_bus *fb;
	int ret = -ENODEV;

	rcu_read_lock();
	list_for_each_entry_rcu(fb, &mk_pcifront_buses, list) {
		if (fb->domain == domain && fb->busnr == bus) {
			ret = mk_pcifront_access(fb, devfn, where, size, val,
						 write ? MK_PCI_CFG_WRITE :
							 MK_PCI_CFG_READ);
			break;
		}
	}
	rcu_read_unlock();

	if (ret == -ENODEV && !write)
		*val = ~0U;
	return ret;
}

/**
 * mk_pcifront_ecam - The ECAM window of a bus of this kernel's tree
 * @domain: PCI domain
 * @bus: Bus number
 *
 * Passed on to the tree of an instance of this kernel, for when both its
 * host and this kernel are fenced.
 *
 * Returns: the physical address of the bus's 1MB window, or 0 if none
 */
u64 mk_pcifront_ecam(unsigned int domain, unsigned int bus)
{
	struct mk_pcifront_bus *fb;
	u64 ecam = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(fb, &mk_pcifront_buses, list) {
		if (fb->domain == domain && fb->busnr == bus) {
			ecam = fb->ecam ? fb->ecam_phys : 0;
			break;
		}
	}
	rcu_read_unlock();
	return ecam;
}

/* Mapped now: nothing can be mapped under the PCI core's lock, where it is used */
static void mk_pcifront_map_ecam(struct device_node *np,
					struct mk_pcifront_bus *fb)
{
	struct resource ecam;

	if (of_address_to_resource(np, 0, &ecam))
		return;

	if (resource_size(&ecam) < SZ_1M) {
		pr_warn("%pOF: ECAM window %pR is too small\n", np, &ecam);
		return;
	}

	fb->ecam = ioremap(ecam.start, SZ_1M);
	if (fb->ecam)
		fb->ecam_phys = ecam.start;
}

static struct pci_ops mk_pcifront_ops = {
	.read = mk_pcifront_read,
	.write = mk_pcifront_write,
};

/**
 * mk_arch_pcifront_prepare - Arch part of setting up a root bus
 * @bridge: The host bridge, not yet registered
 * @domain: Its PCI domain
 *
 * An architecture whose PCI code expects its own sysdata on a root bus
 * provides it here.
 */
int __weak mk_arch_pcifront_prepare(struct pci_host_bridge *bridge, int domain)
{
	return 0;
}

static void mk_pcifront_add_windows(struct device_node *np,
				    struct pci_host_bridge *bridge)
{
	struct of_pci_range_parser parser;
	struct of_pci_range range;
	struct resource *res;

	if (of_pci_range_parser_init(&parser, np))
		return;

	for_each_of_pci_range(&parser, &range) {
		if (!(range.flags & (IORESOURCE_IO | IORESOURCE_MEM)))
			continue;

		res = kzalloc_obj(*res, GFP_KERNEL);
		if (!res)
			return;
		if (of_pci_range_to_resource(&range, np, res)) {
			kfree(res);
			continue;
		}
		res->name = "PCI Bus multikernel";
		pci_add_resource_offset(&bridge->windows, res,
					res->start - range.pci_addr);
	}
}

static int mk_pcifront_add_bus(struct device_node *np)
{
	struct pci_host_bridge *bridge;
	struct resource_entry *entry;
	struct mk_pcifront_bus *fb;
	struct device_node *child;
	struct resource *bus_res;
	u32 domain = 0, range[2];
	int devfn, ret;

	of_property_read_u32(np, "linux,pci-domain", &domain);
	if (of_property_read_u32_array(np, "bus-range", range, 2)) {
		pr_warn("%pOF has no bus-range, skipped\n", np);
		return -EINVAL;
	}

	bridge = pci_alloc_host_bridge(sizeof(*fb));
	bus_res = kzalloc_obj(*bus_res, GFP_KERNEL);
	if (!bridge || !bus_res) {
		ret = -ENOMEM;
		goto err;
	}

	fb = pci_host_bridge_priv(bridge);
	fb->domain = domain;
	fb->busnr = range[0];
	mk_pcifront_map_ecam(np, fb);
	for_each_child_of_node(np, child) {
		devfn = of_pci_get_devfn(child);
		if (devfn >= 0)
			set_bit(devfn, fb->devfns);
	}

	bus_res->start = range[0];
	bus_res->end = range[1];
	bus_res->flags = IORESOURCE_BUS;
	bus_res->name = np->full_name;
	pci_add_resource(&bridge->windows, bus_res);
	mk_pcifront_add_windows(np, bridge);

	/* The bus binds to its node by identity, not by a bus number search */
	bridge->dev.of_node = of_node_get(np);
	bridge->busnr = range[0];
	bridge->ops = &mk_pcifront_ops;
	if (IS_ENABLED(CONFIG_PCI_DOMAINS_GENERIC))
		bridge->domain_nr = domain;

	ret = mk_arch_pcifront_prepare(bridge, domain);
	if (ret)
		goto err_node;

	ret = pci_scan_root_bus_bridge(bridge);
	if (ret)
		goto err_node;

	/* A bus scan skips the slot of a function 0 that is not ours */
	for_each_set_bit(devfn, fb->devfns, 256)
		pci_scan_single_device(bridge->bus, devfn);

	/* The host assigned the BARs and keeps them, so take them as they are */
	pci_bus_claim_resources(bridge->bus);

	list_add_tail_rcu(&fb->list, &mk_pcifront_buses);
	pci_bus_add_devices(bridge->bus);
	pr_info("Root bus %04x:%02x from %pOF\n", domain, range[0], np);
	return 0;

err_node:
	of_node_put(np);
	resource_list_for_each_entry(entry, &bridge->windows)
		kfree(entry->res);
	pci_free_host_bridge(bridge);
	return ret;
err:
	kfree(bus_res);
	if (bridge)
		pci_free_host_bridge(bridge);
	return ret;
}

static struct device_node *mk_pcifront_bus_node(u16 domain, u8 busnr)
{
	struct device_node *np;
	u32 d, range[2];

	for_each_compatible_node(np, NULL, MK_PCI_HOST_BRIDGE) {
		d = 0;
		of_property_read_u32(np, "linux,pci-domain", &d);
		if (d == domain &&
		    !of_property_read_u32_array(np, "bus-range", range, 2) &&
		    range[0] == busnr)
			return np;
	}
	return NULL;
}

/* A bus node as the host writes them into a boot tree */
static struct device_node *
mk_pcifront_new_bus_node(struct of_changeset *cs, u16 domain, u8 busnr,
			 const struct mk_pci_bus_desc *desc)
{
	u32 ranges[ARRAY_SIZE(desc->ranges)];
	u32 bus_range[2] = { busnr, busnr };
	u32 reg[4] = {
		upper_32_bits(desc->ecam), lower_32_bits(desc->ecam),
		0, SZ_1M,
	};
	struct device_node *np;
	unsigned int i, nr;
	char name[16];
	int ret;

	snprintf(name, sizeof(name), "pci@%x,%x", domain, busnr);
	np = of_changeset_create_node(cs, of_root, name);
	if (!np)
		return ERR_PTR(-ENOMEM);

	nr = min_t(u32, desc->nr_ranges, ARRAY_SIZE(ranges));
	for (i = 0; i < nr; i++)
		ranges[i] = be32_to_cpu(desc->ranges[i]);

	ret = of_changeset_add_prop_string(cs, np, "compatible",
					   MK_PCI_HOST_BRIDGE);
	if (!ret)
		ret = of_changeset_add_prop_string(cs, np, "device_type", "pci");
	if (!ret)
		ret = of_changeset_add_prop_u32(cs, np, "#address-cells", 3);
	if (!ret)
		ret = of_changeset_add_prop_u32(cs, np, "#size-cells", 2);
	if (!ret)
		ret = of_changeset_add_prop_u32(cs, np, "linux,pci-domain", domain);
	if (!ret)
		ret = of_changeset_add_prop_u32_array(cs, np, "bus-range",
						      bus_range, 2);
	if (!ret && desc->ecam)
		ret = of_changeset_add_prop_u32_array(cs, np, "reg", reg, 4);
	if (!ret && nr)
		ret = of_changeset_add_prop_u32_array(cs, np, "ranges", ranges, nr);
	return ret ? ERR_PTR(ret) : np;
}

static int mk_pcifront_add_node(u16 domain, u8 busnr, u8 devfn, u16 vendor,
				u16 device, const struct mk_pci_bus_desc *desc,
				struct device_node **bus_np, bool *new_bus)
{
	u32 reg[5] = { (u32)busnr << 16 | (u32)devfn << 8 };
	struct device_node *np;
	struct of_changeset *cs;
	char name[16];
	int ret;

	*bus_np = mk_pcifront_bus_node(domain, busnr);
	*new_bus = !*bus_np;
	if (*bus_np) {
		np = of_pci_find_child_device(*bus_np, devfn);
		of_node_put(np);
		if (np)
			return 0;
	}

	cs = kzalloc_obj(*cs, GFP_KERNEL);
	if (!cs)
		return -ENOMEM;
	of_changeset_init(cs);

	if (*new_bus) {
		*bus_np = mk_pcifront_new_bus_node(cs, domain, busnr, desc);
		if (IS_ERR(*bus_np)) {
			ret = PTR_ERR(*bus_np);
			*bus_np = NULL;
			goto err;
		}
	}

	snprintf(name, sizeof(name), "pci@%x,%x", PCI_SLOT(devfn), PCI_FUNC(devfn));
	np = of_changeset_create_node(cs, *bus_np, name);
	ret = np ? 0 : -ENOMEM;
	if (!ret)
		ret = of_changeset_add_prop_u32_array(cs, np, "reg", reg, 5);
	if (!ret)
		ret = of_changeset_add_prop_u32(cs, np, "vendor-id", vendor);
	if (!ret)
		ret = of_changeset_add_prop_u32(cs, np, "device-id", device);
	if (!ret)
		ret = of_changeset_apply(cs);
	if (ret)
		goto err;

	/* The nodes are this kernel's for good: the changeset is never reverted */
	if (*new_bus)
		of_node_get(*bus_np);
	return 0;

err:
	if (!*new_bus)
		of_node_put(*bus_np);
	*bus_np = NULL;
	of_changeset_destroy(cs);
	kfree(cs);
	return ret;
}

static int mk_pcifront_scan_function(u16 domain, u8 busnr, u8 devfn)
{
	struct resource *r;
	struct pci_bus *bus;
	struct pci_dev *pdev;
	int i;

	bus = pci_find_bus(domain, busnr);
	if (!bus)
		return -ENODEV;

	set_bit(devfn, mk_pcifront_of(bus)->devfns);
	pdev = pci_scan_single_device(bus, devfn);
	if (!pdev)
		return -ENODEV;

	pci_dev_for_each_resource(pdev, r, i) {
		if (i < PCI_BRIDGE_RESOURCES && r->flags && !r->parent)
			pci_claim_resource(pdev, i);
	}
	pci_bus_add_device(pdev);
	return 0;
}

/**
 * mk_pcifront_add_function - Take a function handed over while running
 * @domain: PCI domain
 * @bus: Bus number
 * @devfn: Device and function
 * @vendor: Its vendor ID
 * @device: Its device ID
 * @desc: The bus it sits on, as the host describes it
 *
 * Gives the function a node in this kernel's tree, and its bus one too
 * when the tree has none, the way the host would have described them at
 * boot, then makes the bus a root bus or scans the function on it.
 *
 * Returns: 0 once the function is on a bus of this kernel, or -errno
 */
int mk_pcifront_add_function(u16 domain, u8 bus, u8 devfn, u16 vendor,
			     u16 device, const struct mk_pci_bus_desc *desc)
{
	struct device_node *bus_np;
	struct pci_bus *pbus;
	struct pci_dev *pdev;
	bool new_bus;
	int ret;

	if (!mk_manifest_phys() || !host_instance)
		return -ENODEV;

	pci_lock_rescan_remove();
	pbus = pci_find_bus(domain, bus);
	pdev = pbus ? pci_get_slot(pbus, devfn) : NULL;
	if (pdev) {
		pci_dev_put(pdev);
		ret = 0;
		goto unlock;
	}

	ret = mk_pcifront_add_node(domain, bus, devfn, vendor, device, desc,
				   &bus_np, &new_bus);
	if (ret)
		goto unlock;

	if (new_bus)
		ret = mk_pcifront_add_bus(bus_np);
	else
		ret = mk_pcifront_scan_function(domain, bus, devfn);
	of_node_put(bus_np);
unlock:
	pci_unlock_rescan_remove();
	return ret;
}

/* The IDs of a function, from the host tree user space armed this kernel with */
static int mk_pcifront_host_ids(u16 domain, u8 bus, u8 devfn, u16 *vendor,
				u16 *device)
{
	struct device_node *devices, *np;
	const char *id;
	char want[16];
	u32 v, d;
	int ret = -ENOENT;

	devices = of_find_node_by_path("/chosen/multikernel,host-tree/devices");
	if (!devices)
		return -ENOENT;

	snprintf(want, sizeof(want), "%04x:%02x:%02x.%x", domain, bus,
		 PCI_SLOT(devfn), PCI_FUNC(devfn));
	for_each_child_of_node(devices, np) {
		if (of_property_read_string(np, "pci-id", &id) || strcmp(id, want))
			continue;
		if (!of_property_read_u32(np, "vendor-id", &v) &&
		    !of_property_read_u32(np, "device-id", &d)) {
			*vendor = v;
			*device = d;
			ret = 0;
		}
		of_node_put(np);
		break;
	}
	of_node_put(devices);
	return ret;
}

/* A bus as the host described it in multikernel,pci-buses */
static int mk_pcifront_host_bus(u16 domain, u8 bus, struct mk_pci_bus_desc *desc)
{
	struct device_node *np;
	const __be32 *ranges;
	char path[48];
	u32 reg[4];
	int len;

	snprintf(path, sizeof(path), "/chosen/multikernel,pci-buses/pci@%x,%x",
		 domain, bus);
	np = of_find_node_by_path(path);
	if (!np)
		return -ENOENT;

	memset(desc, 0, sizeof(*desc));
	if (!of_property_read_u32_array(np, "reg", reg, 4))
		desc->ecam = (u64)reg[0] << 32 | reg[1];
	ranges = of_get_property(np, "ranges", &len);
	if (ranges) {
		desc->nr_ranges = min_t(u32, len / sizeof(*ranges),
					ARRAY_SIZE(desc->ranges));
		memcpy(desc->ranges, ranges, desc->nr_ranges * sizeof(*ranges));
	}
	of_node_put(np);
	return 0;
}

/**
 * mk_pcifront_adopt_function - Take a function of the fenced host
 * @domain: PCI domain
 * @bus: Bus number
 * @devfn: Device and function
 *
 * Before the fence the function is the host's, and its config space is
 * out of reach: only the host may lend it.
 *
 * Returns: 0 once the function is on a bus of this kernel, -EPERM while
 * the host is not fenced, -ENOENT when the host did not describe it, or
 * another -errno
 */
int mk_pcifront_adopt_function(u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_bus_desc *desc;
	struct pci_dev *pdev;
	u16 vendor, device;
	int ret;

	pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
	if (pdev) {
		pci_dev_put(pdev);
		return 0;
	}
	if (!READ_ONCE(mk_pcifront_direct_access))
		return -EPERM;

	ret = mk_pcifront_host_ids(domain, bus, devfn, &vendor, &device);
	if (ret) {
		pr_err("%04x:%02x:%02x.%x is not in the host tree\n", domain,
		       bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
		return ret;
	}

	desc = kmalloc_obj(*desc, GFP_KERNEL);
	if (!desc)
		return -ENOMEM;
	ret = mk_pcifront_host_bus(domain, bus, desc);
	if (ret)
		pr_err("Bus %04x:%02x was not described by the host\n", domain,
		       bus);
	else
		ret = mk_pcifront_add_function(domain, bus, devfn, vendor,
					       device, desc);
	kfree(desc);
	return ret;
}

/**
 * mk_pcifront_init - Create the PCI buses of a spawn kernel
 *
 * Runs once. An architecture may call it from where its PCI init order
 * wants the buses; it runs at subsys_initcall otherwise.
 *
 * Returns: 0, also when this kernel is not a spawn or has no PCI buses
 */
int __init mk_pcifront_init(void)
{
	static bool done;
	struct device_node *np;
	int scanned = 0;

	if (done || !mk_manifest_phys())
		return 0;
	done = true;

	if (!host_instance) {
		pr_err("No ring to the host, no PCI for this instance\n");
		return 0;
	}

	pci_lock_rescan_remove();
	for_each_compatible_node(np, NULL, MK_PCI_HOST_BRIDGE)
		if (!mk_pcifront_add_bus(np))
			scanned++;
	pci_unlock_rescan_remove();

	if (!scanned)
		pr_info("No PCI buses described for this instance\n");
	return 0;
}

static int __init mk_pcifront_initcall(void)
{
	return mk_pcifront_init();
}
subsys_initcall(mk_pcifront_initcall);
