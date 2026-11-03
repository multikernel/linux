// SPDX-License-Identifier: GPL-2.0-only
/*
 * multikernel.c - PCI of a multikernel spawn kernel
 *
 * The root buses come from the instance device tree and reach config
 * space through the kernel that lent their devices, both generic
 * (kernel/multikernel/pcifront.c). What is x86 about them is the
 * sysdata every x86 root bus carries, and that this kernel sets up no
 * config mechanism of its own: the 0xCF8 ports and ECAM are shared with
 * every other kernel on the machine. The raw accessors, which x86 code
 * uses by address, go through the host as well.
 */
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/multikernel.h>

#include <asm/pci_x86.h>

int mk_arch_pcifront_prepare(struct pci_host_bridge *bridge, int domain)
{
	struct pci_sysdata *sd = kzalloc_obj(*sd, GFP_KERNEL);

	if (!sd)
		return -ENOMEM;

	sd->node = NUMA_NO_NODE;
#ifdef CONFIG_PCI_DOMAINS
	sd->domain = domain;
#endif
	bridge->sysdata = sd;
	return 0;
}

static int pci_multikernel_read(unsigned int seg, unsigned int bus,
				unsigned int devfn, int reg, int len, u32 *val)
{
	return pcibios_err_to_errno(mk_pcifront_config(seg, bus, devfn, reg,
						       len, val, false));
}

static int pci_multikernel_write(unsigned int seg, unsigned int bus,
				 unsigned int devfn, int reg, int len, u32 val)
{
	return pcibios_err_to_errno(mk_pcifront_config(seg, bus, devfn, reg,
						       len, &val, true));
}

static const struct pci_raw_ops pci_multikernel_raw_ops = {
	.read = pci_multikernel_read,
	.write = pci_multikernel_write,
};

/* In place of the PCI BIOS and the direct mechanisms */
int __init pci_multikernel_arch_init(void)
{
	raw_pci_ops = &pci_multikernel_raw_ops;
	raw_pci_ext_ops = &pci_multikernel_raw_ops;
	return 0;
}

int __init pci_multikernel_init(void)
{
	/*
	 * Here rather than at the front end's own initcall: x86 sets up its
	 * root buses before pcibios_init() and the PCI IRQ setup run. The
	 * tree is the sole source of topology, so never fall back to
	 * probing bus 0.
	 */
	mk_pcifront_init();
	return 0;
}
