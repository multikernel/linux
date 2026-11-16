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
 * the ones that never come online. Harts the host never booted are not
 * in the host's node, and are added to the spawn's with the interrupt
 * files they found to be theirs.
 */

#define pr_fmt(fmt) "mk_imsic: " fmt

#include <linux/irqchip/riscv-imsic.h>
#include <linux/irqdomain.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/sort.h>

#include <asm/csr.h>
#include <asm/processor.h>
#include <asm/smp.h>

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
 * can sit on a bus the instance tree does not have. Returns the node.
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
	return mk_dtb_set_reg(fdt, node, reg, nr) ?: node;
}

static bool mk_imsic_host_file(const struct imsic_global_config *imsic,
			       phys_addr_t file)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (per_cpu_ptr(imsic->local, cpu)->msi_pa == file)
			return true;
	}
	return false;
}

/**
 * mk_imsic_free_files - Interrupt files no known hart has
 * @files: Filled with their addresses
 * @max: Room in @files
 * @nr_harts: Harts looking for their file
 *
 * The files sit one hart index apart from the base address. A node that
 * does not say how many hart indices there are leaves the driver with
 * just enough for the harts it lists, so the search goes on past those
 * until there is a file for every hart that looks for one.
 */
unsigned int mk_imsic_free_files(u64 *files, unsigned int max,
				 unsigned int nr_harts)
{
	const struct imsic_global_config *imsic = imsic_get_global_config();
	unsigned int shift, i, n = 0;

	if (!imsic)
		return 0;

	shift = imsic->guest_index_bits + IMSIC_MMIO_PAGE_SHIFT;
	for (i = 0; n < max && (i < BIT(imsic->hart_index_bits) || n < nr_harts); i++) {
		phys_addr_t file = imsic->base_addr + ((phys_addr_t)i << shift);

		if (!mk_imsic_host_file(imsic, file) && !mk_imsic_file_taken(file))
			files[n++] = file;
	}
	return n;
}

struct mk_imsic_file {
	u64 addr;
	u32 phandle;
};

static int mk_imsic_file_cmp(const void *a, const void *b)
{
	const struct mk_imsic_file *fa = a, *fb = b;

	return fa->addr < fb->addr ? -1 : fa->addr > fb->addr;
}

/* The file of the hart the i-th interrupt of the host's node goes to */
static bool mk_imsic_host_entry(struct device_node *np, unsigned int i,
				const struct imsic_global_config *imsic,
				struct mk_imsic_file *file)
{
	struct of_phandle_args parent;
	unsigned long hartid;
	int cpu = -1;

	if (of_irq_parse_one(np, i, &parent))
		return false;
	if (!riscv_of_parent_hartid(parent.np, &hartid))
		cpu = riscv_hartid_to_cpuid(hartid);
	file->phandle = parent.np->phandle;
	of_node_put(parent.np);
	if (cpu < 0)
		return false;

	file->addr = per_cpu_ptr(imsic->local, cpu)->msi_pa;
	return file->addr;
}

/*
 * Give the instance's IMSIC the files of the harts the host's node
 * leaves out. A driver finds a hart's file by counting through reg, so
 * the harts go in the order of their files and reg covers exactly those.
 */
static int mk_dtb_imsic_add_harts(void *fdt, int node, struct device_node *np)
{
	const struct imsic_global_config *imsic = imsic_get_global_config();
	struct mk_imsic_file *files __free(kfree) = NULL;
	fdt32_t *parents __free(kfree) = NULL;
	unsigned int nr_host = of_irq_count(np);
	u64 reg[2 * MK_IMSIC_MAX_REG], stride;
	const struct mk_hart *hart;
	unsigned int i, n = 0, nr_new = 0, nr_reg = 0;

	mk_for_each_unclaimed_hart(hart)
		nr_new += !!hart->file;
	if (!nr_new || !imsic)
		return 0;

	files = kmalloc_array(nr_host + nr_new, sizeof(*files), GFP_KERNEL);
	parents = kmalloc_array(2 * (nr_host + nr_new), sizeof(*parents),
				GFP_KERNEL);
	if (!files || !parents)
		return -FDT_ERR_NOSPACE;

	for (i = 0; i < nr_host; i++)
		n += mk_imsic_host_entry(np, i, imsic, &files[n]);
	mk_for_each_unclaimed_hart(hart) {
		if (!hart->file)
			continue;
		files[n].addr = hart->file;
		files[n++].phandle = hart->phandle;
	}
	sort(files, n, sizeof(*files), mk_imsic_file_cmp, NULL);

	stride = BIT_ULL(imsic->guest_index_bits + IMSIC_MMIO_PAGE_SHIFT);
	for (i = 0; i < n; i++) {
		parents[2 * i] = cpu_to_fdt32(files[i].phandle);
		parents[2 * i + 1] = cpu_to_fdt32(RV_IRQ_EXT);

		if (i && files[i].addr == files[i - 1].addr + stride) {
			reg[2 * nr_reg - 1] += stride;
			continue;
		}
		if (nr_reg == MK_IMSIC_MAX_REG)
			return -FDT_ERR_NOSPACE;
		reg[2 * nr_reg] = files[i].addr;
		reg[2 * nr_reg + 1] = stride;
		nr_reg++;
	}

	return fdt_setprop(fdt, node, "interrupts-extended", parents,
			   2 * n * sizeof(*parents)) ?:
	       mk_dtb_set_reg(fdt, node, reg, nr_reg);
}

int mk_dtb_add_imsic(void *fdt)
{
	struct device_node *np = mk_of_imsic_node();
	int node, ret;

	if (!np)
		return 0;
	node = mk_dtb_copy_device(fdt, np);
	ret = node < 0 ? node : mk_dtb_imsic_add_harts(fdt, node, np);
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
