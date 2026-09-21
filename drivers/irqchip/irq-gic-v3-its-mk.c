// SPDX-License-Identifier: GPL-2.0-only
/*
 * MSI domain of a multikernel instance on a GICv3 with an ITS.
 *
 * The ITS belongs to the kernel that spawned this one, so this is what
 * is left of an ITS driver when someone else runs the command queue: an
 * MSI parent domain on top of the GIC's LPI range that asks the host to
 * map each event (mk_msi_proxy_map()) and is told which LPI will arrive
 * and where the device has to write the event. That address comes with
 * every answer rather than with the device tree, because a machine can
 * have several ITSs and only the host knows which one sits behind a
 * device. The device is programmed from here as usual.
 *
 * The redistributors of this kernel's CPUs still run on the host's LPI
 * tables, which the host enabled before it gave the CPUs away and which
 * nothing can take back. So the host also owns the configuration bytes,
 * and an LPI stays enabled from the moment it is mapped: masking is left
 * to the MSI capability of the device.
 */

#define pr_fmt(fmt) "ITS-mk: " fmt

#include <linux/bitmap.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include <asm/smp_plat.h>

#include <dt-bindings/interrupt-controller/arm-gic.h>

#include "irq-gic-its-msi-parent.h"
#include <linux/irqchip/irq-msi-lib.h>

#define MK_ITS_COMPATIBLE	"multikernel,gic-v3-its"

struct mk_its_device {
	u32 domain;
	u32 rid;
	u32 nvecs;
	unsigned long *events;
};

struct mk_its_irq {
	struct mk_its_device *dev;
	u32 event;
	phys_addr_t doorbell;
};

static void mk_its_nop(struct irq_data *d)
{
}

/*
 * Called with the descriptor locked, and by a CPU on its way out that is
 * turned off right after. Like the ITS driver's own, the move is complete
 * when this returns: the host has sent the MOVI, which takes a pending
 * interrupt along.
 */
static int mk_its_set_affinity(struct irq_data *d, const struct cpumask *mask,
			       bool force)
{
	const struct cpumask *now = irq_data_get_effective_affinity_mask(d);
	struct mk_its_irq *irq = irq_data_get_irq_chip_data(d);
	unsigned int cpu;
	int ret;

	/* Stay where it is if that is allowed: a move is a round trip to the host */
	cpu = cpumask_first_and_and(now, mask, cpu_online_mask);
	if (cpu < nr_cpu_ids)
		return IRQ_SET_MASK_OK_DONE;

	cpu = cpumask_first_and(mask, cpu_online_mask);
	if (cpu >= nr_cpu_ids)
		return -EINVAL;

	ret = mk_msi_proxy_move(irq->dev->domain, irq->dev->rid, irq->event,
				cpu_logical_map(cpu));
	if (ret)
		return ret;

	irq_data_update_effective_affinity(d, cpumask_of(cpu));
	return IRQ_SET_MASK_OK_DONE;
}

static void mk_its_compose_msi_msg(struct irq_data *d, struct msi_msg *msg)
{
	struct mk_its_irq *irq = irq_data_get_irq_chip_data(d);

	msg->address_lo = lower_32_bits(irq->doorbell);
	msg->address_hi = upper_32_bits(irq->doorbell);
	msg->data = irq->event;
}

static struct irq_chip mk_its_chip = {
	.name			= "ITS-mk",
	.irq_mask		= mk_its_nop,
	.irq_unmask		= mk_its_nop,
	.irq_eoi		= irq_chip_eoi_parent,
	.irq_set_affinity	= mk_its_set_affinity,
	.irq_compose_msi_msg	= mk_its_compose_msi_msg,
};

static int mk_its_msi_prepare(struct irq_domain *domain, struct device *dev,
			      int nvec, msi_alloc_info_t *info)
{
	struct mk_its_device *mdev;

	if (!dev_is_pci(dev))
		return -EINVAL;

	mdev = kzalloc_obj(*mdev);
	if (!mdev)
		return -ENOMEM;

	mdev->nvecs = roundup_pow_of_two(nvec);
	mdev->events = bitmap_zalloc(mdev->nvecs, GFP_KERNEL);
	if (!mdev->events) {
		kfree(mdev);
		return -ENOMEM;
	}
	mdev->domain = pci_domain_nr(to_pci_dev(dev)->bus);
	mdev->rid = pci_dev_id(to_pci_dev(dev));

	info->scratchpad[0].ptr = mdev;
	return 0;
}

static void mk_its_msi_teardown(struct irq_domain *domain, msi_alloc_info_t *info)
{
	struct mk_its_device *mdev = info->scratchpad[0].ptr;

	bitmap_free(mdev->events);
	kfree(mdev);
}

static struct msi_domain_ops mk_its_msi_domain_ops = {
	.msi_prepare	= mk_its_msi_prepare,
	.msi_teardown	= mk_its_msi_teardown,
};

static int mk_its_alloc_one(struct irq_domain *domain, unsigned int virq,
			    struct mk_its_device *mdev, u32 event)
{
	struct irq_fwspec fwspec = {
		.fwnode = domain->parent->fwnode,
		.param_count = 3,
		.param = { GIC_IRQ_TYPE_LPI, 0, IRQ_TYPE_EDGE_RISING },
	};
	unsigned int cpu = cpumask_first(cpu_online_mask);
	struct mk_its_irq *irq;
	struct irq_data *irqd;
	int lpi, ret;

	irq = kzalloc_obj(*irq);
	if (!irq)
		return -ENOMEM;
	irq->dev = mdev;
	irq->event = event;

	lpi = mk_msi_proxy_map(mdev->domain, mdev->rid, event,
			       cpu_logical_map(cpu), &irq->doorbell);
	if (lpi < 0) {
		kfree(irq);
		return lpi;
	}

	fwspec.param[1] = lpi;
	ret = irq_domain_alloc_irqs_parent(domain, virq, 1, &fwspec);
	if (ret) {
		kfree(irq);
		return ret;
	}

	irq_domain_set_hwirq_and_chip(domain, virq, lpi, &mk_its_chip, irq);
	irqd = irq_get_irq_data(virq);
	irqd_set_single_target(irqd);
	irq_data_update_effective_affinity(irqd, cpumask_of(cpu));
	return 0;
}

static int mk_its_domain_alloc(struct irq_domain *domain, unsigned int virq,
			       unsigned int nr_irqs, void *args)
{
	msi_alloc_info_t *info = args;
	struct mk_its_device *mdev = info->scratchpad[0].ptr;
	unsigned int i;
	int first, ret;

	first = bitmap_find_free_region(mdev->events, mdev->nvecs,
					get_count_order(nr_irqs));
	if (first < 0)
		return -ENOSPC;

	for (i = 0; i < nr_irqs; i++) {
		ret = mk_its_alloc_one(domain, virq + i, mdev, first + i);
		if (ret)
			return ret;
	}
	return 0;
}

/* The host keeps the mapping until this kernel is gone; the event is reusable */
static void mk_its_domain_free(struct irq_domain *domain, unsigned int virq,
			       unsigned int nr_irqs)
{
	unsigned int i;

	for (i = 0; i < nr_irqs; i++) {
		struct irq_data *d = irq_domain_get_irq_data(domain, virq + i);
		struct mk_its_irq *irq = irq_data_get_irq_chip_data(d);

		if (irq) {
			bitmap_clear(irq->dev->events, irq->event, 1);
			kfree(irq);
		}
		irq_domain_reset_irq_data(d);
	}
	irq_domain_free_irqs_parent(domain, virq, nr_irqs);
}

static const struct irq_domain_ops mk_its_domain_ops = {
	.select	= msi_lib_irq_domain_select,
	.alloc	= mk_its_domain_alloc,
	.free	= mk_its_domain_free,
};

static struct msi_domain_info mk_its_msi_info = {
	.ops = &mk_its_msi_domain_ops,
};

/*
 * No "interrupt-controller" property, so of_irq_init() does not come by.
 * Any time after the GIC and before the first PCI host bridge will do.
 */
static int __init mk_its_init(void)
{
	struct irq_domain_info info = {
		.ops		= &mk_its_domain_ops,
		.host_data	= &mk_its_msi_info,
	};
	struct device_node *np, *gic;
	int ret = -ENODEV;

	np = of_find_compatible_node(NULL, NULL, MK_ITS_COMPATIBLE);
	if (!np)
		return 0;

	gic = of_irq_find_parent(np);
	info.parent = gic ? irq_find_host(gic) : NULL;
	of_node_put(gic);

	if (!info.parent)
		goto out;

	info.fwnode = of_fwnode_handle(np);
	ret = msi_create_parent_irq_domain(&info, &gic_v3_its_msi_parent_ops) ?
	      0 : -ENOMEM;
out:
	if (ret)
		pr_err("%pOF: no MSI domain: %d\n", np, ret);
	else
		pr_info("MSIs through the host's ITS\n");
	of_node_put(np);
	return ret;
}
arch_initcall(mk_its_init);
