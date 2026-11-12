// SPDX-License-Identifier: GPL-2.0-only
/*
 * The host's VT-d units, as a spawn sees them:
 *
 *   /chosen/multikernel,iommus {
 *       #address-cells = <2>; #size-cells = <2>;
 *       iommu@fed90000 {
 *           compatible = "multikernel,vtd";
 *           reg = <base size>;
 *           linux,pci-domain = <0>;
 *           numa-node-id = <0>;			if known
 *           multikernel,irte-block = <first count>;	if it remaps
 *       };
 *   };
 *
 * and each PCI function node names its unit in multikernel,iommu-base.
 *
 * A unit has one interrupt remapping table, the host's, so the host lends
 * each spawn a block of it. The spawn composes its entries there; the host
 * checks and writes them. Writes may come from irqchip callbacks with
 * interrupts off, so the spawn polls.
 *
 * An entry names a function in its source verification, and is written only
 * while that function is leased to the spawn. It is part of the lease: when
 * the lease ends, the entries naming the function are cleared.
 */

#define pr_fmt(fmt) "mk_dmar: " fmt

#include <linux/dmar.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <asm/multikernel.h>

/* 256 entries per spawn and unit, in an aligned block */
#define MK_IRTE_ORDER		8
#define MK_IOMMUS_PATH		"/chosen/multikernel,iommus"

struct mk_irte_payload {
	u64 seq;
	u64 unit;		/* register base of the VT-d unit */
	u64 low;
	u64 high;
	u32 index;
	u32 mask;		/* with a zero entry: clear 1 << mask entries */
	int result;		/* ACK: 0 or -errno */
	int sender_instance_id;
};

struct mk_irte_block {
	struct list_head list;
	struct mk_instance *instance;
	u64 unit;
	u32 first;
	u32 count;
};

static LIST_HEAD(mk_irte_blocks);
static DEFINE_RAW_SPINLOCK(mk_irte_blocks_lock);

static struct mk_irte_block *mk_irte_find_block(int instance_id, u64 unit)
{
	struct mk_irte_block *b;

	list_for_each_entry(b, &mk_irte_blocks, list)
		if (b->instance->id == instance_id && b->unit == unit)
			return b;
	return NULL;
}

/* A spawn spawned again keeps its blocks */
static struct mk_irte_block *mk_irte_block_of(struct mk_instance *instance, u64 unit)
{
	struct mk_irte_block *b;
	u32 first;
	int ret;

	scoped_guard(raw_spinlock_irqsave, &mk_irte_blocks_lock) {
		b = mk_irte_find_block(instance->id, unit);
		if (b)
			return b;
	}
	ret = intel_irq_remap_reserve(unit, MK_IRTE_ORDER, &first);
	if (ret)
		return ERR_PTR(ret);
	b = kzalloc_obj(*b, GFP_KERNEL);
	if (!b) {
		intel_irq_remap_release(unit, first, MK_IRTE_ORDER);
		return ERR_PTR(-ENOMEM);
	}
	b->instance = mk_instance_get(instance);
	b->unit = unit;
	b->first = first;
	b->count = 1U << MK_IRTE_ORDER;
	scoped_guard(raw_spinlock_irqsave, &mk_irte_blocks_lock)
		list_add(&b->list, &mk_irte_blocks);
	return b;
}

static int mk_dt_emit_unit(void *fdt, struct mk_instance *instance,
			   const struct dmar_unit_desc *unit)
{
	fdt64_t reg[2] = { cpu_to_fdt64(unit->base), cpu_to_fdt64(unit->size) };
	struct mk_irte_block *b;
	char name[32];
	int ret;

	snprintf(name, sizeof(name), "iommu@%llx", unit->base);
	ret = fdt_begin_node(fdt, name);
	if (!ret)
		ret = fdt_property_string(fdt, "compatible", "multikernel,vtd");
	if (!ret)
		ret = fdt_property(fdt, "reg", reg, sizeof(reg));
	if (!ret)
		ret = fdt_property_u32(fdt, "linux,pci-domain", unit->segment);
	if (!ret && unit->node != NUMA_NO_NODE)
		ret = fdt_property_u32(fdt, "numa-node-id", unit->node);
	if (ret)
		return ret;

	b = mk_irte_block_of(instance, unit->base);
	if (!IS_ERR(b)) {
		fdt32_t block[2] = { cpu_to_fdt32(b->first), cpu_to_fdt32(b->count) };

		ret = fdt_property(fdt, "multikernel,irte-block", block, sizeof(block));
	} else if (PTR_ERR(b) != -ENODEV) {
		pr_warn("instance %d: no remapping entries on %llx\n",
			instance->id, unit->base);
	}
	return ret ? ret : fdt_end_node(fdt);
}

int mk_arch_manifest_chosen(void *fdt, struct mk_instance *instance)
{
	struct dmar_unit_desc unit;
	int i, ret;

	if (dmar_unit_get(0, &unit))
		return 0;
	ret = fdt_begin_node(fdt, "multikernel,iommus");
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 2);
	for (i = 0; !ret && !dmar_unit_get(i, &unit); i++)
		ret = mk_dt_emit_unit(fdt, instance, &unit);
	return ret ? ret : fdt_end_node(fdt);
}

u64 mk_arch_pci_iommu(struct pci_dev *pdev)
{
	u64 base;

	return dmar_device_unit(pdev, &base) ? 0 : base;
}

void mk_arch_instance_destroy(struct mk_instance *instance)
{
	struct mk_irte_block *b, *n;
	LIST_HEAD(gone);

	scoped_guard(raw_spinlock_irqsave, &mk_irte_blocks_lock) {
		list_for_each_entry_safe(b, n, &mk_irte_blocks, list)
			if (b->instance == instance)
				list_move(&b->list, &gone);
	}
	list_for_each_entry_safe(b, n, &gone, list) {
		intel_irq_remap_release(b->unit, b->first, MK_IRTE_ORDER);
		mk_instance_put(b->instance);
		kfree(b);
	}
}

struct mk_irte_lent {
	struct mk_instance *instance;
	u64 source;
};

static void mk_irte_unlend(void *data)
{
	struct mk_irte_lent *lent = data;
	struct mk_irte_block *b;

	scoped_guard(raw_spinlock_irqsave, &mk_irte_blocks_lock) {
		list_for_each_entry(b, &mk_irte_blocks, list)
			if (b->instance == lent->instance)
				intel_irq_remap_clear_source(b->unit, b->first, b->count,
							     lent->source);
	}
	mk_instance_put(lent->instance);
	kfree(lent);
}

int mk_arch_lease_grant(struct mk_instance *instance, struct pci_dev *pdev)
{
	struct mk_irte_lent *lent;

	if (!intel_irq_remap_units(NULL, 0))
		return 0;
	lent = kzalloc_obj(*lent, GFP_KERNEL);
	if (!lent)
		return -ENOMEM;
	lent->instance = mk_instance_get(instance);
	lent->source = intel_irq_remap_msi_source(pdev);
	return devm_add_action_or_reset(&pdev->dev, mk_irte_unlend, lent);
}

/* Under the lock, so the block cannot be released and reused meanwhile */
static int mk_irte_apply(struct mk_instance *instance, const struct mk_irte_payload *req)
{
	struct mk_irte_block *b;

	guard(raw_spinlock_irqsave)(&mk_irte_blocks_lock);
	b = mk_irte_find_block(instance->id, req->unit);
	if (!b || req->mask > MK_IRTE_ORDER || req->index < b->first ||
	    req->index + (1U << req->mask) > b->first + b->count)
		return -EPERM;
	return intel_irq_remap_write(req->unit, req->index, req->mask, req->low,
				     req->high);
}

/* Only for a function leased to @instance, at its own CPUs, and while the lease holds */
static int mk_irte_check_and_apply(struct mk_instance *instance,
				   const struct mk_irte_payload *req)
{
	struct mk_lease *lease = NULL;
	struct pci_dev *pdev;
	u32 apicid;
	int ret = -EPERM;

	if (!req->low && !req->high)
		return mk_irte_apply(instance, req);
	if (intel_irq_remap_msi_dest(req->low, &apicid) ||
	    !mk_cpu_set_contains(instance->cpus, apicid))
		return -EPERM;

	pdev = intel_irq_remap_msi_device(req->unit, req->high);
	if (pdev)
		lease = mk_lease_lock(instance, pdev);
	/* A DMA alias names another function than the one it stands for */
	if (lease && intel_irq_remap_msi_source(pdev) == req->high)
		ret = mk_irte_apply(instance, req);
	if (lease)
		mk_lease_unlock(lease);
	pci_dev_put(pdev);
	return ret;
}

struct mk_irte_work {
	struct work_struct work;
	struct mk_irte_payload req;
};

/* The lease is a mutex, so requests are answered in process context */
static void mk_irte_work_fn(struct work_struct *work)
{
	struct mk_irte_work *w = container_of(work, struct mk_irte_work, work);
	struct mk_irte_payload *req = &w->req;
	struct mk_instance *instance = mk_instance_find(req->sender_instance_id);

	if (instance) {
		req->result = mk_irte_check_and_apply(instance, req);
		req->sender_instance_id = mk_self->id;
		mk_send_message_to(instance, MK_MSG_IO, MK_IO_IRTE_ACK, req, sizeof(*req));
		mk_instance_put(instance);
	}
	kfree(w);
}

static void mk_irte_write_request(const struct mk_irte_payload *req)
{
	struct mk_irte_work *w = kzalloc_obj(*w, GFP_ATOMIC);

	if (!w)
		return;
	w->req = *req;
	INIT_WORK(&w->work, mk_irte_work_fn);
	schedule_work(&w->work);
}

/* The @i-th unit, or with @i < 0 the one at @base */
static struct device_node *mk_dmar_unit_node(int i, u64 base)
{
	struct device_node *units, *np;
	u64 reg;

	units = of_find_node_by_path(MK_IOMMUS_PATH);
	if (!units)
		return NULL;
	for_each_child_of_node(units, np) {
		if (!of_device_is_compatible(np, "multikernel,vtd") ||
		    of_property_read_u64(np, "reg", &reg))
			continue;
		if (i < 0 ? reg == base : !i--)
			break;
	}
	of_node_put(units);
	return np;
}

static int mk_dmar_unit(int i, struct dmar_unit_desc *desc)
{
	struct device_node *np = mk_dmar_unit_node(i, 0);
	u32 segment = 0, node;
	int ret;

	if (!np)
		return -ENOENT;
	ret = of_property_read_u64_index(np, "reg", 0, &desc->base) ?:
	      of_property_read_u64_index(np, "reg", 1, &desc->size);
	of_property_read_u32(np, "linux,pci-domain", &segment);
	desc->segment = segment;
	desc->node = of_property_read_u32(np, "numa-node-id", &node) ? NUMA_NO_NODE : node;
	of_node_put(np);
	return ret ? -EINVAL : 0;
}

static int mk_dmar_device_unit(struct pci_dev *pdev, u64 *base)
{
	struct device_node *np = pci_device_to_OF_node(pdev);

	return np && !of_property_read_u64(np, "multikernel,iommu-base", base) ? 0 : -ENODEV;
}

static int mk_irte_block(u64 unit, u32 *first, u32 *count)
{
	struct device_node *np = mk_dmar_unit_node(-1, unit);
	int ret;

	if (!np)
		return -ENODEV;
	ret = of_property_read_u32_index(np, "multikernel,irte-block", 0, first) ?:
	      of_property_read_u32_index(np, "multikernel,irte-block", 1, count);
	of_node_put(np);
	return ret ? -ENODEV : 0;
}

static int mk_irte_write(u64 unit, u32 index, u32 mask, u64 low, u64 high)
{
	struct mk_irte_payload req = {
		.seq = mk_request_seq(),
		.unit = unit,
		.low = low,
		.high = high,
		.index = index,
		.mask = mask,
		.sender_instance_id = mk_self->id,
	};
	struct mk_irte_payload ack;
	struct mk_instance *host;
	int ret;

	/* The entry is in this kernel's table, live once it claims the unit */
	if (mk_host_fenced())
		return 0;
	host = READ_ONCE(host_instance);
	if (!host)
		return -ENODEV;
	ret = mk_request_sync(host, MK_MSG_IO, MK_IO_IRTE_WRITE, req.seq,
			      &req, sizeof(req), &ack, sizeof(ack));
	return ret ? ret : ack.result;
}

static void mk_irte_msg_handler(struct mk_instance *from, u32 msg_type, u32 subtype,
				void *payload, u32 payload_len, void *ctx)
{
	struct mk_irte_payload *p = payload;

	if (payload_len < sizeof(*p))
		return;

	switch (subtype) {
	case MK_IO_IRTE_WRITE:
		mk_irte_write_request(p);
		break;
	case MK_IO_IRTE_ACK:
		mk_request_answer(p->seq, p, sizeof(*p));
		break;
	}
}

static const struct dmar_foreign_ops mk_dmar_foreign_ops = {
	.unit		= mk_dmar_unit,
	.device_unit	= mk_dmar_device_unit,
	.irte_block	= mk_irte_block,
	.irte_write	= mk_irte_write,
};

void __init mk_dmar_init(void)
{
	dmar_set_foreign_ops(&mk_dmar_foreign_ops);
}

int mk_arch_iommu_claim(u64 base)
{
	return intel_iommu_claim(base);
}

static int __init mk_irte_init(void)
{
	return mk_register_msg_handler(MK_MSG_IO, mk_irte_msg_handler, NULL);
}
fs_initcall(mk_irte_init);
