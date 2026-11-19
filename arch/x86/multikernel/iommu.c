// SPDX-License-Identifier: GPL-2.0-only
/*
 * The host's IOMMUs, as a spawn sees them:
 *
 *   /chosen/multikernel,iommus {
 *       #address-cells = <2>; #size-cells = <2>;
 *       iommu@fed90000 { ... };
 *   };
 *
 * and each PCI function node names its unit in multikernel,iommu-base.
 *
 * A spawn registers the units with the vendor's driver as driven by another
 * kernel, and that driver remaps the interrupts of the spawn's functions in
 * tables of its own, which no unit loads. The host owns the tables that are
 * loaded, so the driver has each entry written there as well, with
 * MK_IO_IRTE_WRITE: the host checks that the function is leased to the
 * spawn and that the interrupt goes to one of its CPUs. Writes may come
 * from irqchip callbacks with interrupts off, so the spawn polls for the
 * MK_IO_IRTE_ACK, while the host answers from a work item, because the
 * lease is a mutex.
 *
 * A spawn that takes over from its host claims the units, which then load
 * its tables.
 *
 * What a unit's node says and what an entry holds is the vendor's: VT-d in
 * dmar.c.
 */

#include <linux/dmar.h>
#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <asm/multikernel.h>

#include "iommu.h"

int mk_arch_manifest_chosen(void *fdt, struct mk_instance *instance)
{
	struct dmar_unit_desc vtd;
	int ret;

	if (dmar_unit_get(0, &vtd))
		return 0;
	ret = fdt_begin_node(fdt, "multikernel,iommus");
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 2);
	if (!ret)
		ret = mk_dmar_emit_units(fdt, instance);
	return ret ? ret : fdt_end_node(fdt);
}

u64 mk_arch_pci_iommu(struct pci_dev *pdev)
{
	u64 base;

	return dmar_device_unit(pdev, &base) ? 0 : base;
}

int mk_arch_lease_grant(struct mk_instance *instance, struct pci_dev *pdev)
{
	return mk_dmar_lease_grant(instance, pdev);
}

int mk_arch_iommu_claim(u64 base)
{
	return mk_dmar_claim(base);
}

/**
 * mk_irte_write - Have the host write an interrupt remapping entry
 * @unit: register base of the unit
 * @index: the entry
 * @mask: with a zero entry, clear 1 << @mask entries from @index on
 * @low: the entry, as the vendor of the unit lays it out
 * @high: likewise
 *
 * Any context. Return: 0 or a negative errno.
 */
int mk_irte_write(u64 unit, u32 index, u32 mask, u64 low, u64 high)
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

	/* The entry is in this kernel's table, loaded once it claims the unit */
	if (mk_host_fenced())
		return 0;
	host = READ_ONCE(host_instance);
	if (!host)
		return -ENODEV;
	ret = mk_request_sync(host, MK_MSG_IO, MK_IO_IRTE_WRITE, req.seq,
			      &req, sizeof(req), &ack, sizeof(ack));
	return ret ? ret : ack.result;
}

struct mk_irte_work {
	struct work_struct work;
	struct mk_irte_payload req;
};

static void mk_irte_work_fn(struct work_struct *work)
{
	struct mk_irte_work *w = container_of(work, struct mk_irte_work, work);
	struct mk_irte_payload *req = &w->req;
	struct mk_instance *instance = mk_instance_find(req->sender_instance_id);

	if (instance) {
		req->result = mk_dmar_irte_apply(instance, req);
		req->sender_instance_id = mk_self->id;
		mk_send_message_to(instance, MK_MSG_IO, MK_IO_IRTE_ACK, req, sizeof(*req));
		mk_instance_put(instance);
	}
	kfree(w);
}

static void mk_iommu_msg_handler(struct mk_instance *from, u32 msg_type, u32 subtype,
				 void *payload, u32 payload_len, void *ctx)
{
	struct mk_irte_payload *p = payload;
	struct mk_irte_work *w;

	if (payload_len < sizeof(*p))
		return;

	switch (subtype) {
	case MK_IO_IRTE_WRITE:
		w = kzalloc_obj(*w, GFP_ATOMIC);
		if (!w)
			return;
		w->req = *p;
		INIT_WORK(&w->work, mk_irte_work_fn);
		schedule_work(&w->work);
		break;
	case MK_IO_IRTE_ACK:
		mk_request_answer(p->seq, p, sizeof(*p));
		break;
	}
}

static int __init mk_iommu_init(void)
{
	return mk_register_msg_handler(MK_MSG_IO, mk_iommu_msg_handler, NULL);
}
fs_initcall(mk_iommu_init);
