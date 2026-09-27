// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * Config space of the PCI functions lent to instances, served over the
 * message ring.
 *
 * An instance never generates a config cycle itself: it asks the kernel
 * that lent it the function, which checks that the function is the
 * instance's and makes the access with its own accessors, quirks
 * included. Nothing else on the fabric is reachable that way, the
 * bridges above the function included, and no two kernels ever share a
 * config mechanism such as the 0xCF8 port pair.
 *
 * Only config space goes this way. BARs, DMA and MSIs stay direct, so
 * none of this is on the data path of a running device. The mask bits
 * of a plain MSI are in config space, but MSI is oneshot safe, so they
 * are only touched to start and stop an interrupt, to hold off one that
 * fires again while it is handled, and while it is disabled.
 *
 * Writes are filtered, after xen-pciback: the instance owns what the
 * function does, while the lending kernel keeps what places it on the
 * fabric. BARs stay where they were assigned and only appear to size,
 * the header outside the Command register and a few scratch fields is
 * read only, and SR-IOV is not offered.
 *
 * A function taken back from an instance, however the instance stopped,
 * is reset, after xen-pciback too, or has its bus mastering cleared when
 * it has no reset: whatever the instance left it doing, its DMA into
 * memory the pool hands out again included, stops here, and the next
 * kernel to be given it meets it clean.
 *
 * Requests are answered from the doorbell interrupt, which is what lets
 * an instance wait for the answer with interrupts off. A kernel that is
 * itself an instance reaches config space over the ring too, which it
 * cannot do from a message handler, so it answers from a work item.
 */

#define pr_fmt(fmt) "mk_pciback: " fmt

#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "internal.h"

/* Bits of the Command register an instance may change */
#define MK_PCIBACK_CMD	(PCI_COMMAND_IO | PCI_COMMAND_MEMORY |		\
			 PCI_COMMAND_MASTER | PCI_COMMAND_PARITY |	\
			 PCI_COMMAND_SERR | PCI_COMMAND_INTX_DISABLE)

/* Bit of the ROM BAR in mk_pciback_dev.sizing, after the six BARs */
#define MK_PCIBACK_ROM	PCI_STD_NUM_BARS

/* A function an instance may reach, while the instance runs */
struct mk_pciback_dev {
	struct list_head list;
	refcount_t ref;
	struct mk_instance *instance;
	struct pci_dev *pdev;
	unsigned long sizing;	/* BARs written with something else than their value */
	u16 sriov;		/* SR-IOV capability, or 0 */
};

static LIST_HEAD(mk_pciback_devs);
static DEFINE_RAW_SPINLOCK(mk_pciback_lock);

struct mk_pciback_work {
	struct work_struct work;
	struct mk_pci_cfg_payload req;
	u32 subtype;
};

static struct mk_pciback_dev *mk_pciback_find(int instance_id, u16 domain,
					      u8 bus, u8 devfn)
{
	struct mk_pciback_dev *d;

	lockdep_assert_held(&mk_pciback_lock);

	list_for_each_entry(d, &mk_pciback_devs, list) {
		if (d->instance->id == instance_id &&
		    pci_domain_nr(d->pdev->bus) == domain &&
		    d->pdev->bus->number == bus && d->pdev->devfn == devfn)
			return d;
	}
	return NULL;
}

static bool mk_pciback_valid(const struct mk_pci_cfg_payload *req)
{
	if (req->size != 1 && req->size != 2 && req->size != 4)
		return false;
	return req->where % req->size == 0 &&
	       req->where + req->size <= PCI_CFG_SPACE_EXP_SIZE;
}

static int mk_pciback_read(struct pci_dev *pdev, int where, int size, u32 *val)
{
	u16 w;
	u8 b;
	int ret;

	switch (size) {
	case 1:
		ret = pci_read_config_byte(pdev, where, &b);
		*val = b;
		break;
	case 2:
		ret = pci_read_config_word(pdev, where, &w);
		*val = w;
		break;
	default:
		ret = pci_read_config_dword(pdev, where, val);
		break;
	}
	return ret;
}

static int mk_pciback_write(struct pci_dev *pdev, int where, int size, u32 val)
{
	switch (size) {
	case 1:
		return pci_write_config_byte(pdev, where, val);
	case 2:
		return pci_write_config_word(pdev, where, val);
	default:
		return pci_write_config_dword(pdev, where, val);
	}
}

/* The BAR, or MK_PCIBACK_ROM, that a dword of the header is, or -1 */
static int mk_pciback_bar_slot(const struct pci_dev *pdev, int reg)
{
	if (pdev->hdr_type != PCI_HEADER_TYPE_NORMAL)
		return -1;
	if (reg >= PCI_BASE_ADDRESS_0 && reg <= PCI_BASE_ADDRESS_5)
		return (reg - PCI_BASE_ADDRESS_0) / 4;
	if (reg == PCI_ROM_ADDRESS)
		return MK_PCIBACK_ROM;
	return -1;
}

/* Zero for a BAR the function does not implement */
static u64 mk_pciback_size_mask(const struct resource *res)
{
	return res->flags ? ~(resource_size(res) - 1) : 0;
}

/*
 * What a BAR reads back while it is being sized: the size of the
 * resource this kernel found behind it, with the type bits of @cur.
 */
static u32 mk_pciback_bar_sized(const struct pci_dev *pdev, int slot, u32 cur)
{
	u64 mask;
	int i;

	if (slot == MK_PCIBACK_ROM)
		return mk_pciback_size_mask(&pdev->resource[PCI_ROM_RESOURCE]) &
		       PCI_ROM_ADDRESS_MASK;

	/* The upper half of a 64-bit BAR sizes with its lower half */
	for (i = 0; i < slot; i++) {
		if (!(pdev->resource[i].flags & IORESOURCE_MEM_64))
			continue;
		if (++i == slot)
			return upper_32_bits(mk_pciback_size_mask(&pdev->resource[i - 1]));
	}

	mask = mk_pciback_size_mask(&pdev->resource[slot]);
	if (!mask)
		return 0;
	if (cur & PCI_BASE_ADDRESS_SPACE_IO)
		return ((u32)mask & PCI_BASE_ADDRESS_IO_MASK) |
		       (cur & ~PCI_BASE_ADDRESS_IO_MASK);
	return ((u32)mask & PCI_BASE_ADDRESS_MEM_MASK) |
	       (cur & ~PCI_BASE_ADDRESS_MEM_MASK);
}

/* The bits of a dword, outside the BARs, that an instance may write */
static u32 mk_pciback_wmask(const struct mk_pciback_dev *d, int reg)
{
	if (reg >= PCI_STD_HEADER_SIZEOF) {
		if (d->sriov && reg >= d->sriov &&
		    reg < d->sriov + PCI_EXT_CAP_SRIOV_SIZEOF)
			return 0;
		return ~0U;
	}

	switch (reg) {
	case PCI_COMMAND:
		/* Status is write-one-to-clear, and only the function's own */
		return MK_PCIBACK_CMD | 0xffff0000;
	case PCI_CACHE_LINE_SIZE:
		/* And the latency timer next to it */
		return 0x0000ffff;
	case PCI_INTERRUPT_LINE:
		return 0x000000ff;
	}
	return 0;
}

static int mk_pciback_filtered_read(struct mk_pciback_dev *d, int where,
				    int size, u32 *val)
{
	int slot = mk_pciback_bar_slot(d->pdev, where & ~3);
	int ret;

	ret = mk_pciback_read(d->pdev, where, size, val);
	if (!ret && size == 4 && slot >= 0 && test_bit(slot, &d->sizing))
		*val = mk_pciback_bar_sized(d->pdev, slot, *val);
	return ret;
}

/*
 * A BAR is never written. Sizing writes all ones and then puts back what
 * was there, so anything but the BAR's value starts a sizing, which the
 * value ends. Placement is the lending kernel's.
 */
static int mk_pciback_bar_write(struct mk_pciback_dev *d, int where, int size,
				u32 val, int slot)
{
	u32 cur;
	int ret;

	if (size != 4)
		return PCIBIOS_SUCCESSFUL;

	ret = mk_pciback_read(d->pdev, where, 4, &cur);
	if (ret)
		return ret;

	if (val == cur)
		clear_bit(slot, &d->sizing);
	else
		set_bit(slot, &d->sizing);
	return PCIBIOS_SUCCESSFUL;
}

/* A write to what is not the instance's own is dropped, as if read only */
static int mk_pciback_filtered_write(struct mk_pciback_dev *d, int where,
				     int size, u32 val)
{
	u32 all = size == 4 ? ~0U : (1U << (size * 8)) - 1;
	int slot = mk_pciback_bar_slot(d->pdev, where & ~3);
	u32 mask, cur;
	int ret;

	if (slot >= 0)
		return mk_pciback_bar_write(d, where, size, val, slot);

	mask = (mk_pciback_wmask(d, where & ~3) >> ((where & 3) * 8)) & all;
	if (!mask)
		return PCIBIOS_SUCCESSFUL;

	if (mask != all) {
		ret = mk_pciback_read(d->pdev, where, size, &cur);
		if (ret)
			return ret;
		val = (val & mask) | (cur & ~mask);
	}
	return mk_pciback_write(d->pdev, where, size, val);
}

static void mk_pciback_do(struct mk_pciback_dev *d, u32 subtype,
			  struct mk_pci_cfg_payload *ack)
{
	if (!mk_pciback_valid(ack)) {
		ack->result = PCIBIOS_BAD_REGISTER_NUMBER;
	} else if (subtype == MK_PCI_CFG_READ) {
		ack->result = mk_pciback_filtered_read(d, ack->where, ack->size,
						       &ack->val);
	} else {
		ack->result = mk_pciback_filtered_write(d, ack->where,
							ack->size, ack->val);
	}

	if (subtype == MK_PCI_CFG_READ && ack->result)
		ack->val = ~0U;
}

static void mk_pciback_put(struct mk_pciback_dev *d)
{
	if (!refcount_dec_and_test(&d->ref))
		return;
	pm_runtime_put(&d->pdev->dev);
	pci_dev_put(d->pdev);
	mk_instance_put(d->instance);
	kfree(d);
}

static void mk_pciback_answer(struct mk_instance *instance,
			      struct mk_pci_cfg_payload *ack)
{
	ack->sender_instance_id = mk_self->id;
	mk_send_message_to(instance, MK_MSG_PCI, MK_PCI_CFG_ACK, ack,
			   sizeof(*ack));
}

/*
 * The slow way: the requester is not known here (it was lent nothing),
 * or this kernel's own config access goes over the ring.
 */
static void mk_pciback_work_fn(struct work_struct *work)
{
	struct mk_pciback_work *w = container_of(work, struct mk_pciback_work, work);
	struct mk_pci_cfg_payload *ack = &w->req;
	struct mk_instance *instance;
	struct mk_pciback_dev *d;

	instance = mk_instance_find(ack->sender_instance_id);
	if (!instance)
		goto out;

	scoped_guard(raw_spinlock_irqsave, &mk_pciback_lock) {
		d = mk_pciback_find(instance->id, ack->domain, ack->bus,
				    ack->devfn);
		if (d)
			refcount_inc(&d->ref);
	}

	if (d) {
		mk_pciback_do(d, w->subtype, ack);
		mk_pciback_put(d);
	} else {
		ack->result = PCIBIOS_DEVICE_NOT_FOUND;
		ack->val = ~0U;
	}

	mk_pciback_answer(instance, ack);
	mk_instance_put(instance);
out:
	kfree(w);
}

static void mk_pciback_defer(const struct mk_pci_cfg_payload *req, u32 subtype)
{
	struct mk_pciback_work *w = kzalloc(sizeof(*w), GFP_ATOMIC);

	if (!w)
		return;
	w->req = *req;
	w->subtype = subtype;
	INIT_WORK(&w->work, mk_pciback_work_fn);
	schedule_work(&w->work);
}

static void mk_pciback_request(const struct mk_pci_cfg_payload *req,
			       u32 subtype)
{
	struct mk_pci_cfg_payload ack = *req;
	struct mk_pciback_dev *d;

	if (mk_manifest_phys()) {
		mk_pciback_defer(req, subtype);
		return;
	}

	guard(raw_spinlock_irqsave)(&mk_pciback_lock);

	d = mk_pciback_find(req->sender_instance_id, req->domain, req->bus,
			    req->devfn);
	if (!d) {
		mk_pciback_defer(req, subtype);
		return;
	}

	mk_pciback_do(d, subtype, &ack);
	mk_pciback_answer(d->instance, &ack);
}

static void mk_pciback_msg_handler(u32 msg_type, u32 subtype, u64 msg_id,
				   void *payload, u32 payload_len, void *ctx)
{
	if (payload_len < sizeof(struct mk_pci_cfg_payload))
		return;

	switch (subtype) {
	case MK_PCI_CFG_READ:
	case MK_PCI_CFG_WRITE:
		mk_pciback_request(payload, subtype);
		break;
	case MK_PCI_CFG_ACK:
		mk_request_answer(((struct mk_pci_cfg_payload *)payload)->seq,
				  payload, sizeof(struct mk_pci_cfg_payload));
		break;
	}
}

/**
 * mk_pciback_lend_one - Let a running instance reach a function's config space
 * @instance: The instance
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function
 *
 * Returns: 0 on success, or a negative error code
 */
int mk_pciback_lend_one(struct mk_instance *instance, u16 domain, u8 bus,
			u8 devfn)
{
	struct mk_pciback_dev *d;
	struct pci_dev *pdev;

	pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
	if (!pdev) {
		pr_warn("Instance %d: no PCI function %04x:%02x:%02x.%x here to lend\n",
			instance->id, domain, bus, PCI_SLOT(devfn),
			PCI_FUNC(devfn));
		return -ENODEV;
	}

	d = kzalloc(sizeof(*d), GFP_KERNEL);
	if (!d) {
		pci_dev_put(pdev);
		return -ENOMEM;
	}

	/* Config cycles to a function in D3cold come back as all ones */
	pm_runtime_get_sync(&pdev->dev);

	refcount_set(&d->ref, 1);
	d->pdev = pdev;
	d->sriov = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_SRIOV);
	d->instance = instance;
	mk_instance_get(instance);

	scoped_guard(raw_spinlock_irqsave, &mk_pciback_lock)
		list_add(&d->list, &mk_pciback_devs);
	return 0;
}

static void mk_pciback_free(struct list_head *gone)
{
	struct mk_pciback_dev *d, *tmp;

	list_for_each_entry_safe(d, tmp, gone, list) {
		if (pci_reset_function(d->pdev))
			pci_clear_master(d->pdev);
		mk_pciback_put(d);
	}
}

/**
 * mk_pciback_unlend_one - Take back one function from an instance
 */
void mk_pciback_unlend_one(struct mk_instance *instance, u16 domain, u8 bus,
			   u8 devfn)
{
	struct mk_pciback_dev *d;
	LIST_HEAD(gone);

	scoped_guard(raw_spinlock_irqsave, &mk_pciback_lock) {
		d = mk_pciback_find(instance->id, domain, bus, devfn);
		if (d)
			list_move(&d->list, &gone);
	}
	mk_pciback_free(&gone);
}

/**
 * mk_pciback_unlend - Take back every function an instance could reach
 * @instance: The instance, which no longer runs
 */
void mk_pciback_unlend(struct mk_instance *instance)
{
	struct mk_pciback_dev *d, *tmp;
	LIST_HEAD(gone);

	scoped_guard(raw_spinlock_irqsave, &mk_pciback_lock) {
		list_for_each_entry_safe(d, tmp, &mk_pciback_devs, list) {
			if (d->instance == instance)
				list_move(&d->list, &gone);
		}
	}
	mk_pciback_free(&gone);
}

/**
 * mk_pciback_lend - Let an instance about to start reach its functions
 * @instance: The instance
 *
 * Returns: 0 on success, or a negative error code, in which case nothing
 * is lent and the instance must not be started
 */
int mk_pciback_lend(struct mk_instance *instance)
{
	struct mk_pci_device *dev;
	int ret;

	mk_pciback_unlend(instance);

	if (!instance->pci_devices_valid)
		return 0;

	list_for_each_entry(dev, &instance->pci_devices, list) {
		ret = mk_pciback_lend_one(instance, dev->domain, dev->bus,
					  PCI_DEVFN(dev->slot, dev->func));
		if (ret) {
			mk_pciback_unlend(instance);
			return ret;
		}
	}
	return 0;
}

/* Answers reach a spawn's front end from its first bus scan, at subsys_initcall */
static int __init mk_pciback_init(void)
{
	return mk_register_msg_handler(MK_MSG_PCI, mk_pciback_msg_handler, NULL);
}
arch_initcall(mk_pciback_init);
