// SPDX-License-Identifier: GPL-2.0-only
/*
 * MSIs for an instance's PCI devices, through the host's ITS.
 *
 * A GICv3 ITS has a single command queue, which belongs to the kernel
 * that booted the machine. An instance therefore cannot map the MSIs of
 * the devices it was given, and asks over the message ring instead:
 * MK_IO_MSI_MAP names a device, an event and one of the instance's CPUs,
 * the host programs its ITS and answers with the LPI that will arrive
 * there. The instance writes address and data into the device itself, as
 * it would with an ITS of its own.
 *
 * Both ends live here. The ITS side of the host is its_foreign_*() in the
 * ITS driver, the interrupt domain of the instance is irq-gic-v3-its-mk.
 */

#define pr_fmt(fmt) "mk_its: " fmt

#include <linux/completion.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#define MK_MSI_TIMEOUT_MS	5000

struct mk_msi_work {
	struct work_struct work;
	struct mk_io_msi_payload req;
};

/*
 * A request this kernel waits on. The answer is more than a result code,
 * so it is kept here until the waiter picks it up.
 */
struct mk_msi_request {
	struct list_head list;
	u64 key;
	struct completion done;
	struct mk_io_msi_payload answer;
};

static LIST_HEAD(mk_msi_requests);
static DEFINE_SPINLOCK(mk_msi_requests_lock);

static u64 mk_msi_key(const struct mk_io_msi_payload *p)
{
	return (u64)p->domain << 48 | (u64)p->rid << 32 | p->event;
}

/* Only a device the instance was given, only a CPU it owns */
static int mk_msi_map_for(struct mk_instance *instance,
			  struct mk_io_msi_payload *req)
{
	struct irq_domain *msi_domain;
	struct mk_pci_device *mine;
	phys_addr_t doorbell = 0;
	struct pci_dev *pdev;
	bool owned = false;
	int cpu, ret;

	list_for_each_entry(mine, &instance->pci_devices, list) {
		if (mine->domain == req->domain && mine->bus == req->rid >> 8 &&
		    PCI_DEVFN(mine->slot, mine->func) == (req->rid & 0xff)) {
			owned = true;
			break;
		}
	}
	if (!owned || !mk_cpu_set_contains(instance->cpus, req->phys_cpu))
		return -EPERM;

	cpu = arch_cpu_from_physical_id(req->phys_cpu);
	if (cpu < 0)
		return -EINVAL;

	pdev = pci_get_domain_bus_and_slot(req->domain, req->rid >> 8,
					   req->rid & 0xff);
	if (!pdev)
		return -ENODEV;

	/* The device's MSI domain names the ITS behind it, of possibly several */
	msi_domain = dev_get_msi_domain(&pdev->dev);
	ret = its_foreign_map(instance, msi_domain,
			      pci_msi_domain_get_msi_rid(msi_domain, pdev),
			      req->event, req->nvecs, cpu, &doorbell);
	pci_dev_put(pdev);
	if (ret >= 0)
		req->doorbell = doorbell;
	return ret;
}

/* The ITS driver sleeps, and messages arrive in interrupt context */
static void mk_msi_map_work(struct work_struct *work)
{
	struct mk_msi_work *w = container_of(work, struct mk_msi_work, work);
	struct mk_io_msi_payload *req = &w->req;
	struct mk_instance *instance;
	int to = req->sender_instance_id;

	instance = mk_instance_find(to);
	req->result = instance ? mk_msi_map_for(instance, req) : -ENOENT;
	if (instance)
		mk_instance_put(instance);

	if (req->result < 0)
		pr_err("Instance %d: no MSI for %04x:%02x:%02x.%x event %u: %d\n",
		       to, req->domain, req->rid >> 8, PCI_SLOT(req->rid),
		       PCI_FUNC(req->rid), req->event, req->result);

	req->sender_instance_id = mk_self->id;
	mk_send_message(to, MK_MSG_IO, MK_IO_MSI_ACK, req, sizeof(*req));
	kfree(w);
}

static void mk_msi_answer(const struct mk_io_msi_payload *answer)
{
	struct mk_msi_request *r;
	unsigned long flags;

	spin_lock_irqsave(&mk_msi_requests_lock, flags);
	list_for_each_entry(r, &mk_msi_requests, list) {
		if (r->key == mk_msi_key(answer)) {
			r->answer = *answer;
			complete(&r->done);
			break;
		}
	}
	spin_unlock_irqrestore(&mk_msi_requests_lock, flags);
}

static void mk_msi_msg_handler(u32 msg_type, u32 subtype, void *payload,
			       u32 payload_len, void *ctx)
{
	struct mk_io_msi_payload *p = payload;
	struct mk_msi_work *w;

	if (payload_len < sizeof(*p))
		return;

	switch (subtype) {
	case MK_IO_MSI_MAP:
		w = kzalloc(sizeof(*w), GFP_ATOMIC);
		if (!w)
			return;
		w->req = *p;
		INIT_WORK(&w->work, mk_msi_map_work);
		schedule_work(&w->work);
		break;
	case MK_IO_MSI_ACK:
		mk_msi_answer(p);
		break;
	}
}

/**
 * mk_msi_proxy_map - Ask the host to route a device's MSI to a CPU
 * @domain: PCI domain of the device
 * @rid: bus << 8 | devfn
 * @event: MSI data the device will write
 * @nvecs: events the device may use
 * @phys_cpu: target, one of this kernel's CPUs
 * @doorbell: set to the address to write @event to. NULL moves an event
 *	      that is mapped already without waiting for the answer, from a
 *	      context that cannot sleep
 *
 * Returns the interrupt number (0 when not waiting) or a negative error.
 */
int mk_msi_proxy_map(u32 domain, u32 rid, u32 event, u32 nvecs,
		     mk_phys_cpu_t phys_cpu, phys_addr_t *doorbell)
{
	struct mk_io_msi_payload req = {
		.domain = domain,
		.rid = rid,
		.event = event,
		.nvecs = nvecs,
		.phys_cpu = phys_cpu,
		.sender_instance_id = mk_self->id,
	};
	struct mk_msi_request *r;
	unsigned long flags;
	int ret;

	if (!doorbell)
		return mk_send_message(0, MK_MSG_IO, MK_IO_MSI_MAP, &req,
				       sizeof(req));

	r = kzalloc_obj(*r);
	if (!r)
		return -ENOMEM;
	r->key = mk_msi_key(&req);
	init_completion(&r->done);

	spin_lock_irqsave(&mk_msi_requests_lock, flags);
	list_add(&r->list, &mk_msi_requests);
	spin_unlock_irqrestore(&mk_msi_requests_lock, flags);

	ret = mk_send_message(0, MK_MSG_IO, MK_IO_MSI_MAP, &req, sizeof(req));
	if (!ret && !wait_for_completion_timeout(&r->done,
						 msecs_to_jiffies(MK_MSI_TIMEOUT_MS)))
		ret = -ETIMEDOUT;

	/* Off the list before the answer is read: a late one must not land in it */
	spin_lock_irqsave(&mk_msi_requests_lock, flags);
	list_del(&r->list);
	spin_unlock_irqrestore(&mk_msi_requests_lock, flags);

	if (!ret) {
		ret = r->answer.result;
		*doorbell = r->answer.doorbell;
	}
	kfree(r);
	return ret;
}

void mk_msi_proxy_release(struct mk_instance *instance)
{
	its_foreign_release(instance);
}

phys_addr_t mk_msi_proxy_doorbell(struct pci_dev *pdev)
{
	return its_foreign_doorbell(dev_get_msi_domain(&pdev->dev));
}

static int __init mk_msi_proxy_init(void)
{
	return mk_register_msg_handler(MK_MSG_IO, mk_msi_msg_handler, NULL);
}
fs_initcall(mk_msi_proxy_init);
