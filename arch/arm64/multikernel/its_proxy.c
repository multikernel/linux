// SPDX-License-Identifier: GPL-2.0
/*
 * MSIs for an instance's PCI devices, through the host's ITS.
 *
 * A GICv3 ITS has a single command queue, which belongs to the kernel
 * that booted the machine. An instance therefore cannot map the MSIs of
 * the devices it was given, and asks over the message ring instead:
 *
 *  - MK_IO_MSI_MAP names a device, an event and one of the instance's
 *    CPUs. The host programs the ITS behind the device and answers with
 *    the LPI that will arrive there and the doorbell to write the event
 *    to. The instance asks from process context and sleeps; the host works
 *    in a work item, because the ITS driver sleeps too.
 *  - MK_IO_MSI_MOVE moves a mapped event to another CPU. It comes from an
 *    interrupt chip callback, with the descriptor locked and possibly from
 *    a dying CPU inside stop_machine(), and that CPU may be turned off the
 *    moment the callback returns. So the instance waits for the answer by
 *    polling the ring, and the host moves the event right in its doorbell
 *    interrupt, which takes a cache of what MAP resolved: neither the PCI
 *    device nor the instance can be looked up there.
 *
 * Both answers are MK_IO_MSI_ACK. There is no unmap: the host drops
 * everything when the instance halts, and again before it is started.
 *
 * Both ends live here. The ITS side of the host is its_foreign_*() in the
 * ITS driver, the interrupt domain of the instance is irq-gic-v3-its-mk.
 */

#define pr_fmt(fmt) "mk_its: " fmt

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#define MK_MSI_MAP_TIMEOUT_MS	5000
/* As long as the ITS driver gives one of its own commands */
#define MK_MSI_MOVE_TIMEOUT_US	USEC_PER_SEC
#define MK_MSI_MOVE_POLL_US	10

/*
 * @rid is the device as the instance sees it on its PCI bus, @event the
 * MSI data it will write.
 */
struct mk_io_msi_payload {
	u32 request;            /* MK_IO_MSI_MAP or MK_IO_MSI_MOVE, echoed in the ACK */
	u32 domain;             /* PCI domain */
	u32 rid;                /* bus << 8 | devfn */
	u32 event;
	u64 phys_cpu;           /* Target CPU, one of the sender's */
	u64 doorbell;           /* ACK of a MAP: address the device writes the event to */
	int result;             /* ACK: LPI INTID of a MAP, 0 of a MOVE, or -errno */
	int sender_instance_id;
};

/* An answer belongs to the request it echoes */
static bool mk_msi_same_request(const struct mk_io_msi_payload *a,
				const struct mk_io_msi_payload *b)
{
	return a->request == b->request && a->domain == b->domain &&
	       a->rid == b->rid && a->event == b->event;
}

/*
 * Host side
 */

struct mk_msi_work {
	struct work_struct work;
	struct mk_io_msi_payload req;
};

/* What a MAP resolved about a device, for the MOVEs that follow */
struct mk_msi_route {
	struct list_head list;
	struct mk_instance *instance;
	u32 domain;
	u32 rid;
	struct irq_domain *msi_domain;
	u32 dev_id;
};

static LIST_HEAD(mk_msi_routes);
static DEFINE_RAW_SPINLOCK(mk_msi_routes_lock);

static struct mk_msi_route *mk_msi_find_route(int instance_id, u32 domain, u32 rid)
{
	struct mk_msi_route *route;

	list_for_each_entry(route, &mk_msi_routes, list) {
		if (route->instance->id == instance_id &&
		    route->domain == domain && route->rid == rid)
			return route;
	}
	return NULL;
}

static int mk_msi_remember_route(struct mk_instance *instance,
				 const struct mk_io_msi_payload *req,
				 struct irq_domain *msi_domain, u32 dev_id)
{
	struct mk_msi_route *route;

	scoped_guard(raw_spinlock_irqsave, &mk_msi_routes_lock) {
		if (mk_msi_find_route(instance->id, req->domain, req->rid))
			return 0;
	}

	route = kzalloc_obj(*route);
	if (!route)
		return -ENOMEM;
	route->instance = mk_instance_get(instance);
	route->domain = req->domain;
	route->rid = req->rid;
	route->msi_domain = msi_domain;
	route->dev_id = dev_id;

	/* One work item at a time maps for a device, so nobody got in between */
	scoped_guard(raw_spinlock_irqsave, &mk_msi_routes_lock)
		list_add(&route->list, &mk_msi_routes);
	return 0;
}

/* Every vector the device has: the instance's driver may use any of them */
static u32 mk_msi_max_vectors(struct pci_dev *pdev)
{
	return max3(pci_msix_vec_count(pdev), pci_msi_vec_count(pdev), 1);
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
	u32 dev_id;

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
	dev_id = pci_msi_domain_get_msi_rid(msi_domain, pdev);
	ret = its_foreign_map(instance, msi_domain, dev_id, req->event,
			      mk_msi_max_vectors(pdev), cpu, &doorbell);
	pci_dev_put(pdev);
	if (ret < 0)
		return ret;

	req->doorbell = doorbell;
	return mk_msi_remember_route(instance, req, msi_domain, dev_id) ?: ret;
}

static void mk_msi_map_work(struct work_struct *work)
{
	struct mk_msi_work *w = container_of(work, struct mk_msi_work, work);
	struct mk_io_msi_payload *req = &w->req;
	struct mk_instance *instance;
	int to = req->sender_instance_id;

	instance = mk_instance_find(to);
	req->result = instance ? mk_msi_map_for(instance, req) : -ENOENT;
	if (req->result < 0)
		pr_err("Instance %d: no MSI for %04x:%02x:%02x.%x event %u: %d\n",
		       to, req->domain, req->rid >> 8, PCI_SLOT(req->rid),
		       PCI_FUNC(req->rid), req->event, req->result);

	req->sender_instance_id = mk_self->id;
	if (instance) {
		mk_send_message_to(instance, MK_MSG_IO, MK_IO_MSI_ACK, req,
				   sizeof(*req));
		mk_instance_put(instance);
	}
	kfree(w);
}

/*
 * In the doorbell interrupt. The route keeps the instance alive, and the
 * lock keeps the route: mk_arch_msi_release() takes it to unlink. Without
 * a route there is nobody to answer: the instance never mapped the device,
 * or has halted since, and its request times out.
 */
static void mk_msi_move(const struct mk_io_msi_payload *req)
{
	struct mk_io_msi_payload ack = *req;
	struct mk_msi_route *route;
	int cpu;

	guard(raw_spinlock_irqsave)(&mk_msi_routes_lock);

	route = mk_msi_find_route(req->sender_instance_id, req->domain, req->rid);
	if (!route)
		return;

	cpu = arch_cpu_from_physical_id(req->phys_cpu);
	if (cpu < 0 || !mk_cpu_set_contains(route->instance->cpus, req->phys_cpu))
		ack.result = -EPERM;
	else
		ack.result = its_foreign_move(route->instance, route->msi_domain,
					      route->dev_id, req->event, cpu);

	ack.sender_instance_id = mk_self->id;
	mk_send_message_to(route->instance, MK_MSG_IO, MK_IO_MSI_ACK, &ack,
			   sizeof(ack));
}

void mk_arch_msi_release(struct mk_instance *instance)
{
	struct mk_msi_route *route, *tmp;
	LIST_HEAD(gone);

	scoped_guard(raw_spinlock_irqsave, &mk_msi_routes_lock) {
		list_for_each_entry_safe(route, tmp, &mk_msi_routes, list) {
			if (route->instance == instance)
				list_move(&route->list, &gone);
		}
	}

	list_for_each_entry_safe(route, tmp, &gone, list) {
		mk_instance_put(route->instance);
		kfree(route);
	}

	its_foreign_release(instance);
}

phys_addr_t mk_arch_msi_doorbell(struct pci_dev *pdev)
{
	return its_foreign_doorbell(dev_get_msi_domain(&pdev->dev));
}

/*
 * Instance side
 */

/* On the requester's stack until the answer is in, or given up on */
struct mk_msi_request {
	struct list_head list;
	struct completion done;
	struct mk_io_msi_payload msg;	/* the request, then its answer */
};

static LIST_HEAD(mk_msi_requests);
static DEFINE_RAW_SPINLOCK(mk_msi_requests_lock);

static void mk_msi_answer(const struct mk_io_msi_payload *answer)
{
	struct mk_msi_request *r;

	guard(raw_spinlock_irqsave)(&mk_msi_requests_lock);

	list_for_each_entry(r, &mk_msi_requests, list) {
		if (mk_msi_same_request(&r->msg, answer)) {
			r->msg = *answer;
			complete(&r->done);
			return;
		}
	}
}

static bool mk_msi_wait_sleeping(struct mk_msi_request *r)
{
	return wait_for_completion_timeout(&r->done,
					   msecs_to_jiffies(MK_MSI_MAP_TIMEOUT_MS));
}

/*
 * Nobody may be there to take the doorbell: this CPU has interrupts off,
 * and under stop_machine() so has every other. Drain the ring from here.
 */
static bool mk_msi_wait_polling(struct mk_msi_request *r)
{
	unsigned int waited;

	for (waited = 0; waited < MK_MSI_MOVE_TIMEOUT_US;
	     waited += MK_MSI_MOVE_POLL_US) {
		mk_ipi_poll();
		if (try_wait_for_completion(&r->done))
			return true;
		udelay(MK_MSI_MOVE_POLL_US);
	}
	return false;
}

static int mk_msi_request(struct mk_io_msi_payload *req,
			  bool (*wait)(struct mk_msi_request *r))
{
	struct mk_msi_request r;
	int ret;

	if (!host_instance)
		return -ENODEV;
	req->sender_instance_id = mk_self->id;
	r.msg = *req;
	init_completion(&r.done);

	scoped_guard(raw_spinlock_irqsave, &mk_msi_requests_lock)
		list_add(&r.list, &mk_msi_requests);

	ret = mk_send_message_to(host_instance, MK_MSG_IO, req->request, req,
				 sizeof(*req));
	if (!ret && !wait(&r))
		ret = -ETIMEDOUT;

	/* Off the list before the stack frame goes: a late answer finds nothing */
	scoped_guard(raw_spinlock_irqsave, &mk_msi_requests_lock)
		list_del(&r.list);

	if (ret)
		return ret;
	*req = r.msg;
	return req->result;
}

/**
 * mk_msi_proxy_map - Ask the host to route a device's MSI to a CPU
 * @domain: PCI domain of the device
 * @rid: bus << 8 | devfn
 * @event: MSI data the device will write
 * @phys_cpu: target, one of this kernel's CPUs
 * @doorbell: set to the address to write @event to
 *
 * Sleeps. Returns the interrupt number or a negative error code.
 */
int mk_msi_proxy_map(u32 domain, u32 rid, u32 event, u64 phys_cpu,
		     phys_addr_t *doorbell)
{
	struct mk_io_msi_payload req = {
		.request = MK_IO_MSI_MAP,
		.domain = domain,
		.rid = rid,
		.event = event,
		.phys_cpu = phys_cpu,
	};
	int ret = mk_msi_request(&req, mk_msi_wait_sleeping);

	if (ret >= 0)
		*doorbell = req.doorbell;
	return ret;
}

/**
 * mk_msi_proxy_move - Ask the host to move a routed MSI to another CPU
 * @domain: PCI domain of the device
 * @rid: bus << 8 | devfn
 * @event: event that mk_msi_proxy_map() has routed
 * @phys_cpu: new target, one of this kernel's CPUs
 *
 * Returns once the host has moved it, so the CPU it came from may go
 * away. Any context. Returns 0 or a negative error code.
 */
int mk_msi_proxy_move(u32 domain, u32 rid, u32 event, u64 phys_cpu)
{
	struct mk_io_msi_payload req = {
		.request = MK_IO_MSI_MOVE,
		.domain = domain,
		.rid = rid,
		.event = event,
		.phys_cpu = phys_cpu,
	};

	return mk_msi_request(&req, mk_msi_wait_polling);
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
	case MK_IO_MSI_MOVE:
		mk_msi_move(p);
		break;
	case MK_IO_MSI_ACK:
		mk_msi_answer(p);
		break;
	}
}

static int __init mk_msi_proxy_init(void)
{
	return mk_register_msg_handler(MK_MSG_IO, mk_msi_msg_handler, NULL);
}
fs_initcall(mk_msi_proxy_init);
