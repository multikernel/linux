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
 * Both answers are MK_IO_MSI_ACK. There is no unmap: what the host maps
 * for a device, its events and the doorbell window in the device's IOMMU
 * domain, is part of the instance's lease on the device and goes with it.
 *
 * Both ends live here. The ITS side of the host is its_foreign_*() in the
 * ITS driver, the interrupt domain of the instance is irq-gic-v3-its-mk.
 *
 * An instance that takes over from its host claims the host's ITSes and
 * becomes the one that maps: its own requests are then served right here,
 * as are those of the instances it spawns. Whatever the host had mapped for
 * it is mapped again at the same LPIs, so neither its devices nor its
 * interrupt descriptors notice.
 */

#define pr_fmt(fmt) "mk_its: " fmt

#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqdomain.h>
#include <linux/msi.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "internal.h"

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

/*
 * What a MAP resolved about a device, for the MOVEs that follow. The ITS
 * holds the device's events under the lease, which they end with.
 */
struct mk_msi_route {
	struct list_head list;
	struct mk_instance *instance;
	struct mk_lease *lease;
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

static void mk_msi_drop_route(void *data)
{
	struct mk_msi_route *route = data;

	scoped_guard(raw_spinlock_irqsave, &mk_msi_routes_lock)
		list_del(&route->list);
	its_foreign_unmap(route->lease, route->msi_domain, route->dev_id);
	mk_instance_put(route->instance);
	kfree(route);
}

/*
 * At the first MAP of a device in a lease, before the ITS has anything of
 * it, so that whatever the ITS ends up holding goes with the lease.
 */
static int mk_msi_add_route(struct mk_instance *instance, struct pci_dev *pdev,
			    struct mk_lease *lease,
			    const struct mk_io_msi_payload *req,
			    struct irq_domain *msi_domain, u32 dev_id)
{
	struct mk_msi_route *route;

	route = kzalloc_obj(*route);
	if (!route)
		return -ENOMEM;
	route->instance = mk_instance_get(instance);
	route->lease = lease;
	route->domain = req->domain;
	route->rid = req->rid;
	route->msi_domain = msi_domain;
	route->dev_id = dev_id;

	scoped_guard(raw_spinlock_irqsave, &mk_msi_routes_lock)
		list_add(&route->list, &mk_msi_routes);

	return devm_add_action_or_reset(&pdev->dev, mk_msi_drop_route, route);
}

/* Every vector the device has: the instance's driver may use any of them */
static u32 mk_msi_max_vectors(struct pci_dev *pdev)
{
	return max3(pci_msix_vec_count(pdev), pci_msi_vec_count(pdev), 1);
}

/*
 * The ITS behind a device, of possibly several, and its DeviceID there: as
 * the firmware says, through the device's MSI domain, unless this kernel
 * took the ITS over from its host and has only the host's word for it.
 */
void mk_msi_resolve(struct pci_dev *pdev, struct irq_domain **its, u32 *dev_id)
{
	if (!mk_its_lookup(pci_domain_nr(pdev->bus), pci_dev_id(pdev), its,
			   dev_id))
		return;
	*its = dev_get_msi_domain(&pdev->dev);
	*dev_id = pci_msi_domain_get_msi_rid(*its, pdev);
}

/* Only a device the instance holds a lease on, only a CPU it owns */
static int mk_msi_map_for(struct mk_instance *instance,
			  struct mk_io_msi_payload *req)
{
	struct irq_domain *msi_domain;
	phys_addr_t doorbell = 0;
	struct mk_lease *lease;
	struct pci_dev *pdev;
	bool first;
	int cpu, lpi, ret;
	u32 dev_id;

	if (!mk_cpu_set_contains(instance->cpus, req->phys_cpu))
		return -EPERM;

	cpu = arch_cpu_from_physical_id(req->phys_cpu);
	if (cpu < 0)
		return -EINVAL;

	pdev = pci_get_domain_bus_and_slot(req->domain, req->rid >> 8,
					   req->rid & 0xff);
	if (!pdev)
		return -ENODEV;

	/* Held across the mapping, so that nothing is mapped after the lease */
	lease = mk_lease_lock(instance, pdev);
	if (!lease) {
		ret = -EPERM;
		goto put;
	}

	mk_msi_resolve(pdev, &msi_domain, &dev_id);

	scoped_guard(raw_spinlock_irqsave, &mk_msi_routes_lock)
		first = !mk_msi_find_route(instance->id, req->domain, req->rid);
	if (first) {
		ret = mk_msi_add_route(instance, pdev, lease, req, msi_domain,
				       dev_id);
		if (ret)
			goto unlock;
	}

	lpi = its_foreign_map(lease, msi_domain, dev_id, req->event,
			      mk_msi_max_vectors(pdev), cpu, &doorbell);
	if (lpi < 0) {
		ret = lpi;
		goto unlock;
	}

	/* Before the ACK, which the instance waits for to program the vector */
	ret = mk_lease_allow_msi(lease, doorbell) ?: lpi;
	req->doorbell = doorbell;

unlock:
	mk_lease_unlock(lease);
put:
	pci_dev_put(pdev);
	return ret;
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
 * lock keeps the route: the end of the lease takes it to unlink. Without
 * a route there is nobody to answer: the instance never mapped the device,
 * or no longer holds it, and its request times out.
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
		ack.result = its_foreign_move(route->lease, route->msi_domain,
					      route->dev_id, req->event, cpu);

	ack.sender_instance_id = mk_self->id;
	mk_send_message_to(route->instance, MK_MSG_IO, MK_IO_MSI_ACK, &ack,
			   sizeof(ack));
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
	struct mk_instance *host;
	int ret;

	/* A fenced host never answers */
	host = READ_ONCE(host_instance);
	if (!host || mk_host_fenced())
		return -ENODEV;
	req->sender_instance_id = mk_self->id;
	r.msg = *req;
	init_completion(&r.done);

	scoped_guard(raw_spinlock_irqsave, &mk_msi_requests_lock)
		list_add(&r.list, &mk_msi_requests);

	ret = mk_send_message_to(host, MK_MSG_IO, req->request, req,
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

/*
 * Every bus of an instance is one of pcifront's, and every MSI of it goes
 * through the proxy, the host picking the ITS behind each device at MAP
 * time. So the proxy is the MSI domain of each bridge pcifront creates,
 * at boot or later, rather than something the tree says bus by bus.
 */
int mk_arch_pcifront_prepare(struct pci_host_bridge *bridge, int domain)
{
	struct irq_domain *msi_domain = NULL;
	struct device_node *np;

	np = of_find_compatible_node(NULL, NULL, MK_ITS_PROXY_COMPATIBLE);
	if (np) {
		msi_domain = irq_find_matching_fwnode(of_fwnode_handle(np),
						      DOMAIN_BUS_PCI_MSI);
		of_node_put(np);
	}
	if (msi_domain)
		dev_set_msi_domain(&bridge->dev, msi_domain);
	return 0;
}

/*
 * Every event mapped for this kernel: by the host, or by this kernel once
 * it owns the ITS. The mutex orders mappings against a claim, the lock
 * guards the fields for moves, which may not sleep.
 */
struct mk_msi_mapping {
	struct list_head list;
	u32 domain;
	u32 rid;
	u32 event;
	u32 lpi;
	unsigned int cpu;
	struct irq_domain *its;		/* once this kernel owns the ITS */
	u32 dev_id;
};

static LIST_HEAD(mk_msi_mappings);
static DEFINE_MUTEX(mk_msi_mappings_mutex);
static DEFINE_RAW_SPINLOCK(mk_msi_mappings_lock);

/* What this kernel holds its own devices under in its ITS */
static char mk_msi_self;

static struct mk_msi_mapping *mk_msi_find_mapping(u32 domain, u32 rid, u32 event)
{
	struct mk_msi_mapping *m;

	list_for_each_entry(m, &mk_msi_mappings, list)
		if (m->domain == domain && m->rid == rid && m->event == event)
			return m;
	return NULL;
}

static int mk_msi_map_local(struct irq_domain *its, u32 dev_id, u32 domain,
			    u32 rid, u32 event, unsigned int cpu,
			    phys_addr_t *doorbell)
{
	struct pci_dev *pdev;
	int lpi;

	pdev = pci_get_domain_bus_and_slot(domain, rid >> 8, rid & 0xff);
	if (!pdev)
		return -ENODEV;
	lpi = its_foreign_map(&mk_msi_self, its, dev_id, event,
			      mk_msi_max_vectors(pdev), cpu, doorbell);
	pci_dev_put(pdev);
	return lpi;
}

static int mk_msi_map_remote(u32 domain, u32 rid, u32 event, u64 phys_cpu,
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
 * mk_msi_proxy_map - Have a device's MSI routed to a CPU
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
	int cpu = arch_cpu_from_physical_id(phys_cpu);
	struct irq_domain *its = NULL;
	struct mk_msi_mapping *m, *new;
	u32 dev_id = 0;
	int lpi;

	if (cpu < 0)
		return -EINVAL;
	new = kzalloc_obj(*new);
	if (!new)
		return -ENOMEM;

	guard(mutex)(&mk_msi_mappings_mutex);

	if (!mk_its_lookup(domain, rid, &its, &dev_id))
		lpi = mk_msi_map_local(its, dev_id, domain, rid, event, cpu,
				       doorbell);
	else
		lpi = mk_msi_map_remote(domain, rid, event, phys_cpu, doorbell);
	if (lpi < 0) {
		kfree(new);
		return lpi;
	}

	scoped_guard(raw_spinlock_irqsave, &mk_msi_mappings_lock) {
		m = mk_msi_find_mapping(domain, rid, event);
		if (!m) {
			m = new;
			new = NULL;
			m->domain = domain;
			m->rid = rid;
			m->event = event;
			list_add(&m->list, &mk_msi_mappings);
		}
		m->lpi = lpi;
		m->cpu = cpu;
		m->its = its;
		m->dev_id = dev_id;
	}
	kfree(new);
	return lpi;
}

/**
 * mk_msi_proxy_move - Have a routed MSI moved to another CPU
 * @domain: PCI domain of the device
 * @rid: bus << 8 | devfn
 * @event: event that mk_msi_proxy_map() has routed
 * @phys_cpu: new target, one of this kernel's CPUs
 *
 * Returns once it has moved, so the CPU it came from may go away. Any
 * context. Returns 0 or a negative error code.
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
	int cpu = arch_cpu_from_physical_id(phys_cpu);
	struct mk_msi_mapping *m;
	int ret;

	if (cpu < 0)
		return -EINVAL;

	scoped_guard(raw_spinlock_irqsave, &mk_msi_mappings_lock) {
		m = mk_msi_find_mapping(domain, rid, event);
		if (m && m->its) {
			ret = its_foreign_move(&mk_msi_self, m->its, m->dev_id,
					       event, cpu);
			if (!ret)
				m->cpu = cpu;
			return ret;
		}
	}

	ret = mk_msi_request(&req, mk_msi_wait_polling);
	if (ret)
		return ret;

	guard(raw_spinlock_irqsave)(&mk_msi_mappings_lock);
	m = mk_msi_find_mapping(domain, rid, event);
	if (m)
		m->cpu = cpu;
	return 0;
}

/**
 * mk_msi_proxy_unmap - A device no longer has MSIs
 * @domain: PCI domain of the device
 * @rid: bus << 8 | devfn
 *
 * What this kernel mapped in its own ITS goes, so that the device can be
 * lent to an instance. What the host mapped stays the host's to drop.
 */
void mk_msi_proxy_unmap(u32 domain, u32 rid)
{
	struct mk_msi_mapping *m, *tmp;
	struct irq_domain *its = NULL;
	u32 dev_id = 0;

	guard(mutex)(&mk_msi_mappings_mutex);

	list_for_each_entry_safe(m, tmp, &mk_msi_mappings, list) {
		if (m->domain != domain || m->rid != rid || !m->its)
			continue;
		its = m->its;
		dev_id = m->dev_id;
		scoped_guard(raw_spinlock_irqsave, &mk_msi_mappings_lock)
			list_del(&m->list);
		kfree(m);
	}
	if (its)
		its_foreign_unmap(&mk_msi_self, its, dev_id);
}

/*
 * After a claim: map everything the host had mapped for this kernel, now
 * in the ITS this kernel owns, at the same LPIs and to the same CPUs.
 */
void mk_msi_proxy_rebind(void)
{
	struct irq_domain *its = NULL;
	struct mk_msi_mapping *m;
	struct pci_dev *pdev;
	u32 dev_id;
	int ret;

	guard(mutex)(&mk_msi_mappings_mutex);

	list_for_each_entry(m, &mk_msi_mappings, list) {
		if (m->its || mk_its_lookup(m->domain, m->rid, &its, &dev_id))
			continue;
		pdev = pci_get_domain_bus_and_slot(m->domain, m->rid >> 8,
						   m->rid & 0xff);
		ret = pdev ? its_foreign_keep(&mk_msi_self, its, dev_id, m->event,
					      mk_msi_max_vectors(pdev), m->cpu,
					      m->lpi) : -ENODEV;
		pci_dev_put(pdev);
		if (ret) {
			pr_warn("%04x:%02x:%02x.%d: event %u lost LPI %u: %d\n",
				m->domain, m->rid >> 8, PCI_SLOT(m->rid),
				PCI_FUNC(m->rid), m->event, m->lpi, ret);
			continue;
		}
		scoped_guard(raw_spinlock_irqsave, &mk_msi_mappings_lock) {
			m->its = its;
			m->dev_id = dev_id;
		}
	}
}

static void mk_msi_msg_handler(struct mk_instance *from, u32 msg_type, u32 subtype,
			       void *payload, u32 payload_len, void *ctx)
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
