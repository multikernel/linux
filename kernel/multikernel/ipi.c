// SPDX-License-Identifier: GPL-2.0-only
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/ratelimit.h>
#include <linux/rculist.h>
#include <linux/smp.h>
#include "internal.h"

static struct mk_ipi_handler *mk_handlers;
static DEFINE_RAW_SPINLOCK(mk_handlers_lock);
static LIST_HEAD(mk_ipi_endpoints);
static DEFINE_RAW_SPINLOCK(mk_ipi_endpoints_lock);
static bool mk_handlers_ready;
static DEFINE_RATELIMIT_STATE(mk_ipi_full_rs, DEFAULT_RATELIMIT_INTERVAL,
			      DEFAULT_RATELIMIT_BURST);

static struct mk_shared_data *mk_instance_ipi_area(struct mk_instance *instance)
{
	return READ_ONCE(instance->ipi_data);
}

struct mk_shared_data *mk_instance_halt_data(struct mk_instance *instance)
{
	struct mk_shared_data *shared = READ_ONCE(instance->halt_data);

	return shared ? shared : mk_instance_ipi_area(instance);
}

int mk_ipi_endpoint_init(struct mk_instance *instance, bool parent_side)
{
	struct mk_ipi_endpoint *endpoint = &instance->ipi_endpoint;
	unsigned long flags;

	if (!mk_instance_ipi_area(instance))
		return -ENODEV;
	if (endpoint->registered)
		return 0;
	endpoint->tx = parent_side ? &instance->ipi_data->to_child :
				     &instance->ipi_data->to_parent;
	endpoint->rx = parent_side ? &instance->ipi_data->to_parent :
				     &instance->ipi_data->to_child;
	endpoint->tx_head = 0;
	endpoint->rx_tail = 0;
	endpoint->tx_enabled = true;
	endpoint->rx_dispatching = false;
	endpoint->parent_side = parent_side;
	raw_spin_lock_irqsave(&mk_ipi_endpoints_lock, flags);
	list_add_tail_rcu(&endpoint->rx_node, &mk_ipi_endpoints);
	endpoint->registered = true;
	raw_spin_unlock_irqrestore(&mk_ipi_endpoints_lock, flags);
	return 0;
}

void mk_ipi_endpoint_close(struct mk_instance *instance)
{
	struct mk_ipi_endpoint *endpoint = &instance->ipi_endpoint;
	unsigned long flags;

	if (!endpoint->registered)
		return;
	raw_spin_lock_irqsave(&endpoint->tx_lock, flags);
	endpoint->tx_enabled = false;
	raw_spin_unlock_irqrestore(&endpoint->tx_lock, flags);
}

void mk_ipi_endpoint_unregister(struct mk_instance *instance)
{
	struct mk_ipi_endpoint *endpoint = &instance->ipi_endpoint;
	unsigned long flags;

	if (!endpoint->registered)
		return;
	mk_ipi_endpoint_close(instance);
	raw_spin_lock_irqsave(&mk_ipi_endpoints_lock, flags);
	if (endpoint->registered) {
		list_del_rcu(&endpoint->rx_node);
		endpoint->registered = false;
	}
	raw_spin_unlock_irqrestore(&mk_ipi_endpoints_lock, flags);
	synchronize_rcu();
}

void mk_ipi_link_reset(struct mk_instance *instance, int parent_id,
		       int child_id, mk_phys_cpu_t parent_cpu,
		       mk_phys_cpu_t child_cpu)
{
	struct mk_shared_data *shared = mk_instance_ipi_area(instance);

	if (!shared)
		return;
	mk_ipi_endpoint_unregister(instance);
	mk_shared_data_reset(shared);
	WRITE_ONCE(shared->parent_id, parent_id);
	WRITE_ONCE(shared->child_id, child_id);
	WRITE_ONCE(shared->parent_doorbell_cpu, parent_cpu);
	WRITE_ONCE(shared->child_doorbell_cpu, child_cpu);
	mk_ipi_endpoint_init(instance, true);
}

struct mk_ipi_handler *
multikernel_register_handler(mk_ipi_callback_t callback, void *ctx,
			     unsigned int ipi_type)
{
	struct mk_ipi_handler *handler;
	unsigned long flags;

	if (!callback)
		return NULL;
	handler = kzalloc(sizeof(*handler), GFP_KERNEL);
	if (!handler)
		return NULL;
	handler->callback = callback;
	handler->context = ctx;
	handler->ipi_type = ipi_type;
	raw_spin_lock_irqsave(&mk_handlers_lock, flags);
	handler->next = mk_handlers;
	mk_handlers = handler;
	raw_spin_unlock_irqrestore(&mk_handlers_lock, flags);
	return handler;
}
EXPORT_SYMBOL(multikernel_register_handler);

void multikernel_unregister_handler(struct mk_ipi_handler *handler)
{
	struct mk_ipi_handler **pp, *p = NULL;
	unsigned long flags;

	if (!handler)
		return;
	raw_spin_lock_irqsave(&mk_handlers_lock, flags);
	for (pp = &mk_handlers; (p = *pp); pp = &p->next) {
		if (p == handler) {
			*pp = p->next;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&mk_handlers_lock, flags);
	kfree(p);
}
EXPORT_SYMBOL(multikernel_unregister_handler);

int mk_arm_force_halt(struct mk_instance *instance)
{
	struct mk_shared_data *shared = mk_instance_halt_data(instance);

	if (!shared)
		return -ENODEV;
	WRITE_ONCE(shared->force_halt, 1);
	smp_wmb();
	return 0;
}

int mk_send_ipi_data(struct mk_instance *instance, void *data,
		     size_t data_size, unsigned long type)
{
	struct mk_ipi_endpoint *endpoint;
	struct mk_ipi_data *slot;
	struct mk_shared_data *shared;
	mk_phys_cpu_t target;
	unsigned long flags;
	u32 idx;
	int ret = 0;

	if (!instance || data_size > MK_MAX_DATA_SIZE || (data_size && !data))
		return -EINVAL;
	endpoint = &instance->ipi_endpoint;
	if (!READ_ONCE(endpoint->registered))
		return -ESHUTDOWN;
	raw_spin_lock_irqsave(&endpoint->tx_lock, flags);
	if (!READ_ONCE(endpoint->registered) || !endpoint->tx_enabled) {
		ret = -ESHUTDOWN;
		goto unlock;
	}
	shared = READ_ONCE(instance->ipi_data);
	if (!shared) {
		ret = -ENODEV;
		goto unlock;
	}
	target = endpoint->parent_side ? mk_cpu_set_first(instance->cpus) :
		 READ_ONCE(shared->parent_doorbell_cpu);
	if (target == MK_PHYS_CPU_INVALID) {
		ret = -ENODEV;
		goto unlock;
	}
	if (endpoint->parent_side)
		WRITE_ONCE(shared->child_doorbell_cpu, target);
	idx = endpoint->tx_head & (MK_IPI_RING_SIZE - 1);
	slot = &endpoint->tx->entries[idx];
	/* Pair with the receiver's release when it makes the slot reusable. */
	if (smp_load_acquire(&slot->ready)) {
		ret = -ENOSPC;
		goto unlock;
	}
	WRITE_ONCE(slot->sender_cpu, arch_cpu_physical_id(smp_processor_id()));
	WRITE_ONCE(slot->type, type);
	WRITE_ONCE(slot->data_size, data_size);
	if (data_size)
		memcpy(slot->buffer, data, data_size);
	/* Publish all message fields before the receiver observes readiness. */
	smp_store_release(&slot->ready, 1);
	endpoint->tx_head++;
unlock:
	raw_spin_unlock_irqrestore(&endpoint->tx_lock, flags);
	if (!ret)
		mk_arch_send_ipi(target);
	else if (ret == -ENOSPC && __ratelimit(&mk_ipi_full_rs))
		printk_deferred(KERN_WARNING
				"multikernel: IPI ring full for instance %d\n",
				instance->id);
	return ret;
}

int multikernel_send_ipi_data(int instance_id, void *data, size_t data_size,
			      unsigned long type)
{
	struct mk_instance *instance = mk_instance_find(instance_id);
	int ret;

	if (!instance)
		return -EINVAL;
	ret = mk_send_ipi_data(instance, data, data_size, type);
	mk_instance_put(instance);
	return ret;
}

int multikernel_send_ipi_data_to_host(void *data, size_t data_size,
				      unsigned long type)
{
	struct mk_instance *instance = READ_ONCE(host_instance);

	if (!instance)
		return -ENODEV;
	return mk_send_ipi_data(instance, data, data_size, type);
}
EXPORT_SYMBOL(multikernel_send_ipi_data_to_host);

static void mk_ipi_dispatch(struct mk_ipi_data *slot)
{
	struct mk_ipi_handler *handler;
	mk_ipi_callback_t callback = NULL;
	void *context = NULL;
	unsigned long flags;

	if (READ_ONCE(slot->data_size) > MK_MAX_DATA_SIZE)
		return;
	raw_spin_lock_irqsave(&mk_handlers_lock, flags);
	for (handler = mk_handlers; handler; handler = handler->next) {
		if (handler->ipi_type == READ_ONCE(slot->type)) {
			callback = handler->callback;
			context = handler->context;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&mk_handlers_lock, flags);
	if (callback)
		callback(slot, context);
}

static void mk_ipi_drain_endpoint(struct mk_ipi_endpoint *endpoint)
{
	struct mk_ipi_data *slot;
	unsigned long flags;
	u32 idx;

	raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
	if (endpoint->rx_dispatching) {
		raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
		return;
	}
	endpoint->rx_dispatching = true;
	raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
	for (;;) {
		idx = endpoint->rx_tail & (MK_IPI_RING_SIZE - 1);
		slot = &endpoint->rx->entries[idx];
		/* Pair with the producer's release publication of this slot. */
		if (!smp_load_acquire(&slot->ready)) {
			raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
			endpoint->rx_dispatching = false;
			/* Close the empty-ring handoff race with a new publication. */
			if (smp_load_acquire(&slot->ready)) {
				endpoint->rx_dispatching = true;
				raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
				continue;
			}
			raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
			return;
		}
		mk_ipi_dispatch(slot);
		/* The callback must finish reading before the slot is reusable. */
		smp_store_release(&slot->ready, 0);
		endpoint->rx_tail++;
	}
}

static void mk_ipi_drain_all(void)
{
	struct mk_ipi_endpoint *endpoint;

	if (!READ_ONCE(mk_handlers_ready))
		return;
	rcu_read_lock();
	list_for_each_entry_rcu(endpoint, &mk_ipi_endpoints, rx_node)
		mk_ipi_drain_endpoint(endpoint);
	rcu_read_unlock();
}

void mk_ipi_handlers_enable(void)
{
	WRITE_ONCE(mk_handlers_ready, true);
	mk_ipi_drain_all();
}

void mk_poll_ipi_messages(void)
{
	unsigned long flags;

	local_irq_save(flags);
	mk_ipi_drain_all();
	local_irq_restore(flags);
}

void generic_multikernel_interrupt(void)
{
	mk_ipi_drain_all();
}

/**
 * mk_has_pending_shutdown - Check if the host demanded a forcible shutdown
 *
 * Tests the force-halt marker the host arms before NMIing this kernel's
 * CPUs. The marker used to be a message peeked in the IPI ring, but a
 * ring message is consumed by the doorbell interrupt: on a responsive
 * kernel the ordinary message path could eat it before the NMIs landed,
 * and every NMI then found nothing to act on. The marker is host-owned
 * and stays up until the host has confirmed all CPUs parked, so it
 * gives the same answer no matter when each NMI arrives.
 *
 * A spawn kernel that has no ring cannot be asked anything, so an NMI
 * no local source claims is the only voice the host has left; it is
 * taken as the demand (the caller sits on the unknown-NMI chain). A
 * host without a pool has no ring either, but its NMIs are its own.
 *
 * Safe to call from NMI context (a single read of shared memory).
 *
 * Returns: true if shutdown requested, false otherwise
 */
bool mk_has_pending_shutdown(void)
{
	if (!mk_self)
		return false;

	if (!mk_self->ipi_data)
		return mk_manifest_phys() != 0;

	return READ_ONCE(mk_self->ipi_data->force_halt);
}
