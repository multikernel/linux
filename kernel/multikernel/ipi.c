// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/multikernel.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include "internal.h"

#define MK_IPI_ENDPOINT_BATCH 8
#define MK_IPI_LINK_BUDGET 8

static LIST_HEAD(mk_handlers);
static DEFINE_RAW_SPINLOCK(mk_handlers_lock);

static LIST_HEAD(mk_ipi_endpoints);
static DEFINE_RAW_SPINLOCK(mk_ipi_endpoints_lock);
static struct list_head *mk_ipi_cursor = &mk_ipi_endpoints;
static unsigned int mk_ipi_endpoint_count;
static bool mk_handlers_ready;
static DEFINE_PER_CPU(bool, mk_draining);

static inline unsigned int mk_ring_idx(unsigned int index)
{
	return index & (MK_IPI_RING_SIZE - 1);
}

static noinline void mk_ipi_kick_local(void)
{
	mk_arch_send_ipi(arch_cpu_physical_id(0));
}

static void mk_ipi_ring_reset(struct mk_ipi_ring *ring)
{
	unsigned int i;

	for (i = 0; i < MK_IPI_RING_SIZE; i++)
		WRITE_ONCE(ring->entries[i].ready, 0);
}

static void mk_shared_data_reset(struct mk_shared_data *shared)
{
	mk_ipi_ring_reset(&shared->to_child);
	mk_ipi_ring_reset(&shared->to_parent);
	WRITE_ONCE(shared->force_halt, 0);
	memset(shared->parked, 0, sizeof(shared->parked));
}

struct mk_shared_data *mk_instance_halt_data(struct mk_instance *instance)
{
	struct mk_shared_data *shared = READ_ONCE(instance->halt_data);

	return shared ? shared : READ_ONCE(instance->ipi_data);
}

/**
 * mk_ipi_endpoint_register - Publish one side of a duplex IPI link
 * @instance: Record for the peer at the other end of the link
 * @parent_side: True in the parent kernel, false in its child
 * @doorbell_cpu: Stable physical CPU to notify in the peer
 *
 * Ordinary detach and re-registration preserve the local ring indices.
 */
int mk_ipi_endpoint_register(struct mk_instance *instance, bool parent_side,
			     mk_phys_cpu_t doorbell_cpu)
{
	struct mk_ipi_endpoint *endpoint;
	struct mk_shared_data *shared;
	unsigned long flags;

	if (!instance || doorbell_cpu == MK_PHYS_CPU_INVALID)
		return -EINVAL;
	shared = READ_ONCE(instance->ipi_data);
	if (!shared)
		return -ENODEV;

	endpoint = &instance->ipi_endpoint;
	if (WARN_ON_ONCE(READ_ONCE(endpoint->registered)))
		return -EALREADY;

	raw_spin_lock_irqsave(&endpoint->tx_lock, flags);
	endpoint->tx = parent_side ? &shared->to_child : &shared->to_parent;
	endpoint->doorbell_cpu = doorbell_cpu;
	endpoint->tx_enabled = true;
	raw_spin_unlock_irqrestore(&endpoint->tx_lock, flags);

	raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
	endpoint->rx = parent_side ? &shared->to_parent : &shared->to_child;
	endpoint->rx_dispatching = false;
	raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);

	raw_spin_lock_irqsave(&mk_ipi_endpoints_lock, flags);
	INIT_LIST_HEAD(&endpoint->rx_node);
	list_add_tail_rcu(&endpoint->rx_node, &mk_ipi_endpoints);
	WRITE_ONCE(endpoint->registered, true);
	mk_ipi_endpoint_count++;
	raw_spin_unlock_irqrestore(&mk_ipi_endpoints_lock, flags);

	/* Pairs with the handler publication in mk_ipi_handlers_enable(). */
	if (smp_load_acquire(&mk_handlers_ready))
		mk_ipi_kick_local();
	return 0;
}

/**
 * mk_ipi_endpoint_unregister - Stop and unpublish a duplex endpoint
 * @instance: Peer record whose endpoint is being detached
 *
 * Must be called from process context and never from an IPI callback. The
 * function waits for senders and hardirq callbacks that already found the
 * endpoint before returning. Local ring indices are preserved for reattach.
 */
void mk_ipi_endpoint_unregister(struct mk_instance *instance)
{
	struct mk_ipi_endpoint *endpoint;
	unsigned long flags;
	bool removed = false;

	if (!instance)
		return;
	endpoint = &instance->ipi_endpoint;

	raw_spin_lock_irqsave(&endpoint->tx_lock, flags);
	endpoint->tx_enabled = false;
	raw_spin_unlock_irqrestore(&endpoint->tx_lock, flags);

	raw_spin_lock_irqsave(&mk_ipi_endpoints_lock, flags);
	if (endpoint->registered) {
		if (mk_ipi_cursor == &endpoint->rx_node)
			mk_ipi_cursor = endpoint->rx_node.prev;
		list_del_rcu(&endpoint->rx_node);
		WRITE_ONCE(endpoint->registered, false);
		mk_ipi_endpoint_count--;
		removed = true;
	}
	raw_spin_unlock_irqrestore(&mk_ipi_endpoints_lock, flags);

	if (!removed)
		return;

	synchronize_rcu();

	raw_spin_lock_irqsave(&endpoint->tx_lock, flags);
	endpoint->tx = NULL;
	raw_spin_unlock_irqrestore(&endpoint->tx_lock, flags);
	raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
	endpoint->rx = NULL;
	raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
	INIT_LIST_HEAD(&endpoint->rx_node);
}

/**
 * mk_ipi_link_reset - Start a confirmed-stopped peer link at generation zero
 * @instance: Peer whose CPUs are parked and endpoint is detached
 *
 * Returns 0 on success or a negative error when the reset preconditions are
 * not met.
 */
int mk_ipi_link_reset(struct mk_instance *instance)
{
	struct mk_ipi_endpoint *endpoint;
	struct mk_shared_data *shared;
	unsigned long flags;

	if (!instance)
		return -EINVAL;
	endpoint = &instance->ipi_endpoint;
	shared = READ_ONCE(instance->ipi_data);
	if (!shared)
		return -ENODEV;

	if (WARN_ON_ONCE(READ_ONCE(endpoint->registered)))
		return -EBUSY;
	raw_spin_lock_irqsave(&endpoint->tx_lock, flags);
	raw_spin_lock(&endpoint->rx_lock);
	mk_shared_data_reset(shared);
	endpoint->tx_head = 0;
	endpoint->rx_tail = 0;
	endpoint->rx_dispatching = false;
	raw_spin_unlock(&endpoint->rx_lock);
	raw_spin_unlock_irqrestore(&endpoint->tx_lock, flags);
	return 0;
}

/**
 * multikernel_register_handler - Register a hardirq IPI callback
 * @callback: Atomic callback invoked directly from the IPI handler
 * @ctx: Opaque callback context
 * @ipi_type: Message type delivered to the callback
 *
 * The callback must not sleep and must not unregister itself.
 */
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
	list_add_rcu(&handler->node, &mk_handlers);
	raw_spin_unlock_irqrestore(&mk_handlers_lock, flags);
	return handler;
}
EXPORT_SYMBOL(multikernel_register_handler);

/**
 * multikernel_unregister_handler - Unregister an IPI callback
 * @handler: Handler returned by multikernel_register_handler()
 *
 * Must be called from process context and outside the callback. It waits for
 * hardirq readers that may still be using the callback and its context.
 */
void multikernel_unregister_handler(struct mk_ipi_handler *handler)
{
	unsigned long flags;

	if (!handler)
		return;
	raw_spin_lock_irqsave(&mk_handlers_lock, flags);
	list_del_rcu(&handler->node);
	raw_spin_unlock_irqrestore(&mk_handlers_lock, flags);
	synchronize_rcu();
	kfree(handler);
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

/**
 * mk_ipi_send - Queue data on a peer's duplex link
 * @peer: Referenced peer, or NULL for lookup by ID
 * @instance_id: Peer instance ID
 * @data: Payload, or NULL for a zero-length message
 * @data_size: Payload size
 * @type: Message type
 *
 * Safe in IRQ-disabled and hardirq contexts. Endpoint lookup is RCU-protected
 * and publication is serialized per link direction.
 */
static int mk_ipi_send(struct mk_instance *peer, int instance_id, void *data,
		       size_t data_size, unsigned long type)
{
	struct mk_ipi_endpoint *endpoint;
	struct mk_ipi_data *slot;
	mk_phys_cpu_t target = MK_PHYS_CPU_INVALID;
	unsigned long flags;
	int ret = -ENODEV;
	u32 index;

	if (data_size > MK_MAX_DATA_SIZE || (data_size && !data))
		return -EINVAL;

	rcu_read_lock();
	list_for_each_entry_rcu(endpoint, &mk_ipi_endpoints, rx_node) {
		struct mk_instance *instance;

		instance = container_of(endpoint, struct mk_instance, ipi_endpoint);
		if (READ_ONCE(instance->id) != instance_id ||
		    (peer && instance != peer))
			continue;

		raw_spin_lock_irqsave(&endpoint->tx_lock, flags);
		if (!READ_ONCE(endpoint->registered) || !endpoint->tx_enabled ||
		    !endpoint->tx) {
			ret = -ESHUTDOWN;
			goto unlock;
		}

		index = mk_ring_idx(endpoint->tx_head);
		slot = &endpoint->tx->entries[index];
		/* Observe consumption before reusing this slot. */
		if (smp_load_acquire(&slot->ready)) {
			ret = -ENOSPC;
			goto unlock;
		}

		WRITE_ONCE(slot->sender_cpu,
			   arch_cpu_physical_id(raw_smp_processor_id()));
		WRITE_ONCE(slot->type, type);
		WRITE_ONCE(slot->data_size, data_size);
		if (data_size)
			memcpy(slot->buffer, data, data_size);
		/* Publish the payload before the remote consumer sees ready. */
		smp_store_release(&slot->ready, 1);
		endpoint->tx_head++;
		target = endpoint->doorbell_cpu;
		ret = 0;

unlock:
		raw_spin_unlock_irqrestore(&endpoint->tx_lock, flags);
		break;
	}

	if (!ret)
		mk_arch_send_ipi(target);
	rcu_read_unlock();

	if (ret == -ENOSPC)
		printk_deferred(KERN_WARNING
				"multikernel: IPI ring full for instance %d\n",
				instance_id);
	return ret;
}

int multikernel_send_ipi_data(int instance_id, void *data, size_t data_size,
			      unsigned long type)
{
	return mk_ipi_send(NULL, instance_id, data, data_size, type);
}
EXPORT_SYMBOL_GPL(multikernel_send_ipi_data);

/* The caller pins the exact peer; never substitute a reused instance ID. */
int multikernel_send_ipi_data_to(struct mk_instance *instance, void *data,
				 size_t data_size, unsigned long type)
{
	return mk_ipi_send(instance, instance->id, data, data_size, type);
}

static bool mk_ipi_dispatch(struct mk_ipi_data *slot)
{
	struct mk_ipi_handler *handler;
	size_t data_size = READ_ONCE(slot->data_size);

	if (data_size > MK_MAX_DATA_SIZE) {
		printk_deferred(KERN_WARNING
				"multikernel: oversized IPI payload (%zu bytes)\n",
				data_size);
		return true;
	}

	list_for_each_entry_rcu(handler, &mk_handlers, node) {
		if (handler->ipi_type == READ_ONCE(slot->type)) {
			handler->callback(slot, handler->context);
			return true;
		}
	}
	/* Early polling must not discard messages for later initcall consumers. */
	return smp_load_acquire(&mk_handlers_ready);
}

static bool mk_ipi_endpoint_pending(struct mk_ipi_endpoint *endpoint)
{
	struct mk_ipi_ring *ring;
	unsigned long flags;
	bool pending = false;
	u32 index;

	raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
	if (!READ_ONCE(endpoint->registered))
		goto out;
	if (endpoint->rx_dispatching) {
		pending = true;
		goto out;
	}
	ring = endpoint->rx;
	if (ring) {
		index = mk_ring_idx(endpoint->rx_tail);
		/* Observe the payload after the producer publishes ready. */
		pending = smp_load_acquire(&ring->entries[index].ready);
	}
out:
	raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
	return pending;
}

static noinline void mk_ipi_drain_endpoint(struct mk_ipi_endpoint *endpoint)
{
	struct mk_ipi_data *slot;
	struct mk_ipi_ring *ring;
	unsigned long flags;
	unsigned int drained = 0;
	u32 index;

	raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
	if (!endpoint->registered || endpoint->rx_dispatching || !endpoint->rx) {
		raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
		return;
	}
	endpoint->rx_dispatching = true;
	ring = endpoint->rx;
	raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);

	while (drained < MK_IPI_LINK_BUDGET) {
		raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
		index = mk_ring_idx(endpoint->rx_tail);
		slot = &ring->entries[index];
		/* Observe the payload after the producer publishes ready. */
		if (!smp_load_acquire(&slot->ready)) {
			raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
			break;
		}
		raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);

		if (!mk_ipi_dispatch(slot))
			break;
		/* Finish callback reads before the producer reuses this slot. */
		smp_store_release(&slot->ready, 0);

		raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
		endpoint->rx_tail++;
		raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
		drained++;
	}

	raw_spin_lock_irqsave(&endpoint->rx_lock, flags);
	endpoint->rx_dispatching = false;
	raw_spin_unlock_irqrestore(&endpoint->rx_lock, flags);
}

static unsigned int
mk_ipi_select_endpoints(struct mk_ipi_endpoint **selected)
{
	struct mk_ipi_endpoint *endpoint;
	struct list_head *node;
	unsigned long flags;
	unsigned int count = 0;
	unsigned int scanned;

	raw_spin_lock_irqsave(&mk_ipi_endpoints_lock, flags);
	node = mk_ipi_cursor;
	for (scanned = 0; scanned < mk_ipi_endpoint_count; scanned++) {
		node = node->next;
		if (node == &mk_ipi_endpoints)
			node = node->next;
		endpoint = list_entry(node, struct mk_ipi_endpoint, rx_node);
		if (!mk_ipi_endpoint_pending(endpoint))
			continue;
		selected[count++] = endpoint;
		if (count == MK_IPI_ENDPOINT_BATCH)
			break;
	}
	if (count)
		mk_ipi_cursor = &selected[count - 1]->rx_node;
	raw_spin_unlock_irqrestore(&mk_ipi_endpoints_lock, flags);
	return count;
}

static noinline bool mk_ipi_any_pending(void)
{
	struct mk_ipi_endpoint *endpoint;

	list_for_each_entry_rcu(endpoint, &mk_ipi_endpoints, rx_node) {
		if (mk_ipi_endpoint_pending(endpoint))
			return true;
	}
	return false;
}

void mk_ipi_handlers_enable(void)
{
	/* Publish all handler registrations before enabling dispatch. */
	smp_store_release(&mk_handlers_ready, true);
	mk_ipi_kick_local();
}

static void mk_ipi_drain(bool poll)
{
	struct mk_ipi_endpoint *selected[MK_IPI_ENDPOINT_BATCH];
	unsigned int count;
	unsigned int i;
	bool pending;
	unsigned long flags;

	/* Explicit polling also serves PCI requests before late initcalls. */
	if (!poll && !smp_load_acquire(&mk_handlers_ready))
		return;

	local_irq_save(flags);
	if (this_cpu_read(mk_draining))
		goto out;
	this_cpu_write(mk_draining, true);
	rcu_read_lock();
	count = mk_ipi_select_endpoints(selected);
	for (i = 0; i < count; i++)
		mk_ipi_drain_endpoint(selected[i]);
	pending = mk_ipi_any_pending();
	rcu_read_unlock();

	this_cpu_write(mk_draining, false);
	/* Pair with handler publication before requesting an interrupt drain. */
	if (pending && smp_load_acquire(&mk_handlers_ready))
		mk_ipi_kick_local();
out:
	local_irq_restore(flags);
}

bool mk_ipi_in_drain(void)
{
	return this_cpu_read(mk_draining);
}

void mk_ipi_poll(void)
{
	mk_ipi_drain(true);
}

void generic_multikernel_interrupt(void)
{
	mk_ipi_drain(false);
}

bool mk_has_pending_shutdown(void)
{
	if (!mk_self)
		return false;
	if (!mk_self->ipi_data)
		return mk_manifest_phys() != 0;
	return mk_force_halt_armed();
}

bool mk_force_halt_armed(void)
{
	return mk_self && mk_self->ipi_data &&
	       READ_ONCE(mk_self->ipi_data->force_halt);
}
