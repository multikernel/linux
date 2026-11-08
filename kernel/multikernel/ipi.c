// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/ratelimit.h>
#include <linux/spinlock.h>
#include <linux/multikernel.h>
#include <linux/kexec.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include "internal.h"

/* Callback management */
static struct mk_ipi_handler *mk_handlers;
static raw_spinlock_t mk_handlers_lock = __RAW_SPIN_LOCK_UNLOCKED(mk_handlers_lock);

static DEFINE_RAW_SPINLOCK(mk_drain_lock);
static DEFINE_PER_CPU(bool, mk_draining);
static DEFINE_RATELIMIT_STATE(mk_ipi_full_rs, DEFAULT_RATELIMIT_INTERVAL, 1);

/* Children whose to_parent ring this kernel drains, under mk_drain_lock */
static LIST_HEAD(mk_ipi_rx_list);

/*
 * Ring indices live in memory another kernel instance can write, so every
 * read is masked before it indexes the entry array. An instance that dies
 * mid-update must not be able to walk this kernel off the end of its ring.
 */
static inline unsigned int mk_ring_idx(unsigned int i)
{
	return i & (MK_IPI_RING_SIZE - 1);
}

/**
 * mk_ipi_rx_add - Start draining a child's to_parent ring
 * @instance: Child about to run, with its rings freshly cleared
 */
void mk_ipi_rx_add(struct mk_instance *instance)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&mk_drain_lock, flags);
	if (list_empty(&instance->ipi_rx_node))
		list_add_tail(&instance->ipi_rx_node, &mk_ipi_rx_list);
	raw_spin_unlock_irqrestore(&mk_drain_lock, flags);
}

/**
 * mk_ipi_rx_del - Stop draining a child's to_parent ring
 * @instance: Child that is no longer running
 *
 * Once this returns, no drain is looking at the instance's ring.
 */
void mk_ipi_rx_del(struct mk_instance *instance)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&mk_drain_lock, flags);
	list_del_init(&instance->ipi_rx_node);
	raw_spin_unlock_irqrestore(&mk_drain_lock, flags);
}

/**
 * multikernel_register_handler - Register a callback for multikernel IPI
 * @callback: Function to call when IPI is received
 * @ctx: Context pointer passed to the callback
 * @ipi_type: IPI type this handler should process
 *
 * Returns pointer to handler on success, NULL on failure
 */
struct mk_ipi_handler *multikernel_register_handler(mk_ipi_callback_t callback, void *ctx, unsigned int ipi_type)
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

/**
 * multikernel_unregister_handler - Unregister a multikernel IPI callback
 * @handler: Handler pointer returned from multikernel_register_handler
 *
 * Must not be called from a multikernel IPI callback.
 */
void multikernel_unregister_handler(struct mk_ipi_handler *handler)
{
	struct mk_ipi_handler **pp, *p;
	unsigned long flags;

	if (!handler)
		return;

	raw_spin_lock_irqsave(&mk_handlers_lock, flags);
	pp = &mk_handlers;
	while ((p = *pp) != NULL) {
		if (p == handler) {
			*pp = p->next;
			break;
		}
		pp = &p->next;
	}
	raw_spin_unlock_irqrestore(&mk_handlers_lock, flags);

	/* A drain calls the handler unlocked but holds mk_drain_lock throughout */
	raw_spin_lock_irqsave(&mk_drain_lock, flags);
	raw_spin_unlock_irqrestore(&mk_drain_lock, flags);

	kfree(p);
}
EXPORT_SYMBOL(multikernel_unregister_handler);

/**
 * mk_arm_force_halt - Post the force-halt marker for an instance
 * @instance: Instance about to be NMIed
 *
 * The instance's CPUs test the marker from their NMI handlers, so it
 * must be armed before the NMIs are sent. It stays armed until the
 * kexec path has confirmed every CPU parked and wipes the shared area
 * for the next run, which is what makes the NMI rescue idempotent: a
 * repeat force halt still reaches CPUs an earlier one missed.
 *
 * Returns 0 on success, -ENODEV if the instance has no shared IPI area.
 */
int mk_arm_force_halt(struct mk_instance *instance)
{
	struct mk_shared_data *ipi_data = READ_ONCE(instance->ipi_data);

	if (!ipi_data)
		return -ENODEV;

	WRITE_ONCE(ipi_data->force_halt, 1);
	/* The marker must be visible before the NMIs that test it */
	smp_wmb();
	return 0;
}

/**
 * mk_ipi_send_by_id - Send data to another instance via IPI
 * @instance_id: Target multikernel instance ID
 * @data: Pointer to data to send
 * @data_size: Size of data
 * @type: User-defined type identifier
 *
 * This function enqueues data into the target instance's IPI ring buffer
 * and sends an IPI to notify the target CPU.
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_ipi_send_by_id(int instance_id, void *data, size_t data_size, unsigned long type)
{
	struct mk_instance *instance = mk_instance_find(instance_id);
	int ret;

	if (!instance)
		return -EINVAL;

	ret = mk_ipi_send(instance, data, data_size, type);
	mk_instance_put(instance);
	return ret;
}

/*
 * The same for a caller that holds a reference to @instance. Looking an
 * instance up by ID takes a mutex; this does not sleep, so it is the one
 * to use with interrupts off.
 */
int mk_ipi_send(struct mk_instance *instance, void *data, size_t data_size,
		unsigned long type)
{
	struct mk_shared_data *ipi_data;
	struct mk_ipi_ring *ring;
	struct mk_ipi_data *slot;
	int instance_id = instance->id;
	unsigned int head, next_head, tail;
	mk_phys_cpu_t target;

	/* Messages go only to a running kernel, as only a running one drains them */
	if (READ_ONCE(instance->state) != MK_STATE_ACTIVE || READ_ONCE(instance->silent))
		return -EHOSTDOWN;
	if (data_size > MK_MAX_DATA_SIZE)
		return -EINVAL;

	target = instance->ipi_target;
	if (target == MK_PHYS_CPU_INVALID)
		target = mk_cpu_set_first(instance->cpus);
	if (target == MK_PHYS_CPU_INVALID) {
		pr_err("Instance %d has no CPU to receive the IPI\n", instance_id);
		return -ENODEV;
	}

	/* Our own to_child ring has our parent as its producer */
	if (instance == mk_self)
		return -EINVAL;

	/*
	 * The link to the parent lives in this kernel's own shared area,
	 * the one to a child in that child's, which is pinned here.
	 */
	if (instance == host_instance) {
		ipi_data = READ_ONCE(mk_self->ipi_data);
		ring = ipi_data ? &ipi_data->to_parent : NULL;
	} else {
		ipi_data = READ_ONCE(instance->ipi_data);
		ring = ipi_data ? &ipi_data->to_child : NULL;
	}
	if (!ring) {
		pr_err("Multikernel IPI buffer not available for instance %d\n", instance_id);
		return -ENODEV;
	}

	/* Try to enqueue the message in the ring buffer */
	do {
		head = mk_ring_idx(atomic_read(&ring->head));
		next_head = mk_ring_idx(head + 1);
		tail = mk_ring_idx(atomic_read(&ring->tail));

		/* Check if ring buffer is full */
		if (next_head == tail) {
			/*
			 * Console output reaches this path, so a plain printk
			 * here re-enters the console write that called us and
			 * deadlocks on its lock with interrupts already off.
			 * Rate limited, as that output comes straight back here
			 * while the ring stays full.
			 */
			if (!__ratelimit(&mk_ipi_full_rs))
				return -ENOSPC;
			printk_deferred(KERN_WARNING
					"multikernel: IPI ring full for instance %d (head=%u, tail=%u)\n",
					instance_id, head, tail);
			return -ENOSPC;
		}

		/* Try to claim this slot atomically */
	} while (atomic_cmpxchg(&ring->head, head, next_head) != head);

	/* We've claimed slot 'head', now fill it */
	slot = &ring->entries[head];

	slot->sender_cpu = arch_cpu_physical_id(smp_processor_id());
	slot->type = type;

	if (data && data_size > 0)
		memcpy(slot->buffer, data, data_size);

	/*
	 * data_size publishes the slot: the reader treats a zero as "the
	 * producer has claimed this slot but has not filled it yet" and
	 * waits. Claiming the slot advanced head, so a reader can already
	 * be looking at it; everything above must be visible first.
	 */
	smp_store_release(&slot->data_size, data_size);

	mk_arch_send_ipi(target);
	return 0;
}

static void mk_ipi_drain_ring(struct mk_ipi_ring *ring, struct mk_instance *from)
{
	struct mk_ipi_data *slot;
	struct mk_ipi_handler *handler;
	unsigned int head, tail, next_tail;
	size_t data_size;
	int messages_processed = 0;

	while (1) {
		tail = mk_ring_idx(atomic_read(&ring->tail));
		head = mk_ring_idx(atomic_read(&ring->head));

		if (tail == head)
			break;

		slot = &ring->entries[tail];

		/*
		 * Pairs with the store_release in mk_ipi_send().
		 * Zero means the sender claimed this slot but has not
		 * finished writing it. Leave it alone: skipping it would
		 * drop the message it is about to publish. Its own IPI, or
		 * the next one, brings us back here.
		 *
		 * A sender stopped before publishing leaves its slot zero
		 * forever. Only its own kernel produces on this ring, and
		 * mk_instance_start() clears it before that kernel's
		 * successor runs.
		 */
		data_size = smp_load_acquire(&slot->data_size);
		if (data_size == 0)
			break;

		if (data_size > MK_MAX_DATA_SIZE) {
			pr_warn_once("Multikernel IPI slot %u has bad size %zu\n",
				     tail, data_size);
			slot->data_size = 0;
			next_tail = mk_ring_idx(tail + 1);
			atomic_set(&ring->tail, next_tail);
			continue;
		}

		/* Dispatch to registered handler */
		raw_spin_lock(&mk_handlers_lock);
		for (handler = mk_handlers; handler; handler = handler->next) {
			if (handler->ipi_type == slot->type && handler->callback) {
				mk_ipi_callback_t cb = handler->callback;
				void *ctx = handler->context;

				raw_spin_unlock(&mk_handlers_lock);
				cb(slot, from, ctx);
				goto advance_tail;
			}
		}
		raw_spin_unlock(&mk_handlers_lock);

advance_tail:
		/* Mark consumed so the slot reads as unpublished again */
		slot->data_size = 0;
		next_tail = mk_ring_idx(tail + 1);
		atomic_set(&ring->tail, next_tail);
		messages_processed++;

		if (messages_processed >= MK_IPI_RING_SIZE)
			break;
	}
}

/**
 * multikernel_interrupt_handler - Handle the multikernel IPI
 *
 * This function is called when a multikernel IPI is received.
 * Messages are drained here, in interrupt context.
 */
static void multikernel_interrupt_handler(void)
{
	struct mk_shared_data *ipi_data;
	struct mk_instance *child;
	unsigned long flags;

	if (!mk_self)
		return;

	/*
	 * Drain here rather than from irq_work. We are already in interrupt
	 * context and every handler is safe to call from it, and irq_work
	 * brings a failure mode with it: the work is a single static
	 * instance, so if it is ever left pending - its self-IPI lost while
	 * the CPU was bringing its APIC up, say - every later queue attempt
	 * is a no-op and the ring never drains again.
	 *
	 * Each ring has one consumer at a time. That used to be implied by
	 * the doorbell going to a single CPU; mk_ipi_poll() is a second way
	 * in, so it is a lock now. Waiting for it rather than giving up
	 * matters: a poller that is just leaving may not look again.
	 *
	 * The doorbell does not say who rang, so look at the link from the
	 * parent and at every running child's link.
	 */
	raw_spin_lock_irqsave(&mk_drain_lock, flags);
	this_cpu_write(mk_draining, true);
	if (mk_self->ipi_data && host_instance)
		mk_ipi_drain_ring(&mk_self->ipi_data->to_child, host_instance);
	list_for_each_entry(child, &mk_ipi_rx_list, ipi_rx_node) {
		ipi_data = READ_ONCE(child->ipi_data);
		if (ipi_data)
			mk_ipi_drain_ring(&ipi_data->to_parent, child);
	}
	this_cpu_write(mk_draining, false);
	raw_spin_unlock_irqrestore(&mk_drain_lock, flags);
}

/**
 * mk_ipi_in_drain - Whether this CPU is running a message handler
 *
 * A handler that polled the ring for an answer would wait for the drain
 * lock it already holds.
 */
bool mk_ipi_in_drain(void)
{
	return this_cpu_read(mk_draining);
}

/**
 * mk_ipi_poll - Drain the message ring without waiting for the doorbell
 *
 * For a caller that waits for an answer where the doorbell interrupt
 * cannot be taken: with interrupts off on the doorbell CPU, or while
 * stop_machine() holds every CPU. Message handlers run in the caller's
 * context, which they are fit for, as they normally run in the interrupt.
 */
void mk_ipi_poll(void)
{
	multikernel_interrupt_handler();
}

/**
 * Generic multikernel interrupt handler - called by the IPI vector
 *
 * This is the function that gets called by the IPI vector handler.
 */
void generic_multikernel_interrupt(void)
{
	multikernel_interrupt_handler();
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

	return mk_force_halt_armed();
}

/**
 * mk_force_halt_armed - Check the force-halt marker alone
 *
 * Unlike mk_has_pending_shutdown(), never true for a kernel without a
 * ring, so it can be tested on NMIs that a local source may own.
 */
bool mk_force_halt_armed(void)
{
	return mk_self && mk_self->ipi_data &&
	       READ_ONCE(mk_self->ipi_data->force_halt);
}
