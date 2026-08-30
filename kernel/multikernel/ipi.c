// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/smp.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <linux/multikernel.h>
#include <linux/kexec.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include "internal.h"

/* Callback management */
static struct mk_ipi_handler *mk_handlers;
static raw_spinlock_t mk_handlers_lock = __RAW_SPIN_LOCK_UNLOCKED(mk_handlers_lock);

static void mk_ipi_drain_ring(void);

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
 * mk_ipi_ring_drop_pending - Discard everything queued in this kernel's ring
 *
 * Called when an instance is re-spawned. A halting instance parks its CPUs
 * wherever they were, including between claiming a ring slot and publishing
 * it, and the drain stops at such a slot forever. Anything still queued was
 * sent by a kernel that is gone, so drop it all rather than let one
 * abandoned slot wedge the ring.
 */
void mk_ipi_ring_drop_pending(void)
{
	struct mk_ipi_ring *ring;
	unsigned int head, tail;

	if (!root_instance || !root_instance->ipi_data)
		return;

	ring = &root_instance->ipi_data->ring;
	head = mk_ring_idx(atomic_read(&ring->head));

	for (tail = mk_ring_idx(atomic_read(&ring->tail)); tail != head;
	     tail = mk_ring_idx(tail + 1))
		ring->entries[tail].data_size = 0;

	atomic_set(&ring->tail, head);
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

	kfree(p);
}
EXPORT_SYMBOL(multikernel_unregister_handler);

/*
 * An instance's IPI area is allocated when its image is loaded; the
 * instance pointer is filled in lazily on first use.
 */
static struct mk_shared_data *mk_instance_ipi_area(struct mk_instance *instance)
{
	struct mk_shared_data *ipi_data;

	if (instance->ipi_data)
		return instance->ipi_data;

	if (!instance->kimage || !instance->kimage->mk_ipi)
		return NULL;

	ipi_data = phys_to_virt(instance->kimage->mk_ipi);
	if (cmpxchg(&instance->ipi_data, NULL, ipi_data) == NULL)
		pr_info("Initialized IPI ring buffer for instance %d: phys=0x%llx\n",
			instance->id, (unsigned long long)instance->kimage->mk_ipi);

	return instance->ipi_data;
}

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
	struct mk_shared_data *ipi_data = mk_instance_ipi_area(instance);

	if (!ipi_data)
		return -ENODEV;

	WRITE_ONCE(ipi_data->force_halt, 1);
	/* The marker must be visible before the NMIs that test it */
	smp_wmb();
	return 0;
}

/**
 * multikernel_send_ipi_data - Send data to another CPU via IPI
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
int multikernel_send_ipi_data(int instance_id, void *data, size_t data_size, unsigned long type)
{
	struct mk_ipi_data *slot;
	struct mk_instance *instance = mk_instance_find(instance_id);
	unsigned int head, next_head, tail;
	mk_phys_cpu_t target;

	if (!instance)
		return -EINVAL;
	if (data_size > MK_MAX_DATA_SIZE) {
		mk_instance_put(instance);
		return -EINVAL;
	}

	target = mk_cpu_set_first(instance->cpus);
	if (target == MK_PHYS_CPU_INVALID) {
		pr_err("Instance %d has no CPUs to receive the IPI\n", instance_id);
		mk_instance_put(instance);
		return -ENODEV;
	}

	if (!mk_instance_ipi_area(instance)) {
		pr_err("Multikernel IPI buffer not available for instance %d\n", instance_id);
		mk_instance_put(instance);
		return -ENODEV;
	}

	/* Try to enqueue the message in the ring buffer */
	do {
		head = mk_ring_idx(atomic_read(&instance->ipi_data->ring.head));
		next_head = mk_ring_idx(head + 1);
		tail = mk_ring_idx(atomic_read(&instance->ipi_data->ring.tail));

		/* Check if ring buffer is full */
		if (next_head == tail) {
			/*
			 * Console output reaches this path, so a plain printk
			 * here re-enters the console write that called us and
			 * deadlocks on its lock with interrupts already off.
			 */
			printk_deferred(KERN_WARNING
					"multikernel: IPI ring full for instance %d (head=%u, tail=%u)\n",
					instance_id, head, tail);
			mk_instance_put(instance);
			return -ENOSPC;
		}

		/* Try to claim this slot atomically */
	} while (atomic_cmpxchg(&instance->ipi_data->ring.head, head, next_head) != head);

	/* We've claimed slot 'head', now fill it */
	slot = &instance->ipi_data->ring.entries[head];

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

	mk_instance_put(instance);
	return 0;
}

static void mk_ipi_drain_ring(void)
{
	struct mk_ipi_data *slot;
	struct mk_ipi_handler *handler;
	unsigned int head, tail, next_tail;
	size_t data_size;
	int messages_processed = 0;

	if (!root_instance || !root_instance->ipi_data)
		return;

	while (1) {
		tail = mk_ring_idx(atomic_read(&root_instance->ipi_data->ring.tail));
		head = mk_ring_idx(atomic_read(&root_instance->ipi_data->ring.head));

		if (tail == head)
			break;

		slot = &root_instance->ipi_data->ring.entries[tail];

		/*
		 * Pairs with the store_release in multikernel_send_ipi_data().
		 * Zero means the sender claimed this slot but has not
		 * finished writing it. Leave it alone: skipping it would
		 * drop the message it is about to publish. Its own IPI, or
		 * the next one, brings us back here.
		 *
		 * A sender stopped before publishing leaves its slot zero
		 * forever; mk_ipi_ring_drop_pending() clears those out when
		 * the instance is re-spawned.
		 */
		data_size = smp_load_acquire(&slot->data_size);
		if (data_size == 0)
			break;

		if (data_size > MK_MAX_DATA_SIZE) {
			pr_warn_once("Multikernel IPI slot %u has bad size %zu\n",
				     tail, data_size);
			slot->data_size = 0;
			next_tail = mk_ring_idx(tail + 1);
			atomic_set(&root_instance->ipi_data->ring.tail, next_tail);
			continue;
		}

		/* Dispatch to registered handler */
		raw_spin_lock(&mk_handlers_lock);
		for (handler = mk_handlers; handler; handler = handler->next) {
			if (handler->ipi_type == slot->type && handler->callback) {
				mk_ipi_callback_t cb = handler->callback;
				void *ctx = handler->context;

				raw_spin_unlock(&mk_handlers_lock);
				cb(slot, ctx);
				goto advance_tail;
			}
		}
		raw_spin_unlock(&mk_handlers_lock);

advance_tail:
		/* Mark consumed so the slot reads as unpublished again */
		slot->data_size = 0;
		next_tail = mk_ring_idx(tail + 1);
		atomic_set(&root_instance->ipi_data->ring.tail, next_tail);
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
	if (!root_instance || !root_instance->ipi_data)
		return;

	/*
	 * Drain here rather than from irq_work. We are already in interrupt
	 * context and every handler is safe to call from it, and irq_work
	 * brings a failure mode with it: the work is a single static
	 * instance, so if it is ever left pending - its self-IPI lost while
	 * the CPU was bringing its APIC up, say - every later queue attempt
	 * is a no-op and the ring never drains again.
	 */
	mk_ipi_drain_ring();
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
	if (!root_instance)
		return false;

	if (!root_instance->ipi_data)
		return mk_manifest_phys() != 0;

	return READ_ONCE(root_instance->ipi_data->force_halt);
}
