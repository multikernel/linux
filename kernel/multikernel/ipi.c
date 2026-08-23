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
#include <linux/delay.h>
#include <linux/ratelimit.h>
#include <linux/ktime.h>
#include <linux/wait.h>
#include "internal.h"

/* Callback management */
static struct mk_ipi_handler *mk_handlers;
static raw_spinlock_t mk_handlers_lock = __RAW_SPIN_LOCK_UNLOCKED(mk_handlers_lock);
static DEFINE_RATELIMIT_STATE(mk_ipi_publish_rs, DEFAULT_RATELIMIT_INTERVAL,
			      DEFAULT_RATELIMIT_BURST);

static void mk_ipi_drain_ring(void);
static DECLARE_WAIT_QUEUE_HEAD(mk_reply_waitq);

#define MK_IPI_PRODUCER_RETRIES	10000
#define MK_IPI_GATE_INDEX_BITS	6
#define MK_IPI_GATE_INDEX_MASK	(MK_IPI_RING_SIZE - 1)
#define MK_REPLY_STATE_MASK	(BIT(MK_REPLY_STATE_BITS) - 1)
#define MK_REPLY_GENERATION_MAX	(U64_MAX >> MK_REPLY_STATE_BITS)

static u64 mk_reply_token(u64 generation, enum mk_reply_state state)
{
	return generation << MK_REPLY_STATE_BITS | state;
}

static u64 mk_reply_generation(u64 token)
{
	return token >> MK_REPLY_STATE_BITS;
}

static enum mk_reply_state mk_reply_state(u64 token)
{
	return token & MK_REPLY_STATE_MASK;
}

/*
 * A nonzero gate records both the physical producer CPU and the slot at head.
 * This makes the serialization recoverable after that exact CPU is confirmed
 * parked. A boolean shared lock would be unsafe because the force-stop NMI may
 * prevent its owner from ever returning to release it.
 */
static u64 mk_ipi_gate_token(mk_phys_cpu_t owner, unsigned int idx)
{
	BUILD_BUG_ON(BIT(MK_IPI_GATE_INDEX_BITS) != MK_IPI_RING_SIZE);
	if (owner >= (U64_MAX >> MK_IPI_GATE_INDEX_BITS))
		return 0;

	return ((owner + 1) << MK_IPI_GATE_INDEX_BITS) | idx;
}

static mk_phys_cpu_t mk_ipi_gate_owner(u64 token)
{
	return (token >> MK_IPI_GATE_INDEX_BITS) - 1;
}

static unsigned int mk_ipi_gate_index(u64 token)
{
	return token & MK_IPI_GATE_INDEX_MASK;
}

/*
 * Serialize producers with preemption disabled so the physical owner encoded
 * in the gate remains stable. Keep local IRQs enabled while waiting for a
 * producer in another kernel, then disable them only for the short publish
 * critical section. No NMI path sends general messages; force halt uses a
 * persistent host-owned marker.
 * Advancing head before READY lets recovery distinguish both interruption
 * windows without allowing another producer to pass the gate.
 */
static int mk_ipi_ring_publish(struct mk_shared_data *shared, int instance_id,
			       const void *data, size_t data_size,
			       unsigned long type)
{
	struct mk_ipi_ring *ring = &shared->ring;
	struct mk_ipi_data *slot;
	mk_phys_cpu_t owner;
	unsigned long flags;
	bool contended = false;
	unsigned int retry;
	unsigned int idx;
	u64 token, old;
	int state;
	int head;
	int ret;

	preempt_disable();
	owner = arch_cpu_physical_id(smp_processor_id());

	for (retry = 0; retry < MK_IPI_PRODUCER_RETRIES; retry++) {
		head = atomic_read(&ring->head);
		idx = head & MK_IPI_GATE_INDEX_MASK;
		token = mk_ipi_gate_token(owner, idx);
		if (!token) {
			ret = -EOVERFLOW;
			goto out_enable;
		}

		old = atomic64_cmpxchg_acquire(&ring->producer_gate, 0, token);
		if (!old) {
			if ((atomic_read(&ring->head) &
			     MK_IPI_GATE_INDEX_MASK) != idx) {
				atomic64_set_release(&ring->producer_gate, 0);
				contended = true;
				cpu_relax();
				continue;
			}
			break;
		}
		contended = true;
		if (mk_ipi_gate_owner(old) == owner) {
			ret = -EDEADLK;
			goto out_count_contention;
		}
		cpu_relax();
	}

	if (retry == MK_IPI_PRODUCER_RETRIES) {
		ret = -EAGAIN;
		goto out_count_contention;
	}

	local_irq_save(flags);
	if (contended)
		atomic_inc(&ring->producer_contention);
	if (!atomic_read_acquire(&shared->ready) ||
	    READ_ONCE(shared->ready_instance_id) != instance_id) {
		ret = -ESHUTDOWN;
		goto out_release_gate;
	}

	slot = &ring->entries[idx];
	state = atomic_cmpxchg(&slot->state, MK_IPI_SLOT_EMPTY,
			       MK_IPI_SLOT_WRITING);
	if (state != MK_IPI_SLOT_EMPTY) {
		if (state == MK_IPI_SLOT_READY ||
		    state == MK_IPI_SLOT_CONSUMING ||
		    state == MK_IPI_SLOT_CANCELLED) {
			atomic_inc(&ring->full_failures);
			ret = -ENOSPC;
		} else {
			atomic_inc(&ring->invalid_state);
			ret = -EIO;
		}
		goto out_release_gate;
	}

	WRITE_ONCE(slot->data_size, 0);
	WRITE_ONCE(slot->sender_cpu, owner);
	WRITE_ONCE(slot->type, type);
	if (data_size)
		memcpy(slot->buffer, data, data_size);
	WRITE_ONCE(slot->data_size, data_size);
	atomic_set(&ring->head, (idx + 1) & MK_IPI_GATE_INDEX_MASK);
	atomic_set_release(&slot->state, MK_IPI_SLOT_READY);
	ret = 0;

out_release_gate:
	atomic64_set_release(&ring->producer_gate, 0);
	local_irq_restore(flags);
out_enable:
	preempt_enable();
	return ret;

out_count_contention:
	atomic_inc(&ring->producer_contention);
	goto out_enable;
}

static bool mk_ipi_slot_is_pending(int state)
{
	return state == MK_IPI_SLOT_READY ||
	       state == MK_IPI_SLOT_CANCELLED;
}

static void mk_ipi_slot_release(struct mk_ipi_data *slot)
{
	WRITE_ONCE(slot->data_size, 0);
	atomic_set_release(&slot->state, MK_IPI_SLOT_EMPTY);
}

int mk_ipi_shared_validate(const struct mk_shared_data *shared)
{
	if (!shared)
		return -ENODEV;
	if (READ_ONCE(shared->abi_magic) != MK_IPI_ABI_MAGIC ||
	    READ_ONCE(shared->abi_version) != MK_IPI_ABI_VERSION ||
	    READ_ONCE(shared->abi_size) != sizeof(*shared))
		return -EPROTO;

	return 0;
}

int mk_ipi_shared_mark_ready(struct mk_shared_data *shared, int instance_id)
{
	int ret;

	ret = mk_ipi_shared_validate(shared);
	if (ret)
		return ret;

	WRITE_ONCE(shared->ready_instance_id, instance_id);
	atomic_set_release(&shared->ready, 1);
	/* Drain messages queued after the host prepared the ring for this boot. */
	mk_ipi_drain_ring();
	return 0;
}

int mk_reply_reserve(struct mk_shared_data *shared, u32 kind, u64 request_id,
		     struct mk_reply_handle *reply)
{
	struct mk_reply_table *table;
	unsigned int i;
	int ret;

	if (!reply || !request_id || !kind)
		return -EINVAL;
	ret = mk_ipi_shared_validate(shared);
	if (ret)
		return ret;

	table = &shared->replies;
	for (i = 0; i < MK_REPLY_SLOTS; i++) {
		struct mk_reply_slot *slot = &table->slots[i];
		u64 generation;
		u64 claim;
		u64 old;

		old = atomic64_read(&slot->state_generation);
		if (mk_reply_state(old) != MK_REPLY_FREE)
			continue;
		generation = mk_reply_generation(old) + 1;
		if (!generation || generation > MK_REPLY_GENERATION_MAX)
			generation = 1;
		claim = mk_reply_token(generation, MK_REPLY_WRITING);
		if (atomic64_cmpxchg_acquire(&slot->state_generation, old,
					     claim) != old)
			continue;

		WRITE_ONCE(slot->request_id, request_id);
		WRITE_ONCE(slot->kind, kind);
		WRITE_ONCE(slot->status, -ETIMEDOUT);
		WRITE_ONCE(slot->value, ~0U);
		atomic64_set(&slot->owner_cpu, MK_REPLY_OWNER_INVALID);
		atomic64_set_release(&slot->state_generation,
				     mk_reply_token(generation,
						    MK_REPLY_RESERVED));
		reply->slot = i;
		reply->kind = kind;
		reply->request_id = request_id;
		reply->generation = generation;
		return 0;
	}

	atomic_inc(&table->occupied_failures);
	return -ENOSPC;
}

static int mk_reply_take_ready(struct mk_shared_data *shared,
			       struct mk_reply_handle *reply,
			       s32 *status, u32 *value)
{
	struct mk_reply_slot *slot = &shared->replies.slots[reply->slot];
	u64 ready = mk_reply_token(reply->generation, MK_REPLY_READY);
	u64 free = mk_reply_token(reply->generation, MK_REPLY_FREE);

	if (atomic64_read_acquire(&slot->state_generation) != ready)
		return -EAGAIN;
	if (READ_ONCE(slot->request_id) != reply->request_id ||
	    READ_ONCE(slot->kind) != reply->kind)
		return -EPROTO;
	if (status)
		*status = READ_ONCE(slot->status);
	if (value)
		*value = READ_ONCE(slot->value);
	atomic64_set(&slot->owner_cpu, MK_REPLY_OWNER_INVALID);
	if (atomic64_cmpxchg_release(&slot->state_generation, ready, free) !=
	    ready)
		return -EAGAIN;
	return 0;
}

static int mk_reply_cancel(struct mk_shared_data *shared,
			   struct mk_reply_handle *reply, bool atomic_timeout)
{
	struct mk_reply_table *table = &shared->replies;
	struct mk_reply_slot *slot = &table->slots[reply->slot];
	u64 reserved = mk_reply_token(reply->generation, MK_REPLY_RESERVED);
	u64 writing = mk_reply_token(reply->generation, MK_REPLY_WRITING);
	u64 executing = mk_reply_token(reply->generation, MK_REPLY_EXECUTING);
	u64 committed = mk_reply_token(reply->generation, MK_REPLY_COMMITTED);
	u64 abandoned = mk_reply_token(reply->generation, MK_REPLY_ABANDONED);
	u64 ready = mk_reply_token(reply->generation, MK_REPLY_READY);
	u64 free = mk_reply_token(reply->generation, MK_REPLY_FREE);
	u64 token;

	if (atomic64_cmpxchg_release(&slot->state_generation, reserved, free) ==
	    reserved)
		goto cancelled;

	for (;;) {
		token = atomic64_read_acquire(&slot->state_generation);
		if (token == ready)
			return 1;
		if (token == committed)
			return -EINPROGRESS;
		if (token == writing &&
		    atomic64_cmpxchg_release(&slot->state_generation, writing,
					     abandoned) == writing)
			break;
		if (token == executing &&
		    atomic64_cmpxchg_release(&slot->state_generation, executing,
					     committed) == executing) {
			atomic_inc(&table->indeterminate_timeouts);
			if (atomic_timeout)
				atomic_inc(&table->atomic_timeouts);
			return -EINPROGRESS;
		}
		if (token != writing && token != executing)
			break;
	}

cancelled:
	atomic_inc(&table->cancelled_slots);
	if (atomic_timeout)
		atomic_inc(&table->atomic_timeouts);
	return 0;
}

static bool mk_reply_wait_done(struct mk_shared_data *shared,
			       const struct mk_reply_handle *reply)
{
	struct mk_reply_slot *slot = &shared->replies.slots[reply->slot];
	u64 token;

	token = atomic64_read_acquire(&slot->state_generation);
	return token == mk_reply_token(reply->generation, MK_REPLY_READY) ||
	       mk_reply_generation(token) != reply->generation ||
	       mk_reply_state(token) == MK_REPLY_FREE;
}

int mk_reply_wait_atomic(struct mk_shared_data *shared,
			 struct mk_reply_handle *reply, unsigned int timeout_us,
			 s32 *status, u32 *value)
{
	u64 deadline;
	int cancelled;

	if (!shared || !reply || reply->slot >= MK_REPLY_SLOTS)
		return -EINVAL;
	deadline = ktime_get_mono_fast_ns() + (u64)timeout_us * NSEC_PER_USEC;
	for (;;) {
		int ret = mk_reply_take_ready(shared, reply, status, value);

		if (!ret)
			return 0;
		if (ret != -EAGAIN)
			return ret;
		if (ktime_get_mono_fast_ns() >= deadline)
			break;
		cpu_relax();
	}

	cancelled = mk_reply_cancel(shared, reply, true);
	if (cancelled > 0)
		return mk_reply_take_ready(shared, reply, status, value);
	if (cancelled < 0)
		return cancelled;
	return -ETIMEDOUT;
}

int mk_reply_wait(struct mk_shared_data *shared,
		  struct mk_reply_handle *reply, unsigned int timeout_ms,
		  s32 *status, u32 *value)
{
	long waited;
	int cancelled;
	int ret;

	if (!shared || !reply || reply->slot >= MK_REPLY_SLOTS)
		return -EINVAL;
	waited = wait_event_timeout(mk_reply_waitq,
				    mk_reply_wait_done(shared, reply),
				    msecs_to_jiffies(timeout_ms));
	if (!waited) {
		cancelled = mk_reply_cancel(shared, reply, false);
		if (cancelled > 0)
			return mk_reply_take_ready(shared, reply, status, value);
		if (cancelled < 0)
			return cancelled;
		return -ETIMEDOUT;
	}
	ret = mk_reply_take_ready(shared, reply, status, value);
	if (ret == -EAGAIN)
		ret = -ESTALE;
	return ret;
}

void mk_reply_release(struct mk_shared_data *shared,
		      struct mk_reply_handle *reply)
{
	if (!shared || !reply || reply->slot >= MK_REPLY_SLOTS)
		return;
	mk_reply_cancel(shared, reply, false);
}

int mk_reply_claim(struct mk_instance *instance,
		   const struct mk_reply_handle *reply)
{
	struct mk_shared_data *shared;
	struct mk_reply_slot *slot;
	u64 writing;
	u64 abandoned;
	u64 reserved;
	u64 free;
	u64 owner;
	int ret;

	if (!instance || !reply || reply->slot >= MK_REPLY_SLOTS)
		return -EINVAL;
	shared = instance->ipi_data;
	ret = mk_ipi_shared_validate(shared);
	if (ret)
		return ret;
	if (!atomic_read_acquire(&shared->ready) ||
	    READ_ONCE(shared->ready_instance_id) != instance->id)
		return -ESHUTDOWN;

	slot = &shared->replies.slots[reply->slot];
	reserved = mk_reply_token(reply->generation, MK_REPLY_RESERVED);
	writing = mk_reply_token(reply->generation, MK_REPLY_WRITING);
	abandoned = mk_reply_token(reply->generation, MK_REPLY_ABANDONED);
	free = mk_reply_token(reply->generation, MK_REPLY_FREE);
	owner = arch_cpu_physical_id(smp_processor_id());
	if (atomic64_cmpxchg_acquire(&slot->owner_cpu,
				     MK_REPLY_OWNER_INVALID, owner) !=
	    MK_REPLY_OWNER_INVALID) {
		atomic_inc(&shared->replies.late_replies);
		return -ESTALE;
	}
	if (atomic64_cmpxchg_acquire(&slot->state_generation, reserved,
				     writing) != reserved) {
		/* Reservation resets stale ownership before it can be reused. */
		atomic_inc(&shared->replies.late_replies);
		return -ESTALE;
	}
	if (READ_ONCE(slot->request_id) != reply->request_id ||
	    READ_ONCE(slot->kind) != reply->kind) {
		u64 old;

		old = atomic64_cmpxchg_release(&slot->state_generation, writing,
					       free);
		if (old == abandoned)
			old = atomic64_cmpxchg_release(&slot->state_generation,
						       abandoned, free);
		if (old == writing || old == abandoned)
			wake_up_all(&mk_reply_waitq);
		atomic_inc(&shared->replies.late_replies);
		return -ESTALE;
	}
	return 0;
}

int mk_reply_begin_execute(struct mk_instance *instance,
			   const struct mk_reply_handle *reply)
{
	struct mk_reply_slot *slot;
	u64 writing;
	u64 executing;
	u64 old;

	if (!instance || !instance->ipi_data || !reply ||
	    reply->slot >= MK_REPLY_SLOTS)
		return -EINVAL;
	slot = &instance->ipi_data->replies.slots[reply->slot];
	writing = mk_reply_token(reply->generation, MK_REPLY_WRITING);
	executing = mk_reply_token(reply->generation, MK_REPLY_EXECUTING);
	old = atomic64_cmpxchg_acquire(&slot->state_generation, writing,
				       executing);
	if (old == writing)
		return 0;
	if (old == mk_reply_token(reply->generation, MK_REPLY_ABANDONED))
		return -ECANCELED;
	return -ESTALE;
}

int mk_reply_publish(struct mk_instance *instance,
		     const struct mk_reply_handle *reply, s32 status, u32 value)
{
	struct mk_shared_data *shared;
	struct mk_reply_slot *slot;
	mk_phys_cpu_t target;
	u64 writing;
	u64 executing;
	u64 committed;
	u64 abandoned;
	u64 ready;
	u64 free;
	u64 old;
	int ret;

	if (!instance || !reply || reply->slot >= MK_REPLY_SLOTS)
		return -EINVAL;
	shared = instance->ipi_data;
	ret = mk_ipi_shared_validate(shared);
	if (ret)
		return ret;
	slot = &shared->replies.slots[reply->slot];
	writing = mk_reply_token(reply->generation, MK_REPLY_WRITING);
	executing = mk_reply_token(reply->generation, MK_REPLY_EXECUTING);
	committed = mk_reply_token(reply->generation, MK_REPLY_COMMITTED);
	abandoned = mk_reply_token(reply->generation, MK_REPLY_ABANDONED);
	ready = mk_reply_token(reply->generation, MK_REPLY_READY);
	free = mk_reply_token(reply->generation, MK_REPLY_FREE);

	/*
	 * Claim this exact generation before touching its payload.  A timed-out
	 * publisher may resume after the slot has been reused; writing first would
	 * corrupt the new request even though the state transition later failed.
	 */
	old = atomic64_cmpxchg_acquire(&slot->state_generation, executing,
				       committed);
	if (old == writing)
		old = atomic64_cmpxchg_acquire(&slot->state_generation, writing,
					       committed);
	if (old == abandoned) {
		atomic64_cmpxchg_release(&slot->state_generation, abandoned, free);
		atomic_inc(&shared->replies.late_replies);
		return -ESTALE;
	}
	if (old != executing && old != writing) {
		atomic_inc(&shared->replies.late_replies);
		return -EIO;
	}
	WRITE_ONCE(slot->status, status);
	WRITE_ONCE(slot->value, value);
	if (atomic64_cmpxchg_release(&slot->state_generation, committed, ready) !=
	    committed) {
		atomic_inc(&shared->replies.late_replies);
		return -ESTALE;
	}

	target = mk_cpu_set_first(instance->cpus);
	if (target == MK_PHYS_CPU_INVALID)
		return -ENODEV;
	mk_arch_send_ipi(target);
	return 0;
}

void mk_reply_scan(struct mk_shared_data *shared)
{
	unsigned int i;

	if (!shared)
		return;
	for (i = 0; i < MK_REPLY_SLOTS; i++) {
		struct mk_reply_slot *slot = &shared->replies.slots[i];
		u64 token = atomic64_read_acquire(&slot->state_generation);

		if (mk_reply_state(token) == MK_REPLY_READY) {
			wake_up_all(&mk_reply_waitq);
			return;
		}
	}
}

int mk_ipi_shared_wait_ready(struct mk_shared_data *shared, int instance_id,
			     unsigned int timeout_ms)
{
	unsigned long deadline;
	int ret;

	ret = mk_ipi_shared_validate(shared);
	if (ret)
		return ret;

	deadline = jiffies + msecs_to_jiffies(timeout_ms);
	do {
		if (atomic_read_acquire(&shared->ready))
			return READ_ONCE(shared->ready_instance_id) == instance_id ?
				0 : -EPROTO;
		msleep(20);
	} while (time_before(jiffies, deadline));

	return -ETIMEDOUT;
}

int mk_ipi_shared_reset_downlink(struct mk_shared_data *shared,
				 int instance_id)
{
	struct mk_ipi_ring *ring;
	mk_phys_cpu_t owner;
	unsigned long flags;
	unsigned int retry;
	unsigned int idx;
	u64 epoch;
	u64 token, old;
	int head;
	int ret = 0;

	if (!shared)
		return -EINVAL;

	/* Exclude new publishers before waiting for an in-flight one. */
	WRITE_ONCE(shared->ready_instance_id, -1);
	atomic_set_release(&shared->ready, 0);
	/* Pair identity invalidation with the publisher's identity check. */
	smp_mb();
	ring = &shared->ring;
	preempt_disable();
	owner = arch_cpu_physical_id(smp_processor_id());
	for (retry = 0; retry < MK_IPI_PRODUCER_RETRIES; retry++) {
		head = atomic_read(&ring->head);
		idx = head & MK_IPI_GATE_INDEX_MASK;
		token = mk_ipi_gate_token(owner, idx);
		if (!token) {
			ret = -EOVERFLOW;
			goto out_enable;
		}
		old = atomic64_cmpxchg_acquire(&ring->producer_gate, 0, token);
		if (!old)
			break;
		if (mk_ipi_gate_owner(old) == owner) {
			ret = -EDEADLK;
			goto out_enable;
		}
		cpu_relax();
	}
	if (retry == MK_IPI_PRODUCER_RETRIES) {
		ret = -EAGAIN;
		goto out_enable;
	}

	local_irq_save(flags);
	/* The old receiver is parked and every pre-existing publisher drained. */
	mk_ipi_ring_reset_contents(ring);
	WRITE_ONCE(shared->force_halt, 0);
	mk_reply_table_reset(&shared->replies);
	mk_irq_mailbox_reset(&shared->irq_mailbox);
	mk_pci_stats_reset(&shared->pci_stats);
	epoch = READ_ONCE(shared->spawn_epoch) + 1;
	if (!epoch)
		epoch = 1;
	WRITE_ONCE(shared->spawn_epoch, epoch);
	WRITE_ONCE(shared->abi_magic, MK_IPI_ABI_MAGIC);
	WRITE_ONCE(shared->abi_version, MK_IPI_ABI_VERSION);
	WRITE_ONCE(shared->abi_size, sizeof(*shared));
	/*
	 * Publish the target identity before launch so callers can queue while
	 * the receiver boots. Readiness remains clear until its handlers exist.
	 */
	WRITE_ONCE(shared->ready_instance_id, instance_id);
	atomic_set(&shared->ready, 0);
	atomic64_set_release(&ring->producer_gate, 0);

	local_irq_restore(flags);
out_enable:
	preempt_enable();
	return ret;
}

static void mk_reply_recover_halted(struct mk_shared_data *shared,
				    const struct mk_cpu_set *halted_cpus)
{
	struct mk_reply_table *table = &shared->replies;
	unsigned int i;

	for (i = 0; i < MK_REPLY_SLOTS; i++) {
		struct mk_reply_slot *slot = &table->slots[i];
		enum mk_reply_state state;
		u64 token, free;
		u64 owner;

		token = atomic64_read_acquire(&slot->state_generation);
		state = mk_reply_state(token);
		if (state != MK_REPLY_RESERVED && state != MK_REPLY_WRITING &&
		    state != MK_REPLY_EXECUTING && state != MK_REPLY_COMMITTED &&
		    state != MK_REPLY_ABANDONED)
			continue;

		owner = atomic64_read(&slot->owner_cpu);
		if (owner == MK_REPLY_OWNER_INVALID ||
		    !mk_cpu_set_contains(halted_cpus, owner))
			continue;

		free = mk_reply_token(mk_reply_generation(token), MK_REPLY_FREE);
		if (atomic64_cmpxchg_release(&slot->state_generation, token, free) !=
		    token)
			continue;

		atomic_inc(&table->cancelled_slots);
		wake_up_all(&mk_reply_waitq);
	}
}

/**
 * mk_ipi_ring_recover_halted - Recover a ring producer after it is parked
 * @halted_cpus: Exact set of CPUs confirmed parked by the caller
 *
 * A force-stop NMI can park a producer while it owns the shared gate. Only its
 * receiver may recover the write, and only after the owner CPU is proven not
 * to be executing it. Other instances may still publish into the host ring,
 * so this function never resets the ring or touches another owner's gate.
 */
int mk_ipi_ring_recover_halted(const struct mk_cpu_set *halted_cpus)
{
	struct mk_ipi_data *slot;
	struct mk_ipi_ring *ring;
	mk_phys_cpu_t owner;
	mk_phys_cpu_t target;
	unsigned int idx;
	unsigned int next;
	u64 token;
	int state;
	int head;
	int ret = 0;

	if (!halted_cpus || !root_instance || !root_instance->ipi_data)
		return -EINVAL;

	ring = &root_instance->ipi_data->ring;
	mk_reply_recover_halted(root_instance->ipi_data, halted_cpus);
	token = atomic64_read_acquire(&ring->producer_gate);
	if (!token)
		goto kick;
	if (!(token >> MK_IPI_GATE_INDEX_BITS)) {
		atomic_inc(&ring->invalid_state);
		ret = -EIO;
		goto kick;
	}

	owner = mk_ipi_gate_owner(token);
	if (!mk_cpu_set_contains(halted_cpus, owner))
		goto kick;

	idx = mk_ipi_gate_index(token);
	next = (idx + 1) & MK_IPI_GATE_INDEX_MASK;
	slot = &ring->entries[idx];
	state = atomic_read_acquire(&slot->state);
	head = atomic_read(&ring->head) & MK_IPI_GATE_INDEX_MASK;
	switch (state) {
	case MK_IPI_SLOT_EMPTY:
		if (head != idx && head != next) {
			atomic_inc(&ring->invalid_state);
			ret = -EIO;
		}
		break;
	case MK_IPI_SLOT_WRITING:
		if (head == idx) {
			atomic_set(&ring->head, next);
		} else if (head != next) {
			atomic_inc(&ring->invalid_state);
			ret = -EIO;
			break;
		}
		atomic_set_release(&slot->state, MK_IPI_SLOT_CANCELLED);
		atomic_inc(&ring->cancelled_writes);
		break;
	case MK_IPI_SLOT_READY:
	case MK_IPI_SLOT_CANCELLED:
		if (head == idx) {
			/* Repair an interrupted publication before releasing its gate. */
			atomic_set(&ring->head, next);
			atomic_inc(&ring->invalid_state);
		} else if (head != next) {
			atomic_inc(&ring->invalid_state);
			ret = -EIO;
		}
		break;
	case MK_IPI_SLOT_CONSUMING:
		/*
		 * The consumer may claim a full-ring tail while this producer
		 * waits to test it, leaving head at idx with nothing published.
		 * Head at next means the previous publication was claimed before
		 * its now-stale gate could be released. Both cursors are valid.
		 */
		if (head != idx && head != next) {
			atomic_inc(&ring->invalid_state);
			ret = -EIO;
		}
		break;
	default:
		atomic_inc(&ring->invalid_state);
		ret = -EIO;
		break;
	}

	/* Keep the gate closed when cursor repair cannot make the FIFO safe. */
	if (ret)
		goto kick;
	if (atomic64_cmpxchg_release(&ring->producer_gate, token, 0) != token) {
		atomic_inc(&ring->invalid_state);
		ret = -EAGAIN;
	}

kick:
	/* The producer may have published and parked before ringing the bell. */
	target = mk_cpu_set_first(root_instance->cpus);
	if (target != MK_PHYS_CPU_INVALID)
		mk_arch_send_ipi(target);

	return ret;
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
 * @instance: Target multikernel instance
 * @data: Pointer to data to send
 * @data_size: Size of data
 * @type: User-defined type identifier
 *
 * This function enqueues data into the target instance's IPI ring buffer
 * and sends an IPI to notify the target CPU.
 *
 * Returns 0 on success, negative error code on failure
 */
static int __mk_send_ipi_data(struct mk_instance *instance,
			      mk_phys_cpu_t target, void *data,
			      size_t data_size, unsigned long type)
{
	int instance_id;
	int ret;

	if (!instance || target == MK_PHYS_CPU_INVALID)
		return -EINVAL;
	instance_id = instance->id;
	if (data_size > MK_MAX_DATA_SIZE || (data_size && !data))
		return -EINVAL;

	target = mk_cpu_set_first(instance->cpus);
	if (target == MK_PHYS_CPU_INVALID) {
		pr_err("Instance %d has no CPUs to receive the IPI\n", instance_id);
		return -ENODEV;
	}

	if (!mk_instance_ipi_area(instance)) {
		pr_err("Multikernel IPI buffer not available for instance %d\n", instance_id);
		return -ENODEV;
	}
	ret = mk_ipi_shared_validate(instance->ipi_data);
	if (ret)
		return ret;
	/* A prepared downlink may accept messages before the receiver is ready. */
	if (READ_ONCE(instance->ipi_data->ready_instance_id) != instance_id)
		return -EPROTO;

	ret = mk_ipi_ring_publish(instance->ipi_data, instance_id, data,
				  data_size, type);
	if (ret) {
		/*
		 * A doorbell can be coalesced while the target is draining this
		 * ring.  Kick it again before reporting backpressure so READY
		 * entries cannot remain stranded without another notification.
		 */
		mk_arch_send_ipi(target);
		/* Console writers reach this path with their lock and IRQs held. */
		if (ret != -EDEADLK && __ratelimit(&mk_ipi_publish_rs)) {
			if (ret == -ENOSPC)
				printk_deferred(KERN_WARNING
					"multikernel: IPI ring full for instance %d\n",
					instance_id);
			else if (ret == -EAGAIN)
				printk_deferred(KERN_WARNING
					"multikernel: IPI producer busy for instance %d\n",
					instance_id);
			else
				printk_deferred(KERN_ERR
					"multikernel: IPI publish failed for instance %d: %d\n",
					instance_id, ret);
		}
		return ret;
	}
	mk_arch_send_ipi(target);

	return 0;
}

int mk_send_ipi_data_to_cpu(struct mk_instance *instance,
			    mk_phys_cpu_t target, void *data,
			    size_t data_size, unsigned long type)
{
	return __mk_send_ipi_data(instance, target, data, data_size, type);
}

int mk_send_ipi_data(struct mk_instance *instance, void *data,
		     size_t data_size, unsigned long type)
{
	mk_phys_cpu_t target;

	if (!instance)
		return -EINVAL;
	target = mk_cpu_set_first(instance->cpus);
	if (target == MK_PHYS_CPU_INVALID) {
		pr_err("Instance %d has no CPUs to receive the IPI\n",
		       instance->id);
		return -ENODEV;
	}
	return __mk_send_ipi_data(instance, target, data, data_size, type);
}

int multikernel_send_ipi_data(int instance_id, void *data, size_t data_size,
			      unsigned long type)
{
	struct mk_instance *instance;
	int ret;

	instance = mk_instance_find(instance_id);
	if (!instance)
		return -EINVAL;
	ret = mk_send_ipi_data(instance, data, data_size, type);
	mk_instance_put(instance);
	return ret;
}

static void mk_ipi_drain_ring(void)
{
	struct mk_ipi_data *slot;
	struct mk_ipi_handler *handler;
	struct mk_ipi_ring *ring;
	unsigned int tail, idx;
	size_t data_size;
	int state;
	int messages_processed = 0;

	if (!root_instance || !root_instance->ipi_data)
		return;

	ring = &root_instance->ipi_data->ring;
	while (messages_processed < MK_IPI_RING_SIZE) {
		tail = atomic_read(&ring->tail);
		idx = tail & (MK_IPI_RING_SIZE - 1);
		slot = &ring->entries[idx];

		state = atomic_read_acquire(&slot->state);
		if (!mk_ipi_slot_is_pending(state)) {
			if (state != MK_IPI_SLOT_EMPTY &&
			    state != MK_IPI_SLOT_WRITING &&
			    state != MK_IPI_SLOT_CONSUMING) {
				atomic_inc(&ring->invalid_state);
				pr_warn_once("Multikernel IPI slot %u has bad state %d\n",
					     idx, state);
			}
			break;
		}

		if (atomic_cmpxchg_acquire(&slot->state, state,
					   MK_IPI_SLOT_CONSUMING) != state)
			break;

		if (state == MK_IPI_SLOT_CANCELLED)
			goto advance_tail;

		data_size = READ_ONCE(slot->data_size);
		if (data_size > MK_MAX_DATA_SIZE) {
			pr_warn_once("Multikernel IPI slot %u has bad size %zu\n",
				     idx, data_size);
			goto advance_tail;
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
		mk_ipi_slot_release(slot);
		atomic_set(&ring->tail, (idx + 1) & (MK_IPI_RING_SIZE - 1));
		messages_processed++;
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
	mk_reply_scan(root_instance->ipi_data);
	mk_pci_irq_mailbox_drain(root_instance->ipi_data);

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
 * Safe to call from NMI context (a single read of shared memory).
 *
 * Returns: true if shutdown requested, false otherwise
 */
bool mk_has_pending_shutdown(void)
{
	if (!root_instance || !root_instance->ipi_data)
		return false;

	return READ_ONCE(root_instance->ipi_data->force_halt);
}
