// SPDX-License-Identifier: GPL-2.0-only
/* Host PCI config, MSI, reset, and failure-control paths. */
#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/device/bus.h>
#include <linux/interrupt.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "pci_internal.h"
#include "internal.h"

#define MK_PCI_MAILBOX_QUIESCE_MS	1000

static unsigned long mk_pci_mailbox_deadline(void)
{
	return jiffies + msecs_to_jiffies(MK_PCI_MAILBOX_QUIESCE_MS);
}

static bool mk_pci_notifier_registered;
static bool mk_pci_control_registered;
static mempool_t *mk_pci_control_pool;
static struct workqueue_struct *mk_pci_control_wq;
static DEFINE_SPINLOCK(mk_pci_control_lock);
static DECLARE_WAIT_QUEUE_HEAD(mk_pci_control_waitq);
static unsigned int mk_pci_control_active;
static bool mk_pci_control_shutdown = true;
static atomic64_t mk_pci_control_pool_exhausted = ATOMIC64_INIT(0);

u64 mk_pci_control_pool_exhausted_read(void)
{
	return atomic64_read(&mk_pci_control_pool_exhausted);
}

struct mk_pci_control_work {
	struct work_struct work;
	mk_phys_cpu_t sender_cpu;
	union {
		struct mk_pci_cfg_request cfg;
		struct mk_pci_irq_request irq;
		struct mk_pci_reset_request reset;
	} request;
};

static bool mk_pci_control_handler_get(void)
{
	unsigned long flags;
	bool acquired = false;

	spin_lock_irqsave(&mk_pci_control_lock, flags);
	if (!mk_pci_control_shutdown) {
		mk_pci_control_active++;
		acquired = true;
	}
	spin_unlock_irqrestore(&mk_pci_control_lock, flags);
	return acquired;
}

static void mk_pci_control_handler_put(void)
{
	unsigned long flags;
	bool drained;

	spin_lock_irqsave(&mk_pci_control_lock, flags);
	WARN_ON_ONCE(!mk_pci_control_active);
	if (mk_pci_control_active)
		mk_pci_control_active--;
	drained = !mk_pci_control_active;
	spin_unlock_irqrestore(&mk_pci_control_lock, flags);
	if (drained)
		wake_up_all(&mk_pci_control_waitq);
}

static void mk_pci_control_shutdown_begin(void)
{
	unsigned long flags;

	spin_lock_irqsave(&mk_pci_control_lock, flags);
	mk_pci_control_shutdown = true;
	spin_unlock_irqrestore(&mk_pci_control_lock, flags);
}

static void mk_pci_control_shutdown_end(void)
{
	unsigned long flags;

	spin_lock_irqsave(&mk_pci_control_lock, flags);
	mk_pci_control_active = 0;
	mk_pci_control_shutdown = false;
	spin_unlock_irqrestore(&mk_pci_control_lock, flags);
}

static int mk_pci_forwarding_cpu(void)
{
	/* The host IPI manifest publishes logical CPU 0's physical ID. */
	if (!cpu_online(0))
		return -ENODEV;

	return 0;
}

static void mk_pci_mailbox_clear_bit(struct mk_irq_mailbox *mailbox,
				     unsigned int slot)
{
	atomic64_andnot(BIT_ULL(slot & 63),
			&mailbox->pending_bitmap[slot / 64]);
}

static bool mk_pci_mailbox_quiesce(struct mk_pci_irq_vector *vector,
				   bool parked_force,
				   unsigned long deadline)
{
	struct mk_shared_data *shared = vector->assignment->instance->ipi_data;
	struct mk_irq_mailbox *mailbox;
	struct mk_irq_mailbox_entry *entry;
	u64 base, token;

	if (!shared || vector->mailbox_slot == MK_IRQ_MAILBOX_SLOT_INVALID ||
	    !vector->mailbox_generation)
		return true;
	mailbox = &shared->irq_mailbox;
	entry = &mailbox->entries[vector->mailbox_slot];
	base = mk_irq_mailbox_token(vector->mailbox_generation, 0) |
		MK_IRQ_MAILBOX_MASKED;
	for (;;) {
		token = atomic64_read_acquire(&entry->pending_generation);
		if (mk_irq_mailbox_generation(token) !=
		    vector->mailbox_generation) {
			atomic_inc(&mailbox->stale);
			return false;
		}
		if (mk_irq_mailbox_consuming(token)) {
			if (parked_force) {
				if (atomic64_cmpxchg_release(&entry->pending_generation,
							     token, base) == token)
					break;
				continue;
			}
			if (!mk_irq_mailbox_masked(token))
				atomic64_cmpxchg(&entry->pending_generation,
						 token,
						 token | MK_IRQ_MAILBOX_MASKED);
			if (time_after_eq(jiffies, deadline))
				return false;
			usleep_range(50, 100);
			continue;
		}
		if (atomic64_cmpxchg_release(&entry->pending_generation,
					     token, base) == token)
			break;
		cpu_relax();
	}
	mk_pci_mailbox_clear_bit(mailbox, vector->mailbox_slot);
	WRITE_ONCE(entry->local_irq, 0);
	return true;
}

static void mk_pci_mailbox_release(struct mk_pci_irq_vector *vector)
{
	struct mk_shared_data *shared = vector->assignment->instance->ipi_data;
	struct mk_irq_mailbox *mailbox;
	struct mk_irq_mailbox_entry *entry;
	u64 token;

	if (!shared || vector->mailbox_slot == MK_IRQ_MAILBOX_SLOT_INVALID ||
	    !vector->mailbox_generation)
		return;
	mailbox = &shared->irq_mailbox;
	entry = &mailbox->entries[vector->mailbox_slot];
	for (;;) {
		token = atomic64_read_acquire(&entry->pending_generation);
		if (mk_irq_mailbox_generation(token) !=
		    vector->mailbox_generation) {
			atomic_inc(&mailbox->stale);
			return;
		}
		if (atomic64_cmpxchg_release(&entry->pending_generation,
					     token, 0) == token)
			break;
		cpu_relax();
	}
	mk_pci_mailbox_clear_bit(mailbox, vector->mailbox_slot);
	WRITE_ONCE(entry->lifecycle_epoch, 0);
	WRITE_ONCE(entry->lifecycle_generation, 0);
	WRITE_ONCE(entry->device_id, 0);
	WRITE_ONCE(entry->local_irq, 0);
	WRITE_ONCE(entry->vector, 0);
	vector->mailbox_slot = MK_IRQ_MAILBOX_SLOT_INVALID;
	vector->mailbox_generation = 0;
}

static int mk_pci_mailbox_reserve(struct mk_pci_irq_vector *vector,
				  unsigned int vector_index)
{
	struct mk_pci_assignment *assignment = vector->assignment;
	struct mk_shared_data *shared = assignment->instance->ipi_data;
	struct mk_irq_mailbox *mailbox;
	struct mk_irq_mailbox_entry *entry;
	u32 generation;
	u32 device_id;
	unsigned int slot;
	u64 base;

	if (!shared)
		return -ENODEV;
	mailbox = &shared->irq_mailbox;
	generation = (u32)atomic_inc_return(&mailbox->next_generation);
	if (!generation)
		generation = (u32)atomic_inc_return(&mailbox->next_generation);
	if (!generation)
		return -EOVERFLOW;
	device_id = MK_PCI_IRQ_ID(pci_domain_nr(assignment->vf->bus),
				  assignment->vf->bus->number,
				  assignment->vf->devfn);
	base = mk_irq_mailbox_token(generation, 0) | MK_IRQ_MAILBOX_MASKED;
	for (slot = 0; slot < MK_IRQ_MAILBOX_SLOTS; slot++) {
		entry = &mailbox->entries[slot];
		if (atomic64_read(&entry->pending_generation))
			continue;
		if (atomic64_cmpxchg_release(&entry->pending_generation, 0,
					     base))
			continue;
		WRITE_ONCE(entry->lifecycle_epoch, assignment->irq_epoch);
		WRITE_ONCE(entry->lifecycle_generation,
			   assignment->irq_generation);
		WRITE_ONCE(entry->device_id, device_id);
		WRITE_ONCE(entry->local_irq, 0);
		WRITE_ONCE(entry->vector, vector_index);
		vector->mailbox_slot = slot;
		vector->mailbox_generation = generation;
		return 0;
	}
	return -ENOSPC;
}

void mk_pci_irq_retry_workfn(struct work_struct *work)
{
	struct mk_instance *instance = container_of(to_delayed_work(work),
						   struct mk_instance,
						   irq_retry_work);
	struct mk_shared_data *shared = READ_ONCE(instance->ipi_data);
	bool any_pending = false;
	bool unmasked_pending = false;
	mk_phys_cpu_t target;
	unsigned int slot;

	if (!shared)
		return;
	for (slot = 0; slot < MK_IRQ_MAILBOX_SLOTS; slot++) {
		struct mk_irq_mailbox_entry *entry;
		u64 token;

		entry = &shared->irq_mailbox.entries[slot];
		token = atomic64_read_acquire(&entry->pending_generation);

		if (!mk_irq_mailbox_generation(token))
			continue;
		if (mk_irq_mailbox_pending(token)) {
			any_pending = true;
			atomic64_or(BIT_ULL(slot & 63),
				    &shared->irq_mailbox.pending_bitmap[slot / 64]);
			if (!mk_irq_mailbox_masked(token))
				unmasked_pending = true;
		} else if (mk_irq_mailbox_consuming(token)) {
			any_pending = true;
		}
	}
	if (unmasked_pending) {
		target = mk_instance_irq_route_load(instance);
		if (target != MK_PHYS_CPU_INVALID)
			mk_arch_send_ipi(target);
	}
	if (any_pending)
		mod_delayed_work(system_wq, &instance->irq_retry_work,
				 msecs_to_jiffies(unmasked_pending ? 10 : 100));
}

static irqreturn_t mk_pci_forward_irq(int irq, void *data)
{
	struct mk_pci_irq_vector *vector = data;
	struct mk_pci_assignment *assignment = vector->assignment;
	struct mk_shared_data *shared = assignment->instance->ipi_data;
	struct mk_irq_mailbox *mailbox;
	struct mk_irq_mailbox_entry *entry;
	mk_phys_cpu_t target;
	u64 old, new;
	u32 pending;
	u32 local_irq;

	/* Pair with BIND's publication of the shared mailbox identity. */
	local_irq = smp_load_acquire(&vector->local_irq);

	if (READ_ONCE(assignment->instance->state) != MK_STATE_ACTIVE ||
	    READ_ONCE(assignment->irq_state) != MK_PCI_MSI_ACTIVE ||
	    !local_irq || !shared ||
	    vector->mailbox_slot == MK_IRQ_MAILBOX_SLOT_INVALID ||
	    !vector->mailbox_generation)
		return IRQ_HANDLED;
	mailbox = &shared->irq_mailbox;
	entry = &mailbox->entries[vector->mailbox_slot];
	for (;;) {
		old = atomic64_read_acquire(&entry->pending_generation);
		if (mk_irq_mailbox_generation(old) !=
		    vector->mailbox_generation) {
			atomic_inc(&mailbox->stale);
			return IRQ_HANDLED;
		}
		pending = mk_irq_mailbox_pending(old);
		if (pending == MK_IRQ_MAILBOX_PENDING_MASK) {
			atomic_inc(&mailbox->saturated);
			break;
		}
		new = mk_irq_mailbox_token(vector->mailbox_generation,
					   pending + 1) |
			(old & (MK_IRQ_MAILBOX_MASKED |
				MK_IRQ_MAILBOX_CONSUMING));
		if (atomic64_cmpxchg(&entry->pending_generation, old, new) == old)
			break;
		cpu_relax();
	}
	atomic64_or(BIT_ULL(vector->mailbox_slot & 63),
		    &mailbox->pending_bitmap[vector->mailbox_slot / 64]);
	atomic_inc(&mailbox->recorded);
	if (!pending)
		mod_delayed_work(system_wq, &assignment->instance->irq_retry_work,
				 msecs_to_jiffies(10));
	if (atomic64_inc_return(&vector->forwarded) == 1)
		pr_info("Forwarding host IRQ %u as instance IRQ %u for %s vector %u\n",
			irq, local_irq, pci_name(assignment->vf),
			(unsigned int)(vector - assignment->irq_vectors));
	target = mk_instance_irq_route_load(assignment->instance);
	if (target != MK_PHYS_CPU_INVALID)
		mk_arch_send_ipi(target);
	return IRQ_HANDLED;
}

static unsigned int mk_pci_quiesce_irqs(struct mk_pci_assignment *assignment,
					bool parked_force,
					unsigned long deadline)
{
	unsigned int disabled = 0;
	unsigned int i;

	assignment->irq_mailbox_failed = false;
	for (i = 0; i < assignment->nr_irq_vectors; i++)
		WRITE_ONCE(assignment->irq_vectors[i].local_irq, 0);

	for (i = 0; i < assignment->nr_irq_vectors; i++) {
		struct mk_pci_irq_vector *vector = &assignment->irq_vectors[i];

		if (vector->requested && !vector->disabled) {
			disable_irq(vector->host_irq);
			vector->disabled = true;
			disabled++;
		}
	}
	for (i = 0; i < assignment->nr_irq_vectors; i++) {
		struct mk_pci_irq_vector *vector = &assignment->irq_vectors[i];

		if (!mk_pci_mailbox_quiesce(vector, parked_force, deadline))
			assignment->irq_mailbox_failed = true;
	}
	if (assignment->irq_bound_map)
		bitmap_zero(assignment->irq_bound_map,
			    assignment->nr_irq_vectors);
	if (assignment->irq_state != MK_PCI_MSI_IDLE &&
	    assignment->irq_state != MK_PCI_MSI_FAILED)
		assignment->irq_state = MK_PCI_MSI_PREPARED;

	return disabled;
}

int mk_pci_release_irqs(struct mk_pci_assignment *assignment,
			       bool parked_force)
{
	unsigned long deadline = mk_pci_mailbox_deadline();
	unsigned int i;

	mk_pci_quiesce_irqs(assignment, parked_force, deadline);
	if (assignment->irq_mailbox_failed)
		return -ETIMEDOUT;
	for (i = 0; i < assignment->nr_irq_vectors; i++) {
		struct mk_pci_irq_vector *vector = &assignment->irq_vectors[i];

		if (vector->requested)
			free_irq(vector->host_irq, vector);
		mk_pci_mailbox_release(vector);
	}
	if (assignment->nr_irq_vectors)
		pci_free_irq_vectors(assignment->vf);
	kfree(assignment->irq_vectors);
	bitmap_free(assignment->irq_bound_map);
	assignment->irq_vectors = NULL;
	assignment->irq_bound_map = NULL;
	assignment->nr_irq_vectors = 0;
	assignment->irq_msix = false;
	assignment->irq_needs_reprogram = false;
	assignment->irq_flr_deadline = 0;
	assignment->irq_mailbox_failed = false;
	return 0;
}

int mk_pci_quiesce_instance_irqs(struct mk_instance *instance,
				 bool parked_force)
{
	struct mk_pci_assignment *assignment;
	unsigned long deadline = mk_pci_mailbox_deadline();
	unsigned int disabled = 0;
	int ret = 0;

	if (!instance || instance == root_instance)
		return 0;

	lockdep_assert_held(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	list_for_each_entry(assignment, &instance->pci_assignments,
			    instance_node) {
		disabled += mk_pci_quiesce_irqs(assignment, parked_force,
						deadline);
		if (assignment->irq_mailbox_failed)
			ret = -ETIMEDOUT;
	}
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	if (disabled)
		pr_info("Quiesced %u host-owned PCI IRQ vectors for instance %d\n",
			disabled, instance->id);
	return ret;
}

unsigned int mk_pci_sync_instance_irq_route(struct mk_instance *instance)
{
	struct mk_pci_assignment *assignment;
	unsigned int requested = 0;
	unsigned int i;

	lockdep_assert_held(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	list_for_each_entry(assignment, &instance->pci_assignments,
			    instance_node) {
		for (i = 0; i < assignment->nr_irq_vectors; i++) {
			struct mk_pci_irq_vector *vector =
				&assignment->irq_vectors[i];

			if (vector->requested) {
				requested++;
				synchronize_irq(vector->host_irq);
			}
		}
	}
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	if (requested) {
		mk_phys_cpu_t target = mk_instance_irq_route_load(instance);

		if (target != MK_PHYS_CPU_INVALID)
			mk_arch_send_ipi(target);
	}
	return requested;
}

static bool mk_pci_generation_after(u32 generation, u32 last)
{
	return !last || (s32)(generation - last) > 0;
}

static int mk_pci_setup_irqs(struct mk_pci_assignment *assignment,
			     const struct mk_pci_irq_request *request)
{
	struct mk_pci_irq_vector *vectors;
	unsigned long *bound_map;
	unsigned int flags;
	int forwarding_cpu;
	int i;
	int nvec;
	int ret;

	if (!request->nr_vectors ||
	    request->nr_vectors > MK_IRQ_MAILBOX_SLOTS)
		return -EINVAL;
	if (!request->lifecycle_generation)
		return -EINVAL;
	if (assignment->irq_epoch &&
	    assignment->irq_epoch != request->lifecycle_epoch)
		return -ESTALE;
	forwarding_cpu = mk_pci_forwarding_cpu();
	if (forwarding_cpu < 0) {
		pr_err("Host control CPU is unavailable for %s MSI forwarding\n",
		       pci_name(assignment->vf));
		return forwarding_cpu;
	}
	if (assignment->irq_generation == request->lifecycle_generation) {
		if ((assignment->irq_state == MK_PCI_MSI_PREPARED ||
		     assignment->irq_state == MK_PCI_MSI_COMMITTED ||
		     assignment->irq_state == MK_PCI_MSI_ACTIVE) &&
		    assignment->nr_irq_vectors == request->nr_vectors &&
		    assignment->irq_msix == request->msix)
			return 0;
		return -ESTALE;
	}
	if (!mk_pci_generation_after(request->lifecycle_generation,
				     assignment->irq_generation))
		return -ESTALE;
	if (assignment->nr_irq_vectors) {
		ret = mk_pci_release_irqs(assignment, false);
		if (ret)
			return ret;
	}
	assignment->irq_epoch = request->lifecycle_epoch;
	assignment->irq_generation = request->lifecycle_generation;
	assignment->irq_state = MK_PCI_MSI_FAILED;

	vectors = kcalloc(request->nr_vectors, sizeof(*vectors), GFP_KERNEL);
	if (!vectors)
		return -ENOMEM;
	bound_map = bitmap_zalloc(request->nr_vectors, GFP_KERNEL);
	if (!bound_map) {
		kfree(vectors);
		return -ENOMEM;
	}
	flags = request->msix ? PCI_IRQ_MSIX : PCI_IRQ_MSI;
	nvec = pci_alloc_irq_vectors(assignment->vf, request->nr_vectors,
				     request->nr_vectors, flags);
	if (nvec < 0) {
		bitmap_free(bound_map);
		kfree(vectors);
		return nvec;
	}

	assignment->irq_vectors = vectors;
	assignment->irq_bound_map = bound_map;
	assignment->nr_irq_vectors = nvec;
	assignment->irq_msix = request->msix;
	for (i = 0; i < nvec; i++) {
		vectors[i].assignment = assignment;
		vectors[i].host_irq = pci_irq_vector(assignment->vf, i);
		vectors[i].mailbox_slot = MK_IRQ_MAILBOX_SLOT_INVALID;
		ret = mk_pci_mailbox_reserve(&vectors[i], i);
		if (ret)
			goto err_release;
	}
	for (i = 0; i < nvec; i++) {
		ret = request_irq(vectors[i].host_irq, mk_pci_forward_irq,
				  IRQF_NO_AUTOEN | IRQF_NOBALANCING,
				  "multikernel-pci-forward", &vectors[i]);
		if (ret)
			goto err_release;
		vectors[i].requested = true;
		vectors[i].disabled = true;
		ret = irq_set_affinity(vectors[i].host_irq,
				       cpumask_of(forwarding_cpu));
		if (ret)
			goto err_release;
	}
	assignment->irq_state = MK_PCI_MSI_PREPARED;
	pr_info("Allocated %d host-owned %s vectors for %s (instance %d, CPU %d)\n",
		nvec, request->msix ? "MSI-X" : "MSI",
		pci_name(assignment->vf), assignment->instance->id,
		forwarding_cpu);
	return 0;

err_release:
	pr_err("Failed to configure host-owned IRQ for %s vector %d: %d\n",
	       pci_name(assignment->vf), i, ret);
	if (mk_pci_release_irqs(assignment, false))
		return -ETIMEDOUT;
	return ret;
}

static int mk_pci_bind_irq(struct mk_pci_assignment *assignment,
			   const struct mk_pci_irq_request *request)
{
	struct mk_shared_data *shared = assignment->instance->ipi_data;
	struct mk_pci_irq_vector *vector;
	unsigned long delay;
	unsigned int count;
	unsigned int i;
	u32 last_irq;
	u32 local_irq;

	if (mk_instance_irq_route_load(assignment->instance) ==
	    MK_PHYS_CPU_INVALID)
		return -ENODEV;
	if (!request->lifecycle_generation ||
	    assignment->irq_generation != request->lifecycle_generation)
		return -ESTALE;
	if (assignment->irq_epoch != request->lifecycle_epoch ||
	    (assignment->irq_state != MK_PCI_MSI_PREPARED &&
	     assignment->irq_state != MK_PCI_MSI_ACTIVE))
		return -ESTALE;

	if (!assignment->irq_vectors ||
	    assignment->irq_msix != request->msix)
		return -EINVAL;
	count = request->msix ? 1 : request->nr_vectors;
	if (!count || request->vector >= assignment->nr_irq_vectors ||
	    count > assignment->nr_irq_vectors - request->vector)
		return -EINVAL;
	last_irq = request->local_irq + count - 1;
	if (!request->local_irq || last_irq < request->local_irq)
		return -EINVAL;

	for (i = 0; i < count; i++) {
		struct mk_irq_mailbox_entry *entry;
		u64 token;

		vector = &assignment->irq_vectors[request->vector + i];
		local_irq = READ_ONCE(vector->local_irq);
		if (!vector->requested ||
		    vector->mailbox_slot == MK_IRQ_MAILBOX_SLOT_INVALID ||
		    !vector->mailbox_generation)
			return -EINVAL;
		entry = &shared->irq_mailbox.entries[vector->mailbox_slot];
		token = atomic64_read_acquire(&entry->pending_generation);
		if (mk_irq_mailbox_generation(token) !=
		    vector->mailbox_generation ||
		    READ_ONCE(entry->lifecycle_epoch) != assignment->irq_epoch ||
		    READ_ONCE(entry->lifecycle_generation) !=
			assignment->irq_generation ||
		    READ_ONCE(entry->vector) != request->vector + i)
			return -ESTALE;
		if (local_irq && local_irq != request->local_irq + i)
			return -EBUSY;
	}

	if (assignment->irq_needs_reprogram) {
		if (time_before(jiffies, assignment->irq_flr_deadline)) {
			delay = assignment->irq_flr_deadline - jiffies;
			msleep(jiffies_to_msecs(delay) + 1);
		}
		pci_restore_msi_state(assignment->vf);
		assignment->irq_needs_reprogram = false;
		assignment->irq_flr_deadline = 0;
		pr_info("Reprogrammed host-owned MSI state for %s during restore\n",
			pci_name(assignment->vf));
	}

	for (i = 0; i < count; i++) {
		struct mk_irq_mailbox_entry *entry;

		vector = &assignment->irq_vectors[request->vector + i];
		entry = &shared->irq_mailbox.entries[vector->mailbox_slot];
		WRITE_ONCE(entry->local_irq, request->local_irq + i);
		/* Make the shared identity visible before routing this vector. */
		smp_store_release(&vector->local_irq, request->local_irq + i);
	}
	bitmap_set(assignment->irq_bound_map, request->vector, count);
	return 0;
}

static int
mk_pci_restore_irqs_begin(struct mk_pci_assignment *assignment,
			  const struct mk_pci_irq_request *request)
{
	if (assignment->irq_epoch != request->lifecycle_epoch ||
	    assignment->irq_generation != request->lifecycle_generation)
		return -ESTALE;
	if (assignment->irq_state == MK_PCI_MSI_PREPARED &&
	    assignment->irq_needs_reprogram)
		return 0;
	if (assignment->irq_state != MK_PCI_MSI_ACTIVE)
		return -ESTALE;

	mk_pci_quiesce_irqs(assignment, false, mk_pci_mailbox_deadline());
	if (assignment->irq_mailbox_failed)
		return -ETIMEDOUT;
	assignment->irq_needs_reprogram = true;
	return 0;
}

static int mk_pci_commit_irqs(struct mk_pci_assignment *assignment,
			      const struct mk_pci_irq_request *request)
{
	unsigned int i;

	if (assignment->irq_epoch != request->lifecycle_epoch ||
	    assignment->irq_generation != request->lifecycle_generation ||
	    (assignment->irq_state != MK_PCI_MSI_PREPARED &&
	     assignment->irq_state != MK_PCI_MSI_ACTIVE) ||
	    !assignment->irq_bound_map ||
	    !bitmap_full(assignment->irq_bound_map,
			 assignment->nr_irq_vectors))
		return -ESTALE;

	for (i = 0; i < assignment->nr_irq_vectors; i++) {
		struct mk_pci_irq_vector *vector = &assignment->irq_vectors[i];

		if (!READ_ONCE(vector->local_irq))
			return -EINVAL;
	}
	if (assignment->irq_state == MK_PCI_MSI_ACTIVE)
		return 0;
	assignment->irq_state = MK_PCI_MSI_COMMITTED;
	return 0;
}

static int mk_pci_activate_irqs(struct mk_pci_assignment *assignment,
				const struct mk_pci_irq_request *request)
{
	unsigned int i;

	if (assignment->irq_epoch != request->lifecycle_epoch ||
	    assignment->irq_generation != request->lifecycle_generation)
		return -ESTALE;
	if (assignment->irq_state == MK_PCI_MSI_ACTIVE)
		return 0;
	if (assignment->irq_state != MK_PCI_MSI_COMMITTED ||
	    !assignment->nr_irq_vectors || !assignment->irq_bound_map ||
	    !bitmap_full(assignment->irq_bound_map,
			 assignment->nr_irq_vectors))
		return -ESTALE;
	for (i = 0; i < assignment->nr_irq_vectors; i++) {
		struct mk_pci_irq_vector *vector = &assignment->irq_vectors[i];

		if (!vector->requested || !READ_ONCE(vector->local_irq))
			return -EINVAL;
	}
	assignment->irq_state = MK_PCI_MSI_ACTIVE;
	for (i = 0; i < assignment->nr_irq_vectors; i++) {
		struct mk_pci_irq_vector *vector = &assignment->irq_vectors[i];

		if (vector->disabled) {
			enable_irq(vector->host_irq);
			vector->disabled = false;
		}
	}
	return 0;
}

static int mk_pci_teardown_irqs(struct mk_pci_assignment *assignment,
				const struct mk_pci_irq_request *request)
{
	if (assignment->irq_epoch &&
	    assignment->irq_epoch != request->lifecycle_epoch)
		return -ESTALE;
	if (assignment->irq_generation != request->lifecycle_generation &&
	    !mk_pci_generation_after(request->lifecycle_generation,
				     assignment->irq_generation))
		return -ESTALE;

	if (assignment->nr_irq_vectors) {
		int ret = mk_pci_release_irqs(assignment, false);

		if (ret)
			return ret;
	}
	assignment->irq_epoch = request->lifecycle_epoch;
	assignment->irq_generation = request->lifecycle_generation;
	assignment->irq_state = MK_PCI_MSI_IDLE;
	return 0;
}

static bool mk_pci_is_flr_write(struct pci_dev *vf,
				const struct mk_pci_cfg_request *request)
{
	u16 flr_byte;
	unsigned int bit;

	if (!request->write || !pci_is_pcie(vf))
		return false;
	flr_byte = pci_pcie_cap(vf) + PCI_EXP_DEVCTL + 1;
	if (request->reg > flr_byte ||
	    request->reg + request->len <= flr_byte)
		return false;
	bit = (flr_byte - request->reg) * 8 + 7;
	return request->value & BIT(bit);
}

static bool mk_pci_request_route_stale(struct mk_instance *instance,
				       mk_phys_cpu_t sender_cpu)
{
	if (!instance || instance == root_instance)
		return true;
	if (READ_ONCE(instance->state) != MK_STATE_ACTIVE)
		return true;

	mk_cpu_ownership_assert_held();
	return !mk_cpu_set_contains(instance->cpus, sender_cpu);
}

static int mk_pci_config_access(struct mk_instance *instance,
				const struct mk_pci_cfg_request *request,
				u32 *value,
				const struct mk_reply_handle *reply)
{
	struct mk_pci_assignment *assignment;
	struct pci_dev *vf;
	bool flr;
	int ret;

	if (request->len != 1 && request->len != 2 && request->len != 4)
		return PCIBIOS_BAD_REGISTER_NUMBER;
	if (request->reg > PCI_CFG_SPACE_EXP_SIZE - request->len)
		return PCIBIOS_BAD_REGISTER_NUMBER;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	assignment = mk_pci_find_assignment(instance, request->domain,
					    request->bus, request->devfn);
	if (!assignment || !assignment->assigned ||
	    !mk_pci_device_live(assignment->vf)) {
		ret = PCIBIOS_DEVICE_NOT_FOUND;
		goto out;
	}
	ret = mk_reply_begin_execute(instance, reply);
	if (ret)
		goto out;
	/* Committed: complete and let publish reclaim an indeterminate timeout. */

	vf = assignment->vf;
	flr = mk_pci_is_flr_write(vf, request);
	if (flr) {
		ret = PCIBIOS_SET_FAILED;
		goto out;
	}
	if (request->write) {
		switch (request->len) {
		case 1:
			ret = pci_write_config_byte(vf, request->reg,
						    request->value);
			break;
		case 2:
			ret = pci_write_config_word(vf, request->reg,
						    request->value);
			break;
		default:
			ret = pci_write_config_dword(vf, request->reg,
						     request->value);
			break;
		}
	} else {
		switch (request->len) {
		case 1: {
			u8 data;

			ret = pci_read_config_byte(vf, request->reg, &data);
			*value = data;
			break;
		}
		case 2: {
			u16 data;

			ret = pci_read_config_word(vf, request->reg, &data);
			*value = data;
			break;
		}
		default:
			ret = pci_read_config_dword(vf, request->reg, value);
			break;
		}
	}
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	return ret;
}

static void mk_pci_cfg_work_fn(struct work_struct *work)
{
	struct mk_pci_control_work *control_work =
		container_of(work, struct mk_pci_control_work, work);
	struct mk_pci_cfg_request *request = &control_work->request.cfg;
	struct mk_reply_handle reply = {
		.slot = request->reply_slot,
		.kind = MK_REPLY_PCI_CFG,
		.request_id = request->request_id,
		.generation = request->reply_generation,
	};
	struct mk_instance *instance;
	u32 value = ~0U;
	s32 status;

	instance = mk_instance_find(request->sender_instance_id);
	if (!instance)
		goto out;
	down_read(&instance->control_route_sem);
	mk_cpu_ownership_lock();
	status = mk_pci_request_route_stale(instance, control_work->sender_cpu) ?
		-ESTALE : 0;
	mk_cpu_ownership_unlock();
	/* An untrusted payload ID must never select another instance's slot. */
	if (status)
		goto unlock_route;
	if (mk_reply_claim(instance, &reply))
		goto unlock_route;
	status = mk_pci_config_access(instance, request, &value, &reply);
	if (mk_reply_publish(instance, &reply, status, value))
		pr_warn_ratelimited("Failed to return PCI config response to instance %d\n",
				    instance->id);
unlock_route:
	up_read(&instance->control_route_sem);
	mk_instance_put(instance);
out:
	mempool_free(control_work, mk_pci_control_pool);
}

static int mk_pci_irq_access(struct mk_instance *instance,
			     const struct mk_pci_irq_request *request,
			     const struct mk_reply_handle *reply)
{
	struct mk_pci_assignment *assignment;
	int ret;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	if (request->operation != MK_PCI_IRQ_TEARDOWN &&
	    READ_ONCE(instance->state) != MK_STATE_ACTIVE) {
		ret = -ESHUTDOWN;
		goto out;
	}
	assignment = mk_pci_find_assignment(instance, request->domain,
					    request->bus, request->devfn);
	if (!assignment || !assignment->assigned ||
	    !mk_pci_device_live(assignment->vf)) {
		ret = -ENODEV;
		goto out;
	}
	if (!instance->ipi_data || !request->lifecycle_epoch ||
	    request->lifecycle_epoch !=
		READ_ONCE(instance->ipi_data->spawn_epoch)) {
		ret = -ESTALE;
		goto out;
	}
	ret = mk_reply_begin_execute(instance, reply);
	if (ret)
		goto out;
	/*
	 * This CAS is the sole cancellation boundary.  IRQ programming is
	 * non-cancellable once EXECUTING; a timed-out waiter moves the exact
	 * generation to COMMITTED for mk_reply_publish() to reclaim afterwards.
	 */

	switch (request->operation) {
	case MK_PCI_IRQ_SETUP:
		ret = mk_pci_setup_irqs(assignment, request);
		break;
	case MK_PCI_IRQ_RESTORE_BEGIN:
		ret = mk_pci_restore_irqs_begin(assignment, request);
		break;
	case MK_PCI_IRQ_BIND:
		ret = mk_pci_bind_irq(assignment, request);
		break;
	case MK_PCI_IRQ_COMMIT:
		ret = mk_pci_commit_irqs(assignment, request);
		break;
	case MK_PCI_IRQ_ACTIVATE:
		ret = mk_pci_activate_irqs(assignment, request);
		break;
	case MK_PCI_IRQ_TEARDOWN:
		ret = mk_pci_teardown_irqs(assignment, request);
		break;
	default:
		ret = -EINVAL;
		break;
	}
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	return ret;
}

static void mk_pci_irq_work_fn(struct work_struct *work)
{
	struct mk_pci_control_work *control_work =
		container_of(work, struct mk_pci_control_work, work);
	struct mk_pci_irq_request *request = &control_work->request.irq;
	struct mk_reply_handle reply = {
		.slot = request->reply_slot,
		.kind = MK_REPLY_PCI_IRQ,
		.request_id = request->request_id,
		.generation = request->reply_generation,
	};
	struct mk_instance *instance;
	s32 status;

	instance = mk_instance_find(request->sender_instance_id);
	if (!instance)
		goto out;
	down_read(&instance->control_route_sem);
	mk_cpu_ownership_lock();
	status = mk_pci_request_route_stale(instance, control_work->sender_cpu) ?
		-ESTALE : 0;
	mk_cpu_ownership_unlock();
	if (status)
		goto unlock_route;
	if (mk_reply_claim(instance, &reply))
		goto unlock_route;
	status = mk_pci_irq_access(instance, request, &reply);
	if (mk_reply_publish(instance, &reply, status, 0))
		pr_warn_ratelimited("Failed to return PCI IRQ response to instance %d\n",
				    instance->id);
unlock_route:
	up_read(&instance->control_route_sem);
	mk_instance_put(instance);
out:
	mempool_free(control_work, mk_pci_control_pool);
}

static int mk_pci_reset_access(struct mk_instance *instance,
			       const struct mk_pci_reset_request *request,
			       const struct mk_reply_handle *reply)
{
	struct mk_pci_assignment *assignment;
	int ret;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	if (READ_ONCE(instance->state) != MK_STATE_ACTIVE) {
		ret = -ESHUTDOWN;
		goto out;
	}
	assignment = mk_pci_find_assignment(instance, request->domain,
					    request->bus, request->devfn);
	if (!assignment || !assignment->assigned ||
	    !mk_pci_device_live(assignment->vf) || !assignment->vf->is_virtfn) {
		ret = -ENODEV;
		goto out;
	}
	if (!instance->ipi_data || !request->lifecycle_epoch ||
	    request->lifecycle_epoch !=
		READ_ONCE(instance->ipi_data->spawn_epoch) ||
	    !request->reset_generation ||
	    !mk_pci_generation_after(request->reset_generation,
				     assignment->reset_generation)) {
		ret = -ESTALE;
		goto out;
	}
	ret = mk_reply_begin_execute(instance, reply);
	if (ret)
		goto out;

	/* Tombstone this serial before side effects so delayed replays reject. */
	assignment->reset_generation = request->reset_generation;
	mk_pci_quiesce_irqs(assignment, false, mk_pci_mailbox_deadline());
	if (assignment->irq_mailbox_failed) {
		assignment->irq_state = MK_PCI_MSI_FAILED;
		mk_pci_schedule_failure(assignment);
		ret = -ETIMEDOUT;
		goto out;
	}
	ret = pcie_reset_flr(assignment->vf, false);
	if (ret) {
		assignment->irq_state = MK_PCI_MSI_FAILED;
		mk_pci_schedule_failure(assignment);
		goto out;
	}
	if (assignment->nr_irq_vectors) {
		assignment->irq_needs_reprogram = true;
		assignment->irq_flr_deadline =
			jiffies + msecs_to_jiffies(MK_PCI_FLR_SETTLE_MS);
	}
	pr_info("Invalidated host-owned MSI bindings for spawn-triggered FLR of %s\n",
		pci_name(assignment->vf));
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	return ret;
}

static void mk_pci_reset_work_fn(struct work_struct *work)
{
	struct mk_pci_control_work *control_work =
		container_of(work, struct mk_pci_control_work, work);
	struct mk_pci_reset_request *request = &control_work->request.reset;
	struct mk_reply_handle reply = {
		.slot = request->reply_slot,
		.kind = MK_REPLY_PCI_RESET,
		.request_id = request->request_id,
		.generation = request->reply_generation,
	};
	struct mk_instance *instance;
	s32 status;

	instance = mk_instance_find(request->sender_instance_id);
	if (!instance)
		goto out;
	down_read(&instance->control_route_sem);
	mk_cpu_ownership_lock();
	status = mk_pci_request_route_stale(instance, control_work->sender_cpu) ?
		-ESTALE : 0;
	mk_cpu_ownership_unlock();
	if (status)
		goto unlock_route;
	if (mk_reply_claim(instance, &reply))
		goto unlock_route;
	status = mk_pci_reset_access(instance, request, &reply);
	if (mk_reply_publish(instance, &reply, status, 0))
		pr_warn_ratelimited("Failed to return PCI reset response to instance %d\n",
				    instance->id);
unlock_route:
	up_read(&instance->control_route_sem);
	mk_instance_put(instance);
out:
	mempool_free(control_work, mk_pci_control_pool);
}

static void mk_pci_control_msg_handler(u32 msg_type, u32 subtype,
				       void *payload, u32 payload_len,
				       mk_phys_cpu_t sender_cpu, void *ctx)
{
	struct mk_pci_control_work *control_work;
	size_t request_size;
	work_func_t work_fn;

	if (msg_type != MK_MSG_PCI)
		return;
	if (!mk_pci_control_handler_get())
		return;

	switch (subtype) {
	case MK_PCI_CFG_REQUEST:
		request_size = sizeof(control_work->request.cfg);
		work_fn = mk_pci_cfg_work_fn;
		break;
	case MK_PCI_IRQ_REQUEST:
		request_size = sizeof(control_work->request.irq);
		work_fn = mk_pci_irq_work_fn;
		break;
	case MK_PCI_RESET_REQUEST:
		request_size = sizeof(control_work->request.reset);
		work_fn = mk_pci_reset_work_fn;
		break;
	default:
		goto out;
	}
	if (payload_len != request_size)
		goto out;
	/*
	 * Valid senders reserve one of MK_REPLY_SLOTS before publishing. Every
	 * active instance owns at least one disjoint possible CPU, so the pool
	 * covers the maximum number of valid requests across all instances. This
	 * keeps the hardirq receive path allocation-safe without changing reply
	 * or route validation. Duplicate traffic is outside the cooperative ABI.
	 */
	control_work = mempool_alloc(mk_pci_control_pool, GFP_ATOMIC);
	if (!control_work) {
		atomic64_inc(&mk_pci_control_pool_exhausted);
		pr_warn_ratelimited("Multikernel PCI control work pool exhausted\n");
		goto out;
	}
	INIT_WORK(&control_work->work, work_fn);
	memcpy(&control_work->request, payload, request_size);
	control_work->sender_cpu = sender_cpu;
	if (!queue_work(mk_pci_control_wq, &control_work->work))
		mempool_free(control_work, mk_pci_control_pool);
out:
	mk_pci_control_handler_put();
}

void mk_pci_assignment_failure_work(struct work_struct *work)
{
	struct mk_pci_assignment *assignment =
		container_of(work, struct mk_pci_assignment, failure_work);
	struct mk_instance *instance = assignment->instance;
	int ret;

	pr_err("PCI assignment lease for %s was lost by instance %d (%s)\n",
	       pci_name(assignment->vf), instance->id, instance->name);

	if (READ_ONCE(instance->state) == MK_STATE_ACTIVE) {
		ret = mk_instance_force_halt(instance);
		if (ret)
			pr_err("Failed to force halt instance %d after PCI lease loss: %d\n",
			       instance->id, ret);
	}

	mk_instance_mark_failed(instance);
}

void mk_pci_schedule_failure(struct mk_pci_assignment *assignment)
{
	if (atomic_cmpxchg(&assignment->failure_pending, 0, 1))
		return;

	if (!schedule_work(&assignment->failure_work))
		atomic_set(&assignment->failure_pending, 0);
}

static int mk_pci_bus_notify(struct notifier_block *nb, unsigned long action,
			     void *data)
{
	struct pci_dev *pdev = to_pci_dev(data);
	struct mk_pci_assignment *assignment;
	unsigned long flags;

	if (action != BUS_NOTIFY_DEL_DEVICE &&
	    action != BUS_NOTIFY_REMOVED_DEVICE &&
	    action != BUS_NOTIFY_UNBOUND_DRIVER)
		return NOTIFY_DONE;

	spin_lock_irqsave(&mk_pci_active_lock, flags);
	list_for_each_entry(assignment, &mk_pci_active_assignments,
			    active_node) {
		if (pdev != assignment->vf && pdev != assignment->pf)
			continue;
		if (pdev == assignment->vf &&
		    action == BUS_NOTIFY_UNBOUND_DRIVER &&
		    assignment->expected_unbind)
			continue;
		mk_pci_schedule_failure(assignment);
	}
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);

	return NOTIFY_OK;
}

static struct notifier_block mk_pci_bus_notifier = {
	.notifier_call = mk_pci_bus_notify,
};

int mk_pci_control_system_init(void)
{
	unsigned int pool_size;
	size_t work_size = sizeof(struct mk_pci_control_work);
	int ret;

	ret = bus_register_notifier(&pci_bus_type, &mk_pci_bus_notifier);
	if (ret)
		return ret;
	mk_pci_notifier_registered = true;
	if (!root_instance || root_instance->id != 0)
		return 0;

	pool_size = max_t(unsigned int, num_possible_cpus(), 1) *
		MK_REPLY_SLOTS;
	mk_pci_control_pool = mempool_create_kmalloc_pool(pool_size, work_size);
	if (!mk_pci_control_pool) {
		ret = -ENOMEM;
		goto unregister_notifier;
	}
	mk_pci_control_wq = alloc_workqueue("mk-pci-control",
					WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!mk_pci_control_wq) {
		ret = -ENOMEM;
		goto destroy_pool;
	}
	mk_pci_control_shutdown_end();
	ret = mk_register_msg_handler(MK_MSG_PCI, mk_pci_control_msg_handler,
				      NULL);
	if (ret)
		goto destroy_workqueue;
	mk_pci_control_registered = true;
	return 0;

destroy_workqueue:
	mk_pci_control_shutdown_begin();
	destroy_workqueue(mk_pci_control_wq);
	mk_pci_control_wq = NULL;
destroy_pool:
	mempool_destroy(mk_pci_control_pool);
	mk_pci_control_pool = NULL;
unregister_notifier:
	bus_unregister_notifier(&pci_bus_type, &mk_pci_bus_notifier);
	mk_pci_notifier_registered = false;
	return ret;
}

void mk_pci_control_system_cleanup(void)
{
	if (mk_pci_control_registered) {
		mk_pci_control_shutdown_begin();
		mk_unregister_msg_handler(MK_MSG_PCI,
					  mk_pci_control_msg_handler);
		mk_pci_control_registered = false;
		wait_event(mk_pci_control_waitq,
			   !READ_ONCE(mk_pci_control_active));
	}
	if (mk_pci_control_wq) {
		destroy_workqueue(mk_pci_control_wq);
		mk_pci_control_wq = NULL;
	}
	mempool_destroy(mk_pci_control_pool);
	mk_pci_control_pool = NULL;
	if (mk_pci_notifier_registered) {
		bus_unregister_notifier(&pci_bus_type, &mk_pci_bus_notifier);
		mk_pci_notifier_registered = false;
	}
}
