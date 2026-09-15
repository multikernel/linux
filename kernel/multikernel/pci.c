// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multikernel PCI assignment policy
 *
 * Keeps assigned-device discovery, identity presentation, bridge traversal,
 * and resource restoration independent from the manifest that populated
 * the current instance.
 *
 * Configuration-space filtering constrains normal PCI access by a cooperative
 * spawn kernel. It is not a security boundary: a privileged kernel can issue
 * configuration cycles or map physical configuration windows directly. The
 * host-owned IOMMU domain separately constrains DMA initiated by an assigned
 * device.
 */

#include <linux/bitmap.h>
#include <linux/delay.h>
#include <linux/device/bus.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/overflow.h>
#include <linux/pci.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "internal.h"

struct mk_pci_assignment;

#define MK_PCI_FLR_SETTLE_MS	100
#define MK_PCI_MAILBOX_QUIESCE_MS	1000

static unsigned long mk_pci_mailbox_deadline(void)
{
	return jiffies + msecs_to_jiffies(MK_PCI_MAILBOX_QUIESCE_MS);
}

struct mk_pci_irq_vector {
	struct mk_pci_assignment *assignment;
	unsigned int host_irq;
	u32 local_irq;
	u32 mailbox_slot;
	u32 mailbox_generation;
	atomic64_t forwarded;
	bool requested;
	bool disabled;
};

struct mk_pci_assignment {
	struct list_head instance_node;
	struct list_head active_node;
	struct list_head transaction_node;
	struct mk_instance *instance;
	struct mk_pci_device *inventory;
	struct pci_dev *vf;
	struct pci_dev *pf;
	const struct device_driver *host_driver;
	struct iommu_group *iommu_group;
	struct iommu_domain *iommu_domain;
	char *host_driver_override;
	struct mutex iommu_mutex; /* Serializes IOMMU activation and teardown. */
	unsigned int iommu_mapped_regions;
	bool iommu_dma_owner;
	bool iommu_attached;
	bool iommu_override_active;
	struct mk_pci_irq_vector *irq_vectors;
	unsigned long *irq_bound_map;
	unsigned int nr_irq_vectors;
	u64 irq_epoch;
	u32 irq_generation;
	u32 reset_generation;
	u8 irq_state;
	bool irq_msix;
	bool irq_needs_reprogram;
	bool irq_mailbox_failed;
	unsigned long irq_flr_deadline;
	bool device_enabled;
	struct work_struct failure_work;
	atomic_t failure_pending;
	bool assigned;
	bool inventory_moved;
	bool expected_unbind;
};

static DEFINE_MUTEX(mk_pci_lease_mutex);
static DEFINE_SPINLOCK(mk_pci_active_lock);
static LIST_HEAD(mk_pci_active_assignments);
static bool mk_pci_notifier_registered;
static bool mk_pci_control_registered;
static struct mk_pci_control_work *mk_pci_control_pool;
static unsigned long *mk_pci_control_pool_busy;
static unsigned int mk_pci_control_pool_size;
static atomic_t mk_pci_control_pool_cursor = ATOMIC_INIT(0);
static struct workqueue_struct *mk_pci_control_wq;
static DECLARE_WAIT_QUEUE_HEAD(mk_pci_control_waitq);
#define MK_PCI_CONTROL_SHUTDOWN	BIT(30)
#define MK_PCI_CONTROL_ACTIVE_MASK	(MK_PCI_CONTROL_SHUTDOWN - 1)
static atomic_t mk_pci_control_state = ATOMIC_INIT(MK_PCI_CONTROL_SHUTDOWN);
static atomic64_t mk_pci_control_pool_exhausted = ATOMIC64_INIT(0);
static DEFINE_RATELIMIT_STATE(mk_pci_control_pool_rs,
			     DEFAULT_RATELIMIT_INTERVAL,
			     DEFAULT_RATELIMIT_BURST);

struct mk_pci_control_work {
	struct work_struct work;
	work_func_t dispatch;
	unsigned int pool_slot;
	s32 sender_instance_id;
	union {
		struct mk_pci_cfg_request cfg;
		struct mk_pci_irq_request irq;
		struct mk_pci_reset_request reset;
	} request;
};

static void mk_pci_schedule_failure(struct mk_pci_assignment *assignment);

static void mk_pci_control_wake_workfn(struct work_struct *work)
{
	wake_up_all(&mk_pci_control_waitq);
}

static DECLARE_WORK(mk_pci_control_wake_work,
			    mk_pci_control_wake_workfn);

static bool mk_pci_control_handler_get(void)
{
	int state = atomic_read(&mk_pci_control_state);

	for (;;) {
		if (state & MK_PCI_CONTROL_SHUTDOWN)
			return false;
		if ((state & MK_PCI_CONTROL_ACTIVE_MASK) ==
		    MK_PCI_CONTROL_ACTIVE_MASK)
			return false;
		if (atomic_try_cmpxchg(&mk_pci_control_state, &state, state + 1))
			return true;
	}
}

static void mk_pci_control_handler_put(void)
{
	int state = atomic_read(&mk_pci_control_state);
	int new_state;

	for (;;) {
		if (!(state & MK_PCI_CONTROL_ACTIVE_MASK))
			return;
		new_state = state - 1;
		if (atomic_try_cmpxchg(&mk_pci_control_state, &state, new_state))
			break;
	}
	if (new_state == MK_PCI_CONTROL_SHUTDOWN)
		schedule_work(&mk_pci_control_wake_work);
}

static void mk_pci_control_shutdown_begin(void)
{
	atomic_or(MK_PCI_CONTROL_SHUTDOWN, &mk_pci_control_state);
}

static void mk_pci_control_shutdown_end(void)
{
	WARN_ON_ONCE(atomic_read(&mk_pci_control_state) !=
		     MK_PCI_CONTROL_SHUTDOWN);
	atomic_set(&mk_pci_control_state, 0);
}

static struct mk_pci_control_work *mk_pci_control_work_get(void)
{
	unsigned int start;
	unsigned int slot;
	unsigned int i;

	start = (unsigned int)atomic_inc_return(&mk_pci_control_pool_cursor);
	for (i = 0; i < mk_pci_control_pool_size; i++) {
		slot = (start + i) % mk_pci_control_pool_size;
		if (!test_and_set_bit_lock(slot, mk_pci_control_pool_busy))
			return &mk_pci_control_pool[slot];
	}
	return NULL;
}

static void
mk_pci_control_work_put(struct mk_pci_control_work *control_work)
{
	clear_bit_unlock(control_work->pool_slot, mk_pci_control_pool_busy);
}

static bool mk_pci_device_live(struct pci_dev *pdev)
{
	return device_is_registered(&pdev->dev) &&
	       !pci_dev_is_disconnected(pdev) &&
	       pci_device_is_present(pdev);
}

static int mk_pci_forwarding_cpu(void)
{
	/* The host IPI manifest publishes logical CPU 0's physical ID. */
	if (!cpu_online(0))
		return -ENODEV;

	return 0;
}

static bool mk_pci_device_matches_bdf(const struct mk_pci_device *device,
				      u16 domain, u8 bus, u8 devfn)
{
	return device->domain == domain && device->bus == bus &&
	       device->slot == PCI_SLOT(devfn) &&
	       device->func == PCI_FUNC(devfn);
}

static struct mk_pci_device *
mk_pci_find_device_bdf(struct list_head *devices, u16 domain, u8 bus, u8 devfn)
{
	struct mk_pci_device *device;

	list_for_each_entry(device, devices, list) {
		if (mk_pci_device_matches_bdf(device, domain, bus, devfn))
			return device;
	}

	return NULL;
}

static bool mk_pci_inventory_matches(const struct mk_pci_device *left,
				     const struct mk_pci_device *right)
{
	return left->vendor == right->vendor &&
	       left->device == right->device &&
	       mk_pci_device_matches_bdf(left, right->domain, right->bus,
					 PCI_DEVFN(right->slot, right->func));
}

static struct mk_pci_device *
mk_pci_find_root_inventory(const struct mk_pci_device *requested)
{
	struct mk_pci_device *device;

	list_for_each_entry(device, &mk_self->pci_devices, list) {
		if (mk_pci_inventory_matches(device, requested))
			return device;
	}

	return NULL;
}

static struct mk_pci_device *
mk_pci_find_root_bdf(u16 domain, u8 bus, u8 devfn)
{
	return mk_pci_find_device_bdf(&mk_self->pci_devices, domain, bus,
				      devfn);
}

static struct mk_pci_assignment *
mk_pci_find_assignment(struct mk_instance *instance, u16 domain, u8 bus,
		       u8 devfn)
{
	struct mk_pci_assignment *assignment;

	list_for_each_entry(assignment, &instance->pci_assignments,
			    instance_node) {
		if (mk_pci_device_matches_bdf(assignment->inventory, domain, bus,
					      devfn))
			return assignment;
	}

	return NULL;
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

static void mk_pci_irq_retry_workfn(struct work_struct *work)
{
	struct mk_instance *instance = container_of(to_delayed_work(work),
						   struct mk_instance,
						   irq_retry_work);
	struct mk_shared_data *shared;
	bool any_pending = false;
	bool unmasked_pending = false;
	mk_phys_cpu_t target;
	unsigned long flags;
	unsigned int slot;

	raw_spin_lock_irqsave(&instance->control_route_lock, flags);
	shared = READ_ONCE(instance->ipi_data);
	if (!shared)
		goto unlock;
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
unlock:
	raw_spin_unlock_irqrestore(&instance->control_route_lock, flags);
	if (any_pending)
		mod_delayed_work(system_wq, &instance->irq_retry_work,
				 msecs_to_jiffies(unmasked_pending ? 10 : 100));
}

static irqreturn_t mk_pci_forward_irq(int irq, void *data)
{
	struct mk_pci_irq_vector *vector = data;
	struct mk_pci_assignment *assignment = vector->assignment;
	struct mk_instance *instance = assignment->instance;
	struct mk_shared_data *shared;
	struct mk_irq_mailbox *mailbox;
	struct mk_irq_mailbox_entry *entry;
	bool first_forward = false;
	bool schedule_retry = false;
	mk_phys_cpu_t target;
	u64 old, new;
	u32 pending;
	u32 local_irq;
	unsigned long flags;

	/* Pair with BIND's publication of the shared mailbox identity. */
	local_irq = smp_load_acquire(&vector->local_irq);

	raw_spin_lock_irqsave(&instance->control_route_lock, flags);
	shared = READ_ONCE(instance->ipi_data);
	if (READ_ONCE(instance->state) != MK_STATE_ACTIVE ||
	    READ_ONCE(assignment->irq_state) != MK_PCI_MSI_ACTIVE ||
	    !local_irq || !shared ||
	    vector->mailbox_slot == MK_IRQ_MAILBOX_SLOT_INVALID ||
	    !vector->mailbox_generation)
		goto unlock;
	mailbox = &shared->irq_mailbox;
	entry = &mailbox->entries[vector->mailbox_slot];
	for (;;) {
		old = atomic64_read_acquire(&entry->pending_generation);
		if (mk_irq_mailbox_generation(old) !=
		    vector->mailbox_generation) {
			atomic_inc(&mailbox->stale);
			goto unlock;
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
		schedule_retry = true;
	first_forward = atomic64_inc_return(&vector->forwarded) == 1;
	target = mk_instance_irq_route_load(instance);
	if (target != MK_PHYS_CPU_INVALID)
		mk_arch_send_ipi(target);
unlock:
	raw_spin_unlock_irqrestore(&instance->control_route_lock, flags);
	if (schedule_retry)
		mod_delayed_work(system_wq, &instance->irq_retry_work,
				 msecs_to_jiffies(10));
	if (first_forward)
		printk_deferred(KERN_INFO
				"Forwarding host IRQ %u as instance IRQ %u for %s vector %u\n",
				irq, local_irq, pci_name(assignment->vf),
				(unsigned int)(vector - assignment->irq_vectors));
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

static int mk_pci_release_irqs(struct mk_pci_assignment *assignment,
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

	if (!instance || instance == mk_self)
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
		mk_phys_cpu_t target;
		unsigned long flags;

		raw_spin_lock_irqsave(&instance->control_route_lock, flags);
		target = mk_instance_irq_route_load(instance);
		if (target != MK_PHYS_CPU_INVALID)
			mk_arch_send_ipi(target);
		raw_spin_unlock_irqrestore(&instance->control_route_lock, flags);
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
				       s32 sender_instance_id,
				       u64 lifecycle_epoch)
{
	if (!instance || instance == mk_self ||
	    instance->id != sender_instance_id)
		return true;
	if (READ_ONCE(instance->state) != MK_STATE_ACTIVE)
		return true;
	return !instance->ipi_data || !lifecycle_epoch ||
	       READ_ONCE(instance->ipi_data->spawn_epoch) != lifecycle_epoch;
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

	instance = mk_instance_find(control_work->sender_instance_id);
	if (!instance)
		goto out;
	down_read(&instance->control_route_sem);
	status = mk_pci_request_route_stale(instance,
					    control_work->sender_instance_id,
					    request->lifecycle_epoch) ?
		-ESTALE : 0;
	/* An untrusted payload ID must never select another instance's slot. */
	if (status)
		goto unlock_route;
	if (mk_reply_claim(instance, &reply))
		goto unlock_route;
	status = mk_pci_config_access(instance, request, &value, &reply);
	if (mk_reply_publish_route_locked(instance, &reply, status, value))
		pr_warn_ratelimited("Failed to return PCI config response to instance %d\n",
				    instance->id);
unlock_route:
	up_read(&instance->control_route_sem);
	mk_instance_put(instance);
out:
	return;
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

	instance = mk_instance_find(control_work->sender_instance_id);
	if (!instance)
		goto out;
	down_read(&instance->control_route_sem);
	status = mk_pci_request_route_stale(instance,
					    control_work->sender_instance_id,
					    request->lifecycle_epoch) ?
		-ESTALE : 0;
	if (status)
		goto unlock_route;
	if (mk_reply_claim(instance, &reply))
		goto unlock_route;
	status = mk_pci_irq_access(instance, request, &reply);
	if (mk_reply_publish_route_locked(instance, &reply, status, 0))
		pr_warn_ratelimited("Failed to return PCI IRQ response to instance %d\n",
				    instance->id);
unlock_route:
	up_read(&instance->control_route_sem);
	mk_instance_put(instance);
out:
	return;
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

	instance = mk_instance_find(control_work->sender_instance_id);
	if (!instance)
		goto out;
	down_read(&instance->control_route_sem);
	status = mk_pci_request_route_stale(instance,
					    control_work->sender_instance_id,
					    request->lifecycle_epoch) ?
		-ESTALE : 0;
	if (status)
		goto unlock_route;
	if (mk_reply_claim(instance, &reply))
		goto unlock_route;
	status = mk_pci_reset_access(instance, request, &reply);
	if (mk_reply_publish_route_locked(instance, &reply, status, 0))
		pr_warn_ratelimited("Failed to return PCI reset response to instance %d\n",
				    instance->id);
unlock_route:
	up_read(&instance->control_route_sem);
	mk_instance_put(instance);
out:
	return;
}

static void mk_pci_control_work_fn(struct work_struct *work)
{
	struct mk_pci_control_work *control_work =
		container_of(work, struct mk_pci_control_work, work);

	control_work->dispatch(work);
	mk_pci_control_work_put(control_work);
}

static void mk_pci_control_msg_handler(u32 msg_type, u32 subtype,
				       void *payload, u32 payload_len,
				       s32 sender_instance_id, void *ctx)
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
	control_work = mk_pci_control_work_get();
	if (!control_work) {
		atomic64_inc(&mk_pci_control_pool_exhausted);
		if (__ratelimit(&mk_pci_control_pool_rs))
			printk_deferred(KERN_WARNING
					"Multikernel PCI control work pool exhausted\n");
		goto out;
	}
	control_work->dispatch = work_fn;
	memcpy(&control_work->request, payload, request_size);
	control_work->sender_instance_id = sender_instance_id;
	switch (subtype) {
	case MK_PCI_CFG_REQUEST:
		control_work->request.cfg.sender_instance_id = sender_instance_id;
		break;
	case MK_PCI_IRQ_REQUEST:
		control_work->request.irq.sender_instance_id = sender_instance_id;
		break;
	case MK_PCI_RESET_REQUEST:
		control_work->request.reset.sender_instance_id = sender_instance_id;
		break;
	}
	if (!queue_work(mk_pci_control_wq, &control_work->work))
		mk_pci_control_work_put(control_work);
out:
	mk_pci_control_handler_put();
}

static void mk_pci_assignment_failure_work(struct work_struct *work)
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

static void mk_pci_schedule_failure(struct mk_pci_assignment *assignment)
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

static void
mk_pci_release_bound_driver(struct mk_pci_assignment *assignment)
{
	unsigned long flags;

	spin_lock_irqsave(&mk_pci_active_lock, flags);
	assignment->expected_unbind = true;
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);
	device_release_driver(&assignment->vf->dev);
	spin_lock_irqsave(&mk_pci_active_lock, flags);
	assignment->expected_unbind = false;
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);
}

#if IS_ENABLED(CONFIG_IOMMU_API)
#define MK_PCI_ASSIGNMENT_DRIVER_NAME "multikernel-pci-assignment"

static int mk_pci_iommu_assignment_probe(struct pci_dev *pdev,
					 const struct pci_device_id *id);
static void mk_pci_iommu_assignment_remove(struct pci_dev *pdev);

static struct pci_driver mk_pci_assignment_driver = {
	.name = MK_PCI_ASSIGNMENT_DRIVER_NAME,
	.probe = mk_pci_iommu_assignment_probe,
	.remove = mk_pci_iommu_assignment_remove,
	.driver_managed_dma = true,
};

struct mk_pci_iommu_group_check {
	struct device *vf;
	unsigned int count;
};

static int mk_pci_iommu_check_group_device(struct device *dev, void *data)
{
	struct mk_pci_iommu_group_check *check = data;

	check->count++;
	return dev == check->vf ? 0 : -EXDEV;
}

static void mk_pci_iommu_free_resv_regions(struct list_head *regions)
{
	struct iommu_resv_region *region, *tmp;

	list_for_each_entry_safe(region, tmp, regions, list) {
		list_del(&region->list);
		kfree(region);
	}
}

static int mk_pci_iommu_validate_group(struct mk_pci_assignment *assignment)
{
	struct mk_pci_iommu_group_check check = {
		.vf = &assignment->vf->dev,
	};
	int ret;

	ret = iommu_group_for_each_dev(assignment->iommu_group, &check,
				       mk_pci_iommu_check_group_device);
	if (ret || check.count != 1) {
		pr_err("IOMMU group %d for %s is not an isolated singleton group\n",
		       iommu_group_id(assignment->iommu_group),
		       pci_name(assignment->vf));
		return ret ?: -EXDEV;
	}

	if (!iommu_group_has_isolated_msi(assignment->iommu_group)) {
		pr_err("IOMMU group %d for %s lacks isolated MSI delivery\n",
		       iommu_group_id(assignment->iommu_group),
		       pci_name(assignment->vf));
		return -EPERM;
	}

	return 0;
}

static int
mk_pci_iommu_validate_resv_regions(struct mk_pci_assignment *assignment)
{
	struct iommu_resv_region *region;
	struct mk_memory_region *memory;
	LIST_HEAD(resv_regions);
	u64 memory_end, resv_end;
	int ret;

	ret = iommu_get_group_resv_regions(assignment->iommu_group,
					   &resv_regions);
	if (ret)
		goto out;

	list_for_each_entry(region, &resv_regions, list) {
		if (region->type == IOMMU_RESV_DIRECT_RELAXABLE)
			continue;
		if (!region->length ||
		    check_add_overflow((u64)region->start,
				       (u64)region->length - 1, &resv_end)) {
			pr_err("IOMMU group %d for %s has invalid reserved region at %#llx\n",
			       iommu_group_id(assignment->iommu_group),
			       pci_name(assignment->vf),
			       (unsigned long long)region->start);
			ret = -EOVERFLOW;
			goto out;
		}

		list_for_each_entry(memory,
				    &assignment->instance->memory_regions, list) {
			resource_size_t size = resource_size(&memory->res);

			if (!size ||
			    check_add_overflow((u64)memory->res.start,
					       (u64)size - 1, &memory_end)) {
				ret = -EOVERFLOW;
				goto out;
			}
			if ((u64)memory->res.start > resv_end ||
			    memory_end < (u64)region->start)
				continue;

			pr_err("Instance %d IOVA %#llx-%#llx overlaps IOMMU reserved region %#llx-%#llx type %u for %s\n",
			       assignment->instance->id,
			       (unsigned long long)memory->res.start,
			       (unsigned long long)memory_end,
			       (unsigned long long)region->start,
			       (unsigned long long)resv_end, region->type,
			       pci_name(assignment->vf));
			ret = -EPERM;
			goto out;
		}
	}

	ret = 0;
out:
	mk_pci_iommu_free_resv_regions(&resv_regions);
	return ret;
}

static int
mk_pci_iommu_validate_region(struct mk_pci_assignment *assignment,
			     const struct mk_memory_region *region)
{
	struct iommu_domain *domain = assignment->iommu_domain;
	resource_size_t start = region->res.start;
	resource_size_t size = resource_size(&region->res);
	u64 dma_mask = dma_get_mask(&assignment->vf->dev);
	u64 end;
	unsigned long min_page_size;

	if (!size || check_add_overflow((u64)start, (u64)size - 1, &end))
		return -EOVERFLOW;
	if (!domain->pgsize_bitmap)
		return -EOPNOTSUPP;

	min_page_size = 1UL << __ffs(domain->pgsize_bitmap);
	if (!IS_ALIGNED(start, min_page_size) ||
	    !IS_ALIGNED(size, min_page_size)) {
		pr_err("Instance %d memory %#llx-%#llx is not aligned to IOMMU page size %#lx\n",
		       assignment->instance->id, (unsigned long long)start,
		       (unsigned long long)end, min_page_size);
		return -EINVAL;
	}
	if (start > ULONG_MAX || end > ULONG_MAX || end > dma_mask) {
		pr_err("Instance %d memory %#llx-%#llx exceeds DMA addressability of %s\n",
		       assignment->instance->id, (unsigned long long)start,
		       (unsigned long long)end, pci_name(assignment->vf));
		return -ERANGE;
	}
	if (domain->geometry.force_aperture &&
	    (start < domain->geometry.aperture_start ||
	     end > domain->geometry.aperture_end)) {
		pr_err("Instance %d memory %#llx-%#llx is outside the IOMMU aperture for %s\n",
		       assignment->instance->id, (unsigned long long)start,
		       (unsigned long long)end, pci_name(assignment->vf));
		return -ERANGE;
	}

	return 0;
}

static void mk_pci_iommu_unmap_regions(struct mk_pci_assignment *assignment)
{
	struct mk_memory_region *region;
	unsigned int remaining = assignment->iommu_mapped_regions;

	list_for_each_entry(region, &assignment->instance->memory_regions, list) {
		resource_size_t size;
		size_t unmapped;

		if (!remaining)
			break;
		size = resource_size(&region->res);
		unmapped = iommu_unmap(assignment->iommu_domain,
				       region->res.start, size);
		if (unmapped != size)
			pr_err("IOMMU unmapped only %#zx of %#llx bytes for instance %d at %#llx\n",
			       unmapped, (unsigned long long)size,
			       assignment->instance->id,
			       (unsigned long long)region->res.start);
		remaining--;
	}
	if (remaining)
		pr_err("IOMMU lease for %s lost %u mapped instance regions\n",
		       pci_name(assignment->vf), remaining);
	assignment->iommu_mapped_regions = 0;
}

static int
mk_pci_quiesce_assignment(struct mk_pci_assignment *assignment)
{
	struct pci_dev *vf = assignment->vf;
	bool transactions_drained;
	int ret;

	ret = mk_pci_release_irqs(assignment, false);
	if (ret)
		return ret;
	if (!mk_pci_device_live(vf))
		return 0;

	/*
	 * Releasing DMA ownership restores the group's default domain. Stop new
	 * DMA first, drain requests already issued, and reset the VF while the
	 * assignment domain still contains any stragglers.
	 */
	pci_clear_master(vf);
	transactions_drained = pci_wait_for_pending_transaction(vf);
	ret = pcie_reset_flr(vf, false);
	if (!ret)
		return 0;
	if (ret == -ENOTTY && transactions_drained)
		return 0;

	if (!transactions_drained)
		pr_err("Timed out draining DMA from assigned VF %s\n",
		       pci_name(vf));
	if (ret != -ENOTTY)
		pr_err("Failed to reset assigned VF %s: %d\n",
		       pci_name(vf), ret);

	/*
	 * Keep the assignment domain attached when the device cannot be made
	 * safe. The lease owner can retry teardown after the instance halts.
	 */
	return ret == -ENOTTY ? -ETIMEDOUT : ret;
}

static int
mk_pci_reset_assignment_for_start(struct mk_pci_assignment *assignment)
{
	struct pci_dev *vf = assignment->vf;
	int ret;

	ret = mk_pci_release_irqs(assignment, true);
	if (ret)
		return ret;
	assignment->irq_epoch = 0;
	assignment->irq_generation = 0;
	assignment->reset_generation = 0;
	assignment->irq_state = MK_PCI_MSI_IDLE;
	if (!assignment->assigned || !assignment->iommu_attached)
		return -EINVAL;
	if (!mk_pci_device_live(vf))
		return -ENODEV;

	/*
	 * A stopped instance may have left DMA active. Keep its restrictive
	 * domain attached while stopping new requests, draining old ones, and
	 * resetting device state before the instance image is reused.
	 */
	pci_clear_master(vf);
	if (!pci_wait_for_pending_transaction(vf)) {
		pr_err("Timed out draining assigned VF %s before instance restart\n",
		       pci_name(vf));
		return -ETIMEDOUT;
	}

	ret = pcie_reset_flr(vf, false);
	if (ret) {
		pr_err("Failed to reset assigned VF %s before instance restart: %d\n",
		       pci_name(vf), ret);
		return ret == -ENOTTY ? -EOPNOTSUPP : ret;
	}
	return 0;
}

static void
__mk_pci_iommu_deactivate_assignment(struct mk_pci_assignment *assignment)
{
	if (assignment->iommu_attached) {
		iommu_detach_group(assignment->iommu_domain,
				   assignment->iommu_group);
		assignment->iommu_attached = false;
	}
	if (assignment->iommu_dma_owner) {
		iommu_device_release_dma_owner(&assignment->vf->dev);
		assignment->iommu_dma_owner = false;
	}
}

static void
mk_pci_iommu_deactivate_assignment(struct mk_pci_assignment *assignment)
{
	mutex_lock(&assignment->iommu_mutex);
	__mk_pci_iommu_deactivate_assignment(assignment);
	mutex_unlock(&assignment->iommu_mutex);
}

static void mk_pci_iommu_release_assignment(struct mk_pci_assignment *assignment)
{
	mutex_lock(&assignment->iommu_mutex);
	__mk_pci_iommu_deactivate_assignment(assignment);

	if (assignment->iommu_domain) {
		mk_pci_iommu_unmap_regions(assignment);
		iommu_domain_free(assignment->iommu_domain);
		assignment->iommu_domain = NULL;
	}
	if (assignment->iommu_group) {
		iommu_group_put(assignment->iommu_group);
		assignment->iommu_group = NULL;
	}
	mutex_unlock(&assignment->iommu_mutex);
}

static int mk_pci_iommu_prepare_assignment(struct mk_pci_assignment *assignment)
{
	struct mk_memory_region *region;
	int ret;

	if (!device_iommu_mapped(&assignment->vf->dev)) {
		pr_err("Cannot assign %s without an active hardware IOMMU\n",
		       pci_name(assignment->vf));
		return -EOPNOTSUPP;
	}
	if (!device_iommu_capable(&assignment->vf->dev,
				  IOMMU_CAP_CACHE_COHERENCY)) {
		pr_err("Cannot assign %s without coherent IOMMU mappings\n",
		       pci_name(assignment->vf));
		return -EOPNOTSUPP;
	}
	if (!assignment->instance->region_count ||
	    list_empty(&assignment->instance->memory_regions))
		return -EINVAL;

	assignment->iommu_group = iommu_group_get(&assignment->vf->dev);
	if (!assignment->iommu_group)
		return -ENODEV;

	ret = mk_pci_iommu_validate_group(assignment);
	if (ret)
		goto err_release;
	ret = mk_pci_iommu_validate_resv_regions(assignment);
	if (ret)
		goto err_release;

	assignment->iommu_domain =
		iommu_paging_domain_alloc(&assignment->vf->dev);
	if (IS_ERR(assignment->iommu_domain)) {
		ret = PTR_ERR(assignment->iommu_domain);
		assignment->iommu_domain = NULL;
		goto err_release;
	}

	list_for_each_entry(region, &assignment->instance->memory_regions, list) {
		resource_size_t size = resource_size(&region->res);

		ret = mk_pci_iommu_validate_region(assignment, region);
		if (ret)
			goto err_release;
		ret = iommu_map(assignment->iommu_domain, region->res.start,
				region->res.start, size,
				IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE, GFP_KERNEL);
		if (ret)
			goto err_release;
		assignment->iommu_mapped_regions++;
	}

	/*
	 * The domain blocks DMA outside these mappings, but translation-fault
	 * notification is not portable. In particular, Intel VT-d reports primary
	 * faults through dmar_fault() without invoking a legacy domain handler.
	 * Do not claim automatic instance failure on an IOMMU fault here.
	 */
	pr_info("Prepared host IOMMU domain for %s with %u instance regions\n",
		pci_name(assignment->vf), assignment->iommu_mapped_regions);
	return 0;

err_release:
	mk_pci_iommu_release_assignment(assignment);
	return ret;
}

static int mk_pci_iommu_commit_assignment(struct mk_pci_assignment *assignment)
{
	int ret;

	if (!assignment->iommu_domain)
		return 0;

	if (assignment->vf->driver_override) {
		assignment->host_driver_override =
			kstrdup(assignment->vf->driver_override, GFP_KERNEL);
		if (!assignment->host_driver_override)
			return -ENOMEM;
	}

	ret = driver_set_override(&assignment->vf->dev,
				  &assignment->vf->driver_override,
				  MK_PCI_ASSIGNMENT_DRIVER_NAME,
				  strlen(MK_PCI_ASSIGNMENT_DRIVER_NAME));
	if (ret)
		return ret;
	assignment->iommu_override_active = true;
	pci_set_drvdata(assignment->vf, assignment);
	ret = device_driver_attach(&mk_pci_assignment_driver.driver,
				   &assignment->vf->dev);
	if (ret)
		return ret;
	if (assignment->vf->dev.driver != &mk_pci_assignment_driver.driver)
		return -ENODEV;
	return 0;
}

static int mk_pci_iommu_assignment_probe(struct pci_dev *pdev,
					 const struct pci_device_id *id)
{
	struct mk_pci_assignment *assignment = pci_get_drvdata(pdev);
	int ret;

	if (!assignment || assignment->vf != pdev || !assignment->iommu_domain)
		return -ENODEV;
	ret = iommu_device_claim_dma_owner(&assignment->vf->dev, assignment);
	if (ret)
		return ret;
	assignment->iommu_dma_owner = true;

	ret = iommu_attach_group(assignment->iommu_domain,
				 assignment->iommu_group);
	if (ret) {
		iommu_device_release_dma_owner(&assignment->vf->dev);
		assignment->iommu_dma_owner = false;
		return ret;
	}
	assignment->iommu_attached = true;
	ret = pci_enable_device(pdev);
	if (ret) {
		iommu_detach_group(assignment->iommu_domain,
				   assignment->iommu_group);
		assignment->iommu_attached = false;
		iommu_device_release_dma_owner(&assignment->vf->dev);
		assignment->iommu_dma_owner = false;
		return ret;
	}
	assignment->device_enabled = true;
	pr_info("Attached %s to host-owned IOMMU domain for instance %d\n",
		pci_name(assignment->vf), assignment->instance->id);
	return 0;
}

static void mk_pci_iommu_assignment_remove(struct pci_dev *pdev)
{
	struct mk_pci_assignment *assignment = pci_get_drvdata(pdev);
	int ret;

	if (!assignment || assignment->vf != pdev)
		return;

	if (READ_ONCE(assignment->expected_unbind)) {
		if (assignment->device_enabled) {
			pci_disable_device(pdev);
			assignment->device_enabled = false;
		}
		pci_set_drvdata(pdev, NULL);
		return;
	}

	ret = mk_pci_quiesce_assignment(assignment);
	if (ret) {
		pr_crit("Keeping IOMMU containment for %s after unsafe driver removal: %d\n",
			pci_name(pdev), ret);
		mk_pci_schedule_failure(assignment);
	} else {
		mk_pci_iommu_deactivate_assignment(assignment);
	}
	if (assignment->device_enabled) {
		pci_disable_device(pdev);
		assignment->device_enabled = false;
	}
	pci_set_drvdata(pdev, NULL);
}

static int mk_pci_restore_host_binding(struct mk_pci_assignment *assignment)
{
	struct pci_dev *vf = assignment->vf;
	const char *override = assignment->host_driver_override ?: "";
	int ret = 0;

	if (vf->dev.driver == &mk_pci_assignment_driver.driver) {
		mk_pci_release_bound_driver(assignment);
	} else if (vf->dev.driver) {
		pr_err("Cannot release assignment driver from %s: device is bound to %s\n",
		       pci_name(vf), vf->dev.driver->name);
		return -EBUSY;
	}

	pci_set_drvdata(vf, NULL);
	if (assignment->iommu_override_active) {
		ret = driver_set_override(&vf->dev, &vf->driver_override,
					  override, strlen(override));
		if (ret)
			return ret;
		assignment->iommu_override_active = false;
	}

	mk_pci_iommu_deactivate_assignment(assignment);
	if (assignment->host_driver && mk_pci_device_live(vf)) {
		if (!vf->dev.driver) {
			ret = device_driver_attach(assignment->host_driver, &vf->dev);
			if (ret) {
				pr_err("Failed to restore driver %s to %s: %d\n",
				       assignment->host_driver->name,
				       pci_name(vf), ret);
				return ret;
			}
		} else if (vf->dev.driver != assignment->host_driver) {
			pr_err("Cannot restore driver %s to %s: device is bound to %s\n",
			       assignment->host_driver->name, pci_name(vf),
			       vf->dev.driver->name);
			return -EBUSY;
		}
	}
	return 0;
}

static int mk_pci_iommu_system_init(void)
{
	return pci_register_driver(&mk_pci_assignment_driver);
}

static void mk_pci_iommu_system_cleanup(void)
{
	pci_unregister_driver(&mk_pci_assignment_driver);
}
#else
static int
mk_pci_reset_assignment_for_start(struct mk_pci_assignment *assignment)
{
	return -EOPNOTSUPP;
}

static int
mk_pci_quiesce_assignment(struct mk_pci_assignment *assignment)
{
	return 0;
}

static int mk_pci_iommu_prepare_assignment(struct mk_pci_assignment *assignment)
{
	pr_err("Cannot assign %s without CONFIG_IOMMU_API\n",
	       pci_name(assignment->vf));
	return -EOPNOTSUPP;
}

static int mk_pci_iommu_commit_assignment(struct mk_pci_assignment *assignment)
{
	return 0;
}

static void mk_pci_iommu_release_assignment(struct mk_pci_assignment *assignment)
{
}

static int mk_pci_restore_host_binding(struct mk_pci_assignment *assignment)
{
	return 0;
}

static int mk_pci_iommu_system_init(void)
{
	return 0;
}

static void mk_pci_iommu_system_cleanup(void)
{
}
#endif

static int
mk_pci_prepare_assignment(struct mk_instance *instance,
			  const struct mk_pci_device *requested,
			  struct list_head *transaction)
{
	struct mk_pci_assignment *assignment;
	struct mk_pci_device *inventory;
	struct pci_dev *vf;
	struct pci_dev *pf;
	struct pci_dev *physfn;
	int ret;

	inventory = mk_pci_find_root_inventory(requested);
	if (!inventory) {
		pr_err("PCI device %04x:%04x@%04x:%02x:%02x.%x is not available in the root pool\n",
		       requested->vendor, requested->device, requested->domain,
		       requested->bus, requested->slot, requested->func);
		return -ENOENT;
	}

	vf = pci_get_domain_bus_and_slot(inventory->domain,
					 inventory->bus,
					 PCI_DEVFN(inventory->slot,
						   inventory->func));
	if (!vf)
		return -ENODEV;

	if (vf->vendor != inventory->vendor ||
	    vf->device != inventory->device) {
		pr_err("PCI identity changed for %s: expected %04x:%04x, found %04x:%04x\n",
		       pci_name(vf), inventory->vendor, inventory->device,
		       vf->vendor, vf->device);
		pci_dev_put(vf);
		return -ENODEV;
	}

	physfn = pci_physfn(vf);
	if (!vf->is_virtfn || physfn == vf) {
		pr_err("PCI assignment only supports SR-IOV VFs, rejecting %s\n",
		       pci_name(vf));
		pci_dev_put(vf);
		return -EOPNOTSUPP;
	}

	if (!mk_pci_device_live(vf) || !mk_pci_device_live(physfn)) {
		pci_dev_put(vf);
		return -ENODEV;
	}
	ret = pcie_reset_flr(vf, true);
	if (ret) {
		pr_err("PCI assignment requires FLR for safe instance restart, rejecting %s\n",
		       pci_name(vf));
		pci_dev_put(vf);
		return -EOPNOTSUPP;
	}

	if (pci_is_dev_assigned(vf) ||
	    mk_pci_find_assignment(instance, inventory->domain,
				   inventory->bus,
				   PCI_DEVFN(inventory->slot,
					     inventory->func))) {
		pci_dev_put(vf);
		return -EBUSY;
	}

	pf = pci_dev_get(physfn);
	assignment = kzalloc_obj(*assignment, GFP_KERNEL);
	if (!assignment) {
		pci_dev_put(pf);
		pci_dev_put(vf);
		return -ENOMEM;
	}

	assignment->instance = instance;
	assignment->inventory = inventory;
	assignment->vf = vf;
	assignment->pf = pf;
	assignment->host_driver = vf->dev.driver;
	if (assignment->host_driver && assignment->host_driver->owner &&
	    !try_module_get(assignment->host_driver->owner)) {
		kfree(assignment);
		pci_dev_put(pf);
		pci_dev_put(vf);
		return -ENODEV;
	}

	INIT_LIST_HEAD(&assignment->instance_node);
	INIT_LIST_HEAD(&assignment->active_node);
	INIT_LIST_HEAD(&assignment->transaction_node);
	mutex_init(&assignment->iommu_mutex);
	INIT_WORK(&assignment->failure_work, mk_pci_assignment_failure_work);
	atomic_set(&assignment->failure_pending, 0);

	ret = mk_pci_iommu_prepare_assignment(assignment);
	if (ret)
		goto err_module;

	list_add_tail(&assignment->instance_node, &instance->pci_assignments);
	list_add_tail(&assignment->transaction_node, transaction);

	return 0;

err_module:
	if (assignment->host_driver && assignment->host_driver->owner)
		module_put(assignment->host_driver->owner);
	kfree(assignment);
	pci_dev_put(pf);
	pci_dev_put(vf);
	return ret;
}

static int mk_pci_commit_assignment(struct mk_pci_assignment *assignment)
{
	struct pci_dev *vf = assignment->vf;
	unsigned long flags;
	int ret;
	int i;

	if (!mk_pci_device_live(vf) || !mk_pci_device_live(assignment->pf))
		return -ENODEV;

	if (vf->dev.driver != assignment->host_driver ||
	    pci_is_dev_assigned(vf))
		return -EBUSY;

	pci_set_dev_assigned(vf);
	assignment->assigned = true;

	spin_lock_irqsave(&mk_pci_active_lock, flags);
	list_add_tail(&assignment->active_node, &mk_pci_active_assignments);
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);

	if (assignment->host_driver)
		mk_pci_release_bound_driver(assignment);

	if (vf->dev.driver)
		return -EBUSY;

	ret = mk_pci_iommu_commit_assignment(assignment);
	if (ret)
		return ret;

	for (i = 0; i < MK_PCI_RESOURCE_COUNT; i++) {
		assignment->inventory->resources[i].start =
			vf->resource[i].start;
		assignment->inventory->resources[i].end =
			vf->resource[i].end;
		assignment->inventory->resources[i].flags =
			vf->resource[i].flags;
	}
	assignment->inventory->resources_valid = true;

	list_move_tail(&assignment->inventory->list,
		       &assignment->instance->pci_devices);
	mk_self->pci_device_count--;
	assignment->instance->pci_device_count++;
	assignment->instance->pci_devices_valid = true;
	assignment->inventory_moved = true;

	pr_info("Leased SR-IOV VF %s to instance %d (%s)\n",
		pci_name(vf), assignment->instance->id,
		assignment->instance->name);
	return 0;
}

static int mk_pci_release_assignment(struct mk_pci_assignment *assignment,
				     struct list_head *released)
{
	struct mk_instance *instance = assignment->instance;
	struct pci_dev *vf = assignment->vf;
	unsigned long flags;
	int ret;

	if (!assignment->assigned)
		goto release_resources;

	ret = mk_pci_quiesce_assignment(assignment);
	if (ret)
		return ret;

	ret = mk_pci_restore_host_binding(assignment);
	if (ret)
		return ret;

	spin_lock_irqsave(&mk_pci_active_lock, flags);
	if (!list_empty(&assignment->active_node))
		list_del_init(&assignment->active_node);
	assignment->expected_unbind = false;
	spin_unlock_irqrestore(&mk_pci_active_lock, flags);

	if (assignment->assigned) {
		pci_clear_dev_assigned(vf);
		assignment->assigned = false;
	}

release_resources:
	mk_pci_iommu_release_assignment(assignment);

	if (assignment->inventory_moved && mk_self) {
		assignment->inventory->resources_valid = false;
		list_move_tail(&assignment->inventory->list,
			       &mk_self->pci_devices);
		instance->pci_device_count--;
		mk_self->pci_device_count++;
		mk_self->pci_devices_valid = true;
		assignment->inventory_moved = false;
	}

	if (!list_empty(&assignment->transaction_node))
		list_del_init(&assignment->transaction_node);
	list_del_init(&assignment->instance_node);
	list_add_tail(&assignment->transaction_node, released);

	return 0;
}

static void mk_pci_finalize_releases(struct list_head *released)
{
	struct mk_pci_assignment *assignment, *tmp;

	list_for_each_entry_safe(assignment, tmp, released, transaction_node) {
		list_del_init(&assignment->transaction_node);
		cancel_work_sync(&assignment->failure_work);
		kfree(assignment->host_driver_override);
		if (assignment->host_driver && assignment->host_driver->owner)
			module_put(assignment->host_driver->owner);
		pci_dev_put(assignment->pf);
		pci_dev_put(assignment->vf);
		kfree(assignment);
	}
}

static int mk_pci_rollback_transaction(struct list_head *transaction,
				       struct list_head *released)
{
	struct mk_pci_assignment *assignment, *tmp;
	int rollback_ret = 0;
	int ret;

	list_for_each_entry_safe_reverse(assignment, tmp, transaction,
					 transaction_node) {
		ret = mk_pci_release_assignment(assignment, released);
		if (!ret)
			continue;
		pr_crit("Failed to roll back PCI assignment for %s: %d\n",
			pci_name(assignment->vf), ret);
		list_del_init(&assignment->transaction_node);
		if (!rollback_ret)
			rollback_ret = ret;
	}

	return rollback_ret;
}

static int mk_pci_commit_transaction(struct list_head *transaction)
{
	struct mk_pci_assignment *assignment;
	int ret;

	list_for_each_entry(assignment, transaction, transaction_node) {
		ret = mk_pci_commit_assignment(assignment);
		if (ret)
			return ret;
	}

	while (!list_empty(transaction)) {
		assignment = list_first_entry(transaction,
					      struct mk_pci_assignment,
					      transaction_node);
		list_del_init(&assignment->transaction_node);
	}

	return 0;
}

void mk_pci_lease_instance_init(struct mk_instance *instance)
{
	INIT_DELAYED_WORK(&instance->irq_retry_work, mk_pci_irq_retry_workfn);
}

void mk_pci_irq_retry_disable_sync(struct mk_instance *instance)
{
	disable_delayed_work_sync(&instance->irq_retry_work);
}

void mk_pci_irq_retry_enable(struct mk_instance *instance)
{
	enable_delayed_work(&instance->irq_retry_work);
}

bool mk_pci_iommu_lease_active_locked(struct mk_instance *instance)
{
	if (!instance)
		return false;

	lockdep_assert_held(&instance->resource_mutex);
	return !list_empty(&instance->pci_assignments);
}

int mk_pci_assign_devices(struct mk_instance *instance,
			  const struct list_head *requested_devices,
			  int requested_count)
{
	struct mk_pci_device *requested;
	LIST_HEAD(released);
	LIST_HEAD(transaction);
	int prepared = 0;
	int ret = 0;
	int rollback_ret;

	if (!instance || instance == mk_self || !requested_devices ||
	    requested_count < 0)
		return -EINVAL;
	if (!mk_self || !mk_self->pci_devices_valid)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();

	list_for_each_entry(requested, requested_devices, list) {
		ret = mk_pci_prepare_assignment(instance, requested,
						&transaction);
		if (ret)
			goto rollback;
		prepared++;
	}

	if (prepared != requested_count) {
		ret = -EINVAL;
		goto rollback;
	}

	ret = mk_pci_commit_transaction(&transaction);
	if (ret)
		goto rollback;
	goto out;

rollback:
	rollback_ret = mk_pci_rollback_transaction(&transaction, &released);
	if (rollback_ret)
		ret = rollback_ret;
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	mk_pci_finalize_releases(&released);
	return ret;
}

int mk_pci_assign_device(struct mk_instance *instance, u16 domain, u8 bus,
			 u8 devfn)
{
	struct mk_pci_device *inventory;
	LIST_HEAD(released);
	LIST_HEAD(transaction);
	int ret;
	int rollback_ret;

	if (!instance || instance == mk_self)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();

	if (instance->state != MK_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}
	if (!mk_self || !mk_self->pci_devices_valid) {
		ret = -EINVAL;
		goto out;
	}

	inventory = mk_pci_find_root_bdf(domain, bus, devfn);
	if (!inventory) {
		ret = -ENOENT;
		goto out;
	}

	ret = mk_pci_prepare_assignment(instance, inventory, &transaction);
	if (ret)
		goto rollback;
	ret = mk_pci_commit_transaction(&transaction);
	if (ret)
		goto rollback;
	goto out;

rollback:
	rollback_ret = mk_pci_rollback_transaction(&transaction, &released);
	if (rollback_ret)
		ret = rollback_ret;
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	mk_pci_finalize_releases(&released);
	return ret;
}

int mk_pci_unassign_device(struct mk_instance *instance, u16 domain, u8 bus,
			   u8 devfn)
{
	struct mk_pci_assignment *assignment;
	LIST_HEAD(released);
	int ret;

	if (!instance || instance == mk_self)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();

	if (instance->state != MK_STATE_READY) {
		ret = -EBUSY;
		goto out;
	}

	assignment = mk_pci_find_assignment(instance, domain, bus, devfn);
	if (!assignment) {
		ret = -ENOENT;
		goto out;
	}

	ret = mk_pci_release_assignment(assignment, &released);
out:
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	mk_pci_finalize_releases(&released);
	return ret;
}

int mk_pci_release_assignments(struct mk_instance *instance)
{
	struct mk_pci_assignment *assignment;
	LIST_HEAD(released);
	int ret = 0;

	if (!instance || instance == mk_self)
		return 0;

	mk_cpu_transaction_lock();
	down_write(&instance->control_route_sem);
	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	while (!list_empty(&instance->pci_assignments)) {
		assignment = list_last_entry(&instance->pci_assignments,
					     struct mk_pci_assignment,
					     instance_node);
		ret = mk_pci_release_assignment(assignment, &released);
		if (ret) {
			pr_crit("Instance %d retains unsafe PCI lease for %s: %d\n",
				instance->id, pci_name(assignment->vf), ret);
			break;
		}
	}
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	up_write(&instance->control_route_sem);
	mk_cpu_transaction_unlock();
	/*
	 * The assignment is no longer reachable by routed requests.  Cancel its
	 * failure work after dropping the route and transaction locks because the
	 * worker may itself force-halt the instance and take both locks.
	 */
	mk_pci_finalize_releases(&released);
	if (!ret)
		cancel_delayed_work_sync(&instance->irq_retry_work);
	return ret;
}

int mk_pci_prepare_instance_start(struct mk_instance *instance)
{
	struct mk_pci_assignment *assignment;
	int ret = 0;

	if (!instance || instance == mk_self)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	mutex_lock(&mk_pci_lease_mutex);
	pci_lock_rescan_remove();
	list_for_each_entry(assignment, &instance->pci_assignments,
			    instance_node) {
		ret = mk_pci_reset_assignment_for_start(assignment);
		if (ret)
			break;
	}
	pci_unlock_rescan_remove();
	mutex_unlock(&mk_pci_lease_mutex);
	mutex_unlock(&instance->resource_mutex);
	return ret;
}

int mk_pci_lease_system_init(void)
{
	unsigned int i;
	unsigned int pool_size;
	int ret;

	ret = mk_pci_iommu_system_init();
	if (ret)
		return ret;
	ret = bus_register_notifier(&pci_bus_type, &mk_pci_bus_notifier);
	if (ret) {
		mk_pci_iommu_system_cleanup();
		return ret;
	}
	mk_pci_notifier_registered = true;
	if (mk_self && mk_self->id == 0) {
		pool_size = max_t(unsigned int, num_possible_cpus(), 1) *
			MK_REPLY_SLOTS;
		mk_pci_control_pool = kcalloc(pool_size,
					      sizeof(*mk_pci_control_pool),
					      GFP_KERNEL);
		if (!mk_pci_control_pool) {
			ret = -ENOMEM;
			goto unregister_notifier;
		}
		mk_pci_control_pool_busy = bitmap_zalloc(pool_size, GFP_KERNEL);
		if (!mk_pci_control_pool_busy) {
			ret = -ENOMEM;
			goto free_pool;
		}
		mk_pci_control_pool_size = pool_size;
		atomic_set(&mk_pci_control_pool_cursor, 0);
		for (i = 0; i < pool_size; i++) {
			INIT_WORK(&mk_pci_control_pool[i].work,
				  mk_pci_control_work_fn);
			mk_pci_control_pool[i].pool_slot = i;
		}
		mk_pci_control_wq =
			alloc_workqueue("mk-pci-control",
					WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
		if (!mk_pci_control_wq) {
			ret = -ENOMEM;
			goto free_pool_bitmap;
		}
		mk_pci_control_shutdown_end();
		ret = mk_register_msg_handler(MK_MSG_PCI,
					      mk_pci_control_msg_handler, NULL);
		if (ret)
			goto destroy_workqueue;
		mk_pci_control_registered = true;
	}
	return 0;

destroy_workqueue:
	mk_pci_control_shutdown_begin();
	destroy_workqueue(mk_pci_control_wq);
	mk_pci_control_wq = NULL;
free_pool_bitmap:
	bitmap_free(mk_pci_control_pool_busy);
	mk_pci_control_pool_busy = NULL;
	mk_pci_control_pool_size = 0;
free_pool:
	kfree(mk_pci_control_pool);
	mk_pci_control_pool = NULL;
unregister_notifier:
	bus_unregister_notifier(&pci_bus_type, &mk_pci_bus_notifier);
	mk_pci_notifier_registered = false;
	mk_pci_iommu_system_cleanup();
	return ret;
}

void mk_pci_lease_system_cleanup(void)
{
	if (mk_pci_control_registered) {
		mk_pci_control_shutdown_begin();
		mk_unregister_msg_handler(MK_MSG_PCI,
					  mk_pci_control_msg_handler);
		mk_pci_control_registered = false;
		wait_event(mk_pci_control_waitq,
			   !(atomic_read(&mk_pci_control_state) &
			     MK_PCI_CONTROL_ACTIVE_MASK));
	}
	if (mk_pci_control_wq) {
		destroy_workqueue(mk_pci_control_wq);
		mk_pci_control_wq = NULL;
	}
	bitmap_free(mk_pci_control_pool_busy);
	mk_pci_control_pool_busy = NULL;
	mk_pci_control_pool_size = 0;
	kfree(mk_pci_control_pool);
	mk_pci_control_pool = NULL;
	if (mk_pci_notifier_registered) {
		bus_unregister_notifier(&pci_bus_type, &mk_pci_bus_notifier);
		mk_pci_notifier_registered = false;
	}
	mk_pci_iommu_system_cleanup();
}

static struct mk_pci_device *
mk_pci_find_assigned_bdf(u16 domain, u8 bus, u8 devfn)
{
	if (!mk_self || mk_self->id == 0 ||
	    !mk_self->pci_devices_valid)
		return NULL;

	return mk_pci_find_device_bdf(&mk_self->pci_devices,
				      domain, bus, devfn);
}

static struct mk_pci_device *mk_pci_find_assigned(struct pci_bus *bus, int devfn)
{
	return mk_pci_find_assigned_bdf(pci_domain_nr(bus), bus->number, devfn);
}

/**
 * mk_pci_get_assigned_identity_bdf - Get an assigned function's identity
 * @domain: PCI domain number
 * @bus: PCI bus number
 * @devfn: device/function number
 * @vendor: assigned Vendor ID
 * @device_id: assigned Device ID
 *
 * Returns: true when assignment metadata contains an exact location match.
 */
bool mk_pci_get_assigned_identity_bdf(unsigned int domain, unsigned int bus,
				      unsigned int devfn, u16 *vendor,
				      u16 *device_id)
{
	struct mk_pci_device *device;

	if (domain != (u16)domain || bus != (u8)bus || devfn != (u8)devfn)
		return false;
	device = mk_pci_find_assigned_bdf(domain, bus, devfn);

	if (!device)
		return false;

	if (vendor)
		*vendor = device->vendor;
	if (device_id)
		*device_id = device->device;
	return true;
}

static void mk_pci_restore_resources(struct pci_dev *dev)
{
	struct mk_pci_device *device;
	int i;

	device = mk_pci_find_assigned(dev->bus, dev->devfn);
	if (!device || !device->resources_valid)
		return;

	dev->non_compliant_bars = true;
	for (i = 0; i < MK_PCI_RESOURCE_COUNT; i++) {
		dev->resource[i].start = device->resources[i].start;
		dev->resource[i].end = device->resources[i].end;
		dev->resource[i].flags = device->resources[i].flags;
	}
	pr_info("Restored PCI BAR resources for %s\n", pci_name(dev));
}

DECLARE_PCI_FIXUP_EARLY(PCI_ANY_ID, PCI_ANY_ID, mk_pci_restore_resources);
