// SPDX-License-Identifier: GPL-2.0-only
/*
 * x86 PCI support for multikernel spawn kernels.
 *
 * Spawn kernels discover only assigned BDFs and proxy all configuration
 * accesses to the host kernel.
 */
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/ktime.h>
#include <linux/msi.h>
#include <linux/multikernel.h>
#include <linux/panic.h>
#include <linux/pci.h>
#include <linux/topology.h>

#include <asm/pci_x86.h>
#include <asm/x86_init.h>

static bool mk_pci_roots_ready;
#define MK_PCI_ENUM_RETRIES	3
#define MK_PCI_ENUM_RETRY_MS	20
static atomic64_t mk_pci_request_id = ATOMIC64_INIT(0);
#define MK_PCI_RESET_TIMEOUT_MS	70000
#ifdef CONFIG_PCI_MSI
static void mk_pci_forward_irq_set_mask(struct irq_data *data, bool masked);
static void mk_pci_irq_mailbox_requeue(struct mk_irq_mailbox *mailbox,
				       unsigned int slot);

static void mk_pci_forward_irq_noop(struct irq_data *data)
{
}

static void mk_pci_forward_irq_mask(struct irq_data *data)
{
	mk_pci_forward_irq_set_mask(data, true);
}

static void mk_pci_forward_irq_unmask(struct irq_data *data)
{
	mk_pci_forward_irq_set_mask(data, false);
}

static void mk_pci_forward_irq_write_msg(struct irq_data *data,
					 struct msi_msg *msg)
{
}

static struct irq_chip mk_pci_forward_irq_chip = {
	.name = "multikernel-pci-forward",
	.irq_ack = mk_pci_forward_irq_noop,
	/* Host process-context lifecycle owns physical mask state. */
	.irq_mask = mk_pci_forward_irq_mask,
	.irq_unmask = mk_pci_forward_irq_unmask,
	.irq_write_msi_msg = mk_pci_forward_irq_write_msg,
};

static void mk_pci_bind_local_irqs(unsigned int irq, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		irq_set_chip_and_handler(irq + i, &mk_pci_forward_irq_chip,
					 handle_edge_irq);
}

static bool mk_pci_forward_irq_matches(u32 irq_number, u32 vector,
				       u32 device_id,
				       struct irq_data **irq_data)
{
	struct irq_data *data = irq_get_irq_data(irq_number);
	struct msi_desc *desc;
	struct pci_dev *dev;
	unsigned int offset;

	if (!data)
		return false;
	desc = irq_data_get_msi_desc(data);
	if (!desc || vector < desc->msi_index)
		return false;

	dev = msi_desc_to_pci_dev(desc);
	offset = vector - desc->msi_index;
	if (offset >= desc->nvec_used || desc->irq + offset != irq_number ||
	    pci_domain_nr(dev->bus) != MK_PCI_IRQ_ID_DOMAIN(device_id) ||
	    dev->bus->number != MK_PCI_IRQ_ID_BUS(device_id) ||
	    dev->devfn != MK_PCI_IRQ_ID_DEVFN(device_id))
		return false;

	*irq_data = data;
	return true;
}

static void mk_pci_forward_irq_set_mask(struct irq_data *data, bool masked)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct mk_irq_mailbox *mailbox;
	struct pci_dev *dev;
	u32 device_id;
	u32 generation;
	u32 vector;
	unsigned int slot;
	u64 epoch;

	if (!desc || !root_instance || !root_instance->ipi_data)
		return;
	dev = msi_desc_to_pci_dev(desc);
	generation = READ_ONCE(dev->multikernel_msi_generation);
	epoch = READ_ONCE(root_instance->ipi_data->spawn_epoch);
	device_id = MK_PCI_IRQ_ID(pci_domain_nr(dev->bus), dev->bus->number,
				  dev->devfn);
	vector = desc->msi_index + data->irq - desc->irq;
	mailbox = &root_instance->ipi_data->irq_mailbox;
	for (slot = 0; slot < MK_IRQ_MAILBOX_SLOTS; slot++) {
		struct mk_irq_mailbox_entry *entry = &mailbox->entries[slot];
		u64 old, new;
		u32 slot_generation;

		old = atomic64_read_acquire(&entry->pending_generation);
		if (!mk_irq_mailbox_generation(old) ||
		    READ_ONCE(entry->lifecycle_epoch) != epoch ||
		    READ_ONCE(entry->lifecycle_generation) != generation ||
		    READ_ONCE(entry->device_id) != device_id ||
		    READ_ONCE(entry->local_irq) != data->irq ||
		    READ_ONCE(entry->vector) != vector)
			continue;
		slot_generation = mk_irq_mailbox_generation(old);
		for (;;) {
			new = masked ? old | MK_IRQ_MAILBOX_MASKED :
				old & ~MK_IRQ_MAILBOX_MASKED;
			if (new == old ||
			    atomic64_cmpxchg(&entry->pending_generation,
					     old, new) == old)
				break;
			old = atomic64_read_acquire(&entry->pending_generation);
			if (mk_irq_mailbox_generation(old) != slot_generation)
				return;
		}
		if (!masked && mk_irq_mailbox_pending(new)) {
			mk_phys_cpu_t target;

			mk_pci_irq_mailbox_requeue(mailbox, slot);
			target = arch_cpu_physical_id(smp_processor_id());
			if (target != MK_PHYS_CPU_INVALID)
				mk_arch_send_ipi(target);
		}
		return;
	}
}

static void mk_pci_irq_mailbox_requeue(struct mk_irq_mailbox *mailbox,
				       unsigned int slot)
{
	atomic64_or(BIT_ULL(slot & 63),
		    &mailbox->pending_bitmap[slot / 64]);
}

static void mk_pci_irq_mailbox_drain_slot(struct mk_shared_data *shared,
					  unsigned int slot)
{
	struct mk_irq_mailbox *mailbox = &shared->irq_mailbox;
	struct mk_irq_mailbox_entry *entry = &mailbox->entries[slot];
	struct irq_data *irq_data;
	struct pci_dev *dev;
	u64 lifecycle_epoch;
	u64 token, base, claim;
	u32 lifecycle_generation;
	u32 pending;
	u32 device_id;
	u32 local_irq;
	u16 vector;

	token = atomic64_read_acquire(&entry->pending_generation);
	pending = mk_irq_mailbox_pending(token);
	if (!mk_irq_mailbox_generation(token) || !pending)
		return;
	if (mk_irq_mailbox_consuming(token)) {
		mk_pci_irq_mailbox_requeue(mailbox, slot);
		return;
	}
	lifecycle_epoch = READ_ONCE(entry->lifecycle_epoch);
	lifecycle_generation = READ_ONCE(entry->lifecycle_generation);
	device_id = READ_ONCE(entry->device_id);
	local_irq = READ_ONCE(entry->local_irq);
	vector = READ_ONCE(entry->vector);
	base = token & ~MK_IRQ_MAILBOX_PENDING_MASK;

	if (!local_irq || !root_instance || !root_instance->ipi_data ||
	    lifecycle_epoch != READ_ONCE(shared->spawn_epoch))
		goto stale;
	if (mk_irq_mailbox_masked(token)) {
		atomic_inc(&mailbox->masked_deferred);
		mk_pci_irq_mailbox_requeue(mailbox, slot);
		return;
	}
	claim = base | MK_IRQ_MAILBOX_CONSUMING;
	if (atomic64_cmpxchg_acquire(&entry->pending_generation,
				     token, claim) != token) {
		mk_pci_irq_mailbox_requeue(mailbox, slot);
		return;
	}
	token = atomic64_read_acquire(&entry->pending_generation);
	if (mk_irq_mailbox_generation(token) !=
	    mk_irq_mailbox_generation(claim))
		goto claimed_stale;
	if (mk_irq_mailbox_masked(token)) {
		atomic_inc(&mailbox->masked_deferred);
		goto claimed_defer;
	}
	if (!mk_pci_forward_irq_matches(local_irq, vector, device_id,
					&irq_data))
		goto claimed_stale;
	dev = msi_desc_to_pci_dev(irq_data_get_msi_desc(irq_data));
	if (lifecycle_epoch != READ_ONCE(entry->lifecycle_epoch) ||
	    lifecycle_generation !=
		READ_ONCE(entry->lifecycle_generation) ||
	    device_id != READ_ONCE(entry->device_id) ||
	    local_irq != READ_ONCE(entry->local_irq) ||
	    vector != READ_ONCE(entry->vector) ||
	    READ_ONCE(dev->multikernel_msi_state) != MK_PCI_MSI_ACTIVE ||
	    lifecycle_generation !=
		READ_ONCE(dev->multikernel_msi_generation) ||
	    irq_data_get_irq_chip(irq_data) != &mk_pci_forward_irq_chip)
		goto claimed_stale;
	if (pending > 1)
		atomic_add(pending - 1, &mailbox->coalesced);
	if (generic_handle_irq_safe(local_irq))
		atomic_inc(&mailbox->dispatch_failed);

	for (;;) {
		u64 new;

		token = atomic64_read_acquire(&entry->pending_generation);
		if (mk_irq_mailbox_generation(token) !=
		    mk_irq_mailbox_generation(claim) ||
		    !mk_irq_mailbox_consuming(token))
			return;
		new = token & ~MK_IRQ_MAILBOX_CONSUMING;
		if (atomic64_cmpxchg_release(&entry->pending_generation,
					     token, new) != token)
			continue;
		if (mk_irq_mailbox_pending(new))
			mk_pci_irq_mailbox_requeue(mailbox, slot);
		return;
	}

claimed_defer:
	for (;;) {
		u32 new_pending;
		u64 new;

		token = atomic64_read_acquire(&entry->pending_generation);
		if (mk_irq_mailbox_generation(token) !=
		    mk_irq_mailbox_generation(claim) ||
		    !mk_irq_mailbox_consuming(token))
			return;
		new_pending = mk_irq_mailbox_pending(token);
		if (new_pending < MK_IRQ_MAILBOX_PENDING_MASK)
			new_pending++;
		new = mk_irq_mailbox_token(mk_irq_mailbox_generation(token),
					   new_pending) |
			(token & MK_IRQ_MAILBOX_MASKED);
		if (atomic64_cmpxchg_release(&entry->pending_generation,
					     token, new) != token)
			continue;
		mk_pci_irq_mailbox_requeue(mailbox, slot);
		if (!mk_irq_mailbox_masked(new)) {
			mk_phys_cpu_t target =
				arch_cpu_physical_id(smp_processor_id());

			if (target != MK_PHYS_CPU_INVALID)
				mk_arch_send_ipi(target);
		}
		return;
	}

claimed_stale:
	atomic_inc(&mailbox->stale);
	for (;;) {
		u64 new;

		token = atomic64_read_acquire(&entry->pending_generation);
		if (mk_irq_mailbox_generation(token) !=
		    mk_irq_mailbox_generation(claim) ||
		    !mk_irq_mailbox_consuming(token))
			return;
		new = token & ~MK_IRQ_MAILBOX_CONSUMING;
		if (atomic64_cmpxchg_release(&entry->pending_generation,
					     token, new) != token)
			continue;
		if (mk_irq_mailbox_pending(new))
			mk_pci_irq_mailbox_requeue(mailbox, slot);
		return;
	}
	return;

stale:
	if (atomic64_cmpxchg_acquire(&entry->pending_generation,
				     token, base) != token)
		mk_pci_irq_mailbox_requeue(mailbox, slot);
	atomic_inc(&mailbox->stale);
}

void mk_pci_irq_mailbox_drain(struct mk_shared_data *shared)
{
	unsigned int word;

	if (!shared)
		return;
	for (word = 0; word < MK_IRQ_MAILBOX_WORDS; word++) {
		atomic64_t *pending_bitmap;
		unsigned long bits;

		pending_bitmap = &shared->irq_mailbox.pending_bitmap[word];
		bits = atomic64_xchg_acquire(pending_bitmap, 0);

		while (bits) {
			unsigned int bit = __ffs(bits);

			bits &= bits - 1;
			mk_pci_irq_mailbox_drain_slot(shared, word * 64 + bit);
		}
	}
}

static int mk_pci_send_irq_request(struct mk_pci_irq_request *request)
{
	struct mk_reply_handle reply;
	s32 status;
	int ret;

	if (WARN_ON_ONCE(irqs_disabled() || !in_task()))
		return -EWOULDBLOCK;
	might_sleep();
	if (!request->lifecycle_generation || !root_instance ||
	    !root_instance->ipi_data)
		return -EINVAL;
	request->lifecycle_epoch =
		READ_ONCE(root_instance->ipi_data->spawn_epoch);
	if (!request->lifecycle_epoch)
		return -EPROTO;

	request->request_id = atomic64_inc_return(&mk_pci_request_id);
	request->sender_instance_id = root_instance ? root_instance->id : -1;
	ret = mk_reply_reserve(root_instance->ipi_data, MK_REPLY_PCI_IRQ,
			       request->request_id, &reply);
	if (ret)
		return ret;
	request->reply_slot = reply.slot;
	request->reply_generation = reply.generation;

	ret = mk_send_message(0, MK_MSG_PCI, MK_PCI_IRQ_REQUEST,
			      request, sizeof(*request));
	if (ret) {
		mk_reply_release(root_instance->ipi_data, &reply);
		return ret;
	}

	ret = mk_reply_wait(root_instance->ipi_data, &reply, 1000,
			    &status, NULL);
	return ret ? ret : status;
}

bool mk_pci_msi_controlled(struct pci_dev *dev)
{
	return mk_pci_controlled(dev);
}

static int mk_pci_msi_teardown_generation(struct pci_dev *dev,
					  u32 generation);

int mk_pci_msi_prepare(struct pci_dev *dev, int nvec, int type)
{
	u32 generation;
	u8 state;
	struct mk_pci_irq_request request = {
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
		.operation = MK_PCI_IRQ_SETUP,
		.nr_vectors = nvec,
		.msix = type == PCI_CAP_ID_MSIX,
	};
	int ret;

	if (!mk_pci_msi_controlled(dev))
		return 0;
	state = READ_ONCE(dev->multikernel_msi_state);
	if (state == MK_PCI_MSI_FAILED) {
		generation = READ_ONCE(dev->multikernel_msi_generation);
		ret = mk_pci_msi_teardown_generation(dev, generation);
		if (ret)
			return ret;
		WRITE_ONCE(dev->multikernel_msi_state, MK_PCI_MSI_IDLE);
		state = MK_PCI_MSI_IDLE;
	}
	if (state != MK_PCI_MSI_IDLE)
		return -EBUSY;

	generation = READ_ONCE(dev->multikernel_msi_generation) + 1;
	if (!generation)
		generation = 1;
	WRITE_ONCE(dev->multikernel_msi_generation, generation);
	request.lifecycle_generation = generation;
	ret = mk_pci_send_irq_request(&request);
	if (ret) {
		if (ret == -EINPROGRESS) {
			int cleanup_ret;

			cleanup_ret = mk_pci_msi_teardown_generation(dev, generation);
			WRITE_ONCE(dev->multikernel_msi_state,
				   cleanup_ret ? MK_PCI_MSI_FAILED :
				   MK_PCI_MSI_IDLE);
		}
		return ret;
	}
	WRITE_ONCE(dev->multikernel_msi_nvec, nvec);
	WRITE_ONCE(dev->multikernel_msi_msix, type == PCI_CAP_ID_MSIX);
	WRITE_ONCE(dev->multikernel_msi_state, MK_PCI_MSI_PREPARED);
	return 0;
}

static int mk_pci_msi_bind(struct pci_dev *dev, unsigned int index,
			   unsigned int irq, unsigned int nvec, bool msix,
			   u32 generation)
{
	struct mk_pci_irq_request request = {
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
		.operation = MK_PCI_IRQ_BIND,
		.vector = index,
		.nr_vectors = nvec,
		.msix = msix,
		.local_irq = irq,
		.lifecycle_generation = generation,
	};
	unsigned int count = msix ? 1 : nvec;
	unsigned int i;
	int ret;

	/* The local descriptor must be dispatchable before the host unmasks. */
	mk_pci_bind_local_irqs(irq, count);
	ret = mk_pci_send_irq_request(&request);
	if (ret)
		return ret;
	/* Publish the irqdesc's initial logical mask state into the token. */
	for (i = 0; i < count; i++) {
		struct irq_data *data = irq_get_irq_data(irq + i);

		if (!data)
			return -EINVAL;
		mk_pci_forward_irq_set_mask(data,
					    irqd_irq_disabled(data) ||
					    irqd_irq_masked(data));
	}
	return 0;
}

static int mk_pci_msi_teardown_generation(struct pci_dev *dev, u32 generation)
{
	struct mk_pci_irq_request request = {
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
		.operation = MK_PCI_IRQ_TEARDOWN,
		.lifecycle_generation = generation,
	};

	return mk_pci_send_irq_request(&request);
}

static int mk_pci_msi_commit(struct pci_dev *dev, u32 generation)
{
	struct mk_pci_irq_request request = {
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
		.operation = MK_PCI_IRQ_COMMIT,
		.lifecycle_generation = generation,
	};

	return mk_pci_send_irq_request(&request);
}

static int mk_pci_msi_host_activate(struct pci_dev *dev, u32 generation)
{
	struct mk_pci_irq_request request = {
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
		.operation = MK_PCI_IRQ_ACTIVATE,
		.lifecycle_generation = generation,
	};

	return mk_pci_send_irq_request(&request);
}

static int mk_pci_msi_restore_begin(struct pci_dev *dev, u32 generation)
{
	struct mk_pci_irq_request request = {
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
		.operation = MK_PCI_IRQ_RESTORE_BEGIN,
		.lifecycle_generation = generation,
	};

	return mk_pci_send_irq_request(&request);
}

static int mk_pci_msi_bind_all(struct pci_dev *dev, u32 generation)
{
	struct msi_desc *desc;
	unsigned int expected = READ_ONCE(dev->multikernel_msi_nvec);
	unsigned int next = 0;
	bool msix = READ_ONCE(dev->multikernel_msi_msix);
	int ret;

	msi_for_each_desc(desc, &dev->dev, MSI_DESC_ALL) {
		unsigned int count = msix ? 1 : desc->nvec_used;

		if (next >= expected || desc->msi_index != next || !count ||
		    count > expected - next)
			return -EINVAL;
		ret = mk_pci_msi_bind(dev, desc->msi_index, desc->irq,
				      desc->nvec_used, msix, generation);
		if (ret)
			return ret;
		next += count;
	}
	if (next != expected)
		return -EINVAL;
	return mk_pci_msi_commit(dev, generation);
}

static int mk_pci_msi_mask_mailbox(struct pci_dev *dev)
{
	struct msi_desc *desc;
	unsigned long deadline;
	u64 epoch;
	u32 device_id;
	u32 generation;
	unsigned int slot;

	msi_for_each_desc(desc, &dev->dev, MSI_DESC_ALL) {
		unsigned int count = desc->pci.msi_attrib.is_msix ?
			1 : desc->nvec_used;
		unsigned int i;

		for (i = 0; i < count; i++) {
			struct irq_data *data = irq_get_irq_data(desc->irq + i);

			if (data)
				mk_pci_forward_irq_set_mask(data, true);
		}
	}

	epoch = READ_ONCE(root_instance->ipi_data->spawn_epoch);
	generation = READ_ONCE(dev->multikernel_msi_generation);
	device_id = MK_PCI_IRQ_ID(pci_domain_nr(dev->bus), dev->bus->number,
				  dev->devfn);
	deadline = jiffies + msecs_to_jiffies(1000);
	for (;;) {
		bool consuming = false;

		for (slot = 0; slot < MK_IRQ_MAILBOX_SLOTS; slot++) {
			struct mk_irq_mailbox_entry *entry =
				&root_instance->ipi_data->irq_mailbox.entries[slot];
			u64 token;

			token = atomic64_read_acquire(&entry->pending_generation);

			if (mk_irq_mailbox_generation(token) &&
			    mk_irq_mailbox_consuming(token) &&
			    READ_ONCE(entry->lifecycle_epoch) == epoch &&
			    READ_ONCE(entry->lifecycle_generation) == generation &&
			    READ_ONCE(entry->device_id) == device_id) {
				consuming = true;
				break;
			}
		}
		if (!consuming)
			break;
		if (time_after_eq(jiffies, deadline))
			return -ETIMEDOUT;
		usleep_range(50, 100);
	}
	msi_for_each_desc(desc, &dev->dev, MSI_DESC_ALL) {
		unsigned int count = desc->pci.msi_attrib.is_msix ?
			1 : desc->nvec_used;
		unsigned int i;

		for (i = 0; i < count; i++)
			synchronize_irq(desc->irq + i);
	}
	return 0;
}

int mk_pci_msi_activate(struct pci_dev *dev)
{
	u32 generation;
	int cleanup_ret;
	int ret;

	if (!mk_pci_msi_controlled(dev))
		return 0;
	if (READ_ONCE(dev->multikernel_msi_state) != MK_PCI_MSI_PREPARED)
		return -EIO;
	generation = READ_ONCE(dev->multikernel_msi_generation);
	ret = mk_pci_msi_bind_all(dev, generation);
	if (ret) {
		pr_err("Failed to activate host-owned MSI vectors for %s: %d\n",
		       pci_name(dev), ret);
		cleanup_ret = mk_pci_msi_teardown_generation(dev, generation);
		WRITE_ONCE(dev->multikernel_msi_state,
			   cleanup_ret ? MK_PCI_MSI_FAILED : MK_PCI_MSI_IDLE);
		return ret;
	}

	/* The guest must be able to consume the first edge before host unmask. */
	WRITE_ONCE(dev->multikernel_msi_state, MK_PCI_MSI_ACTIVE);
	ret = mk_pci_msi_host_activate(dev, generation);
	if (ret) {
		cleanup_ret = mk_pci_msi_mask_mailbox(dev);
		if (!cleanup_ret)
			cleanup_ret = mk_pci_msi_teardown_generation(dev, generation);
		WRITE_ONCE(dev->multikernel_msi_state,
			   cleanup_ret ? MK_PCI_MSI_FAILED : MK_PCI_MSI_IDLE);
		return ret;
	}
	return 0;
}

int mk_pci_msi_restore(struct pci_dev *dev)
{
	u32 generation;
	int cleanup_ret;
	int ret;

	if (!mk_pci_msi_controlled(dev))
		return 0;
	if (READ_ONCE(dev->multikernel_msi_state) != MK_PCI_MSI_ACTIVE)
		return -EIO;
	generation = READ_ONCE(dev->multikernel_msi_generation);
	ret = mk_pci_msi_mask_mailbox(dev);
	if (ret) {
		WRITE_ONCE(dev->multikernel_msi_state, MK_PCI_MSI_FAILED);
		return ret;
	}
	ret = mk_pci_msi_restore_begin(dev, generation);
	if (!ret)
		ret = mk_pci_msi_bind_all(dev, generation);
	if (!ret)
		ret = mk_pci_msi_host_activate(dev, generation);
	if (ret) {
		cleanup_ret = mk_pci_msi_teardown_generation(dev, generation);
		WRITE_ONCE(dev->multikernel_msi_state, MK_PCI_MSI_FAILED);
		if (cleanup_ret)
			pr_err("Failed to quiesce host-owned MSI after restore failure for %s: %d\n",
			       pci_name(dev), cleanup_ret);
		return ret;
	}
	return 0;
}

int mk_pci_msi_teardown(struct pci_dev *dev)
{
	u32 generation;
	int ret;

	if (!mk_pci_msi_controlled(dev))
		return 0;
	if (READ_ONCE(dev->multikernel_msi_state) == MK_PCI_MSI_IDLE)
		return 0;
	generation = READ_ONCE(dev->multikernel_msi_generation);
	ret = mk_pci_msi_mask_mailbox(dev);
	if (!ret)
		ret = mk_pci_msi_teardown_generation(dev, generation);
	WRITE_ONCE(dev->multikernel_msi_state,
		   ret ? MK_PCI_MSI_FAILED : MK_PCI_MSI_IDLE);
	return ret;
}
#endif /* CONFIG_PCI_MSI */

bool mk_pci_controlled(struct pci_dev *dev)
{
	return root_instance && root_instance->id != 0 &&
		mk_pci_get_assigned_identity_bdf(pci_domain_nr(dev->bus),
						 dev->bus->number, dev->devfn,
						 NULL, NULL);
}

int mk_pci_reset_flr(struct pci_dev *dev)
{
	struct mk_pci_reset_request request = {
		.domain = pci_domain_nr(dev->bus),
		.bus = dev->bus->number,
		.devfn = dev->devfn,
	};
	struct mk_reply_handle reply;
	u32 generation;
	s32 status;
	int ret;

	if (WARN_ON_ONCE(irqs_disabled() || !in_task()))
		return -EWOULDBLOCK;
	might_sleep();
	if (!root_instance || !root_instance->ipi_data)
		return -ENODEV;
	request.lifecycle_epoch =
		READ_ONCE(root_instance->ipi_data->spawn_epoch);
	if (!request.lifecycle_epoch)
		return -EPROTO;

	generation = READ_ONCE(dev->multikernel_reset_generation) + 1;
	if (!generation)
		generation = 1;
	WRITE_ONCE(dev->multikernel_reset_generation, generation);
	request.reset_generation = generation;
	request.request_id = atomic64_inc_return(&mk_pci_request_id);
	request.sender_instance_id = root_instance->id;
	ret = mk_reply_reserve(root_instance->ipi_data, MK_REPLY_PCI_RESET,
			       request.request_id, &reply);
	if (ret)
		return ret;
	request.reply_slot = reply.slot;
	request.reply_generation = reply.generation;

	ret = mk_send_message(0, MK_MSG_PCI, MK_PCI_RESET_REQUEST,
			      &request, sizeof(request));
	if (ret) {
		mk_reply_release(root_instance->ipi_data, &reply);
		return ret;
	}

	ret = mk_reply_wait(root_instance->ipi_data, &reply,
			    MK_PCI_RESET_TIMEOUT_MS,
			    &status, NULL);
	return ret ? ret : status;
}

static void mk_pci_record_latency(u64 start)
{
	struct mk_shared_data *shared = READ_ONCE(root_instance->ipi_data);
	struct mk_pci_stats *stats;
	u64 elapsed = ktime_get_mono_fast_ns() - start;
	u64 old_max;

	if (!shared)
		return;
	stats = &shared->pci_stats;
	old_max = atomic64_read(&stats->config_max_ns);
	atomic64_inc(&stats->config_requests);
	atomic64_add(elapsed, &stats->config_total_ns);
	while (elapsed > old_max) {
		u64 previous = atomic64_cmpxchg(&stats->config_max_ns, old_max,
						 elapsed);

		if (previous == old_max)
			break;
		old_max = previous;
	}
}

static int mk_pci_remote_config(unsigned int domain, unsigned int bus,
				unsigned int devfn, int where, int size,
				bool write, u32 *value)
{
	struct mk_pci_cfg_request request = {
		.request_id = atomic64_inc_return(&mk_pci_request_id),
		.sender_instance_id = root_instance ? root_instance->id : -1,
		.domain = domain,
		.bus = bus,
		.devfn = devfn,
		.reg = where,
		.len = size,
		.write = write,
		.value = *value,
	};
	struct mk_reply_handle reply;
	s32 status;
	u32 response_value;
	u64 start = ktime_get_mono_fast_ns();
	int ret;

	ret = mk_reply_reserve(root_instance->ipi_data, MK_REPLY_PCI_CFG,
			       request.request_id, &reply);
	if (ret)
		goto out_error;
	request.reply_slot = reply.slot;
	request.reply_generation = reply.generation;

	ret = mk_send_message(0, MK_MSG_PCI, MK_PCI_CFG_REQUEST,
			      &request, sizeof(request));
	if (ret) {
		mk_reply_release(root_instance->ipi_data, &reply);
		goto out_error;
	}
	ret = mk_reply_wait_atomic(root_instance->ipi_data, &reply, 20000,
				   &status, &response_value);
	if (ret)
		goto out_error;
	if (status < 0) {
		ret = status;
		goto out_error;
	}
	if (!write)
		*value = response_value;
	mk_pci_record_latency(start);
	return status;

out_error:
	if (ret < 0) {
		pr_err_ratelimited("Multikernel PCI config request timed out or failed to send: %d\n",
				   ret);
	}
	return PCIBIOS_SET_FAILED;
}

static bool mk_pci_identity_read(u16 vendor, u16 device, int where, int size,
				 u32 *value)
{
	u32 identity;
	u32 mask;

	if (where < PCI_VENDOR_ID || where + size > PCI_COMMAND)
		return false;

	identity = vendor | (u32)device << 16;
	mask = size == sizeof(identity) ? ~0U : (1U << (size * 8)) - 1;
	*value = (identity >> (where * 8)) & mask;
	return true;
}

static int mk_pci_raw_read(unsigned int domain, unsigned int bus,
			   unsigned int devfn, int where, int size,
			   u32 *value)
{
	u16 vendor, device;

	if (!mk_pci_get_assigned_identity_bdf(domain, bus, devfn, &vendor,
					      &device)) {
		*value = ~0U;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}
	if (mk_pci_identity_read(vendor, device, where, size, value))
		return PCIBIOS_SUCCESSFUL;

	return mk_pci_remote_config(domain, bus, devfn, where, size, false,
				    value);
}

static int mk_pci_raw_write(unsigned int domain, unsigned int bus,
			    unsigned int devfn, int where, int size,
			    u32 value)
{
	if (!mk_pci_get_assigned_identity_bdf(domain, bus, devfn, NULL, NULL))
		return PCIBIOS_DEVICE_NOT_FOUND;

	return mk_pci_remote_config(domain, bus, devfn, where, size, true,
				    &value);
}

static const struct pci_raw_ops mk_pci_filtered_raw_ops = {
	.read = mk_pci_raw_read,
	.write = mk_pci_raw_write,
};

static int __init x86_multikernel_pci_arch_init(void)
{
	if (!root_instance || !root_instance->pci_devices_valid)
		return 0;

	raw_pci_ops = &mk_pci_filtered_raw_ops;
	raw_pci_ext_ops = &mk_pci_filtered_raw_ops;
	mk_pci_roots_ready = true;
	pr_notice("Multikernel selected host-mediated PCI config access\n");

	return 0;
}

static struct pci_bus * __init mk_pci_get_root(u16 domain, u8 bus_number)
{
	struct resource_entry *window;
	struct pci_sysdata *sd;
	struct pci_bus *bus;
	bool has_busn_res = false;
	LIST_HEAD(resources);

	if (domain && !pci_domains_supported) {
		pr_err("Multikernel cannot scan PCI root %04x:%02x without domain support\n",
		       domain, bus_number);
		return ERR_PTR(-EOPNOTSUPP);
	}
	bus = pci_find_bus(domain, bus_number);
	if (bus)
		return bus;

	sd = kzalloc_obj(*sd, GFP_KERNEL);
	if (!sd)
		return ERR_PTR(-ENOMEM);
	sd->domain = domain;
	sd->node = x86_pci_root_bus_node(bus_number);
	x86_pci_root_bus_resources(bus_number, &resources);
	resource_list_for_each_entry(window, &resources) {
		if (window->res->flags & IORESOURCE_BUS) {
			has_busn_res = true;
			break;
		}
	}
	bus = pci_create_root_bus(NULL, bus_number, &pci_root_ops, sd,
				  &resources);
	if (!bus) {
		pci_free_resource_list(&resources);
		kfree(sd);
		return ERR_PTR(-ENOMEM);
	}
	if (!has_busn_res) {
		if (!pci_bus_insert_busn_res(bus, bus_number, bus_number)) {
			pci_remove_root_bus(bus);
			kfree(sd);
			return ERR_PTR(-EBUSY);
		}
	}
	pr_notice("Multikernel created synthetic PCI root %04x:%02x\n",
		  domain, bus_number);
	return bus;
}

static struct pci_dev * __init
mk_pci_scan_assigned_device(struct pci_bus *bus, unsigned int devfn)
{
	struct pci_dev *pdev;
	unsigned int attempt;

	for (attempt = 0; attempt < MK_PCI_ENUM_RETRIES; attempt++) {
		pdev = pci_scan_single_device(bus, devfn);
		if (pdev)
			return pdev;
		if (attempt + 1 < MK_PCI_ENUM_RETRIES)
			msleep(MK_PCI_ENUM_RETRY_MS);
	}

	return NULL;
}

static int __init x86_multikernel_pci_init(void)
{
	const struct mk_pci_device *device;
	struct pci_bus *bus;
	struct pci_dev *pdev;

	if (!root_instance)
		panic("Multikernel lost restored instance metadata");
	if (!root_instance->pci_device_count)
		return 0;
	if (!root_instance->pci_devices_valid || !mk_pci_roots_ready)
		panic("Multikernel assigned PCI inventory is unavailable");

	list_for_each_entry(device, &root_instance->pci_devices, list) {
		bus = mk_pci_get_root(device->domain, device->bus);
		if (IS_ERR(bus))
			panic("Multikernel failed to create synthetic PCI root %04x:%02x: %ld",
			      device->domain, device->bus, PTR_ERR(bus));
		pdev = mk_pci_scan_assigned_device(bus,
						   PCI_DEVFN(device->slot,
							     device->func));
		if (!pdev)
			panic("Multikernel failed to enumerate assigned PCI device %04x:%02x:%02x.%x after %u attempts",
			      device->domain, device->bus, device->slot,
			      device->func, MK_PCI_ENUM_RETRIES);
		pci_bus_add_devices(bus);
	}
	if (atomic64_read(&root_instance->ipi_data->pci_stats.config_requests)) {
		struct mk_pci_stats *stats = &root_instance->ipi_data->pci_stats;
		u64 count = atomic64_read(&stats->config_requests);

		pr_notice("Multikernel PCI control plane: %llu config requests, average %llu ns, max %llu ns\n",
			  count, atomic64_read(&stats->config_total_ns) / count,
			  atomic64_read(&stats->config_max_ns));
	}

	/* Suppress legacy bus 0 probing after every assigned root is present. */
	return 0;
}
void __init x86_multikernel_pci_platform_init(void)
{
	pci_probe = PCI_PROBE_NOEARLY;
	x86_init.pci.arch_init = x86_multikernel_pci_arch_init;
	x86_init.pci.init = x86_multikernel_pci_init;
}
