// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multikernel Resource Hotplug Management
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * This module handles CPU and memory hotplugging operations for
 * multikernel instances. It registers IPI callbacks to handle resource
 * addition/removal requests and performs the actual hotplug operations.
 *
 * The code is designed to work on both host and spawn kernels:
 * - Host kernel removes resources before transferring to spawn kernel
 * - Spawn kernel adds resources after receiving them from host kernel
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/memory.h>
#include <linux/memory_hotplug.h>
#include <linux/node.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include "internal.h"

static const char mk_mem_resource_name[] = "System RAM (multikernel)";

/* Resource operation tracking for rollback support */
struct mk_hotplug_op {
	enum {
		MK_HOTPLUG_CPU_ADD,
		MK_HOTPLUG_CPU_REMOVE,
		MK_HOTPLUG_MEM_ADD,
		MK_HOTPLUG_MEM_REMOVE,
		MK_HOTPLUG_DEVICE_ADD,
		MK_HOTPLUG_DEVICE_REMOVE
	} type;

	union {
		struct {
			u64 cpu_id;        /* Physical CPU ID */
			u32 numa_node;
		} cpu;

		struct {
			u64 start_pfn;
			u64 nr_pages;
			u32 numa_node;
			u64 phys_addr;
		} mem;

		struct {
			u16 domain;
			u8 bus;
			u8 devfn;
			char prev_driver[64]; /* Previous driver name */
		} device;
	};

	struct list_head list;
};

static DEFINE_MUTEX(mk_hotplug_mutex);
static LIST_HEAD(mk_hotplug_ops);

/*
 * A remove ACK must not overtake an earlier queued add. CPU requests share an
 * ordered queue; memory and device workers retain their existing scheduling.
 * The raw lock protects resource admission and CPU queue detachment;
 * the receive path runs in hard-IPI context, including on PREEMPT_RT.
 */
static DEFINE_RAW_SPINLOCK(mk_cpu_hotplug_lock);
static struct workqueue_struct *mk_cpu_hotplug_wq;
static bool mk_hotplug_accepting;
static unsigned int mk_hotplug_inflight;
static DECLARE_WAIT_QUEUE_HEAD(mk_hotplug_wait);

static int mk_queue_hotplug_work(struct work_struct *work, bool cpu)
{
	unsigned long flags;
	int ret = 0;

	raw_spin_lock_irqsave(&mk_cpu_hotplug_lock, flags);
	if (!mk_hotplug_accepting) {
		ret = -ESHUTDOWN;
	} else {
		mk_hotplug_inflight++;
		if (cpu)
			queue_work(mk_cpu_hotplug_wq, work);
		else
			schedule_work(work);
	}
	raw_spin_unlock_irqrestore(&mk_cpu_hotplug_lock, flags);
	return ret;
}

static int mk_queue_cpu_work(struct work_struct *work)
{
	return mk_queue_hotplug_work(work, true);
}

static void mk_hotplug_work_done(void)
{
	unsigned long flags;
	bool idle;

	raw_spin_lock_irqsave(&mk_cpu_hotplug_lock, flags);
	idle = !--mk_hotplug_inflight;
	raw_spin_unlock_irqrestore(&mk_cpu_hotplug_lock, flags);
	if (idle)
		wake_up_all(&mk_hotplug_wait);
}

static bool mk_hotplug_idle(void)
{
	unsigned long flags;
	bool idle;

	raw_spin_lock_irqsave(&mk_cpu_hotplug_lock, flags);
	idle = !mk_hotplug_inflight;
	raw_spin_unlock_irqrestore(&mk_cpu_hotplug_lock, flags);
	return idle;
}

/*
 * Process context only, outside all controller/tracking locks and resource
 * workers. Close incoming admission before waiting for accepted workers to
 * finish mutation, ACK transmission and work allocation release. A stuck
 * worker must prevent a successful shutdown ACK, not permit unsafe reuse.
 * This does not fence local controllers, drivers or other ring writers.
 */
void mk_hotplug_quiesce(void)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&mk_cpu_hotplug_lock, flags);
	mk_hotplug_accepting = false;
	raw_spin_unlock_irqrestore(&mk_cpu_hotplug_lock, flags);
	wait_event(mk_hotplug_wait, mk_hotplug_idle());
}

static struct workqueue_struct *mk_cpu_hotplug_detach(void)
{
	struct workqueue_struct *wq;
	unsigned long flags;

	raw_spin_lock_irqsave(&mk_cpu_hotplug_lock, flags);
	wq = mk_cpu_hotplug_wq;
	mk_cpu_hotplug_wq = NULL;
	raw_spin_unlock_irqrestore(&mk_cpu_hotplug_lock, flags);
	return wq;
}

/*
 * CPU Hotplug Operations
 */
struct mk_cpu_hotplug_work {
	struct work_struct work;
	u64 msg_id;
	mk_phys_cpu_t cpu_id;
	u32 numa_node;
	u32 flags;
	int sender_instance_id;  /* For sending ACK back */
	u32 operation;           /* MK_RES_CPU_ADD or MK_RES_CPU_REMOVE */
};

/*
 * Ownership tracking for this kernel's own hotplug: mk_self->cpus
 * is the set of CPUs this kernel owns, in the host and in spawn kernels
 * alike. The assignable-pool bookkeeping (mk_pool) is not done here;
 * it belongs to the mk_send_cpu_* initiator paths of the kernel that
 * manages the pool.
 */
static void mk_account_cpu_offline(mk_phys_cpu_t cpu_id)
{
	mk_cpu_set_del(mk_self->cpus, cpu_id);
	mk_instance_ipi_retarget(mk_self);
}

/**
 * Search present CPUs (not possible CPUs) to find the logical CPU with matching
 * physical ID. Using present CPUs is important because topology can change during
 * multikernel operations, and we only care about CPUs that are actually present.
 */
static int mk_cpu_to_logical(mk_phys_cpu_t cpu_id)
{
	int cpu;

	for_each_present_cpu(cpu) {
		if (arch_cpu_physical_id(cpu) == cpu_id)
			return cpu;
	}

	pr_err("Multikernel hotplug: Physical CPU %llu not found in present CPUs\n",
	       cpu_id);
	return -EINVAL;
}

static int mk_do_cpu_add(mk_phys_cpu_t cpu_id, u32 numa_node, u32 flags)
{
	bool owned, attempted = false;
	int logical_cpu;
	int ret;
	struct mk_hotplug_op *op;

	lockdep_assert_held(&mk_overlay_mutex);
	pr_info("Multikernel hotplug: Adding CPU %llu (numa=%d, flags=0x%x)\n",
		cpu_id, (int)numa_node, flags);

	logical_cpu = mk_cpu_to_logical(cpu_id);
	if (logical_cpu < 0) {
		/*
		 * Not present: this pool CPU has never run here (or was
		 * removed earlier). It was enumerated at boot from the host
		 * tree's cpus list, so it has a logical slot in the possible
		 * map. reclaim_cpu() restores presence under native serialization.
		 */
		logical_cpu = arch_cpu_from_physical_id(cpu_id);
		if (logical_cpu < 0) {
			pr_err("Multikernel hotplug: CPU %llu is not in this kernel's pool\n",
			       cpu_id);
			return -ENODEV;
		}
	}

	if (logical_cpu >= nr_cpu_ids || !cpu_possible(logical_cpu))
		return -ENODEV;
	if (!mk_self->cpus)
		return -EINVAL;
	owned = mk_cpu_set_contains(mk_self->cpus, cpu_id);
	ret = mk_cpu_set_add(mk_self->cpus, cpu_id);
	if (ret)
		return ret;

	/* Register absent enumerated CPUs before exposing them to native bringup. */
	lock_device_hotplug();
	if (!get_cpu_device(logical_cpu)) {
		struct cpu *c = &per_cpu(cpu_devices, logical_cpu);

		c->hotpluggable = true;
		ret = cpu_present(logical_cpu) ? -ENODEV : register_cpu(c, logical_cpu);
	}
	unlock_device_hotplug();
	if (ret)
		goto failed;

	ret = reclaim_cpu(logical_cpu, &attempted);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to add CPU %d (phys %llu): %d\n",
		       logical_cpu, cpu_id, ret);
		goto failed;
	}

	mk_instance_ipi_retarget(mk_self);

	/* Track the operation for potential rollback */
	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (op) {
		op->type = MK_HOTPLUG_CPU_ADD;
		op->cpu.cpu_id = cpu_id;
		op->cpu.numa_node = numa_node;

		mutex_lock(&mk_hotplug_mutex);
		list_add_tail(&op->list, &mk_hotplug_ops);
		mutex_unlock(&mk_hotplug_mutex);
	}

	pr_info("Multikernel hotplug: Successfully added CPU %d (phys %llu)\n",
		logical_cpu, cpu_id);

	return 0;
failed:
	if (!attempted) {
		if (!owned)
			mk_cpu_set_del(mk_self->cpus, cpu_id);
	} else if (mk_pool) {
		/*
		 * Keep pool membership until after the wake callback: it selects
		 * the local park slot. Once bringup was attempted, even a rolled
		 * back CPU must not become assignable without independent proof.
		 */
		guard(mutex)(&mk_pool->cpus_lock);
		mk_cpu_set_del(mk_pool->cpus, cpu_id);
	}
	return ret;
}

static int mk_do_cpu_remove(mk_phys_cpu_t cpu_id)
{
	int logical_cpu;
	int ret;
	struct mk_hotplug_op *op;

	logical_cpu = mk_cpu_to_logical(cpu_id);
	if (logical_cpu < 0) {
		pr_err("Multikernel hotplug: Physical CPU %llu not found\n", cpu_id);
		return -ENODEV;
	}

	ret = depart_cpu(logical_cpu);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to remove CPU %d (phys %llu): %d\n",
		       logical_cpu, cpu_id, ret);
		return ret;
	}

	mk_account_cpu_offline(cpu_id);

	/* Track the operation for potential rollback */
	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (op) {
		op->type = MK_HOTPLUG_CPU_REMOVE;
		op->cpu.cpu_id = cpu_id;
		op->cpu.numa_node = 0;

		mutex_lock(&mk_hotplug_mutex);
		list_add_tail(&op->list, &mk_hotplug_ops);
		mutex_unlock(&mk_hotplug_mutex);
	}

	pr_info("Multikernel hotplug: Successfully removed CPU %d (phys %llu)\n",
		logical_cpu, cpu_id);

	return 0;
}

static void mk_cpu_add_work_fn(struct work_struct *work)
{
	struct mk_cpu_hotplug_work *hp_work = container_of(work, struct mk_cpu_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	/* A controller may hold this lock while waiting for a remote ACK. */
	ret = -EBUSY;
	if (mutex_trylock(&mk_overlay_mutex)) {
		ret = mk_do_cpu_add(hp_work->cpu_id, hp_work->numa_node, hp_work->flags);
		mutex_unlock(&mk_overlay_mutex);
	}

	/* Send ACK back to sender */
	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = hp_work->cpu_id;

	ack_ret = mk_send_message_id(hp_work->sender_instance_id, MK_MSG_RESOURCE,
				     MK_RES_ACK, hp_work->msg_id, &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for CPU %llu: %d\n",
			hp_work->cpu_id, ack_ret);
	}

	kfree(hp_work);
	mk_hotplug_work_done();
}

static void mk_cpu_remove_work_fn(struct work_struct *work)
{
	struct mk_cpu_hotplug_work *hp_work = container_of(work, struct mk_cpu_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = -EBUSY;
	if (mutex_trylock(&mk_overlay_mutex)) {
		ret = mk_do_cpu_remove(hp_work->cpu_id);
		mutex_unlock(&mk_overlay_mutex);
	}

	/* Send ACK back to sender */
	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = hp_work->cpu_id;

	ack_ret = mk_send_message_id(hp_work->sender_instance_id, MK_MSG_RESOURCE,
				     MK_RES_ACK, hp_work->msg_id, &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for CPU %llu: %d\n",
			hp_work->cpu_id, ack_ret);
	}

	kfree(hp_work);
	mk_hotplug_work_done();
}

/**
 * mk_handle_cpu_add - Handle CPU addition request
 * @payload: CPU resource payload
 * @payload_len: Payload length
 * @msg_id: Request ID to echo in the reply
 *
 * Brings a CPU online in the receiving kernel. This is called on the spawn
 * kernel side when the host kernel transfers a CPU to it.
 *
 * Returns 0 on success, negative error code on failure
 */
static int mk_handle_cpu_add(struct mk_cpu_resource_payload *payload, u32 payload_len,
			       u64 msg_id)
{
	struct mk_cpu_hotplug_work *hp_work;
	int ret;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid CPU add payload size: %u\n", payload_len);
		return -EINVAL;
	}

	/*
	 * We're in IRQ context (IPI handler), so we can't call add_cpu() directly.
	 */
	hp_work = kmalloc(sizeof(*hp_work), GFP_ATOMIC);
	if (!hp_work)
		return -ENOMEM;

	INIT_WORK(&hp_work->work, mk_cpu_add_work_fn);
	hp_work->msg_id = msg_id;
	hp_work->cpu_id = payload->cpu_id;
	hp_work->numa_node = payload->numa_node;
	hp_work->flags = payload->flags;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_CPU_ADD;
	ret = mk_queue_cpu_work(&hp_work->work);
	if (ret)
		kfree(hp_work);

	return ret;
}

/**
 * mk_handle_cpu_remove - Handle CPU removal request
 * @payload: CPU resource payload
 * @payload_len: Payload length
 * @msg_id: Request ID to echo in the reply
 *
 * Takes a CPU offline in the current kernel. This is called on the host
 * kernel side before transferring a CPU to a spawn kernel.
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_handle_cpu_remove(struct mk_cpu_resource_payload *payload, u32 payload_len,
			 u64 msg_id)
{
	struct mk_cpu_hotplug_work *hp_work;
	int ret;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid CPU remove payload size: %u\n", payload_len);
		return -EINVAL;
	}

	/*
	 * We're in IRQ context (IPI handler), so we can't call remove_cpu() directly.
	 */
	hp_work = kmalloc(sizeof(*hp_work), GFP_ATOMIC);
	if (!hp_work)
		return -ENOMEM;

	INIT_WORK(&hp_work->work, mk_cpu_remove_work_fn);
	hp_work->msg_id = msg_id;
	hp_work->cpu_id = payload->cpu_id;
	hp_work->numa_node = payload->numa_node;
	hp_work->flags = payload->flags;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_CPU_REMOVE;
	ret = mk_queue_cpu_work(&hp_work->work);
	if (ret)
		kfree(hp_work);

	return ret;
}

/*
 * Memory Hotplug Operations
 */

static int mk_online_memory_block_movable(struct memory_block *mem, void *arg)
{
	int ret;

	/* Handle blocks that were auto-onlined to wrong zone */
	if (mem->state == MEM_ONLINE) {
		ret = device_offline(&mem->dev);
		if (ret < 0)
			return ret;
	}

	mem->online_type = MMOP_ONLINE_MOVABLE;
	return device_online(&mem->dev);
}

/*
 * Whole memory blocks are added with their memmap on the memory itself,
 * so that a small kernel can take on far more memory than its own RAM
 * has room to describe; the parts of blocks at either end of a range are
 * added in subsections.
 */
struct mk_mem_piece {
	u64 start;
	u64 size;
	bool blocks;
};

static int mk_mem_pieces(u64 start, u64 size, struct mk_mem_piece *piece)
{
	const u64 block = memory_block_size_bytes();
	const u64 end = start + size;
	const u64 mid_start = min(ALIGN(start, block), end);
	const u64 mid_end = max(ALIGN_DOWN(end, block), mid_start);
	int n = 0;

	if (mid_start > start)
		piece[n++] = (struct mk_mem_piece){ start, mid_start - start, false };
	if (mid_end > mid_start)
		piece[n++] = (struct mk_mem_piece){ mid_start, mid_end - mid_start, true };
	if (end > mid_end)
		piece[n++] = (struct mk_mem_piece){ mid_end, end - mid_end, false };
	return n;
}

static int mk_mem_piece_add(int nid, const struct mk_mem_piece *piece)
{
	int ret;

	if (!piece->blocks)
		return add_and_online_subsections(nid, piece->start, piece->size,
						  MMOP_ONLINE_MOVABLE,
						  mk_mem_resource_name);

	ret = add_memory_driver_managed(nid, piece->start, piece->size,
					mk_mem_resource_name,
					MHP_MEMMAP_ON_MEMORY);
	if (ret < 0)
		return ret;

	ret = walk_memory_blocks(piece->start, piece->size, NULL,
				 mk_online_memory_block_movable);
	if (ret < 0)
		offline_and_remove_memory(piece->start, piece->size);
	return ret;
}

static int mk_mem_piece_remove(const struct mk_mem_piece *piece)
{
	if (piece->blocks)
		return offline_and_remove_memory(piece->start, piece->size);
	return offline_and_remove_subsections(piece->start, piece->size);
}

static int mk_do_mem_add(u64 start_pfn, u64 nr_pages, u32 numa_node, u32 mem_type)
{
	struct mk_mem_piece piece[3];
	int ret, i, n;
	int nid;
	u64 phys_addr;
	u64 size;
	struct mk_hotplug_op *op;

	phys_addr = PFN_PHYS(start_pfn);
	size = PFN_PHYS(nr_pages);

	/*
	 * The payload carries the node as u32, so an unspecified node
	 * arrives as (u32)NUMA_NO_NODE. Anything outside the node range
	 * would index the node mask out of bounds below.
	 */
	nid = (int)numa_node;
	if (nid < 0 || nid >= MAX_NUMNODES) {
		if (numa_node != (u32)NUMA_NO_NODE)
			pr_warn("Multikernel hotplug: NUMA node %u out of range, using node 0\n",
				numa_node);
		nid = 0;
	}

	pr_info("Multikernel hotplug: Adding memory 0x%llx-0x%llx (%llu MB) numa=%d type=0x%x\n",
		phys_addr, phys_addr + size - 1, size >> 20,
		(int)numa_node, mem_type);

	if (!IS_ALIGNED(phys_addr | size, MHP_SUBSECTIONS_ALIGN)) {
		pr_err("Multikernel hotplug: Memory 0x%llx+0x%llx not aligned to 0x%lx\n",
		       phys_addr, size, MHP_SUBSECTIONS_ALIGN);
		return -EINVAL;
	}

	/* Ensure the NUMA node exists */
	if (!node_online(nid)) {
		ret = try_online_node(nid);
		if (ret < 0) {
			pr_warn("Multikernel hotplug: Failed to online node %d: %d, using node 0\n",
				nid, ret);
			nid = 0;
		}
	}

	n = mk_mem_pieces(phys_addr, size, piece);
	for (i = 0; i < n; i++) {
		ret = mk_mem_piece_add(nid, &piece[i]);
		if (ret < 0) {
			pr_err("Multikernel hotplug: Failed to add memory at 0x%llx: %d\n",
			       piece[i].start, ret);
			while (i--)
				mk_mem_piece_remove(&piece[i]);
			return ret;
		}
	}

	/* Track the operation for potential rollback */
	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (op) {
		op->type = MK_HOTPLUG_MEM_ADD;
		op->mem.start_pfn = start_pfn;
		op->mem.nr_pages = nr_pages;
		op->mem.numa_node = nid;
		op->mem.phys_addr = phys_addr;

		mutex_lock(&mk_hotplug_mutex);
		list_add_tail(&op->list, &mk_hotplug_ops);
		mutex_unlock(&mk_hotplug_mutex);
	}

	pr_info("Multikernel hotplug: Successfully added and onlined memory at 0x%llx\n",
		phys_addr);
	return 0;
}

static int mk_do_mem_remove(u64 start_pfn, u64 nr_pages)
{
	struct mk_mem_piece piece[3];
	struct page *page;
	int ret, i, n, nid;
	u64 phys_addr;
	u64 size;
	struct mk_hotplug_op *op;

	phys_addr = PFN_PHYS(start_pfn);
	size = PFN_PHYS(nr_pages);

	pr_info("Multikernel hotplug: Removing memory 0x%llx-0x%llx (%llu MB)\n",
		phys_addr, phys_addr + size - 1, size >> 20);

	if (!IS_ALIGNED(phys_addr | size, MHP_SUBSECTIONS_ALIGN)) {
		pr_err("Multikernel hotplug: Memory 0x%llx+0x%llx not aligned to 0x%lx\n",
		       phys_addr, size, MHP_SUBSECTIONS_ALIGN);
		return -EINVAL;
	}

	page = pfn_to_online_page(start_pfn);
	if (!page)
		return -EINVAL;
	nid = page_to_nid(page);

	n = mk_mem_pieces(phys_addr, size, piece);
	for (i = 0; i < n; i++) {
		ret = mk_mem_piece_remove(&piece[i]);
		if (ret < 0) {
			pr_err("Multikernel hotplug: Failed to remove memory at 0x%llx: %d\n",
			       piece[i].start, ret);
			while (i--)
				mk_mem_piece_add(nid, &piece[i]);
			return ret;
		}
	}

	/* Track the operation for potential rollback */
	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (op) {
		op->type = MK_HOTPLUG_MEM_REMOVE;
		op->mem.start_pfn = start_pfn;
		op->mem.nr_pages = nr_pages;
		op->mem.numa_node = 0;
		op->mem.phys_addr = phys_addr;

		mutex_lock(&mk_hotplug_mutex);
		list_add_tail(&op->list, &mk_hotplug_ops);
		mutex_unlock(&mk_hotplug_mutex);
	}

	pr_info("Multikernel hotplug: Successfully removed memory at 0x%llx\n", phys_addr);
	return 0;
}

struct mk_mem_hotplug_work {
	struct work_struct work;
	u64 msg_id;
	u64 start_pfn;
	u64 nr_pages;
	u32 numa_node;
	u32 mem_type;
	int sender_instance_id;
	u32 operation;
};

static void mk_mem_add_work_fn(struct work_struct *work)
{
	struct mk_mem_hotplug_work *hp_work = container_of(work, struct mk_mem_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = -EBUSY;
	if (mutex_trylock(&mk_overlay_mutex)) {
		ret = mk_do_mem_add(hp_work->start_pfn, hp_work->nr_pages,
				    hp_work->numa_node, hp_work->mem_type);
		mutex_unlock(&mk_overlay_mutex);
	}

	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = hp_work->start_pfn;

	ack_ret = mk_send_message_id(hp_work->sender_instance_id, MK_MSG_RESOURCE,
				     MK_RES_ACK, hp_work->msg_id, &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for mem add at 0x%llx: %d\n",
			(u64)hp_work->start_pfn, ack_ret);
	}

	kfree(hp_work);
	mk_hotplug_work_done();
}

static void mk_mem_remove_work_fn(struct work_struct *work)
{
	struct mk_mem_hotplug_work *hp_work = container_of(work, struct mk_mem_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = -EBUSY;
	if (mutex_trylock(&mk_overlay_mutex)) {
		ret = mk_do_mem_remove(hp_work->start_pfn, hp_work->nr_pages);
		mutex_unlock(&mk_overlay_mutex);
	}

	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = hp_work->start_pfn;

	ack_ret = mk_send_message_id(hp_work->sender_instance_id, MK_MSG_RESOURCE,
				     MK_RES_ACK, hp_work->msg_id, &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for mem remove at 0x%llx: %d\n",
			(u64)hp_work->start_pfn, ack_ret);
	}

	kfree(hp_work);
	mk_hotplug_work_done();
}

static int mk_handle_mem_add(struct mk_mem_resource_payload *payload, u32 payload_len,
			       u64 msg_id)
{
	struct mk_mem_hotplug_work *hp_work;
	int ret;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid memory add payload size: %u\n", payload_len);
		return -EINVAL;
	}

	hp_work = kmalloc(sizeof(*hp_work), GFP_ATOMIC);
	if (!hp_work) {
		pr_err("Multikernel hotplug: Failed to allocate work for mem add at 0x%llx\n",
		       (u64)payload->start_pfn);
		return -ENOMEM;
	}

	INIT_WORK(&hp_work->work, mk_mem_add_work_fn);
	hp_work->msg_id = msg_id;
	hp_work->start_pfn = payload->start_pfn;
	hp_work->nr_pages = payload->nr_pages;
	hp_work->numa_node = payload->numa_node;
	hp_work->mem_type = payload->mem_type;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_MEM_ADD;
	ret = mk_queue_hotplug_work(&hp_work->work, false);
	if (ret) {
		kfree(hp_work);
		return ret;
	}

	return 0;
}

static int mk_handle_mem_remove(struct mk_mem_resource_payload *payload, u32 payload_len,
			       u64 msg_id)
{
	struct mk_mem_hotplug_work *hp_work;
	int ret;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid memory remove payload size: %u\n", payload_len);
		return -EINVAL;
	}

	hp_work = kmalloc(sizeof(*hp_work), GFP_ATOMIC);
	if (!hp_work) {
		pr_err("Multikernel hotplug: Failed to allocate work for mem remove at 0x%llx\n",
		       (u64)payload->start_pfn);
		return -ENOMEM;
	}

	INIT_WORK(&hp_work->work, mk_mem_remove_work_fn);
	hp_work->msg_id = msg_id;
	hp_work->start_pfn = payload->start_pfn;
	hp_work->nr_pages = payload->nr_pages;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_MEM_REMOVE;
	ret = mk_queue_hotplug_work(&hp_work->work, false);
	if (ret) {
		kfree(hp_work);
		return ret;
	}

	return 0;
}

/*
 * PCI Device Hotplug Operations
 */

static int mk_do_device_add(u16 domain, u8 bus, u8 devfn,
			    const char *driver_override, u32 flags)
{
	struct pci_dev *pdev;
	struct pci_bus *pci_bus;
	struct device_driver *drv;
	struct mk_hotplug_op *op;
	char prev_driver[64] = {0};
	int ret;

	pr_info("Multikernel hotplug: Adding device %04x:%02x:%02x.%x driver=%s flags=0x%x\n",
		domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
		driver_override ? driver_override : "none", flags);

	pci_bus = pci_find_bus(domain, bus);
	if (!pci_bus) {
		pr_err("Multikernel hotplug: PCI bus %04x:%02x not found\n", domain, bus);
		return -ENODEV;
	}

	pdev = pci_get_slot(pci_bus, devfn);
	if (!pdev) {
		pr_err("Multikernel hotplug: PCI device %04x:%02x:%02x.%x not found\n",
		       domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
		return -ENODEV;
	}

	/*
	 * A device coming back from the pool arrives driverless: adding it
	 * has to bind the host driver, not unbind one. Only an explicit
	 * override displaces a driver the host is already using.
	 */
	if (driver_override && driver_override[0]) {
		if (pdev->dev.driver) {
			strscpy(prev_driver, pdev->dev.driver->name, sizeof(prev_driver));
			pr_info("Multikernel hotplug: Device currently bound to %s, unbinding\n",
				prev_driver);
			device_release_driver(&pdev->dev);
		}

		ret = driver_set_override(&pdev->dev, &pdev->driver_override,
					  driver_override, strlen(driver_override));
		if (ret < 0) {
			pr_err("Multikernel hotplug: Failed to set driver override to %s: %d\n",
			       driver_override, ret);
			pci_dev_put(pdev);
			return ret;
		}

		drv = driver_find(driver_override, &pci_bus_type);
		if (!drv) {
			pr_err("Multikernel hotplug: Driver %s not found\n", driver_override);
			pci_dev_put(pdev);
			return -ENOENT;
		}

		ret = device_driver_attach(drv, &pdev->dev);
		if (ret < 0) {
			pr_err("Multikernel hotplug: Failed to bind device to %s: %d\n",
			       driver_override, ret);
			pci_dev_put(pdev);
			return ret;
		}

		pr_info("Multikernel hotplug: Successfully bound device to %s\n", driver_override);
	} else if (pdev->dev.driver) {
		strscpy(prev_driver, pdev->dev.driver->name, sizeof(prev_driver));
		pr_info("Multikernel hotplug: Device already bound to %s\n", prev_driver);
	} else {
		/* An override left by an earlier move stops the default driver matching */
		if (pdev->driver_override) {
			ret = driver_set_override(&pdev->dev, &pdev->driver_override,
						  "", 0);
			if (ret < 0) {
				pr_err("Multikernel hotplug: Failed to clear driver override: %d\n",
				       ret);
				pci_dev_put(pdev);
				return ret;
			}
		}

		/*
		 * Bind as the bus would, so that user space holding drivers
		 * off with drivers_autoprobe can prepare the device first.
		 */
		device_initial_probe(&pdev->dev);

		if (pdev->dev.driver)
			pr_info("Multikernel hotplug: Bound device to %s\n",
				pdev->dev.driver->name);
		else
			pr_info("Multikernel hotplug: No driver bound to device %04x:%02x:%02x.%x\n",
				domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
	}

	pci_dev_put(pdev);

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (op) {
		op->type = MK_HOTPLUG_DEVICE_ADD;
		op->device.domain = domain;
		op->device.bus = bus;
		op->device.devfn = devfn;
		strscpy(op->device.prev_driver, prev_driver, sizeof(op->device.prev_driver));

		mutex_lock(&mk_hotplug_mutex);
		list_add_tail(&op->list, &mk_hotplug_ops);
		mutex_unlock(&mk_hotplug_mutex);
	}

	pr_info("Multikernel hotplug: Successfully configured device %04x:%02x:%02x.%x\n",
		domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

	return 0;
}

static int mk_do_device_remove(u16 domain, u8 bus, u8 devfn)
{
	struct pci_dev *pdev;
	struct pci_bus *pci_bus;
	struct mk_hotplug_op *op;
	char prev_driver[64] = {0};

	pr_info("Multikernel hotplug: Removing device %04x:%02x:%02x.%x\n",
		domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

	pci_bus = pci_find_bus(domain, bus);
	if (!pci_bus) {
		pr_err("Multikernel hotplug: PCI bus %04x:%02x not found\n", domain, bus);
		return -ENODEV;
	}

	pdev = pci_get_slot(pci_bus, devfn);
	if (!pdev) {
		pr_err("Multikernel hotplug: PCI device %04x:%02x:%02x.%x not found\n",
		       domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
		return -ENODEV;
	}

	if (pdev->dev.driver) {
		strscpy(prev_driver, pdev->dev.driver->name, sizeof(prev_driver));
		pr_info("Multikernel hotplug: Unbinding device from %s\n", prev_driver);
		device_release_driver(&pdev->dev);
	}

	pci_dev_put(pdev);

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (op) {
		op->type = MK_HOTPLUG_DEVICE_REMOVE;
		op->device.domain = domain;
		op->device.bus = bus;
		op->device.devfn = devfn;
		strscpy(op->device.prev_driver, prev_driver, sizeof(op->device.prev_driver));

		mutex_lock(&mk_hotplug_mutex);
		list_add_tail(&op->list, &mk_hotplug_ops);
		mutex_unlock(&mk_hotplug_mutex);
	}

	pr_info("Multikernel hotplug: Successfully removed device %04x:%02x:%02x.%x\n",
		domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));

	return 0;
}

struct mk_device_hotplug_work {
	struct work_struct work;
	u64 msg_id;
	u16 domain;
	u8 bus;
	u8 devfn;
	u32 flags;
	char driver_override[64];
	int sender_instance_id;
	u32 operation;
	u16 vendor;
	u16 device;
	struct mk_pci_bus_desc bus_desc;
};

static void mk_device_add_work_fn(struct work_struct *work)
{
	struct mk_device_hotplug_work *hp_work = container_of(work, struct mk_device_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = -EBUSY;
	if (mutex_trylock(&mk_overlay_mutex)) {
		ret = 0;
		if (mk_manifest_phys())
			ret = mk_pcifront_add_function(hp_work->domain, hp_work->bus,
						       hp_work->devfn, hp_work->vendor,
						       hp_work->device, &hp_work->bus_desc);
		if (!ret)
			ret = mk_do_device_add(hp_work->domain, hp_work->bus,
					       hp_work->devfn, hp_work->driver_override,
					       hp_work->flags);
		mutex_unlock(&mk_overlay_mutex);
	}

	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = ((u32)hp_work->domain << 16) | (hp_work->bus << 8) | hp_work->devfn;

	ack_ret = mk_send_message_id(hp_work->sender_instance_id, MK_MSG_RESOURCE,
				     MK_RES_ACK, hp_work->msg_id, &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for device %04x:%02x:%02x.%x: %d\n",
			hp_work->domain, hp_work->bus,
			PCI_SLOT(hp_work->devfn), PCI_FUNC(hp_work->devfn), ack_ret);
	}

	kfree(hp_work);
	mk_hotplug_work_done();
}

static void mk_device_remove_work_fn(struct work_struct *work)
{
	struct mk_device_hotplug_work *hp_work = container_of(work, struct mk_device_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = -EBUSY;
	if (mutex_trylock(&mk_overlay_mutex)) {
		ret = mk_do_device_remove(hp_work->domain, hp_work->bus, hp_work->devfn);
		mutex_unlock(&mk_overlay_mutex);
	}

	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = ((u32)hp_work->domain << 16) | (hp_work->bus << 8) | hp_work->devfn;

	ack_ret = mk_send_message_id(hp_work->sender_instance_id, MK_MSG_RESOURCE,
				     MK_RES_ACK, hp_work->msg_id, &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for device %04x:%02x:%02x.%x: %d\n",
			hp_work->domain, hp_work->bus,
			PCI_SLOT(hp_work->devfn), PCI_FUNC(hp_work->devfn), ack_ret);
	}

	kfree(hp_work);
	mk_hotplug_work_done();
}

static int mk_handle_device_add(struct mk_device_resource_payload *payload, u32 payload_len,
			       u64 msg_id)
{
	struct mk_device_hotplug_work *hp_work;
	int ret;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid device add payload size: %u\n", payload_len);
		return -EINVAL;
	}

	hp_work = kmalloc(sizeof(*hp_work), GFP_ATOMIC);
	if (!hp_work) {
		pr_err("Multikernel hotplug: Failed to allocate work structure for device %04x:%02x:%02x.%x\n",
		       payload->domain, payload->bus,
		       PCI_SLOT(payload->devfn), PCI_FUNC(payload->devfn));
		return -ENOMEM;
	}

	INIT_WORK(&hp_work->work, mk_device_add_work_fn);
	hp_work->msg_id = msg_id;
	hp_work->domain = payload->domain;
	hp_work->bus = payload->bus;
	hp_work->devfn = payload->devfn;
	hp_work->flags = payload->flags;
	strscpy(hp_work->driver_override, payload->driver_override, sizeof(hp_work->driver_override));
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_DEVICE_ADD;
	hp_work->vendor = payload->vendor;
	hp_work->device = payload->device;
	hp_work->bus_desc = payload->bus_desc;
	ret = mk_queue_hotplug_work(&hp_work->work, false);
	if (ret) {
		kfree(hp_work);
		return ret;
	}

	return 0;
}

static int mk_handle_device_remove(struct mk_device_resource_payload *payload, u32 payload_len,
			       u64 msg_id)
{
	struct mk_device_hotplug_work *hp_work;
	int ret;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid device remove payload size: %u\n", payload_len);
		return -EINVAL;
	}

	hp_work = kmalloc(sizeof(*hp_work), GFP_ATOMIC);
	if (!hp_work) {
		pr_err("Multikernel hotplug: Failed to allocate work structure for device %04x:%02x:%02x.%x\n",
		       payload->domain, payload->bus,
		       PCI_SLOT(payload->devfn), PCI_FUNC(payload->devfn));
		return -ENOMEM;
	}

	INIT_WORK(&hp_work->work, mk_device_remove_work_fn);
	hp_work->msg_id = msg_id;
	hp_work->domain = payload->domain;
	hp_work->bus = payload->bus;
	hp_work->devfn = payload->devfn;
	hp_work->flags = payload->flags;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_DEVICE_REMOVE;
	ret = mk_queue_hotplug_work(&hp_work->work, false);
	if (ret) {
		kfree(hp_work);
		return ret;
	}

	return 0;
}

/*
 * Message Handler - Dispatches to specific handlers based on subtype
 */

/**
 * mk_resource_msg_handler - Handle resource management messages
 * @msg_type: Message type (should be MK_MSG_RESOURCE)
 * @subtype: Message subtype (CPU_ADD, CPU_REMOVE, MEM_ADD, MEM_REMOVE, DEVICE_ADD, DEVICE_REMOVE)
 * @msg_id: Request ID carried through deferred work and replies
 * @payload: Payload data
 * @payload_len: Payload length
 * @ctx: Context (unused)
 *
 * This is the main message handler registered with the multikernel
 * messaging system. It dispatches to specific handlers based on the
 * message subtype.
 */
static void mk_resource_msg_handler(u32 msg_type, u32 subtype, u64 msg_id,
				    void *payload, u32 payload_len, void *ctx)
{
	union {
		struct mk_cpu_resource_payload cpu;
		struct mk_mem_resource_payload mem;
		struct mk_device_resource_payload device;
		struct mk_resource_ack ack;
	} decoded;
	int ret = 0;

	if (msg_type != MK_MSG_RESOURCE) {
		pr_warn("Multikernel hotplug: Unexpected message type: 0x%x\n", msg_type);
		return;
	}

	/* Wire payloads need not be aligned for their typed fields. */
	if (payload_len) {
		memcpy(&decoded, payload, min_t(size_t, payload_len, sizeof(decoded)));
		payload = &decoded;
	}

	switch (subtype) {
	case MK_RES_CPU_ADD:
		ret = mk_handle_cpu_add(payload, payload_len, msg_id);
		break;

	case MK_RES_CPU_REMOVE:
		ret = mk_handle_cpu_remove(payload, payload_len, msg_id);
		break;

	case MK_RES_MEM_ADD:
		ret = mk_handle_mem_add(payload, payload_len, msg_id);
		break;

	case MK_RES_MEM_REMOVE:
		ret = mk_handle_mem_remove(payload, payload_len, msg_id);
		break;

	case MK_RES_DEVICE_ADD:
		ret = mk_handle_device_add(payload, payload_len, msg_id);
		break;

	case MK_RES_DEVICE_REMOVE:
		ret = mk_handle_device_remove(payload, payload_len, msg_id);
		break;

	case MK_RES_ACK:
		if (payload_len >= sizeof(struct mk_resource_ack)) {
			struct mk_resource_ack *ack = (struct mk_resource_ack *)payload;

			pr_info("Multikernel hotplug: ACK op=0x%x resource=%llu result=%d\n",
				ack->operation, ack->resource_id, (int)ack->result);
			mk_msg_pending_complete(MK_MSG_RESOURCE, ack->operation,
						ack->resource_id, msg_id, ack->result);
		} else {
			pr_warn("Multikernel hotplug: Invalid ACK payload size: %u\n", payload_len);
		}
		ret = 0;
		break;

	default:
		pr_warn("Multikernel hotplug: Unknown resource subtype: 0x%x\n", subtype);
		ret = -EINVAL;
		break;
	}

	if (ret < 0) {
		pr_err("Multikernel hotplug: Handler failed with error: %d\n", ret);
	}
}

/*
 * Initialization and Cleanup
 */

/**
 * mk_hotplug_init - Initialize multikernel hotplug subsystem
 *
 * Registers message handlers for resource management operations.
 * This should be called during multikernel initialization.
 *
 * Returns 0 on success, negative error code on failure
 */
int __init mk_hotplug_init(void)
{
	struct workqueue_struct *wq;
	unsigned long flags;
	int ret;

	pr_info("Initializing multikernel hotplug subsystem\n");

	wq = alloc_ordered_workqueue("mk_cpu_hotplug", WQ_MEM_RECLAIM);
	if (!wq)
		return -ENOMEM;

	raw_spin_lock_irqsave(&mk_cpu_hotplug_lock, flags);
	mk_cpu_hotplug_wq = wq;
	mk_hotplug_accepting = true;
	raw_spin_unlock_irqrestore(&mk_cpu_hotplug_lock, flags);

	/* Register handler for resource management messages */
	ret = mk_register_msg_handler(MK_MSG_RESOURCE, mk_resource_msg_handler, NULL);
	if (ret < 0) {
		pr_err("Failed to register multikernel hotplug message handler: %d\n", ret);
		mk_hotplug_quiesce();
		destroy_workqueue(mk_cpu_hotplug_detach());
		return ret;
	}

	pr_info("Multikernel hotplug subsystem initialized\n");
	return 0;
}

/**
 * mk_hotplug_cleanup - Cleanup multikernel hotplug subsystem
 *
 * Unregisters message handlers and frees tracking structures.
 */
void mk_hotplug_cleanup(void)
{
	struct workqueue_struct *wq;
	struct mk_hotplug_op *op, *tmp;

	pr_info("Cleaning up multikernel hotplug subsystem\n");

	/* Close all resource admission and finish workers before freeing tracking. */
	mk_hotplug_quiesce();
	wq = mk_cpu_hotplug_detach();

	/* Unregister message handler */
	mk_unregister_msg_handler(MK_MSG_RESOURCE, mk_resource_msg_handler);

	if (wq)
		destroy_workqueue(wq);

	/* Free operation tracking list */
	mutex_lock(&mk_hotplug_mutex);
	list_for_each_entry_safe(op, tmp, &mk_hotplug_ops, list) {
		list_del(&op->list);
		kfree(op);
	}
	mutex_unlock(&mk_hotplug_mutex);

	pr_info("Multikernel hotplug subsystem cleaned up\n");
}

/**
 * mk_pool_cpu_add - Move a CPU of this kernel into its assignable pool
 * @cpu_id: Physical CPU ID
 *
 * Only meaningful in a kernel that manages a pool (mk_pool non-NULL).
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_pool_cpu_add(mk_phys_cpu_t cpu_id)
{
	int logical_cpu;
	int ret;

	/*
	 * An offline CPU never reaches the park loop, so the pool would
	 * record a CPU nothing can ever wake.
	 */
	logical_cpu = mk_cpu_to_logical(cpu_id);
	if (logical_cpu < 0 || !cpu_online(logical_cpu)) {
		pr_err("Multikernel hotplug: CPU %llu must be online to join the pool\n",
		       cpu_id);
		return -EINVAL;
	}

	/*
	 * The pool set is the record of which CPUs are parked, so the add
	 * below must not be able to fail: grow it while the CPU is still
	 * ours to keep.
	 */
	{
		guard(mutex)(&mk_pool->cpus_lock);
		ret = mk_cpu_set_reserve(mk_pool->cpus, 1);
	}
	if (ret)
		return ret;

	ret = mk_do_cpu_remove(cpu_id);
	if (ret)
		return ret;

	/* The CPU parked in the pool park area and is assignable again */
	{
		guard(mutex)(&mk_pool->cpus_lock);
		mk_cpu_set_add(mk_pool->cpus, cpu_id);
	}

	return 0;
}

/**
 * mk_pool_cpu_remove - Take a free pool CPU back into this kernel
 * @cpu_id: Physical CPU ID
 * @numa_node: NUMA node to online the CPU on
 * @flags: Additional flags
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_pool_cpu_remove(mk_phys_cpu_t cpu_id, u32 numa_node, u32 flags)
{
	int ret;

	if (!mk_cpu_set_contains(mk_pool->cpus, cpu_id)) {
		pr_err("Multikernel hotplug: CPU %llu is not free in the pool\n",
		       cpu_id);
		return -EBUSY;
	}

	ret = mk_do_cpu_add(cpu_id, numa_node, flags);
	if (ret)
		return ret;

	/* From here on it is an ordinary CPU of this kernel */
	{
		guard(mutex)(&mk_pool->cpus_lock);
		mk_cpu_set_del(mk_pool->cpus, cpu_id);
	}

	return 0;
}

/**
 * mk_pool_device_add - Move a PCI device of this kernel into its pool
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 * @alias: Stable name for the device tree /aliases node, NULL for none
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_pool_device_add(u16 domain, u8 bus, u8 devfn, const char *alias)
{
	int ret;

	ret = mk_do_device_remove(domain, bus, devfn);
	if (ret)
		return ret;

	ret = mk_root_add_pci_device(domain, bus, devfn, alias);
	if (ret && ret != -EEXIST) {
		/* Untracked, the device would belong to neither side */
		pr_err("Multikernel hotplug: device %04x:%02x:%02x.%x not tracked in pool: %d\n",
		       domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), ret);
		if (mk_do_device_add(domain, bus, devfn, NULL, 0))
			pr_err("Multikernel hotplug: device %04x:%02x:%02x.%x could not be rebound to this kernel\n",
			       domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
		return ret;
	}

	return 0;
}

/**
 * mk_pool_device_remove - Take a free pool PCI device back into this kernel
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 * @driver_override: Target driver name for binding (can be NULL)
 * @flags: Additional flags
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_pool_device_remove(u16 domain, u8 bus, u8 devfn,
			  const char *driver_override, u32 flags)
{
	int ret;

	if (!mk_root_has_pci_device(domain, bus, devfn)) {
		pr_err("Multikernel hotplug: device %04x:%02x:%02x.%x is not free in the pool\n",
		       domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
		return -EBUSY;
	}

	ret = mk_do_device_add(domain, bus, devfn, driver_override, flags);
	if (ret)
		return ret;

	ret = mk_root_del_pci_device(domain, bus, devfn);
	if (ret)
		pr_warn("Multikernel hotplug: device %04x:%02x:%02x.%x not dropped from pool: %d\n",
			domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), ret);

	return 0;
}

/**
 * mk_send_cpu_remove - Remove CPU from instance and wait for completion
 * @instance_id: Target instance ID
 * @cpu_id: Physical CPU ID to remove
 *
 * For local instance, executes removal synchronously and returns after completion.
 * For remote instance, sends IPI and waits for ACK response.
 * For instances that are not yet running (MK_STATE_READY/LOADED), transfers
 * the CPU back to this kernel without sending IPIs.
 *
 * Returns: 0 on success, negative error code on failure or timeout
 */
int mk_send_cpu_remove(int instance_id, mk_phys_cpu_t cpu_id)
{
	struct mk_cpu_resource_payload payload = {
		.cpu_id = cpu_id,
		.numa_node = 0,
		.flags = 0,
		.sender_instance_id = mk_self->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;

	/* For self-removal, execute directly (we're in process context) */
	if (instance_id == mk_self->id) {
		if (mk_pool)
			return mk_pool_cpu_add(cpu_id);
		return mk_do_cpu_remove(cpu_id);
	}

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;

	/* For non-running instances, return CPU to root using existing API */
	if (target_instance->state == MK_STATE_FAILED) {
		ret = -EBUSY;
		goto out;
	}
	if (target_instance->state != MK_STATE_ACTIVE) {
		struct mk_cpu_set cpus = { .nr = 1, .cap = 1, .ids = &cpu_id };

		/*
		 * A CPU the instance has already run on is parked on that
		 * instance's context. Bring it back to the host slot before
		 * handing it to the pool, or a later spawn would try to wake
		 * it through a context it no longer watches. No-op for a CPU
		 * that never left the host slot; on failure the CPU stays
		 * with the instance rather than entering the pool unreachable.
		 */
		ret = mk_repark_cpu_to_host(target_instance, cpu_id);
		if (ret < 0) {
			pr_err("Multikernel hotplug: CPU %llu not reparked to host: %d\n",
			       cpu_id, ret);
			goto out;
		}

		ret = mk_instance_return_cpus(target_instance, &cpus);
		goto out;
	}

	/* The pool set must be able to take the CPU once it parks */
	if (!mk_pool) {
		ret = -ENODEV;
		goto out;
	}

	{
		guard(mutex)(&mk_pool->cpus_lock);
		ret = mk_cpu_set_reserve(mk_pool->cpus, 1);
	}
	if (ret)
		goto out;

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_REMOVE, cpu_id);
	if (IS_ERR(pending)) {
		ret = PTR_ERR(pending);
		goto out;
	}

	ret = mk_send_message_id(instance_id, MK_MSG_RESOURCE, MK_RES_CPU_REMOVE,
				 mk_msg_pending_id(pending), &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_cancel(pending);
		goto out;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto out;

	/*
	 * The spawn kernel parked the CPU on its own context when it went
	 * offline. Bring it back to the host slot so it can be spawned or
	 * hot-added elsewhere. If the CPU never claims the repark it still
	 * watches the instance's context, so it must stay accounted to the
	 * instance; released to the pool, a later spawn would target a CPU
	 * that cannot hear the host slot.
	 */
	ret = mk_repark_cpu_to_host(target_instance, cpu_id);
	if (ret < 0) {
		pr_err("Multikernel hotplug: CPU %llu offline in instance %d but not reparked to host: %d\n",
		       cpu_id, instance_id, ret);
		goto out;
	}

	mk_cpu_set_del(target_instance->cpus, cpu_id);
	{
		guard(mutex)(&mk_pool->cpus_lock);
		mk_cpu_set_add(mk_pool->cpus, cpu_id);
	}
	mk_instance_ipi_retarget(target_instance);

	ret = 0;
out:
	mk_instance_put(target_instance);
	return ret;
}

/**
 * mk_send_cpu_add - Add CPU to instance and wait for completion
 * @instance_id: Target instance ID
 * @cpu_id: Physical CPU ID to add
 * @numa_node: NUMA node for the CPU
 * @flags: Additional flags
 *
 * For local instance, executes addition synchronously and returns after completion.
 * For remote instance, sends IPI and waits for ACK response.
 * For instances that are not yet running (MK_STATE_READY/LOADED), transfers
 * the CPU from this kernel without sending IPIs.
 *
 * Returns: 0 on success, negative error code on failure or timeout
 */
int mk_send_cpu_add(int instance_id, mk_phys_cpu_t cpu_id, u32 numa_node, u32 flags)
{
	struct mk_cpu_set cpus = { .nr = 1, .cap = 1, .ids = &cpu_id };
	struct mk_cpu_resource_payload payload = {
		.cpu_id = cpu_id,
		.numa_node = numa_node,
		.flags = flags,
		.sender_instance_id = mk_self->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;

	/* For self-addition, execute directly (we're in process context) */
	if (instance_id == mk_self->id) {
		if (mk_pool)
			return mk_pool_cpu_remove(cpu_id, numa_node, flags);
		return mk_do_cpu_add(cpu_id, numa_node, flags);
	}

	target_instance = mk_instance_find(instance_id);
	if (!target_instance) {
		pr_err("Multikernel hotplug: instance %d not found for CPU add\n",
		       instance_id);
		return -ENODEV;
	}

	/* For non-running instances, transfer CPU from root using existing API */
	if (target_instance->state == MK_STATE_FAILED) {
		ret = -EBUSY;
		goto out;
	}
	if (target_instance->state != MK_STATE_ACTIVE) {
		ret = mk_instance_transfer_cpus(target_instance, &cpus);
		goto out;
	}

	/*
	 * Only a CPU from the assignable pool is parked on the host slot;
	 * publishing a wakeup for any other CPU can only time out.
	 */
	if (!mk_pool || !mk_cpu_set_contains(mk_pool->cpus, cpu_id)) {
		pr_err("Multikernel hotplug: CPU %llu is not in this kernel's pool\n",
		       cpu_id);
		ret = -EBUSY;
		goto out;
	}

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_ADD, cpu_id);
	if (IS_ERR(pending)) {
		ret = PTR_ERR(pending);
		goto out;
	}

	/*
	 * Reserve ownership before any handoff. Once a wakeup is published,
	 * an error or timeout cannot prove the CPU did not consume it. Keep
	 * the CPU assigned to the target, even on failure, until a separate
	 * quiesced removal can safely return it to the pool.
	 */
	ret = mk_instance_transfer_cpus(target_instance, &cpus);
	if (ret) {
		mk_msg_pending_cancel(pending);
		goto out;
	}

	/*
	 * The CPU is parked on the host slot, where the spawn kernel's
	 * secondary wakeup cannot reach it. Point it at the instance's
	 * context before asking the instance to online it.
	 */
	ret = mk_repark_cpu_to_instance(target_instance, cpu_id);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to repark CPU %llu to instance %d: %d\n",
		       cpu_id, instance_id, ret);
		mk_msg_pending_cancel(pending);
		goto out;
	}

	ret = mk_send_message_id(instance_id, MK_MSG_RESOURCE, MK_RES_CPU_ADD,
				 mk_msg_pending_id(pending), &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_cancel(pending);
		goto out;
	}

	/* A timed-out waiter does not cancel the remote CPU-start work. */
	ret = mk_msg_pending_wait(pending, 10000);
out:
	mk_instance_put(target_instance);
	return ret;
}

/**
 * mk_send_mem_add - Add memory to instance
 * @instance_id: Target instance ID
 * @start_pfn: Starting page frame number
 * @nr_pages: Number of pages
 * @numa_node: NUMA node ID
 * @mem_type: Memory type
 *
 * For local instance, executes addition synchronously.
 * For remote instance, sends IPI and waits for ACK response.
 * The range is taken from the pool for the instance first, so that it
 * must be free pool memory and no other instance can be given it; for
 * instances that are not yet running (MK_STATE_READY/LOADED), that is all.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_send_mem_add(int instance_id, u64 start_pfn, u64 nr_pages,
		    u32 numa_node, u32 mem_type)
{
	struct mk_mem_resource_payload payload = {
		.start_pfn = start_pfn,
		.nr_pages = nr_pages,
		.numa_node = numa_node,
		.mem_type = mem_type,
		.sender_instance_id = mk_self->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;

	/* For self-addition, execute directly (we're in process context) */
	if (instance_id == mk_self->id)
		return mk_do_mem_add(start_pfn, nr_pages, numa_node, mem_type);

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;

	if (target_instance->state == MK_STATE_FAILED) {
		ret = -EBUSY;
		goto out;
	}
	/* Reserve the exact range before the running kernel can take it. */
	ret = mk_instance_add_memory_region(target_instance, PFN_PHYS(start_pfn),
					    PFN_PHYS(nr_pages));
	if (ret || target_instance->state != MK_STATE_ACTIVE)
		goto out;

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_MEM_ADD, start_pfn);
	if (IS_ERR(pending)) {
		ret = PTR_ERR(pending);
		goto remove;
	}

	ret = mk_send_message_id(instance_id, MK_MSG_RESOURCE, MK_RES_MEM_ADD,
				 mk_msg_pending_id(pending), &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_cancel(pending);
		goto remove;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	/* Without an answer the kernel may still add it, so it stays its own */
	if (!ret || ret == -ETIMEDOUT)
		goto out;
remove:
	mk_instance_remove_memory_region(target_instance, PFN_PHYS(start_pfn),
					 PFN_PHYS(nr_pages));
out:
	mk_instance_put(target_instance);
	return ret;
}

/**
 * mk_send_mem_remove - Remove memory from instance
 * @instance_id: Target instance ID
 * @start_pfn: Starting page frame number
 * @nr_pages: Number of pages
 *
 * For local instance, executes removal synchronously.
 * For remote instance, sends IPI and waits for ACK response.
 * For instances that are not yet running (MK_STATE_READY/LOADED), removes
 * the memory region from instance's memory_regions list.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_send_mem_remove(int instance_id, u64 start_pfn, u64 nr_pages)
{
	struct mk_mem_resource_payload payload = {
		.start_pfn = start_pfn,
		.nr_pages = nr_pages,
		.numa_node = 0,
		.mem_type = 0,
		.sender_instance_id = mk_self->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;

	/* For self-removal, execute directly (we're in process context) */
	if (instance_id == mk_self->id)
		return mk_do_mem_remove(start_pfn, nr_pages);

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;

	/* For non-running instances, just remove the memory region from the instance */
	if (target_instance->state == MK_STATE_FAILED) {
		ret = -EBUSY;
		goto out;
	}
	if (target_instance->state != MK_STATE_ACTIVE) {
		phys_addr_t phys_addr;
		size_t size;

		phys_addr = PFN_PHYS(start_pfn);
		size = PFN_PHYS(nr_pages);
		ret = mk_instance_remove_memory_region(target_instance, phys_addr, size);
		goto out;
	}

	/* Before the running kernel gives the memory up, not after */
	ret = mk_instance_begin_memory_removal(target_instance, PFN_PHYS(start_pfn),
					       PFN_PHYS(nr_pages));
	if (ret)
		goto out;

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_MEM_REMOVE, start_pfn);
	if (IS_ERR(pending)) {
		ret = PTR_ERR(pending);
		goto abort;
	}

	ret = mk_send_message_id(instance_id, MK_MSG_RESOURCE, MK_RES_MEM_REMOVE,
				 mk_msg_pending_id(pending), &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_cancel(pending);
		goto abort;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto abort;

	mk_instance_finish_memory_removal(target_instance, PFN_PHYS(start_pfn),
					  PFN_PHYS(nr_pages));
	goto out;
abort:
	mk_instance_abort_memory_removal(target_instance, PFN_PHYS(start_pfn),
					 PFN_PHYS(nr_pages));
out:
	mk_instance_put(target_instance);
	return ret;
}

/**
 * mk_send_device_add - Add PCI device to instance and wait for completion
 * @instance_id: Target instance ID
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 * @driver_override: Target driver name for binding (can be NULL)
 * @flags: Additional flags
 *
 * For local instance, executes addition synchronously.
 * For remote instance, sends IPI and waits for ACK response.
 * For instances that are not yet running (MK_STATE_READY/LOADED),
 * adds device to instance's device list.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_send_device_add(int instance_id, u16 domain, u8 bus, u8 devfn,
		       const char *driver_override, u32 flags)
{
	struct mk_device_resource_payload payload = {
		.domain = domain,
		.bus = bus,
		.devfn = devfn,
		.flags = flags,
		.sender_instance_id = mk_self->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	struct pci_dev *pdev;
	int ret;
	u32 resource_id;

	if (driver_override)
		strscpy(payload.driver_override, driver_override, sizeof(payload.driver_override));
	else
		payload.driver_override[0] = '\0';

	resource_id = ((u32)domain << 16) | (bus << 8) | devfn;

	if (instance_id == mk_self->id) {
		if (mk_pool)
			return mk_pool_device_remove(domain, bus, devfn,
						     driver_override, flags);
		if (mk_manifest_phys()) {
			ret = mk_pcifront_adopt_function(domain, bus, devfn);
			if (ret)
				return ret;
		}
		return mk_do_device_add(domain, bus, devfn, driver_override, flags);
	}

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;

	if (target_instance->state == MK_STATE_FAILED) {
		ret = -EBUSY;
		goto out;
	}
	if (target_instance->state != MK_STATE_ACTIVE) {
		ret = mk_instance_add_pci_device(target_instance, domain, bus, devfn);
		goto out;
	}

	/* The instance probes the function as soon as it hears of it */
	ret = mk_pciback_lend_one(target_instance, domain, bus, devfn);
	if (ret)
		goto out;

	/* It may not have the function in its tree, nor even its bus */
	pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
	if (!pdev) {
		ret = -ENODEV;
		goto unlend;
	}
	payload.vendor = pdev->vendor;
	payload.device = pdev->device;
	mk_pci_bus_describe(pdev->bus, &payload.bus_desc);
	pci_dev_put(pdev);

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_DEVICE_ADD, resource_id);
	if (IS_ERR(pending)) {
		ret = PTR_ERR(pending);
		goto unlend;
	}

	ret = mk_send_message_id(instance_id, MK_MSG_RESOURCE, MK_RES_DEVICE_ADD,
				 mk_msg_pending_id(pending), &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_cancel(pending);
		goto unlend;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto unlend;

	ret = mk_instance_add_pci_device(target_instance, domain, bus, devfn);
	if (ret < 0) {
		pr_warn("Device added to target but failed to update tracking: %d\n", ret);
	}

	pr_info("Multikernel hotplug: Device %04x:%02x:%02x.%x successfully added to instance %d\n",
		domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), instance_id);

	mk_instance_put(target_instance);
	return 0;

unlend:
	mk_pciback_unlend_one(target_instance, domain, bus, devfn);
out:
	mk_instance_put(target_instance);
	return ret;
}

/**
 * mk_send_device_remove - Remove PCI device from instance and wait for completion
 * @instance_id: Target instance ID
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * For local instance, executes removal synchronously.
 * For remote instance, sends IPI and waits for ACK response.
 * For instances that are not yet running (MK_STATE_READY/LOADED),
 * removes device from instance's device list.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_send_device_remove(int instance_id, u16 domain, u8 bus, u8 devfn)
{
	struct mk_device_resource_payload payload = {
		.domain = domain,
		.bus = bus,
		.devfn = devfn,
		.flags = 0,
		.sender_instance_id = mk_self->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;
	u32 resource_id;

	payload.driver_override[0] = '\0';
	resource_id = ((u32)domain << 16) | (bus << 8) | devfn;

	if (instance_id == mk_self->id) {
		if (mk_pool)
			return mk_pool_device_add(domain, bus, devfn, NULL);
		return mk_do_device_remove(domain, bus, devfn);
	}

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;

	if (target_instance->state == MK_STATE_FAILED) {
		ret = -EBUSY;
		goto out;
	}
	if (target_instance->state != MK_STATE_ACTIVE) {
		ret = mk_instance_remove_pci_device(target_instance, domain, bus, devfn);
		goto out;
	}

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_DEVICE_REMOVE, resource_id);
	if (IS_ERR(pending)) {
		ret = PTR_ERR(pending);
		goto out;
	}

	ret = mk_send_message_id(instance_id, MK_MSG_RESOURCE, MK_RES_DEVICE_REMOVE,
				 mk_msg_pending_id(pending), &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_cancel(pending);
		goto out;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto out;

	mk_pciback_unlend_one(target_instance, domain, bus, devfn);

	ret = mk_instance_remove_pci_device(target_instance, domain, bus, devfn);
	if (ret < 0) {
		pr_warn("Device removed from target but failed to update tracking: %d\n", ret);
	}

	pr_info("Multikernel hotplug: Device %04x:%02x:%02x.%x successfully removed from instance %d\n",
		domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), instance_id);

	ret = 0;
out:
	mk_instance_put(target_instance);
	return ret;
}
