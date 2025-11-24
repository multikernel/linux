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
#include <asm/apic.h>
#include "internal.h"

/* Resource operation tracking for rollback support */
struct mk_hotplug_op {
	enum {
		MK_HOTPLUG_CPU_ADD,
		MK_HOTPLUG_CPU_REMOVE,
		MK_HOTPLUG_MEM_ADD,
		MK_HOTPLUG_MEM_REMOVE
	} type;

	union {
		struct {
			u32 cpu_id;        /* Physical CPU ID */
			u32 numa_node;
		} cpu;

		struct {
			u64 start_pfn;
			u64 nr_pages;
			u32 numa_node;
			u64 phys_addr;
		} mem;
	};

	struct list_head list;
};

static DEFINE_MUTEX(mk_hotplug_mutex);
static LIST_HEAD(mk_hotplug_ops);

/*
 * CPU Hotplug Operations
 */
struct mk_cpu_hotplug_work {
	struct work_struct work;
	u32 cpu_id;
	u32 numa_node;
	u32 flags;
	int sender_instance_id;  /* For sending ACK back */
	u32 operation;           /* MK_RES_CPU_ADD or MK_RES_CPU_REMOVE */
};

/**
 * Search present CPUs (not possible CPUs) to find the logical CPU with matching
 * physical ID. Using present CPUs is important because topology can change during
 * multikernel operations, and we only care about CPUs that are actually present.
 */
static int mk_cpu_to_logical(u32 cpu_id)
{
	int cpu;

	for_each_present_cpu(cpu) {
		if (arch_cpu_physical_id(cpu) == cpu_id)
			return cpu;
	}

	pr_err("Multikernel hotplug: Physical CPU %u not found in present CPUs\n",
	       cpu_id);
	return -EINVAL;
}

static int mk_do_cpu_add(u32 cpu_id, u32 numa_node, u32 flags)
{
	int logical_cpu;
	int ret;
	struct mk_hotplug_op *op;

	pr_info("Multikernel hotplug: Adding CPU %u (numa=%u, flags=0x%x)\n",
		cpu_id, numa_node, flags);

	logical_cpu = mk_cpu_to_logical(cpu_id);
	if (logical_cpu < 0) {
		pr_err("Multikernel hotplug: CPU %u not found in present CPUs\n", cpu_id);
		return -ENODEV;
	}

	if (cpu_online(logical_cpu)) {
		pr_warn("Multikernel hotplug: CPU %d (phys %u) already online\n",
			logical_cpu, cpu_id);
		if (root_instance->cpus)
			set_bit(cpu_id, root_instance->cpus);
		return 0;
	}

	if (!get_cpu_device(logical_cpu)) {
		struct cpu *c = &per_cpu(cpu_devices, logical_cpu);
		c->hotpluggable = true;
		ret = register_cpu(c, logical_cpu);
		if (ret) {
			pr_err("Multikernel hotplug: Failed to register CPU %d: %d\n",
			       logical_cpu, ret);
			return ret;
		}
	}

	ret = add_cpu(logical_cpu);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to add CPU %d (phys %u): %d\n",
		       logical_cpu, cpu_id, ret);
		return ret;
	}

	if (root_instance->cpus)
		set_bit(cpu_id, root_instance->cpus);

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

	pr_info("Multikernel hotplug: Successfully added CPU %d (phys %u)\n",
		logical_cpu, cpu_id);

	return 0;
}

static int mk_do_cpu_remove(u32 cpu_id)
{
	int logical_cpu;
	int ret;
	struct mk_hotplug_op *op;

	logical_cpu = mk_cpu_to_logical(cpu_id);
	if (logical_cpu < 0) {
		pr_err("Multikernel hotplug: Physical CPU %u not found\n", cpu_id);
		return -ENODEV;
	}

	if (!cpu_online(logical_cpu)) {
		pr_warn("Multikernel hotplug: CPU %d (phys %u) already offline\n",
			logical_cpu, cpu_id);
		if (root_instance->cpus)
			clear_bit(cpu_id, root_instance->cpus);
		return 0;
	}

	/* Don't allow removing CPU 0 (boot processor) */
	if (logical_cpu == 0) {
		pr_err("Multikernel hotplug: Cannot remove boot CPU\n");
		return -EINVAL;
	}

	ret = remove_cpu(logical_cpu);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to remove CPU %d (phys %u): %d\n",
		       logical_cpu, cpu_id, ret);
		return ret;
	}

	if (root_instance->cpus)
		clear_bit(cpu_id, root_instance->cpus);

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

	pr_info("Multikernel hotplug: Successfully removed CPU %d (phys %u)\n",
		logical_cpu, cpu_id);

	return 0;
}

static void mk_cpu_add_work_fn(struct work_struct *work)
{
	struct mk_cpu_hotplug_work *hp_work = container_of(work, struct mk_cpu_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = mk_do_cpu_add(hp_work->cpu_id, hp_work->numa_node, hp_work->flags);

	/* Send ACK back to sender */
	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = hp_work->cpu_id;
	ack.reserved = 0;

	ack_ret = mk_send_message(hp_work->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for CPU %u: %d\n",
			hp_work->cpu_id, ack_ret);
	}

	kfree(hp_work);
}

static void mk_cpu_remove_work_fn(struct work_struct *work)
{
	struct mk_cpu_hotplug_work *hp_work = container_of(work, struct mk_cpu_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = mk_do_cpu_remove(hp_work->cpu_id);

	/* Send ACK back to sender */
	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = hp_work->cpu_id;
	ack.reserved = 0;

	ack_ret = mk_send_message(hp_work->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for CPU %u: %d\n",
			hp_work->cpu_id, ack_ret);
	}

	kfree(hp_work);
}

/**
 * mk_handle_cpu_add - Handle CPU addition request
 * @payload: CPU resource payload
 * @payload_len: Payload length
 *
 * Brings a CPU online in the receiving kernel. This is called on the spawn
 * kernel side when the host kernel transfers a CPU to it.
 *
 * Returns 0 on success, negative error code on failure
 */
static int mk_handle_cpu_add(struct mk_cpu_resource_payload *payload, u32 payload_len)
{
	struct mk_cpu_hotplug_work *hp_work;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid CPU add payload size: %u\n", payload_len);
		return -EINVAL;
	}

	/*
	 * We're in IRQ context (IPI handler), so we can't call add_cpu() directly.
	 */
	hp_work = kmalloc(sizeof(*hp_work), GFP_ATOMIC);
	if (!hp_work) {
		pr_err("Multikernel hotplug: Failed to allocate work structure for CPU %u\n",
		       payload->cpu_id);
		return -ENOMEM;
	}

	INIT_WORK(&hp_work->work, mk_cpu_add_work_fn);
	hp_work->cpu_id = payload->cpu_id;
	hp_work->numa_node = payload->numa_node;
	hp_work->flags = payload->flags;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_CPU_ADD;
	schedule_work(&hp_work->work);

	return 0;
}

/**
 * mk_handle_cpu_remove - Handle CPU removal request
 * @payload: CPU resource payload
 * @payload_len: Payload length
 *
 * Takes a CPU offline in the current kernel. This is called on the host
 * kernel side before transferring a CPU to a spawn kernel.
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_handle_cpu_remove(struct mk_cpu_resource_payload *payload, u32 payload_len)
{
	struct mk_cpu_hotplug_work *hp_work;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid CPU remove payload size: %u\n", payload_len);
		return -EINVAL;
	}

	/*
	 * We're in IRQ context (IPI handler), so we can't call remove_cpu() directly.
	 */
	hp_work = kmalloc(sizeof(*hp_work), GFP_ATOMIC);
	if (!hp_work) {
		pr_err("Multikernel hotplug: Failed to allocate work structure for CPU %u\n",
		       payload->cpu_id);
		return -ENOMEM;
	}

	INIT_WORK(&hp_work->work, mk_cpu_remove_work_fn);
	hp_work->cpu_id = payload->cpu_id;
	hp_work->numa_node = payload->numa_node;
	hp_work->flags = payload->flags;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_CPU_REMOVE;
	schedule_work(&hp_work->work);

	return 0;
}

/*
 * Memory Hotplug Operations
 */

static int mk_do_mem_add(u64 start_pfn, u64 nr_pages, u32 numa_node, u32 mem_type)
{
	int ret;
	int nid;
	u64 phys_addr;
	u64 size;
	struct zone *zone = NULL;
	mhp_t mhp_flags = MHP_NONE;
	struct mk_hotplug_op *op;

	phys_addr = PFN_PHYS(start_pfn);
	size = PFN_PHYS(nr_pages);
	nid = numa_node;

	pr_info("Multikernel hotplug: Adding memory 0x%llx-0x%llx (%llu MB) numa=%u type=0x%x\n",
		phys_addr, phys_addr + size - 1, size >> 20,
		numa_node, mem_type);

	if (!IS_ALIGNED(phys_addr, memory_block_size_bytes())) {
		pr_err("Multikernel hotplug: Memory address 0x%llx not aligned to block size 0x%lx\n",
		       phys_addr, memory_block_size_bytes());
		return -EINVAL;
	}

	if (!IS_ALIGNED(size, memory_block_size_bytes())) {
		pr_err("Multikernel hotplug: Memory size 0x%llx not aligned to block size 0x%lx\n",
		       size, memory_block_size_bytes());
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

	ret = add_memory(nid, phys_addr, size, mhp_flags);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to add memory at 0x%llx: %d\n",
		       phys_addr, ret);
		return ret;
	}

	zone = zone_for_pfn_range(mhp_get_default_online_type(), nid,
				  NULL, start_pfn, nr_pages);
	if (!zone) {
		pr_warn("Multikernel hotplug: Could not determine zone, memory added but not onlined\n");
	} else {
		get_online_mems();
		mem_hotplug_begin();
		ret = online_pages(start_pfn, nr_pages, zone, NULL);
		mem_hotplug_done();
		put_online_mems();

		if (ret < 0) {
			pr_err("Multikernel hotplug: Failed to online memory at 0x%llx: %d\n",
			       phys_addr, ret);
			/* Memory is added but not online - not a fatal error */
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
	int ret;
	u64 phys_addr;
	u64 size;
	struct zone *zone;
	struct mk_hotplug_op *op;

	phys_addr = PFN_PHYS(start_pfn);
	size = PFN_PHYS(nr_pages);

	pr_info("Multikernel hotplug: Removing memory 0x%llx-0x%llx (%llu MB)\n",
		phys_addr, phys_addr + size - 1, size >> 20);

	if (!IS_ALIGNED(phys_addr, memory_block_size_bytes())) {
		pr_err("Multikernel hotplug: Memory address 0x%llx not aligned to block size 0x%lx\n",
		       phys_addr, memory_block_size_bytes());
		return -EINVAL;
	}

	if (!IS_ALIGNED(size, memory_block_size_bytes())) {
		pr_err("Multikernel hotplug: Memory size 0x%llx not aligned to block size 0x%lx\n",
		       size, memory_block_size_bytes());
		return -EINVAL;
	}

	/* Determine the zone for this memory range */
	zone = page_zone(pfn_to_page(start_pfn));

	get_online_mems();
	mem_hotplug_begin();
	ret = offline_pages(start_pfn, nr_pages, zone, NULL);
	mem_hotplug_done();
	put_online_mems();

	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to offline memory at 0x%llx: %d\n",
		       phys_addr, ret);
		pr_err("This usually means the memory is in use and cannot be migrated\n");
		return ret;
	}

	ret = remove_memory(phys_addr, size);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to remove memory at 0x%llx: %d\n",
		       phys_addr, ret);
		return ret;
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

static int mk_handle_mem_add(struct mk_mem_resource_payload *payload, u32 payload_len)
{
	struct mk_resource_ack ack;
	int ret, ack_ret;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid memory add payload size: %u\n", payload_len);
		return -EINVAL;
	}

	ret = mk_do_mem_add(payload->start_pfn, payload->nr_pages,
			    payload->numa_node, payload->mem_type);

	ack.operation = MK_RES_MEM_ADD;
	ack.result = ret;
	ack.resource_id = (u32)payload->start_pfn;
	ack.reserved = 0;
	ack_ret = mk_send_message(payload->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for mem add at 0x%llx: %d\n",
			payload->start_pfn, ack_ret);
	}

	return ret;
}

static int mk_handle_mem_remove(struct mk_mem_resource_payload *payload, u32 payload_len)
{
	struct mk_resource_ack ack;
	int ret, ack_ret;

	if (payload_len < sizeof(*payload)) {
		pr_err("Multikernel hotplug: Invalid memory remove payload size: %u\n", payload_len);
		return -EINVAL;
	}

	ret = mk_do_mem_remove(payload->start_pfn, payload->nr_pages);

	ack.operation = MK_RES_MEM_REMOVE;
	ack.result = ret;
	ack.resource_id = (u32)payload->start_pfn;
	ack.reserved = 0;
	ack_ret = mk_send_message(payload->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for mem remove at 0x%llx: %d\n",
			payload->start_pfn, ack_ret);
	}

	return ret;
}

/*
 * Message Handler - Dispatches to specific handlers based on subtype
 */

/**
 * mk_resource_msg_handler - Handle resource management messages
 * @msg_type: Message type (should be MK_MSG_RESOURCE)
 * @subtype: Message subtype (CPU_ADD, CPU_REMOVE, MEM_ADD, MEM_REMOVE)
 * @payload: Payload data
 * @payload_len: Payload length
 * @ctx: Context (unused)
 *
 * This is the main message handler registered with the multikernel
 * messaging system. It dispatches to specific handlers based on the
 * message subtype.
 */
static void mk_resource_msg_handler(u32 msg_type, u32 subtype,
				    void *payload, u32 payload_len, void *ctx)
{
	int ret = 0;

	if (msg_type != MK_MSG_RESOURCE) {
		pr_warn("Multikernel hotplug: Unexpected message type: 0x%x\n", msg_type);
		return;
	}

	switch (subtype) {
	case MK_RES_CPU_ADD:
		ret = mk_handle_cpu_add((struct mk_cpu_resource_payload *)payload, payload_len);
		break;

	case MK_RES_CPU_REMOVE:
		ret = mk_handle_cpu_remove((struct mk_cpu_resource_payload *)payload, payload_len);
		break;

	case MK_RES_MEM_ADD:
		ret = mk_handle_mem_add((struct mk_mem_resource_payload *)payload, payload_len);
		break;

	case MK_RES_MEM_REMOVE:
		ret = mk_handle_mem_remove((struct mk_mem_resource_payload *)payload, payload_len);
		break;

	case MK_RES_ACK:
		if (payload_len >= sizeof(struct mk_resource_ack)) {
			struct mk_resource_ack *ack = (struct mk_resource_ack *)payload;
			mk_msg_pending_complete(MK_MSG_RESOURCE, ack->operation,
						ack->resource_id, ack->result);
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
	int ret;

	pr_info("Initializing multikernel hotplug subsystem\n");

	/* Register handler for resource management messages */
	ret = mk_register_msg_handler(MK_MSG_RESOURCE, mk_resource_msg_handler, NULL);
	if (ret < 0) {
		pr_err("Failed to register multikernel hotplug message handler: %d\n", ret);
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
	struct mk_hotplug_op *op, *tmp;

	pr_info("Cleaning up multikernel hotplug subsystem\n");

	/* Unregister message handler */
	mk_unregister_msg_handler(MK_MSG_RESOURCE, mk_resource_msg_handler);

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
 * mk_send_cpu_remove - Remove CPU from instance and wait for completion
 * @instance_id: Target instance ID
 * @cpu_id: Physical CPU ID to remove
 *
 * For local instance, executes removal synchronously and returns after completion.
 * For remote instance, sends IPI and waits for ACK response.
 *
 * Returns: 0 on success, negative error code on failure or timeout
 */
int mk_send_cpu_remove(int instance_id, u32 cpu_id)
{
	struct mk_cpu_resource_payload payload = {
		.cpu_id = cpu_id,
		.numa_node = 0,
		.flags = 0,
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	int ret;

	/* For self-removal, execute directly (we're in process context) */
	if (instance_id == root_instance->id)
		return mk_do_cpu_remove(cpu_id);

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_REMOVE, cpu_id);
	if (!pending)
		return -ENOMEM;

	ret = mk_send_message(instance_id, MK_MSG_RESOURCE, MK_RES_CPU_REMOVE,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);  /* Immediate cleanup */
		return ret;
	}

	return mk_msg_pending_wait(pending, 10000);
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
 *
 * Returns: 0 on success, negative error code on failure or timeout
 */
int mk_send_cpu_add(int instance_id, u32 cpu_id, u32 numa_node, u32 flags)
{
	struct mk_cpu_resource_payload payload = {
		.cpu_id = cpu_id,
		.numa_node = numa_node,
		.flags = flags,
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	int ret;

	/* For self-addition, execute directly (we're in process context) */
	if (instance_id == root_instance->id)
		return mk_do_cpu_add(cpu_id, numa_node, flags);

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_ADD, cpu_id);
	if (!pending)
		return -ENOMEM;

	ret = mk_send_message(instance_id, MK_MSG_RESOURCE, MK_RES_CPU_ADD,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);  /* Immediate cleanup */
		return ret;
	}

	return mk_msg_pending_wait(pending, 10000);
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
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	int ret;

	/* For self-addition, execute directly (we're in process context) */
	if (instance_id == root_instance->id)
		return mk_do_mem_add(start_pfn, nr_pages, numa_node, mem_type);

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_MEM_ADD, (u32)start_pfn);
	if (!pending)
		return -ENOMEM;

	ret = mk_send_message(instance_id, MK_MSG_RESOURCE, MK_RES_MEM_ADD,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);  /* Immediate cleanup */
		return ret;
	}

	return mk_msg_pending_wait(pending, 10000);
}

/**
 * mk_send_mem_remove - Remove memory from instance
 * @instance_id: Target instance ID
 * @start_pfn: Starting page frame number
 * @nr_pages: Number of pages
 *
 * For local instance, executes removal synchronously.
 * For remote instance, sends IPI and waits for ACK response.
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
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	int ret;

	/* For self-removal, execute directly (we're in process context) */
	if (instance_id == root_instance->id)
		return mk_do_mem_remove(start_pfn, nr_pages);

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_MEM_REMOVE, (u32)start_pfn);
	if (!pending)
		return -ENOMEM;

	ret = mk_send_message(instance_id, MK_MSG_RESOURCE, MK_RES_MEM_REMOVE,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);  /* Immediate cleanup */
		return ret;
	}

	return mk_msg_pending_wait(pending, 10000);
}
