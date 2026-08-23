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
 * CPU Hotplug Operations
 */
struct mk_cpu_hotplug_work {
	struct work_struct work;
	mk_phys_cpu_t cpu_id;
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
	int logical_cpu;
	int ret;
	struct mk_hotplug_op *op;

	pr_info("Multikernel hotplug: Adding CPU %llu (numa=%d, flags=0x%x)\n",
		cpu_id, (int)numa_node, flags);

	mk_cpu_transaction_lock();
	logical_cpu = mk_cpu_to_logical(cpu_id);
	if (logical_cpu < 0) {
		/*
		 * Not present: this pool CPU has never run here (or was
		 * removed earlier). It was enumerated at boot from the manifest
		 * pool-cpus list, so it has a logical slot in the possible
		 * map; mark it present again before onlining.
		 */
		logical_cpu = arch_cpu_from_physical_id(cpu_id);
		if (logical_cpu < 0) {
			pr_err("Multikernel hotplug: CPU %llu is not in this kernel's pool\n",
			       cpu_id);
			ret = -ENODEV;
			goto unlock_transaction;
		}
		set_cpu_present(logical_cpu, true);
	}

	if (cpu_online(logical_cpu)) {
		pr_warn("Multikernel hotplug: CPU %d (phys %llu) already online\n",
			logical_cpu, cpu_id);
		mk_cpu_ownership_lock();
		if (root_instance->cpus) {
			ret = mk_cpu_set_add(root_instance->cpus, cpu_id);
			if (ret)
				pr_warn("Multikernel hotplug: Failed to track CPU %llu in root pool\n",
					cpu_id);
		}
		mk_cpu_ownership_unlock();
		ret = 0;
		goto unlock_transaction;
	}

	mk_cpu_ownership_lock();
	if (root_instance->cpus) {
		ret = mk_cpu_set_reserve(root_instance->cpus, 1);
		if (ret) {
			mk_cpu_ownership_unlock();
			goto unlock_transaction;
		}
	}
	mk_cpu_ownership_unlock();

	if (!get_cpu_device(logical_cpu)) {
		struct cpu *c = &per_cpu(cpu_devices, logical_cpu);

		c->hotpluggable = true;
		ret = register_cpu(c, logical_cpu);
		if (ret) {
			pr_err("Multikernel hotplug: Failed to register CPU %d: %d\n",
			       logical_cpu, ret);
			goto unlock_transaction;
		}
	}

	ret = add_cpu(logical_cpu);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to add CPU %d (phys %llu): %d\n",
		       logical_cpu, cpu_id, ret);
		goto unlock_transaction;
	}

	mk_cpu_ownership_lock();
	if (!root_instance->cpus) {
		ret = -ENODEV;
	} else {
		ret = mk_cpu_set_add(root_instance->cpus, cpu_id);
		if (ret)
			pr_warn("Multikernel hotplug: Failed to track CPU %llu in root pool\n",
				cpu_id);
	}
	mk_cpu_ownership_unlock();
	if (ret) {
		int rollback_ret = remove_cpu(logical_cpu);

		if (rollback_ret)
			pr_crit("Multikernel hotplug: CPU %d is online but untracked; rollback failed: %d\n",
				logical_cpu, rollback_ret);
		goto unlock_transaction;
	}

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

	ret = 0;
unlock_transaction:
	mk_cpu_transaction_unlock();
	return ret;
}

static int mk_do_cpu_remove(mk_phys_cpu_t cpu_id)
{
	int logical_cpu;
	int ret;
	struct mk_hotplug_op *op;

	mk_cpu_transaction_lock();
	logical_cpu = mk_cpu_to_logical(cpu_id);
	if (logical_cpu < 0) {
		pr_err("Multikernel hotplug: Physical CPU %llu not found\n", cpu_id);
		ret = -ENODEV;
		goto unlock_transaction;
	}

	mk_cpu_ownership_lock();

	if (!cpu_online(logical_cpu)) {
		pr_warn("Multikernel hotplug: CPU %d (phys %llu) already offline\n",
			logical_cpu, cpu_id);
		mk_cpu_set_del(root_instance->cpus, cpu_id);
		mk_cpu_ownership_unlock();
		ret = 0;
		goto unlock_transaction;
	}

	/* Don't allow removing CPU 0 (boot processor) */
	if (logical_cpu == 0) {
		pr_err("Multikernel hotplug: Cannot remove boot CPU\n");
		mk_cpu_ownership_unlock();
		ret = -EINVAL;
		goto unlock_transaction;
	}
	mk_cpu_ownership_unlock();

	mk_set_pool_cpu(logical_cpu, true);

	ret = remove_cpu(logical_cpu);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to remove CPU %d (phys %llu): %d\n",
		       logical_cpu, cpu_id, ret);
		mk_set_pool_cpu(logical_cpu, false);
		goto unlock_transaction;
	}

	mk_cpu_ownership_lock();
	mk_cpu_set_del(root_instance->cpus, cpu_id);
	mk_cpu_ownership_unlock();

	/*
	 * Clear CPU from present mask to prevent host kernel from trying
	 * to interact with it after spawn kernel takes over.
	 */
	set_cpu_present(logical_cpu, false);

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

	ret = 0;
unlock_transaction:
	mk_cpu_transaction_unlock();
	return ret;
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

	ack_ret = mk_send_message(hp_work->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for CPU %llu: %d\n",
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

	ack_ret = mk_send_message(hp_work->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for CPU %llu: %d\n",
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
	if (!hp_work)
		return -ENOMEM;

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
	if (!hp_work)
		return -ENOMEM;

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

static int mk_do_mem_add(u64 start_pfn, u64 nr_pages, u32 numa_node, u32 mem_type)
{
	int ret;
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

	ret = add_memory_driver_managed(nid, phys_addr, size,
					mk_mem_resource_name,
					MHP_MEMMAP_ON_MEMORY);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to add memory at 0x%llx: %d\n",
		       phys_addr, ret);
		return ret;
	}

	ret = walk_memory_blocks(phys_addr, size, NULL,
				 mk_online_memory_block_movable);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to online memory at 0x%llx: %d\n",
		       phys_addr, ret);
		offline_and_remove_memory(phys_addr, size);
		return ret;
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

	ret = offline_and_remove_memory(phys_addr, size);
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

struct mk_mem_hotplug_work {
	struct work_struct work;
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

	ret = mk_do_mem_add(hp_work->start_pfn, hp_work->nr_pages,
			    hp_work->numa_node, hp_work->mem_type);

	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = hp_work->start_pfn;

	ack_ret = mk_send_message(hp_work->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for mem add at 0x%llx: %d\n",
			(u64)hp_work->start_pfn, ack_ret);
	}

	kfree(hp_work);
}

static void mk_mem_remove_work_fn(struct work_struct *work)
{
	struct mk_mem_hotplug_work *hp_work = container_of(work, struct mk_mem_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = mk_do_mem_remove(hp_work->start_pfn, hp_work->nr_pages);

	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = hp_work->start_pfn;

	ack_ret = mk_send_message(hp_work->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for mem remove at 0x%llx: %d\n",
			(u64)hp_work->start_pfn, ack_ret);
	}

	kfree(hp_work);
}

static int mk_handle_mem_add(struct mk_mem_resource_payload *payload, u32 payload_len)
{
	struct mk_mem_hotplug_work *hp_work;

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
	hp_work->start_pfn = payload->start_pfn;
	hp_work->nr_pages = payload->nr_pages;
	hp_work->numa_node = payload->numa_node;
	hp_work->mem_type = payload->mem_type;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_MEM_ADD;
	schedule_work(&hp_work->work);

	return 0;
}

static int mk_handle_mem_remove(struct mk_mem_resource_payload *payload, u32 payload_len)
{
	struct mk_mem_hotplug_work *hp_work;

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
	hp_work->start_pfn = payload->start_pfn;
	hp_work->nr_pages = payload->nr_pages;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_MEM_REMOVE;
	schedule_work(&hp_work->work);

	return 0;
}

/*
 * PCI Device Hotplug Operations
 */

#ifdef CONFIG_PCI
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

		/* device_attach() takes the device lock itself */
		ret = device_attach(&pdev->dev);
		if (ret < 0) {
			pr_err("Multikernel hotplug: Failed to bind device %04x:%02x:%02x.%x: %d\n",
			       domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), ret);
			pci_dev_put(pdev);
			return ret;
		}

		if (ret == 0)
			pr_info("Multikernel hotplug: No driver matches device %04x:%02x:%02x.%x\n",
				domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
		else
			pr_info("Multikernel hotplug: Bound device to %s\n",
				pdev->dev.driver ? pdev->dev.driver->name : "its driver");
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
#else
static int mk_do_device_add(u16 domain, u8 bus, u8 devfn,
			    const char *driver_override, u32 flags)
{
	return -EOPNOTSUPP;
}

static int mk_do_device_remove(u16 domain, u8 bus, u8 devfn)
{
	return -EOPNOTSUPP;
}
#endif

struct mk_device_hotplug_work {
	struct work_struct work;
	u16 domain;
	u8 bus;
	u8 devfn;
	u32 flags;
	char driver_override[64];
	int sender_instance_id;
	u32 operation;
};

static void mk_device_add_work_fn(struct work_struct *work)
{
	struct mk_device_hotplug_work *hp_work = container_of(work, struct mk_device_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = mk_do_device_add(hp_work->domain, hp_work->bus, hp_work->devfn,
			       hp_work->driver_override, hp_work->flags);

	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = (hp_work->domain << 16) | (hp_work->bus << 8) | hp_work->devfn;

	ack_ret = mk_send_message(hp_work->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for device %04x:%02x:%02x.%x: %d\n",
			hp_work->domain, hp_work->bus,
			PCI_SLOT(hp_work->devfn), PCI_FUNC(hp_work->devfn), ack_ret);
	}

	kfree(hp_work);
}

static void mk_device_remove_work_fn(struct work_struct *work)
{
	struct mk_device_hotplug_work *hp_work = container_of(work, struct mk_device_hotplug_work, work);
	struct mk_resource_ack ack;
	int ret, ack_ret;

	ret = mk_do_device_remove(hp_work->domain, hp_work->bus, hp_work->devfn);

	ack.operation = hp_work->operation;
	ack.result = ret;
	ack.resource_id = (hp_work->domain << 16) | (hp_work->bus << 8) | hp_work->devfn;

	ack_ret = mk_send_message(hp_work->sender_instance_id, MK_MSG_RESOURCE, MK_RES_ACK,
				  &ack, sizeof(ack));
	if (ack_ret < 0) {
		pr_warn("Multikernel hotplug: Failed to send ACK for device %04x:%02x:%02x.%x: %d\n",
			hp_work->domain, hp_work->bus,
			PCI_SLOT(hp_work->devfn), PCI_FUNC(hp_work->devfn), ack_ret);
	}

	kfree(hp_work);
}

static int mk_handle_device_add(struct mk_device_resource_payload *payload, u32 payload_len)
{
	struct mk_device_hotplug_work *hp_work;

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
	hp_work->domain = payload->domain;
	hp_work->bus = payload->bus;
	hp_work->devfn = payload->devfn;
	hp_work->flags = payload->flags;
	strscpy(hp_work->driver_override, payload->driver_override, sizeof(hp_work->driver_override));
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_DEVICE_ADD;
	schedule_work(&hp_work->work);

	return 0;
}

static int mk_handle_device_remove(struct mk_device_resource_payload *payload, u32 payload_len)
{
	struct mk_device_hotplug_work *hp_work;

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
	hp_work->domain = payload->domain;
	hp_work->bus = payload->bus;
	hp_work->devfn = payload->devfn;
	hp_work->flags = payload->flags;
	hp_work->sender_instance_id = payload->sender_instance_id;
	hp_work->operation = MK_RES_DEVICE_REMOVE;
	schedule_work(&hp_work->work);

	return 0;
}

/*
 * Message Handler - Dispatches to specific handlers based on subtype
 */

/**
 * mk_resource_msg_handler - Handle resource management messages
 * @msg_type: Message type (should be MK_MSG_RESOURCE)
 * @subtype: Message subtype (CPU_ADD, CPU_REMOVE, MEM_ADD, MEM_REMOVE, DEVICE_ADD, DEVICE_REMOVE)
 * @payload: Payload data
 * @payload_len: Payload length
 * @ctx: Context (unused)
 *
 * This is the main message handler registered with the multikernel
 * messaging system. It dispatches to specific handlers based on the
 * message subtype.
 */
static void mk_resource_msg_handler(u32 msg_type, u32 subtype,
				    void *payload, u32 payload_len,
				    mk_phys_cpu_t sender_cpu, void *ctx)
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

	case MK_RES_DEVICE_ADD:
		ret = mk_handle_device_add((struct mk_device_resource_payload *)payload, payload_len);
		break;

	case MK_RES_DEVICE_REMOVE:
		ret = mk_handle_device_remove((struct mk_device_resource_payload *)payload, payload_len);
		break;

	case MK_RES_ACK:
		if (payload_len >= sizeof(struct mk_resource_ack)) {
			struct mk_resource_ack *ack = (struct mk_resource_ack *)payload;

			pr_info("Multikernel hotplug: ACK op=0x%x resource=%llu result=%d\n",
				ack->operation, ack->resource_id, (int)ack->result);
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
 * mk_pool_cpu_add - Move a CPU of this kernel into its assignable pool
 * @cpu_id: Physical CPU ID
 *
 * Only meaningful in a kernel that manages a pool (mk_cpu_pool non-NULL).
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
	ret = mk_cpu_set_reserve(mk_cpu_pool, 1);
	if (ret)
		return ret;

	ret = mk_do_cpu_remove(cpu_id);
	if (ret)
		return ret;

	/* The CPU parked in the host park area and is assignable again */
	mk_cpu_set_add(mk_cpu_pool, cpu_id);

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

	if (!mk_cpu_set_contains(mk_cpu_pool, cpu_id)) {
		pr_err("Multikernel hotplug: CPU %llu is not free in the pool\n",
		       cpu_id);
		return -EBUSY;
	}

	ret = mk_do_cpu_add(cpu_id, numa_node, flags);
	if (ret)
		return ret;

	/* From here on it is an ordinary CPU of this kernel */
	if (mk_cpu_set_del(mk_cpu_pool, cpu_id)) {
		int cpu = arch_cpu_from_physical_id(cpu_id);

		if (cpu >= 0)
			mk_set_pool_cpu(cpu, false);
	}

	return 0;
}

/**
 * mk_pool_device_add - Move a PCI device of this kernel into its pool
 * @domain: PCI domain
 * @bus: PCI bus
 * @devfn: PCI device and function (combined)
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_pool_device_add(u16 domain, u8 bus, u8 devfn)
{
	int ret;

	ret = mk_do_device_remove(domain, bus, devfn);
	if (ret)
		return ret;

	ret = mk_root_add_pci_device(domain, bus, devfn);
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
 * the CPU back to root instance without sending IPIs.
 *
 * Returns: 0 on success, negative error code on failure or timeout
 */
int mk_send_cpu_remove(int instance_id, mk_phys_cpu_t cpu_id)
{
	struct mk_cpu_set removing = { .nr = 1, .cap = 1, .ids = &cpu_id };
	struct mk_cpu_resource_payload payload = {
		.cpu_id = cpu_id,
		.numa_node = 0,
		.flags = 0,
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	mk_phys_cpu_t route_cpu;
	int ret;

	raw_spin_lock_init(&removing.lock);

	/* For self-removal, execute directly (we're in process context) */
	if (instance_id == root_instance->id) {
		if (mk_cpu_pool)
			return mk_pool_cpu_add(cpu_id);
		return mk_do_cpu_remove(cpu_id);
	}

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;

	/* For non-running instances, return CPU to root using existing API */
	if (target_instance->state != MK_STATE_ACTIVE) {
		struct mk_cpu_set cpus = { .nr = 1, .cap = 1, .ids = &cpu_id };

		raw_spin_lock_init(&cpus.lock);
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

	/* The pool set must exist before the ownership transaction starts. */
	if (!mk_cpu_pool) {
		ret = -ENODEV;
		goto out;
	}

	mk_cpu_transaction_lock();
	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_REMOVE, cpu_id);
	if (!pending) {
		ret = -ENOMEM;
		goto unlock_transaction;
	}

	mk_cpu_ownership_lock();
	if (!mk_cpu_set_contains(target_instance->cpus, cpu_id)) {
		pr_err("Multikernel hotplug: CPU %llu not assigned to instance %d\n",
		       cpu_id, instance_id);
		ret = -EINVAL;
		mk_cpu_ownership_unlock();
		mk_msg_pending_wait(pending, 0);
		goto unlock_transaction;
	}

	ret = mk_cpu_set_reserve(mk_cpu_pool, 1);
	if (ret) {
		mk_cpu_ownership_unlock();
		mk_msg_pending_wait(pending, 0);
		goto unlock_transaction;
	}
	mk_cpu_ownership_unlock();
	ret = mk_instance_migrate_irq_route(target_instance, &removing);
	if (ret) {
		mk_msg_pending_wait(pending, 0);
		goto unlock_transaction;
	}
	route_cpu = mk_instance_irq_route_load(target_instance);

	ret = mk_send_message_to_cpu(target_instance, route_cpu,
				     MK_MSG_RESOURCE, MK_RES_CPU_REMOVE,
				     &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);  /* Immediate cleanup */
		goto unlock_transaction;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto unlock_transaction;

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
		goto unlock_transaction;
	}

	down_write(&target_instance->control_route_sem);
	mk_cpu_ownership_lock();
	if (!mk_cpu_set_contains(target_instance->cpus, cpu_id)) {
		ret = -ESTALE;
		goto unlock_ownership;
	}
	ret = mk_cpu_set_add(mk_cpu_pool, cpu_id);
	if (ret) {
		pr_warn("Multikernel hotplug: Failed to track CPU %llu in pool\n",
			cpu_id);
		goto unlock_ownership;
	}
	mk_cpu_set_del(target_instance->cpus, cpu_id);

	ret = 0;
unlock_ownership:
	mk_cpu_ownership_unlock();
	up_write(&target_instance->control_route_sem);
unlock_transaction:
	mk_cpu_transaction_unlock();
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
 * the CPU from root instance without sending IPIs.
 *
 * Returns: 0 on success, negative error code on failure or timeout
 */
int mk_send_cpu_add(int instance_id, mk_phys_cpu_t cpu_id, u32 numa_node, u32 flags)
{
	struct mk_cpu_resource_payload payload = {
		.cpu_id = cpu_id,
		.numa_node = numa_node,
		.flags = flags,
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;

	/* For self-addition, execute directly (we're in process context) */
	if (instance_id == root_instance->id) {
		if (mk_cpu_pool)
			return mk_pool_cpu_remove(cpu_id, numa_node, flags);
		return mk_do_cpu_add(cpu_id, numa_node, flags);
	}

	target_instance = mk_instance_find(instance_id);
	if (!target_instance) {
		pr_err("Multikernel hotplug: instance %d not found for CPU add\n",
		       instance_id);
		return -ENODEV;
	}
	if (arch_cpu_from_physical_id(cpu_id) == 0) {
		pr_err("Multikernel hotplug: CPU %llu is reserved for host control\n",
		       cpu_id);
		ret = -EINVAL;
		goto out;
	}

	/* For non-running instances, transfer CPU from root using existing API */
	if (target_instance->state != MK_STATE_ACTIVE) {
		struct mk_cpu_set cpus = { .nr = 1, .cap = 1, .ids = &cpu_id };

		raw_spin_lock_init(&cpus.lock);
		ret = mk_instance_transfer_cpus(target_instance, &cpus);
		goto out;
	}

	mk_cpu_transaction_lock();
	mk_cpu_ownership_lock();
	if (!mk_cpu_set_contains(mk_cpu_pool, cpu_id)) {
		pr_err("Multikernel hotplug: CPU %llu not available in the pool\n",
		       cpu_id);
		ret = -EBUSY;
		mk_cpu_ownership_unlock();
		goto unlock_transaction;
	}

	ret = mk_cpu_set_reserve(target_instance->cpus, 1);
	if (ret) {
		mk_cpu_ownership_unlock();
		goto unlock_transaction;
	}
	mk_cpu_ownership_unlock();

	/*
	 * The CPU is parked on the host slot, where the spawn kernel's
	 * secondary wakeup cannot reach it. Point it at the instance's
	 * context before asking the instance to online it.
	 */
	ret = mk_repark_cpu_to_instance(target_instance, cpu_id);
	if (ret < 0) {
		pr_err("Multikernel hotplug: Failed to repark CPU %llu to instance %d: %d\n",
		       cpu_id, instance_id, ret);
		goto unlock_transaction;
	}

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_CPU_ADD, cpu_id);
	if (!pending) {
		mk_repark_cpu_to_host(target_instance, cpu_id);
		ret = -ENOMEM;
		goto unlock_transaction;
	}

	ret = mk_send_message_to_instance(target_instance, MK_MSG_RESOURCE,
					  MK_RES_CPU_ADD, &payload,
					  sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);  /* Immediate cleanup */
		mk_repark_cpu_to_host(target_instance, cpu_id);
		goto unlock_transaction;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0) {
		/*
		 * Best effort: if the instance never picked the CPU up, it
		 * is still parked on the instance context and comes home;
		 * if the instance onlined it despite the error, nothing is
		 * watching the context and this times out harmlessly.
		 */
		mk_repark_cpu_to_host(target_instance, cpu_id);
		goto unlock_transaction;
	}

	down_write(&target_instance->control_route_sem);
	mk_cpu_ownership_lock();
	if (!mk_cpu_set_contains(mk_cpu_pool, cpu_id)) {
		ret = -ESTALE;
		goto unlock_ownership;
	}
	ret = mk_cpu_set_add(target_instance->cpus, cpu_id);
	if (ret) {
		pr_warn("Multikernel hotplug: Failed to track CPU %llu in instance %d\n",
			cpu_id, instance_id);
		goto unlock_ownership;
	}
	mk_cpu_set_del(mk_cpu_pool, cpu_id);
	if (mk_instance_irq_route_load(target_instance) == MK_PHYS_CPU_INVALID)
		mk_instance_irq_route_store(target_instance, cpu_id);

	ret = 0;
unlock_ownership:
	mk_cpu_ownership_unlock();
	up_write(&target_instance->control_route_sem);
unlock_transaction:
	mk_cpu_transaction_unlock();
out:
	mk_instance_put(target_instance);
	return ret;
}

static int mk_memory_change_allowed(struct mk_instance *instance)
{
	bool iommu_active;

	mutex_lock(&instance->resource_mutex);
	iommu_active = mk_pci_iommu_lease_active_locked(instance);
	mutex_unlock(&instance->resource_mutex);
	if (!iommu_active)
		return 0;

	pr_err("Cannot change memory for instance %d while an IOMMU lease is active\n",
	       instance->id);
	return -EBUSY;
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
 * For instances that are not yet running (MK_STATE_READY/LOADED), adds
 * the memory region to instance's memory_regions list.
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
	struct mk_instance *target_instance;
	int ret;

	/* For self-addition, execute directly (we're in process context) */
	if (instance_id == root_instance->id)
		return mk_do_mem_add(start_pfn, nr_pages, numa_node, mem_type);

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;
	ret = mk_memory_change_allowed(target_instance);
	if (ret) {
		mk_instance_put(target_instance);
		return ret;
	}

	/* For non-running instances, allocate memory from pool and add to instance */
	if (target_instance->state != MK_STATE_ACTIVE) {
		size_t size;

		size = PFN_PHYS(nr_pages);
		ret = mk_instance_add_memory_region(target_instance, size,
						    (int)numa_node);
		goto out;
	}

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_MEM_ADD, start_pfn);
	if (!pending) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mk_send_message(instance_id, MK_MSG_RESOURCE, MK_RES_MEM_ADD,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);  /* Immediate cleanup */
		goto out;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto out;

	ret = mk_instance_add_memory_region(target_instance, PFN_PHYS(nr_pages),
					    (int)numa_node);
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
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;

	/* For self-removal, execute directly (we're in process context) */
	if (instance_id == root_instance->id)
		return mk_do_mem_remove(start_pfn, nr_pages);

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;
	ret = mk_memory_change_allowed(target_instance);
	if (ret) {
		mk_instance_put(target_instance);
		return ret;
	}

	/* For non-running instances, just remove the memory region from the instance */
	if (target_instance->state != MK_STATE_ACTIVE) {
		phys_addr_t phys_addr;
		size_t size;

		phys_addr = PFN_PHYS(start_pfn);
		size = PFN_PHYS(nr_pages);
		ret = mk_instance_remove_memory_region(target_instance, phys_addr, size);
		goto out;
	}

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_MEM_REMOVE, start_pfn);
	if (!pending) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mk_send_message(instance_id, MK_MSG_RESOURCE, MK_RES_MEM_REMOVE,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);  /* Immediate cleanup */
		goto out;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto out;

	/* Update root kernel's view of instance memory after successful IPI */
	ret = mk_instance_remove_memory_region(target_instance,
					       PFN_PHYS(start_pfn),
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
	if (!root_instance)
		return -ENODEV;
	struct mk_device_resource_payload payload = {
		.domain = domain,
		.bus = bus,
		.devfn = devfn,
		.flags = flags,
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;
	u32 resource_id;

	if (driver_override)
		strscpy(payload.driver_override, driver_override, sizeof(payload.driver_override));
	else
		payload.driver_override[0] = '\0';

	resource_id = (domain << 16) | (bus << 8) | devfn;

	if (instance_id == root_instance->id) {
		if (mk_cpu_pool)
			return mk_pool_device_remove(domain, bus, devfn,
						     driver_override, flags);
		return mk_do_device_add(domain, bus, devfn, driver_override, flags);
	}

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;

	if (target_instance->state != MK_STATE_ACTIVE) {
		ret = mk_instance_add_pci_device(target_instance, domain, bus, devfn);
		goto out;
	}

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_DEVICE_ADD, resource_id);
	if (!pending) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mk_send_message(instance_id, MK_MSG_RESOURCE, MK_RES_DEVICE_ADD,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);
		goto out;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto out;

	ret = mk_instance_add_pci_device(target_instance, domain, bus, devfn);
	if (ret < 0) {
		pr_warn("Device added to target but failed to update tracking: %d\n", ret);
	}

	pr_info("Multikernel hotplug: Device %04x:%02x:%02x.%x successfully added to instance %d\n",
		domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn), instance_id);

	ret = 0;
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
	if (!root_instance)
		return -ENODEV;
	struct mk_device_resource_payload payload = {
		.domain = domain,
		.bus = bus,
		.devfn = devfn,
		.flags = 0,
		.sender_instance_id = root_instance->id
	};
	struct mk_pending_msg *pending;
	struct mk_instance *target_instance;
	int ret;
	u32 resource_id;

	payload.driver_override[0] = '\0';
	resource_id = (domain << 16) | (bus << 8) | devfn;

	if (instance_id == root_instance->id) {
		if (mk_cpu_pool)
			return mk_pool_device_add(domain, bus, devfn);
		return mk_do_device_remove(domain, bus, devfn);
	}

	target_instance = mk_instance_find(instance_id);
	if (!target_instance)
		return -ENODEV;

	if (target_instance->state != MK_STATE_ACTIVE) {
		ret = mk_instance_remove_pci_device(target_instance, domain, bus, devfn);
		goto out;
	}

	pending = mk_msg_pending_add(MK_MSG_RESOURCE, MK_RES_DEVICE_REMOVE, resource_id);
	if (!pending) {
		ret = -ENOMEM;
		goto out;
	}

	ret = mk_send_message(instance_id, MK_MSG_RESOURCE, MK_RES_DEVICE_REMOVE,
			      &payload, sizeof(payload));
	if (ret < 0) {
		mk_msg_pending_wait(pending, 0);
		goto out;
	}

	ret = mk_msg_pending_wait(pending, 10000);
	if (ret < 0)
		goto out;

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
