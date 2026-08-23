// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * Multikernel kernel instance filesystem
 *
 * Provides a dedicated filesystem for multikernel instance management.
 * Mounted at /sys/fs/multikernel/ with full mkdir/rmdir support:
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/ioport.h>
#include <linux/idr.h>
#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/fs_context.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/cpumask.h>
#include <linux/multikernel.h>
#include <linux/libfdt.h>
#include <linux/sizes.h>
#include "internal.h"

#define MULTIKERNEL_MAGIC	0x6d6b6673	/* "mkfs" */

/* Global multikernel filesystem state */
static struct kernfs_root *mk_kernfs_root;        /* Kernfs root for multikernel filesystem */
struct kernfs_node *mk_root_kn;                    /* Root kernfs node */
struct kernfs_node *mk_instances_kn;               /* Instances subdirectory node */
LIST_HEAD(mk_instance_list);                      /* List of all instances */
DEFINE_MUTEX(mk_instance_mutex);                  /* Protects instance list */
DEFINE_IDR(mk_instance_idr);               /* ID allocator for instances */

DEFINE_MUTEX(mk_host_dtb_mutex);           /* Protects host DTB access */

/* Filesystem context structure */
struct mk_fs_context {
	struct kernfs_fs_context kfc;
};

/* Forward declarations */
static int mk_kernfs_mkdir(struct kernfs_node *parent, const char *name, umode_t mode);
static int mk_kernfs_rmdir(struct kernfs_node *kn);
static int mk_get_tree(struct fs_context *fc);
static void mk_free_fs_context(struct fs_context *fc);
static int mk_init_fs_context(struct fs_context *fc);
static void mk_kill_sb(struct super_block *sb);
static int mk_create_instance_files(struct mk_instance *instance);

/* Kernfs syscall operations */
static struct kernfs_syscall_ops mk_kernfs_syscall_ops = {
	.mkdir = mk_kernfs_mkdir,
	.rmdir = mk_kernfs_rmdir,
};

/* Filesystem context operations */
static const struct fs_context_operations mk_fs_context_ops = {
	.free		= mk_free_fs_context,
	.get_tree	= mk_get_tree,
};

/* Filesystem type */
static struct file_system_type mk_fs_type = {
	.name			= "multikernel",
	.init_fs_context	= mk_init_fs_context,
	.kill_sb		= mk_kill_sb,
	.fs_flags		= 0,
};

/**
 * State string conversion
 */
static const char * const mk_state_strings[] = {
	[MK_STATE_EMPTY]   = "empty",
	[MK_STATE_READY]   = "ready",
	[MK_STATE_LOADED]  = "loaded",
	[MK_STATE_ACTIVE]  = "active",
	[MK_STATE_FAILED]  = "failed",
};

const char *mk_state_to_string(enum mk_instance_state state)
{
	if (state >= 0 && state < ARRAY_SIZE(mk_state_strings))
		return mk_state_strings[state];
	return "unknown";
}

enum mk_instance_state mk_string_to_state(const char *str)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(mk_state_strings); i++) {
		if (sysfs_streq(str, mk_state_strings[i]))
			return i;
	}
	return MK_STATE_FAILED;  /* Invalid input */
}

/**
 * Kernfs file operations for instance attributes
 */

/* id attribute - shows kernel-assigned ID */
static int id_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct mk_instance *instance = of->kn->priv;
	seq_printf(sf, "%d\n", instance->id);
	return 0;
}

/* status attribute - shows instance state (read-only, managed by kernel) */
static int status_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct mk_instance *instance = of->kn->priv;
	seq_printf(sf, "%s\n", mk_state_to_string(instance->state));
	return 0;
}

/*
 * This is an observational snapshot, not a transaction: producers may update
 * fields while the file is read.  Shared transport counters are u32 values
 * and restart with a new spawn_epoch, so consumers compare modulo-u32 deltas
 * only between samples from the same epoch.
 */
static int stats_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct mk_instance *instance = of->kn->priv;
	struct mk_shared_data *shared;
	struct {
		u64 spawn_epoch;
		u64 irq_pending_total;
		u64 pci_config_requests;
		u64 pci_config_total_ns;
		u64 pci_config_max_ns;
		u64 pci_control_pool_exhausted;
		u32 ipi_producer_contention;
		u32 ipi_full_failures;
		u32 ipi_invalid_state;
		u32 ipi_cancelled_writes;
		u32 reply_late_replies;
		u32 reply_cancelled_slots;
		u32 reply_atomic_timeouts;
		u32 reply_indeterminate_timeouts;
		u32 reply_occupied_failures;
		u32 irq_recorded;
		u32 irq_coalesced;
		u32 irq_masked_deferred;
		u32 irq_stale;
		u32 irq_dispatch_failed;
		u32 irq_saturated;
		u32 ipi_slots[4];
		u32 reply_states[MK_REPLY_ABANDONED + 1];
		u32 irq_active;
		u32 irq_pending;
		u32 irq_masked;
		u32 irq_consuming;
		u32 reply_busy;
		u32 ipi_gate_busy;
		bool available;
	} stats = {};
	unsigned int i;

	stats.pci_control_pool_exhausted =
		mk_pci_control_pool_exhausted_read();
	down_read(&instance->control_route_sem);
	shared = READ_ONCE(instance->ipi_data);
	if (!shared)
		goto unlock;
	stats.available = true;
	stats.spawn_epoch = READ_ONCE(shared->spawn_epoch);
	stats.ipi_producer_contention =
		atomic_read(&shared->ring.producer_contention);
	stats.ipi_full_failures = atomic_read(&shared->ring.full_failures);
	stats.ipi_invalid_state = atomic_read(&shared->ring.invalid_state);
	stats.ipi_cancelled_writes = atomic_read(&shared->ring.cancelled_writes);
	stats.ipi_gate_busy = !!atomic64_read_acquire(&shared->ring.producer_gate);
	stats.reply_late_replies = atomic_read(&shared->replies.late_replies);
	stats.reply_cancelled_slots = atomic_read(&shared->replies.cancelled_slots);
	stats.reply_atomic_timeouts = atomic_read(&shared->replies.atomic_timeouts);
	stats.reply_indeterminate_timeouts =
		atomic_read(&shared->replies.indeterminate_timeouts);
	stats.reply_occupied_failures =
		atomic_read(&shared->replies.occupied_failures);
	stats.irq_recorded = atomic_read(&shared->irq_mailbox.recorded);
	stats.irq_coalesced = atomic_read(&shared->irq_mailbox.coalesced);
	stats.irq_masked_deferred =
		atomic_read(&shared->irq_mailbox.masked_deferred);
	stats.irq_stale = atomic_read(&shared->irq_mailbox.stale);
	stats.irq_dispatch_failed =
		atomic_read(&shared->irq_mailbox.dispatch_failed);
	stats.irq_saturated = atomic_read(&shared->irq_mailbox.saturated);
	stats.pci_config_requests =
		atomic64_read(&shared->pci_stats.config_requests);
	stats.pci_config_total_ns =
		atomic64_read(&shared->pci_stats.config_total_ns);
	stats.pci_config_max_ns =
		atomic64_read(&shared->pci_stats.config_max_ns);
	for (i = 0; i < MK_IPI_RING_SIZE; i++) {
		u32 state = atomic_read_acquire(&shared->ring.entries[i].state);

		if (state >= MK_IPI_SLOT_WRITING && state <= MK_IPI_SLOT_CANCELLED)
			stats.ipi_slots[state - MK_IPI_SLOT_WRITING]++;
	}
	for (i = 0; i < MK_REPLY_SLOTS; i++) {
		struct mk_reply_slot *slot = &shared->replies.slots[i];
		u64 token = atomic64_read_acquire(&slot->state_generation);
		u32 state = token & (BIT(MK_REPLY_STATE_BITS) - 1);

		if (state <= MK_REPLY_ABANDONED)
			stats.reply_states[state]++;
		if (state != MK_REPLY_FREE)
			stats.reply_busy++;
	}
	for (i = 0; i < MK_IRQ_MAILBOX_SLOTS; i++) {
		struct mk_irq_mailbox_entry *entry =
			&shared->irq_mailbox.entries[i];
		u64 token = atomic64_read_acquire(&entry->pending_generation);

		if (!mk_irq_mailbox_generation(token))
			continue;
		stats.irq_active++;
		if (mk_irq_mailbox_pending(token)) {
			stats.irq_pending++;
			stats.irq_pending_total += mk_irq_mailbox_pending(token);
		}
		if (mk_irq_mailbox_masked(token))
			stats.irq_masked++;
		if (mk_irq_mailbox_consuming(token))
			stats.irq_consuming++;
	}
unlock:
	up_read(&instance->control_route_sem);

	seq_puts(sf, "stats_version 1\n");
	seq_printf(sf, "abi_version %u\n", MK_IPI_ABI_VERSION);
	seq_puts(sf, "snapshot_atomic 0\n");
	seq_puts(sf, "transport_counter_bits 32\n");
	seq_printf(sf, "transport_available %u\n", stats.available);
	seq_printf(sf, "spawn_epoch %llu\n",
		   (unsigned long long)stats.spawn_epoch);
#define MK_STATS_VALUE(name, value) seq_printf(sf, name " %u\n", value)
	MK_STATS_VALUE("ipi.producer_contention", stats.ipi_producer_contention);
	MK_STATS_VALUE("ipi.full_failures", stats.ipi_full_failures);
	MK_STATS_VALUE("ipi.invalid_state", stats.ipi_invalid_state);
	MK_STATS_VALUE("ipi.cancelled_writes", stats.ipi_cancelled_writes);
	MK_STATS_VALUE("ipi.gate_busy", stats.ipi_gate_busy);
	MK_STATS_VALUE("ipi.slot_writing", stats.ipi_slots[0]);
	MK_STATS_VALUE("ipi.slot_ready", stats.ipi_slots[1]);
	MK_STATS_VALUE("ipi.slot_consuming", stats.ipi_slots[2]);
	MK_STATS_VALUE("ipi.slot_cancelled", stats.ipi_slots[3]);
	MK_STATS_VALUE("reply.late_replies", stats.reply_late_replies);
	MK_STATS_VALUE("reply.cancelled_slots", stats.reply_cancelled_slots);
	MK_STATS_VALUE("reply.atomic_timeouts", stats.reply_atomic_timeouts);
	MK_STATS_VALUE("reply.indeterminate_timeouts",
		       stats.reply_indeterminate_timeouts);
	MK_STATS_VALUE("reply.occupied_failures", stats.reply_occupied_failures);
	MK_STATS_VALUE("reply.slot_busy", stats.reply_busy);
	MK_STATS_VALUE("reply.slot_reserved", stats.reply_states[MK_REPLY_RESERVED]);
	MK_STATS_VALUE("reply.slot_writing", stats.reply_states[MK_REPLY_WRITING]);
	MK_STATS_VALUE("reply.slot_executing", stats.reply_states[MK_REPLY_EXECUTING]);
	MK_STATS_VALUE("reply.slot_committed", stats.reply_states[MK_REPLY_COMMITTED]);
	MK_STATS_VALUE("reply.slot_ready", stats.reply_states[MK_REPLY_READY]);
	MK_STATS_VALUE("reply.slot_abandoned", stats.reply_states[MK_REPLY_ABANDONED]);
	MK_STATS_VALUE("irq.recorded", stats.irq_recorded);
	MK_STATS_VALUE("irq.coalesced", stats.irq_coalesced);
	MK_STATS_VALUE("irq.masked_deferred", stats.irq_masked_deferred);
	MK_STATS_VALUE("irq.stale", stats.irq_stale);
	MK_STATS_VALUE("irq.dispatch_failed", stats.irq_dispatch_failed);
	MK_STATS_VALUE("irq.saturated", stats.irq_saturated);
	MK_STATS_VALUE("irq.slot_active", stats.irq_active);
	MK_STATS_VALUE("irq.slot_pending", stats.irq_pending);
	MK_STATS_VALUE("irq.slot_masked", stats.irq_masked);
	MK_STATS_VALUE("irq.slot_consuming", stats.irq_consuming);
#undef MK_STATS_VALUE
	seq_printf(sf, "irq.pending_total %llu\n",
		   (unsigned long long)stats.irq_pending_total);
	seq_printf(sf, "pci.config_requests %llu\n",
		   (unsigned long long)stats.pci_config_requests);
	seq_printf(sf, "pci.config_total_ns %llu\n",
		   (unsigned long long)stats.pci_config_total_ns);
	seq_printf(sf, "pci.config_average_ns %llu\n",
		   stats.pci_config_requests ?
		   (unsigned long long)(stats.pci_config_total_ns /
					stats.pci_config_requests) : 0);
	seq_printf(sf, "pci.config_max_ns %llu\n",
		   (unsigned long long)stats.pci_config_max_ns);
	seq_printf(sf, "pci.control_pool_exhausted %llu\n",
		   (unsigned long long)stats.pci_control_pool_exhausted);
	return 0;
}

/* Root-level device_tree attribute - shows current baseline pool from kernel structures */
static int root_device_tree_seq_show(struct seq_file *sf, void *v)
{
	void *dtb_data = NULL;
	size_t dtb_size = 0;
	int ret;

	ret = mk_dt_generate_instance_dtb(root_instance, &dtb_data, &dtb_size);
	if (ret) {
		pr_err("Failed to generate baseline DTB: %d\n", ret);
		return ret;
	}

	seq_write(sf, dtb_data, dtb_size);
	kfree(dtb_data);
	return 0;
}

/* Instance device_tree attribute - binary DTB (read-only) */
static ssize_t instance_device_tree_read(struct kernfs_open_file *of,
					 char *buf, size_t count, loff_t off)
{
	struct mk_instance *instance = of->kn->priv;
	void *dtb_data = NULL;
	size_t dtb_size = 0;
	size_t to_read;
	int ret;

	ret = mk_dt_generate_instance_dtb(instance, &dtb_data, &dtb_size);
	if (ret) {
		pr_err("Instance '%s': Failed to generate device tree: %d\n",
		       instance->name, ret);
		return ret;
	}

	if (off >= dtb_size) {
		kfree(dtb_data);
		return 0;
	}

	to_read = min(count, dtb_size - (size_t)off);
	memcpy(buf, dtb_data + off, to_read);
	kfree(dtb_data);

	return to_read;
}


/* Root-level device_tree write - accepts host kernel configuration only */
static ssize_t root_device_tree_write(struct kernfs_open_file *of, char *buf, size_t count, loff_t off)
{
	const void *fdt = buf;
	int instances_node, instance_node;
	int ret;

	pr_info("Loading host kernel device tree configuration (%zu bytes at offset %lld)\n", count, off);

	/* Validate DTB header */
	ret = fdt_check_header(fdt);
	if (ret) {
		pr_err("Invalid device tree header: %d\n", ret);
		return -EINVAL;
	}

	if (fdt_totalsize(fdt) != count) {
		pr_err("DTB size mismatch: header says %u bytes, received %zu bytes\n",
		       fdt_totalsize(fdt), count);
		return -EINVAL;
	}

	instances_node = fdt_path_offset(fdt, "/instances");
	if (instances_node >= 0) {
		instance_node = fdt_first_subnode(fdt, instances_node);
		if (instance_node >= 0) {
			pr_err("Device tree contains kernel instances. Host kernel configuration must not contain instances.\n");
			return -EINVAL;
		}
	}

	/* Baseline and overlays both drive the pool moves; one at a time */
	mutex_lock(&mk_overlay_mutex);
	ret = mk_baseline_validate_and_initialize(fdt, count);
	mutex_unlock(&mk_overlay_mutex);
	if (ret) {
		pr_err("Baseline validation and initialization failed: %d\n", ret);
		return ret;
	}

	pr_info("Successfully stored host kernel device tree configuration\n");
	return count;
}

/**
 * mk_create_instance_from_dtb() - Create a multikernel instance from DTB resources node
 * @name: Instance name
 * @id: Instance ID (or -1 for auto-allocation)
 * @fdt: Device tree containing the DTB resources node
 * @resources_node: Offset of the resources node in the FDT
 * @dtb_size: Size of the full DTB (for storage)
 *
 * Creates a multikernel instance by parsing resources directly from a resources node.
 * This is used by overlay instance-create operations where the resources are directly
 * available.
 *
 * If id is -1, the kernel will automatically allocate the next available ID.
 * If id is >= 0, the kernel will use that specific ID (caller must ensure it's available).
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_create_instance_from_dtb(const char *name, int id, const void *fdt,
				      int resources_node, size_t dtb_size)
{
	struct mk_instance *instance;
	struct kernfs_node *kn;
	struct mk_dt_config config;
	void *dtb_copy;
	int release_ret;
	int ret;
	int allocated_id;

	instance = kzalloc(sizeof(*instance), GFP_KERNEL);
	if (!instance)
		return -ENOMEM;

	instance->id = 0;
	instance->name = kstrdup(name, GFP_KERNEL);
	if (!instance->name) {
		ret = -ENOMEM;
		goto err_free_instance;
	}

	instance->cpus = mk_cpu_set_alloc();
	if (!instance->cpus) {
		ret = -ENOMEM;
		goto err_free_name;
	}

	mk_dt_config_init(&config);
	ret = mk_dt_parse_resources(fdt, resources_node, name, &config);
	if (ret) {
		pr_err("Failed to parse resources for instance '%s': %d\n", name, ret);
		goto err_free_cpumask;
	}

	INIT_LIST_HEAD(&instance->memory_regions);
	INIT_LIST_HEAD(&instance->list);
	init_rwsem(&instance->control_route_sem);
	instance->irq_route_cpu = MK_PHYS_CPU_INVALID;
	INIT_LIST_HEAD(&instance->pci_devices);
	mk_pci_lease_instance_init(instance);
	INIT_LIST_HEAD(&instance->platform_devices);
	kref_init(&instance->refcount);

	kn = kernfs_create_dir(mk_instances_kn, name, 0755, instance);
	if (IS_ERR(kn)) {
		ret = PTR_ERR(kn);
		pr_err("Failed to create kernfs directory for instance '%s': %d\n", name, ret);
		goto err_free_config;
	}
	instance->kn = kn;
	mk_instance_get(instance);

	/* Allocate instance ID early so resource reservation logs show correct ID */
	if (id == 0) {
		pr_err("Instance ID 0 is reserved for root instance\n");
		ret = -ENOMEM;
		goto err_remove_dir;
	}

	if (id < 0)
		allocated_id = idr_alloc(&mk_instance_idr, instance, 1, INT_MAX, GFP_KERNEL);
	else
		allocated_id = idr_alloc(&mk_instance_idr, instance, id, id + 1, GFP_KERNEL);

	if (allocated_id < 0) {
		pr_err("Failed to register instance '%s' in IDR: %d\n", name, allocated_id);
		ret = allocated_id;
		goto err_remove_dir;
	}

	instance->id = allocated_id;

	ret = mk_create_instance_files(instance);
	if (ret) {
		pr_err("Failed to create files for instance '%s': %d\n", name, ret);
		goto err_free_idr;
	}

	ret = mk_instance_reserve_resources(instance, &config);
	if (ret) {
		pr_err("Failed to reserve resources for instance '%s': %d\n", name, ret);
		goto err_free_resources;
	}

	ret = mk_dt_generate_instance_dtb(instance, &dtb_copy, &dtb_size);
	if (ret) {
		pr_err("Failed to generate DTB for instance '%s': %d\n", name, ret);
		goto err_free_resources;
	}

	instance->dtb_data = dtb_copy;
	instance->dtb_size = dtb_size;

	list_add_tail(&instance->list, &mk_instance_list);

	kernfs_activate(kn);
	mk_instance_set_state(instance, MK_STATE_READY);
	mk_dt_config_free(&config);

	return 0;

	kfree(instance->dtb_data);
	instance->dtb_data = NULL;
err_free_resources:
	release_ret = mk_instance_release_resources(instance);
	if (release_ret) {
		pr_crit("Retaining failed instance '%s' because PCI cleanup failed: %d\n",
			name, release_ret);
		list_add_tail(&instance->list, &mk_instance_list);
		kernfs_activate(kn);
		mk_instance_set_state(instance, MK_STATE_FAILED);
		mk_dt_config_free(&config);
		return release_ret;
	}
err_free_idr:
	idr_remove(&mk_instance_idr, instance->id);
err_remove_dir:
	kernfs_remove(kn);
	mk_instance_put(instance);
err_free_config:
	mk_dt_config_free(&config);
err_free_cpumask:
	mk_cpu_set_free(instance->cpus);
err_free_name:
	kfree(instance->name);
err_free_instance:
	kfree(instance);
	return ret;
}


/* Kernfs file operations */
static const struct kernfs_ops mk_id_ops = {
	.seq_show = id_seq_show,
};

static const struct kernfs_ops mk_status_ops = {
	.seq_show = status_seq_show,
};

static const struct kernfs_ops mk_stats_ops = {
	.seq_show = stats_seq_show,
};

/* Root-level device_tree operations */
static const struct kernfs_ops mk_root_device_tree_ops = {
	.seq_show = root_device_tree_seq_show,
	.write = root_device_tree_write,
	.atomic_write_len = SZ_1M,  /* Accept DTBs up to 1MB atomically */
};

/* Instance device_tree operations (read-only, binary) */
static const struct kernfs_ops mk_instance_device_tree_ops = {
	.read = instance_device_tree_read,
};

/**
 * Create instance attributes in kernfs
 */
static int mk_create_instance_files(struct mk_instance *instance)
{
	struct kernfs_node *kn;

	kn = __kernfs_create_file(instance->kn, "id", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &mk_id_ops, instance, NULL, NULL);
	if (IS_ERR(kn)) {
		pr_err("Failed to create id file for instance %s\n", instance->name);
		return PTR_ERR(kn);
	}

	kn = __kernfs_create_file(instance->kn, "status", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &mk_status_ops, instance, NULL, NULL);
	if (IS_ERR(kn)) {
		pr_err("Failed to create status file for instance %s\n", instance->name);
		return PTR_ERR(kn);
	}
	kn = __kernfs_create_file(instance->kn, "stats", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &mk_stats_ops, instance, NULL, NULL);
	if (IS_ERR(kn)) {
		pr_err("Failed to create stats file for instance %s\n", instance->name);
		return PTR_ERR(kn);
	}

	kn = __kernfs_create_file(instance->kn, "device_tree", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &mk_instance_device_tree_ops, instance, NULL, NULL);
	if (IS_ERR(kn)) {
		pr_err("Failed to create device_tree file for instance %s\n", instance->name);
		return PTR_ERR(kn);
	}

	return 0;
}


static int mk_kernfs_mkdir(struct kernfs_node *parent, const char *name, umode_t mode)
{
	return -EPERM;
}


static int mk_kernfs_rmdir(struct kernfs_node *kn)
{
	return mk_overlay_rmdir(kn);
}

/**
 * mk_instance_destroy - Destroy a multikernel instance
 * @instance: Instance to destroy
 *
 * Removes the instance from the global list, IDR, and kernfs.
 * The instance must not be active or loading.
 *
 * When the instance is released (via mk_instance_put), all resources
 * (CPUs, memory, PCI devices) are automatically returned to the root
 * instance pool, making them available for future instance allocations.
 *
 * Caller must hold mk_instance_mutex.
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_instance_destroy(struct mk_instance *instance)
{
	int ret;

	lockdep_assert_held(&mk_instance_mutex);

	if (!instance) {
		pr_err("NULL instance passed to mk_instance_destroy\n");
		return -EINVAL;
	}

	if (instance->state == MK_STATE_ACTIVE) {
		pr_err("Cannot remove active instance '%s' (ID: %d). Instance must be stopped first.\n",
		       instance->name, instance->id);
		return -EBUSY;
	}

	if (instance->state == MK_STATE_LOADED) {
		pr_err("Cannot remove instance '%s' (ID: %d) with loaded kernel. Unload it first.\n",
		       instance->name, instance->id);
		return -EBUSY;
	}

	ret = mk_instance_release_resources(instance);
	if (ret) {
		pr_crit("Cannot remove instance '%s' while PCI cleanup is unsafe: %d\n",
			instance->name, ret);
		mk_instance_set_state(instance, MK_STATE_FAILED);
		return ret;
	}

	list_del(&instance->list);
	idr_remove(&mk_instance_idr, instance->id);
	if (instance->kn) {
		kernfs_remove(instance->kn);
		instance->kn = NULL;
		mk_instance_put(instance);
	}
	mk_instance_put(instance);

	return 0;
}

/**
 * Filesystem operations implementation
 */

static int mk_init_fs_context(struct fs_context *fc)
{
	struct mk_fs_context *ctx;
	struct kernfs_fs_context *kfc;

	ctx = kzalloc(sizeof(struct mk_fs_context), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	kfc = &ctx->kfc;
	kfc->root = mk_kernfs_root;
	kfc->magic = MULTIKERNEL_MAGIC;
	fc->fs_private = ctx;
	fc->ops = &mk_fs_context_ops;
	fc->global = true;
	return 0;
}

static int mk_get_tree(struct fs_context *fc)
{
	int ret;

	ret = kernfs_get_tree(fc);
	if (ret)
		return ret;

	return 0;
}

static void mk_free_fs_context(struct fs_context *fc)
{
	struct mk_fs_context *ctx = fc->fs_private;

	if (ctx) {
		kernfs_free_fs_context(fc);
		kfree(ctx);
	}
	fc->fs_private = NULL;
}

static void mk_kill_sb(struct super_block *sb)
{
	kernfs_kill_sb(sb);
}

/**
 * Module initialization and cleanup
 */
int mk_kernfs_init(void)
{
	int ret;

	/* Create kernfs root with mkdir/rmdir support */
	mk_kernfs_root = kernfs_create_root(&mk_kernfs_syscall_ops,
					    KERNFS_ROOT_CREATE_DEACTIVATED,
					    NULL);
	if (IS_ERR(mk_kernfs_root)) {
		ret = PTR_ERR(mk_kernfs_root);
		pr_err("Failed to create multikernel kernfs root: %d\n", ret);
		return ret;
	}

	/* Get the root kernfs node */
	mk_root_kn = kernfs_root_to_node(mk_kernfs_root);

	/* Create instances subdirectory */
	mk_instances_kn = kernfs_create_dir(mk_root_kn, "instances", 0755, NULL);
	if (IS_ERR(mk_instances_kn)) {
		ret = PTR_ERR(mk_instances_kn);
		pr_err("Failed to create instances directory: %d\n", ret);
		kernfs_destroy_root(mk_kernfs_root);
		return ret;
	}

	struct kernfs_node *device_tree_kn = __kernfs_create_file(mk_root_kn, "device_tree", 0644,
								   GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
								   SZ_1M,  /* 1MB prealloc for large DTBs */
								   &mk_root_device_tree_ops, NULL, NULL, NULL);
	if (IS_ERR(device_tree_kn)) {
		ret = PTR_ERR(device_tree_kn);
		pr_err("Failed to create root device_tree file: %d\n", ret);
		kernfs_destroy_root(mk_kernfs_root);
		return ret;
	}

	/* Register the filesystem */
	ret = register_filesystem(&mk_fs_type);
	if (ret) {
		pr_err("Failed to register multikernel filesystem: %d\n", ret);
		kernfs_destroy_root(mk_kernfs_root);
		return ret;
	}

	/* Create a mount point in sysfs */
	ret = sysfs_create_mount_point(fs_kobj, "multikernel");
	if (ret) {
		pr_err("Failed to create multikernel mount point: %d\n", ret);
		unregister_filesystem(&mk_fs_type);
		kernfs_destroy_root(mk_kernfs_root);
		return ret;
	}

	ret = mk_overlay_init();
	if (ret < 0) {
		pr_warn("Failed to initialize overlay support: %d\n", ret);
		/* Continue without overlay support - this is not fatal */
	}

	/* Activate the kernfs root */
	kernfs_activate(mk_root_kn);

	pr_info("Multikernel filesystem initialized. Mount with: mount -t multikernel none /sys/fs/multikernel\n");
	return 0;
}

void mk_kernfs_cleanup(void)
{
	struct mk_instance *instance, *tmp;

	/* Remove all instances */
	mutex_lock(&mk_instance_mutex);
	list_for_each_entry_safe(instance, tmp, &mk_instance_list, list) {
		list_del(&instance->list);
		idr_remove(&mk_instance_idr, instance->id);
		mk_instance_put(instance);
	}
	mutex_unlock(&mk_instance_mutex);

	/* Clean up IDR */
	idr_destroy(&mk_instance_idr);

	/* Free host kernel DTB */
	mutex_lock(&mk_host_dtb_mutex);
	kfree(root_instance->dtb_data);
	root_instance->dtb_data = NULL;
	root_instance->dtb_size = 0;
	mutex_unlock(&mk_host_dtb_mutex);

	/* Remove sysfs mount point */
	sysfs_remove_mount_point(fs_kobj, "multikernel");

	/* Unregister filesystem */
	unregister_filesystem(&mk_fs_type);

	/* Remove kernfs directory */
	if (mk_root_kn) {
		kernfs_remove(mk_root_kn);
		mk_root_kn = NULL;
	}

	/* Destroy kernfs root */
	if (mk_kernfs_root) {
		kernfs_destroy_root(mk_kernfs_root);
		mk_kernfs_root = NULL;
	}

	pr_info("Multikernel filesystem cleaned up\n");
}
