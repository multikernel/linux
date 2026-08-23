// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * Multikernel Device Tree Overlay Support
 *
 * Provides /sys/fs/multikernel/overlays/ for dynamic resource adjustments
 * via Device Tree overlays. Each overlay is tracked as an independent
 * transaction that can be applied and rolled back atomically.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>
#include <linux/numa.h>
#include <linux/pci.h>
#include <linux/sort.h>
#include <linux/kstrtox.h>
#include <linux/multikernel.h>
#include "internal.h"

/*
 * Parse a cpu@N node's reg property into a physical CPU ID. Accepts either
 * one 64-bit cell or one 32-bit cell.
 */
static int mk_overlay_parse_cpu_reg(const void *fdt, int item_node,
				    const char *name, mk_phys_cpu_t *cpu_id)
{
	const void *reg;
	int len;

	reg = fdt_getprop(fdt, item_node, "reg", &len);
	if (!reg || (len != sizeof(fdt32_t) && len != sizeof(fdt64_t))) {
		pr_err("Invalid reg property in %s\n", name);
		return -EINVAL;
	}

	if (len == sizeof(fdt64_t))
		*cpu_id = fdt64_to_cpu(*(const fdt64_t *)reg);
	else
		*cpu_id = fdt32_to_cpu(*(const fdt32_t *)reg);

	return 0;
}

/* Transaction status */
enum mk_overlay_tx_status {
	MK_OVERLAY_TX_PENDING = 0,
	MK_OVERLAY_TX_APPLIED,
	MK_OVERLAY_TX_FAILED,
	MK_OVERLAY_TX_REMOVED,
};

/* Overlay transaction descriptor */
struct mk_overlay_tx {
	int id;                          /* Transaction ID (user-facing) */
	enum mk_overlay_tx_status status;
	char target_path[128];           /* Target path of the first fragment */
	char resources[256];             /* Affected resources description */
	void *dtbo_data;                 /* Copy of original overlay blob */
	size_t dtbo_size;                /* Size of overlay blob */
	struct kernfs_node *dir_kn;      /* Kernfs directory node */
	struct list_head list;           /* Link in global transaction list */
};

struct kernfs_node *mk_overlay_root_kn;          /* /sys/fs/multikernel/overlays */
static LIST_HEAD(mk_overlay_tx_list);            /* List of all transactions */
/*
 * Serializes every user-driven reconfiguration of this kernel's resources:
 * the transaction list, overlay application and rollback, and the baseline
 * write in kernfs.c. Two writers would otherwise run pool moves at once.
 */
DEFINE_MUTEX(mk_overlay_mutex);
static atomic_t mk_overlay_next_id = ATOMIC_INIT(1); /* Next transaction ID */

/* Forward declarations */
static ssize_t mk_overlay_new_write(struct kernfs_open_file *of, char *buf,
				     size_t nbytes, loff_t off);

/**
 * Status to string conversion
 */
static const char *mk_overlay_status_str(enum mk_overlay_tx_status status)
{
	switch (status) {
	case MK_OVERLAY_TX_PENDING:
		return "pending";
	case MK_OVERLAY_TX_APPLIED:
		return "applied";
	case MK_OVERLAY_TX_FAILED:
		return "failed";
	case MK_OVERLAY_TX_REMOVED:
		return "removed";
	default:
		return "unknown";
	}
}

/**
 * Transaction attribute file operations
 */

/* tx_XXX/id */
static int tx_id_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct mk_overlay_tx *tx = of->kn->priv;

	if (!tx)
		return -EINVAL;
	seq_printf(sf, "%d\n", tx->id);
	return 0;
}

/* tx_XXX/status */
static int tx_status_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct mk_overlay_tx *tx = of->kn->priv;

	if (!tx)
		return -EINVAL;
	seq_printf(sf, "%s\n", mk_overlay_status_str(tx->status));
	return 0;
}

/* tx_XXX/instance */
static int tx_instance_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct mk_overlay_tx *tx = of->kn->priv;

	if (!tx)
		return -EINVAL;
	seq_printf(sf, "%s\n", tx->target_path);
	return 0;
}

/* tx_XXX/resources */
static int tx_resources_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct mk_overlay_tx *tx = of->kn->priv;

	if (!tx)
		return -EINVAL;
	seq_printf(sf, "%s\n", tx->resources);
	return 0;
}

/* tx_XXX/dtbo - binary attribute */
static ssize_t tx_dtbo_read(struct kernfs_open_file *of, char *buf,
			     size_t nbytes, loff_t off)
{
	struct mk_overlay_tx *tx = of->kn->priv;

	if (!tx || !tx->dtbo_data)
		return -EINVAL;

	if (off >= tx->dtbo_size)
		return 0;

	if (off + nbytes > tx->dtbo_size)
		nbytes = tx->dtbo_size - off;

	memcpy(buf, (char *)tx->dtbo_data + off, nbytes);
	return nbytes;
}

static struct kernfs_ops tx_id_ops = {
	.seq_show = tx_id_seq_show,
};

static struct kernfs_ops tx_status_ops = {
	.seq_show = tx_status_seq_show,
};

static struct kernfs_ops tx_instance_ops = {
	.seq_show = tx_instance_seq_show,
};

static struct kernfs_ops tx_resources_ops = {
	.seq_show = tx_resources_seq_show,
};

static struct kernfs_ops tx_dtbo_ops = {
	.read = tx_dtbo_read,
};

static struct kernfs_ops mk_overlay_new_ops = {
	.write = mk_overlay_new_write,
};

/*
 * Overlay format
 *
 * A transaction is a device tree overlay with any number of fragments.
 * Each fragment names what it modifies with the standard target-path
 * property and carries its operations under __overlay__:
 *
 *   fragment@0 {
 *     target-path = "/resources";		the pool this kernel manages
 *     __overlay__ {
 *       memory-add    { memory@0 { size = <u64>; numa-node-id = <u32>; }; };
 *       memory-remove { memory@0 { reg = <u64 base, u64 size>; }; };
 *       cpu-add       { cpu@0 { reg = <u64 cpuid>; }; };
 *       cpu-remove    { cpu@0 { reg = <u64 cpuid>; }; };
 *       device-add    { pci@0 { pci-id = "DDDD:BB:SS.F"; }; };
 *       device-remove { pci@0 { pci-id = "DDDD:BB:SS.F"; }; };
 *     };
 *   };
 *
 *   fragment@1 {
 *     target-path = "/instances/db";		an existing instance
 *     __overlay__ {
 *       memory-add    { memory@0 { reg = <u64 base, u64 size>; numa-node-id = <u32>; }; };
 *       memory-remove { memory@0 { reg = <u64 base, u64 size>; }; };
 *       cpu-add       { cpu@0 { reg = <u64 cpuid>; numa-node-id = <u32>; }; };
 *       cpu-remove    { cpu@0 { reg = <u64 cpuid>; }; };
 *       device-add    { pci@0 { pci-id = "DDDD:BB:SS.F"; driver = "vfio-pci"; }; };
 *       device-remove { pci@0 { pci-id = "DDDD:BB:SS.F"; }; };
 *     };
 *   };
 *
 *   fragment@2 {
 *     target-path = "/instances";		the instance namespace
 *     __overlay__ {
 *       instance-create { instance-name = "db"; id = <N>; resources { ... }; };
 *       instance-remove { instance-name = "db"; };
 *     };
 *   };
 *
 * Operation names read from the target's point of view: under /resources,
 * cpu-add hands a CPU of this kernel to the pool and cpu-remove takes a
 * free pool CPU back.
 *
 * Fragments are processed in ascending unit-address order. Within a
 * fragment the order is instance-create, memory-remove, memory-add,
 * cpu-remove, cpu-add, device-remove, device-add, instance-remove, so
 * that a resource is released by its source before its destination
 * acquires it. A /resources fragment moves memory-remove after
 * cpu-remove and device-remove instead, so resources leave the pool as
 * CPU, device, memory and join it as memory, CPU, device: the host park
 * area lives in pool memory and cannot be released until the pool CPUs
 * that run on it have come back, so a single fragment that returns the
 * CPUs and removes the last chunk has to do the CPUs first. Rollback
 * walks both orders in reverse.
 */

#define MK_OVERLAY_POOL_PATH		"/resources"
#define MK_OVERLAY_INSTANCES_PATH	"/instances"
#define MK_OVERLAY_INSTANCE_PREFIX	"/instances/"

enum mk_overlay_target_kind {
	MK_OVERLAY_TARGET_POOL,
	MK_OVERLAY_TARGET_INSTANCE,
	MK_OVERLAY_TARGET_INSTANCES,
};

struct mk_overlay_target {
	enum mk_overlay_target_kind kind;
	const char *path;
	struct mk_instance *instance;
};

#define MK_OVERLAY_FRAGMENT_PREFIX	"fragment@"
#define MK_OVERLAY_FRAGMENT_PREFIX_LEN	(sizeof(MK_OVERLAY_FRAGMENT_PREFIX) - 1)

struct mk_overlay_fragment {
	u32 unit;
	int node;
};

static int mk_overlay_fragment_cmp(const void *a, const void *b)
{
	const struct mk_overlay_fragment *x = a;
	const struct mk_overlay_fragment *y = b;

	if (x->unit == y->unit)
		return 0;

	return x->unit < y->unit ? -1 : 1;
}

/**
 * mk_overlay_collect_fragments - Gather fragment@N nodes in unit-address order
 * @fdt: Overlay blob
 * @out: Receives the caller-freed array of fragments
 *
 * Returns the number of fragments, or a negative error code.
 */
static int mk_overlay_collect_fragments(const void *fdt,
					struct mk_overlay_fragment **out)
{
	struct mk_overlay_fragment *frags;
	int node, n = 0;

	fdt_for_each_subnode(node, fdt, 0) {
		const char *name = fdt_get_name(fdt, node, NULL);

		if (name && !strncmp(name, MK_OVERLAY_FRAGMENT_PREFIX,
				     MK_OVERLAY_FRAGMENT_PREFIX_LEN))
			n++;
	}

	if (!n)
		return -EINVAL;

	frags = kcalloc(n, sizeof(*frags), GFP_KERNEL);
	if (!frags)
		return -ENOMEM;

	n = 0;
	fdt_for_each_subnode(node, fdt, 0) {
		const char *name = fdt_get_name(fdt, node, NULL);

		if (!name || strncmp(name, MK_OVERLAY_FRAGMENT_PREFIX,
				     MK_OVERLAY_FRAGMENT_PREFIX_LEN))
			continue;

		if (kstrtou32(name + MK_OVERLAY_FRAGMENT_PREFIX_LEN, 16,
			      &frags[n].unit)) {
			pr_err("Overlay: '%s' has no valid unit address\n", name);
			kfree(frags);
			return -EINVAL;
		}

		frags[n].node = node;
		n++;
	}

	sort(frags, n, sizeof(*frags), mk_overlay_fragment_cmp, NULL);
	*out = frags;
	return n;
}

/**
 * mk_overlay_parse_metadata - Extract display metadata from an overlay
 *
 * The transaction is described by the target path of its first fragment
 * and by the optional mk,resources string at the overlay root.
 */
static void mk_overlay_parse_metadata(struct mk_overlay_tx *tx, const void *fdt)
{
	struct mk_overlay_fragment *frags;
	const char *prop;
	int root_node, len, nr;

	strscpy(tx->target_path, "unknown", sizeof(tx->target_path));
	strscpy(tx->resources, "unknown", sizeof(tx->resources));

	if (fdt_check_header(fdt) != 0) {
		pr_warn("Invalid FDT header in overlay\n");
		return;
	}

	root_node = fdt_path_offset(fdt, "/");
	if (root_node < 0)
		return;

	prop = fdt_getprop(fdt, root_node, "mk,resources", &len);
	if (prop && len > 0)
		strscpy(tx->resources, prop, sizeof(tx->resources));

	nr = mk_overlay_collect_fragments(fdt, &frags);
	if (nr < 0)
		return;

	prop = fdt_getprop(fdt, frags[0].node, "target-path", &len);
	if (prop && len > 0)
		strscpy(tx->target_path, prop, sizeof(tx->target_path));

	kfree(frags);
}

static int mk_overlay_resolve_target(struct mk_overlay_tx *tx, const void *fdt,
				     int fragment, struct mk_overlay_target *target)
{
	const char *path, *name;
	int len;

	path = fdt_getprop(fdt, fragment, "target-path", &len);
	if (!path || len <= 0 || path[len - 1] != '\0') {
		pr_err("Overlay tx%d: fragment without a valid target-path\n",
		       tx->id);
		return -EINVAL;
	}

	target->path = path;
	target->instance = NULL;

	if (!strcmp(path, MK_OVERLAY_POOL_PATH)) {
		if (!mk_cpu_pool) {
			pr_err("Overlay tx%d: this kernel manages no pool, %s is not a valid target\n",
			       tx->id, path);
			return -EPERM;
		}
		target->kind = MK_OVERLAY_TARGET_POOL;
		return 0;
	}

	if (!strcmp(path, MK_OVERLAY_INSTANCES_PATH)) {
		target->kind = MK_OVERLAY_TARGET_INSTANCES;
		return 0;
	}

	if (strncmp(path, MK_OVERLAY_INSTANCE_PREFIX,
		    strlen(MK_OVERLAY_INSTANCE_PREFIX))) {
		pr_err("Overlay tx%d: unsupported target-path '%s'\n",
		       tx->id, path);
		return -EINVAL;
	}

	name = path + strlen(MK_OVERLAY_INSTANCE_PREFIX);
	if (!*name || strchr(name, '/')) {
		pr_err("Overlay tx%d: '%s' does not name an instance\n",
		       tx->id, path);
		return -EINVAL;
	}

	mutex_lock(&mk_instance_mutex);
	target->instance = mk_instance_find_by_name(name);
	mutex_unlock(&mk_instance_mutex);

	if (!target->instance) {
		pr_err("Overlay tx%d: instance '%s' not found\n", tx->id, name);
		return -ENOENT;
	}

	target->kind = MK_OVERLAY_TARGET_INSTANCE;
	return 0;
}

static const char *mk_overlay_target_name(const struct mk_overlay_target *target)
{
	if (target->kind == MK_OVERLAY_TARGET_INSTANCE)
		return target->instance->name;

	return target->path;
}

static int mk_overlay_check_resource_target(struct mk_overlay_tx *tx,
					    const struct mk_overlay_target *target,
					    const char *op_name)
{
	if (target->kind == MK_OVERLAY_TARGET_INSTANCES) {
		pr_err("Overlay tx%d: %s is not a resource holder, %s rejected\n",
		       tx->id, target->path, op_name);
		return -EINVAL;
	}

	return 0;
}

static int mk_overlay_check_namespace_target(struct mk_overlay_tx *tx,
					     const struct mk_overlay_target *target,
					     const char *op_name)
{
	if (target->kind != MK_OVERLAY_TARGET_INSTANCES) {
		pr_err("Overlay tx%d: %s belongs under %s, not %s\n",
		       tx->id, op_name, MK_OVERLAY_INSTANCES_PATH, target->path);
		return -EINVAL;
	}

	return 0;
}

/* reg = <u64 base, u64 size>, stored as four big-endian cells */
static int mk_overlay_parse_mem_reg(const void *fdt, int item_node,
				    const char *name, u64 *base, u64 *size)
{
	const fdt32_t *reg;
	int len;

	reg = fdt_getprop(fdt, item_node, "reg", &len);
	if (!reg || len != 4 * (int)sizeof(fdt32_t)) {
		pr_err("Invalid reg property in %s\n", name);
		return -EINVAL;
	}

	*base = ((u64)fdt32_to_cpu(reg[0]) << 32) | fdt32_to_cpu(reg[1]);
	*size = ((u64)fdt32_to_cpu(reg[2]) << 32) | fdt32_to_cpu(reg[3]);
	return 0;
}

static int mk_overlay_parse_mem_size(const void *fdt, int item_node,
				     const char *name, u64 *size)
{
	const fdt32_t *prop;
	int len;

	prop = fdt_getprop(fdt, item_node, "size", &len);
	if (!prop || len != 2 * (int)sizeof(fdt32_t)) {
		pr_err("Invalid size property in %s\n", name);
		return -EINVAL;
	}

	*size = ((u64)fdt32_to_cpu(prop[0]) << 32) | fdt32_to_cpu(prop[1]);
	if (!*size || !PAGE_ALIGNED(*size)) {
		pr_err("%s: size 0x%llx is not a positive page multiple\n",
		       name, *size);
		return -EINVAL;
	}

	return 0;
}

static int mk_overlay_parse_numa(const void *fdt, int item_node,
				 const char *name, int *node)
{
	const fdt32_t *prop;
	int len;

	*node = NUMA_NO_NODE;

	prop = fdt_getprop(fdt, item_node, "numa-node-id", &len);
	if (!prop)
		return 0;

	if (len != (int)sizeof(fdt32_t)) {
		pr_err("Invalid numa-node-id property in %s\n", name);
		return -EINVAL;
	}

	if (fdt32_to_cpu(*prop) >= MAX_NUMNODES) {
		pr_err("%s: numa-node-id %u out of range\n", name,
		       fdt32_to_cpu(*prop));
		return -EINVAL;
	}

	*node = (int)fdt32_to_cpu(*prop);
	return 0;
}

static u32 mk_overlay_parse_u32(const void *fdt, int item_node,
				const char *prop_name)
{
	const fdt32_t *prop;
	int len;

	prop = fdt_getprop(fdt, item_node, prop_name, &len);
	if (!prop || len != (int)sizeof(fdt32_t))
		return 0;

	return fdt32_to_cpu(*prop);
}

static int mk_overlay_parse_pci_id(const void *fdt, int item_node,
				   const char *name, u16 *domain, u8 *bus,
				   u8 *devfn)
{
	const char *pci_id_str;
	u8 slot, func;
	int len, ret;

	pci_id_str = fdt_getprop(fdt, item_node, "pci-id", &len);
	if (!pci_id_str || len <= 0 || pci_id_str[len - 1] != '\0') {
		pr_err("Invalid pci-id property in %s\n", name);
		return -EINVAL;
	}

	ret = mk_pci_parse_bdf(pci_id_str, len, domain, bus, &slot, &func);
	if (ret) {
		pr_err("Invalid or out-of-range pci-id '%s'\n", pci_id_str);
		return ret;
	}

	*devfn = PCI_DEVFN(slot, func);
	return 0;
}

/**
 * mk_overlay_op_memory_add - Apply or undo a memory-add operation
 * @undo: Send the inverse operation instead of the operation itself
 *
 * A pool item requests a size, since the pool picks the base; an
 * instance item names the range explicitly.
 */
static int mk_overlay_op_memory_add(struct mk_overlay_tx *tx, const void *fdt,
				    int op_node,
				    const struct mk_overlay_target *target,
				    bool undo)
{
	const char *verb = undo ? "Rollback" : "Overlay";
	int item_node, ret;

	ret = mk_overlay_check_resource_target(tx, target, "memory-add");
	if (ret)
		return ret;

	fdt_for_each_subnode(item_node, fdt, op_node) {
		const char *name = fdt_get_name(fdt, item_node, NULL);
		u64 base, size;
		int node, len;

		if (!name || strncmp(name, "memory@", 7))
			continue;

		ret = mk_overlay_parse_numa(fdt, item_node, name, &node);
		if (ret)
			return ret;

		if (target->kind == MK_OVERLAY_TARGET_POOL) {
			if (fdt_getprop(fdt, item_node, "reg", &len)) {
				pr_err("Overlay tx%d: %s adds pool memory by size, not by reg\n",
				       tx->id, name);
				return -EINVAL;
			}

			ret = mk_overlay_parse_mem_size(fdt, item_node, name,
							&size);
			if (ret)
				return ret;

			/*
			 * The pool chose the base at grow time and the
			 * overlay never recorded it, so the chunk cannot
			 * be identified for a shrink.
			 */
			if (undo) {
				pr_warn("Rollback tx%d: cannot release the %llu MB the pool grew by\n",
					tx->id, size >> 20);
				continue;
			}

			pr_info("Overlay tx%d: +memory %llu MB numa=%d -> %s\n",
				tx->id, size >> 20, node, target->path);

			ret = mk_pool_mem_grow(size, node, NULL);
			if (ret) {
				pr_err("Failed to grow the pool by %llu MB: %d\n",
				       size >> 20, ret);
				return ret;
			}
			continue;
		}

		ret = mk_overlay_parse_mem_reg(fdt, item_node, name, &base,
					       &size);
		if (ret)
			return ret;

		pr_info("%s tx%d: %cmemory 0x%llx-0x%llx (%llu MB) numa=%d %s %s\n",
			verb, tx->id, undo ? '-' : '+', base, base + size - 1,
			size >> 20, node, undo ? "from" : "->",
			target->instance->name);

		if (undo)
			ret = mk_send_mem_remove(target->instance->id,
						 base >> PAGE_SHIFT,
						 size >> PAGE_SHIFT);
		else
			ret = mk_send_mem_add(target->instance->id,
					      base >> PAGE_SHIFT,
					      size >> PAGE_SHIFT, (u32)node,
					      mk_overlay_parse_u32(fdt, item_node,
								   "mem-type"));
		if (ret < 0) {
			pr_err("Failed to send memory IPI: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

/*
 * Take one chunk out of the pool. The host park area is pool memory, so
 * the chunk holding it only comes out once every pool CPU is home, and
 * whatever memory the pool has left has to host the area again: nothing
 * else would rebuild it until the pool next grows.
 */
static int mk_overlay_pool_mem_remove(struct mk_overlay_tx *tx, u64 base,
				      u64 size)
{
	int ret;

	/*
	 * Only a chunk the park area is pinning gets a teardown, so a range
	 * that matches no chunk at all never costs the pool its park area.
	 */
	ret = mk_pool_mem_shrink(base, size);
	if (ret != -EBUSY || !mk_host_park_uses(base, size)) {
		if (ret)
			pr_err("Failed to resize the pool: %d\n", ret);
		return ret;
	}

	ret = mk_teardown_host_park();
	if (ret) {
		pr_err("Overlay tx%d: chunk 0x%llx+0x%llx holds the host park area; return every pool CPU first (%d)\n",
		       tx->id, base, size, ret);
		return ret;
	}

	ret = mk_pool_mem_shrink(base, size);
	if (ret) {
		pr_err("Failed to resize the pool: %d\n", ret);
		/* The chunk stayed, so the pool must get its park area back */
		if (mk_setup_host_park())
			pr_err("Overlay tx%d: the host park area could not be rebuilt; a memory-add will retry\n",
			       tx->id);
		return ret;
	}

	ret = mk_setup_host_park();
	if (ret == -ENODEV)		/* nothing left to park in */
		return 0;
	if (ret)
		pr_err("Overlay tx%d: chunk removed but the host park area could not be rebuilt (%d); a memory-add will retry\n",
		       tx->id, ret);

	return ret;
}

/**
 * mk_overlay_op_memory_remove - Apply or undo a memory-remove operation
 * @undo: Send the inverse operation instead of the operation itself
 */
static int mk_overlay_op_memory_remove(struct mk_overlay_tx *tx, const void *fdt,
				       int op_node,
				       const struct mk_overlay_target *target,
				       bool undo)
{
	const char *verb = undo ? "Rollback" : "Overlay";
	int item_node, ret;

	ret = mk_overlay_check_resource_target(tx, target, "memory-remove");
	if (ret)
		return ret;

	fdt_for_each_subnode(item_node, fdt, op_node) {
		const char *name = fdt_get_name(fdt, item_node, NULL);
		u64 base, size;
		int node;

		if (!name || strncmp(name, "memory@", 7))
			continue;

		ret = mk_overlay_parse_mem_reg(fdt, item_node, name, &base,
					       &size);
		if (ret)
			return ret;

		ret = mk_overlay_parse_numa(fdt, item_node, name, &node);
		if (ret)
			return ret;

		if (target->kind == MK_OVERLAY_TARGET_POOL) {
			if (undo) {
				/*
				 * Only the capacity can be restored: the
				 * kernel has since handed the old range
				 * back to the buddy allocator. A host park
				 * area torn down below is rebuilt inside
				 * the new chunk by the grow itself.
				 */
				pr_info("Rollback tx%d: regrowing the pool by %llu MB\n",
					tx->id, size >> 20);
				ret = mk_pool_mem_grow(size, node, NULL);
				if (ret) {
					pr_err("Failed to resize the pool: %d\n",
					       ret);
					return ret;
				}
				continue;
			}

			pr_info("Overlay tx%d: -memory 0x%llx-0x%llx (%llu MB) from %s\n",
				tx->id, base, base + size - 1, size >> 20,
				target->path);

			ret = mk_overlay_pool_mem_remove(tx, base, size);
			if (ret)
				return ret;
			continue;
		}

		pr_info("%s tx%d: %cmemory 0x%llx-0x%llx (%llu MB) %s %s\n",
			verb, tx->id, undo ? '+' : '-', base, base + size - 1,
			size >> 20, undo ? "->" : "from",
			target->instance->name);

		if (undo)
			ret = mk_send_mem_add(target->instance->id,
					      base >> PAGE_SHIFT,
					      size >> PAGE_SHIFT, (u32)node,
					      mk_overlay_parse_u32(fdt, item_node,
								   "mem-type"));
		else
			ret = mk_send_mem_remove(target->instance->id,
						 base >> PAGE_SHIFT,
						 size >> PAGE_SHIFT);
		if (ret < 0) {
			pr_err("Failed to send memory IPI: %d\n", ret);
			return ret;
		}
	}

	return 0;
}

/**
 * mk_overlay_op_cpu - Move the CPUs listed under a cpu-add or cpu-remove node
 * @give: True to hand the CPUs to the target, false to take them back
 * @undo: True while rolling the transaction back, for the log line
 */
static int mk_overlay_op_cpu(struct mk_overlay_tx *tx, const void *fdt,
			     int op_node, const struct mk_overlay_target *target,
			     bool give, bool undo)
{
	const char *verb = undo ? "Rollback" : "Overlay";
	int item_node, ret;

	ret = mk_overlay_check_resource_target(tx, target, "cpu operation");
	if (ret)
		return ret;

	fdt_for_each_subnode(item_node, fdt, op_node) {
		const char *name = fdt_get_name(fdt, item_node, NULL);
		mk_phys_cpu_t cpu_id;
		int node;
		u32 flags;

		if (!name || strncmp(name, "cpu@", 4))
			continue;

		ret = mk_overlay_parse_cpu_reg(fdt, item_node, name, &cpu_id);
		if (ret)
			return ret;

		ret = mk_overlay_parse_numa(fdt, item_node, name, &node);
		if (ret)
			return ret;

		flags = mk_overlay_parse_u32(fdt, item_node, "flags");

		pr_info("%s tx%d: %ccpu %llu numa=%d %s %s\n",
			verb, tx->id, give ? '+' : '-', cpu_id, node,
			give ? "->" : "from", mk_overlay_target_name(target));

		if (target->kind == MK_OVERLAY_TARGET_POOL)
			ret = give ? mk_pool_cpu_add(cpu_id) :
				     mk_pool_cpu_remove(cpu_id, (u32)node, flags);
		else if (give)
			ret = mk_send_cpu_add(target->instance->id, cpu_id,
					      (u32)node, flags);
		else
			ret = mk_send_cpu_remove(target->instance->id, cpu_id);

		if (ret < 0) {
			pr_err("Failed to move CPU %llu: %d\n", cpu_id, ret);
			return ret;
		}
	}

	return 0;
}

/**
 * mk_overlay_op_device - Move the devices listed under a device-* node
 * @give: True to hand the devices to the target, false to take them back
 * @undo: True while rolling the transaction back, for the log line
 */
static int mk_overlay_op_device(struct mk_overlay_tx *tx, const void *fdt,
				int op_node,
				const struct mk_overlay_target *target,
				bool give, bool undo)
{
	const char *verb = undo ? "Rollback" : "Overlay";
	int item_node, ret;

	ret = mk_overlay_check_resource_target(tx, target, "device operation");
	if (ret)
		return ret;

	fdt_for_each_subnode(item_node, fdt, op_node) {
		const char *name = fdt_get_name(fdt, item_node, NULL);
		const char *driver;
		u16 domain;
		u8 bus, devfn;
		u32 flags;
		int len;

		if (!name || strncmp(name, "pci@", 4))
			continue;

		ret = mk_overlay_parse_pci_id(fdt, item_node, name, &domain,
					      &bus, &devfn);
		if (ret)
			return ret;

		driver = fdt_getprop(fdt, item_node, "driver", &len);
		flags = mk_overlay_parse_u32(fdt, item_node, "flags");

		if (target->kind == MK_OVERLAY_TARGET_POOL)
			pr_info("%s tx%d: %cdevice %04x:%02x:%02x.%x %s %s\n",
				verb, tx->id, give ? '+' : '-', domain, bus,
				PCI_SLOT(devfn), PCI_FUNC(devfn),
				give ? "->" : "from",
				mk_overlay_target_name(target));
		else
			pr_info("%s tx%d: %cdevice %04x:%02x:%02x.%x driver=%s %s %s\n",
				verb, tx->id, give ? '+' : '-', domain, bus,
				PCI_SLOT(devfn), PCI_FUNC(devfn),
				driver ? driver : "none", give ? "->" : "from",
				mk_overlay_target_name(target));

		if (target->kind == MK_OVERLAY_TARGET_POOL)
			ret = give ? mk_pool_device_add(domain, bus, devfn) :
				     mk_pool_device_remove(domain, bus, devfn,
							   NULL, 0);
		else if (give)
			ret = mk_send_device_add(target->instance->id, domain,
						 bus, devfn, driver, flags);
		else
			ret = mk_send_device_remove(target->instance->id,
						    domain, bus, devfn);

		if (ret < 0) {
			pr_err("Failed to move device %04x:%02x:%02x.%x: %d\n",
			       domain, bus, PCI_SLOT(devfn), PCI_FUNC(devfn),
			       ret);
			return ret;
		}
	}

	return 0;
}

/**
 * mk_overlay_instance_name - Read and validate an instance-name property
 *
 * Returns the name, or NULL after logging why it is unusable.
 */
static const char *mk_overlay_instance_name(struct mk_overlay_tx *tx,
					    const void *fdt, int op_node,
					    const char *verb, const char *op_name)
{
	const char *name;
	int len;

	name = fdt_getprop(fdt, op_node, "instance-name", &len);
	if (!name || len <= 0 || name[len - 1] != '\0' || !name[0]) {
		pr_err("%s tx%d: %s requires a valid 'instance-name'\n",
		       verb, tx->id, op_name);
		return NULL;
	}

	if (strchr(name, '/')) {
		pr_err("%s tx%d: instance name '%s' must not contain '/'\n",
		       verb, tx->id, name);
		return NULL;
	}

	return name;
}

static int mk_overlay_op_instance_create(struct mk_overlay_tx *tx,
					 const void *fdt, int op_node,
					 const struct mk_overlay_target *target)
{
	const char *instance_name;
	const fdt32_t *id_prop;
	int resources_node;
	int instance_id;
	int len, ret;

	ret = mk_overlay_check_namespace_target(tx, target, "instance-create");
	if (ret)
		return ret;

	instance_name = mk_overlay_instance_name(tx, fdt, op_node, "Overlay",
						 "instance-create");
	if (!instance_name)
		return -EINVAL;

	id_prop = fdt_getprop(fdt, op_node, "id", &len);
	instance_id = (id_prop && len == (int)sizeof(fdt32_t)) ?
		      (int)fdt32_to_cpu(*id_prop) : -1;

	resources_node = fdt_subnode_offset(fdt, op_node, "resources");
	if (resources_node < 0) {
		pr_err("Overlay tx%d: instance-create requires a 'resources' subnode\n",
		       tx->id);
		return -EINVAL;
	}

	mutex_lock(&mk_instance_mutex);

	if (mk_instance_find_by_name(instance_name)) {
		mutex_unlock(&mk_instance_mutex);
		pr_err("Overlay tx%d: instance '%s' already exists\n",
		       tx->id, instance_name);
		return -EEXIST;
	}

	if (instance_id >= 0 && idr_find(&mk_instance_idr, instance_id)) {
		mutex_unlock(&mk_instance_mutex);
		pr_err("Overlay tx%d: instance ID %d is already in use\n",
		       tx->id, instance_id);
		return -EEXIST;
	}

	pr_info("Overlay tx%d: Creating instance '%s'\n", tx->id, instance_name);

	ret = mk_create_instance_from_dtb(instance_name, instance_id, fdt,
					  resources_node, tx->dtbo_size);
	mutex_unlock(&mk_instance_mutex);

	if (ret) {
		pr_err("Overlay tx%d: Failed to create instance '%s': %d\n",
		       tx->id, instance_name, ret);
		return ret;
	}

	pr_info("Overlay tx%d: Instance '%s' created successfully\n",
		tx->id, instance_name);
	return 0;
}

static int mk_overlay_op_instance_remove(struct mk_overlay_tx *tx,
					 const void *fdt, int op_node,
					 const struct mk_overlay_target *target,
					 bool undo)
{
	const char *instance_name;
	struct mk_instance *instance;
	int ret;

	ret = mk_overlay_check_namespace_target(tx, target, "instance-remove");
	if (ret)
		return ret;

	instance_name = mk_overlay_instance_name(tx, fdt, op_node,
						 undo ? "Rollback" : "Overlay",
						 "instance-remove");
	if (!instance_name)
		return -EINVAL;

	/*
	 * Restoring a destroyed instance would need its whole configuration
	 * kept alive somewhere; user space re-creates it with a new overlay.
	 */
	if (undo) {
		pr_warn("Rollback tx%d: cannot restore removed instance '%s', apply an instance-create overlay\n",
			tx->id, instance_name);
		return 0;
	}

	mutex_lock(&mk_instance_mutex);
	instance = mk_instance_find_by_name(instance_name);
	if (!instance) {
		mutex_unlock(&mk_instance_mutex);
		pr_err("Overlay tx%d: instance '%s' not found\n",
		       tx->id, instance_name);
		return -ENOENT;
	}

	pr_info("Overlay tx%d: Removing instance '%s' (ID: %d)\n",
		tx->id, instance_name, instance->id);

	ret = mk_instance_destroy(instance);
	mutex_unlock(&mk_instance_mutex);

	if (ret < 0) {
		pr_err("Overlay tx%d: Failed to remove instance '%s': %d\n",
		       tx->id, instance_name, ret);
		return ret;
	}

	pr_info("Overlay tx%d: Instance '%s' removed successfully\n",
		tx->id, instance_name);
	return 0;
}

/* Undo of instance-create: destroy what the transaction created */
static int mk_overlay_undo_instance_create(struct mk_overlay_tx *tx,
					   const void *fdt, int op_node,
					   const struct mk_overlay_target *target)
{
	const char *instance_name;
	struct mk_instance *instance;
	int ret;

	ret = mk_overlay_check_namespace_target(tx, target, "instance-create");
	if (ret)
		return ret;

	instance_name = mk_overlay_instance_name(tx, fdt, op_node, "Rollback",
						 "instance-create");
	if (!instance_name)
		return -EINVAL;

	mutex_lock(&mk_instance_mutex);
	instance = mk_instance_find_by_name(instance_name);
	if (!instance) {
		mutex_unlock(&mk_instance_mutex);
		pr_warn("Rollback tx%d: instance '%s' is already gone\n",
			tx->id, instance_name);
		return 0;
	}

	pr_info("Rollback tx%d: Removing instance '%s' (ID: %d)\n",
		tx->id, instance_name, instance->id);
	ret = mk_instance_destroy(instance);
	mutex_unlock(&mk_instance_mutex);

	if (ret < 0)
		pr_err("Rollback tx%d: Failed to destroy instance '%s': %d\n",
		       tx->id, instance_name, ret);

	return ret;
}

static int mk_overlay_fragment_overlay_node(struct mk_overlay_tx *tx,
					    const void *fdt, int fragment,
					    const struct mk_overlay_target *target)
{
	int overlay_node;

	overlay_node = fdt_subnode_offset(fdt, fragment, "__overlay__");
	if (overlay_node < 0)
		pr_err("Overlay tx%d: fragment for %s has no __overlay__ node\n",
		       tx->id, target->path);

	return overlay_node;
}

enum mk_overlay_op {
	MK_OVERLAY_OP_INSTANCE_CREATE,
	MK_OVERLAY_OP_MEMORY_REMOVE,
	MK_OVERLAY_OP_MEMORY_ADD,
	MK_OVERLAY_OP_CPU_REMOVE,
	MK_OVERLAY_OP_CPU_ADD,
	MK_OVERLAY_OP_DEVICE_REMOVE,
	MK_OVERLAY_OP_DEVICE_ADD,
	MK_OVERLAY_OP_INSTANCE_REMOVE,
	MK_OVERLAY_OP_COUNT,
};

static const char * const mk_overlay_op_names[MK_OVERLAY_OP_COUNT] = {
	[MK_OVERLAY_OP_INSTANCE_CREATE]	= "instance-create",
	[MK_OVERLAY_OP_MEMORY_REMOVE]	= "memory-remove",
	[MK_OVERLAY_OP_MEMORY_ADD]	= "memory-add",
	[MK_OVERLAY_OP_CPU_REMOVE]	= "cpu-remove",
	[MK_OVERLAY_OP_CPU_ADD]		= "cpu-add",
	[MK_OVERLAY_OP_DEVICE_REMOVE]	= "device-remove",
	[MK_OVERLAY_OP_DEVICE_ADD]	= "device-add",
	[MK_OVERLAY_OP_INSTANCE_REMOVE]	= "instance-remove",
};

/* A resource is released by its source before its destination acquires it */
static const u8 mk_overlay_order[MK_OVERLAY_OP_COUNT] = {
	MK_OVERLAY_OP_INSTANCE_CREATE,
	MK_OVERLAY_OP_MEMORY_REMOVE,
	MK_OVERLAY_OP_MEMORY_ADD,
	MK_OVERLAY_OP_CPU_REMOVE,
	MK_OVERLAY_OP_CPU_ADD,
	MK_OVERLAY_OP_DEVICE_REMOVE,
	MK_OVERLAY_OP_DEVICE_ADD,
	MK_OVERLAY_OP_INSTANCE_REMOVE,
};

/*
 * The pool takes its memory back last: the host park area every pool CPU
 * runs on is pool memory, and it can only be released once the CPUs have
 * come home, so one fragment can empty the pool completely.
 */
static const u8 mk_overlay_pool_order[MK_OVERLAY_OP_COUNT] = {
	MK_OVERLAY_OP_INSTANCE_CREATE,
	MK_OVERLAY_OP_CPU_REMOVE,
	MK_OVERLAY_OP_DEVICE_REMOVE,
	MK_OVERLAY_OP_MEMORY_REMOVE,
	MK_OVERLAY_OP_MEMORY_ADD,
	MK_OVERLAY_OP_CPU_ADD,
	MK_OVERLAY_OP_DEVICE_ADD,
	MK_OVERLAY_OP_INSTANCE_REMOVE,
};

static int mk_overlay_run_op(struct mk_overlay_tx *tx, const void *fdt,
			     int overlay_node,
			     const struct mk_overlay_target *target,
			     enum mk_overlay_op op, bool undo)
{
	int op_node;

	op_node = fdt_subnode_offset(fdt, overlay_node, mk_overlay_op_names[op]);
	if (op_node < 0)
		return 0;

	switch (op) {
	case MK_OVERLAY_OP_INSTANCE_CREATE:
		if (undo)
			return mk_overlay_undo_instance_create(tx, fdt, op_node,
							       target);
		return mk_overlay_op_instance_create(tx, fdt, op_node, target);
	case MK_OVERLAY_OP_MEMORY_REMOVE:
		return mk_overlay_op_memory_remove(tx, fdt, op_node, target,
						   undo);
	case MK_OVERLAY_OP_MEMORY_ADD:
		return mk_overlay_op_memory_add(tx, fdt, op_node, target, undo);
	case MK_OVERLAY_OP_CPU_REMOVE:
		return mk_overlay_op_cpu(tx, fdt, op_node, target, undo, undo);
	case MK_OVERLAY_OP_CPU_ADD:
		return mk_overlay_op_cpu(tx, fdt, op_node, target, !undo, undo);
	case MK_OVERLAY_OP_DEVICE_REMOVE:
		return mk_overlay_op_device(tx, fdt, op_node, target, undo,
					    undo);
	case MK_OVERLAY_OP_DEVICE_ADD:
		return mk_overlay_op_device(tx, fdt, op_node, target, !undo,
					    undo);
	case MK_OVERLAY_OP_INSTANCE_REMOVE:
		return mk_overlay_op_instance_remove(tx, fdt, op_node, target,
						     undo);
	default:
		return -EINVAL;
	}
}

static int mk_overlay_walk_fragment(struct mk_overlay_tx *tx, const void *fdt,
				    int fragment, bool undo)
{
	struct mk_overlay_target target;
	const u8 *order;
	int overlay_node, i, ret;

	ret = mk_overlay_resolve_target(tx, fdt, fragment, &target);
	if (ret)
		return ret;

	overlay_node = mk_overlay_fragment_overlay_node(tx, fdt, fragment,
							&target);
	if (overlay_node < 0)
		return -EINVAL;

	order = target.kind == MK_OVERLAY_TARGET_POOL ? mk_overlay_pool_order
						      : mk_overlay_order;

	for (i = 0; i < MK_OVERLAY_OP_COUNT; i++) {
		enum mk_overlay_op op = undo ? order[MK_OVERLAY_OP_COUNT - 1 - i]
					     : order[i];

		ret = mk_overlay_run_op(tx, fdt, overlay_node, &target, op,
					undo);
		if (ret)
			return ret;
	}

	return 0;
}

static int mk_overlay_apply_fragment(struct mk_overlay_tx *tx, const void *fdt,
				     int fragment)
{
	return mk_overlay_walk_fragment(tx, fdt, fragment, false);
}

static int mk_overlay_rollback_fragment(struct mk_overlay_tx *tx,
					const void *fdt, int fragment)
{
	return mk_overlay_walk_fragment(tx, fdt, fragment, true);
}

/**
 * mk_overlay_parse_and_apply - Apply every fragment of a transaction
 *
 * Returns 0 on success, negative error code on failure.
 */
static int mk_overlay_parse_and_apply(struct mk_overlay_tx *tx, const void *fdt)
{
	struct mk_overlay_fragment *frags;
	int i, nr, ret = 0;

	nr = mk_overlay_collect_fragments(fdt, &frags);
	if (nr < 0) {
		pr_err("Overlay tx%d: no usable fragment@N node: %d\n",
		       tx->id, nr);
		return nr;
	}

	for (i = 0; i < nr; i++) {
		ret = mk_overlay_apply_fragment(tx, fdt, frags[i].node);
		if (ret)
			break;
	}

	kfree(frags);
	return ret;
}

/**
 * mk_overlay_parse_and_rollback - Undo every fragment of a transaction
 *
 * Fragments and the operations inside them are walked in reverse of the
 * apply order, so a resource is released before it is handed back.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int mk_overlay_parse_and_rollback(struct mk_overlay_tx *tx,
					 const void *fdt)
{
	struct mk_overlay_fragment *frags;
	int i, nr, ret = 0;

	nr = mk_overlay_collect_fragments(fdt, &frags);
	if (nr < 0) {
		pr_err("Rollback tx%d: no usable fragment@N node: %d\n",
		       tx->id, nr);
		return nr;
	}

	for (i = nr - 1; i >= 0; i--) {
		ret = mk_overlay_rollback_fragment(tx, fdt, frags[i].node);
		if (ret)
			break;
	}

	kfree(frags);
	return ret;
}

static int mk_overlay_create_tx_files(struct mk_overlay_tx *tx)
{
	struct kernfs_node *kn;

	kn = __kernfs_create_file(tx->dir_kn, "id", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &tx_id_ops, tx, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	kn = __kernfs_create_file(tx->dir_kn, "status", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &tx_status_ops, tx, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	kn = __kernfs_create_file(tx->dir_kn, "instance", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &tx_instance_ops, tx, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	kn = __kernfs_create_file(tx->dir_kn, "resources", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &tx_resources_ops, tx, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	kn = __kernfs_create_file(tx->dir_kn, "dtbo", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &tx_dtbo_ops, tx, NULL, NULL);
	if (IS_ERR(kn))
		return PTR_ERR(kn);

	return 0;
}

static int mk_overlay_apply(const void *dtbo_data, size_t dtbo_size)
{
	struct mk_overlay_tx *tx;
	int ret, tx_id;
	char tx_name[32];

	tx = kzalloc(sizeof(*tx), GFP_KERNEL);
	if (!tx)
		return -ENOMEM;

	tx->dtbo_data = kmemdup(dtbo_data, dtbo_size, GFP_KERNEL);
	if (!tx->dtbo_data) {
		kfree(tx);
		return -ENOMEM;
	}
	tx->dtbo_size = dtbo_size;

	tx_id = atomic_inc_return(&mk_overlay_next_id);
	tx->id = tx_id;
	tx->status = MK_OVERLAY_TX_PENDING;
	INIT_LIST_HEAD(&tx->list);

	mk_overlay_parse_metadata(tx, dtbo_data);

	pr_info("Applying overlay transaction %d (target=%s, resources=%s)\n",
		tx->id, tx->target_path, tx->resources);

	guard(mutex)(&mk_overlay_mutex);

	ret = mk_overlay_parse_and_apply(tx, dtbo_data);

	if (ret < 0) {
		pr_err("Failed to apply overlay transaction %d: %d\n", tx->id, ret);
		tx->status = MK_OVERLAY_TX_FAILED;
		/* Continue to create sysfs entry so user can see failure */
	} else {
		tx->status = MK_OVERLAY_TX_APPLIED;
		pr_info("Overlay transaction %d applied successfully\n", tx->id);
	}

	snprintf(tx_name, sizeof(tx_name), "tx_%d", tx->id);
	tx->dir_kn = kernfs_create_dir(mk_overlay_root_kn, tx_name, 0755, tx);
	if (IS_ERR(tx->dir_kn)) {
		ret = PTR_ERR(tx->dir_kn);
		pr_err("Failed to create kernfs directory for transaction %d: %d\n",
		       tx->id, ret);
		kfree(tx->dtbo_data);
		kfree(tx);
		return ret;
	}

	ret = mk_overlay_create_tx_files(tx);
	if (ret) {
		pr_err("Failed to create attribute files for transaction %d: %d\n",
		       tx->id, ret);
		kernfs_remove(tx->dir_kn);
		kfree(tx->dtbo_data);
		kfree(tx);
		return ret;
	}

	kernfs_activate(tx->dir_kn);

	list_add_tail(&tx->list, &mk_overlay_tx_list);

	return tx->id;
}

static int mk_overlay_remove_tx(struct mk_overlay_tx *tx)
{
	int ret = 0;

	lockdep_assert_held(&mk_overlay_mutex);

	pr_info("Removing overlay transaction %d\n", tx->id);

	ret = mk_overlay_parse_and_rollback(tx, tx->dtbo_data);

	if (ret < 0) {
		pr_err("Failed to rollback overlay transaction %d: %d\n", tx->id, ret);
		/* Continue with cleanup even if rollback failed */
	} else {
		pr_info("Overlay transaction %d rolled back successfully\n", tx->id);
	}

	tx->status = MK_OVERLAY_TX_REMOVED;

	list_del(&tx->list);
	/* The whole overlays directory goes away with the caller */
	kfree(tx->dtbo_data);
	kfree(tx);

	return 0;
}

/**
 * mk_overlay_new_write - Handle writes to /overlays/new
 *
 * User writes binary DTBO blob to this file to apply a new overlay.
 */
static ssize_t mk_overlay_new_write(struct kernfs_open_file *of, char *buf,
				     size_t nbytes, loff_t off)
{
	void *dtbo_copy;
	int ret;

	if (off != 0)
		return -EINVAL;

	if (nbytes == 0)
		return -EINVAL;

	if (nbytes > 1024 * 1024) { /* 1MB limit */
		pr_err("Overlay blob too large: %zu bytes\n", nbytes);
		return -EFBIG;
	}

	dtbo_copy = kmalloc(nbytes, GFP_KERNEL);
	if (!dtbo_copy)
		return -ENOMEM;

	memcpy(dtbo_copy, buf, nbytes);

	ret = fdt_check_header(dtbo_copy);
	if (ret != 0) {
		pr_err("Invalid overlay FDT header: %d\n", ret);
		kfree(dtbo_copy);
		return -EINVAL;
	}

	ret = mk_overlay_apply(dtbo_copy, nbytes);
	kfree(dtbo_copy);

	if (ret < 0)
		return ret;

	return nbytes;
}

/**
 * mk_overlay_rmdir - Roll a transaction back on rmdir of its directory
 * @kn: Directory the user is removing
 *
 * Called for every rmdir under /sys/fs/multikernel/; only the transaction
 * directories are removable, everything else keeps returning -EPERM.
 *
 * A rollback that fails leaves the transaction in place with status
 * "failed", so the user can see what happened and retry.
 */
int mk_overlay_rmdir(struct kernfs_node *kn)
{
	struct mk_overlay_tx *tx = kn->priv;
	struct kernfs_node *parent;
	bool is_tx;
	int ret;

	parent = kernfs_get_parent(kn);
	is_tx = parent && parent == mk_overlay_root_kn;
	kernfs_put(parent);

	if (!is_tx || !tx)
		return -EPERM;

	scoped_guard(mutex, &mk_overlay_mutex) {
		if (list_empty(&tx->list))
			return -ENOENT;

		pr_info("Removing overlay transaction %d\n", tx->id);

		ret = mk_overlay_parse_and_rollback(tx, tx->dtbo_data);
		if (ret < 0) {
			pr_err("Failed to rollback overlay transaction %d: %d\n",
			       tx->id, ret);
			tx->status = MK_OVERLAY_TX_FAILED;
			return ret;
		}

		pr_info("Overlay transaction %d rolled back successfully\n",
			tx->id);
		tx->status = MK_OVERLAY_TX_REMOVED;
		list_del_init(&tx->list);
	}

	/*
	 * Removes the directory this call runs from, which plain
	 * kernfs_remove() cannot do, and drains readers of the transaction's
	 * files before the transaction they point at goes away.
	 */
	kernfs_remove_self(kn);
	kfree(tx->dtbo_data);
	kfree(tx);

	return 0;
}

int mk_overlay_init(void)
{
	struct kernfs_node *kn;

	pr_info("Initializing multikernel overlay subsystem\n");

	if (!mk_root_kn) {
		pr_err("Multikernel root kernfs node not available\n");
		return -ENODEV;
	}

	mk_overlay_root_kn = kernfs_create_dir(mk_root_kn, "overlays", 0755, NULL);
	if (IS_ERR(mk_overlay_root_kn)) {
		pr_err("Failed to create overlays directory: %ld\n",
		       PTR_ERR(mk_overlay_root_kn));
		return PTR_ERR(mk_overlay_root_kn);
	}

	kn = __kernfs_create_file(mk_overlay_root_kn, "new", 0200,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &mk_overlay_new_ops, NULL, NULL, NULL);
	if (IS_ERR(kn)) {
		pr_err("Failed to create overlays/new file: %ld\n", PTR_ERR(kn));
		kernfs_remove(mk_overlay_root_kn);
		return PTR_ERR(kn);
	}

	pr_info("Multikernel overlay subsystem initialized\n");
	return 0;
}

void mk_overlay_exit(void)
{
	struct mk_overlay_tx *tx, *tmp;

	pr_info("Cleaning up multikernel overlay subsystem\n");

	mutex_lock(&mk_overlay_mutex);
	list_for_each_entry_safe(tx, tmp, &mk_overlay_tx_list, list) {
		mk_overlay_remove_tx(tx);
	}
	mutex_unlock(&mk_overlay_mutex);

	if (mk_overlay_root_kn) {
		kernfs_remove(mk_overlay_root_kn);
		mk_overlay_root_kn = NULL;
	}
}
