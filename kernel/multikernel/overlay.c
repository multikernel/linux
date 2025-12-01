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
#include <linux/pci.h>
#include <linux/multikernel.h>
#include "internal.h"

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
	char instance_name[64];          /* Affected instance name (for display) */
	char resources[256];             /* Affected resources description */
	void *dtbo_data;                 /* Copy of original overlay blob */
	size_t dtbo_size;                /* Size of overlay blob */
	struct kernfs_node *dir_kn;      /* Kernfs directory node */
	struct list_head list;           /* Link in global transaction list */
};

struct kernfs_node *mk_overlay_root_kn;          /* /sys/fs/multikernel/overlays */
static LIST_HEAD(mk_overlay_tx_list);            /* List of all transactions */
static DEFINE_MUTEX(mk_overlay_mutex);           /* Protects transaction list */
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
	seq_printf(sf, "%s\n", tx->instance_name);
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

/**
 * mk_overlay_parse_metadata - Extract metadata from overlay DTS
 *
 * Looks for special properties in the overlay:
 * - mk,instance: affected instance name
 * - mk,resources: resource description string
 */
static void mk_overlay_parse_metadata(struct mk_overlay_tx *tx, const void *fdt)
{
	const char *instance_name = NULL;
	int root_node, len;
	const char *prop;

	strcpy(tx->instance_name, "unknown");
	strcpy(tx->resources, "unknown");

	if (fdt_check_header(fdt) != 0) {
		pr_warn("Invalid FDT header in overlay\n");
		return;
	}

	root_node = fdt_path_offset(fdt, "/");
	if (root_node < 0)
		return;

	prop = fdt_getprop(fdt, root_node, "mk,instance", &len);
	if (prop && len > 0)
		instance_name = prop;

	prop = fdt_getprop(fdt, root_node, "mk,resources", &len);
	if (prop && len > 0) {
		strscpy(tx->resources, prop, sizeof(tx->resources));
	}

	int fragment_node = fdt_subnode_offset(fdt, root_node, "fragment-0");
	if (fragment_node >= 0) {
		int overlay_node = fdt_subnode_offset(fdt, fragment_node, "__overlay__");
		if (overlay_node >= 0) {
			prop = fdt_getprop(fdt, overlay_node, "mk,instance", &len);
			if (prop && len > 0)
				instance_name = prop;

			prop = fdt_getprop(fdt, overlay_node, "mk,resources", &len);
			if (prop && len > 0)
				strscpy(tx->resources, prop, sizeof(tx->resources));
		}
	}

	if (instance_name)
		strscpy(tx->instance_name, instance_name, sizeof(tx->instance_name));
}

static struct mk_instance *mk_overlay_get_instance_for_operation(
	int op_node, const void *fdt, const char *op_name, int tx_id)
{
	const char *instance_name;
	struct mk_instance *instance;
	int len;

	instance_name = fdt_getprop(fdt, op_node, "mk,instance", &len);
	if (!instance_name || len <= 0) {
		pr_err("Overlay tx%d: %s requires mk,instance property\n",
		       tx_id, op_name);
		return NULL;
	}

	mutex_lock(&mk_instance_mutex);
	instance = mk_instance_find_by_name(instance_name);
	mutex_unlock(&mk_instance_mutex);

	if (!instance) {
		pr_err("Overlay tx%d: %s instance '%s' not found\n",
		       tx_id, op_name, instance_name);
		return NULL;
	}

	return instance;
}

/**
 * mk_overlay_parse_and_apply - Parse overlay and send resource changes via IPI
 *
 * This function parses the Device Tree overlay and translates resource changes
 * into IPI messages sent to the target instances. The overlay is always applied
 * by the host/root kernel, which then sends IPIs to the appropriate instances
 * (including itself) based on mk,instance properties in each operation section.
 *
 * Instance Creation:
 *   - instance-create operation creates a new kernel instance from DTB definition
 *   - Must be processed first before any resource operations
 *   - Requires 'name' and 'id' properties, plus /instances/<name> node in overlay
 *
 * Each resource operation section MUST specify mk,instance to indicate which
 * kernel instance the operation targets.
 *
 * Operation Ordering (Create-Remove-Modify-Add-Destroy):
 * Operations are processed in this order to ensure clean resource migration:
 *   0. instance-create - Create new instance first (if specified)
 *   1. memory-remove   - Remove memory from source instance first
 *   2. memory-add      - Then add memory to destination instance
 *   3. cpu-remove      - Remove CPU from source instance first
 *   4. cpu-add         - Then add CPU to destination instance
 *   5. device-remove   - Remove PCI device from source instance first
 *   6. device-add      - Then add PCI device to destination instance
 *   7. instance-remove - Remove instance last (after all resources transferred)
 *
 * This ordering prevents race conditions where a resource could be owned by
 * two instances simultaneously. The source instance must cleanly release the
 * resource before the destination instance can acquire it.
 *
 * Overlay format:
 *   fragment@0/__overlay__/
 *     ├── instance-create { instance-name = "<name>"; id = <N>; resources { ... }; }
 *     ├── instance-remove { instance-name = "<name>"; }
 *     ├── memory-remove { mk,instance = "source"; region@N { reg = <addr size>; }; }
 *     ├── memory-add { mk,instance = "target"; region@N { reg = <addr size>; }; }
 *     ├── cpu-remove { mk,instance = "source"; cpu@N { reg = <cpuid>; }; }
 *     ├── cpu-add { mk,instance = "target"; cpu@N { reg = <cpuid>; numa-node = <N>; }; }
 *     ├── device-remove { mk,instance = "source"; pci@N { pci-id = "DDDD:BB:SS.F"; }; }
 *     └── device-add { mk,instance = "target"; pci@N { pci-id = "DDDD:BB:SS.F"; driver = "vfio-pci"; }; }
 *
 * Returns 0 on success, negative error code on failure.
 */
static int mk_overlay_parse_and_apply(struct mk_overlay_tx *tx,
				       const void *fdt)
{
	int ret = 0;
	int fragment_node, overlay_node;
	int op_node, item_node;
	const fdt32_t *reg;
	const fdt32_t *numa;
	int len;

	/* Find fragment@0 */
	fragment_node = fdt_subnode_offset(fdt, 0, "fragment@0");
	if (fragment_node < 0) {
		pr_err("No fragment@0 found in overlay\n");
		return -EINVAL;
	}

	/* Find __overlay__ */
	overlay_node = fdt_subnode_offset(fdt, fragment_node, "__overlay__");
	if (overlay_node < 0) {
		pr_err("No __overlay__ found in fragment\n");
		return -EINVAL;
	}

	/* Process instance-create operations first (must happen before any resource operations) */
	op_node = fdt_subnode_offset(fdt, overlay_node, "instance-create");
	if (op_node >= 0) {
		const fdt32_t *id_prop;
		const char *instance_name;
		int resources_node;
		u32 instance_id;

		instance_name = fdt_getprop(fdt, op_node, "instance-name", &len);
		if (!instance_name || len <= 0) {
			pr_err("Overlay tx%d: instance-create requires 'instance-name' property\n", tx->id);
			return -EINVAL;
		}

		id_prop = fdt_getprop(fdt, op_node, "id", &len);
		if (id_prop && len >= 4) {
			instance_id = fdt32_to_cpu(*id_prop);
		} else {
			instance_id = -1;
		}

		resources_node = fdt_subnode_offset(fdt, op_node, "resources");
		if (resources_node < 0) {
			pr_err("Overlay tx%d: instance-create requires 'resources' subnode\n", tx->id);
			return -EINVAL;
		}

		mutex_lock(&mk_instance_mutex);

		if (mk_instance_find_by_name(instance_name)) {
			mutex_unlock(&mk_instance_mutex);
			pr_err("Overlay tx%d: instance '%s' already exists\n", tx->id, instance_name);
			return -EEXIST;
		}

		if (instance_id >= 0 && idr_find(&mk_instance_idr, instance_id)) {
			mutex_unlock(&mk_instance_mutex);
			pr_err("Overlay tx%d: instance ID %u is already in use\n", tx->id, instance_id);
			pr_err("Overlay tx%d: Use a different ID or omit the 'id' property for auto-allocation\n", tx->id);
			return -EEXIST;
		}

		if (instance_id >= 0) {
			pr_info("Overlay tx%d: Creating instance '%s' (ID: %u)\n",
				tx->id, instance_name, instance_id);
		} else {
			pr_info("Overlay tx%d: Creating instance '%s' (ID: auto-allocated)\n",
				tx->id, instance_name);
		}

		ret = mk_create_instance_from_dtb(instance_name, instance_id,
						  fdt, resources_node, tx->dtbo_size);
		mutex_unlock(&mk_instance_mutex);

		if (ret) {
			pr_err("Overlay tx%d: Failed to create instance '%s': %d\n",
			       tx->id, instance_name, ret);
			return ret;
		}

		pr_info("Overlay tx%d: Instance '%s' created successfully\n",
			tx->id, instance_name);
	}

	op_node = fdt_subnode_offset(fdt, overlay_node, "memory-remove");
	if (op_node >= 0) {
		struct mk_instance *remove_instance;

		remove_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "memory-remove", tx->id);
		if (!remove_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);

			if (strncmp(name, "region@", 7) != 0)
				continue;

			reg = fdt_getprop(fdt, item_node, "reg", &len);
			if (!reg || len < 16) {
				pr_err("Invalid reg property in %s\n", name);
				return -EINVAL;
			}

			u64 addr = ((u64)fdt32_to_cpu(reg[0]) << 32) | fdt32_to_cpu(reg[1]);
			u64 size = ((u64)fdt32_to_cpu(reg[2]) << 32) | fdt32_to_cpu(reg[3]);
			u64 start_pfn = addr >> PAGE_SHIFT;
			u64 nr_pages = size >> PAGE_SHIFT;

			pr_info("Overlay tx%d: -memory 0x%llx-0x%llx (%llu MB) from %s\n",
				tx->id, addr, addr + size - 1, size >> 20,
				remove_instance->name);

			ret = mk_send_mem_remove(remove_instance->id, start_pfn, nr_pages);
			if (ret < 0) {
				pr_err("Failed to send mem_remove IPI: %d\n", ret);
				return ret;
			}
		}
	}

	op_node = fdt_subnode_offset(fdt, overlay_node, "memory-add");
	if (op_node >= 0) {
		struct mk_instance *add_instance;

		add_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "memory-add", tx->id);
		if (!add_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);

			if (strncmp(name, "region@", 7) != 0)
				continue;

			/* Get memory region: reg = <addr-hi addr-lo size-hi size-lo> */
			reg = fdt_getprop(fdt, item_node, "reg", &len);
			if (!reg || len < 16) {
				pr_err("Invalid reg property in %s\n", name);
				return -EINVAL;
			}

			u64 addr = ((u64)fdt32_to_cpu(reg[0]) << 32) | fdt32_to_cpu(reg[1]);
			u64 size = ((u64)fdt32_to_cpu(reg[2]) << 32) | fdt32_to_cpu(reg[3]);
			u64 start_pfn = addr >> PAGE_SHIFT;
			u64 nr_pages = size >> PAGE_SHIFT;

			/* Get optional numa-node */
			u32 numa_node = 0;
			numa = fdt_getprop(fdt, item_node, "numa-node", &len);
			if (numa && len >= 4)
				numa_node = fdt32_to_cpu(*numa);

			/* Get optional mem-type */
			u32 mem_type = 0;
			const fdt32_t *type = fdt_getprop(fdt, item_node, "mem-type", &len);
			if (type && len >= 4)
				mem_type = fdt32_to_cpu(*type);

			pr_info("Overlay tx%d: +memory 0x%llx-0x%llx (%llu MB) numa=%u -> %s\n",
				tx->id, addr, addr + size - 1, size >> 20,
				numa_node, add_instance->name);

			ret = mk_send_mem_add(add_instance->id, start_pfn, nr_pages,
					      numa_node, mem_type);
			if (ret < 0) {
				pr_err("Failed to send mem_add IPI: %d\n", ret);
				return ret;
			}
		}
	}

	op_node = fdt_subnode_offset(fdt, overlay_node, "cpu-remove");
	if (op_node >= 0) {
		struct mk_instance *remove_instance;

		remove_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "cpu-remove", tx->id);
		if (!remove_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);

			if (strncmp(name, "cpu@", 4) != 0)
				continue;

			reg = fdt_getprop(fdt, item_node, "reg", &len);
			if (!reg || len < 4) {
				pr_err("Invalid reg property in %s\n", name);
				return -EINVAL;
			}

			u32 cpu_id = fdt32_to_cpu(*reg);

			pr_info("Overlay tx%d: -cpu %u from %s\n",
				tx->id, cpu_id, remove_instance->name);

			ret = mk_send_cpu_remove(remove_instance->id, cpu_id);
			if (ret < 0) {
				pr_err("Failed to send cpu_remove IPI: %d\n", ret);
				return ret;
			}
		}
	}

	op_node = fdt_subnode_offset(fdt, overlay_node, "cpu-add");
	if (op_node >= 0) {
		struct mk_instance *add_instance;

		add_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "cpu-add", tx->id);
		if (!add_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);

			if (strncmp(name, "cpu@", 4) != 0)
				continue;

			/* Get CPU ID: reg = <cpuid> */
			reg = fdt_getprop(fdt, item_node, "reg", &len);
			if (!reg || len < 4) {
				pr_err("Invalid reg property in %s\n", name);
				return -EINVAL;
			}

			u32 cpu_id = fdt32_to_cpu(*reg);

			/* Get optional numa-node */
			u32 numa_node = 0;
			numa = fdt_getprop(fdt, item_node, "numa-node", &len);
			if (numa && len >= 4)
				numa_node = fdt32_to_cpu(*numa);

			/* Get optional flags */
			u32 flags = 0;
			const fdt32_t *flags_prop = fdt_getprop(fdt, item_node, "flags", &len);
			if (flags_prop && len >= 4)
				flags = fdt32_to_cpu(*flags_prop);

			pr_info("Overlay tx%d: +cpu %u numa=%u -> %s\n",
				tx->id, cpu_id, numa_node, add_instance->name);

			ret = mk_send_cpu_add(add_instance->id, cpu_id, numa_node, flags);
			if (ret < 0) {
				pr_err("Failed to send cpu_add IPI: %d\n", ret);
				return ret;
			}
		}
	}

	/* Process device-remove operations */
	op_node = fdt_subnode_offset(fdt, overlay_node, "device-remove");
	if (op_node >= 0) {
		struct mk_instance *remove_instance;

		remove_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "device-remove", tx->id);
		if (!remove_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);
			const char *pci_id_str;
			unsigned int domain, bus, slot, func;

			if (strncmp(name, "pci@", 4) != 0)
				continue;

			/* Get PCI ID: pci-id = "DDDD:BB:SS.F" */
			pci_id_str = fdt_getprop(fdt, item_node, "pci-id", &len);
			if (!pci_id_str) {
				pr_err("Invalid pci-id property in %s\n", name);
				return -EINVAL;
			}

			if (sscanf(pci_id_str, "%x:%x:%x.%x", &domain, &bus, &slot, &func) != 4) {
				pr_err("Invalid pci-id format '%s'\n", pci_id_str);
				return -EINVAL;
			}

			pr_info("Overlay tx%d: -device %04x:%02x:%02x.%x from %s\n",
				tx->id, domain, bus, slot, func, remove_instance->name);

			ret = mk_send_device_remove(remove_instance->id, domain, bus,
						    PCI_DEVFN(slot, func));
			if (ret < 0) {
				pr_err("Failed to send device_remove IPI: %d\n", ret);
				return ret;
			}
		}
	}

	/* Process device-add operations */
	op_node = fdt_subnode_offset(fdt, overlay_node, "device-add");
	if (op_node >= 0) {
		struct mk_instance *add_instance;

		add_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "device-add", tx->id);
		if (!add_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);
			const char *pci_id_str;
			const char *driver_name = NULL;
			unsigned int domain, bus, slot, func;
			u32 flags = 0;

			if (strncmp(name, "pci@", 4) != 0)
				continue;

			/* Get PCI ID: pci-id = "DDDD:BB:SS.F" */
			pci_id_str = fdt_getprop(fdt, item_node, "pci-id", &len);
			if (!pci_id_str) {
				pr_err("Invalid pci-id property in %s\n", name);
				return -EINVAL;
			}

			if (sscanf(pci_id_str, "%x:%x:%x.%x", &domain, &bus, &slot, &func) != 4) {
				pr_err("Invalid pci-id format '%s'\n", pci_id_str);
				return -EINVAL;
			}

			/* Get optional driver override */
			driver_name = fdt_getprop(fdt, item_node, "driver", &len);

			/* Get optional flags */
			const fdt32_t *flags_prop = fdt_getprop(fdt, item_node, "flags", &len);
			if (flags_prop && len >= 4)
				flags = fdt32_to_cpu(*flags_prop);

			pr_info("Overlay tx%d: +device %04x:%02x:%02x.%x driver=%s -> %s\n",
				tx->id, domain, bus, slot, func,
				driver_name ? driver_name : "none",
				add_instance->name);

			ret = mk_send_device_add(add_instance->id, domain, bus,
						 PCI_DEVFN(slot, func), driver_name, flags);
			if (ret < 0) {
				pr_err("Failed to send device_add IPI: %d\n", ret);
				return ret;
			}
		}
	}

	/* Process instance-remove operations last (after all resources have been migrated) */
	op_node = fdt_subnode_offset(fdt, overlay_node, "instance-remove");
	if (op_node >= 0) {
		const char *instance_name;
		struct mk_instance *instance;

		instance_name = fdt_getprop(fdt, op_node, "instance-name", &len);
		if (!instance_name || len <= 0) {
			pr_err("Overlay tx%d: instance-remove requires 'instance-name' property\n", tx->id);
			return -EINVAL;
		}

		mutex_lock(&mk_instance_mutex);
		instance = mk_instance_find_by_name(instance_name);
		if (!instance) {
			mutex_unlock(&mk_instance_mutex);
			pr_err("Overlay tx%d: instance '%s' not found\n", tx->id, instance_name);
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
	}

	return 0;
}

/**
 * mk_overlay_parse_and_rollback - Parse overlay and send reverse IPI operations
 *
 * This function rolls back an applied overlay by sending reverse operations
 * in REVERSE ORDER to maintain symmetry with the apply path.
 *
 * Normal apply order (Create-Remove-Modify-Add-Destroy):
 *   0. instance-create - Create new instance
 *   1. memory-remove from source
 *   2. memory-add to destination
 *   3. cpu-remove from source
 *   4. cpu-add to destination
 *   5. device-remove from source
 *   6. device-add to destination
 *   7. instance-remove - Remove instance
 *
 * Rollback order (must be exact reverse - Restore-Add-Modify-Remove-Destroy):
 *   1. instance-remove → re-create instance (undo instance-remove, restore instance)
 *   2. device-add → device-remove (undo device-add, remove from destination)
 *   3. device-remove → device-add (undo device-remove, add back to source)
 *   4. cpu-add → cpu-remove (undo cpu-add, remove from destination)
 *   5. cpu-remove → cpu-add (undo cpu-remove, add back to source)
 *   6. memory-add → memory-remove (undo memory-add, remove from destination)
 *   7. memory-remove → memory-add (undo memory-remove, add back to source)
 *   8. instance-create → destroy instance (undo instance-create, remove instance)
 *
 * This ordering ensures clean resource migration in reverse, preventing
 * race conditions and maintaining the same safety guarantees as the forward path.
 * Instance removal is done LAST to ensure all resources are returned first.
 * Instance re-creation is done FIRST to ensure the instance exists before resources are added back.
 *
 * Each operation section must have mk,instance property for rollback to work.
 */
static int mk_overlay_parse_and_rollback(struct mk_overlay_tx *tx,
					  const void *fdt)
{
	int ret = 0;
	int fragment_node, overlay_node;
	int op_node, item_node;
	const fdt32_t *reg;
	const fdt32_t *numa;
	int len;

	fragment_node = fdt_subnode_offset(fdt, 0, "fragment@0");
	if (fragment_node < 0) {
		pr_err("No fragment@0 found in overlay\n");
		return -EINVAL;
	}

	overlay_node = fdt_subnode_offset(fdt, fragment_node, "__overlay__");
	if (overlay_node < 0) {
		pr_err("No __overlay__ found in fragment\n");
		return -EINVAL;
	}

	/*
	 * STEP 1: Rollback instance-remove → re-create instance
	 * (Reverse of last operation in apply path)
	 * NOTE: Full rollback of instance-remove would require storing the instance's
	 * original configuration, which is complex. For now, we log a warning.
	 * The proper way to restore a removed instance is to apply a new overlay
	 * with instance-create that recreates it with the desired resources.
	 */
	op_node = fdt_subnode_offset(fdt, overlay_node, "instance-remove");
	if (op_node >= 0) {
		const char *instance_name;

		instance_name = fdt_getprop(fdt, op_node, "instance-name", &len);
		if (!instance_name || len <= 0) {
			pr_err("Rollback tx%d: instance-remove requires 'instance-name' property\n", tx->id);
			return -EINVAL;
		}

		pr_warn("Rollback tx%d: Cannot automatically restore removed instance '%s'\n",
			tx->id, instance_name);
		pr_warn("Rollback tx%d: To restore instance '%s', apply a new overlay with instance-create\n",
			tx->id, instance_name);
		/* Not a fatal error - continue with other rollback operations */
	}

	/*
	 * STEP 2: Rollback device-add → send device-remove
	 * (Reverse of sixth operation in apply path)
	 */
	op_node = fdt_subnode_offset(fdt, overlay_node, "device-add");
	if (op_node >= 0) {
		struct mk_instance *add_instance;

		add_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "device-add", tx->id);
		if (!add_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);
			const char *pci_id_str;
			unsigned int domain, bus, slot, func;

			if (strncmp(name, "pci@", 4) != 0)
				continue;

			pci_id_str = fdt_getprop(fdt, item_node, "pci-id", &len);
			if (!pci_id_str) {
				pr_err("Invalid pci-id property in %s\n", name);
				return -EINVAL;
			}

			if (sscanf(pci_id_str, "%x:%x:%x.%x", &domain, &bus, &slot, &func) != 4) {
				pr_err("Invalid pci-id format '%s'\n", pci_id_str);
				return -EINVAL;
			}

			pr_info("Rollback tx%d: -device %04x:%02x:%02x.%x from %s\n",
				tx->id, domain, bus, slot, func, add_instance->name);

			/* Send remove for what was added */
			ret = mk_send_device_remove(add_instance->id, domain, bus,
						    PCI_DEVFN(slot, func));
			if (ret < 0) {
				pr_err("Failed to send device_remove IPI for rollback: %d\n", ret);
				return ret;
			}
		}
	}

	/*
	 * STEP 3: Rollback device-remove → send device-add
	 * (Reverse of fifth operation in apply path)
	 */
	op_node = fdt_subnode_offset(fdt, overlay_node, "device-remove");
	if (op_node >= 0) {
		struct mk_instance *remove_instance;

		remove_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "device-remove", tx->id);
		if (!remove_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);
			const char *pci_id_str;
			const char *driver_name = NULL;
			unsigned int domain, bus, slot, func;
			u32 flags = 0;

			if (strncmp(name, "pci@", 4) != 0)
				continue;

			pci_id_str = fdt_getprop(fdt, item_node, "pci-id", &len);
			if (!pci_id_str) {
				pr_err("Invalid pci-id property in %s\n", name);
				return -EINVAL;
			}

			if (sscanf(pci_id_str, "%x:%x:%x.%x", &domain, &bus, &slot, &func) != 4) {
				pr_err("Invalid pci-id format '%s'\n", pci_id_str);
				return -EINVAL;
			}

			/* Get optional driver override */
			driver_name = fdt_getprop(fdt, item_node, "driver", &len);

			/* Get optional flags */
			const fdt32_t *flags_prop = fdt_getprop(fdt, item_node, "flags", &len);
			if (flags_prop && len >= 4)
				flags = fdt32_to_cpu(*flags_prop);

			pr_info("Rollback tx%d: +device %04x:%02x:%02x.%x driver=%s to %s\n",
				tx->id, domain, bus, slot, func,
				driver_name ? driver_name : "none",
				remove_instance->name);

			/* Send add for what was removed */
			ret = mk_send_device_add(remove_instance->id, domain, bus,
						 PCI_DEVFN(slot, func), driver_name, flags);
			if (ret < 0) {
				pr_err("Failed to send device_add IPI for rollback: %d\n", ret);
				return ret;
			}
		}
	}

	/*
	 * STEP 4: Rollback cpu-add → send cpu-remove
	 * (Reverse of fourth operation in apply path)
	 */
	op_node = fdt_subnode_offset(fdt, overlay_node, "cpu-add");
	if (op_node >= 0) {
		struct mk_instance *add_instance;

		add_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "cpu-add", tx->id);
		if (!add_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);

			if (strncmp(name, "cpu@", 4) != 0)
				continue;

			reg = fdt_getprop(fdt, item_node, "reg", &len);
			if (!reg || len < 4) {
				pr_err("Invalid reg property in %s\n", name);
				return -EINVAL;
			}

			u32 cpu_id = fdt32_to_cpu(*reg);

			pr_info("Rollback tx%d: -cpu %u from %s\n",
				tx->id, cpu_id, add_instance->name);

			/* Send remove for what was added */
			ret = mk_send_cpu_remove(add_instance->id, cpu_id);
			if (ret < 0) {
				pr_err("Failed to send cpu_remove IPI for rollback: %d\n", ret);
				return ret;
			}
		}
	}

	/*
	 * STEP 5: Rollback cpu-remove → send cpu-add
	 * (Reverse of third operation in apply path)
	 */
	op_node = fdt_subnode_offset(fdt, overlay_node, "cpu-remove");
	if (op_node >= 0) {
		struct mk_instance *remove_instance;

		remove_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "cpu-remove", tx->id);
		if (!remove_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);

			if (strncmp(name, "cpu@", 4) != 0)
				continue;

			reg = fdt_getprop(fdt, item_node, "reg", &len);
			if (!reg || len < 4) {
				pr_err("Invalid reg property in %s\n", name);
				return -EINVAL;
			}

			u32 cpu_id = fdt32_to_cpu(*reg);

			/* Get optional numa-node */
			u32 numa_node = 0;
			numa = fdt_getprop(fdt, item_node, "numa-node", &len);
			if (numa && len >= 4)
				numa_node = fdt32_to_cpu(*numa);

			/* Get optional flags */
			u32 flags = 0;
			const fdt32_t *flags_prop = fdt_getprop(fdt, item_node, "flags", &len);
			if (flags_prop && len >= 4)
				flags = fdt32_to_cpu(*flags_prop);

			pr_info("Rollback tx%d: +cpu %u numa=%u to %s\n",
				tx->id, cpu_id, numa_node, remove_instance->name);

			/* Send add for what was removed */
			ret = mk_send_cpu_add(remove_instance->id, cpu_id, numa_node, flags);
			if (ret < 0) {
				pr_err("Failed to send cpu_add IPI for rollback: %d\n", ret);
				return ret;
			}
		}
	}

	/*
	 * STEP 6: Rollback memory-add → send memory-remove
	 * (Reverse of second operation in apply path)
	 */
	op_node = fdt_subnode_offset(fdt, overlay_node, "memory-add");
	if (op_node >= 0) {
		struct mk_instance *add_instance;

		add_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "memory-add", tx->id);
		if (!add_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);

			if (strncmp(name, "region@", 7) != 0)
				continue;

			reg = fdt_getprop(fdt, item_node, "reg", &len);
			if (!reg || len < 16) {
				pr_err("Invalid reg property in %s\n", name);
				return -EINVAL;
			}

			u64 addr = ((u64)fdt32_to_cpu(reg[0]) << 32) | fdt32_to_cpu(reg[1]);
			u64 size = ((u64)fdt32_to_cpu(reg[2]) << 32) | fdt32_to_cpu(reg[3]);
			u64 start_pfn = addr >> PAGE_SHIFT;
			u64 nr_pages = size >> PAGE_SHIFT;

			pr_info("Rollback tx%d: -memory 0x%llx-0x%llx (%llu MB) from %s\n",
				tx->id, addr, addr + size - 1, size >> 20,
				add_instance->name);

			/* Send remove for what was added */
			ret = mk_send_mem_remove(add_instance->id, start_pfn, nr_pages);
			if (ret < 0) {
				pr_err("Failed to send mem_remove IPI for rollback: %d\n", ret);
				return ret;
			}
		}
	}

	/*
	 * STEP 7: Rollback memory-remove → send memory-add
	 * (Reverse of first operation in apply path)
	 */
	op_node = fdt_subnode_offset(fdt, overlay_node, "memory-remove");
	if (op_node >= 0) {
		struct mk_instance *remove_instance;

		remove_instance = mk_overlay_get_instance_for_operation(
			op_node, fdt, "memory-remove", tx->id);
		if (!remove_instance)
			return -EINVAL;

		fdt_for_each_subnode(item_node, fdt, op_node) {
			const char *name = fdt_get_name(fdt, item_node, NULL);

			if (strncmp(name, "region@", 7) != 0)
				continue;

			reg = fdt_getprop(fdt, item_node, "reg", &len);
			if (!reg || len < 16) {
				pr_err("Invalid reg property in %s\n", name);
				return -EINVAL;
			}

			u64 addr = ((u64)fdt32_to_cpu(reg[0]) << 32) | fdt32_to_cpu(reg[1]);
			u64 size = ((u64)fdt32_to_cpu(reg[2]) << 32) | fdt32_to_cpu(reg[3]);
			u64 start_pfn = addr >> PAGE_SHIFT;
			u64 nr_pages = size >> PAGE_SHIFT;

			/* Get optional numa-node */
			u32 numa_node = 0;
			numa = fdt_getprop(fdt, item_node, "numa-node", &len);
			if (numa && len >= 4)
				numa_node = fdt32_to_cpu(*numa);

			/* Get optional mem-type */
			u32 mem_type = 0;
			const fdt32_t *type = fdt_getprop(fdt, item_node, "mem-type", &len);
			if (type && len >= 4)
				mem_type = fdt32_to_cpu(*type);

			pr_info("Rollback tx%d: +memory 0x%llx-0x%llx (%llu MB) numa=%u to %s\n",
				tx->id, addr, addr + size - 1, size >> 20,
				numa_node, remove_instance->name);

			/* Send add for what was removed */
			ret = mk_send_mem_add(remove_instance->id, start_pfn, nr_pages,
					      numa_node, mem_type);
			if (ret < 0) {
				pr_err("Failed to send mem_add IPI for rollback: %d\n", ret);
				return ret;
			}
		}
	}

	/*
	 * STEP 8: Rollback instance-create → remove the instance
	 * (Reverse of zeroth operation in apply path - must be LAST)
	 */
	op_node = fdt_subnode_offset(fdt, overlay_node, "instance-create");
	if (op_node >= 0) {
		const char *instance_name;
		struct mk_instance *instance;

		instance_name = fdt_getprop(fdt, op_node, "instance-name", &len);
		if (!instance_name || len <= 0) {
			pr_err("Rollback tx%d: instance-create requires 'instance-name' property\n", tx->id);
			return -EINVAL;
		}

		mutex_lock(&mk_instance_mutex);
		instance = mk_instance_find_by_name(instance_name);
		if (!instance) {
			mutex_unlock(&mk_instance_mutex);
			pr_warn("Rollback tx%d: instance '%s' not found (may have been removed already)\n",
				tx->id, instance_name);
			return 0; /* Not a fatal error - instance already gone */
		}

		pr_info("Rollback tx%d: Removing instance '%s' (ID: %d)\n",
			tx->id, instance_name, instance->id);
		ret = mk_instance_destroy(instance);
		mutex_unlock(&mk_instance_mutex);

		if (ret < 0) {
			pr_err("Rollback tx%d: Failed to destroy instance '%s': %d\n",
			       tx->id, instance_name, ret);
			return ret;
		}

		pr_info("Rollback tx%d: Instance '%s' removed successfully\n",
			tx->id, instance_name);
	}

	return 0;
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

	pr_info("Applying overlay transaction %d (metadata: instance=%s, resources=%s)\n",
		tx->id, tx->instance_name, tx->resources);

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

	mutex_lock(&mk_overlay_mutex);
	list_add_tail(&tx->list, &mk_overlay_tx_list);
	mutex_unlock(&mk_overlay_mutex);

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
	/* Don't call kernfs_remove() here - the kernfs layer handles directory
	 * removal automatically after rmdir callback returns success */
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
 * mk_overlay_rmdir - Handle rmdir on transaction directories
 *
 * Called when user does: rmdir /sys/fs/multikernel/overlays/tx_XXX
 */
int mk_overlay_rmdir(struct kernfs_node *kn)
{
	struct mk_overlay_tx *tx = kn->priv;
	int ret;

	if (!tx) {
		pr_err("No transaction data found for kernfs node\n");
		return -EINVAL;
	}

	mutex_lock(&mk_overlay_mutex);

	if (list_empty(&tx->list)) {
		mutex_unlock(&mk_overlay_mutex);
		return -ENOENT;
	}
	ret = mk_overlay_remove_tx(tx);

	mutex_unlock(&mk_overlay_mutex);

	return ret;
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
