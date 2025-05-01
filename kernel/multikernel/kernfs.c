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
static struct kernfs_node *mk_root_kn;            /* Root kernfs node */
static struct kernfs_node *mk_instances_kn;       /* Instances subdirectory node */
LIST_HEAD(mk_instance_list);                      /* List of all instances */
DEFINE_MUTEX(mk_instance_mutex);                  /* Protects instance list */
DEFINE_IDR(mk_instance_idr);               /* ID allocator for instances */

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
static int mk_create_instance_from_dtb(const char *name, int id, const void *fdt,
				        int instance_node, size_t full_dtb_size);

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
	[MK_STATE_LOADING] = "loading",
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

/* Root-level device_tree attribute - handles full multikernel DTB upload */
static int root_device_tree_seq_show(struct seq_file *sf, void *v)
{
	if (root_instance->dtb_data) {
		const void *fdt = root_instance->dtb_data;
		int ret = fdt_check_header(fdt);
		if (ret) {
			seq_printf(sf, "/* Invalid device tree blob in root_instance: %d */\n", ret);
			return 0;
		}

		int instances_node = fdt_path_offset(fdt, "/instances");
		if (instances_node < 0) {
			seq_printf(sf, "/* No instances node found */\n");
			return 0;
		}

		/* Find the first (and should be only) instance in this DTB */
		int instance_node = fdt_first_subnode(fdt, instances_node);
		if (instance_node < 0) {
			seq_printf(sf, "/* No instance found */\n");
			return 0;
		}

		const char *instance_name = fdt_get_name(fdt, instance_node, NULL);
		if (!instance_name) {
			seq_printf(sf, "/* Invalid instance name */\n");
			return 0;
		}

		/* Show the DTB with instance as root node */
		seq_printf(sf, "/dts-v1/;\n\n");
		seq_printf(sf, "/%s {\n", instance_name);
		seq_printf(sf, "\tcompatible = \"multikernel-v1\";\n");

		/* Display instance properties */
		int prop_offset = fdt_first_property_offset(fdt, instance_node);
		while (prop_offset >= 0) {
			const struct fdt_property *prop = fdt_get_property_by_offset(fdt, prop_offset, NULL);
			if (prop) {
				const char *prop_name = fdt_string(fdt, fdt32_to_cpu(prop->nameoff));
				int prop_len = fdt32_to_cpu(prop->len);

				if (prop_len == 4) {
					/* Assume it's a u32 */
					u32 val = fdt32_to_cpu(*(const fdt32_t *)prop->data);
					seq_printf(sf, "\t%s = <%u>;\n", prop_name, val);
				} else {
					/* For other types, show as hex */
					seq_printf(sf, "\t%s = [", prop_name);
					const u8 *data = (const u8 *)prop->data;
					for (int i = 0; i < prop_len; i++) {
						seq_printf(sf, "%02x", data[i]);
						if (i < prop_len - 1) seq_printf(sf, " ");
					}
					seq_printf(sf, "];\n");
				}
			}
			prop_offset = fdt_next_property_offset(fdt, prop_offset);
		}

		/* Display subnodes (like resources) */
		int subnode;
		fdt_for_each_subnode(subnode, fdt, instance_node) {
			const char *subnode_name = fdt_get_name(fdt, subnode, NULL);
			if (subnode_name) {
				seq_printf(sf, "\t%s {\n", subnode_name);

				/* Display subnode properties */
				prop_offset = fdt_first_property_offset(fdt, subnode);
				while (prop_offset >= 0) {
					const struct fdt_property *prop = fdt_get_property_by_offset(fdt, prop_offset, NULL);
					if (prop) {
						const char *prop_name = fdt_string(fdt, fdt32_to_cpu(prop->nameoff));
						int prop_len = fdt32_to_cpu(prop->len);

						if (prop_len == 4) {
							/* Assume it's a u32 */
							u32 val = fdt32_to_cpu(*(const fdt32_t *)prop->data);
							if (strcmp(prop_name, "memory-bytes") == 0) {
								seq_printf(sf, "\t\t%s = <0x%x>; // %u MB\n",
									   prop_name, val, val >> 20);
							} else {
								seq_printf(sf, "\t\t%s = <%u>;\n", prop_name, val);
							}
						} else {
							/* For other types, show as hex */
							seq_printf(sf, "\t\t%s = [", prop_name);
							const u8 *data = (const u8 *)prop->data;
							for (int i = 0; i < prop_len; i++) {
								seq_printf(sf, "%02x", data[i]);
								if (i < prop_len - 1) seq_printf(sf, " ");
							}
							seq_printf(sf, "];\n");
						}
					}
					prop_offset = fdt_next_property_offset(fdt, prop_offset);
				}

				seq_printf(sf, "\t};\n");
			}
		}

		if (root_instance->ipi_data) {
			seq_printf(sf, "\tipi-buffer {\n");
			seq_printf(sf, "\t\tphys-addr = <0x%llx>;\n",
				   (unsigned long long)root_instance->ipi_phys);
			seq_printf(sf, "\t\tpages = <%u>;\n", root_instance->ipi_pages);
			seq_printf(sf, "\t};\n");
		}

		seq_printf(sf, "};\n");
	} else {
		seq_printf(sf, "Write multikernel device tree here to propagate to instances\n");
	}
	return 0;
}

/* Instance device_tree_source attribute - shows instance-specific DTB (read-only) */
static int device_tree_source_seq_show(struct seq_file *sf, void *v)
{
	struct kernfs_open_file *of = sf->private;
	struct mk_instance *instance = of->kn->priv;

	if (!instance->dtb_data) {
		seq_printf(sf, "(no device tree loaded)\n");
		return 0;
	}

	/* Parse the instance DTB and show it with the instance as root */
	const void *fdt = instance->dtb_data;
	int ret = fdt_check_header(fdt);
	if (ret) {
		seq_printf(sf, "/* Invalid device tree blob: %d */\n", ret);
		return 0;
	}

	int instances_node = fdt_path_offset(fdt, "/instances");
	if (instances_node < 0) {
		seq_printf(sf, "/* No instances node found */\n");
		return 0;
	}

	/* Find the first (and should be only) instance in this per-instance DTB */
	int instance_node = fdt_first_subnode(fdt, instances_node);
	if (instance_node < 0) {
		seq_printf(sf, "/* No instance found */\n");
		return 0;
	}

	const char *instance_name = fdt_get_name(fdt, instance_node, NULL);
	if (!instance_name) {
		seq_printf(sf, "/* Invalid instance name */\n");
		return 0;
	}

	/* Show the DTB with instance as root node */
	seq_printf(sf, "/dts-v1/;\n\n");
	seq_printf(sf, "/%s {\n", instance_name);
	seq_printf(sf, "\tcompatible = \"multikernel-v1\";\n");

	/* Display instance properties */
	int prop_offset = fdt_first_property_offset(fdt, instance_node);
	while (prop_offset >= 0) {
		const struct fdt_property *prop = fdt_get_property_by_offset(fdt, prop_offset, NULL);
		if (prop) {
			const char *prop_name = fdt_string(fdt, fdt32_to_cpu(prop->nameoff));
			int prop_len = fdt32_to_cpu(prop->len);

			if (prop_len == 4) {
				/* Assume it's a u32 */
				u32 val = fdt32_to_cpu(*(const fdt32_t *)prop->data);
				seq_printf(sf, "\t%s = <%u>;\n", prop_name, val);
			} else {
				/* For other types, show as hex */
				seq_printf(sf, "\t%s = [", prop_name);
				const u8 *data = (const u8 *)prop->data;
				for (int i = 0; i < prop_len; i++) {
					seq_printf(sf, "%02x", data[i]);
					if (i < prop_len - 1) seq_printf(sf, " ");
				}
				seq_printf(sf, "];\n");
			}
		}
		prop_offset = fdt_next_property_offset(fdt, prop_offset);
	}

	/* Display subnodes (like resources) */
	int subnode;
	fdt_for_each_subnode(subnode, fdt, instance_node) {
		const char *subnode_name = fdt_get_name(fdt, subnode, NULL);
		if (subnode_name) {
			seq_printf(sf, "\t%s {\n", subnode_name);

			/* Display subnode properties */
			prop_offset = fdt_first_property_offset(fdt, subnode);
			while (prop_offset >= 0) {
				const struct fdt_property *prop = fdt_get_property_by_offset(fdt, prop_offset, NULL);
				if (prop) {
					const char *prop_name = fdt_string(fdt, fdt32_to_cpu(prop->nameoff));
					int prop_len = fdt32_to_cpu(prop->len);

					if (prop_len == 4) {
						/* Assume it's a u32 */
						u32 val = fdt32_to_cpu(*(const fdt32_t *)prop->data);
						if (strcmp(prop_name, "memory-bytes") == 0) {
							seq_printf(sf, "\t\t%s = <0x%x>; // %u MB\n",
								   prop_name, val, val >> 20);
						} else {
							seq_printf(sf, "\t\t%s = <%u>;\n", prop_name, val);
						}
					} else {
						/* For other types, show as hex */
						seq_printf(sf, "\t\t%s = [", prop_name);
						const u8 *data = (const u8 *)prop->data;
						for (int i = 0; i < prop_len; i++) {
							seq_printf(sf, "%02x", data[i]);
							if (i < prop_len - 1) seq_printf(sf, " ");
						}
						seq_printf(sf, "];\n");
					}
				}
				prop_offset = fdt_next_property_offset(fdt, prop_offset);
			}

			seq_printf(sf, "\t};\n");
		}
	}

	seq_printf(sf, "};\n");
	return 0;
}

/* Root-level device_tree write - parses multikernel DTB and creates instances */
static ssize_t root_device_tree_write(struct kernfs_open_file *of, char *buf, size_t count, loff_t off)
{
	const void *fdt = buf;
	int instances_node, instance_node;
	const fdt32_t *id_prop;
	const char *instance_name;
	struct mk_instance *instance;
	int ret;

	pr_info("Loading multikernel device tree (%zu bytes)\n", count);

	/* Validate DTB header */
	ret = fdt_check_header(fdt);
	if (ret) {
		pr_err("Invalid device tree header: %d\n", ret);
		return -EINVAL;
	}

	/* Find /instances node */
	instances_node = fdt_path_offset(fdt, "/instances");
	if (instances_node < 0) {
		pr_err("No /instances node found in device tree\n");
		return -EINVAL;
	}

	mutex_lock(&mk_instance_mutex);

	/* Iterate through each instance in the DTB */
	fdt_for_each_subnode(instance_node, fdt, instances_node) {
		/* Get instance name */
		instance_name = fdt_get_name(fdt, instance_node, NULL);
		if (!instance_name) {
			pr_err("Failed to get instance name\n");
			continue;
		}

		/* Get instance ID */
		id_prop = fdt_getprop(fdt, instance_node, "id", NULL);
		if (!id_prop) {
			pr_err("No 'id' property found in instance '%s'\n", instance_name);
			continue;
		}

		/* Check if instance already exists */
		instance = mk_instance_find_by_name(instance_name);
		if (instance) {
			pr_info("Instance '%s' already exists, updating DTB\n", instance_name);
		} else {
			/* Create new instance */
			ret = mk_create_instance_from_dtb(instance_name, fdt32_to_cpu(*id_prop),
							  fdt, instance_node, count);
			if (ret) {
				pr_err("Failed to create instance '%s': %d\n", instance_name, ret);
				continue;
			}
		}
	}

	mutex_unlock(&mk_instance_mutex);

	pr_info("Successfully processed multikernel device tree\n");
	return count;
}

/* Helper function to extract instance DTB from a specific node */
static int mk_extract_instance_dtb_from_node(const void *fdt, int instance_node,
					      const char *instance_name,
					      void **instance_dtb, size_t *instance_size)
{
	void *new_fdt;
	int ret;
	size_t new_size = PAGE_SIZE;

	/* Create new DTB with just this instance */
	new_fdt = kmalloc(new_size, GFP_KERNEL);
	if (!new_fdt)
		return -ENOMEM;

	ret = fdt_create(new_fdt, new_size);
	ret |= fdt_finish_reservemap(new_fdt);
	ret |= fdt_begin_node(new_fdt, "");
	ret |= fdt_property_string(new_fdt, "compatible", "multikernel-v1");
	ret |= fdt_begin_node(new_fdt, "instances");

	/* Copy the instance node */
	ret |= fdt_begin_node(new_fdt, instance_name);

	/* Copy all properties from the instance node */
	int prop_offset = fdt_first_property_offset(fdt, instance_node);
	while (prop_offset >= 0) {
		const struct fdt_property *prop = fdt_get_property_by_offset(fdt, prop_offset, NULL);
		if (prop) {
			const char *prop_name = fdt_string(fdt, fdt32_to_cpu(prop->nameoff));
			ret |= fdt_property(new_fdt, prop_name, prop->data, fdt32_to_cpu(prop->len));
		}
		prop_offset = fdt_next_property_offset(fdt, prop_offset);
	}

	/* Copy all subnodes from the instance node (including resources) */
	int subnode;
	fdt_for_each_subnode(subnode, fdt, instance_node) {
		const char *subnode_name = fdt_get_name(fdt, subnode, NULL);
		if (!subnode_name)
			continue;

		ret |= fdt_begin_node(new_fdt, subnode_name);

		/* Copy all properties from the subnode */
		prop_offset = fdt_first_property_offset(fdt, subnode);
		while (prop_offset >= 0) {
			const struct fdt_property *prop = fdt_get_property_by_offset(fdt, prop_offset, NULL);
			if (prop) {
				const char *prop_name = fdt_string(fdt, fdt32_to_cpu(prop->nameoff));
				ret |= fdt_property(new_fdt, prop_name, prop->data, fdt32_to_cpu(prop->len));
			}
			prop_offset = fdt_next_property_offset(fdt, prop_offset);
		}

		ret |= fdt_end_node(new_fdt); /* end subnode */
	}
	ret |= fdt_end_node(new_fdt); /* end instance */
	ret |= fdt_end_node(new_fdt); /* end instances */
	ret |= fdt_end_node(new_fdt); /* end root */
	ret |= fdt_finish(new_fdt);

	if (ret) {
		pr_err("Failed to create instance DTB: %d\n", ret);
		kfree(new_fdt);
		return ret;
	}

	*instance_dtb = new_fdt;
	*instance_size = fdt_totalsize(new_fdt);

	return 0;
}

static int mk_create_instance_from_dtb(const char *name, int id, const void *fdt,
				       int instance_node, size_t full_dtb_size)
{
	struct mk_instance *instance;
	struct kernfs_node *kn;
	struct mk_dt_config config;
	void *instance_dtb;
	size_t instance_dtb_size;
	int ret;

	ret = mk_extract_instance_dtb_from_node(fdt, instance_node, name,
						&instance_dtb, &instance_dtb_size);
	if (ret) {
		pr_err("Failed to extract DTB for instance '%s': %d\n", name, ret);
		return ret;
	}

	instance = kzalloc(sizeof(*instance), GFP_KERNEL);
	if (!instance) {
		kfree(instance_dtb);
		return -ENOMEM;
	}

	instance->id = id;
	instance->name = kstrdup(name, GFP_KERNEL);
	if (!instance->name) {
		ret = -ENOMEM;
		goto cleanup_instance;
	}

	instance->state = MK_STATE_EMPTY;
	INIT_LIST_HEAD(&instance->list);
	INIT_LIST_HEAD(&instance->memory_regions);
	instance->region_count = 0;
	kref_init(&instance->refcount);

	instance->cpus = kzalloc(BITS_TO_LONGS(NR_CPUS) * sizeof(unsigned long), GFP_KERNEL);
	if (!instance->cpus) {
		ret = -ENOMEM;
		goto cleanup_instance_name;
	}

	/* Create kernfs directory under instances/ */
	kn = kernfs_create_dir(mk_instances_kn, name, 0755, instance);
	if (IS_ERR(kn)) {
		ret = PTR_ERR(kn);
		pr_err("Failed to create kernfs directory for instance '%s': %d\n", name, ret);
		goto cleanup_instance_name;
	}

	instance->kn = kn;

	/* Parse and validate the instance DTB */
	mk_dt_config_init(&config);
	ret = mk_dt_parse(instance_dtb, instance_dtb_size, &config);
	if (ret) {
		pr_err("Failed to parse DTB for instance '%s': %d\n", name, ret);
		goto cleanup_kernfs;
	}

	/* Reserve resources */
	ret = mk_instance_reserve_resources(instance, &config);
	if (ret) {
		pr_err("Failed to reserve resources for instance '%s': %d\n", name, ret);
		goto cleanup_config;
	}

	/* Store DTB data in instance */
	instance->dtb_data = instance_dtb;
	instance->dtb_size = instance_dtb_size;

	/* Create instance attribute files */
	ret = mk_create_instance_files(instance);
	if (ret) {
		pr_err("Failed to create attribute files for instance '%s': %d\n", name, ret);
		goto cleanup_config;
	}

	/* Store in IDR for quick lookup */
	ret = idr_alloc(&mk_instance_idr, instance, id, id + 1, GFP_KERNEL);
	if (ret < 0) {
		pr_err("Failed to allocate IDR slot %d for instance '%s': %d\n", id, name, ret);
		goto cleanup_config;
	}

	/* Add to global list */
	list_add_tail(&instance->list, &mk_instance_list);

	/* Update instance state */
	mk_instance_set_state(instance, MK_STATE_READY);

	/* Activate the kernfs node */
	kernfs_activate(kn);

	/* Clean up parsed config */
	mk_dt_config_free(&config);

	pr_info("Created instance '%s' (ID: %d) from multikernel DTB\n", name, id);
	return 0;

cleanup_config:
	mk_dt_config_free(&config);
cleanup_kernfs:
	kernfs_remove(kn);
cleanup_instance_name:
	kfree(instance->name);
cleanup_instance:
	kfree(instance);
	kfree(instance_dtb);
	return ret;
}


/* Kernfs file operations */
static const struct kernfs_ops mk_id_ops = {
	.seq_show = id_seq_show,
};

static const struct kernfs_ops mk_status_ops = {
	.seq_show = status_seq_show,
};

/* Root-level device_tree operations */
static const struct kernfs_ops mk_root_device_tree_ops = {
	.seq_show = root_device_tree_seq_show,
	.write = root_device_tree_write,
	.atomic_write_len = SZ_1M,  /* Accept DTBs up to 1MB atomically */
};

/* Instance device_tree_source operations (read-only) */
static const struct kernfs_ops mk_device_tree_source_ops = {
	.seq_show = device_tree_source_seq_show,
};


/**
 * Create instance attributes in kernfs
 */
static int mk_create_instance_files(struct mk_instance *instance)
{
	struct kernfs_node *kn;

	/* Create id file */
	kn = __kernfs_create_file(instance->kn, "id", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &mk_id_ops, instance, NULL, NULL);
	if (IS_ERR(kn)) {
		pr_err("Failed to create id file for instance %s\n", instance->name);
		return PTR_ERR(kn);
	}

	/* Create status file (read-only, managed by kernel) */
	kn = __kernfs_create_file(instance->kn, "status", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &mk_status_ops, instance, NULL, NULL);
	if (IS_ERR(kn)) {
		pr_err("Failed to create status file for instance %s\n", instance->name);
		return PTR_ERR(kn);
	}

	/* Create device_tree_source file (read-only) */
	kn = __kernfs_create_file(instance->kn, "device_tree_source", 0444,
				  GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, 0,
				  &mk_device_tree_source_ops, instance, NULL, NULL);
	if (IS_ERR(kn)) {
		pr_err("Failed to create device_tree_source file for instance %s\n", instance->name);
		return PTR_ERR(kn);
	}


	return 0;
}

/**
 * mk_kernfs_mkdir - Handle mkdir operations in multikernel kernfs
 * @parent: Parent kernfs node
 * @name: Directory name to create
 * @mode: Directory mode
 *
 * This function is called when user does: mkdir /sys/kernel/multikernel/my-kernel
 */
static int mk_kernfs_mkdir(struct kernfs_node *parent, const char *name, umode_t mode)
{
	/* Only allow mkdir under instances/ directory */
	if (parent != mk_instances_kn) {
		pr_err("Instances can only be created under /instances directory\n");
		return -EPERM;
	}

	/* Manual instance creation is now disabled - instances are created via device_tree upload */
	pr_err("Manual instance creation disabled. Upload multikernel device tree to /device_tree instead.\n");
	return -EPERM;
}

/**
 * mk_kernfs_rmdir - Handle rmdir operations in multikernel kernfs
 * @kn: Kernfs node to remove
 */
static int mk_kernfs_rmdir(struct kernfs_node *kn)
{
	struct mk_instance *instance = kn->priv;

	if (!instance) {
		pr_err("No instance data found for kernfs node\n");
		return -EINVAL;
	}

	mutex_lock(&mk_instance_mutex);

	/* Check if instance is active - prevent removal of active instances */
	if (instance->state == MK_STATE_ACTIVE) {
		mutex_unlock(&mk_instance_mutex);
		pr_err("Cannot remove active instance '%s' (ID: %d). Instance must be stopped first.\n",
		       instance->name, instance->id);
		return -EBUSY;
	}

	/* Check if instance is currently loading - also prevent removal */
	if (instance->state == MK_STATE_LOADING) {
		mutex_unlock(&mk_instance_mutex);
		pr_err("Cannot remove loading instance '%s' (ID: %d). Wait for loading to complete.\n",
		       instance->name, instance->id);
		return -EBUSY;
	}

	list_del(&instance->list);
	idr_remove(&mk_instance_idr, instance->id);

	mutex_unlock(&mk_instance_mutex);

	mk_instance_put(instance);
	kernfs_remove_self(kn);
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
