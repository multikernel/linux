// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 */
#ifndef _LINUX_MULTIKERNEL_H
#define _LINUX_MULTIKERNEL_H

#include <linux/types.h>
#include <linux/irq_work.h>
#include <linux/kobject.h>
#include <linux/kernfs.h>
#include <linux/ioport.h>
#include <linux/of.h>
#include <linux/cpumask.h>
#include <linux/genalloc.h>

/**
 * Multikernel IPI interface
 */

/* Maximum data size that can be transferred via IPI */
#define MK_MAX_DATA_SIZE 256

/* IPI ring buffer size - must be power of 2 for efficient modulo */
#define MK_IPI_RING_SIZE 64

/* Data structure for passing parameters via IPI */
struct mk_ipi_data {
	int sender_cpu;          /* Which CPU sent this IPI */
	unsigned int type;      /* User-defined type identifier */
	size_t data_size;        /* Size of the data */
	char buffer[MK_MAX_DATA_SIZE]; /* Actual data buffer */
};

/* IPI ring buffer for queuing messages */
struct mk_ipi_ring {
	atomic_t head;                          /* Producer index */
	atomic_t tail;                          /* Consumer index */
	struct mk_ipi_data entries[MK_IPI_RING_SIZE]; /* Ring buffer entries */
};

/* Shared memory structures - per-instance design */
struct mk_shared_data {
	struct mk_ipi_ring ring;  /* IPI message ring buffer */
};

/* Function pointer type for IPI callbacks */
typedef void (*mk_ipi_callback_t)(struct mk_ipi_data *data, void *ctx);

struct mk_ipi_handler {
	mk_ipi_callback_t callback;
	void *context;
	unsigned int ipi_type;       /* IPI type this handler is registered for */
	struct mk_ipi_handler *next;
	struct mk_ipi_data *saved_data;
	struct irq_work work;
};

/**
 * multikernel_register_handler - Register a callback for multikernel IPI
 * @callback: Function to call when IPI is received
 * @ctx: Context pointer passed to the callback
 * @ipi_type: IPI type this handler should process
 *
 * Returns pointer to handler on success, NULL on failure
 */
struct mk_ipi_handler *multikernel_register_handler(mk_ipi_callback_t callback, void *ctx, unsigned int ipi_type);

/**
 * multikernel_unregister_handler - Unregister a multikernel IPI callback
 * @handler: Handler pointer returned from multikernel_register_handler
 */
void multikernel_unregister_handler(struct mk_ipi_handler *handler);

/**
 * multikernel_send_ipi_data - Send data to another CPU via IPI
 * @instance_id: Target multikernel instance ID
 * @data: Pointer to data to send
 * @data_size: Size of data
 * @type: User-defined type identifier
 *
 * This function copies the data to per-CPU storage and sends an IPI
 * to the target CPU.
 *
 * Returns 0 on success, negative error code on failure
 */
int multikernel_send_ipi_data(int instance_id, void *data, size_t data_size, unsigned long type);

void generic_multikernel_interrupt(void);

struct resource;

extern phys_addr_t multikernel_alloc(size_t size);
extern void multikernel_free(phys_addr_t addr, size_t size);
extern struct resource *multikernel_get_pool_resource(void);
extern bool multikernel_pool_available(void);

/* Per-instance memory pool management */
extern void *multikernel_create_instance_pool(int instance_id, size_t pool_size, int min_alloc_order);
extern void multikernel_destroy_instance_pool(void *pool_handle);
extern phys_addr_t multikernel_instance_alloc(void *pool_handle, size_t size, size_t align);
extern void multikernel_instance_free(void *pool_handle, phys_addr_t addr, size_t size);
extern size_t multikernel_instance_pool_avail(void *pool_handle);

/**
 * Multikernel Instance States
 */
enum mk_instance_state {
	MK_STATE_EMPTY = 0,     /* Instance directory exists but no DTB */
	MK_STATE_READY,         /* DTB loaded, resources reserved */
	MK_STATE_LOADING,       /* Kernel being loaded */
	MK_STATE_ACTIVE,        /* Kernel running */
	MK_STATE_FAILED,        /* Error occurred */
};

/**
 * Memory region wrapper
 *
 * This wraps a struct resource with gen_pool_chunk for memory pool management.
 * Used by instance management to track both resource hierarchy and pool chunks.
 */
struct mk_memory_region {
	struct resource res;            /* The actual resource */
	struct gen_pool_chunk *chunk;   /* Associated gen_pool chunk */
	struct list_head list;          /* List entry for management */
};

/**
 * Complete multikernel device tree configuration
 *
 * This structure handles memory size requirements and CPU assignment
 * parsed from device tree blobs.
 */
struct mk_dt_config {
	/* Version for compatibility checking */
	u32 version;

	/* Memory requirements */
	size_t memory_size;              /* Total memory size required */

	/* CPU resources */
	unsigned long *cpus;             /* Bitmap of physical CPU IDs */

	/* Extensibility: Reserved fields for future use */
	u32 reserved[12];                /* Increased due to removed fields */

	/* Raw device tree data */
	void *dtb_data;
	size_t dtb_size;
};

/**
 * Multikernel Instance Structure
 *
 * Each instance represents a potential or active multikernel with
 * its own resource allocation and state management.
 */
struct mk_instance {
	int id;                         /* Kernel-assigned instance ID */
	char *name;                     /* User-provided instance name */
	enum mk_instance_state state;   /* Current state */

	/* Resource management - list of reserved memory regions */
	struct list_head memory_regions;  /* List of struct mk_memory_region */
	int region_count;                  /* Number of memory regions */
	/* Memory pool for this instance */
	void *instance_pool;            /* Handle for instance-specific memory pool */
	size_t pool_size;               /* Size of the instance pool */

	/* CPU resources */
	unsigned long *cpus;             /* Bitmap of assigned physical CPU IDs */

	/* Device tree information */
	void *dtb_data;                 /* Device tree blob data */
	size_t dtb_size;                /* Size of DTB */

	/* IPI communication buffer */
	struct mk_shared_data *ipi_data; /* IPI shared memory buffer (virtual address) */
	phys_addr_t ipi_phys;           /* IPI buffer physical address */
	u32 ipi_pages;                  /* IPI buffer size in pages */

	/* Kexec integration */
	struct kimage *kimage;          /* Associated kimage object */

	/* Sysfs representation */
	struct kernfs_node *kn;            /* Kernfs node for this instance */

	/* List management */
	struct list_head list;          /* Link to global instance list */

	/* Reference counting */
	struct kref refcount;           /* Reference count for cleanup */
};

/**
 * Device Tree Parsing Functions
 */

/**
 * mk_dt_parse() - Parse multikernel device tree blob
 * @dtb_data: Device tree blob data
 * @dtb_size: Size of DTB data
 * @config: Output configuration structure
 *
 * Parses a device tree blob and extracts multikernel-specific
 * memory region properties. Supports multiple memory regions
 * specified as:
 * - linux,multikernel-memory = <start1 size1 start2 size2 ...>;
 *
 * Each memory region becomes a struct resource that will be
 * inserted as a child of the main multikernel_res.
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_dt_parse(const void *dtb_data, size_t dtb_size,
		struct mk_dt_config *config);

/**
 * mk_dt_validate() - Validate parsed device tree configuration
 * @config: Configuration to validate
 *
 * Validates that the parsed memory regions are reasonable and
 * compatible with the current system state. Checks for:
 * - Region alignment
 * - Availability in multikernel pool
 * - No overlaps between regions
 *
 * Returns 0 if valid, negative error code on validation failure.
 */
int mk_dt_validate(const struct mk_dt_config *config);

/**
 * mk_dt_config_init() - Initialize a device tree configuration
 * @config: Configuration structure to initialize
 *
 * Initializes all fields to safe defaults.
 */
void mk_dt_config_init(struct mk_dt_config *config);

/**
 * mk_dt_config_free() - Free device tree configuration resources
 * @config: Configuration to free
 *
 * Frees any dynamically allocated resources in the configuration.
 */
void mk_dt_config_free(struct mk_dt_config *config);

/**
 * mk_dt_resources_available() - Check if memory and CPU resources are available
 * @config: Configuration with resources to check
 *
 * Checks if the specified memory size is available in the
 * multikernel memory pool and all CPUs are possible on the system.
 *
 * Returns true if all resources are available, false otherwise.
 */
bool mk_dt_resources_available(const struct mk_dt_config *config);

/**
 * mk_dt_get_property_size() - Get size of a specific property
 * @dtb_data: Device tree blob
 * @dtb_size: Size of DTB
 * @property: Property name (e.g., "linux,multikernel-memory")
 *
 * Helper function to determine the size of a property before parsing.
 * Useful for validation and memory allocation.
 *
 * Returns property size in bytes, or -ENOENT if not found.
 */
int mk_dt_get_property_size(const void *dtb_data, size_t dtb_size,
			    const char *property);

/**
 * mk_dt_print_config() - Print configuration for debugging
 * @config: Configuration to print
 *
 * Prints the parsed configuration in a human-readable format
 * for debugging purposes.
 */
void mk_dt_print_config(const struct mk_dt_config *config);

/**
 * Sysfs Interface Functions
 */

/**
 * mk_kernfs_init() - Initialize multikernel kernfs interface
 *
 * Creates /sys/kernel/multikernel/ directory and sets up
 * the kernfs infrastructure for multikernel instances.
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_kernfs_init(void);

/**
 * mk_kernfs_cleanup() - Cleanup multikernel kernfs interface
 *
 * Removes all kernfs entries and cleans up resources.
 */
void mk_kernfs_cleanup(void);

/**
 * mk_instance_find_by_name() - Find an existing instance by name
 * @name: Instance name to find
 *
 * Returns pointer to mk_instance if found, NULL otherwise.
 * Caller must hold appropriate locks.
 */
struct mk_instance *mk_instance_find_by_name(const char *name);

/**
 * mk_instance_get() - Increment reference count
 * @instance: Instance to reference
 *
 * Returns the instance pointer for convenience.
 */
struct mk_instance *mk_instance_get(struct mk_instance *instance);

/**
 * mk_instance_put() - Decrement reference count
 * @instance: Instance to dereference
 *
 * May free the instance if reference count reaches zero.
 */
void mk_instance_put(struct mk_instance *instance);

/**
 * mk_instance_set_state() - Update instance state
 * @instance: Instance to update
 * @state: New state
 *
 * Updates the instance state and notifies sysfs.
 */
void mk_instance_set_state(struct mk_instance *instance,
			   enum mk_instance_state state);

/**
 * mk_instance_reserve_resources() - Reserve CPU and memory resources for instance
 * @instance: Instance to reserve resources for
 * @config: Device tree configuration with memory size and CPU assignment
 *
 * Allocates the specified memory size from the multikernel pool, creates
 * memory regions, and copies CPU assignment.
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_instance_reserve_resources(struct mk_instance *instance,
				  const struct mk_dt_config *config);

/**
 * mk_instance_free_memory() - Free all reserved memory regions
 * @instance: Instance to free memory for
 *
 * Returns all reserved memory regions back to the multikernel pool
 * and removes them from the resource hierarchy.
 */
void mk_instance_free_memory(struct mk_instance *instance);

void *mk_instance_alloc(struct mk_instance *instance, size_t size, size_t align);
void mk_instance_free(struct mk_instance *instance, void *virt_addr, size_t size);

void *mk_kimage_alloc(struct kimage *image, size_t size, size_t align);
void mk_kimage_free(struct kimage *image, void *virt_addr, size_t size);

/**
 * String conversion helpers
 */
const char *mk_state_to_string(enum mk_instance_state state);
enum mk_instance_state mk_string_to_state(const char *str);

/**
 * Kexec Integration Functions
 *
 * These functions bridge the gap between the sysfs instance management
 * and the kexec multikernel system.
 */

/**
 * mk_instance_find() - Find instance by a multikernel instance ID
 * @mk_id: Multikernel instance ID
 *
 * Returns pointer to mk_instance if found, NULL otherwise.
 */
struct mk_instance *mk_instance_find(int mk_id);

/**
 * mk_instance_set_kexec_active() - Mark instance as active for kexec
 * @mk_id: Multikernel ID from kexec system
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_instance_set_kexec_active(int mk_id);

/**
 * mk_instance_set_kexec_loading() - Mark instance as loading for kexec
 * @mk_id: Multikernel ID from kexec system
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_instance_set_kexec_loading(int mk_id);

/**
 * Version and Compatibility
 */
#define MK_DT_CONFIG_VERSION_1  1
#define MK_DT_CONFIG_CURRENT    MK_DT_CONFIG_VERSION_1
#define MK_FDT_COMPATIBLE "multikernel-v1"

/**
 * Property Names
 */
#define MK_DT_RESOURCE_MEMORY   "memory-bytes"
#define MK_DT_RESOURCE_CPUS     "cpus"

static const char * const mk_resource_properties[] = {
	MK_DT_RESOURCE_MEMORY,
	MK_DT_RESOURCE_CPUS,
	NULL  /* Sentinel */
};

static inline bool mk_is_resource_property(const char *prop_name)
{
	const char * const *prop;

	if (!prop_name)
		return false;

	for (prop = mk_resource_properties; *prop; prop++) {
		if (strcmp(prop_name, *prop) == 0)
			return true;
	}
	return false;
}

/**
 * KHO (Kexec HandOver) Integration Functions
 *
 * These functions provide KHO support for preserving and restoring
 * multikernel instance device trees across kexec boundaries.
 */

/**
 * mk_kho_preserve_dtb() - Preserve multikernel DTB for kexec
 * @image: Target kimage
 * @fdt: FDT being built for KHO
 * @mk_id: Multikernel instance ID
 *
 * Called by mk_kexec_finalize() to add multikernel DTB to KHO FDT.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_kho_preserve_dtb(struct kimage *image, void *fdt, int mk_id);

/**
 * mk_kho_preserve_host_ipi() - Preserve host's IPI buffer address in KHO
 * @image: Target kimage
 * @fdt: FDT being built for KHO
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_kho_preserve_host_ipi(struct kimage *image, void *fdt);

/**
 * mk_kho_restore_dtbs() - Restore DTBs from KHO shared memory
 *
 * Called during multikernel initialization to restore DTBs that were
 * preserved by the previous kernel via KHO.
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init mk_kho_restore_dtbs(void);

#endif /* _LINUX_MULTIKERNEL_H */
