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
#include <linux/sizes.h>
#include <linux/spinlock.h>
#include <linux/multikernel_abi.h>

struct pci_bus;

/**
 * Physical CPU identifiers
 *
 * Instances are described by the physical IDs of their CPUs (APIC ID on
 * x86, MPIDR on arm64, hartid on riscv). Physical IDs are sparse 64-bit
 * values, so they cannot be used as bit positions in NR_CPUS-sized
 * bitmaps; a set is a small array instead. Entries keep insertion order,
 * so the first CPU of a device tree list stays the instance's boot CPU.
 */
typedef u64 mk_phys_cpu_t;

#define MK_PHYS_CPU_INVALID	(~(mk_phys_cpu_t)0)

struct mk_cpu_set {
	unsigned int nr;	/* Entries in use */
	unsigned int cap;	/* Allocated capacity */
	mk_phys_cpu_t *ids;
};

struct mk_cpu_set *mk_cpu_set_alloc(void);
void mk_cpu_set_free(struct mk_cpu_set *set);
void mk_cpu_set_clear(struct mk_cpu_set *set);
int mk_cpu_set_reserve(struct mk_cpu_set *set, unsigned int extra);
int mk_cpu_set_add(struct mk_cpu_set *set, mk_phys_cpu_t id);
bool mk_cpu_set_del(struct mk_cpu_set *set, mk_phys_cpu_t id);
bool mk_cpu_set_contains(const struct mk_cpu_set *set, mk_phys_cpu_t id);
int mk_cpu_set_copy(struct mk_cpu_set *dst, const struct mk_cpu_set *src);
int mk_cpu_set_format(char *buf, size_t size, const struct mk_cpu_set *set);

static inline unsigned int mk_cpu_set_count(const struct mk_cpu_set *set)
{
	return set ? set->nr : 0;
}

static inline bool mk_cpu_set_empty(const struct mk_cpu_set *set)
{
	return mk_cpu_set_count(set) == 0;
}

static inline mk_phys_cpu_t mk_cpu_set_first(const struct mk_cpu_set *set)
{
	return mk_cpu_set_empty(set) ? MK_PHYS_CPU_INVALID : set->ids[0];
}

#define mk_cpu_set_for_each(i, id, set)					\
	for ((i) = 0;							\
	     (set) && (i) < (set)->nr &&				\
	     (((id) = (set)->ids[(i)]), true);				\
	     (i)++)

/**
 * Multikernel IPI interface
 */

/* Maximum data size that can be transferred via IPI */
#define MK_MAX_DATA_SIZE 4096

/* IPI ring buffer size - must be power of 2 for efficient modulo */
#define MK_IPI_RING_SIZE 64

#define MK_IPI_SLOT_EMPTY	0
#define MK_IPI_SLOT_WRITING	1
#define MK_IPI_SLOT_READY	2
#define MK_IPI_SLOT_CONSUMING	3
#define MK_IPI_SLOT_CANCELLED	4
#define MK_IPI_ABI_MAGIC		0x4d4b495049303033ULL /* "MKIPI003" */
#define MK_IPI_READY_TIMEOUT_MS	120000

/* Data structure for passing parameters via IPI */
struct mk_ipi_data {
	atomic_t state;
	u64 sender_cpu;          /* Physical ID of the CPU that sent this IPI */
	unsigned int type;      /* User-defined type identifier */
	size_t data_size;        /* Size of the data */
	char buffer[MK_MAX_DATA_SIZE]; /* Actual data buffer */
};

/* IPI ring buffer for queuing messages */
struct mk_ipi_ring {
	atomic_t head;                          /* Producer allocation cursor */
	atomic_t tail;                          /* Consumer scan cursor */
	struct mk_ipi_data entries[MK_IPI_RING_SIZE]; /* Ring buffer entries */
	/* Appended shared ABI: do not move fields above this line. */
	atomic64_t producer_gate;               /* Owner CPU and claimed slot */
	atomic_t producer_contention;           /* Sends that observed a busy gate */
	atomic_t full_failures;                 /* Sends rejected by a full ring */
	atomic_t invalid_state;                 /* Invalid slot state observations */
	atomic_t cancelled_writes;              /* Halted producer writes recovered */
};

/* Shared memory structures - per-instance design */
struct mk_shared_data {
	struct mk_ipi_ring ring;  /* IPI message ring buffer */
	/*
	 * Force-halt marker, host-owned. Armed before the host NMIs the
	 * instance's CPUs and cleared with the rest of this struct when
	 * the instance is re-executed, so it cannot be consumed early the
	 * way a ring message can, and a repeated force halt still reaches
	 * CPUs the first one missed.
	 */
	u32 force_halt;
	/* Appended ABI handshake; existing shared offsets stay unchanged. */
	u64 abi_magic;
	u32 abi_version;
	u32 abi_size;
	s32 ready_instance_id;
	atomic_t ready;
};

static inline void mk_ipi_ring_reset_contents(struct mk_ipi_ring *ring)
{
	unsigned int i;

	atomic_set(&ring->head, 0);
	atomic_set(&ring->tail, 0);
	for (i = 0; i < MK_IPI_RING_SIZE; i++) {
		WRITE_ONCE(ring->entries[i].data_size, 0);
		atomic_set(&ring->entries[i].state, MK_IPI_SLOT_EMPTY);
	}
	atomic_set(&ring->producer_contention, 0);
	atomic_set(&ring->full_failures, 0);
	atomic_set(&ring->invalid_state, 0);
	atomic_set(&ring->cancelled_writes, 0);
}

static inline void mk_ipi_ring_reset(struct mk_ipi_ring *ring)
{
	mk_ipi_ring_reset_contents(ring);
	atomic64_set(&ring->producer_gate, 0);
}

static inline void mk_shared_data_reset(struct mk_shared_data *shared)
{
	mk_ipi_ring_reset(&shared->ring);
	WRITE_ONCE(shared->force_halt, 0);
	WRITE_ONCE(shared->abi_magic, MK_IPI_ABI_MAGIC);
	WRITE_ONCE(shared->abi_version, MK_IPI_ABI_VERSION);
	WRITE_ONCE(shared->abi_size, sizeof(*shared));
	WRITE_ONCE(shared->ready_instance_id, -1);
	atomic_set(&shared->ready, 0);
}

/* Function pointer type for IPI callbacks */
typedef void (*mk_ipi_callback_t)(struct mk_ipi_data *data, void *ctx);

struct mk_ipi_handler {
	mk_ipi_callback_t callback;
	void *context;
	unsigned int ipi_type;       /* IPI type this handler is registered for */
	struct mk_ipi_handler *next;
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

int mk_ipi_shared_validate(const struct mk_shared_data *shared);
int mk_ipi_shared_mark_ready(struct mk_shared_data *shared, int instance_id);
int mk_ipi_shared_wait_ready(struct mk_shared_data *shared, int instance_id,
			     unsigned int timeout_ms);
int mk_ipi_shared_reset_downlink(struct mk_shared_data *shared,
				 int instance_id);

/* Recover a producer only after every CPU in @halted_cpus is parked. */
int mk_ipi_ring_recover_halted(const struct mk_cpu_set *halted_cpus);

/*
 * Multikernel Messaging System
 */

/**
 * Message type definitions - organized by category
 */

/* Top-level message categories */
#define MK_MSG_IO           0x1000
#define MK_MSG_RESOURCE     0x2000
#define MK_MSG_SYSTEM       0x3000
#define MK_MSG_USER         0x4000
#define MK_MSG_NETWORK      0x5000

/* I/O interrupt forwarding subtypes */
#define MK_IO_IRQ_FORWARD   (MK_MSG_IO + 1)
#define MK_IO_IRQ_BALANCE   (MK_MSG_IO + 2)
#define MK_IO_IRQ_MASK      (MK_MSG_IO + 3)
#define MK_IO_IRQ_UNMASK    (MK_MSG_IO + 4)

/* Resource management subtypes */
#define MK_RES_CPU_ADD      (MK_MSG_RESOURCE + 1)
#define MK_RES_CPU_REMOVE   (MK_MSG_RESOURCE + 2)
#define MK_RES_MEM_ADD      (MK_MSG_RESOURCE + 3)
#define MK_RES_MEM_REMOVE   (MK_MSG_RESOURCE + 4)
#define MK_RES_QUERY        (MK_MSG_RESOURCE + 5)
#define MK_RES_DEVICE_ADD   (MK_MSG_RESOURCE + 6)
#define MK_RES_DEVICE_REMOVE (MK_MSG_RESOURCE + 7)
#define MK_RES_ACK          (MK_MSG_RESOURCE + 0x100)  /* Response/acknowledgment */

/* System management subtypes */
#define MK_SYS_HEARTBEAT    (MK_MSG_SYSTEM + 1)
#define MK_SYS_SHUTDOWN     (MK_MSG_SYSTEM + 2)
#define MK_SYS_SHUTDOWN_ACK (MK_MSG_SYSTEM + 3)
#define MK_SYS_HALTED       (MK_MSG_SYSTEM + 4)  /* Voluntary halt notification */

/* Network/vsock subtypes */
#define MK_NET_VSOCK_PKT    (MK_MSG_NETWORK + 1)  /* vsock packet */
#define MK_NET_DATA_READY   (MK_MSG_NETWORK + 2)  /* Data available notification */

/**
 * Core message structure
 */
struct mk_message {
	u32 msg_type;           /* Message type identifier */
	u32 msg_subtype;        /* Subtype for specific operations */
	u64 msg_id;             /* Optional message ID for correlation */
	u32 payload_len;        /* Length of payload data */
	u8 payload[];           /* Variable payload (up to remaining IPI buffer) */
};

/**
 * Payload structures for specific message types
 */

/* I/O interrupt forwarding */
struct mk_io_irq_payload {
	u32 irq_number;         /* Hardware IRQ number */
	u32 vector;             /* Interrupt vector */
	u32 device_id;          /* Device identifier (optional) */
	u32 flags;              /* Control flags (priority, etc.) */
};

/* IRQ control flags */
#define MK_IRQ_HIGH_PRIORITY    0x01
#define MK_IRQ_LOW_LATENCY      0x02
#define MK_IRQ_EDGE_TRIGGERED   0x04
#define MK_IRQ_LEVEL_TRIGGERED  0x08

/* CPU resource operations */
struct mk_cpu_resource_payload {
	u64 cpu_id;             /* Physical CPU ID */
	u32 numa_node;          /* NUMA node (optional) */
	u32 flags;              /* CPU capabilities/attributes */
	int sender_instance_id; /* Sender instance ID for ACK */
};

/* CPU capability flags */
#define MK_CPU_HAS_AVX512       0x01
#define MK_CPU_HAS_TSX          0x02
#define MK_CPU_HYPERTHREAD      0x04

/* Memory resource operations */
struct mk_mem_resource_payload {
	u64 start_pfn;          /* Starting page frame number */
	u64 nr_pages;           /* Number of pages */
	u32 numa_node;          /* NUMA node */
	u32 mem_type;           /* Memory type (normal/DMA/etc.) */
	int sender_instance_id; /* Sender instance ID for ACK */
};

/* Memory types */
#define MK_MEM_NORMAL           0x01
#define MK_MEM_DMA              0x02
#define MK_MEM_DMA32            0x04
#define MK_MEM_HIGHMEM          0x08

/* PCI device resource operations */
struct mk_device_resource_payload {
	u16 domain;             /* PCI domain */
	u8 bus;                 /* PCI bus */
	u8 devfn;               /* PCI device and function (combined) */
	u32 flags;              /* Device flags */
	char driver_override[64]; /* Target driver name for binding */
	int sender_instance_id; /* Sender instance ID for ACK */
};

/* Device flags */
#define MK_DEVICE_BIND_VFIO     0x01  /* Bind to VFIO driver */
#define MK_DEVICE_BIND_STUB     0x02  /* Bind to pci-stub driver */

/* Resource operation response/ACK */
struct mk_resource_ack {
	u32 operation;          /* Original operation (MK_RES_CPU_ADD, etc.) */
	u32 result;             /* Result code: 0 = success, negative = error */
	u64 resource_id;        /* Physical CPU ID, memory PFN, etc. */
};

/* Shutdown request payload */
struct mk_shutdown_payload {
	u32 flags;
	int sender_instance_id;
};

#define MK_SHUTDOWN_GRACEFUL  0x01

/**
 * Message handler callback type
 */
typedef void (*mk_msg_handler_t)(u32 msg_type, u32 subtype,
				 void *payload, u32 payload_len, void *ctx);

/* Opaque type for pending message tracking */
struct mk_pending_msg;

/**
 * Message API functions
 */

/**
 * mk_send_message - Send a message to another CPU
 * @instance_id: Target multikernel instance ID
 * @msg_type: Message type identifier
 * @subtype: Message subtype
 * @payload: Pointer to payload data (can be NULL)
 * @payload_len: Length of payload data
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_send_message(int instance_id, u32 msg_type, u32 subtype,
		    void *payload, u32 payload_len);

/**
 * mk_register_msg_handler - Register handler for specific message type
 * @msg_type: Message type to handle
 * @handler: Handler function
 * @ctx: Context pointer passed to handler
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_register_msg_handler(u32 msg_type, mk_msg_handler_t handler, void *ctx);

/**
 * mk_unregister_msg_handler - Unregister message handler
 * @msg_type: Message type to unregister
 * @handler: Handler function to remove
 *
 * Returns 0 on success, negative error code on failure
 */
int mk_unregister_msg_handler(u32 msg_type, mk_msg_handler_t handler);

/* Pending message tracking for request-response pattern */
struct mk_pending_msg *mk_msg_pending_add(u32 msg_type, u32 operation, u64 resource_id);
void mk_msg_pending_complete(u32 msg_type, u32 operation, u64 resource_id, int result);
int mk_msg_pending_wait(struct mk_pending_msg *pending, unsigned long timeout_ms);

/**
 * Convenience functions for common message types
 */

/* I/O interrupt forwarding */
static inline int mk_send_irq_forward(int instance_id, u32 irq_number,
				      u32 vector, u32 device_id, u32 flags)
{
	struct mk_io_irq_payload payload = {
		.irq_number = irq_number,
		.vector = vector,
		.device_id = device_id,
		.flags = flags
	};
	return mk_send_message(instance_id, MK_MSG_IO, MK_IO_IRQ_FORWARD,
			       &payload, sizeof(payload));
}

/* CPU resource management - these wait for operation to complete */
int mk_send_cpu_add(int instance_id, mk_phys_cpu_t cpu_id, u32 numa_node, u32 flags);
int mk_send_cpu_remove(int instance_id, mk_phys_cpu_t cpu_id);

/* Memory resource management */
int mk_send_mem_add(int instance_id, u64 start_pfn, u64 nr_pages,
		    u32 numa_node, u32 mem_type);
int mk_send_mem_remove(int instance_id, u64 start_pfn, u64 nr_pages);

/* PCI device resource management */
int mk_send_device_add(int instance_id, u16 domain, u8 bus, u8 devfn,
		       const char *driver_override, u32 flags);
int mk_send_device_remove(int instance_id, u16 domain, u8 bus, u8 devfn);

/* Messaging system functions */
int __init mk_messaging_init(void);
void mk_messaging_cleanup(void);

/**
 * struct mk_pool_chunk - one physically contiguous piece of the memory pool
 * @list: link in the global chunk list
 * @pages: head page of the contiguous allocation backing the chunk
 * @nr_pages: number of pages in @pages
 * @node: NUMA node the chunk was allocated on
 * @res: /proc/iomem resource, parent of every instance region carved out of it
 */
struct mk_pool_chunk {
	struct list_head list;
	struct page *pages;
	unsigned long nr_pages;
	int node;
	struct resource res;
};

int mk_pool_mem_grow(size_t size, int node, phys_addr_t *out_base);
int mk_pool_mem_shrink(phys_addr_t start, size_t size);
extern phys_addr_t multikernel_alloc(size_t size, int node);
extern void multikernel_free(phys_addr_t addr, size_t size);
struct resource *mk_pool_chunk_resource(phys_addr_t addr);
size_t mk_pool_total_bytes(void);
size_t mk_pool_avail_bytes(void);
bool mk_pool_empty(void);
int mk_pool_for_each_chunk(int (*fn)(struct mk_pool_chunk *, void *), void *data);
bool mk_pool_cpus_returned(void);

/**
 * struct mk_pool_chunk_range - a pool chunk copied out of the chunk list
 * @start: physical base of the chunk
 * @size: chunk size in bytes
 * @node: NUMA node the chunk lives on
 */
struct mk_pool_chunk_range {
	phys_addr_t start;
	size_t size;
	int node;
};

int mk_pool_snapshot_chunks(struct mk_pool_chunk_range *out, int max);

#ifdef CONFIG_X86
int mk_arch_pool_chunk_added(phys_addr_t start, size_t size);
bool mk_host_park_uses(phys_addr_t start, size_t size);
int mk_teardown_host_park(void);
#else
static inline int mk_arch_pool_chunk_added(phys_addr_t start, size_t size)
{
	return 0;
}

static inline bool mk_host_park_uses(phys_addr_t start, size_t size)
{
	return false;
}

static inline int mk_teardown_host_park(void)
{
	return 0;
}
#endif

/* Per-instance memory pool management */
extern void *multikernel_create_instance_pool(int instance_id, size_t pool_size,
					      int min_alloc_order, int node);
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
	MK_STATE_LOADED,        /* Kernel loaded, ready to start */
	MK_STATE_ACTIVE,        /* Kernel running */
	MK_STATE_FAILED,        /* Error occurred */
};

/**
 * Root instance pointer - points to the current running kernel instance
 * In the host kernel, this is instance 0.
 * In a spawn kernel, this is the spawned instance (1, 2, etc.).
 */
extern struct mk_instance *root_instance;

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
 * PCI device specification
 *
 * Represents a single PCI device that should be accessible to an instance.
 * Format: vendor:device@domain:bus:slot.func
 */
struct mk_pci_device {
	char name[64];     /* Device name from DTB (e.g., "enp9s0_dev") */
	u16 vendor;        /* PCI vendor ID */
	u16 device;        /* PCI device ID */
	u16 domain;        /* PCI domain number */
	u8 bus;            /* PCI bus number */
	u8 slot;           /* PCI slot number */
	u8 func;           /* PCI function number */
	struct list_head list;  /* Link to device list */
};

/**
 * Platform device specification
 *
 * Represents a single platform/ACPI device that should be accessible to an instance.
 * Platform devices are identified by ACPI HID (Hardware ID) or device name.
 *
 * Examples:
 *   - i8042 keyboard controller: hid="PNP0303" or name="i8042"
 *   - Serial port: hid="PNP0501"
 *   - RTC: hid="PNP0B00"
 */
#define MK_PLATFORM_DEVICE_ID_LEN 16
#define MK_PLATFORM_DEVICE_NAME_LEN 32
struct mk_platform_device {
	char hid[MK_PLATFORM_DEVICE_ID_LEN];      /* ACPI Hardware ID (e.g., "PNP0303") */
	char name[MK_PLATFORM_DEVICE_NAME_LEN];   /* Platform device name (e.g., "i8042") */
	struct list_head list;                     /* Link to device list */
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
	struct mk_cpu_set *cpus;         /* Set of physical CPU IDs */

	/* NUMA node the instance memory comes from, NUMA_NO_NODE if any */
	int numa_node;

	/* PCI device resources */
	struct list_head pci_devices;    /* List of struct mk_pci_device */
	int pci_device_count;            /* Number of PCI devices */
	bool pci_devices_valid;          /* Whether PCI device list is valid */

	/* Platform device resources */
	struct list_head platform_devices;   /* List of struct mk_platform_device */
	int platform_device_count;           /* Number of platform devices */
	bool platform_devices_valid;         /* Whether platform device list is valid */

	/* Extensibility: Reserved fields for future use */
	u32 reserved[6];                 /* Reduced due to added fields */

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
	struct mk_cpu_set *cpus;         /* Set of assigned physical CPU IDs */

	/* PCI device resources */
	struct list_head pci_devices;    /* List of struct mk_pci_device */
	int pci_device_count;            /* Number of PCI devices */
	bool pci_devices_valid;          /* Whether PCI device list is valid */

	/* Platform device resources */
	struct list_head platform_devices;   /* List of struct mk_platform_device */
	int platform_device_count;           /* Number of platform devices */
	bool platform_devices_valid;         /* Whether platform device list is valid */

	/* Device tree information */
	void *dtb_data;                 /* Device tree blob data */
	size_t dtb_size;                /* Size of DTB */

	/* IPI communication buffer */
	struct mk_shared_data *ipi_data; /* IPI shared memory buffer (virtual address) */
	phys_addr_t ipi_phys;           /* IPI buffer physical address */
	u32 ipi_pages;                  /* IPI buffer size in pages */

	/* Kexec integration */
	struct kimage *kimage;          /* Associated kimage object */

	/* Spawn resources - reused across re-spawns, freed on pool destroy */
	struct mk_spawn_context *spawn_ctx;
	phys_addr_t spawn_ctx_phys;
	struct mk_ident_pgtable *ident_pgt;
	void *trampoline_va;
	void *park_va;			/* Pool park page, written once by the host */

	/*
	 * Control block: host-owned structures the spawn kernel must never
	 * allocate over (spawn context, trampoline, park page, identity
	 * page tables). Carved from one contiguous range so it can be
	 * reserved in the spawn kernel's e820 with a single entry.
	 */
	void *ctrl_va;
	phys_addr_t ctrl_phys;
	size_t ctrl_used;

	/*
	 * CPUs currently parked on this instance's context rather than the
	 * host pool slot. Membership is per CPU because it changes one CPU
	 * at a time: hotplug moves CPUs in and out while the instance runs,
	 * and a stopped instance can gain CPUs that are still parked on the
	 * host slot while the ones it already ran on watch its context.
	 */
	struct mk_cpu_set *cpus_on_slot;

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
 * inserted as a child of the pool chunk that holds it.
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
 * mk_halt_to_pool() - Halt this spawn kernel, returning its CPUs to the pool
 *
 * Notifies the host and parks every CPU in the pool wait loop, keeping
 * the instance re-spawnable. Never returns.
 */
void __noreturn mk_halt_to_pool(void);

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


int mk_instance_transfer_cpus(struct mk_instance *instance,
			       const struct mk_cpu_set *cpus);
int mk_instance_return_cpus(struct mk_instance *instance,
			     const struct mk_cpu_set *cpus);
int mk_instance_add_memory_region(struct mk_instance *instance, size_t size,
				  int node);
int mk_instance_remove_memory_region(struct mk_instance *instance,
				     phys_addr_t phys_addr, size_t size);
int mk_instance_add_pci_device(struct mk_instance *instance,
			       u16 domain, u8 bus, u8 devfn);
int mk_instance_remove_pci_device(struct mk_instance *instance,
				  u16 domain, u8 bus, u8 devfn);

void *mk_instance_alloc(struct mk_instance *instance, size_t size, size_t align);
void mk_instance_free(struct mk_instance *instance, void *virt_addr, size_t size);

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
 * mk_instance_set_kexec_active() - Mark instance as active for kexec
 * @mk_id: Multikernel ID from kexec system
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_instance_set_kexec_active(int mk_id);

/*
 * The declarations below are referenced from always-built code (kexec,
 * PCI and platform device probing, SMP setup), so they carry stubs for
 * the CONFIG_MULTIKERNEL=n build.
 */
struct kimage;
struct pci_bus;

#ifdef CONFIG_MULTIKERNEL
bool multikernel_allow_emergency_restart(void);
int multikernel_halt_by_id(int mk_id);
int multikernel_force_halt_by_id(int mk_id);
bool cpu_is_multikernel_pool(unsigned int cpu);
bool mk_has_pending_shutdown(void);
void mk_nmi_offline_park(void);

/* Instance lookup and reference counting */
struct mk_instance *mk_instance_find(int mk_id);
void mk_instance_put(struct mk_instance *instance);
void mk_instance_set_state(struct mk_instance *instance,
			   enum mk_instance_state state);
int mk_instance_abort_spawn(struct mk_instance *instance);

/* Kimage-based access to the instance memory pool */
void *mk_kimage_alloc(struct kimage *image, size_t size, size_t align);
void mk_kimage_free(struct kimage *image, void *virt_addr, size_t size);

/* Device probe filtering against the instance's allowlist */
bool mk_pci_should_probe(struct pci_bus *bus, int devfn);
bool mk_platform_device_allowed(const char *name, const char *hid);

/* Early CPU registration from the manifest (spawn kernels) */
void mk_register_cpus_from_manifest(void);

/* Accept the manifest handed over at boot (spawn kernels) */
void mk_manifest_populate(phys_addr_t fdt_phys, u64 fdt_len);
bool mk_manifest_rejected(void);

/* Build the manifest for a spawn (host, kexec path) */
int mk_manifest_finalize(struct kimage *image);
#else
static inline bool multikernel_allow_emergency_restart(void)
{
	return true;
}
static inline int multikernel_halt_by_id(int mk_id)
{
	return -ENODEV;
}
static inline int multikernel_force_halt_by_id(int mk_id)
{
	return -ENODEV;
}
static inline bool cpu_is_multikernel_pool(unsigned int cpu)
{
	return false;
}
static inline void mk_nmi_offline_park(void)
{
}
static inline struct mk_instance *mk_instance_find(int mk_id)
{
	return NULL;
}
static inline void mk_instance_put(struct mk_instance *instance)
{
}
static inline void mk_instance_set_state(struct mk_instance *instance,
					 enum mk_instance_state state)
{
}
static inline void *mk_kimage_alloc(struct kimage *image, size_t size,
				    size_t align)
{
	return NULL;
}
static inline void mk_kimage_free(struct kimage *image, void *virt_addr,
				  size_t size)
{
}
static inline bool mk_pci_should_probe(struct pci_bus *bus, int devfn)
{
	return true;
}
static inline bool mk_platform_device_allowed(const char *name, const char *hid)
{
	return true;
}
static inline void mk_register_cpus_from_manifest(void)
{
}
static inline void mk_manifest_populate(phys_addr_t fdt_phys, u64 fdt_len)
{
}

static inline bool mk_manifest_rejected(void)
{
	return false;
}
#endif

/**
 * Version and Compatibility
 */
#define MK_DT_CONFIG_VERSION_1  1
#define MK_DT_CONFIG_CURRENT    MK_DT_CONFIG_VERSION_1
/* Bumped whenever the shared-memory layout or message semantics change. */
#define MK_FDT_COMPATIBLE "multikernel-v3"

/**
 * Property Names
 */
#define MK_DT_RESOURCE_MEMORY   "memory-bytes"
#define MK_DT_RESOURCE_CPUS     "cpus"
#define MK_DT_RESOURCE_DEVICES  "devices"
#define MK_DT_RESOURCE_NUMA     "numa-nodes"

/**
 * Manifest Integration Functions
 *
 * These functions build the instance device tree into the manifest on
 * the host side, and restore an instance from it on the spawn side.
 */

/**
 * mk_manifest_add_instance_dtb() - Preserve multikernel DTB for kexec
 * @image: Target kimage
 * @fdt: The manifest FDT being built
 * @mk_id: Multikernel instance ID
 *
 * Called by mk_manifest_finalize() to add the multikernel DTB to the manifest.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_manifest_add_instance_dtb(struct kimage *image, void *fdt, int mk_id);

/**
 * mk_manifest_add_host_ipi() - Add the host's IPI buffer address to the manifest
 * @image: Target kimage
 * @fdt: The manifest FDT being built
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_manifest_add_host_ipi(struct kimage *image, void *fdt);


/**
 * mk_instance_restore_from_manifest() - Restore this instance from the manifest
 *
 * Called during multikernel initialization to restore DTBs that were
 * placed in the manifest by the host kernel.
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init mk_instance_restore_from_manifest(void);

/*
 * mk_register_cpus_from_manifest() registers CPUs from the manifest during SMP
 * configuration, before topology_init_possible_cpus(); it is declared
 * above with the CONFIG_MULTIKERNEL stubs.
 */

/**
 * PCI Device Enforcement Functions
 */

/**
 * mk_pci_should_probe() - Check if PCI probing should occur at a location
 * @bus: PCI bus
 * @devfn: PCI device/function number
 *
 * Called BEFORE any PCI config space reads to determine if probing
 * should proceed. This prevents config space accesses to devices
 * that are not in the whitelist, avoiding hardware conflicts on bare metal.
 *
 * Returns: true if probing should proceed, false to skip entirely
 *
 * Declared above with the CONFIG_MULTIKERNEL stubs.
 */

/**
 * mk_platform_device_allowed() - Check if a platform device is allowed by DTB allowlist
 * @name: Platform device name (e.g., "i8042", "serial8250")
 * @hid: ACPI Hardware ID if available (e.g., "PNP0303"), can be NULL
 *
 * Checks if the specified platform device is allowed according to the DTB
 * configuration in the root instance. If no root instance exists or no
 * platform device restrictions are configured, all devices are allowed.
 *
 * The check matches against either the device name or ACPI HID for portability.
 *
 * Returns: true if device is allowed, false otherwise
 *
 * Declared above with the CONFIG_MULTIKERNEL stubs.
 */

void *mk_instance_ctrl_alloc(struct mk_instance *instance, size_t size,
			     size_t align);

/**
 * Architecture interface
 *
 * Everything below is implemented per architecture. An architecture that
 * selects ARCH_SUPPORTS_MULTIKERNEL must provide these functions, plus,
 * through <asm/multikernel.h>:
 *
 *  - arch_cpu_physical_id() / arch_cpu_from_physical_id(): translate
 *    between logical CPU numbers and the physical CPU IDs (APIC ID,
 *    MPIDR, hartid) that name CPUs across kernel instances.
 *  - MK_CTRL_BLOCK_SIZE: size of the per-instance control block that
 *    holds the arch's boot structures (spawn context, trampolines, page
 *    tables), carved from instance memory and reserved from the spawn
 *    kernel's allocator.
 *  - The spawn mechanics themselves (context setup, trampolines, CPU
 *    wakeup), which generic code currently drives from the kexec path;
 *    their declarations live in the arch header until that path is
 *    extracted behind a single arch hook.
 */
#ifdef CONFIG_MULTIKERNEL
#include <asm/multikernel.h>
#endif

/* Doorbell for the message ring: IPI a CPU owned by another kernel */
void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu);

/* Enumerate a pool CPU in this kernel's topology during early boot */
void mk_arch_register_cpu(mk_phys_cpu_t phys_id);

/* Mark/query a CPU as parked in the multikernel pool */
void mk_set_pool_cpu(int cpu, bool is_pool);

/* Park the calling CPU in the pool wait loop; never returns */
void __noreturn mk_enter_pool_state(void *info);
int __init mk_arch_prepare_park(void);
bool mk_arch_park_ready(void);

/*
 * Forcible stop of another instance's CPUs (NMI on x86). Registration
 * may fail where the architecture has nothing suitable; graceful
 * shutdown must keep working without it.
 */
int mk_register_stop_nmi_handler(void);
void mk_force_stop_cpu(mk_phys_cpu_t phys_cpu);

/* Host pool park area, set up when the baseline is applied */
int mk_setup_host_park(void);

/*
 * Build the boot state for @instance from the loaded @image and start
 * its boot CPU (a parked pool CPU, given as a logical CPU number). On
 * success the arch keeps its spawn resources in the instance so a
 * re-spawn can reuse them; mk_arch_release_instance() frees them when
 * the instance's memory is torn down.
 */
struct kimage;
int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance,
			   int cpu);
int mk_arch_release_instance(struct mk_instance *instance);

/* Verify one of an instance's CPUs has reached its park loop */
int mk_arch_confirm_parked(struct mk_instance *instance, mk_phys_cpu_t phys_cpu);

/*
 * Wait until every CPU an instance owns is parked. Its kernel image may
 * only be overwritten once this succeeds: a CPU still executing that
 * image when it is rewritten takes the machine down with it.
 */
int mk_instance_confirm_parked(struct mk_instance *instance);

/* Return an instance's parked CPUs to the host slot before teardown */
int mk_repark_instance_to_host(struct mk_instance *instance);

/* Move one parked CPU between the host pool and a live instance */
int mk_repark_cpu_to_instance(struct mk_instance *instance, mk_phys_cpu_t phys_cpu);
int mk_repark_cpu_to_host(struct mk_instance *instance, mk_phys_cpu_t phys_cpu);

#endif /* _LINUX_MULTIKERNEL_H */
