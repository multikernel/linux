/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_MULTIKERNEL_VIRTIO_H
#define _UAPI_LINUX_MULTIKERNEL_VIRTIO_H

#include <linux/types.h>

/*
 * Shared device table between a device-side kernel and an app-kernel.
 * Little endian, naturally aligned. Sizes are the contract: never
 * reorder, only take fields from reserved space.
 */
#define MK_VIRTIO_TABLE_MAGIC	0x4f495456U	/* "VTIO" */
#define MK_VIRTIO_TABLE_VERSION	1
#define MK_VIRTIO_MAX_DEVICES	16
#define MK_VIRTIO_MAX_QUEUES	8
#define MK_VIRTIO_CONFIG_SIZE	256
#define MK_VIRTIO_ENTRY_SIZE	1024
#define MK_VIRTIO_TABLE_SIZE	(4096 + MK_VIRTIO_MAX_DEVICES * MK_VIRTIO_ENTRY_SIZE)
#define MK_VIRTIO_ENTRY_OFFSET(i)	(4096 + (i) * MK_VIRTIO_ENTRY_SIZE)

/* call_pending bit meaning "config changed" rather than a queue */
#define MK_VIRTIO_CALL_CONFIG	63

struct mk_virtio_queue {
	__u64 desc;		/* physical, driver writes */
	__u64 avail;
	__u64 used;
	__u32 num_max;		/* device writes at table fill */
	__u32 num;		/* driver writes */
	__u32 enable;		/* driver writes 1 when the queue is ready */
	__u32 reserved;
	__u64 call_cpu;		/* physical CPU the backend IPIs for this queue */
	__u64 reserved2[2];
};

struct mk_virtio_entry {
	__u32 device_id;	/* virtio device id, 0 = empty slot */
	__u32 vendor_id;
	__u32 num_queues;
	__u32 reserved0;
	__u64 device_features;	/* backend writes before the driver probes */
	__u64 driver_features;	/* driver writes at finalize_features */
	__u32 status;		/* driver writes; backend clears FEATURES_OK to refuse */
	__u32 config_generation;/* backend bumps after changing config */
	__u32 req_seq;		/* driver bumps after a status or reset write */
	__u32 ack_seq;		/* backend copies req_seq after acting */
	__u64 kick_pending;	/* bit q: driver kicked queue q */
	__u64 call_pending;	/* bit q: backend signalled queue q; bit 63: config */
	__u32 ctrl_pending;	/* driver rang the doorbell for a req_seq change */
	__u32 reserved1[15];
	__u8  config[MK_VIRTIO_CONFIG_SIZE];
	struct mk_virtio_queue queues[MK_VIRTIO_MAX_QUEUES];
	__u8  reserved2[128];
};

struct mk_virtio_table {
	__u32 magic;
	__u32 version;
	__u32 num_devices;
	__u32 entry_size;
	__u64 doorbell_cpu;	/* physical CPU the driver IPIs for kicks and ctrl */
	__u32 device_instance;	/* instance id of the device side */
	__u32 reserved[1017];
};

#endif
