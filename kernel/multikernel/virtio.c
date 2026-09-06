// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/multikernel.h>
#include <uapi/linux/multikernel_virtio.h>
#include "internal.h"

static_assert(sizeof(struct mk_virtio_queue) == 64);
static_assert(sizeof(struct mk_virtio_entry) == MK_VIRTIO_ENTRY_SIZE);
static_assert(sizeof(struct mk_virtio_table) == 4096);
static_assert(offsetof(struct mk_virtio_entry, config) == 128);
static_assert(offsetof(struct mk_virtio_entry, queues) == 384);

static mk_phys_cpu_t mk_virtio_doorbell_cpu(void)
{
	if (mk_self->ipi_target != MK_PHYS_CPU_INVALID)
		return mk_self->ipi_target;
	return mk_cpu_set_first(mk_self->cpus);
}

int mk_virtio_table_alloc(struct mk_instance *instance)
{
	struct mk_virtio_table *table;
	struct mk_virtio_dev *vdev;
	int i = 0;

	if (instance->virtio_table)
		return 0;

	table = mk_instance_ctrl_alloc(instance, MK_VIRTIO_TABLE_SIZE, PAGE_SIZE);
	if (!table)
		return -ENOMEM;

	memset(table, 0, MK_VIRTIO_TABLE_SIZE);
	table->magic = MK_VIRTIO_TABLE_MAGIC;
	table->version = MK_VIRTIO_TABLE_VERSION;
	table->entry_size = MK_VIRTIO_ENTRY_SIZE;
	table->num_devices = instance->virtio_device_count;
	table->doorbell_cpu = mk_virtio_doorbell_cpu();
	table->device_instance = mk_self->id;

	list_for_each_entry(vdev, &instance->virtio_devices, list) {
		struct mk_virtio_entry *e = (void *)table + MK_VIRTIO_ENTRY_OFFSET(i);
		int q;

		e->device_id = vdev->device_id;
		e->vendor_id = MK_VIRTIO_TABLE_MAGIC;
		e->num_queues = vdev->num_queues;
		for (q = 0; q < vdev->num_queues; q++)
			e->queues[q].num_max = vdev->queue_size;
		i++;
	}

	instance->virtio_table = table;
	return 0;
}

void mk_virtio_devices_free(struct mk_instance *instance)
{
	struct mk_virtio_dev *vdev, *tmp;

	list_for_each_entry_safe(vdev, tmp, &instance->virtio_devices, list) {
		list_del(&vdev->list);
		kfree(vdev);
	}
	instance->virtio_device_count = 0;
}
