// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * Host side of the virtio transport: the status handshake with each
 * app-kernel driver, and the backends that serve the devices.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/virtio_config.h>
#include <linux/workqueue.h>
#include <linux/multikernel.h>
#include <uapi/linux/multikernel_virtio.h>
#include "internal.h"

struct mk_virtio_host {
	struct mk_instance *instance;
	struct mk_virtio_table *table;
	struct mk_doorbell doorbell;
	struct work_struct work;
	unsigned long ctrl;		/* devices whose driver rang the control doorbell */
	struct list_head list;
	struct mk_virtio_hdev devs[MK_VIRTIO_MAX_DEVICES];
};

/* Serializes the backend list, the host list, bind and unbind, start and stop */
static DEFINE_MUTEX(mk_virtio_mutex);
static LIST_HEAD(mk_virtio_backends);
static LIST_HEAD(mk_virtio_hosts);

static void mk_virtio_hdev_stop(struct mk_virtio_hdev *hdev)
{
	if (!hdev->started)
		return;
	WRITE_ONCE(hdev->started, false);
	/* Kicks run under the doorbell scan's RCU read side */
	synchronize_rcu();
	hdev->backend->stop(hdev);
}

static void mk_virtio_hdev_bind(struct mk_virtio_hdev *hdev,
				const struct mk_virtio_backend *backend)
{
	hdev->entry->device_features = backend->features;
	if (backend->bind(hdev)) {
		hdev->entry->device_features = 0;
		return;
	}
	hdev->backend = backend;
}

static void mk_virtio_hdev_unbind(struct mk_virtio_hdev *hdev)
{
	const struct mk_virtio_backend *backend = hdev->backend;

	if (!backend)
		return;
	mk_virtio_hdev_stop(hdev);
	hdev->backend = NULL;
	backend->unbind(hdev);
	hdev->entry->device_features = 0;
}

static void mk_virtio_hdev_ctrl(struct mk_virtio_hdev *hdev)
{
	struct mk_virtio_entry *e = hdev->entry;
	u32 seq = READ_ONCE(e->req_seq);
	u32 status;

	/* Pairs with the driver's barrier between req_seq and ctrl_pending */
	smp_rmb();
	status = READ_ONCE(e->status);

	if (!status) {
		mk_virtio_hdev_stop(hdev);
	} else if (hdev->backend) {
		if ((status & VIRTIO_CONFIG_S_FEATURES_OK) &&
		    (READ_ONCE(e->driver_features) & ~e->device_features))
			WRITE_ONCE(e->status, status & ~VIRTIO_CONFIG_S_FEATURES_OK);
		if ((status & VIRTIO_CONFIG_S_DRIVER_OK) && !hdev->started &&
		    !hdev->backend->start(hdev))
			WRITE_ONCE(hdev->started, true);
	}

	/* The driver reads status after it sees the ack */
	smp_wmb();
	WRITE_ONCE(e->ack_seq, seq);
}

static void mk_virtio_host_work(struct work_struct *work)
{
	struct mk_virtio_host *host = container_of(work, struct mk_virtio_host, work);
	unsigned int i;

	mutex_lock(&mk_virtio_mutex);
	for_each_set_bit(i, &host->ctrl, MK_VIRTIO_MAX_DEVICES) {
		clear_bit(i, &host->ctrl);
		mk_virtio_hdev_ctrl(&host->devs[i]);
	}
	mutex_unlock(&mk_virtio_mutex);
}

/* Hardirq on the host's doorbell CPU */
static void mk_virtio_host_scan(struct mk_doorbell *db)
{
	struct mk_virtio_host *host = container_of(db, struct mk_virtio_host, doorbell);
	unsigned int i, q;

	for (i = 0; i < host->table->num_devices; i++) {
		struct mk_virtio_hdev *hdev = &host->devs[i];
		u64 kicks = xchg(&hdev->entry->kick_pending, 0);

		if (xchg(&hdev->entry->ctrl_pending, 0)) {
			set_bit(i, &host->ctrl);
			schedule_work(&host->work);
		}
		if (!kicks || !READ_ONCE(hdev->started))
			continue;
		for_each_set_bit(q, (unsigned long *)&kicks, MK_VIRTIO_MAX_QUEUES)
			hdev->backend->kick(hdev, q);
	}
}

void mk_virtio_hdev_call(struct mk_virtio_hdev *hdev, unsigned int queue)
{
	struct mk_virtio_entry *e = hdev->entry;
	mk_phys_cpu_t cpu = READ_ONCE(e->queues[queue].call_cpu);

	if (!cpu) {
		cpu = hdev->instance->ipi_target;
		if (cpu == MK_PHYS_CPU_INVALID)
			cpu = mk_cpu_set_first(hdev->instance->cpus);
	}
	set_bit(queue, (unsigned long *)&e->call_pending);
	mk_doorbell_ring(cpu);
}
EXPORT_SYMBOL_GPL(mk_virtio_hdev_call);

static const struct mk_virtio_backend *mk_virtio_find_backend(u32 device_id)
{
	const struct mk_virtio_backend *backend;

	list_for_each_entry(backend, &mk_virtio_backends, list)
		if (backend->device_id == device_id)
			return backend;
	return NULL;
}

int mk_virtio_register_backend(struct mk_virtio_backend *backend)
{
	struct mk_virtio_host *host;
	unsigned int i;

	mutex_lock(&mk_virtio_mutex);
	if (mk_virtio_find_backend(backend->device_id)) {
		mutex_unlock(&mk_virtio_mutex);
		return -EEXIST;
	}
	list_add_tail(&backend->list, &mk_virtio_backends);
	list_for_each_entry(host, &mk_virtio_hosts, list) {
		for (i = 0; i < host->table->num_devices; i++) {
			struct mk_virtio_hdev *hdev = &host->devs[i];

			if (!hdev->backend && hdev->entry->device_id == backend->device_id)
				mk_virtio_hdev_bind(hdev, backend);
		}
	}
	mutex_unlock(&mk_virtio_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(mk_virtio_register_backend);

void mk_virtio_unregister_backend(struct mk_virtio_backend *backend)
{
	struct mk_virtio_host *host;
	unsigned int i;

	mutex_lock(&mk_virtio_mutex);
	list_for_each_entry(host, &mk_virtio_hosts, list) {
		for (i = 0; i < host->table->num_devices; i++)
			if (host->devs[i].backend == backend)
				mk_virtio_hdev_unbind(&host->devs[i]);
	}
	list_del(&backend->list);
	mutex_unlock(&mk_virtio_mutex);
}
EXPORT_SYMBOL_GPL(mk_virtio_unregister_backend);

int mk_virtio_host_create(struct mk_instance *instance)
{
	struct mk_virtio_table *table = instance->virtio_table;
	struct mk_virtio_host *host;
	unsigned int i;

	host = kzalloc_obj(*host, GFP_KERNEL);
	if (!host)
		return -ENOMEM;

	host->instance = instance;
	host->table = table;
	INIT_WORK(&host->work, mk_virtio_host_work);
	for (i = 0; i < table->num_devices; i++) {
		struct mk_virtio_hdev *hdev = &host->devs[i];

		hdev->instance = instance;
		hdev->entry = (void *)table + MK_VIRTIO_ENTRY_OFFSET(i);
		hdev->index = i;
	}
	instance->virtio_host = host;

	mutex_lock(&mk_virtio_mutex);
	list_add_tail(&host->list, &mk_virtio_hosts);
	for (i = 0; i < table->num_devices; i++) {
		const struct mk_virtio_backend *backend =
			mk_virtio_find_backend(host->devs[i].entry->device_id);

		if (backend)
			mk_virtio_hdev_bind(&host->devs[i], backend);
	}
	mutex_unlock(&mk_virtio_mutex);

	host->doorbell.scan = mk_virtio_host_scan;
	mk_doorbell_register(&host->doorbell);
	return 0;
}

void mk_virtio_host_stop_all(struct mk_instance *instance)
{
	struct mk_virtio_host *host = instance->virtio_host;
	unsigned int i;

	if (!host)
		return;
	mutex_lock(&mk_virtio_mutex);
	for (i = 0; i < host->table->num_devices; i++)
		mk_virtio_hdev_stop(&host->devs[i]);
	mutex_unlock(&mk_virtio_mutex);
}

void mk_virtio_host_destroy(struct mk_instance *instance)
{
	struct mk_virtio_host *host = instance->virtio_host;
	unsigned int i;

	if (!host)
		return;
	mk_doorbell_unregister(&host->doorbell);
	cancel_work_sync(&host->work);

	mutex_lock(&mk_virtio_mutex);
	for (i = 0; i < host->table->num_devices; i++)
		mk_virtio_hdev_unbind(&host->devs[i]);
	list_del(&host->list);
	mutex_unlock(&mk_virtio_mutex);

	instance->virtio_host = NULL;
	kfree(host);
}
