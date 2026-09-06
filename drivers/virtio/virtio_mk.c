// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * Virtio transport over a multikernel shared device table. The table
 * entry is plain memory shared with the device-side kernel; kicks and
 * calls are pending bits plus the multikernel IPI.
 */
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <uapi/linux/multikernel_virtio.h>

#define MK_VIRTIO_ACK_TIMEOUT_US	(2 * USEC_PER_SEC)

struct mk_virtio {
	struct virtio_device vdev;
	struct platform_device *pdev;
	struct mk_virtio_entry *entry;
	struct mk_virtio_table *table;
	struct mk_doorbell doorbell;
	struct virtqueue *vqs[MK_VIRTIO_MAX_QUEUES];
	u32 seq;
};

#define to_mk_virtio(vd) container_of(vd, struct mk_virtio, vdev)

/*
 * Process context only: status writes and reset come from probe and
 * remove. A backend that never answers leaves status at zero, which is
 * how the virtio core learns the device is not there.
 */
static void mk_virtio_sync(struct mk_virtio *mk)
{
	struct mk_virtio_entry *e = mk->entry;
	u32 ack;

	mk->seq++;
	WRITE_ONCE(e->req_seq, mk->seq);
	/* The backend reads status and req_seq once it sees ctrl_pending */
	smp_wmb();
	WRITE_ONCE(e->ctrl_pending, 1);
	mk_doorbell_ring(mk->table->doorbell_cpu);

	if (read_poll_timeout(READ_ONCE, ack, ack == mk->seq, 50,
			      MK_VIRTIO_ACK_TIMEOUT_US, false, e->ack_seq)) {
		dev_err(&mk->pdev->dev, "no backend answered\n");
		WRITE_ONCE(e->status, 0);
	}
	/* Whatever the backend changed before acking is read after the ack */
	smp_rmb();
}

static u64 mk_virtio_get_features(struct virtio_device *vdev)
{
	return READ_ONCE(to_mk_virtio(vdev)->entry->device_features);
}

static int mk_virtio_finalize_features(struct virtio_device *vdev)
{
	struct mk_virtio *mk = to_mk_virtio(vdev);

	vring_transport_features(vdev);
	if (!__virtio_test_bit(vdev, VIRTIO_F_VERSION_1))
		return -EINVAL;
	WRITE_ONCE(mk->entry->driver_features, vdev->features);
	return 0;
}

static void mk_virtio_get(struct virtio_device *vdev, unsigned int offset,
			  void *buf, unsigned int len)
{
	struct mk_virtio *mk = to_mk_virtio(vdev);

	if (offset + len > MK_VIRTIO_CONFIG_SIZE)
		return;
	memcpy(buf, mk->entry->config + offset, len);
}

static void mk_virtio_set(struct virtio_device *vdev, unsigned int offset,
			  const void *buf, unsigned int len)
{
	struct mk_virtio *mk = to_mk_virtio(vdev);

	if (offset + len > MK_VIRTIO_CONFIG_SIZE)
		return;
	memcpy(mk->entry->config + offset, buf, len);
}

static u32 mk_virtio_generation(struct virtio_device *vdev)
{
	return READ_ONCE(to_mk_virtio(vdev)->entry->config_generation);
}

static u8 mk_virtio_get_status(struct virtio_device *vdev)
{
	return READ_ONCE(to_mk_virtio(vdev)->entry->status);
}

static void mk_virtio_set_status(struct virtio_device *vdev, u8 status)
{
	struct mk_virtio *mk = to_mk_virtio(vdev);

	WRITE_ONCE(mk->entry->status, status);
	mk_virtio_sync(mk);
}

static void mk_virtio_reset(struct virtio_device *vdev)
{
	struct mk_virtio *mk = to_mk_virtio(vdev);

	WRITE_ONCE(mk->entry->status, 0);
	mk_virtio_sync(mk);
}

static bool mk_virtio_notify(struct virtqueue *vq)
{
	struct mk_virtio *mk = to_mk_virtio(vq->vdev);

	set_bit(vq->index, (unsigned long *)&mk->entry->kick_pending);
	mk_doorbell_ring(mk->table->doorbell_cpu);
	return true;
}

/* Hardirq, on whichever CPU the backend IPIed */
static void mk_virtio_scan(struct mk_doorbell *db)
{
	struct mk_virtio *mk = container_of(db, struct mk_virtio, doorbell);
	u64 calls = xchg(&mk->entry->call_pending, 0);
	unsigned int q;

	if (!calls)
		return;
	if (calls & BIT_ULL(MK_VIRTIO_CALL_CONFIG))
		virtio_config_changed(&mk->vdev);
	for_each_set_bit(q, (unsigned long *)&calls, MK_VIRTIO_MAX_QUEUES) {
		struct virtqueue *vq = READ_ONCE(mk->vqs[q]);

		if (vq)
			vring_interrupt(0, vq);
	}
}

static void mk_virtio_del_vqs(struct virtio_device *vdev)
{
	struct mk_virtio *mk = to_mk_virtio(vdev);
	struct virtqueue *vq, *n;

	list_for_each_entry_safe(vq, n, &vdev->vqs, list) {
		struct mk_virtio_queue *q = &mk->entry->queues[vq->index];

		WRITE_ONCE(mk->vqs[vq->index], NULL);
		WRITE_ONCE(q->enable, 0);
		vring_del_virtqueue(vq);
	}
}

static struct virtqueue *mk_virtio_setup_vq(struct virtio_device *vdev,
					    unsigned int index,
					    void (*callback)(struct virtqueue *),
					    const char *name, bool ctx)
{
	struct mk_virtio *mk = to_mk_virtio(vdev);
	struct mk_virtio_queue *q = &mk->entry->queues[index];
	struct virtqueue *vq;
	u32 num = READ_ONCE(q->num_max);

	if (index >= mk->entry->num_queues || !num)
		return ERR_PTR(-ENOENT);

	vq = vring_create_virtqueue(index, num, PAGE_SIZE, vdev, true, true, ctx,
				    mk_virtio_notify, callback, name);
	if (!vq)
		return ERR_PTR(-ENOMEM);
	vq->num_max = num;

	q->desc = virtqueue_get_desc_addr(vq);
	q->avail = virtqueue_get_avail_addr(vq);
	q->used = virtqueue_get_used_addr(vq);
	q->num = virtqueue_get_vring_size(vq);
	q->call_cpu = arch_cpu_physical_id(smp_processor_id());
	/* The backend reads the addresses only after it sees enable */
	smp_wmb();
	WRITE_ONCE(q->enable, 1);
	WRITE_ONCE(mk->vqs[index], vq);
	return vq;
}

static int mk_virtio_find_vqs(struct virtio_device *vdev, unsigned int nvqs,
			      struct virtqueue *vqs[],
			      struct virtqueue_info vqs_info[],
			      struct irq_affinity *desc)
{
	unsigned int i, queue_idx = 0;

	for (i = 0; i < nvqs; i++) {
		if (!vqs_info[i].name) {
			vqs[i] = NULL;
			continue;
		}
		vqs[i] = mk_virtio_setup_vq(vdev, queue_idx++, vqs_info[i].callback,
					    vqs_info[i].name, vqs_info[i].ctx);
		if (IS_ERR(vqs[i])) {
			mk_virtio_del_vqs(vdev);
			return PTR_ERR(vqs[i]);
		}
	}
	return 0;
}

static const char *mk_virtio_bus_name(struct virtio_device *vdev)
{
	return "multikernel";
}

static const struct virtio_config_ops mk_virtio_config_ops = {
	.get = mk_virtio_get,
	.set = mk_virtio_set,
	.generation = mk_virtio_generation,
	.get_status = mk_virtio_get_status,
	.set_status = mk_virtio_set_status,
	.reset = mk_virtio_reset,
	.find_vqs = mk_virtio_find_vqs,
	.del_vqs = mk_virtio_del_vqs,
	.get_features = mk_virtio_get_features,
	.finalize_features = mk_virtio_finalize_features,
	.bus_name = mk_virtio_bus_name,
};

static void mk_virtio_release(struct device *dev)
{
	kfree(to_mk_virtio(container_of(dev, struct virtio_device, dev)));
}

static int mk_virtio_probe(struct platform_device *pdev)
{
	struct mk_virtio *mk;
	struct resource *res;
	u64 table_phys;
	int rc;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res || resource_size(res) < MK_VIRTIO_ENTRY_SIZE)
		return -EINVAL;
	if (of_property_read_u64(pdev->dev.of_node, "multikernel,table", &table_phys))
		return -EINVAL;

	mk = kzalloc_obj(*mk, GFP_KERNEL);
	if (!mk)
		return -ENOMEM;

	mk->entry = memremap(res->start, MK_VIRTIO_ENTRY_SIZE, MEMREMAP_WB);
	if (!mk->entry) {
		rc = -ENOMEM;
		goto free;
	}
	if (!mk->entry->device_id) {
		dev_info(&pdev->dev, "empty slot\n");
		rc = -ENODEV;
		goto unmap_entry;
	}
	mk->table = memremap(table_phys, 4096, MEMREMAP_WB);
	if (!mk->table || mk->table->magic != MK_VIRTIO_TABLE_MAGIC) {
		dev_err(&pdev->dev, "bad table\n");
		rc = -ENODEV;
		goto unmap_table;
	}
	mk->pdev = pdev;
	mk->vdev.dev.parent = &pdev->dev;
	mk->vdev.dev.release = mk_virtio_release;
	mk->vdev.config = &mk_virtio_config_ops;
	mk->vdev.id.device = mk->entry->device_id;
	mk->vdev.id.vendor = mk->entry->vendor_id;
	mk->doorbell.scan = mk_virtio_scan;
	mk_doorbell_register(&mk->doorbell);
	platform_set_drvdata(pdev, mk);
	dev_info(&pdev->dev, "device %u, %u queues\n", mk->entry->device_id,
		 mk->entry->num_queues);

	rc = register_virtio_device(&mk->vdev);
	if (rc) {
		mk_doorbell_unregister(&mk->doorbell);
		put_device(&mk->vdev.dev);
	}
	return rc;
unmap_table:
	if (mk->table)
		memunmap(mk->table);
unmap_entry:
	memunmap(mk->entry);
free:
	kfree(mk);
	return rc;
}

static void mk_virtio_remove(struct platform_device *pdev)
{
	struct mk_virtio *mk = platform_get_drvdata(pdev);

	unregister_virtio_device(&mk->vdev);
	mk_doorbell_unregister(&mk->doorbell);
	memunmap(mk->table);
	memunmap(mk->entry);
}

static const struct of_device_id mk_virtio_match[] = {
	{ .compatible = "multikernel,virtio" },
	{},
};
MODULE_DEVICE_TABLE(of, mk_virtio_match);

static struct platform_driver mk_virtio_driver = {
	.probe = mk_virtio_probe,
	.remove = mk_virtio_remove,
	.driver = {
		.name = "virtio_mk",
		.of_match_table = mk_virtio_match,
	},
};
module_platform_driver(mk_virtio_driver);

MODULE_DESCRIPTION("Virtio transport over multikernel shared memory");
MODULE_LICENSE("GPL");
