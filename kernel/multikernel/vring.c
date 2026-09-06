// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * Device side of a split virtqueue in an app-kernel's memory. Every
 * address the driver hands over is checked against the instance's
 * memory before it is dereferenced: the driver is another kernel, and a
 * bad descriptor must break the ring, never this kernel.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/virtio_byteorder.h>
#include <linux/multikernel.h>
#include <linux/multikernel_vring.h>
#include <uapi/linux/multikernel_virtio.h>
#include "internal.h"

struct mk_vring_range {
	u64 start;
	u64 end;
};

static int mk_vring_snapshot_ranges(struct mk_vring *r, struct mk_instance *instance)
{
	struct mk_memory_region *region;
	unsigned int n = 0;

	mutex_lock(&mk_instance_mutex);
	list_for_each_entry(region, &instance->memory_regions, list)
		n++;
	r->ranges = kcalloc(n, sizeof(*r->ranges), GFP_KERNEL);
	if (r->ranges) {
		list_for_each_entry(region, &instance->memory_regions, list) {
			r->ranges[r->nranges].start = region->res.start;
			r->ranges[r->nranges].end = region->res.end;
			r->nranges++;
		}
	}
	mutex_unlock(&mk_instance_mutex);
	return r->ranges ? 0 : -ENOMEM;
}

static void *mk_vring_translate(const struct mk_vring *r, u64 addr, u64 len)
{
	u64 last = addr + len - 1;
	unsigned int i;

	if (!len || last < addr)
		return NULL;
	for (i = 0; i < r->nranges; i++)
		if (addr >= r->ranges[i].start && last <= r->ranges[i].end)
			return phys_to_virt(addr);
	return NULL;
}

int mk_vring_init(struct mk_vring *r, struct mk_virtio_hdev *hdev, unsigned int queue)
{
	struct mk_virtio_queue *q = &hdev->entry->queues[queue];
	u64 features = READ_ONCE(hdev->entry->driver_features);
	u32 num = READ_ONCE(q->num);
	int ret;

	memset(r, 0, sizeof(*r));
	if (!READ_ONCE(q->enable) || !num || num > 32768 || !is_power_of_2(num))
		return -ENXIO;

	ret = mk_vring_snapshot_ranges(r, hdev->instance);
	if (ret)
		return ret;

	r->vr.num = num;
	r->vr.desc = mk_vring_translate(r, q->desc, num * sizeof(struct vring_desc));
	r->vr.avail = mk_vring_translate(r, q->avail, sizeof(struct vring_avail) +
					 (num + 1) * sizeof(__virtio16));
	r->vr.used = mk_vring_translate(r, q->used, sizeof(struct vring_used) +
					num * sizeof(struct vring_used_elem) + sizeof(__virtio16));
	r->segs = kcalloc(num, sizeof(*r->segs), GFP_KERNEL);
	if (!r->vr.desc || !r->vr.avail || !r->vr.used || !r->segs) {
		mk_vring_cleanup(r);
		return r->segs ? -EINVAL : -ENOMEM;
	}
	r->num = num;
	r->event_idx = features & BIT_ULL(VIRTIO_RING_F_EVENT_IDX);
	return 0;
}
EXPORT_SYMBOL_GPL(mk_vring_init);

void mk_vring_cleanup(struct mk_vring *r)
{
	kfree(r->segs);
	kfree(r->ranges);
	r->segs = NULL;
	r->ranges = NULL;
	r->nranges = 0;
	r->num = 0;
}
EXPORT_SYMBOL_GPL(mk_vring_cleanup);

static int mk_vring_add_seg(struct mk_vring *r, struct mk_vring_chain *c,
			    const struct vring_desc *d)
{
	bool write = __virtio16_to_cpu(true, d->flags) & VRING_DESC_F_WRITE;
	u32 len = __virtio32_to_cpu(true, d->len);
	void *va = mk_vring_translate(r, __virtio64_to_cpu(true, d->addr), len);

	if (!va || c->nsegs == r->num)
		return -EINVAL;
	/* Readable after writable is a driver bug the spec forbids */
	if (!write && c->nsegs != c->nread)
		return -EINVAL;
	c->segs[c->nsegs].va = va;
	c->segs[c->nsegs].len = len;
	c->nsegs++;
	if (!write)
		c->nread++;
	c->len += len;
	return 0;
}

/*
 * Walk @table, a descriptor array of @n entries, from entry 0. Each
 * descriptor is copied out before it is looked at, so the driver cannot
 * change one between the check and the use.
 */
static int mk_vring_walk(struct mk_vring *r, struct mk_vring_chain *c,
			 const struct vring_desc *table, u32 n, u16 first,
			 bool allow_indirect)
{
	unsigned int steps = 0;
	u32 i = first;

	while (1) {
		struct vring_desc d;

		if (i >= n || steps++ >= n)
			return -EINVAL;
		memcpy(&d, &table[i], sizeof(d));
		if (__virtio16_to_cpu(true, d.flags) & VRING_DESC_F_INDIRECT) {
			u32 len = __virtio32_to_cpu(true, d.len);
			const struct vring_desc *ind;
			int ret;

			ind = mk_vring_translate(r, __virtio64_to_cpu(true, d.addr), len);
			if (!allow_indirect || !ind || len % sizeof(*ind))
				return -EINVAL;
			ret = mk_vring_walk(r, c, ind, len / sizeof(*ind), 0, false);
			if (ret)
				return ret;
		} else if (mk_vring_add_seg(r, c, &d)) {
			return -EINVAL;
		}
		if (!(__virtio16_to_cpu(true, d.flags) & VRING_DESC_F_NEXT))
			return 0;
		i = __virtio16_to_cpu(true, d.next);
	}
}

int mk_vring_next(struct mk_vring *r, struct mk_vring_chain *c)
{
	u16 avail_idx, head;
	int ret;

	if (r->broken)
		return -EIO;
	avail_idx = __virtio16_to_cpu(true, READ_ONCE(r->vr.avail->idx));
	if (avail_idx == r->last_avail_idx)
		return 0;
	/* The ring entry is read only after the index that announced it */
	smp_rmb();
	head = __virtio16_to_cpu(true,
				 READ_ONCE(r->vr.avail->ring[r->last_avail_idx & (r->num - 1)]));

	c->head = head;
	c->nsegs = 0;
	c->nread = 0;
	c->len = 0;
	c->segs = r->segs;
	ret = mk_vring_walk(r, c, r->vr.desc, r->num, head, true);
	if (ret) {
		pr_warn_ratelimited("multikernel: bad descriptor chain at %u, ring broken\n",
				    head);
		r->broken = true;
		return ret;
	}
	r->last_avail_idx++;
	return 1;
}
EXPORT_SYMBOL_GPL(mk_vring_next);

void mk_vring_unget(struct mk_vring *r, unsigned int n)
{
	r->last_avail_idx -= n;
	r->pending_used = 0;
}
EXPORT_SYMBOL_GPL(mk_vring_unget);

void mk_vring_add_used(struct mk_vring *r, u16 head, u32 len)
{
	u16 idx = (r->used_idx + r->pending_used) & (r->num - 1);

	r->vr.used->ring[idx].id = __cpu_to_virtio32(true, head);
	r->vr.used->ring[idx].len = __cpu_to_virtio32(true, len);
	r->pending_used++;
}
EXPORT_SYMBOL_GPL(mk_vring_add_used);

void mk_vring_publish_used(struct mk_vring *r)
{
	if (!r->pending_used)
		return;
	r->used_idx += r->pending_used;
	r->pending_used = 0;
	/* Entries before the index that publishes them */
	smp_wmb();
	WRITE_ONCE(r->vr.used->idx, __cpu_to_virtio16(true, r->used_idx));
}
EXPORT_SYMBOL_GPL(mk_vring_publish_used);

bool mk_vring_need_call(struct mk_vring *r)
{
	u16 old, new, event;
	bool valid;

	/* The driver's event write and our used index write must be ordered both ways */
	smp_mb();
	if (!r->event_idx)
		return !(__virtio16_to_cpu(true, READ_ONCE(r->vr.avail->flags)) &
			 VRING_AVAIL_F_NO_INTERRUPT);

	old = r->signalled_used;
	valid = r->signalled_used_valid;
	new = r->signalled_used = r->used_idx;
	r->signalled_used_valid = true;
	if (!valid)
		return true;
	event = __virtio16_to_cpu(true, READ_ONCE(vring_used_event(&r->vr)));
	return vring_need_event(event, new, old);
}
EXPORT_SYMBOL_GPL(mk_vring_need_call);

static void mk_vring_set_used_flags(struct mk_vring *r, u16 flags)
{
	WRITE_ONCE(r->vr.used->flags, __cpu_to_virtio16(true, flags));
}

bool mk_vring_enable_kick(struct mk_vring *r)
{
	if (r->event_idx)
		WRITE_ONCE(vring_avail_event(&r->vr), __cpu_to_virtio16(true, r->last_avail_idx));
	else
		mk_vring_set_used_flags(r, 0);
	/* The event must be visible before we look for buffers it would announce */
	smp_mb();
	return __virtio16_to_cpu(true, READ_ONCE(r->vr.avail->idx)) != r->last_avail_idx;
}
EXPORT_SYMBOL_GPL(mk_vring_enable_kick);

void mk_vring_disable_kick(struct mk_vring *r)
{
	if (!r->event_idx)
		mk_vring_set_used_flags(r, VRING_USED_F_NO_NOTIFY);
}
EXPORT_SYMBOL_GPL(mk_vring_disable_kick);

static u32 mk_vring_copy(const struct mk_vring_chain *c, u32 first, u32 last,
			 u32 off, void *buf, u32 len, bool to_chain)
{
	u32 i, done = 0;

	for (i = first; i < last && done < len; i++) {
		const struct mk_vring_seg *s = &c->segs[i];
		u32 n;

		if (off >= s->len) {
			off -= s->len;
			continue;
		}
		n = min(s->len - off, len - done);
		if (to_chain)
			memcpy(s->va + off, buf + done, n);
		else
			memcpy(buf + done, s->va + off, n);
		done += n;
		off = 0;
	}
	return done;
}

u32 mk_vring_copy_from(const struct mk_vring_chain *c, u32 off, void *dst, u32 len)
{
	return mk_vring_copy(c, 0, c->nread, off, dst, len, false);
}
EXPORT_SYMBOL_GPL(mk_vring_copy_from);

u32 mk_vring_copy_to(const struct mk_vring_chain *c, u32 off, const void *src, u32 len)
{
	return mk_vring_copy(c, c->nread, c->nsegs, off, (void *)src, len, true);
}
EXPORT_SYMBOL_GPL(mk_vring_copy_to);
