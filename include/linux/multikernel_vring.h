/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * Device side of a split virtqueue that lives in another kernel's
 * memory. That memory is in this kernel's direct map, so the ring and
 * every buffer are reached by plain pointer once their physical ranges
 * have been checked against the instance's memory.
 */
#ifndef _LINUX_MULTIKERNEL_VRING_H
#define _LINUX_MULTIKERNEL_VRING_H

#include <linux/types.h>
#include <linux/virtio_ring.h>

struct mk_virtio_hdev;
struct mk_vring_range;

struct mk_vring_seg {
	void *va;
	u32 len;
};

/*
 * One descriptor chain. Readable segments come first, as the spec
 * requires; @nread counts them, @len is the sum of every segment.
 */
struct mk_vring_chain {
	u16 head;
	u32 nsegs;
	u32 nread;
	u32 len;
	struct mk_vring_seg *segs;
};

struct mk_vring {
	struct vring vr;
	struct mk_vring_range *ranges;
	unsigned int nranges;
	u16 num;
	u16 last_avail_idx;
	u16 used_idx;		/* shadow of used->idx */
	u16 pending_used;	/* used entries written but not yet published */
	u16 signalled_used;
	bool signalled_used_valid;
	bool event_idx;
	bool broken;
	struct mk_vring_seg *segs;
};

int mk_vring_init(struct mk_vring *r, struct mk_virtio_hdev *hdev, unsigned int queue);
void mk_vring_cleanup(struct mk_vring *r);

/* 1 with @c filled, 0 when the driver has posted nothing, negative if the ring is broken */
int mk_vring_next(struct mk_vring *r, struct mk_vring_chain *c);
/* Give back the last @n chains taken with mk_vring_next() and forget their used entries */
void mk_vring_unget(struct mk_vring *r, unsigned int n);

void mk_vring_add_used(struct mk_vring *r, u16 head, u32 len);
void mk_vring_publish_used(struct mk_vring *r);
bool mk_vring_need_call(struct mk_vring *r);

/* Returns true when the driver already posted more than we have consumed */
bool mk_vring_enable_kick(struct mk_vring *r);
void mk_vring_disable_kick(struct mk_vring *r);

/* Byte @off into the readable part of the chain, and into the writable part */
u32 mk_vring_copy_from(const struct mk_vring_chain *c, u32 off, void *dst, u32 len);
u32 mk_vring_copy_to(const struct mk_vring_chain *c, u32 off, const void *src, u32 len);

static inline u32 mk_vring_chain_writable(const struct mk_vring_chain *c)
{
	u32 i, len = 0;

	for (i = c->nread; i < c->nsegs; i++)
		len += c->segs[i].len;
	return len;
}

#endif /* _LINUX_MULTIKERNEL_VRING_H */
