// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * Physical CPU ID sets for multikernel instances.
 *
 * Physical CPU IDs (APIC ID on x86, MPIDR on arm64, hartid on riscv) are
 * sparse 64-bit values, so instance CPU assignments are kept in small
 * arrays rather than NR_CPUS-sized bitmaps. Sets are tiny (one entry per
 * assigned CPU), so linear scans are fine.
 */
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/multikernel.h>

static void mk_cpu_set_lock(const struct mk_cpu_set *set, unsigned long *flags)
{
	raw_spin_lock_irqsave((raw_spinlock_t *)&set->lock, *flags);
}

static void mk_cpu_set_unlock(const struct mk_cpu_set *set, unsigned long flags)
{
	raw_spin_unlock_irqrestore((raw_spinlock_t *)&set->lock, flags);
}

static int mk_cpu_set_index_locked(const struct mk_cpu_set *set,
				   mk_phys_cpu_t id)
{
	unsigned int i;

	for (i = 0; i < set->nr; i++) {
		if (set->ids[i] == id)
			return i;
	}

	return -1;
}

struct mk_cpu_set *mk_cpu_set_alloc(void)
{
	struct mk_cpu_set *set;

	set = kzalloc_obj(*set, GFP_KERNEL);
	if (set)
		raw_spin_lock_init(&set->lock);
	return set;
}

void mk_cpu_set_free(struct mk_cpu_set *set)
{
	if (!set)
		return;

	kfree(set->ids);
	kfree(set);
}

void mk_cpu_set_clear(struct mk_cpu_set *set)
{
	unsigned long flags;

	if (!set)
		return;

	mk_cpu_set_lock(set, &flags);
	set->nr = 0;
	mk_cpu_set_unlock(set, flags);
}

/**
 * mk_cpu_set_reserve() - Ensure capacity for additional entries
 * @set: Set to grow
 * @extra: Number of entries that must fit beyond the current count
 *
 * After a successful reserve, the next @extra mk_cpu_set_add() calls
 * cannot fail, which lets multi-CPU transfers validate and reserve up
 * front and then move entries without a rollback path.
 */
int mk_cpu_set_reserve(struct mk_cpu_set *set, unsigned int extra)
{
	mk_phys_cpu_t *ids = NULL;
	mk_phys_cpu_t *old_ids;
	unsigned int cap;
	unsigned long flags;

	if (!set)
		return -EINVAL;

	for (;;) {
		mk_cpu_set_lock(set, &flags);
		cap = set->nr + extra;
		if (cap <= set->cap) {
			mk_cpu_set_unlock(set, flags);
			kfree(ids);
			return 0;
		}
		mk_cpu_set_unlock(set, flags);

		cap = max_t(unsigned int, cap, 8);
		kfree(ids);
		ids = kcalloc(cap, sizeof(*ids), GFP_KERNEL);
		if (!ids)
			return -ENOMEM;

		mk_cpu_set_lock(set, &flags);
		if (set->nr + extra > cap) {
			mk_cpu_set_unlock(set, flags);
			continue;
		}
		if (cap <= set->cap) {
			mk_cpu_set_unlock(set, flags);
			kfree(ids);
			return 0;
		}

		memcpy(ids, set->ids, set->nr * sizeof(*ids));
		old_ids = set->ids;
		set->ids = ids;
		set->cap = cap;
		mk_cpu_set_unlock(set, flags);
		kfree(old_ids);
		return 0;
	}
}

/* Idempotent: adding an ID already in the set succeeds without effect */
int mk_cpu_set_add(struct mk_cpu_set *set, mk_phys_cpu_t id)
{
	unsigned long flags;
	int ret;

	if (!set)
		return -EINVAL;

	for (;;) {
		mk_cpu_set_lock(set, &flags);
		if (mk_cpu_set_index_locked(set, id) >= 0) {
			mk_cpu_set_unlock(set, flags);
			return 0;
		}
		if (set->nr < set->cap) {
			set->ids[set->nr++] = id;
			mk_cpu_set_unlock(set, flags);
			return 0;
		}
		mk_cpu_set_unlock(set, flags);

		ret = mk_cpu_set_reserve(set, 1);
		if (ret)
			return ret;
	}
}

bool mk_cpu_set_del(struct mk_cpu_set *set, mk_phys_cpu_t id)
{
	unsigned long flags;
	int idx;

	if (!set)
		return false;

	mk_cpu_set_lock(set, &flags);
	idx = mk_cpu_set_index_locked(set, id);
	if (idx < 0) {
		mk_cpu_set_unlock(set, flags);
		return false;
	}

	memmove(&set->ids[idx], &set->ids[idx + 1],
		(set->nr - idx - 1) * sizeof(set->ids[0]));
	set->nr--;
	mk_cpu_set_unlock(set, flags);
	return true;
}

bool mk_cpu_set_contains(const struct mk_cpu_set *set, mk_phys_cpu_t id)
{
	unsigned long flags;
	bool found;

	if (!set)
		return false;

	mk_cpu_set_lock(set, &flags);
	found = mk_cpu_set_index_locked(set, id) >= 0;
	mk_cpu_set_unlock(set, flags);
	return found;
}

unsigned int mk_cpu_set_count(const struct mk_cpu_set *set)
{
	unsigned long flags;
	unsigned int nr;

	if (!set)
		return 0;

	mk_cpu_set_lock(set, &flags);
	nr = set->nr;
	mk_cpu_set_unlock(set, flags);
	return nr;
}

bool mk_cpu_set_empty(const struct mk_cpu_set *set)
{
	return mk_cpu_set_count(set) == 0;
}

mk_phys_cpu_t mk_cpu_set_first(const struct mk_cpu_set *set)
{
	unsigned long flags;
	mk_phys_cpu_t id;

	if (!set)
		return MK_PHYS_CPU_INVALID;

	mk_cpu_set_lock(set, &flags);
	id = set->nr ? set->ids[0] : MK_PHYS_CPU_INVALID;
	mk_cpu_set_unlock(set, flags);
	return id;
}

bool mk_cpu_set_get(const struct mk_cpu_set *set, unsigned int index,
		    mk_phys_cpu_t *id)
{
	unsigned long flags;
	bool found = false;

	if (!set || !id)
		return false;

	mk_cpu_set_lock(set, &flags);
	if (index < set->nr) {
		*id = set->ids[index];
		found = true;
	}
	mk_cpu_set_unlock(set, flags);
	return found;
}

int mk_cpu_set_copy(struct mk_cpu_set *dst, const struct mk_cpu_set *src)
{
	unsigned long src_flags;
	unsigned long dst_flags;
	unsigned int nr;
	int ret;

	if (!dst || !src)
		return -EINVAL;

	for (;;) {
		nr = mk_cpu_set_count(src);
		ret = mk_cpu_set_reserve(dst, nr);
		if (ret)
			return ret;

		mk_cpu_set_lock(src, &src_flags);
		if (src->nr > dst->cap) {
			mk_cpu_set_unlock(src, src_flags);
			continue;
		}

		mk_cpu_set_lock(dst, &dst_flags);
		memcpy(dst->ids, src->ids, src->nr * sizeof(dst->ids[0]));
		dst->nr = src->nr;
		mk_cpu_set_unlock(dst, dst_flags);
		mk_cpu_set_unlock(src, src_flags);
		return 0;
	}
}

/**
 * mk_cpu_set_format() - Format a set as a human-readable ID list
 * @buf: Output buffer
 * @size: Buffer size
 * @set: Set to format
 *
 * Writes none for an empty set, a comma-separated list of physical
 * IDs otherwise. Output is truncated to @size. Returns the number of
 * characters written.
 */
int mk_cpu_set_format(char *buf, size_t size, const struct mk_cpu_set *set)
{
	unsigned long flags;
	unsigned int i;
	int len = 0;

	if (!buf || !size)
		return 0;
	if (!set)
		return scnprintf(buf, size, "none");

	mk_cpu_set_lock(set, &flags);
	if (!set->nr) {
		mk_cpu_set_unlock(set, flags);
		return scnprintf(buf, size, "none");
	}

	for (i = 0; i < set->nr && len < size; i++) {
		len += scnprintf(buf + len, size - len, "%s%llu",
				 i ? "," : "", set->ids[i]);
	}
	mk_cpu_set_unlock(set, flags);
	return len;
}
