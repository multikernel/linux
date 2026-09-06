// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved
 *
 * Doorbells: pending bits in shared memory plus the bare multikernel
 * IPI. The IPI handler runs every registered scan, which is what turns a
 * doorbell into work without touching the message ring.
 */
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/multikernel.h>

static LIST_HEAD(mk_doorbells);
static DEFINE_SPINLOCK(mk_doorbells_lock);

void mk_doorbell_register(struct mk_doorbell *db)
{
	spin_lock(&mk_doorbells_lock);
	list_add_tail_rcu(&db->list, &mk_doorbells);
	spin_unlock(&mk_doorbells_lock);
}
EXPORT_SYMBOL_GPL(mk_doorbell_register);

void mk_doorbell_unregister(struct mk_doorbell *db)
{
	spin_lock(&mk_doorbells_lock);
	list_del_rcu(&db->list);
	spin_unlock(&mk_doorbells_lock);
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(mk_doorbell_unregister);

void mk_doorbell_ring(mk_phys_cpu_t cpu)
{
	mk_arch_send_ipi(cpu);
}
EXPORT_SYMBOL_GPL(mk_doorbell_ring);

void mk_doorbell_scan_all(void)
{
	struct mk_doorbell *db;

	rcu_read_lock();
	list_for_each_entry_rcu(db, &mk_doorbells, list)
		db->scan(db);
	rcu_read_unlock();
}
