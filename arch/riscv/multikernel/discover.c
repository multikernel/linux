// SPDX-License-Identifier: GPL-2.0-only
/*
 * Harts this kernel never booted.
 *
 * Firmware can hold harts this kernel's device tree does not describe,
 * the cores of another kind on a machine that has two, since one kernel
 * runs on harts of one kind only. They are stopped in firmware, which is
 * the state of a pool hart, so they can be handed to an instance. What a
 * device tree would have said about such a hart it says itself, started
 * once into mk_hart_probe_entry, and that becomes its CPU node.
 */

#define pr_fmt(fmt) "mk_discover: " fmt

#include <linux/gfp.h>
#include <linux/iopoll.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/cpu_ops_sbi.h>
#include <asm/cpufeature.h>
#include <asm/sbi.h>
#include <asm/sections.h>

#include "internal.h"
#include "probe.h"

/*
 * SBI cannot list harts, only tell the state of one, so the hart IDs are
 * walked. This finds harts numbered densely from 0, as they are wherever
 * the hart ID is also the index of the hart's interrupt file.
 */
#define MK_HART_SCAN		4096
#define MK_PROBE_TIMEOUT_US	USEC_PER_SEC

asmlinkage void mk_hart_probe_entry(void);

/*
 * What the tree has no place for. A hart is added complete and neither
 * changes nor leaves, so readers need no lock.
 */
LIST_HEAD(mk_unclaimed_harts);
static DEFINE_MUTEX(mk_discover_lock);

static const struct mk_hart *mk_find_hart(mk_phys_cpu_t hartid)
{
	const struct mk_hart *hart;

	mk_for_each_unclaimed_hart(hart) {
		if (hart->hartid == hartid)
			return hart;
	}
	return NULL;
}

bool mk_arch_cpu_unclaimed(mk_phys_cpu_t hartid)
{
	return mk_find_hart(hartid);
}

unsigned int mk_arch_cpu_kind(mk_phys_cpu_t hartid)
{
	const struct mk_hart *hart = mk_find_hart(hartid);

	return hart ? hart->kind : 0;
}

bool mk_imsic_file_taken(phys_addr_t file)
{
	const struct mk_hart *hart;

	mk_for_each_unclaimed_hart(hart) {
		if (hart->file == file)
			return true;
	}
	return false;
}

static bool mk_same_ids(const struct mk_hart *hart, unsigned long mvendorid,
			unsigned long marchid, unsigned long mimpid)
{
	return hart->mvendorid == mvendorid && hart->marchid == marchid &&
	       hart->mimpid == mimpid;
}

/*
 * The harts this kernel runs on are one kind whatever their ID registers
 * say, as it does run on them all, and a hart with the IDs of one of
 * them is of that kind. Any other IDs are a kind of their own.
 */
static unsigned int mk_hart_kind(const struct mk_hart *hart)
{
	const struct mk_hart *other;
	unsigned int kind = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		if (mk_same_ids(hart, riscv_cached_mvendorid(cpu),
				riscv_cached_marchid(cpu),
				riscv_cached_mimpid(cpu)))
			return 0;
	}

	mk_for_each_unclaimed_hart(other) {
		if (mk_same_ids(hart, other->mvendorid, other->marchid,
				other->mimpid))
			return other->kind;
		kind = max(kind, other->kind);
	}
	return kind + 1;
}

static int mk_run_probe(mk_phys_cpu_t hartid, struct mk_hart_probe *probe)
{
	u64 done;
	int ret;

	guard(mutex)(&mk_park_lock);

	ret = mk_hsm_start(hartid, __pa_symbol(mk_hart_probe_entry), __pa(probe));
	if (ret)
		return ret;

	ret = read_poll_timeout(READ_ONCE, done, done, 100, MK_PROBE_TIMEOUT_US,
				false, probe->done);
	return mk_wait_hart_stopped(hartid) ?: ret;
}

/* @pending: harts yet to be probed, this one included */
static void mk_probe_hart(mk_phys_cpu_t hartid, struct mk_hart_probe *probe,
			  unsigned int pending)
{
	struct mk_hart *hart __free(kfree) = kzalloc(sizeof(*hart), GFP_KERNEL);
	int ret;

	if (!hart)
		return;

	memset(probe, 0, PAGE_SIZE);
	probe->nr_files = mk_imsic_free_files(probe->files, MK_PROBE_MAX_FILES,
					      pending);

	ret = mk_run_probe(hartid, probe);
	if (ret) {
		pr_err("Hart %llu did not describe itself: %d\n", hartid, ret);
		return;
	}
	if (probe->nr_files && !probe->file) {
		pr_err("Hart %llu has no interrupt file where the IMSIC should have it\n",
		       hartid);
		return;
	}

	hart->hartid = hartid;
	hart->mvendorid = probe->mvendorid;
	hart->marchid = probe->marchid;
	hart->mimpid = probe->mimpid;
	hart->kind = mk_hart_kind(hart);
	hart->passed = probe->passed;
	hart->file = probe->file;

	ret = mk_hart_add_node(hart);
	if (ret) {
		pr_err("No device tree node for hart %llu: %d\n", hartid, ret);
		return;
	}

	pr_info("Hart %llu: kind %u (%lx:%lx:%lx), probes %#llx, vlenb %llu, interrupt file %pa\n",
		hartid, hart->kind, hart->mvendorid, hart->marchid,
		hart->mimpid, hart->passed, probe->vlenb, &hart->file);

	list_add_tail_rcu(&no_free_ptr(hart)->node, &mk_unclaimed_harts);
}

/*
 * A hart counts as unclaimed if firmware holds it stopped and the tree
 * has no node for it. One the tree does have, disabled, is left alone:
 * that is a statement about the hart, not silence.
 */
static bool mk_hart_undescribed(mk_phys_cpu_t hartid)
{
	struct device_node *np = mk_of_hart_node(hartid);

	of_node_put(np);
	return !np && sbi_hsm_hart_get_status(hartid) == SBI_HSM_STATE_STOPPED;
}

/*
 * A kernel that was spawned is told its harts by its parent, and what
 * else it finds stopped is the parent's pool.
 */
int mk_arch_pool_discover(struct mk_cpu_set *found)
{
	struct mk_hart_probe *probe;
	const struct mk_hart *hart;
	unsigned int pending = 0;
	mk_phys_cpu_t hartid;
	int ret = 0;

	if (mk_spawned())
		return 0;

	probe = (void *)get_zeroed_page(GFP_KERNEL);
	if (!probe)
		return -ENOMEM;

	guard(mutex)(&mk_discover_lock);

	for (hartid = 0; hartid < MK_HART_SCAN; hartid++)
		pending += mk_hart_undescribed(hartid);

	for (hartid = 0; pending && hartid < MK_HART_SCAN; hartid++) {
		if (mk_hart_undescribed(hartid))
			mk_probe_hart(hartid, probe, pending--);
	}

	mk_for_each_unclaimed_hart(hart) {
		ret = mk_cpu_set_add(found, hart->hartid);
		if (ret)
			break;
	}

	free_page((unsigned long)probe);
	return ret;
}
