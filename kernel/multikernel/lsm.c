// SPDX-License-Identifier: GPL-2.0-only
/*
 * What the user space of a spawn kernel is kept from.
 *
 * A kernel hands root the raw memory and I/O ports of the machine because
 * the machine is its own. Most of the machine is not a spawn's, and
 * nothing below a spawn stops what its kernel allows: the RAM of the other
 * kernels is absent from its memory map and so looks like a hole, where
 * devices live and /dev/mem maps anything.
 *
 * The kernel already asks before it opens each of these doors, for the
 * sake of lockdown. A spawn answers no for the ones that lead out of it,
 * whatever its lockdown level is.
 */

#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/multikernel.h>
#include <linux/security.h>
#include <uapi/linux/lsm.h>

/* A spawn that fenced its host has the machine to itself */
static bool mk_lsm_confined(void)
{
	return mk_spawned() && !mk_host_fenced();
}

static int mk_lsm_locked_down(enum lockdown_reason what)
{
	if (!mk_lsm_confined())
		return 0;

	switch (what) {
	case LOCKDOWN_DEV_MEM:
	case LOCKDOWN_IOPORT:
	case LOCKDOWN_TIOCSSERIAL:
		return -EPERM;
	default:
		return 0;
	}
}

static struct security_hook_list mk_lsm_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(locked_down, mk_lsm_locked_down),
};

static const struct lsm_id mk_lsmid = {
	.name = "multikernel",
	.id = LSM_ID_MULTIKERNEL,
};

static int __init mk_lsm_init(void)
{
	security_add_hooks(mk_lsm_hooks, ARRAY_SIZE(mk_lsm_hooks), &mk_lsmid);
	return 0;
}

/* An early LSM is not subject to lsm=, which a spawn's command line may carry */
DEFINE_EARLY_LSM(multikernel) = {
	.id = &mk_lsmid,
	.init = mk_lsm_init,
};
