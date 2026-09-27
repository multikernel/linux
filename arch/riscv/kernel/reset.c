// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/multikernel.h>
#include <linux/reboot.h>
#include <linux/pm.h>
#include <linux/smp.h>

static void mk_spawn_stop(void)
{
	if (!mk_spawned())
		return;

	/* No messaging, allocations or registry locks, including during panic. */
	smp_send_stop();
	mk_enter_pool_state(NULL);
}

static void default_power_off(void)
{
	while (1)
		wait_for_interrupt();
}

void (*pm_power_off)(void) = NULL;
EXPORT_SYMBOL(pm_power_off);

void machine_restart(char *cmd)
{
	mk_spawn_stop();

	do_kernel_restart(cmd);
	while (1);
}

void machine_halt(void)
{
	mk_spawn_stop();

	do_kernel_power_off();
	default_power_off();
}

void machine_power_off(void)
{
	mk_spawn_stop();

	do_kernel_power_off();
	default_power_off();
}
