// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/multikernel.h>
#include <linux/panic.h>
#include <linux/reboot.h>
#include <linux/pm.h>

static void default_power_off(void)
{
	while (1)
		wait_for_interrupt();
}

void (*pm_power_off)(void) = NULL;
EXPORT_SYMBOL(pm_power_off);

void machine_restart(char *cmd)
{
	if (mk_is_spawn_kernel() && panic_in_progress())
		mk_panic_to_pool();
	if (mk_is_spawn_kernel())
		mk_halt_to_pool();

	do_kernel_restart(cmd);
	while (1);
}

void machine_halt(void)
{
	if (mk_is_spawn_kernel())
		mk_halt_to_pool();

	do_kernel_power_off();
	default_power_off();
}

void machine_power_off(void)
{
	if (mk_is_spawn_kernel())
		mk_halt_to_pool();

	do_kernel_power_off();
	default_power_off();
}
