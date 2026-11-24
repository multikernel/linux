// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multikernel where firmware holds parked CPUs.
 *
 * A pool CPU is one firmware reports off (PSCI) or stopped (SBI HSM): it
 * executes nothing, and the call that starts it is the boot trampoline.
 * A kernel of a multikernel therefore gives its CPUs back to firmware
 * wherever a stock kernel would leave them spinning in its own image or
 * take the whole machine down.
 */

#include <linux/init.h>
#include <linux/multikernel.h>
#include <linux/multikernel_fw_park.h>
#include <linux/panic.h>

/*
 * A reset or power off through firmware acts on the whole machine, so a
 * spawn that reached it would take the host down with it. Every way down
 * ends here first, and in a spawn it does not return.
 */
void mk_spawn_machine_halt(void)
{
	if (mk_spawned())
		mk_halt_to_pool();
}

/*
 * A spawn's image is about to be overwritten, and a host's CPUs are what
 * a backup kernel takes over once it has fenced the host: firmware hands
 * out only CPUs it holds. A kernel outside any multikernel keeps the
 * stock WFI loop.
 */
void mk_stop_this_cpu(void)
{
	if (mk_self)
		mk_enter_pool_state(NULL);
}

/*
 * A panicked spawn kernel spinning in the panic loop holds its CPUs
 * hostage. "Reboot on panic" is mk_spawn_machine_halt() here, which
 * notifies the host and returns the CPUs to firmware, so make it the
 * default.
 */
static int __init mk_spawn_reboot_init(void)
{
	if (mk_spawned() && !panic_timeout)
		panic_timeout = -1;
	return 0;
}
core_initcall(mk_spawn_reboot_init);
