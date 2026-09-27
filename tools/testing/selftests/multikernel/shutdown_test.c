// SPDX-License-Identifier: GPL-2.0-only
/* Run actual machine_* routing; stop firmware/power boundaries return by jump. */
#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdio.h>

static jmp_buf stopped;
static bool spawn, panic;
static int remote_stop, hart_stop, host_reset, notification;
static bool mk_spawned(void) { return spawn; }
static bool mk_is_spawn_kernel(void) { return spawn; }
static bool panic_in_progress(void) { return panic; }
static void smp_send_stop(void) { remote_stop++; }
static void mk_enter_pool_state(void *arg)
{
	assert(!arg);
	hart_stop++;
	longjmp(stopped, 1);
}
static void mk_halt_to_pool(void) { notification++; longjmp(stopped, 1); }
static void mk_panic_to_pool(void) { notification++; longjmp(stopped, 1); }
static void do_kernel_restart(char *arg) { (void)arg; host_reset++; longjmp(stopped, 1); }
static void do_kernel_power_off(void) { host_reset++; longjmp(stopped, 1); }
static void wait_for_interrupt(void) { longjmp(stopped, 1); }
struct pt_regs { int unused; };
#define local_irq_disable() do { } while (0)
#define smp_processor_id() 0
#define crash_save_cpu(regs, cpu) ((void)(regs), (void)(cpu))
#define machine_kexec_mask_interrupts() do { } while (0)
#define pr_info(...) do { } while (0)
static void crash_smp_send_stop(void) { host_reset++; }

#include "under-test.h"
#include "crash.h"

int main(void)
{
	int mode;

	for (mode = 0; mode < 10; mode++) {
		spawn = mode < 5;
		panic = mode % 5 >= 3;
		remote_stop = hart_stop = host_reset = notification = 0;
		if (!setjmp(stopped)) {
			if (mode % 5 == 0)
				machine_halt();
			else if (mode % 5 == 1)
				machine_power_off();
			else if (mode % 5 == 4)
				machine_crash_shutdown(NULL);
			else
				machine_restart(NULL);
		}
		assert(!notification);
		assert(remote_stop == spawn && hart_stop == spawn);
		assert(host_reset == !spawn);
	}
	puts("PASS: spawn halt/poweroff/reboot/panic/crash stop locally, host paths unchanged");
	return 0;
}
