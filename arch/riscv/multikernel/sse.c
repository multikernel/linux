// SPDX-License-Identifier: GPL-2.0-only
/*
 * Force halt through an SBI Supervisor Software Event.
 *
 * S-mode has no NMI, and the doorbell is a supervisor software interrupt
 * that a hart spinning with interrupts masked never takes. An SSE event
 * is raised by firmware with an M-mode interrupt and enters the handler
 * its kernel registered, whatever that hart has masked. So every kernel
 * registers the software-injected event on each of its harts, and a
 * force halt injects it into the harts of an instance.
 *
 * What OpenSBI does with the event shapes the rest:
 *
 * - An event injected into a hart that has not registered it is dropped,
 *   and the caller is told nothing. The doorbell is rung regardless.
 * - Firmware forgets a hart's events when the hart is started, but keeps
 *   them over a kexec, where the handler's address then means nothing.
 *   Hence the shutdown hook, and the unregister before each register for
 *   the kernel a crash enters with no shutdown at all.
 * - Whether a hart takes events at all is a mask that survives the hart
 *   being stopped and started, so it may be found open already.
 * - Injecting into a stopped hart leaves it spinning in firmware until
 *   it is started again, so a stopped hart is left alone.
 */

#define pr_fmt(fmt) "mk_sse: " fmt

#include <linux/cpuhotplug.h>
#include <linux/init.h>
#include <linux/multikernel.h>
#include <linux/printk.h>
#include <linux/syscore_ops.h>
#include <asm/cpu_ops_sbi.h>
#include <asm/sbi.h>

#include "internal.h"

#define MK_SSE_STOP_EVENT	SBI_SSE_EVENT_LOCAL_SOFTWARE_INJECTED

asmlinkage void mk_sse_stop(void);

static bool mk_sse __ro_after_init;

static long mk_sse_call(int fid, unsigned long arg0, unsigned long arg1,
			unsigned long arg2)
{
	return sbi_ecall(SBI_EXT_SSE, fid, arg0, arg1, arg2, 0, 0, 0).error;
}

static void mk_sse_forget(void)
{
	mk_sse_call(SBI_SSE_EVENT_DISABLE, MK_SSE_STOP_EVENT, 0, 0);
	mk_sse_call(SBI_SSE_EVENT_UNREGISTER, MK_SSE_STOP_EVENT, 0, 0);
}

static int mk_sse_cpu_up(unsigned int cpu)
{
	long err;

	mk_sse_forget();

	err = mk_sse_call(SBI_SSE_EVENT_REGISTER, MK_SSE_STOP_EVENT,
			  (unsigned long)mk_sse_stop, 0);
	if (!err)
		err = mk_sse_call(SBI_SSE_EVENT_ENABLE, MK_SSE_STOP_EVENT, 0, 0);
	if (!err) {
		err = mk_sse_call(SBI_SSE_EVENT_HART_UNMASK, 0, 0, 0);
		/* Open already: OpenSBI answers with one or the other */
		if (err == SBI_ERR_ALREADY_STARTED || err == SBI_ERR_ALREADY_STOPPED)
			err = 0;
	}
	if (err) {
		mk_sse_forget();
		pr_warn_once("CPU%u cannot be forced down through SSE: %ld\n",
			     cpu, err);
	}
	return 0;
}

static int mk_sse_cpu_down(unsigned int cpu)
{
	mk_sse_forget();
	return 0;
}

static void mk_sse_shutdown(void *data)
{
	mk_sse_forget();
}

static const struct syscore_ops mk_sse_syscore_ops = {
	.shutdown = mk_sse_shutdown,
};

static struct syscore mk_sse_syscore = {
	.ops = &mk_sse_syscore_ops,
};

/**
 * mk_sse_stop_hart - Raise the stop event on a hart of another kernel
 * @hartid: Hart ID
 *
 * Returns 0 if firmware took the event, which says nothing of the hart
 * taking it, -ENODEV if firmware has no SSE, or the error of the call.
 */
int mk_sse_stop_hart(mk_phys_cpu_t hartid)
{
	if (!mk_sse)
		return -ENODEV;

	if (sbi_hsm_hart_get_status(hartid) == SBI_HSM_STATE_STOPPED)
		return 0;

	return sbi_err_map_linux_errno(mk_sse_call(SBI_SSE_EVENT_INJECT,
						   MK_SSE_STOP_EVENT, hartid, 0));
}

static int __init mk_sse_init(void)
{
	int ret;

	if (sbi_probe_extension(SBI_EXT_SSE) <= 0)
		return 0;

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "riscv/multikernel/sse:online",
				mk_sse_cpu_up, mk_sse_cpu_down);
	if (ret < 0) {
		pr_warn("No force halt through SSE: %d\n", ret);
		return 0;
	}

	register_syscore(&mk_sse_syscore);
	mk_sse = true;
	pr_info("Force halt stops this kernel's harts through SBI SSE\n");
	return 0;
}
early_initcall(mk_sse_init);
