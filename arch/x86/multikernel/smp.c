// SPDX-License-Identifier: GPL-2.0
/*
 * x86 multikernel interrupts between kernels: the doorbell vector of the
 * message rings, the NMI that forces another kernel's CPUs to stop, and
 * how a CPU of this kernel answers either by parking in its cell.
 */

#define pr_fmt(fmt) "multikernel: " fmt

#include <linux/init.h>
#include <linux/instrumentation.h>
#include <linux/crash_core.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <linux/printk.h>
#include <linux/smp.h>
#include <asm/apic.h>
#include <asm/hardirq.h>
#include <asm/idtentry.h>
#include <asm/irqflags.h>
#include <asm/multikernel.h>
#include <asm/nmi.h>
#include <asm/reboot.h>

/*
 * A backup kernel that will take a core of this one has no crash kernel
 * to save our state for it. Record the interrupted registers the way
 * kdump would, only while such a backup is armed.
 */
void mk_save_stop_regs(struct pt_regs *regs)
{
	if (mk_crash_notes_wanted())
		crash_save_cpu(regs, raw_smp_processor_id());
}

DEFINE_IDTENTRY_SYSVEC(sysvec_multikernel)
{
	apic_eoi();
	inc_irq_stat(irq_call_count);
	generic_multikernel_interrupt();
}

/**
 * mk_arch_send_ipi - Ring the multikernel doorbell on another kernel's CPU
 * @phys_cpu: Physical (APIC) ID of the target CPU
 *
 * The target belongs to a different kernel instance, so the IPI goes to
 * the physical APIC ID directly; logical CPU numbers only have meaning
 * within one kernel.
 */
void mk_arch_send_ipi(u64 phys_cpu)
{
	apic_icr_write(APIC_DM_FIXED | APIC_DEST_PHYSICAL | MULTIKERNEL_VECTOR,
		       (u32)phys_cpu);
}

/*
 * Enter pool state: mask all local APIC LVT entries to prevent timer,
 * thermal, performance counter, and other local interrupts from firing
 * into dead/corrupted handlers (which causes triple fault -> system reset
 * on bare metal). Keep the APIC itself enabled for IPI delivery so that
 * re-spawn wakeup works. Then loop in HLT waiting for spawn signals.
 */
void __noreturn mk_enter_pool_state(void *info)
{
	apic_write(APIC_LVTT, APIC_LVT_MASKED);
	apic_write(APIC_LVTTHMR, APIC_LVT_MASKED);
	apic_write(APIC_LVTPC, APIC_LVT_MASKED);
	apic_write(APIC_LVT0, APIC_LVT_MASKED);
	apic_write(APIC_LVT1, APIC_LVT_MASKED);
	apic_write(APIC_LVTERR, APIC_LVT_MASKED);

	local_irq_disable();

	/* Park in this CPU's cell, which no kernel image load touches */
	mk_park_this_cpu();

	/*
	 * No park cell: this kernel has no park table, which pool parking
	 * setup and the normal spawn path always provide. Waiting in this kernel's own
	 * text would take the whole machine down when the next image load
	 * overwrites it, so stop dead instead; INIT can still revive us.
	 */
	pr_emerg("CPU %d: no park cell, halting permanently\n",
		 smp_processor_id());
	while (1)
		native_halt();
}

/*
 * Enter a pool state (HLT loop) rather than calling stop_this_cpu(),
 * because stop_this_cpu() disables the APIC - preventing re-spawn.
 */
static void __noreturn mk_force_stop(struct pt_regs *regs)
{
	pr_emerg("CPU %d: Forcible shutdown via NMI (instance %d)\n",
		 smp_processor_id(), mk_self ? mk_self->id : -1);

	mk_save_stop_regs(regs);
	cpu_emergency_disable_virtualization();
	mk_enter_pool_state(NULL);
}

/*
 * Runs ahead of every local NMI source once the marker is armed. perf
 * would otherwise claim the force-halt NMI on a CPU that panicked: panic
 * masks the PMI but leaves the watchdog counter running, and once that
 * counter overflows perf takes any NMI as its own.
 */
static int mk_stop_nmi_local(unsigned int val, struct pt_regs *regs)
{
	if (!mk_force_halt_armed())
		return NMI_DONE;

	mk_force_stop(regs);
	return NMI_HANDLED; /* unreachable */
}

/*
 * A spawn without a ring has no marker and takes any NMI no local
 * source claims as the demand to park, so it must sit behind perf: a
 * PMI from the hardlockup detector is not a demand.
 */
static int mk_stop_nmi_unknown(unsigned int val, struct pt_regs *regs)
{
	if (!mk_has_pending_shutdown())
		return NMI_DONE;

	mk_force_stop(regs);
	return NMI_HANDLED; /* unreachable */
}

/*
 * Called from the NMI entry's offline bail-out, where the handler chain
 * (and so mk_stop_nmi_local()) never runs. A spawn CPU that went down
 * through a pre-multikernel path sits offline in a HLT loop inside an
 * image the host wants to reuse; honor a pending force halt by parking
 * it in the pool like every other stopped CPU.
 */
void noinstr mk_nmi_offline_park(void)
{
	instrumentation_begin();
	if (mk_park_ready() && mk_has_pending_shutdown()) {
		cpu_emergency_disable_virtualization();
		mk_enter_pool_state(NULL);
	}
	instrumentation_end();
}

/*
 * Register the NMI handlers that forcibly park this kernel's CPUs when a
 * peer demands it. They only act on a pending demand, so they are
 * harmless on their chains and can be installed unconditionally at init
 * on any multikernel-capable kernel; a force halt cannot arrive until a
 * spawn is running, long after this.
 */
static int __init mk_register_force_stop(void)
{
	int ret;

	ret = register_nmi_handler(NMI_LOCAL, mk_stop_nmi_local,
				   NMI_FLAG_FIRST, "mk_stop");
	if (!ret)
		ret = register_nmi_handler(NMI_UNKNOWN, mk_stop_nmi_unknown, 0,
					   "mk_stop");
	if (ret)
		pr_err("Failed to register multikernel NMI stop handler: %d\n",
		       ret);
	return ret;
}
device_initcall(mk_register_force_stop);

/**
 * mk_force_stop_cpu - Send NMI to a specific CPU to force it to stop
 * @instance: Instance the CPU belongs to
 * @phys_cpu: Physical CPU ID to stop
 *
 * The target belongs to a different kernel instance, so the NMI goes to
 * the physical APIC ID directly, like mk_arch_send_ipi(): this kernel's
 * logical CPU map need not cover another kernel's CPUs, and translating
 * through it silently dropped the NMI for CPUs it missed. The ICR must
 * drain first, or back-to-back sends lose all but the first on xAPIC.
 */
void mk_force_stop_cpu(struct mk_instance *instance, u64 phys_cpu)
{
	safe_apic_wait_icr_idle();
	apic_icr_write(APIC_DM_NMI | APIC_DEST_PHYSICAL, (u32)phys_cpu);
}
