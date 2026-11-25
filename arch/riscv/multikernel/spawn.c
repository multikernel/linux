// SPDX-License-Identifier: GPL-2.0-only
/*
 * RISC-V multikernel architecture interface.
 *
 * Firmware owns the hart lifecycle on RISC-V. A pool hart is a hart in
 * the SBI HSM STOPPED state: it executes nothing, so there is no park
 * loop to keep in memory and no mailbox to watch. HART_START is the boot
 * trampoline, entering S-mode with the MMU off, interrupts masked,
 * a0 = hartid and a1 = opaque, which is the Linux boot protocol with the
 * device tree in a1. HART_STATUS tells whether a hart has come back.
 */

#define pr_fmt(fmt) "mk_spawn: " fmt

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/iopoll.h>
#include <linux/irqflags.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/multikernel_fw_park.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/panic.h>
#include <asm/cpu_ops_sbi.h>
#include <asm/mmu.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/sections.h>

#include "internal.h"

/* A halting kernel acknowledges first and stops its harts afterwards */
#define MK_HART_STOP_TIMEOUT_US	USEC_PER_SEC

#define MK_HART_ENTRY_PROP	"multikernel,hart-entry"

asmlinkage void mk_hart_entry(void);
static_assert(offsetof(struct mk_boot_record, a1) == 0);
static_assert(offsetof(struct mk_boot_record, entry) == 8);

/*
 * The mk_hart_entry every hart of this kernel's instances and of this
 * kernel itself enters through: the first host's, handed down to each
 * spawn, so that it is text of a kernel no image load overwrites.
 */
static phys_addr_t mk_entry_pa;

static int __init mk_hart_entry_init(void)
{
	u64 pa;

	if (mk_spawned() && of_chosen &&
	    !of_property_read_u64(of_chosen, MK_HART_ENTRY_PROP, &pa))
		mk_entry_pa = pa;
	else
		mk_entry_pa = __pa_symbol(mk_hart_entry);
	return 0;
}
/* Before smp_init() starts the secondaries */
early_initcall(mk_hart_entry_init);

int mk_arch_manifest_chosen(void *fdt, struct mk_instance *instance)
{
	return fdt_property_u64(fdt, MK_HART_ENTRY_PROP, mk_entry_pa);
}

static struct mk_boot_record mk_secondary_boot[NR_CPUS];

/*
 * A spawn kernel's image is loaded where an earlier one ran, and its
 * secondaries are harts that earlier one stopped, so they go through
 * mk_hart_entry as its boot hart did. A host's image is never replaced
 * while it runs, so its own harts enter directly.
 */
void mk_wrap_hart_entry(unsigned int cpu, unsigned long *entry,
			unsigned long *opaque)
{
	struct mk_boot_record *boot = &mk_secondary_boot[cpu];

	if (!mk_spawned())
		return;

	boot->a1 = *opaque;
	boot->entry = *entry;
	*entry = mk_entry_pa;
	*opaque = __pa(boot);
	/* The hart reads the record with its MMU off, before anything else */
	mb();
}

/*
 * Ring the doorbell of a hart another kernel runs on: an SBI IPI, which
 * firmware delivers as a supervisor software interrupt. sbi_send_ipi()
 * takes a logical CPU of this kernel, so the hart is named directly. The
 * console can be what is sending, so a failure is reported deferred.
 */
void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu)
{
	static bool reported;
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI, 1, phys_cpu,
			0, 0, 0, 0);
	if (ret.error && !xchg(&reported, true)) {
		guard(preempt)();
		printk_deferred_enter();
		pr_err("No doorbell IPI to hart %llu: %ld\n", phys_cpu, ret.error);
		printk_deferred_exit();
	}
}

/*
 * The receiving end, on every software interrupt. Where software
 * interrupts also carry this kernel's own IPIs, one interrupt can stand
 * for a local IPI and a doorbell at once, so the rings cannot be skipped
 * on an interrupt that came with IPIs pending. Draining only looks at
 * this kernel's own rings, which no other sender can fill: there is no
 * foreign doorbell to filter.
 */
void mk_handle_doorbell(void)
{
	/*
	 * First, as the drain waits for a lock the hart this force halt is
	 * meant for may be holding. The marker is in a ring area only a
	 * kernel this one has a link with can write.
	 */
	if (mk_force_halt_armed()) {
		pr_emerg("CPU%u: forcibly stopped by another kernel\n",
			 smp_processor_id());
		set_cpu_online(smp_processor_id(), false);
		mk_arch_enter_pool_state(NULL);
	}

	generic_multikernel_interrupt();
}

void __init mk_arch_register_cpu(mk_phys_cpu_t phys_id)
{
}

/*
 * OpenSBI refuses a hart of another of its domains as if there were no
 * such hart. A kernel only learns of harts in its own domain, so this
 * one is in another: the machine is statically partitioned, and the
 * hart can never be part of a pool.
 */
static void mk_hsm_outside_domain(mk_phys_cpu_t hartid)
{
	pr_err("Hart %llu is outside this kernel's OpenSBI domain\n", hartid);
}

int mk_wait_hart_stopped(mk_phys_cpu_t hartid)
{
	long state;
	int ret;

	ret = read_poll_timeout(sbi_hsm_hart_get_status, state,
				state == SBI_HSM_STATE_STOPPED || state < 0,
				1000, MK_HART_STOP_TIMEOUT_US, false, hartid);
	if (!ret && state == -EINVAL)
		mk_hsm_outside_domain(hartid);
	return ret ?: (state < 0 ? state : 0);
}

int mk_hsm_start(mk_phys_cpu_t hartid, phys_addr_t entry,
		 phys_addr_t opaque)
{
	int ret = sbi_hsm_hart_start(hartid, entry, opaque);

	if (ret == -EINVAL || ret == -EPERM)
		mk_hsm_outside_domain(hartid);
	return ret;
}

/*
 * Return the calling hart to firmware. The boot hart is no exception: the
 * host's harts are started, so it is never the last one firmware knows of.
 */
void __noreturn mk_arch_enter_pool_state(void *info)
{
	local_irq_disable();

	sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STOP, 0, 0, 0, 0, 0, 0);

	pr_crit("CPU%u could not be stopped, the host cannot reuse it\n",
		smp_processor_id());
	while (1)
		wait_for_interrupt();
}

/*
 * SBI cannot stop another hart, so a kernel that no longer answers is
 * made to stop its harts itself: the force-halt marker is armed before
 * this is called, and each hart is made to look at it. An SSE event does
 * that whatever the hart has masked. The doorbell does it for a hart
 * that takes interrupts, which is all there is without SSE in firmware,
 * and what reaches a kernel too young to have registered the event. A
 * hart neither reaches never reports STOPPED, and the host keeps the
 * instance's memory rather than overwrite code it may run.
 */
void mk_arch_force_stop_cpu(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	int ret = mk_sse_stop_hart(phys_cpu);

	if (ret == -ENODEV)
		pr_warn_once("Without SBI SSE, force halt reaches only harts that take interrupts\n");
	else if (ret)
		pr_err_ratelimited("No SSE stop to hart %llu: %d\n", phys_cpu, ret);

	mk_arch_send_ipi(phys_cpu);
}

/**
 * mk_arch_spawn_instance - Start an instance's boot hart on its image
 * @image: Loaded kimage for the instance
 * @instance: Instance being spawned
 *
 * The boot hart is the first the instance owns, which need not be a CPU
 * of this kernel.
 */
int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance)
{
	mk_phys_cpu_t hartid = mk_cpu_set_first(instance->cpus);
	int ret;

	ret = mk_build_boot_dtb(image, instance, image->arch.fdt_addr,
				image->arch.fdt, mk_dtb_add_arch_nodes);
	if (ret)
		return ret;

	instance->arch.boot.a1 = image->arch.fdt_addr;
	instance->arch.boot.entry = image->start;
	/* What the hart reads first must be in memory before it starts */
	mb();
	ret = mk_hsm_start(hartid, mk_entry_pa, __pa(&instance->arch.boot));
	if (ret)
		pr_err("HART_START of hart %llu for instance %d failed: %d\n",
		       hartid, instance->id, ret);
	return ret;
}

/* The boot record is part of the instance, so there is nothing to free */
void mk_arch_release_instance(struct mk_instance *instance)
{
}

/**
 * mk_arch_confirm_parked - Verify a hart has left the instance's kernel
 * @phys_cpu: Hart ID
 *
 * A stopped hart belongs to whoever starts it next, so there is nothing
 * to move. Returns 0 once firmware reports the hart stopped.
 */
int mk_arch_confirm_parked(mk_phys_cpu_t phys_cpu)
{
	return mk_wait_hart_stopped(phys_cpu);
}

int mk_arch_pool_map(phys_addr_t start, size_t size)
{
	map_linear_range(start, size);
	return 0;
}

void mk_arch_pool_unmap(phys_addr_t start, size_t size)
{
	unmap_linear_range(start, size);
}
