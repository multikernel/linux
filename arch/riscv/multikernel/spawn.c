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
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/panic.h>
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
	generic_multikernel_interrupt();
}

void __init mk_arch_register_cpu(mk_phys_cpu_t phys_id)
{
}

static phys_addr_t mk_ram_start __initdata = PHYS_ADDR_MAX;

/* Hot-added RAM must fall inside the linear map, which starts at boot */
void __init mk_arch_register_ram(phys_addr_t start, u64 size)
{
	if (size)
		mk_ram_start = min(mk_ram_start, start);
}

phys_addr_t __init mk_linear_map_start(phys_addr_t dram_start)
{
	return min(dram_start, mk_ram_start);
}

void __init mk_spawn_accept_boot_tree(phys_addr_t dt_phys)
{
	if (!initial_boot_params ||
	    !of_flat_dt_is_compatible(of_get_flat_dt_root(), MK_FDT_COMPATIBLE))
		return;

	mk_manifest_populate(dt_phys, fdt_totalsize(initial_boot_params));
}

static long mk_hsm_status(mk_phys_cpu_t hartid)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STATUS, hartid,
			0, 0, 0, 0, 0);
	return ret.error ? sbi_err_map_linux_errno(ret.error) : ret.value;
}

static int mk_wait_hart_stopped(mk_phys_cpu_t hartid)
{
	long state;
	int ret;

	ret = read_poll_timeout(mk_hsm_status, state,
				state == SBI_HSM_STATE_STOPPED || state < 0,
				1000, MK_HART_STOP_TIMEOUT_US, false, hartid);
	return ret ?: (state < 0 ? state : 0);
}

static int mk_hsm_start(mk_phys_cpu_t hartid, phys_addr_t entry,
			phys_addr_t opaque)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START, hartid,
			entry, opaque, 0, 0, 0);
	return ret.error ? sbi_err_map_linux_errno(ret.error) : 0;
}

/*
 * Return the calling hart to firmware. The boot hart is no exception: the
 * host's harts are started, so it is never the last one firmware knows of.
 */
void __noreturn mk_enter_pool_state(void *info)
{
	local_irq_disable();

	sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STOP, 0, 0, 0, 0, 0, 0);

	pr_crit("CPU%u could not be stopped, the host cannot reuse it\n",
		smp_processor_id());
	while (1)
		wait_for_interrupt();
}

/*
 * SRST and the legacy shutdown call act on the whole machine, so a spawn
 * that reached them would take the host down with it. Every way down
 * ends here first, and in a spawn it does not return.
 */
void mk_spawn_machine_halt(void)
{
	if (mk_spawned())
		mk_halt_to_pool();
}

/*
 * A spawn's image is about to be overwritten, and a host's harts are what
 * a backup kernel takes over once it has fenced the host: firmware hands
 * out only harts that are stopped. A kernel outside any multikernel keeps
 * the stock WFI loop.
 */
void mk_stop_this_cpu(void)
{
	if (mk_self)
		mk_enter_pool_state(NULL);
}

/*
 * A panicked spawn kernel spinning in the panic loop holds its harts
 * hostage. "Reboot on panic" is mk_spawn_machine_halt() here, which
 * notifies the host and stops the harts, so make it the default.
 */
static int __init mk_spawn_reboot_init(void)
{
	if (mk_spawned() && !panic_timeout)
		panic_timeout = -1;
	return 0;
}
core_initcall(mk_spawn_reboot_init);

void mk_force_stop_cpu(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	pr_warn_once("RISC-V multikernel force-stop is not implemented\n");
}

static struct mk_cpu_set *mk_started_set(struct mk_instance *instance)
{
	if (!instance->cpus_started)
		instance->cpus_started = mk_cpu_set_alloc();

	return instance->cpus_started;
}

/**
 * mk_arch_spawn_instance - Start an instance's boot hart on its image
 * @image: Loaded kimage for the instance
 * @instance: Instance being spawned
 * @cpu: Logical CPU, stopped in the pool, to boot the instance on
 *
 * Once the boot hart runs, the instance's kernel may start any other hart
 * it was given without telling the host, so all of them count as started
 * from here on and have to be seen stopped again before the image is
 * reused.
 */
int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance,
			   int cpu)
{
	struct mk_cpu_set *started = mk_started_set(instance);
	mk_phys_cpu_t hartid = arch_cpu_physical_id(cpu);
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret;

	if (!mk_pool)
		return -ENODEV;

	if (!image->arch.fdt_addr) {
		pr_err("Instance %d has no boot device tree\n", instance->id);
		return -EINVAL;
	}

	/* Make the adds below infallible before anything runs */
	if (!started)
		return -ENOMEM;
	ret = mk_cpu_set_reserve(started, mk_cpu_set_count(instance->cpus));
	if (ret)
		return ret;

	ret = mk_build_boot_dtb(image, instance);
	if (ret) {
		pr_err("No boot device tree for instance %d: %d\n",
		       instance->id, ret);
		return ret;
	}

	guard(mutex)(&mk_park_lock);

	instance->arch.boot.a1 = image->arch.fdt_addr;
	instance->arch.boot.entry = image->start;
	/* What the hart reads first must be in memory before it starts */
	mb();
	ret = mk_hsm_start(hartid, mk_entry_pa, __pa(&instance->arch.boot));
	if (ret) {
		pr_err("HART_START of hart %llu for instance %d failed: %d\n",
		       hartid, instance->id, ret);
		return ret;
	}

	mk_cpu_set_for_each(i, phys_cpu, instance->cpus)
		mk_cpu_set_add(started, phys_cpu);

	return 0;
}

/**
 * mk_arch_release_instance - Let go of an instance's harts before teardown
 * @instance: Instance being torn down
 *
 * Fails if a hart is still started: it may be executing the instance's
 * image, so the caller must keep the instance's memory alive.
 */
int mk_arch_release_instance(struct mk_instance *instance)
{
	int ret;

	ret = mk_repark_instance_to_host(instance);
	if (ret) {
		char buf[256];

		mk_cpu_set_format(buf, sizeof(buf), instance->cpus_started);
		pr_err("Instance %d (%s): harts %s are not stopped, keeping its memory\n",
		       instance->id, instance->name, buf);
		return ret;
	}

	mk_cpu_set_free(instance->cpus_started);
	instance->cpus_started = NULL;
	return 0;
}

/**
 * mk_arch_confirm_parked - Verify a hart has left the instance's kernel
 * @instance: Instance the hart belongs to
 * @phys_cpu: Hart ID
 *
 * Returns 0 once firmware reports the hart stopped.
 */
int mk_arch_confirm_parked(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	return mk_wait_hart_stopped(phys_cpu);
}

/**
 * mk_repark_instance_to_host - Return an instance's harts to the pool
 * @instance: Instance being torn down
 *
 * A stopped hart belongs to whoever starts it next, so there is nothing
 * to move. What is left to do is to see every started hart stopped; one
 * that is not stays tracked, and the caller must not free the instance's
 * memory.
 */
int mk_repark_instance_to_host(struct mk_instance *instance)
{
	struct mk_cpu_set *started = instance->cpus_started;
	unsigned int i;
	int failed = 0;

	if (mk_cpu_set_empty(started))
		return 0;

	guard(mutex)(&mk_park_lock);

	/* Back to front, so deleting never shifts entries yet to be visited */
	for (i = mk_cpu_set_count(started); i-- > 0; ) {
		mk_phys_cpu_t phys_cpu = started->ids[i];

		if (mk_wait_hart_stopped(phys_cpu))
			failed++;
		else
			mk_cpu_set_del(started, phys_cpu);
	}

	return failed ? -ETIMEDOUT : 0;
}

/**
 * mk_repark_cpu_to_instance - Hand one pool hart to a live instance
 * @instance: Running instance the hart is being hot-added to
 * @phys_cpu: Hart ID
 *
 * The instance's kernel starts the hart by itself; the host only starts
 * counting it among the harts that kernel may be running on.
 */
int mk_repark_cpu_to_instance(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	struct mk_cpu_set *started = mk_started_set(instance);

	if (!started)
		return -ENOMEM;

	guard(mutex)(&mk_park_lock);

	if (mk_cpu_set_contains(started, phys_cpu))
		return 0;

	return mk_cpu_set_add(started, phys_cpu);
}

/**
 * mk_repark_cpu_to_host - Take one hart back from an instance
 * @instance: Instance the hart was removed from
 * @phys_cpu: Hart ID
 *
 * The instance's kernel reports the hart offline before the hart has
 * reached firmware. Starting it elsewhere only works once it is stopped,
 * so wait for that; until then it stays accounted to the instance.
 */
int mk_repark_cpu_to_host(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	int ret;

	guard(mutex)(&mk_park_lock);

	if (!mk_cpu_set_contains(instance->cpus_started, phys_cpu))
		return 0;

	ret = mk_wait_hart_stopped(phys_cpu);
	if (!ret)
		mk_cpu_set_del(instance->cpus_started, phys_cpu);
	return ret;
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
