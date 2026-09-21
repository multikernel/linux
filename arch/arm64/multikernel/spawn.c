// SPDX-License-Identifier: GPL-2.0
/*
 * arm64 multikernel architecture interface.
 *
 * Firmware owns CPU state on arm64. A pool CPU is a CPU in the PSCI OFF
 * state: it executes nothing, so there is no park loop to keep in memory
 * and no mailbox to watch. CPU_ON is the boot trampoline, delivering the
 * CPU to an Image entry point in exactly the state head.S requires, and
 * AFFINITY_INFO tells whether a CPU has come back.
 */

#define pr_fmt(fmt) "mk_spawn: " fmt

#include <linux/arm_sdei.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/iopoll.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqflags.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of_fdt.h>
#include <linux/panic.h>
#include <linux/psci.h>
#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/daifflags.h>
#include <asm/smp.h>
#include <uapi/linux/psci.h>

#include "internal.h"

/* A halting kernel acknowledges first and turns its CPUs off afterwards */
#define MK_CPU_OFF_TIMEOUT_US	USEC_PER_SEC

/*
 * Ring the doorbell of a CPU that another kernel runs on. There is no
 * foreign doorbell to filter on the receiving side: all it does is
 * drain this kernel's own ring, which such a sender cannot have filled.
 */
void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu)
{
	int ret = gic_v3_send_sgi_to_mpidr(phys_cpu, IPI_MULTIKERNEL);

	if (ret)
		pr_err_ratelimited("No doorbell SGI to CPU 0x%llx: %d\n",
				   phys_cpu, ret);
}

void __init mk_arch_register_cpu(mk_phys_cpu_t phys_id)
{
}

void __init mk_spawn_accept_boot_tree(phys_addr_t dt_phys)
{
	if (!initial_boot_params ||
	    !of_flat_dt_is_compatible(of_get_flat_dt_root(), MK_FDT_COMPATIBLE))
		return;

	mk_manifest_populate(dt_phys, fdt_totalsize(initial_boot_params));
}

/*
 * Return the calling CPU to firmware. The boot CPU is no exception: the
 * host's CPUs are on, so it is never the last one firmware knows about.
 */
void __noreturn mk_enter_pool_state(void *info)
{
	unsigned int cpu = smp_processor_id();
	const struct cpu_operations *ops = get_cpu_ops(cpu);

	local_daif_mask();
	sdei_mask_local_cpu();

	if (ops && ops->cpu_die)
		ops->cpu_die(cpu);

	pr_crit("CPU%u could not be turned off, the host cannot reuse it\n", cpu);
	cpu_park_loop();
}

void mk_spawn_machine_halt(void)
{
	if (mk_spawned())
		mk_halt_to_pool();
}

void mk_spawn_stop_this_cpu(void)
{
	if (mk_spawned())
		mk_enter_pool_state(NULL);
}

/*
 * A panicked spawn kernel spinning in the panic loop holds its CPUs
 * hostage. "Reboot on panic" is mk_spawn_machine_halt() here, which
 * notifies the host and turns the CPUs off, so make it the default.
 */
static int __init mk_spawn_reboot_init(void)
{
	if (mk_spawned() && !panic_timeout)
		panic_timeout = -1;
	return 0;
}
core_initcall(mk_spawn_reboot_init);

void mk_force_stop_cpu(mk_phys_cpu_t phys_cpu)
{
}

static struct mk_cpu_set *mk_started_set(struct mk_instance *instance)
{
	if (!instance->cpus_on_slot)
		instance->cpus_on_slot = mk_cpu_set_alloc();

	return instance->cpus_on_slot;
}

static int mk_wait_cpu_off(mk_phys_cpu_t mpidr)
{
	int state;

	if (!psci_ops.affinity_info)
		return -EOPNOTSUPP;

	return read_poll_timeout(psci_ops.affinity_info, state,
				 state == PSCI_0_2_AFFINITY_LEVEL_OFF,
				 1000, MK_CPU_OFF_TIMEOUT_US, false, mpidr, 0);
}

/*
 * The spawn reads these with the MMU and caches off, so what the host
 * wrote through its cacheable mapping has to be in memory by then.
 */
static void mk_clean_to_poc(phys_addr_t start, size_t size)
{
	unsigned long va = (unsigned long)phys_to_virt(start);

	dcache_clean_inval_poc(va, va + size);
}

/*
 * Everything the new kernel reads before its MMU is on is a segment: the
 * Image and the device tree. The manifest and the message ring are only
 * touched with the caches on, where both kernels see the same memory.
 */
static void mk_clean_image_to_poc(struct kimage *image)
{
	unsigned long i;

	for (i = 0; i < image->nr_segments; i++)
		mk_clean_to_poc(image->segment[i].mem, image->segment[i].memsz);
}

/**
 * mk_arch_spawn_instance - Start an instance's boot CPU on its image
 * @image: Loaded kimage for the instance
 * @instance: Instance being spawned
 * @cpu: Logical CPU, off in the pool, to boot the instance on
 *
 * Once the boot CPU runs, the instance's kernel may turn on any other CPU
 * it was given without telling the host, so all of them count as started
 * from here on and have to be seen off again before the image is reused.
 */
int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance,
			   int cpu)
{
	struct mk_cpu_set *started = mk_started_set(instance);
	mk_phys_cpu_t mpidr = arch_cpu_physical_id(cpu);
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret;

	if (!mk_pool)
		return -ENODEV;

	if (!image->arch.dtb_mem) {
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

	mk_clean_image_to_poc(image);

	guard(mutex)(&mk_pool->park_lock);

	ret = psci_cpu_on_context(mpidr, image->start, image->arch.dtb_mem);
	if (ret) {
		pr_err("CPU_ON of CPU 0x%llx for instance %d failed: %d\n",
		       mpidr, instance->id, ret);
		return ret;
	}

	mk_cpu_set_for_each(i, phys_cpu, instance->cpus)
		mk_cpu_set_add(started, phys_cpu);

	return 0;
}

/**
 * mk_arch_release_instance - Let go of an instance's CPUs before teardown
 * @instance: Instance being torn down
 *
 * Fails if a CPU is still on: it may be executing the instance's image,
 * so the caller must keep the instance's memory alive.
 */
int mk_arch_release_instance(struct mk_instance *instance)
{
	int ret;

	ret = mk_repark_instance_to_host(instance);
	if (ret) {
		char buf[256];

		mk_cpu_set_format(buf, sizeof(buf), instance->cpus_on_slot);
		pr_err("Instance %d (%s): CPUs %s are not off, keeping its memory\n",
		       instance->id, instance->name, buf);
		return ret;
	}

	mk_cpu_set_free(instance->cpus_on_slot);
	instance->cpus_on_slot = NULL;
	return 0;
}

/**
 * mk_arch_confirm_parked - Verify a CPU has left the instance's kernel
 * @instance: Instance the CPU belongs to
 * @phys_cpu: MPIDR of the CPU
 *
 * Returns 0 once firmware reports the CPU off.
 */
int mk_arch_confirm_parked(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	return mk_wait_cpu_off(phys_cpu);
}

/**
 * mk_repark_instance_to_host - Return an instance's CPUs to the pool
 * @instance: Instance being torn down
 *
 * An off CPU belongs to whoever turns it on next, so there is nothing to
 * move. What is left to do is to see every started CPU off; one that is
 * not stays tracked, and the caller must not free the instance's memory.
 */
int mk_repark_instance_to_host(struct mk_instance *instance)
{
	struct mk_cpu_set *started = instance->cpus_on_slot;
	unsigned int i;
	int failed = 0;

	if (mk_cpu_set_empty(started))
		return 0;

	guard(mutex)(&mk_pool->park_lock);

	/* Back to front, so deleting never shifts entries yet to be visited */
	for (i = mk_cpu_set_count(started); i-- > 0; ) {
		mk_phys_cpu_t phys_cpu = started->ids[i];

		if (mk_wait_cpu_off(phys_cpu))
			failed++;
		else
			mk_cpu_set_del(started, phys_cpu);
	}

	return failed ? -ETIMEDOUT : 0;
}

/**
 * mk_repark_cpu_to_instance - Hand one pool CPU to a live instance
 * @instance: Running instance the CPU is being hot-added to
 * @phys_cpu: MPIDR of the CPU
 *
 * The instance's kernel turns the CPU on by itself; the host only starts
 * counting it among the CPUs that kernel may be running on.
 */
int mk_repark_cpu_to_instance(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	struct mk_cpu_set *started = mk_started_set(instance);

	if (!started)
		return -ENOMEM;

	guard(mutex)(&mk_pool->park_lock);

	if (mk_cpu_set_contains(started, phys_cpu))
		return 0;

	return mk_cpu_set_add(started, phys_cpu);
}

/**
 * mk_repark_cpu_to_host - Take one CPU back from an instance
 * @instance: Instance the CPU was removed from
 * @phys_cpu: MPIDR of the CPU
 *
 * The instance's kernel reports the CPU offline before the CPU has
 * reached firmware. Turning it on elsewhere only works once it is off,
 * so wait for that; until then it stays accounted to the instance.
 */
int mk_repark_cpu_to_host(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	int ret;

	guard(mutex)(&mk_pool->park_lock);

	if (!mk_cpu_set_contains(instance->cpus_on_slot, phys_cpu))
		return 0;

	ret = mk_wait_cpu_off(phys_cpu);
	if (!ret)
		mk_cpu_set_del(instance->cpus_on_slot, phys_cpu);
	return ret;
}
