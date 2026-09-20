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

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/iopoll.h>
#include <linux/irqflags.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <linux/psci.h>
#include <asm/cacheflush.h>
#include <asm/smp.h>
#include <uapi/linux/psci.h>

/* A halting kernel acknowledges first and turns its CPUs off afterwards */
#define MK_CPU_OFF_TIMEOUT_US	USEC_PER_SEC

void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu)
{
}

void __init mk_arch_register_cpu(mk_phys_cpu_t phys_id)
{
}

void __noreturn mk_enter_pool_state(void *info)
{
	local_irq_disable();
	cpu_park_loop();
}

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

static void mk_clean_image_to_poc(struct kimage *image,
				  struct mk_instance *instance)
{
	unsigned long i;

	for (i = 0; i < image->nr_segments; i++)
		mk_clean_to_poc(image->segment[i].mem, image->segment[i].memsz);

	if (instance->ctrl_va)
		mk_clean_to_poc(instance->ctrl_phys, MK_CTRL_BLOCK_SIZE);
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

	mk_clean_image_to_poc(image, instance);

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
	instance->arch.dtb = NULL;
	instance->arch.dtb_phys = 0;
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
