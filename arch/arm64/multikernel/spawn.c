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
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqflags.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/multikernel_fw_park.h>
#include <linux/of_fdt.h>
#include <linux/panic.h>
#include <linux/psci.h>
#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/daifflags.h>
#include <asm/mmu.h>
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

/*
 * Return the calling CPU to firmware. The boot CPU is no exception: the
 * host's CPUs are on, so it is never the last one firmware knows about.
 */
void __noreturn mk_enter_pool_state(void *info)
{
	unsigned int cpu = smp_processor_id();
	const struct cpu_operations *ops = get_cpu_ops(cpu);

	local_daif_mask();
	mk_sdei_unreachable();
	sdei_mask_local_cpu();
	gic_v3_cpu_leave();

	if (ops && ops->cpu_die)
		ops->cpu_die(cpu);

	pr_crit("CPU%u could not be turned off, the host cannot reuse it\n", cpu);
	cpu_park_loop();
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
 * PSCI cannot turn another CPU off, so a kernel that no longer answers
 * has to be made to turn its CPUs off itself. SDEI reaches a CPU whatever
 * it has masked, but only one that said it can take the event. The stop
 * IPI its own smp_send_stop() would use goes to every CPU regardless: as
 * IPI_CPU_STOP_NMI a kernel running with pseudo-NMIs takes it even with
 * interrupts masked, and to any other kernel it is an ordinary SGI.
 */
void mk_force_stop_cpu(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	int ret;

	mk_sdei_stop_cpu(instance, phys_cpu);

	ret = gic_v3_send_sgi_to_mpidr(phys_cpu, IPI_CPU_STOP_NMI);
	if (ret)
		pr_err("No stop SGI to CPU 0x%llx: %d\n", phys_cpu, ret);
}

/*
 * A fenced host's CPUs go off one at a time with a single stop event in
 * flight each: firmware can wedge a core whose power down is interrupted,
 * and many cores powering down at once did wedge one. SDEI goes first: a
 * stop SGI taken as an NMI inside an interrupt handler leaves both
 * interrupts active at the GIC through CPU_OFF, and that wedged a busy
 * core. The SGI is for a CPU that cannot take the event.
 */
int mk_arch_fence_cpu(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	int ret;

	if (psci_ops.affinity_info &&
	    psci_ops.affinity_info(phys_cpu, 0) == PSCI_0_2_AFFINITY_LEVEL_OFF)
		return 0;

	ret = mk_sdei_stop_cpu(instance, phys_cpu);
	if (!ret)
		ret = mk_wait_cpu_off(phys_cpu);
	if (ret && !gic_v3_send_sgi_to_mpidr(phys_cpu, IPI_CPU_STOP_NMI))
		ret = mk_wait_cpu_off(phys_cpu);
	return ret;
}

/* A fenced host's SPIs are nobody's: see gic_v3_disable_spis() */
void mk_arch_promote(void)
{
	gic_v3_disable_spis();
}

/*
 * The receiving end. A force halt is announced in the shared ring area
 * before the SGIs go out, and only a kernel this one has a relationship
 * with can write there; a stop from anyone else is ignored, the way x86
 * drops a stop NMI it did not ask for. Obeying means leaving for good:
 * the CPU is turned off, in a host that is being fenced as well.
 */
void mk_foreign_cpu_stop(void)
{
	if (!mk_has_pending_shutdown()) {
		pr_warn_ratelimited("CPU%u: ignoring a stop IPI from another kernel\n",
				    smp_processor_id());
		return;
	}

	set_cpu_online(smp_processor_id(), false);
	mk_enter_pool_state(NULL);
}

/*
 * The spawn reads these with the MMU and caches off, so what the host
 * wrote through its cacheable mapping has to be in memory by then.
 */
static int mk_clean_to_poc(phys_addr_t start, size_t size)
{
	void *va = memremap(start, size, MEMREMAP_WB);

	if (!va)
		return -ENOMEM;
	dcache_clean_inval_poc((unsigned long)va, (unsigned long)va + size);
	memunmap(va);
	return 0;
}

/*
 * Everything the new kernel reads before its MMU is on is a segment: the
 * Image and the device tree. The manifest and the message ring are only
 * touched with the caches on, where both kernels see the same memory.
 */
static int mk_clean_image_to_poc(struct kimage *image)
{
	unsigned long i;
	int ret;

	for (i = 0; i < image->nr_segments; i++) {
		ret = mk_clean_to_poc(image->segment[i].mem,
				      image->segment[i].memsz);
		if (ret)
			return ret;
	}
	return 0;
}

/**
 * mk_arch_spawn_instance - Start an instance's boot CPU on its image
 * @image: Loaded kimage for the instance
 * @instance: Instance being spawned
 *
 * The boot CPU, the first the instance owns, is off in the pool.
 */
int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance)
{
	mk_phys_cpu_t mpidr = mk_cpu_set_first(instance->cpus);
	int ret;

	ret = mk_build_boot_dtb(image, instance, image->arch.dtb_mem,
				image->arch.dtb, mk_dtb_add_arch_nodes);
	if (ret)
		return ret;

	ret = mk_clean_image_to_poc(image);
	if (ret)
		return ret;

	ret = psci_cpu_on_context(mpidr, image->start, image->arch.dtb_mem);
	if (ret)
		pr_err("CPU_ON of CPU 0x%llx for instance %d failed: %d\n",
		       mpidr, instance->id, ret);
	return ret;
}

/* What CPU_ON is given lives in the kimage, so there is nothing to free */
void mk_arch_release_instance(struct mk_instance *instance)
{
}

/**
 * mk_arch_confirm_parked - Verify a CPU has left the instance's kernel
 * @instance: Instance the CPU belongs to
 * @phys_cpu: MPIDR of the CPU
 *
 * An off CPU belongs to whoever turns it on next, so there is nothing to
 * move. Returns 0 once firmware reports the CPU off.
 */
int mk_arch_confirm_parked(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	return mk_wait_cpu_off(phys_cpu);
}

int mk_arch_pool_map(phys_addr_t start, size_t size)
{
	return map_linear_range(start, size);
}

void mk_arch_pool_unmap(phys_addr_t start, size_t size)
{
	unmap_linear_range(start, size);
}
