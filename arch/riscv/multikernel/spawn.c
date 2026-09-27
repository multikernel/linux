// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/processor.h>
#include <linux/smp.h>

#include <asm/cpu_ops_sbi.h>
#include <asm/sbi.h>

#define MK_HSM_POLL_US		1000
#define MK_HSM_TIMEOUT_US	USEC_PER_SEC

static int mk_riscv_setup_instance(struct mk_instance *instance)
{
	struct mk_riscv_spawn_context *ctx;
	size_t stub_size;
	void *block;

	if (instance->arch.ctx)
		return 0;

	stub_size = mk_riscv_entry_stub_end - mk_riscv_entry_stub_start;
	if (WARN_ON_ONCE(!stub_size || stub_size > PAGE_SIZE))
		return -E2BIG;

	block = mk_instance_ctrl_alloc(instance, 2 * PAGE_SIZE, PAGE_SIZE);
	if (!block)
		return -ENOMEM;

	ctx = block;
	memcpy(block + PAGE_SIZE, mk_riscv_entry_stub_start, stub_size);

	instance->arch.ctx = ctx;
	instance->arch.ctx_phys = virt_to_phys(ctx);
	instance->arch.stub = block + PAGE_SIZE;
	instance->arch.stub_phys = instance->arch.ctx_phys + PAGE_SIZE;
	return 0;
}

int mk_arch_prepare_instance(struct kimage *image, struct mk_instance *instance)
{
	return mk_riscv_setup_instance(instance);
}

int mk_arch_manifest_chosen(void *fdt, struct kimage *image,
			    struct mk_instance *instance)
{
	if (!instance->arch.stub_phys)
		return -EINVAL;
	return fdt_property_u64(fdt, MK_FDT_ENTRY_STUB, instance->arch.stub_phys);
}

static int mk_riscv_hart_stopped(unsigned long hartid)
{
	int state, ret;

	state = sbi_hsm_hart_get_status(hartid);
	if (state == SBI_HSM_STATE_STARTED ||
	    state == SBI_HSM_STATE_START_PENDING ||
	    state == SBI_HSM_STATE_STOP_PENDING) {
		ret = read_poll_timeout(sbi_hsm_hart_get_status, state,
					state != SBI_HSM_STATE_STARTED &&
					state != SBI_HSM_STATE_START_PENDING &&
					state != SBI_HSM_STATE_STOP_PENDING,
					MK_HSM_POLL_US, MK_HSM_TIMEOUT_US,
					false, hartid);
		if (ret) {
			pr_err("mk_spawn: hart %lu did not stop within %ld us\n",
			       hartid, MK_HSM_TIMEOUT_US);
			return -EBUSY;
		}
	}

	if (state < 0) {
		if (state == -EPERM)
			pr_err("mk_spawn: SBI domain denied HART_STATUS for hart %lu\n",
			       hartid);
		else
			pr_err("mk_spawn: failed to query hart %lu status: %d\n",
			       hartid, state);
		return state;
	}
	if (state != SBI_HSM_STATE_STOPPED) {
		pr_err("mk_spawn: hart %lu is not stopped (state %d)\n",
		       hartid, state);
		return -EBUSY;
	}

	return 0;
}

static int mk_riscv_prime_icache(unsigned long hartid)
{
	int ret;

	ret = mk_riscv_hart_stopped(hartid);
	if (ret)
		return ret;

	ret = sbi_hsm_hart_start(hartid,
				 __pa_symbol(mk_riscv_entry_fence_stop), 0);
	if (ret) {
		pr_err("mk_spawn: failed to prime hart %lu I-cache: %d\n",
		       hartid, ret);
		if (ret == -EPERM || ret == -EINVAL)
			pr_err("mk_spawn: check SBI domain access and the host entry address\n");
		return ret;
	}

	return mk_riscv_hart_stopped(hartid);
}

void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu)
{
	/* Doorbell transport is the separate #28 series. */
	pr_warn_once("RISC-V multikernel doorbells are not implemented\n");
}

void mk_arch_register_cpu(mk_phys_cpu_t phys_id)
{
	/* RISC-V CPU topology already records possible harts. */
}

void __noreturn mk_enter_pool_state(void *info)
{
	int ret;

	local_irq_disable();
	set_cpu_online(smp_processor_id(), false);
	/* Publish the offline state before firmware stops this hart. */
	smp_mb();

	ret = sbi_hsm_hart_stop();
	pr_emerg("Multikernel: HART_STOP returned on CPU %u: %d\n",
		 smp_processor_id(), ret);
	for (;;)
		wait_for_interrupt();
}

void mk_force_stop_cpu(mk_phys_cpu_t phys_cpu)
{
	pr_warn_once("RISC-V multikernel force-stop is not implemented\n");
}

static int mk_riscv_track_cpu(struct mk_instance *instance, mk_phys_cpu_t cpu)
{
	if (!instance->cpus_on_slot) {
		instance->cpus_on_slot = mk_cpu_set_alloc();
		if (!instance->cpus_on_slot)
			return -ENOMEM;
	}
	return mk_cpu_set_add(instance->cpus_on_slot, cpu);
}

int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance,
			   int cpu)
{
	unsigned long hartid = arch_cpu_physical_id(cpu);
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret;

	if (hartid == INVALID_HARTID || !image->start ||
	    !image->arch.fdt_addr)
		return -EINVAL;

	if (!instance->arch.ctx || !instance->arch.stub_phys)
		return -EINVAL;

	if (!mk_cpu_set_contains(instance->cpus, hartid))
		return -EINVAL;

	/* Record every possible secondary before even the priming HART_START. */
	mk_cpu_set_for_each(i, phys_cpu, instance->cpus) {
		ret = mk_riscv_track_cpu(instance, phys_cpu);
		if (ret)
			return ret;
	}

	WRITE_ONCE(instance->arch.ctx->image_entry, image->start);
	/* Publish all Image, DTB, stub and context stores before starting it. */
	smp_mb();
	mk_cpu_set_for_each(i, phys_cpu, instance->cpus) {
		ret = mk_riscv_prime_icache(phys_cpu);
		if (ret)
			return ret;
	}

	ret = sbi_hsm_hart_start(hartid, instance->arch.stub_phys,
				 image->arch.fdt_addr);
	if (ret == -EPERM)
		pr_err("mk_spawn: SBI domain denied HART_START for hart %lu\n",
		       hartid);
	else if (ret == -EINVAL)
		pr_err("mk_spawn: hart %lu not startable: check SBI domain access and entry address\n",
		       hartid);
	else if (ret)
		pr_err("mk_spawn: failed to start hart %lu: %d\n", hartid, ret);

	return ret;
}

int mk_arch_release_instance(struct mk_instance *instance)
{
	int ret;

	ret = mk_instance_confirm_parked(instance);
	if (ret)
		return ret;

	mk_cpu_set_free(instance->cpus_on_slot);
	instance->cpus_on_slot = NULL;
	instance->arch.ctx = NULL;
	instance->arch.ctx_phys = 0;
	instance->arch.stub = NULL;
	instance->arch.stub_phys = 0;
	return 0;
}

int mk_arch_confirm_parked(struct mk_instance *instance,
			   mk_phys_cpu_t phys_cpu)
{
	return mk_riscv_hart_stopped(phys_cpu);
}

int mk_repark_instance_to_host(struct mk_instance *instance)
{
	return mk_instance_confirm_parked(instance);
}

int mk_repark_cpu_to_instance(struct mk_instance *instance,
			      mk_phys_cpu_t phys_cpu)
{
	int ret;

	if (!instance->arch.stub)
		return -EINVAL;

	ret = mk_riscv_track_cpu(instance, phys_cpu);
	if (ret)
		return ret;

	return mk_riscv_prime_icache(phys_cpu);
}

int mk_repark_cpu_to_host(struct mk_instance *instance,
			  mk_phys_cpu_t phys_cpu)
{
	int ret;

	/* The caller must first quiesce any outstanding remote start request. */
	ret = mk_riscv_hart_stopped(phys_cpu);
	if (!ret)
		mk_cpu_set_del(instance->cpus_on_slot, phys_cpu);
	return ret;
}
