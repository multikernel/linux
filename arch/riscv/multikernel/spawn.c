// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cpu.h>
#include <linux/errno.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
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
		return ret;
	}

	return mk_riscv_hart_stopped(hartid);
}

void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu)
{
	struct sbiret ret;

	/* The host doorbell hart is intentionally absent from a spawn's CPU map. */
	ret = sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI,
			1UL, phys_cpu, 0, 0, 0, 0);
	if (ret.error)
		pr_err("Multikernel: failed to send IPI to hart %llu: %d\n",
		       phys_cpu, sbi_err_map_linux_errno(ret.error));
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

int mk_arch_register_force_stop(void)
{
	return -EOPNOTSUPP;
}

void mk_force_stop_cpu(mk_phys_cpu_t phys_cpu)
{
	pr_warn_once("RISC-V multikernel force-stop is not implemented\n");
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

	ret = mk_riscv_setup_instance(instance);
	if (ret)
		return ret;

	ret = mk_manifest_set_entry_stub(image, instance->arch.stub_phys);
	if (ret)
		return ret;

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
		pr_err("mk_spawn: invalid HART_START parameters for hart %lu\n",
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
	return 0;
}

int mk_repark_cpu_to_instance(struct mk_instance *instance,
			      mk_phys_cpu_t phys_cpu)
{
	if (!instance->arch.stub)
		return -EINVAL;

	return mk_riscv_prime_icache(phys_cpu);
}

int mk_repark_cpu_to_host(struct mk_instance *instance,
			  mk_phys_cpu_t phys_cpu)
{
	return 0;
}
