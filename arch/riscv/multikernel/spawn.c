// SPDX-License-Identifier: GPL-2.0-only
/*
 * RISC-V multikernel architecture interface skeleton.
 *
 * The SBI HSM spawn and park implementation is added by the follow-up
 * architecture patches. Until then, operations which would change CPU
 * ownership fail explicitly instead of pretending that a hart moved.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>

void mk_arch_send_ipi(mk_phys_cpu_t phys_cpu)
{
	pr_warn_once("RISC-V multikernel IPI support is not implemented\n");
}

void mk_arch_register_cpu(mk_phys_cpu_t phys_id)
{
	/* RISC-V CPU topology already records possible harts. */
}

void __noreturn mk_enter_pool_state(void *info)
{
	/* Unreachable while CONFIG_ARCH_HAS_MK_POOL_STATE is disabled. */
	panic("RISC-V multikernel pool parking is not implemented");
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
	return -EOPNOTSUPP;
}

int mk_arch_release_instance(struct mk_instance *instance)
{
	return 0;
}

int mk_arch_confirm_parked(struct mk_instance *instance,
			   mk_phys_cpu_t phys_cpu)
{
	return -EOPNOTSUPP;
}

int mk_repark_instance_to_host(struct mk_instance *instance)
{
	return -EOPNOTSUPP;
}

int mk_repark_cpu_to_instance(struct mk_instance *instance,
			      mk_phys_cpu_t phys_cpu)
{
	return -EOPNOTSUPP;
}

int mk_repark_cpu_to_host(struct mk_instance *instance,
			  mk_phys_cpu_t phys_cpu)
{
	return -EOPNOTSUPP;
}
