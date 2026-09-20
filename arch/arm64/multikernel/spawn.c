// SPDX-License-Identifier: GPL-2.0
/*
 * arm64 multikernel architecture interface.
 *
 * Nothing is implemented yet: every entry point refuses, so an arm64
 * kernel builds with CONFIG_MULTIKERNEL=y but cannot spawn.
 */

#include <linux/errno.h>
#include <linux/init.h>
#include <linux/irqflags.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <asm/smp.h>

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

int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance,
			   int cpu)
{
	return -EOPNOTSUPP;
}

int mk_arch_release_instance(struct mk_instance *instance)
{
	return 0;
}

int mk_arch_confirm_parked(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	return -EOPNOTSUPP;
}

int mk_repark_instance_to_host(struct mk_instance *instance)
{
	return 0;
}

int mk_repark_cpu_to_instance(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	return 0;
}

int mk_repark_cpu_to_host(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	return 0;
}
