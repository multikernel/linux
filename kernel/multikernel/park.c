// SPDX-License-Identifier: GPL-2.0-only
/*
 * The CPUs an instance's kernel may be running on.
 *
 * Once an instance's boot CPU runs, its kernel starts any other CPU it
 * owns without telling this one, so from then on every CPU it owns counts
 * as started until the architecture confirms it parked again. A started
 * CPU may be executing the instance's image: it pins the image, the
 * instance's memory and the park area it left from.
 *
 * How a CPU is started and how it is seen parked is the architecture's;
 * who counts as started is decided here, under mk_park_lock.
 */

#define pr_fmt(fmt) "multikernel: " fmt

#include <linux/cleanup.h>
#include <linux/kexec.h>
#include <linux/multikernel.h>
#include <linux/mutex.h>

#include "internal.h"

DEFINE_MUTEX(mk_park_lock);

static struct mk_cpu_set *mk_started_set(struct mk_instance *instance)
{
	if (!instance->cpus_started)
		instance->cpus_started = mk_cpu_set_alloc();

	return instance->cpus_started;
}

/**
 * mk_instance_start_boot_cpu - Start an instance's kernel on its boot CPU
 * @instance: Instance to start, every CPU it owns parked
 * @image: Its kernel image, ready to boot
 *
 * The boot CPU is the first CPU the instance owns.
 *
 * Returns 0 once the boot CPU was started, or a negative error code with
 * no CPU started.
 */
int mk_instance_start_boot_cpu(struct mk_instance *instance,
			       struct kimage *image)
{
	struct mk_cpu_set *started = mk_started_set(instance);
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret;

	if (!mk_pool)
		return -ENODEV;

	/* Make the adds below infallible before anything runs */
	if (!started)
		return -ENOMEM;
	ret = mk_cpu_set_reserve(started, mk_cpu_set_count(instance->cpus));
	if (ret)
		return ret;

	guard(mutex)(&mk_park_lock);

	ret = mk_arch_spawn_instance(image, instance);
	if (ret)
		return ret;

	mk_cpu_set_for_each(i, phys_cpu, instance->cpus)
		mk_cpu_set_add(started, phys_cpu);
	return 0;
}

/*
 * See every CPU an instance started parked. One that does not park stays
 * tracked, and the caller must not free the instance's memory.
 */
static int mk_instance_confirm_all_parked(struct mk_instance *instance)
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

		if (mk_arch_confirm_parked(instance, phys_cpu))
			failed++;
		else
			mk_cpu_set_del(started, phys_cpu);
	}

	return failed ? -ETIMEDOUT : 0;
}

/**
 * mk_instance_release_spawn_state - Let go of what an instance was started with
 * @instance: Instance being torn down
 *
 * Fails without releasing anything if a CPU never parked: it may still
 * run the instance's kernel, so the caller must keep its memory alive.
 */
int mk_instance_release_spawn_state(struct mk_instance *instance)
{
	int ret;

	ret = mk_instance_confirm_all_parked(instance);
	if (ret) {
		char buf[256];

		mk_cpu_set_format(buf, sizeof(buf), instance->cpus_started);
		pr_err("Instance %d (%s): CPUs %s never parked, keeping its memory\n",
		       instance->id, instance->name, buf);
		return ret;
	}

	mk_cpu_set_free(instance->cpus_started);
	instance->cpus_started = NULL;

	mk_arch_release_instance(instance);
	return 0;
}

/**
 * mk_repark_cpu_to_instance - Hand one parked pool CPU to a live instance
 * @instance: Running instance the CPU is being hot-added to
 * @phys_cpu: Physical ID of the CPU
 *
 * The instance's kernel starts the CPU by itself; this kernel only starts
 * counting it among the CPUs that kernel may be running on.
 */
int mk_repark_cpu_to_instance(struct mk_instance *instance,
			      mk_phys_cpu_t phys_cpu)
{
	struct mk_cpu_set *started = mk_started_set(instance);

	if (!started)
		return -ENOMEM;

	guard(mutex)(&mk_park_lock);

	return mk_cpu_set_add(started, phys_cpu);
}

/**
 * mk_repark_cpu_to_host - Take one CPU back from an instance
 * @instance: Instance the CPU was removed from
 * @phys_cpu: Physical ID of the CPU
 *
 * The instance's kernel reports the CPU offline before the CPU has
 * parked; until it has, it stays accounted to the instance.
 */
int mk_repark_cpu_to_host(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	int ret;

	guard(mutex)(&mk_park_lock);

	if (!mk_cpu_set_contains(instance->cpus_started, phys_cpu))
		return 0;

	ret = mk_arch_confirm_parked(instance, phys_cpu);
	if (!ret)
		mk_cpu_set_del(instance->cpus_started, phys_cpu);
	return ret;
}
