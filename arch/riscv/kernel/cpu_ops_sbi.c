// SPDX-License-Identifier: GPL-2.0-only
/*
 * HSM extension and cpu_ops implementation.
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 */

#include <linux/cacheflush.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/multikernel.h>
#include <linux/sched/task_stack.h>
#include <asm/cpu_ops.h>
#include <asm/cpu_ops_sbi.h>
#include <asm/sbi.h>
#include <asm/smp.h>

extern char secondary_start_sbi[];
const struct cpu_operations cpu_ops_sbi;

/*
 * Ordered booting via HSM brings one cpu at a time. However, cpu hotplug can
 * be invoked from multiple threads in parallel. Define an array of boot data
 * to handle that.
 */
static struct sbi_hart_boot_data boot_data[NR_CPUS];

static int sbi_hsm_err_map_linux_errno(long err)
{
	switch (err) {
	case SBI_ERR_ALREADY_AVAILABLE:
	case SBI_ERR_ALREADY_STARTED:
	case SBI_ERR_ALREADY_STOPPED:
		return -EALREADY;
	case SBI_ERR_FAILURE:
		return -EIO;
	default:
		return sbi_err_map_linux_errno(err);
	}
}

int sbi_hsm_hart_start(unsigned long hartid, unsigned long saddr,
		       unsigned long priv)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START,
			hartid, saddr, priv, 0, 0, 0);
	if (ret.error)
		return sbi_hsm_err_map_linux_errno(ret.error);
	else
		return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
int sbi_hsm_hart_stop(void)
{
	struct sbiret ret;

	/* A stopped hart cannot receive the remote fence for its next entry. */
	local_flush_icache_all();
	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STOP, 0, 0, 0, 0, 0, 0);

	if (ret.error)
		return sbi_hsm_err_map_linux_errno(ret.error);
	else
		return 0;
}

int sbi_hsm_hart_get_status(unsigned long hartid)
{
	struct sbiret ret;

	ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STATUS,
			hartid, 0, 0, 0, 0, 0);
	if (ret.error)
		return sbi_hsm_err_map_linux_errno(ret.error);
	else
		return ret.value;
}
#endif

#ifdef CONFIG_MULTIKERNEL
static int sbi_spawn_cpu_entry(unsigned long *boot_addr)
{
	struct mk_riscv_spawn_context *ctx;
	phys_addr_t stub_addr;

	if (!mk_is_spawn_kernel())
		return 0;

	stub_addr = mk_manifest_entry_stub_phys();
	if (stub_addr < PAGE_SIZE || !IS_ALIGNED(stub_addr, PAGE_SIZE) ||
	    !pfn_valid(PHYS_PFN(stub_addr - PAGE_SIZE)) ||
	    !pfn_valid(PHYS_PFN(stub_addr))) {
		pr_err_once("SBI: invalid multikernel entry stub address %pa\n",
			    &stub_addr);
		return -EINVAL;
	}

	ctx = phys_to_virt(stub_addr - PAGE_SIZE);
	WRITE_ONCE(ctx->image_entry, *boot_addr);
	*boot_addr = stub_addr;
	return 0;
}
#endif

static int sbi_cpu_start(unsigned int cpuid, struct task_struct *tidle)
{
	unsigned long boot_addr = __pa_symbol(secondary_start_sbi);
	unsigned long hartid = cpuid_to_hartid_map(cpuid);
	unsigned long hsm_data;
	struct sbi_hart_boot_data *bdata = &boot_data[cpuid];

	/* Make sure tidle is updated */
	smp_mb();
	bdata->task_ptr = tidle;
	bdata->stack_ptr = task_pt_regs(tidle);
#ifdef CONFIG_MULTIKERNEL
	if (sbi_spawn_cpu_entry(&boot_addr))
		return -EINVAL;
#endif
	/* Make sure boot data is updated */
	smp_mb();
	hsm_data = __pa(bdata);
	return sbi_hsm_hart_start(hartid, boot_addr, hsm_data);
}

#ifdef CONFIG_HOTPLUG_CPU
static void sbi_cpu_stop(void)
{
	int ret;

	ret = sbi_hsm_hart_stop();
	pr_crit("Unable to stop the cpu %d (%d)\n", smp_processor_id(), ret);
}

static int sbi_cpu_is_stopped(unsigned int cpuid)
{
	int rc;
	unsigned long hartid = cpuid_to_hartid_map(cpuid);

	rc = sbi_hsm_hart_get_status(hartid);

	if (rc == SBI_HSM_STATE_STOPPED)
		return 0;
	return rc;
}
#endif

const struct cpu_operations cpu_ops_sbi = {
	.cpu_start	= sbi_cpu_start,
#ifdef CONFIG_HOTPLUG_CPU
	.cpu_stop	= sbi_cpu_stop,
	.cpu_is_stopped	= sbi_cpu_is_stopped,
#endif
};
