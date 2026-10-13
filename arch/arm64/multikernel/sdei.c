// SPDX-License-Identifier: GPL-2.0
/*
 * Force halt through SDEI.
 *
 * The stop SGI reaches a CPU that spins with interrupts masked only when
 * its kernel runs with pseudo-NMIs, and never one that has masked every
 * exception. SDEI's software-signalled event 0 is taken at EL3 and turned
 * into a call of the handler its kernel registered, whatever that CPU has
 * masked. So every kernel registers it, and a force halt signals it to the
 * CPUs of an instance before it sends them the SGI.
 *
 * TF-A acknowledges event 0 on a CPU that has SDEI masked and never ends
 * it, which leaves that CPU unable to take any non-secure interrupt. A CPU
 * therefore publishes in fw_stop[] of its shared area whether it can take
 * the event, and clears that before anything masks SDEI: going off, and
 * around a power-down idle state.
 */

#define pr_fmt(fmt) "mk_sdei: " fmt

#include <linux/acpi.h>
#include <linux/arm_sdei.h>
#include <linux/cpu_pm.h>
#include <linux/cpuhotplug.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/psci.h>
#include <asm/multikernel.h>
#include <asm/sdei.h>

#include "internal.h"

/* The software-signalled event, the only one SDEI_EVENT_SIGNAL raises */
#define MK_SDEI_STOP_EVENT	0

static DEFINE_PER_CPU(u8 *, mk_fw_stop);

#ifdef CONFIG_ACPI
static bool mk_acpi_has_sdei(void)
{
	struct acpi_table_header *table;

	if (acpi_disabled || ACPI_FAILURE(acpi_get_table(ACPI_SIG_SDEI, 0, &table)))
		return false;
	acpi_put_table(table);
	return true;
}
#else
static bool mk_acpi_has_sdei(void)
{
	return false;
}
#endif

/* The conduit to firmware's SDEI, as the SDEI driver finds it; NULL without */
static const char *mk_sdei_method(void)
{
	struct device_node *np;
	const char *method = NULL;

	np = of_find_compatible_node(NULL, NULL, "arm,sdei-1.0");
	if (np) {
		of_property_read_string(np, "method", &method);
		of_node_put(np);
	} else if (mk_acpi_has_sdei()) {
		method = acpi_psci_use_hvc() ? "hvc" : "smc";
	}
	return method;
}

int mk_dtb_add_sdei(void *fdt)
{
	const char *method = mk_sdei_method();
	int node, ret;

	if (!method)
		return 0;

	node = fdt_subnode_offset(fdt, 0, "firmware");
	if (node == -FDT_ERR_NOTFOUND)
		node = fdt_add_subnode(fdt, 0, "firmware");
	if (node >= 0)
		node = fdt_add_subnode(fdt, node, "sdei");
	if (node < 0)
		return node;

	ret = fdt_setprop_string(fdt, node, "compatible", "arm,sdei-1.0");
	if (!ret)
		ret = fdt_setprop_string(fdt, node, "method", method);
	return ret;
}

static void mk_sdei_set_reachable(bool reachable)
{
	u8 *fw_stop = this_cpu_read(mk_fw_stop);

	if (fw_stop)
		WRITE_ONCE(*fw_stop, reachable);
}

void mk_sdei_unreachable(void)
{
	mk_sdei_set_reachable(false);
}

void mk_sdei_stop_cpu(struct mk_instance *instance, u64 mpidr)
{
	struct mk_shared_data *sd = instance->ipi_data;
	int rank = mk_cpu_rank(mpidr);
	int ret;

	if (!sd || rank >= MK_PARKED_MAX || !READ_ONCE(sd->fw_stop[rank]))
		return;

	ret = sdei_event_signal(MK_SDEI_STOP_EVENT, mpidr);
	if (ret)
		pr_err_ratelimited("No SDEI stop to CPU 0x%llx: %d\n", mpidr, ret);
}

static int mk_sdei_stop(u32 event, struct pt_regs *regs, void *arg)
{
	if (!mk_has_pending_shutdown()) {
		pr_warn_ratelimited("CPU%u: ignoring an SDEI stop from another kernel\n",
				    smp_processor_id());
		return 0;
	}

	/*
	 * Complete the event before the CPU goes off. TF-A keeps the
	 * priority of a running handler active, and panics when the CPU
	 * takes the next event on top of it after its next CPU_ON.
	 */
	__sdei_handler_abort();
	__this_cpu_write(sdei_active_normal_event, NULL);

	mk_foreign_cpu_stop();
	return 0;
}

/*
 * The SDEI driver's own states and notifier mask and unmask the CPU. Its
 * hotplug state comes first, so this one is set up after it unmasks and
 * torn down before it masks; the PM notifiers sit on either side of its.
 */
static int mk_sdei_cpu_up(unsigned int cpu)
{
	struct mk_shared_data *sd = mk_self ? mk_self->ipi_data : NULL;
	int rank = mk_cpu_rank(arch_cpu_physical_id(cpu));

	if (sd && rank < MK_PARKED_MAX)
		this_cpu_write(mk_fw_stop, &sd->fw_stop[rank]);
	mk_sdei_set_reachable(true);
	return 0;
}

static int mk_sdei_cpu_down(unsigned int cpu)
{
	mk_sdei_set_reachable(false);
	return 0;
}

static int mk_sdei_pm_enter(struct notifier_block *nb, unsigned long action,
			    void *data)
{
	if (action == CPU_PM_ENTER)
		mk_sdei_set_reachable(false);
	else if (action == CPU_PM_ENTER_FAILED)
		mk_sdei_set_reachable(true);
	return NOTIFY_OK;
}

static int mk_sdei_pm_exit(struct notifier_block *nb, unsigned long action,
			   void *data)
{
	if (action == CPU_PM_EXIT)
		mk_sdei_set_reachable(true);
	return NOTIFY_OK;
}

static struct notifier_block mk_sdei_pm_enter_nb = {
	.notifier_call = mk_sdei_pm_enter,
	.priority = 1,
};

static struct notifier_block mk_sdei_pm_exit_nb = {
	.notifier_call = mk_sdei_pm_exit,
	.priority = -1,
};

static int __init mk_sdei_init(void)
{
	int ret;

	if (!mk_sdei_method())
		return 0;

	ret = sdei_event_register(MK_SDEI_STOP_EVENT, mk_sdei_stop, NULL);
	if (ret)
		goto out;
	ret = sdei_event_enable(MK_SDEI_STOP_EVENT);
	if (ret)
		goto unregister;

	cpu_pm_register_notifier(&mk_sdei_pm_enter_nb);
	cpu_pm_register_notifier(&mk_sdei_pm_exit_nb);
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "arm64/multikernel/sdei:online",
				mk_sdei_cpu_up, mk_sdei_cpu_down);
	if (ret >= 0) {
		pr_info("Force halt stops this kernel's CPUs through SDEI\n");
		return 0;
	}

	cpu_pm_unregister_notifier(&mk_sdei_pm_exit_nb);
	cpu_pm_unregister_notifier(&mk_sdei_pm_enter_nb);
	sdei_event_disable(MK_SDEI_STOP_EVENT);
unregister:
	sdei_event_unregister(MK_SDEI_STOP_EVENT);
out:
	pr_warn("No force halt through SDEI: %d\n", ret);
	return 0;
}
late_initcall(mk_sdei_init);
