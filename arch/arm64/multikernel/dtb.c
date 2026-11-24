// SPDX-License-Identifier: GPL-2.0
/*
 * The device tree an arm64 instance boots from.
 *
 * The tree in x0 is the only boot channel, see kernel/multikernel/boot_dtb.c.
 * On top of the instance tree and /memory, the arm64 boot path reads /cpus,
 * PSCI, the arch timer, the interrupt controller and SDEI.
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/acpi.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/multikernel_fw_park.h>
#include <asm/cputype.h>

#include "internal.h"

/*
 * Every wired interrupt goes through the one GIC distributor, which stays
 * the host's, so an instance has no platform devices: its devices are PCI
 * functions with MSIs. The spawn kernel's GIC driver leaves the
 * distributor alone and maps no SPIs.
 */
static int mk_dtb_add_tenancy(void *fdt, struct mk_instance *instance)
{
	int node;

	if (instance->platform_devices_valid &&
	    !list_empty(&instance->platform_devices)) {
		pr_err("Instance %d: platform devices cannot be given to an instance on arm64\n",
		       instance->id);
		return -FDT_ERR_BADSTATE;
	}

	node = fdt_node_offset_by_compatible(fdt, -1, "arm,gic-v3");
	if (node < 0)
		return node;
	return fdt_setprop_empty(fdt, node, "multikernel,tenant");
}

static int mk_dtb_add_cpu(void *fdt, int cpus, mk_phys_cpu_t mpidr)
{
	char name[32];
	int node, ret;

	snprintf(name, sizeof(name), "cpu@%llx", mpidr);
	node = fdt_add_subnode(fdt, cpus, name);
	if (node < 0)
		return node;

	ret = fdt_setprop_string(fdt, node, "device_type", "cpu");
	if (!ret)
		ret = fdt_setprop_string(fdt, node, "compatible", "arm,armv8");
	if (!ret)
		ret = fdt_setprop_string(fdt, node, "enable-method", "psci");
	if (!ret)
		ret = fdt_setprop_u64(fdt, node, "reg", mpidr);
	return ret;
}

/*
 * The instance's own CPUs come first, the boot CPU leading as it does in
 * instance->cpus, so they get the low logical numbers. Every other CPU
 * of the machine follows: a kernel can only ever online a CPU it
 * enumerated at boot, and the generic code prunes the ones the instance
 * does not own from the present mask.
 *
 * fdt_add_subnode() puts a new node ahead of its siblings, hence the
 * walk from the last CPU to the first.
 */
static int mk_dtb_add_cpus(void *fdt, struct mk_instance *instance)
{
	mk_phys_cpu_t mpidr;
	unsigned int i;
	int cpus, cpu, ret;

	cpus = fdt_add_subnode(fdt, 0, "cpus");
	if (cpus < 0)
		return cpus;
	ret = fdt_setprop_u32(fdt, cpus, "#address-cells", 2);
	if (!ret)
		ret = fdt_setprop_u32(fdt, cpus, "#size-cells", 0);
	if (ret)
		return ret;

	for (cpu = nr_cpu_ids - 1; cpu >= 0; cpu--) {
		if (!cpu_possible(cpu))
			continue;
		mpidr = arch_cpu_physical_id(cpu);
		if (mpidr == INVALID_HWID ||
		    mk_cpu_set_contains(instance->cpus, mpidr))
			continue;
		ret = mk_dtb_add_cpu(fdt, cpus, mpidr);
		if (ret)
			return ret;
	}

	for (i = mk_cpu_set_count(instance->cpus); i-- > 0; ) {
		ret = mk_dtb_add_cpu(fdt, cpus, instance->cpus->ids[i]);
		if (ret)
			return ret;
	}
	return 0;
}

/* Everything here returns libfdt error codes */
int mk_dtb_add_arch_nodes(void *fdt, struct mk_instance *instance)
{
	int ret;

	ret = mk_dtb_add_cpus(fdt, instance);
	if (!ret)
		ret = acpi_disabled ? mk_dtb_add_platform_of(fdt) :
				      mk_dtb_add_platform_acpi(fdt);
	if (!ret)
		ret = mk_dtb_add_sdei(fdt);
	if (!ret)
		ret = mk_dtb_add_tenancy(fdt, instance);
	if (!ret)
		ret = mk_dtb_add_pci(fdt);
	return ret;
}
