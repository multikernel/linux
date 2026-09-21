// SPDX-License-Identifier: GPL-2.0
/*
 * Platform devices of an instance tree, and the instance's tenancy of
 * the GIC.
 *
 * A spawn kernel probes what its tree describes, so granting a platform
 * device is copying its node from the host tree. That takes a host that
 * has one: on an ACPI host the device has no node to copy. Providers the
 * node points at (clocks, resets, power domains, pinctrl) stay with the
 * host and are not followed, which limits this to self-contained
 * devices such as a virtio-mmio transport.
 *
 * The device's SPIs go with it. The spawn's GIC driver runs in tenant
 * mode and maps nothing but the SPIs its node grants, and the host gives
 * them up by unbinding its driver, which leaves them disabled at the
 * distributor until a driver binds again after the instance is gone.
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>

#include "internal.h"

#define MK_GIC_SPI	0

static int mk_dtb_gic_node(void *fdt)
{
	return fdt_node_offset_by_compatible(fdt, -1, "arm,gic-v3");
}

/*
 * Write the device's interrupts as plain GIC specifiers and grant each
 * SPI: whatever interrupt-parent or interrupt-map the host resolves them
 * through is not part of the instance tree.
 */
static int mk_dtb_grant_irqs(void *fdt, const char *path, struct device_node *np)
{
	struct of_phandle_args irq;
	int i, c, node, ret;

	node = fdt_path_offset(fdt, path);
	if (node < 0)
		return node;
	fdt_delprop(fdt, node, "interrupts");
	fdt_delprop(fdt, node, "interrupts-extended");
	fdt_delprop(fdt, node, "interrupt-parent");

	for (i = 0; !of_irq_parse_one(np, i, &irq); i++) {
		bool spi = irq.args_count == 3 && irq.args[0] == MK_GIC_SPI &&
			   of_device_is_compatible(irq.np, "arm,gic-v3");

		of_node_put(irq.np);
		if (!spi) {
			pr_err("%pOF: interrupt %d is no GICv3 SPI\n", np, i);
			return -FDT_ERR_BADVALUE;
		}

		node = fdt_path_offset(fdt, path);
		for (c = 0; c < 3 && node >= 0; c++) {
			ret = fdt_appendprop_u32(fdt, node, "interrupts", irq.args[c]);
			if (ret)
				return ret;
		}

		node = mk_dtb_gic_node(fdt);
		if (node < 0)
			return node;
		ret = fdt_appendprop_u32(fdt, node, "multikernel,spis", irq.args[1]);
		if (!ret)
			ret = fdt_appendprop_u32(fdt, node, "multikernel,spis", 1);
		if (ret)
			return ret;
	}
	return 0;
}

static int mk_dtb_add_device(void *fdt, const char *name)
{
	struct device *dev;
	char path[64];
	int node, ret;

	dev = bus_find_device_by_name(&platform_bus_type, NULL, name);
	if (!dev || !dev->of_node) {
		pr_warn("Platform device %s has no node to describe it to an instance\n",
			name);
		put_device(dev);
		return 0;
	}

	if (dev->driver) {
		pr_err("Platform device %s is still bound to %s here\n",
		       name, dev->driver->name);
		put_device(dev);
		return -FDT_ERR_BADSTATE;
	}

	node = mk_dtb_copy_of_node(fdt, dev->of_node);
	ret = node < 0 ? node : 0;
	if (!ret) {
		snprintf(path, sizeof(path), "/%pOFf", dev->of_node);
		ret = mk_dtb_grant_irqs(fdt, path, dev->of_node);
	}
	put_device(dev);
	return ret;
}

int mk_dtb_add_devices(void *fdt, struct mk_instance *instance)
{
	struct mk_platform_device *plat;
	int node, ret;

	node = mk_dtb_gic_node(fdt);
	if (node < 0)
		return node;
	ret = fdt_setprop_empty(fdt, node, "multikernel,tenant");
	if (ret || !instance->platform_devices_valid)
		return ret;

	list_for_each_entry(plat, &instance->platform_devices, list) {
		if (!plat->name[0])
			continue;
		ret = mk_dtb_add_device(fdt, plat->name);
		if (ret)
			return ret;
	}
	return 0;
}
