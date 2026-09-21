// SPDX-License-Identifier: GPL-2.0
/*
 * Platform nodes of an instance tree, on a host that booted with ACPI.
 *
 * A spawn kernel always boots from a device tree, so what the host read
 * from its tables is written out in the generic bindings: PSCI's conduit
 * from the FADT, the arch timer's PPIs from the GTDT, and the GICv3
 * frames from the MADT. SBSA guarantees the generic drivers bind to it.
 */

#define pr_fmt(fmt) "mk_dtb: " fmt

#include <linux/acpi.h>
#include <linux/irq.h>
#include <linux/libfdt.h>
#include <linux/psci.h>

#include "internal.h"

/* A redistributor frame pair per CPU, where the MADT has no GICR entries */
#define MK_GICR_PER_CPU_SIZE	(2 * SZ_64K)
#define MK_GICR_MAX_REGIONS	256

static int mk_dtb_add_psci(void *fdt)
{
	static const char compatible[] = "arm,psci-1.0\0arm,psci-0.2";
	int node, ret;

	node = fdt_add_subnode(fdt, 0, "psci");
	if (node < 0)
		return node;

	ret = fdt_setprop(fdt, node, "compatible", compatible, sizeof(compatible));
	if (!ret)
		ret = fdt_setprop_string(fdt, node, "method",
					 acpi_psci_use_hvc() ? "hvc" : "smc");
	return ret;
}

static int mk_dtb_append_ppi(void *fdt, int node, u32 gsiv, u32 gtdt_flags)
{
	bool edge = gtdt_flags & ACPI_GTDT_INTERRUPT_MODE;
	bool low = gtdt_flags & ACPI_GTDT_INTERRUPT_POLARITY;
	u32 type;
	int ret;

	if (edge)
		type = low ? IRQ_TYPE_EDGE_FALLING : IRQ_TYPE_EDGE_RISING;
	else
		type = low ? IRQ_TYPE_LEVEL_LOW : IRQ_TYPE_LEVEL_HIGH;

	ret = fdt_appendprop_u32(fdt, node, "interrupts", MK_GIC_PPI);
	if (!ret)
		ret = fdt_appendprop_u32(fdt, node, "interrupts", gsiv - 16);
	if (!ret)
		ret = fdt_appendprop_u32(fdt, node, "interrupts", type);
	return ret;
}

/* The binding's order: secure, non-secure, virtual, hypervisor */
static int mk_dtb_add_timer(void *fdt)
{
	struct acpi_table_header *table;
	struct acpi_table_gtdt *gtdt;
	int node, ret;

	if (ACPI_FAILURE(acpi_get_table(ACPI_SIG_GTDT, 0, &table))) {
		pr_err("No GTDT to describe the arch timer from\n");
		return -FDT_ERR_NOTFOUND;
	}
	gtdt = (struct acpi_table_gtdt *)table;

	node = fdt_add_subnode(fdt, 0, "timer");
	ret = node < 0 ? node : 0;
	if (!ret)
		ret = fdt_setprop_string(fdt, node, "compatible", "arm,armv8-timer");
	if (!ret)
		ret = mk_dtb_append_ppi(fdt, node, gtdt->secure_el1_interrupt,
					gtdt->secure_el1_flags);
	if (!ret)
		ret = mk_dtb_append_ppi(fdt, node, gtdt->non_secure_el1_interrupt,
					gtdt->non_secure_el1_flags);
	if (!ret)
		ret = mk_dtb_append_ppi(fdt, node, gtdt->virtual_timer_interrupt,
					gtdt->virtual_timer_flags);
	if (!ret && gtdt->non_secure_el2_interrupt)
		ret = mk_dtb_append_ppi(fdt, node, gtdt->non_secure_el2_interrupt,
					gtdt->non_secure_el2_flags);
	if (!ret && (gtdt->non_secure_el1_flags & ACPI_GTDT_ALWAYS_ON))
		ret = fdt_setprop_empty(fdt, node, "always-on");

	acpi_put_table(table);
	return ret;
}

struct mk_gic_frames {
	u64 reg[2 * (1 + MK_GICR_MAX_REGIONS)];	/* distributor first */
	int nr_gicr;
	int nr_gicc;
	bool have_gicd;
};

/*
 * Redistributors are described either as GICR regions or, without any,
 * by each GICC's own frame address; the first kind wins, as in the
 * GIC driver's own probing.
 */
static void mk_gic_collect(struct acpi_table_madt *madt,
			   struct mk_gic_frames *f, u8 type)
{
	unsigned long end = (unsigned long)madt + madt->header.length;
	struct acpi_subtable_header *sub;

	for (sub = (void *)(madt + 1);
	     (unsigned long)sub + sizeof(*sub) <= end && sub->length;
	     sub = (void *)sub + sub->length) {
		u64 *gicr = &f->reg[2 * (1 + f->nr_gicr)];

		if (sub->type != type)
			continue;

		if (type == ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR) {
			struct acpi_madt_generic_distributor *gicd = (void *)sub;

			f->reg[0] = gicd->base_address;
			f->reg[1] = SZ_64K;
			f->have_gicd = gicd->version == ACPI_MADT_GIC_VERSION_V3 ||
				       gicd->version == ACPI_MADT_GIC_VERSION_V4 ||
				       gicd->version == ACPI_MADT_GIC_VERSION_NONE;
			return;
		}

		if (f->nr_gicr == MK_GICR_MAX_REGIONS)
			return;

		if (type == ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR) {
			struct acpi_madt_generic_redistributor *r = (void *)sub;

			gicr[0] = r->base_address;
			gicr[1] = r->length;
			f->nr_gicr++;
		} else {
			struct acpi_madt_generic_interrupt *gicc = (void *)sub;

			f->nr_gicc++;
			if (!gicc->gicr_base_address)
				continue;
			gicr[0] = gicc->gicr_base_address;
			gicr[1] = MK_GICR_PER_CPU_SIZE;
			f->nr_gicr++;
		}
	}
}

static int mk_dtb_add_gic(void *fdt)
{
	struct acpi_table_header *table;
	struct mk_gic_frames *f;
	int node, ret;

	if (ACPI_FAILURE(acpi_get_table(ACPI_SIG_MADT, 0, &table))) {
		pr_err("No MADT to describe the GIC from\n");
		return -FDT_ERR_NOTFOUND;
	}

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f) {
		acpi_put_table(table);
		return -FDT_ERR_NOSPACE;
	}

	mk_gic_collect((void *)table, f, ACPI_MADT_TYPE_GENERIC_DISTRIBUTOR);
	mk_gic_collect((void *)table, f, ACPI_MADT_TYPE_GENERIC_REDISTRIBUTOR);
	if (!f->nr_gicr)
		mk_gic_collect((void *)table, f, ACPI_MADT_TYPE_GENERIC_INTERRUPT);
	acpi_put_table(table);

	if (!f->have_gicd || !f->nr_gicr) {
		pr_err("The MADT describes no usable GICv3\n");
		ret = -FDT_ERR_NOTFOUND;
		goto out;
	}

	node = fdt_add_subnode(fdt, 0, "interrupt-controller");
	ret = node < 0 ? node : 0;
	if (!ret)
		ret = fdt_setprop_string(fdt, node, "compatible", "arm,gic-v3");
	if (!ret)
		ret = fdt_setprop_empty(fdt, node, "interrupt-controller");
	if (!ret)
		ret = fdt_setprop_u32(fdt, node, "#interrupt-cells", 3);
	if (!ret)
		ret = fdt_setprop_u32(fdt, node, "#redistributor-regions",
				      f->nr_gicr);
	if (!ret)
		ret = fdt_setprop_u32(fdt, node, "phandle", MK_GIC_PHANDLE);
	if (!ret)
		ret = mk_dtb_set_reg(fdt, node, f->reg, 1 + f->nr_gicr);
	if (!ret)
		ret = fdt_setprop_u32(fdt, 0, "interrupt-parent", MK_GIC_PHANDLE);
out:
	kfree(f);
	return ret;
}

int mk_dtb_add_platform_acpi(void *fdt)
{
	int ret;

	ret = mk_dtb_add_psci(fdt);
	if (!ret)
		ret = mk_dtb_add_timer(fdt);
	if (!ret)
		ret = mk_dtb_add_gic(fdt);
	return ret;
}
