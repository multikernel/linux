// SPDX-License-Identifier: GPL-2.0-only
/*
 * The host's AMD IOMMUs, as a spawn sees them under
 * /chosen/multikernel,iommus (iommu.c):
 *
 *   iommu@fedc0000 {
 *       compatible = "multikernel,amd-vi";
 *       reg = <base size>;
 *       linux,pci-domain = <0>;
 *       multikernel,irq-remap;		if it remaps
 *       multikernel,capability = <cap>;	of its PCI function
 *       multikernel,msi-map = <domain rid devid count>, ...;
 *   };
 *
 * The map says which functions sit behind the unit and under which device
 * ID each is remapped, which the firmware told the host and nothing tells
 * a spawn. A spawn passes on what it was told unchanged.
 *
 * A function has an interrupt remapping table to itself, so a spawn picks
 * the entries of a function it was lent and the host writes them where it
 * says: @high of the request is the device ID, @low the vector and above
 * it the APIC ID, or zero to clear the entry. The table is cleared when
 * the lease ends. A function remapped under another's device ID shares
 * that one's table and is refused.
 */

#define pr_fmt(fmt) "mk_amd_vi: " fmt

#include <linux/amd-iommu.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <asm/multikernel.h>

#include "iommu.h"

#define MK_AMD_VI_COMPATIBLE	"multikernel,amd-vi"
#define MK_AMD_VI_MAP		"multikernel,msi-map"

/*
 * The units
 */

/* One <domain rid devid count> of a unit's map */
struct mk_amd_vi_range {
	u32 domain;
	u32 rid;
	u32 devid;
	u32 count;
};

static int mk_amd_vi_range_add(struct mk_amd_vi_range **map, int *n, u32 domain,
			       u32 rid, u32 devid)
{
	struct mk_amd_vi_range *last = *n ? &(*map)[*n - 1] : NULL, *grown;

	if (last && last->domain == domain && last->rid + last->count == rid &&
	    last->devid + last->count == devid) {
		last->count++;
		return 0;
	}
	grown = krealloc_array(*map, *n + 1, sizeof(**map), GFP_KERNEL);
	if (!grown)
		return -ENOMEM;
	grown[(*n)++] = (struct mk_amd_vi_range){ domain, rid, devid, 1 };
	*map = grown;
	return 0;
}

static bool mk_amd_vi_range_get(struct device_node *np, int i,
				struct mk_amd_vi_range *range)
{
	return !of_property_read_u32_index(np, MK_AMD_VI_MAP, 4 * i, &range->domain) &&
	       !of_property_read_u32_index(np, MK_AMD_VI_MAP, 4 * i + 1, &range->rid) &&
	       !of_property_read_u32_index(np, MK_AMD_VI_MAP, 4 * i + 2, &range->devid) &&
	       !of_property_read_u32_index(np, MK_AMD_VI_MAP, 4 * i + 3, &range->count);
}

static int mk_amd_vi_emit(void *fdt, const struct amd_iommu_unit_desc *unit)
{
	fdt64_t reg[2] = { cpu_to_fdt64(unit->base), cpu_to_fdt64(unit->size) };
	struct mk_amd_vi_range *map = NULL;
	struct pci_dev *pdev = NULL;
	fdt32_t *cells;
	char name[32];
	int n = 0, i, ret = 0;
	u16 devid;
	u64 base;

	for_each_pci_dev(pdev) {
		if (amd_iommu_device_unit(pdev, &base, &devid) || base != unit->base)
			continue;
		ret = mk_amd_vi_range_add(&map, &n, pci_domain_nr(pdev->bus),
					  pci_dev_id(pdev), devid);
		if (ret) {
			pci_dev_put(pdev);
			goto out;
		}
	}

	snprintf(name, sizeof(name), "iommu@%llx", unit->base);
	ret = fdt_begin_node(fdt, name);
	if (!ret)
		ret = fdt_property_string(fdt, "compatible", MK_AMD_VI_COMPATIBLE);
	if (!ret)
		ret = fdt_property(fdt, "reg", reg, sizeof(reg));
	if (!ret)
		ret = fdt_property_u32(fdt, "linux,pci-domain", unit->segment);
	if (!ret && unit->irq_remap)
		ret = fdt_property(fdt, "multikernel,irq-remap", NULL, 0);
	if (!ret)
		ret = fdt_property_u32(fdt, "multikernel,capability", unit->cap);
	if (!ret && n)
		ret = fdt_property_placeholder(fdt, MK_AMD_VI_MAP,
					       n * sizeof(*map), (void **)&cells);
	for (i = 0; !ret && i < n; i++) {
		cells[4 * i] = cpu_to_fdt32(map[i].domain);
		cells[4 * i + 1] = cpu_to_fdt32(map[i].rid);
		cells[4 * i + 2] = cpu_to_fdt32(map[i].devid);
		cells[4 * i + 3] = cpu_to_fdt32(map[i].count);
	}
	if (!ret)
		ret = fdt_end_node(fdt);
out:
	kfree(map);
	return ret;
}

static int mk_amd_vi_copy(void *fdt, struct device_node *np)
{
	struct property *pp;
	char name[32];
	int ret;

	snprintf(name, sizeof(name), "%pOFP", np);
	ret = fdt_begin_node(fdt, name);
	for_each_property_of_node(np, pp) {
		if (ret)
			break;
		if (strcmp(pp->name, "name"))
			ret = fdt_property(fdt, pp->name, pp->value, pp->length);
	}
	return ret ? ret : fdt_end_node(fdt);
}

/* The unit this kernel was told of after @prev, which is put */
static struct device_node *mk_amd_vi_next_told(struct device_node *prev)
{
	struct device_node *units __free(device_node) =
		of_find_node_by_path(MK_IOMMUS_PATH);
	struct device_node *np = prev;

	while ((np = of_get_next_child(units, np)))
		if (of_device_is_compatible(np, MK_AMD_VI_COMPATIBLE))
			break;
	return np;
}

#define for_each_told_unit(np) \
	for (np = mk_amd_vi_next_told(NULL); np; np = mk_amd_vi_next_told(np))

bool mk_amd_vi_units(void)
{
	struct device_node *told __free(device_node) = mk_amd_vi_next_told(NULL);
	struct amd_iommu_unit_desc unit;

	return told || !amd_iommu_unit_get(0, &unit);
}

int mk_amd_vi_emit_units(void *fdt)
{
	struct device_node *told = mk_amd_vi_next_told(NULL);
	struct amd_iommu_unit_desc unit;
	int i, ret = 0;

	if (!told) {
		for (i = 0; !ret && !amd_iommu_unit_get(i, &unit); i++)
			ret = mk_amd_vi_emit(fdt, &unit);
		return ret;
	}
	for (; told && !ret; told = mk_amd_vi_next_told(told))
		ret = mk_amd_vi_copy(fdt, told);
	of_node_put(told);
	return ret;
}

/*
 * Host side
 */

static int mk_amd_vi_segment(u64 base)
{
	struct amd_iommu_unit_desc unit;
	int i;

	for (i = 0; !amd_iommu_unit_get(i, &unit); i++)
		if (unit.base == base)
			return unit.segment;
	return -ENODEV;
}

/* Only for a function leased to @instance, at its own CPUs, and while the lease holds */
int mk_amd_vi_irte_apply(struct mk_instance *instance,
			 const struct mk_irte_payload *req)
{
	int segment = mk_amd_vi_segment(req->unit);
	u32 apicid = req->low >> 32;
	u8 vector = req->low;
	struct mk_lease *lease;
	struct pci_dev *pdev;
	int ret = -EPERM;
	u16 devid;
	u64 base;

	if (segment < 0 || req->mask || req->high > 0xffff)
		return -EINVAL;
	if (vector && !mk_cpu_set_contains(instance->cpus, apicid))
		return -EPERM;

	pdev = pci_get_domain_bus_and_slot(segment, PCI_BUS_NUM(req->high),
					   req->high & 0xff);
	if (!pdev)
		return -ENODEV;
	lease = mk_lease_lock(instance, pdev);
	if (lease) {
		if (!amd_iommu_device_unit(pdev, &base, &devid) &&
		    base == req->unit && devid == req->high)
			ret = amd_iommu_irte_write(pdev, req->index, vector, apicid);
		mk_lease_unlock(lease);
	}
	pci_dev_put(pdev);
	return ret;
}

static void mk_amd_vi_unlend(void *data)
{
	amd_iommu_irte_release(data);
}

int mk_amd_vi_lease_grant(struct pci_dev *pdev)
{
	u16 devid;
	u64 base;

	if (amd_iommu_device_unit(pdev, &base, &devid))
		return 0;
	return devm_add_action_or_reset(&pdev->dev, mk_amd_vi_unlend, pdev);
}

/*
 * Spawn side, for the AMD IOMMU driver
 */

static struct device_node *mk_amd_vi_told(int i, u64 base)
{
	struct device_node *np;
	u64 reg;

	for_each_told_unit(np) {
		if (of_property_read_u64(np, "reg", &reg))
			continue;
		if (i < 0 ? reg == base : !i--)
			break;
	}
	return np;
}

static int mk_amd_vi_unit(int i, struct amd_iommu_unit_desc *unit)
{
	struct device_node *np __free(device_node) = mk_amd_vi_told(i, 0);
	u32 segment;

	if (!np)
		return -ENOENT;
	*unit = (struct amd_iommu_unit_desc){};
	if (of_property_read_u64_index(np, "reg", 0, &unit->base) ||
	    of_property_read_u64_index(np, "reg", 1, &unit->size) ||
	    of_property_read_u32(np, "linux,pci-domain", &segment) ||
	    of_property_read_u32(np, "multikernel,capability", &unit->cap))
		return -EINVAL;
	unit->segment = segment;
	unit->irq_remap = of_property_read_bool(np, "multikernel,irq-remap");
	return 0;
}

/* The ranges of the unit's own PCI domain */
static int mk_amd_vi_map(u64 base, int i, struct amd_iommu_unit_map *map)
{
	struct device_node *np __free(device_node) = mk_amd_vi_told(-1, base);
	struct mk_amd_vi_range range;
	u32 segment;
	int n;

	if (!np || of_property_read_u32(np, "linux,pci-domain", &segment))
		return -ENOENT;
	for (n = 0; mk_amd_vi_range_get(np, n, &range); n++) {
		if (range.domain != segment || i--)
			continue;
		*map = (struct amd_iommu_unit_map){ range.rid, range.devid,
						    range.count };
		return 0;
	}
	return -ENOENT;
}

static int mk_amd_vi_irte_write(u64 base, u16 devid, u32 index, u8 vector,
				u32 apicid)
{
	return mk_irte_write(base, index, 0,
			     vector ? (u64)apicid << 32 | vector : 0, devid);
}

static const struct amd_iommu_foreign_ops mk_amd_vi_foreign_ops = {
	.unit		= mk_amd_vi_unit,
	.map		= mk_amd_vi_map,
	.irte_write	= mk_amd_vi_irte_write,
};

void __init mk_amd_vi_init(void)
{
	amd_iommu_set_foreign_ops(&mk_amd_vi_foreign_ops);
}
