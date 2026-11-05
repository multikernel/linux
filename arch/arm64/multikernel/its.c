// SPDX-License-Identifier: GPL-2.0
/*
 * The machine's ITSes, as a spawn sees them:
 *
 *   /chosen/multikernel,iommus {
 *       #address-cells = <2>; #size-cells = <2>;
 *       iommu@8080000 {
 *           compatible = "multikernel,its";
 *           reg = <base size>;
 *           numa-node-id = <0>;				if known
 *           multikernel,msi-map = <domain rid devid count>, ...;
 *       };
 *   };
 *
 * A spawn that takes over from the host claims them. The DeviceID of a PCI
 * function is what the firmware maps its RID to, and nothing in a spawn's
 * own tree says so, so the map goes with the unit.
 *
 * The host describes the units from its ITS driver. Any other kernel passes
 * on what it was told unchanged, so a kernel that took over describes them
 * to its spawns just as its host did.
 */

#include <linux/irqchip/arm-gic-v3.h>
#include <linux/libfdt.h>
#include <linux/msi.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/slab.h>

#define MK_IOMMUS_PATH		"/chosen/multikernel,iommus"
#define MK_ITS_COMPATIBLE	"multikernel,its"

struct mk_its_map {
	u32 domain;
	u32 rid;
	u32 devid;
	u32 count;
};

static int mk_its_map_add(struct mk_its_map **map, int *n, u32 domain,
			  u32 rid, u32 devid)
{
	struct mk_its_map *last = *n ? &(*map)[*n - 1] : NULL, *grown;

	if (last && last->domain == domain && last->rid + last->count == rid &&
	    last->devid + last->count == devid) {
		last->count++;
		return 0;
	}
	grown = krealloc_array(*map, *n + 1, sizeof(**map), GFP_KERNEL);
	if (!grown)
		return -ENOMEM;
	grown[(*n)++] = (struct mk_its_map){ domain, rid, devid, 1 };
	*map = grown;
	return 0;
}

static int mk_its_build_map(const struct its_unit_desc *its,
			    struct mk_its_map **map, int *n)
{
	struct pci_dev *pdev = NULL;
	int ret;

	for_each_pci_dev(pdev) {
		struct irq_domain *d = dev_get_msi_domain(&pdev->dev);

		if (its_foreign_doorbell(d) != its->base + GITS_TRANSLATER)
			continue;
		ret = mk_its_map_add(map, n, pci_domain_nr(pdev->bus),
				     pci_dev_id(pdev),
				     pci_msi_domain_get_msi_rid(d, pdev));
		if (ret) {
			pci_dev_put(pdev);
			return ret;
		}
	}
	return 0;
}

static int mk_its_emit(void *fdt, const struct its_unit_desc *its)
{
	fdt64_t reg[2] = { cpu_to_fdt64(its->base), cpu_to_fdt64(its->size) };
	struct mk_its_map *map = NULL;
	fdt32_t *cells;
	char name[32];
	int n = 0, i, ret;

	ret = mk_its_build_map(its, &map, &n);
	if (ret)
		goto out;

	snprintf(name, sizeof(name), "iommu@%llx", its->base);
	ret = fdt_begin_node(fdt, name);
	if (!ret)
		ret = fdt_property_string(fdt, "compatible", MK_ITS_COMPATIBLE);
	if (!ret)
		ret = fdt_property(fdt, "reg", reg, sizeof(reg));
	if (!ret && its->node != NUMA_NO_NODE)
		ret = fdt_property_u32(fdt, "numa-node-id", its->node);
	if (!ret && n)
		ret = fdt_property_placeholder(fdt, "multikernel,msi-map",
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

static int mk_its_copy(void *fdt, struct device_node *np)
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

int mk_arch_manifest_chosen(void *fdt, struct mk_instance *instance)
{
	struct device_node *told = of_find_node_by_path(MK_IOMMUS_PATH);
	struct its_unit_desc its;
	struct device_node *np;
	int i, ret;

	if (!told && its_unit_get(0, &its))
		return 0;

	ret = fdt_begin_node(fdt, "multikernel,iommus");
	if (!ret)
		ret = fdt_property_u32(fdt, "#address-cells", 2);
	if (!ret)
		ret = fdt_property_u32(fdt, "#size-cells", 2);
	if (told) {
		for_each_child_of_node(told, np) {
			if (ret) {
				of_node_put(np);
				break;
			}
			if (of_device_is_compatible(np, MK_ITS_COMPATIBLE))
				ret = mk_its_copy(fdt, np);
		}
		of_node_put(told);
	} else {
		for (i = 0; !ret && !its_unit_get(i, &its); i++)
			ret = mk_its_emit(fdt, &its);
	}
	return ret ? ret : fdt_end_node(fdt);
}
