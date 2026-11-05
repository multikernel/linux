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
#include <linux/irqdomain.h>
#include <linux/libfdt.h>
#include <linux/msi.h>
#include <linux/multikernel.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "internal.h"

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

static struct device_node *mk_its_unit(u64 base)
{
	struct device_node *units, *np;
	u64 reg;

	units = of_find_node_by_path(MK_IOMMUS_PATH);
	if (!units)
		return NULL;
	for_each_child_of_node(units, np)
		if (of_device_is_compatible(np, MK_ITS_COMPATIBLE) &&
		    !of_property_read_u64(np, "reg", &reg) && reg == base)
			break;
	of_node_put(units);
	return np;
}

struct mk_its_claimed {
	struct list_head list;
	struct device_node *np;
	struct irq_domain *domain;
};

static LIST_HEAD(mk_its_claimed_list);
static DEFINE_MUTEX(mk_its_claimed_lock);

/**
 * mk_its_lookup - The claimed ITS behind a PCI function
 * @domain: PCI domain of the function
 * @rid: bus << 8 | devfn
 * @its: set to the MSI domain of the ITS
 * @dev_id: set to the DeviceID of the function there
 *
 * Sleeps. Returns 0, or -ENOENT unless this kernel claimed the ITS.
 */
int mk_its_lookup(u32 domain, u32 rid, struct irq_domain **its, u32 *dev_id)
{
	struct mk_its_claimed *c;
	const __be32 *map;
	int i, len;

	guard(mutex)(&mk_its_claimed_lock);
	list_for_each_entry(c, &mk_its_claimed_list, list) {
		map = of_get_property(c->np, "multikernel,msi-map", &len);
		for (i = 0; map && i + 4 <= len / sizeof(*map); i += 4) {
			u32 first = be32_to_cpup(map + i + 1);

			if (be32_to_cpup(map + i) == domain && rid >= first &&
			    rid - first < be32_to_cpup(map + i + 3)) {
				*its = c->domain;
				*dev_id = be32_to_cpup(map + i + 2) + rid - first;
				return 0;
			}
		}
	}
	return -ENOENT;
}

int mk_arch_iommu_claim(u64 base)
{
	struct device_node *np = mk_its_unit(base);
	struct mk_its_claimed *c;
	u32 node;
	u64 size;
	int ret;

	if (!np)
		return -ENODEV;
	c = kzalloc_obj(*c);
	if (!c) {
		ret = -ENOMEM;
		goto put;
	}
	if (of_property_read_u64_index(np, "reg", 1, &size)) {
		ret = -EINVAL;
		goto free;
	}
	if (of_property_read_u32(np, "numa-node-id", &node))
		node = NUMA_NO_NODE;

	scoped_guard(mutex, &mk_its_claimed_lock) {
		struct mk_its_claimed *done;

		list_for_each_entry(done, &mk_its_claimed_list, list)
			if (done->np == np) {
				ret = 0;
				goto free;
			}
	}

	/* The unit node is the fwnode of the ITS domain from now on */
	ret = its_claim(of_fwnode_handle(np), base, size, node);
	if (ret)
		goto free;
	c->np = np;
	c->domain = irq_find_matching_fwnode(of_fwnode_handle(np),
					     DOMAIN_BUS_NEXUS);
	scoped_guard(mutex, &mk_its_claimed_lock)
		list_add_tail(&c->list, &mk_its_claimed_list);

	mk_msi_proxy_rebind();
	return 0;
free:
	kfree(c);
put:
	of_node_put(np);
	return ret;
}
