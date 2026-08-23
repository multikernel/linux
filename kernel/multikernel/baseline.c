// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Multikernel Technologies, Inc. All rights reserved
 *
 * Multikernel baseline DTB validation and initialization
 *
 * The baseline device tree is a set of allocation requests: memory sizes
 * per NUMA node, physical CPU IDs, and devices this kernel hands to the
 * multikernel pool. It is applied exactly once, through the same move
 * primitives user space drives later through overlays.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/libfdt.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/mm.h>
#include <linux/numa.h>
#include <linux/multikernel.h>
#include <linux/ioport.h>
#include <linux/pci.h>

#include "internal.h"

#define MK_BASELINE_MAX_MEM_REQS MAX_NUMNODES

struct mk_baseline_mem_req {
	u64 size;
	int node;
};

/*
 * Parked CPUs this kernel can assign to child instances. The baseline
 * creates it, so it exists exactly in a kernel acting as a parent; it
 * stays NULL until a baseline is applied. instance->cpus,
 * root_instance's included, always means "CPUs that kernel instance
 * owns".
 */
struct mk_cpu_set *mk_cpu_pool;

static int mk_baseline_parse_cpus(const void *fdt, int resources_node,
				  struct mk_cpu_set *requested)
{
	const fdt64_t *prop;
	int len, i, cpu_count;
	char buf[256];

	prop = fdt_getprop(fdt, resources_node, "cpus", &len);
	if (!prop) {
		pr_err("No 'cpus' property in baseline /resources node\n");
		return -EINVAL;
	}

	if (len % sizeof(fdt64_t) != 0) {
		pr_err("Invalid 'cpus' property length: %d (must be an array of 64-bit physical CPU IDs)\n",
		       len);
		return -EINVAL;
	}

	cpu_count = len / sizeof(fdt64_t);
	if (cpu_count == 0) {
		pr_err("Empty CPU list in baseline\n");
		return -EINVAL;
	}

	for (i = 0; i < cpu_count; i++) {
		mk_phys_cpu_t cpu_id = fdt64_to_cpu(prop[i]);
		int ret = mk_cpu_set_add(requested, cpu_id);

		if (ret)
			return ret;
	}

	mk_cpu_set_format(buf, sizeof(buf), requested);
	pr_info("Baseline CPU pool: %d CPUs requested: %s\n", cpu_count, buf);

	return 0;
}

static int mk_baseline_parse_memory(const void *fdt, int resources_node,
				    struct mk_baseline_mem_req *reqs, int max)
{
	int node, n = 0, len;

	fdt_for_each_subnode(node, fdt, resources_node) {
		const char *name = fdt_get_name(fdt, node, NULL);
		const fdt64_t *size;
		const fdt32_t *nid;

		if (!name || strncmp(name, "memory@", 7))
			continue;

		if (n == max) {
			pr_err("Baseline: more than %d memory@ nodes\n", max);
			return -E2BIG;
		}

		size = fdt_getprop(fdt, node, "size", &len);
		if (!size || len != 8) {
			pr_err("Baseline %s: missing or invalid 'size'\n", name);
			return -EINVAL;
		}

		reqs[n].size = fdt64_to_cpu(*size);
		if (!reqs[n].size || !PAGE_ALIGNED(reqs[n].size)) {
			pr_err("Baseline %s: size 0x%llx not a positive page multiple\n",
			       name, reqs[n].size);
			return -EINVAL;
		}

		nid = fdt_getprop(fdt, node, "numa-node-id", &len);
		if (nid && len != 4) {
			pr_err("Baseline %s: invalid 'numa-node-id' length %d\n",
			       name, len);
			return -EINVAL;
		}

		reqs[n].node = nid ? (int)fdt32_to_cpu(*nid) : NUMA_NO_NODE;
		if (reqs[n].node != NUMA_NO_NODE &&
		    (reqs[n].node < 0 || reqs[n].node >= MAX_NUMNODES)) {
			pr_err("Baseline %s: numa-node-id %d out of range\n",
			       name, reqs[n].node);
			return -EINVAL;
		}

		n++;
	}

	if (!n) {
		if (fdt_getprop(fdt, resources_node, "memory-bytes", &len))
			pr_err("Baseline: memory-base/memory-bytes are no longer accepted; use memory@N { size; numa-node-id; }\n");
		else
			pr_err("Baseline has no memory@N node; the pool needs memory\n");
		return -EINVAL;
	}

	return n;
}

static void mk_baseline_free_pci_list(struct list_head *pci_list)
{
	struct mk_pci_device *pci_dev, *tmp;

	list_for_each_entry_safe(pci_dev, tmp, pci_list, list) {
		list_del(&pci_dev->list);
		kfree(pci_dev);
	}
}

static void mk_baseline_clear_resources(struct mk_instance *instance)
{
	struct mk_pci_device *pci_dev, *pci_tmp;
	struct mk_platform_device *plat_dev, *plat_tmp;

	if (!instance)
		return;

	mk_instance_free_memory(instance);
	list_for_each_entry_safe(pci_dev, pci_tmp, &instance->pci_devices, list) {
		list_del(&pci_dev->list);
		kfree(pci_dev);
	}
	instance->pci_device_count = 0;
	instance->pci_devices_valid = false;

	list_for_each_entry_safe(plat_dev, plat_tmp, &instance->platform_devices, list) {
		list_del(&plat_dev->list);
		kfree(plat_dev);
	}
	instance->platform_device_count = 0;
	instance->platform_devices_valid = false;
}

static int mk_baseline_validate_cpus(const struct mk_cpu_set *requested)
{
	mk_phys_cpu_t phys_cpu_id;
	unsigned int i;
	int logical_cpu;
	int validated = 0;

	mk_cpu_set_for_each(i, phys_cpu_id, requested) {
		logical_cpu = arch_cpu_from_physical_id(phys_cpu_id);
		if (logical_cpu < 0) {
			pr_err("Baseline CPU %llu not found in system (not present)\n",
			       phys_cpu_id);
			return -ENODEV;
		}

		if (!cpu_present(logical_cpu)) {
			pr_err("Baseline CPU %llu (logical %d) is not present\n",
			       phys_cpu_id, logical_cpu);
			return -ENODEV;
		}

		if (logical_cpu == 0 || phys_cpu_id == 0) {
			pr_warn("Baseline includes boot CPU (phys %llu, logical %d) - "
				"this may cause system instability\n",
				phys_cpu_id, logical_cpu);
		}

		validated++;
	}

	pr_info("Baseline CPUs validated: %d CPUs available for multikernel pool\n",
		validated);

	return 0;
}

static int mk_baseline_parse_devices(const void *fdt, int resources_node,
				     struct mk_instance *instance,
				     struct list_head *pci_list)
{
	int devices_node, dev_node;
	const char *dev_name, *device_type;
	int pci_count = 0;
	int len;

	devices_node = fdt_subnode_offset(fdt, resources_node, "devices");
	if (devices_node < 0) {
		pr_debug("No 'devices' node in baseline /resources - skipping device parsing\n");
		return 0;
	}

	fdt_for_each_subnode(dev_node, fdt, devices_node) {
		dev_name = fdt_get_name(fdt, dev_node, NULL);
		if (!dev_name) {
			pr_warn("Unnamed device node in baseline, skipping\n");
			continue;
		}

		device_type = fdt_getprop(fdt, dev_node, "device-type", &len);
		if (!device_type) {
			pr_warn("Device '%s' has no device-type property, skipping\n",
				dev_name);
			continue;
		}

		if (strcmp(device_type, "pci") == 0) {
			struct mk_pci_device *existing;
			struct mk_pci_device *pci_dev;
			const char *pci_id_str;
			const fdt32_t *vendor_prop, *device_prop;
			u32 vendor, device;
			u16 domain;
			u8 bus, slot, func;
			int ret;

			pci_id_str = fdt_getprop(fdt, dev_node, "pci-id", &len);
			if (!pci_id_str) {
				pr_err("PCI device '%s' missing pci-id property\n",
				       dev_name);
				return -EINVAL;
			}

			ret = mk_pci_parse_bdf(pci_id_str, len, &domain, &bus,
					       &slot, &func);
			if (ret) {
				pr_err("Invalid or out-of-range pci-id '%.*s' for device '%s'\n",
				       len, pci_id_str, dev_name);
				return ret;
			}

			vendor_prop = fdt_getprop(fdt, dev_node, "vendor-id", &len);
			if (!vendor_prop || len != 4) {
				pr_err("PCI device '%s' missing or invalid vendor-id\n",
				       dev_name);
				return -EINVAL;
			}

			device_prop = fdt_getprop(fdt, dev_node, "device-id", &len);
			if (!device_prop || len != 4) {
				pr_err("PCI device '%s' missing or invalid device-id\n",
				       dev_name);
				return -EINVAL;
			}
			vendor = fdt32_to_cpu(*vendor_prop);
			device = fdt32_to_cpu(*device_prop);
			if (vendor > U16_MAX || device > U16_MAX) {
				pr_err("Out-of-range vendor-id or device-id for device '%s'\n",
				       dev_name);
				return -ERANGE;
			}
			list_for_each_entry(existing, pci_list, list) {
				if (existing->domain == domain &&
				    existing->bus == bus && existing->slot == slot &&
				    existing->func == func) {
					pr_err("Duplicate baseline PCI BDF %04x:%02x:%02x.%x\n",
					       domain, bus, slot, func);
					return -EEXIST;
				}
			}

			pci_dev = kzalloc_obj(*pci_dev, GFP_KERNEL);
			if (!pci_dev) {
				pr_err("Failed to allocate memory for PCI device\n");
				return -ENOMEM;
			}

			strscpy(pci_dev->name, dev_name, sizeof(pci_dev->name));
			pci_dev->vendor = (u16)vendor;
			pci_dev->device = (u16)device;
			pci_dev->domain = domain;
			pci_dev->bus = bus;
			pci_dev->slot = slot;
			pci_dev->func = func;

			list_add_tail(&pci_dev->list, pci_list);
			pci_count++;

			pr_debug("Baseline device pool: requested PCI device '%s' %04x:%04x@%04x:%02x:%02x.%x\n",
				 dev_name, pci_dev->vendor, pci_dev->device,
				 pci_dev->domain, pci_dev->bus, pci_dev->slot,
				 pci_dev->func);
		} else if (strcmp(device_type, "platform") == 0) {
			struct mk_platform_device *plat_dev;
			const char *device_name_str;

			plat_dev = kzalloc_obj(*plat_dev, GFP_KERNEL);
			if (!plat_dev) {
				pr_err("Failed to allocate memory for platform device\n");
				return -ENOMEM;
			}

			strscpy(plat_dev->name, dev_name, sizeof(plat_dev->name));

			device_name_str = fdt_getprop(fdt, dev_node, "device-name", &len);
			if (device_name_str)
				strscpy(plat_dev->name, device_name_str,
					sizeof(plat_dev->name));

			list_add_tail(&plat_dev->list, &instance->platform_devices);
			instance->platform_device_count++;

			pr_debug("Baseline device pool: added platform device '%s'\n",
				 plat_dev->name);
		} else {
			pr_warn("Unknown device-type '%s' for device '%s', skipping\n",
				device_type, dev_name);
		}
	}

	if (pci_count > 0)
		pr_info("Baseline device pool: %d PCI devices requested\n", pci_count);

	if (instance->platform_device_count > 0) {
		instance->platform_devices_valid = true;
		pr_info("Baseline device pool: %d platform devices specified\n",
			instance->platform_device_count);
	}

	return 0;
}

static int mk_baseline_grow_pool(const struct mk_baseline_mem_req *reqs, int n)
{
	int i, ret;

	for (i = 0; i < n; i++) {
		ret = mk_pool_mem_grow(reqs[i].size, reqs[i].node, NULL);
		if (ret) {
			pr_err("Baseline: failed to allocate %llu MB on node %d: %d\n",
			       reqs[i].size >> 20, reqs[i].node, ret);
			return ret;
		}
	}

	return 0;
}

static int mk_baseline_initialize_cpus(const struct mk_cpu_set *requested)
{
	mk_phys_cpu_t phys_cpu_id;
	unsigned int i;
	int ret, failed = 0, moved = 0;

	pr_info("Moving %u CPUs into the multikernel pool\n",
		mk_cpu_set_count(requested));

	mk_cpu_set_for_each(i, phys_cpu_id, requested) {
		ret = mk_pool_cpu_add(phys_cpu_id);
		if (ret) {
			pr_err("Failed to move CPU %llu into the pool: %d\n",
			       phys_cpu_id, ret);
			failed++;
			continue;
		}

		moved++;
	}

	if (failed > 0) {
		pr_err("Failed to move %d CPUs - baseline initialization incomplete\n",
		       failed);
		return -EBUSY;
	}

	pr_info("Moved %d CPUs into the multikernel pool\n", moved);

	return 0;
}

#ifdef CONFIG_PCI
static int mk_baseline_initialize_devices(struct list_head *pci_list)
{
	struct mk_pci_device *pci_dev;
	int ret, failed = 0, moved = 0;

	if (list_empty(pci_list)) {
		pr_debug("No PCI devices in baseline to move into the pool\n");
		return 0;
	}

	list_for_each_entry(pci_dev, pci_list, list) {
		ret = mk_pool_device_add(pci_dev->domain, pci_dev->bus,
					 PCI_DEVFN(pci_dev->slot, pci_dev->func));
		if (ret) {
			pr_warn("PCI device %04x:%04x@%04x:%02x:%02x.%x not moved into the pool: %d\n",
				pci_dev->vendor, pci_dev->device, pci_dev->domain,
				pci_dev->bus, pci_dev->slot, pci_dev->func, ret);
			failed++;
			continue;
		}

		moved++;
	}

	if (failed > 0)
		pr_warn("Failed to move %d PCI devices into the pool\n", failed);

	pr_info("Moved %d PCI devices into the multikernel pool\n", moved);

	return 0;
}
#else
static int mk_baseline_initialize_devices(struct list_head *pci_list)
{
	if (list_empty(pci_list)) {
		pr_debug("No PCI devices in the multikernel pool\n");
		return 0;
	}

	pr_err("Cannot initialize PCI devices without CONFIG_PCI\n");
	return -EOPNOTSUPP;
}
#endif

int mk_baseline_validate_and_initialize(const void *fdt, size_t fdt_size)
{
	struct mk_baseline_mem_req *reqs;
	struct mk_cpu_set *requested;
	LIST_HEAD(pci_list);
	int resources_node, nr_reqs;
	int ret;

	if (!fdt || fdt_size == 0) {
		pr_err("Invalid baseline DTB parameters\n");
		return -EINVAL;
	}

	if (!root_instance) {
		pr_err("root_instance not initialized\n");
		return -EINVAL;
	}

	if (!root_instance->cpus) {
		pr_err("root_instance CPUs bitmap not allocated\n");
		return -ENOMEM;
	}

	if (!mk_pool_empty() || (mk_cpu_pool && !mk_cpu_set_empty(mk_cpu_pool)) ||
	    root_instance->pci_device_count) {
		pr_err("Baseline already applied; change the pool with an overlay targeting /resources\n");
		return -EBUSY;
	}

	ret = fdt_check_header(fdt);
	if (ret) {
		pr_err("Invalid baseline DTB header: %d\n", ret);
		return -EINVAL;
	}

	if (fdt_totalsize(fdt) != fdt_size) {
		pr_err("Baseline DTB size mismatch: header=%u, provided=%zu\n",
		       fdt_totalsize(fdt), fdt_size);
		return -EINVAL;
	}

	resources_node = fdt_path_offset(fdt, "/resources");
	if (resources_node < 0) {
		pr_err("No /resources node found in baseline DTB\n");
		return -EINVAL;
	}

	reqs = kcalloc(MK_BASELINE_MAX_MEM_REQS, sizeof(*reqs), GFP_KERNEL);
	if (!reqs)
		return -ENOMEM;

	requested = mk_cpu_set_alloc();
	if (!requested) {
		kfree(reqs);
		return -ENOMEM;
	}

	mk_baseline_clear_resources(root_instance);

	ret = mk_baseline_parse_cpus(fdt, resources_node, requested);
	if (ret) {
		pr_err("Failed to parse baseline CPUs: %d\n", ret);
		goto out;
	}

	nr_reqs = mk_baseline_parse_memory(fdt, resources_node, reqs,
					   MK_BASELINE_MAX_MEM_REQS);
	if (nr_reqs < 0) {
		ret = nr_reqs;
		goto out;
	}

	ret = mk_baseline_parse_devices(fdt, resources_node, root_instance,
					&pci_list);
	if (ret) {
		pr_err("Failed to parse baseline devices: %d\n", ret);
		goto out;
	}

	ret = mk_baseline_validate_cpus(requested);
	if (ret) {
		pr_err("Baseline CPU validation failed: %d\n", ret);
		goto out;
	}

	/*
	 * The move primitives only track a resource in the pool once the
	 * pool set exists, so it has to be there before the first move.
	 */
	if (!mk_cpu_pool) {
		mk_cpu_pool = mk_cpu_set_alloc();
		if (!mk_cpu_pool) {
			ret = -ENOMEM;
			goto out;
		}
	}

	ret = mk_baseline_grow_pool(reqs, nr_reqs);
	if (ret) {
		pr_err("Baseline pool allocation failed: %d\n", ret);
		goto out;
	}

	ret = mk_setup_host_park();
	if (ret) {
		pr_err("Baseline host park setup failed: %d\n", ret);
		goto out;
	}

	ret = mk_baseline_initialize_cpus(requested);
	if (ret) {
		pr_err("Baseline CPU initialization failed: %d\n", ret);
		goto out;
	}

	ret = mk_baseline_initialize_devices(&pci_list);
	if (ret) {
		pr_err("Baseline device initialization failed: %d\n", ret);
		goto out;
	}

	if (root_instance->dtb_data) {
		pr_info("Replacing existing DTB (%zu bytes) with baseline DTB\n",
			root_instance->dtb_size);
		kfree(root_instance->dtb_data);
	}

	root_instance->dtb_data = kmalloc(fdt_size, GFP_KERNEL);
	if (!root_instance->dtb_data) {
		pr_err("Failed to allocate memory for baseline DTB\n");
		root_instance->dtb_size = 0;
		ret = -ENOMEM;
		goto out;
	}

	memcpy(root_instance->dtb_data, fdt, fdt_size);
	root_instance->dtb_size = fdt_size;

	pr_info("Multikernel baseline initialized successfully\n");
	ret = 0;
out:
	mk_baseline_free_pci_list(&pci_list);
	mk_cpu_set_free(requested);
	kfree(reqs);
	return ret;
}
