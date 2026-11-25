// SPDX-License-Identifier: GPL-2.0-only
/*
 * Defaults for the optional part of the architecture interface, see
 * linux/multikernel.h. An architecture overrides the ones it has
 * something to do in.
 */

#include <linux/errno.h>
#include <linux/multikernel.h>

/* Every CPU firmware lets this kernel start is one it booted */
int __weak mk_arch_pool_discover(struct mk_cpu_set *found)
{
	return 0;
}

bool __weak mk_arch_cpu_unclaimed(mk_phys_cpu_t phys_cpu)
{
	return false;
}

/* Every CPU is alike */
unsigned int __weak mk_arch_cpu_kind(mk_phys_cpu_t phys_cpu)
{
	return 0;
}

bool __weak mk_arch_cpu_faulty(mk_phys_cpu_t phys_cpu)
{
	return false;
}

int __weak mk_arch_fence_cpu(struct mk_instance *instance,
			     mk_phys_cpu_t phys_cpu)
{
	mk_arch_force_stop_cpu(instance, phys_cpu);
	return mk_arch_confirm_parked(phys_cpu);
}

void __weak mk_arch_promote(void)
{
}

void __weak mk_arch_instance_destroy(struct mk_instance *instance)
{
}

int __weak mk_arch_manifest_chosen(void *fdt, struct mk_instance *instance)
{
	return 0;
}

int __weak mk_arch_iommu_claim(u64 base)
{
	return -EOPNOTSUPP;
}

int __weak mk_arch_lease_grant(struct mk_instance *instance, struct pci_dev *pdev)
{
	return 0;
}

u64 __weak mk_arch_pci_bus_ecam(struct pci_bus *bus)
{
	return 0;
}

u64 __weak mk_arch_pci_iommu(struct pci_dev *pdev)
{
	return 0;
}

int __weak mk_arch_pcifront_prepare(struct pci_host_bridge *bridge, int domain)
{
	return 0;
}
