/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _KERNEL_MULTIKERNEL_PCI_INTERNAL_H
#define _KERNEL_MULTIKERNEL_PCI_INTERNAL_H

#include <linux/iommu.h>
#include <linux/multikernel.h>
#include <linux/pci.h>
#include <linux/workqueue.h>

#define MK_PCI_FLR_SETTLE_MS	100

struct mk_pci_assignment;

struct mk_pci_irq_vector {
	struct mk_pci_assignment *assignment;
	unsigned int host_irq;
	u32 local_irq;
	u32 mailbox_slot;
	u32 mailbox_generation;
	atomic64_t forwarded;
	bool requested;
	bool disabled;
};

struct mk_pci_assignment {
	struct list_head instance_node;
	struct list_head active_node;
	struct list_head transaction_node;
	struct mk_instance *instance;
	struct mk_pci_device *inventory;
	struct pci_dev *vf;
	struct pci_dev *pf;
	const struct device_driver *host_driver;
	struct iommu_group *iommu_group;
	struct iommu_domain *iommu_domain;
	char *host_driver_override;
	struct mutex iommu_mutex;
	unsigned int iommu_mapped_regions;
	bool iommu_dma_owner;
	bool iommu_attached;
	bool iommu_override_active;
	struct mk_pci_irq_vector *irq_vectors;
	unsigned long *irq_bound_map;
	unsigned int nr_irq_vectors;
	u64 irq_epoch;
	u32 irq_generation;
	u32 reset_generation;
	u8 irq_state;
	bool irq_msix;
	bool irq_needs_reprogram;
	bool irq_mailbox_failed;
	unsigned long irq_flr_deadline;
	bool device_enabled;
	struct work_struct failure_work;
	atomic_t failure_pending;
	bool assigned;
	bool inventory_moved;
	bool expected_unbind;
};

extern struct mutex mk_pci_lease_mutex;
extern spinlock_t mk_pci_active_lock;
extern struct list_head mk_pci_active_assignments;

bool mk_pci_device_live(struct pci_dev *pdev);
struct mk_pci_assignment *
mk_pci_find_assignment(struct mk_instance *instance, u16 domain, u8 bus,
		       u8 devfn);
struct mk_pci_device *
mk_pci_find_device_bdf(struct list_head *devices, u16 domain, u8 bus,
		       u8 devfn);
int mk_pci_release_irqs(struct mk_pci_assignment *assignment,
			bool parked_force);
void mk_pci_schedule_failure(struct mk_pci_assignment *assignment);
void mk_pci_irq_retry_workfn(struct work_struct *work);
void mk_pci_assignment_failure_work(struct work_struct *work);
int mk_pci_control_system_init(void);
void mk_pci_control_system_cleanup(void);

void mk_pci_release_bound_driver(struct mk_pci_assignment *assignment);
int mk_pci_quiesce_assignment(struct mk_pci_assignment *assignment);
int mk_pci_reset_assignment_for_start(struct mk_pci_assignment *assignment);
void mk_pci_iommu_deactivate_assignment(struct mk_pci_assignment *assignment);
int mk_pci_iommu_prepare_assignment(struct mk_pci_assignment *assignment);
int mk_pci_iommu_commit_assignment(struct mk_pci_assignment *assignment);
void mk_pci_iommu_release_assignment(struct mk_pci_assignment *assignment);
int mk_pci_restore_host_binding(struct mk_pci_assignment *assignment);
int mk_pci_iommu_system_init(void);
void mk_pci_iommu_system_cleanup(void);

#endif /* _KERNEL_MULTIKERNEL_PCI_INTERNAL_H */
