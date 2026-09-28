/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _KERNEL_MULTIKERNEL_INTERNAL_H
#define _KERNEL_MULTIKERNEL_INTERNAL_H

#include <linux/multikernel.h>

struct mk_dt_config;
struct mk_cpu_resource_payload;

extern struct mutex mk_instance_mutex;
extern struct idr mk_instance_idr;
extern struct list_head mk_instance_list;

/* core.c */
struct mk_instance *mk_instance_alloc(int id, const char *name);
int mk_instance_publish(struct mk_instance *instance);
void mk_instance_free(struct mk_instance *instance);

/* core.c */
int mk_instance_force_halt(struct mk_instance *instance);

/* ipi.c */
int mk_send_ipi_data(struct mk_instance *instance, void *data,
		     size_t data_size, unsigned long type);
struct mk_shared_data *mk_instance_halt_data(struct mk_instance *instance);
void mk_poll_ipi_messages(void);
int mk_reply_publish_route_locked(struct mk_instance *instance,
				  const struct mk_reply_handle *reply,
				  s32 status, u32 value);

/* kernfs.c */
extern struct kernfs_node *mk_root_kn;
extern struct kernfs_node *mk_instances_kn;
int mk_create_instance_from_dtb(const char *name, int id, const void *fdt,
				int chosen_node, int resources_node);
struct mk_instance *mk_instance_find_by_name(const char *name);
int mk_instance_destroy(struct mk_instance *instance);
int mk_instance_release_resources(struct mk_instance *instance);
void mk_cpu_ownership_lock(void);
void mk_cpu_ownership_unlock(void);
void mk_cpu_ownership_assert_held(void);
/* Caller serializes CPU ownership changes with mk_cpu_transaction_lock(). */
int mk_instance_migrate_irq_route(struct mk_instance *instance,
				  const struct mk_cpu_set *removing);

/* dts.c */
int mk_dt_parse_chosen(const void *fdt, int chosen_node,
		       struct mk_instance *instance);
int mk_dt_emit_host_tree(void *fdt, const struct mk_instance *instance);
int mk_dt_parse_resources(const void *fdt, int resources_node,
			  const char *instance_name, struct mk_dt_config *config);
int mk_dt_emit_boot_tree(struct mk_instance *instance, void *fdt, size_t size,
			 int (*chosen)(void *fdt, void *data), void *data);
int mk_dt_generate_instance_dtb(struct mk_instance *instance,
				 void **out_dtb, size_t *out_size);
int mk_pci_parse_bdf(const char *pci_id, int len, u16 *domain, u8 *bus,
		     u8 *slot, u8 *func);

/* pci.c */
#if defined(CONFIG_MULTIKERNEL) && defined(CONFIG_PCI)
int mk_pci_lease_system_init(void);
void mk_pci_lease_system_cleanup(void);
void mk_pci_lease_instance_init(struct mk_instance *instance);
void mk_pci_irq_retry_disable_sync(struct mk_instance *instance);
void mk_pci_irq_retry_enable(struct mk_instance *instance);
bool mk_pci_iommu_lease_active_locked(struct mk_instance *instance);
int mk_pci_assign_devices(struct mk_instance *instance,
			  const struct list_head *requested_devices,
			  int requested_count);
int mk_pci_assign_device(struct mk_instance *instance, u16 domain, u8 bus,
			 u8 devfn);
int mk_pci_unassign_device(struct mk_instance *instance, u16 domain, u8 bus,
			   u8 devfn);
int mk_pci_release_assignments(struct mk_instance *instance);
int mk_pci_quiesce_instance_irqs(struct mk_instance *instance,
				 bool parked_force);
unsigned int mk_pci_sync_instance_irq_route(struct mk_instance *instance);
#else
static inline int mk_pci_lease_system_init(void) { return 0; }
static inline void mk_pci_lease_system_cleanup(void) { }
static inline void mk_pci_lease_instance_init(struct mk_instance *instance) { }
static inline void
mk_pci_irq_retry_disable_sync(struct mk_instance *instance)
{
}

static inline void mk_pci_irq_retry_enable(struct mk_instance *instance)
{
}

static inline bool
mk_pci_iommu_lease_active_locked(struct mk_instance *instance)
{
	return false;
}

static inline int
mk_pci_assign_devices(struct mk_instance *instance,
		      const struct list_head *requested_devices,
		      int requested_count)
{
	return requested_count ? -EOPNOTSUPP : 0;
}

static inline int
mk_pci_assign_device(struct mk_instance *instance, u16 domain, u8 bus, u8 devfn)
{
	return -EOPNOTSUPP;
}

static inline int
mk_pci_unassign_device(struct mk_instance *instance, u16 domain, u8 bus,
		       u8 devfn)
{
	return -EOPNOTSUPP;
}

static inline int mk_pci_release_assignments(struct mk_instance *instance)
{
	return 0;
}

static inline int
mk_pci_quiesce_instance_irqs(struct mk_instance *instance, bool parked_force)
{
	return 0;
}

static inline unsigned int
mk_pci_sync_instance_irq_route(struct mk_instance *instance)
{
	return 0;
}
#endif
/* overlay.c */
extern struct kernfs_node *mk_overlay_root_kn;
extern struct mutex mk_overlay_mutex;
int mk_overlay_init(void);
void mk_overlay_exit(void);
int mk_overlay_rmdir(struct kernfs_node *kn);

/* ipi.c */
int mk_arm_force_halt(struct mk_instance *instance);

/* hotplug.c */
int mk_hotplug_init(void);
void mk_hotplug_cleanup(void);
int mk_handle_cpu_remove(struct mk_cpu_resource_payload *payload,
			 u32 payload_len, s32 sender_instance_id);

/*
 * Move primitives between this kernel and the pool it manages. Valid
 * only while mk_pool is non-NULL.
 */
int mk_pool_cpu_add(mk_phys_cpu_t cpu_id);
int mk_pool_cpu_remove(mk_phys_cpu_t cpu_id, u32 numa_node, u32 flags);
int mk_pool_device_add(u16 domain, u8 bus, u8 devfn, const char *alias);
int mk_pool_device_remove(u16 domain, u8 bus, u8 devfn,
			  const char *driver_override, u32 flags);

/* Root pool bookkeeping for PCI devices, see core.c */
bool mk_root_has_pci_device(u16 domain, u8 bus, u8 devfn);
int mk_root_add_pci_device(u16 domain, u8 bus, u8 devfn, const char *alias);
int mk_root_del_pci_device(u16 domain, u8 bus, u8 devfn);

/* contig.c */
struct page *mk_alloc_contig_pages(unsigned long nr_pages, int node);
void mk_free_contig_pages(struct page *pages, unsigned long nr_pages);

/* baseline.c */
int mk_baseline_validate_and_initialize(const void *fdt, size_t fdt_size);

/* dts.c */
const char *mk_dt_node_alias(const void *fdt, int node);
/* of_devices.c: a spawn's devices are the nodes of its tree */
#ifdef CONFIG_OF
struct device_node *mk_of_pci_node(u16 domain, u8 bus, u8 devfn);
bool mk_of_pci_available(u16 domain, u8 bus, u8 devfn);
int mk_of_pci_lend(struct mk_instance *instance, u16 domain, u8 bus, u8 devfn);
void mk_of_pci_take_back(u16 domain, u8 bus, u8 devfn);
#else
static inline bool mk_of_pci_available(u16 domain, u8 bus, u8 devfn)
{
	return false;
}
static inline int mk_of_pci_lend(struct mk_instance *instance, u16 domain,
				 u8 bus, u8 devfn)
{
	return -ENOENT;
}
static inline void mk_of_pci_take_back(u16 domain, u8 bus, u8 devfn)
{
}
#endif

/* manifest.c */
phys_addr_t mk_manifest_phys(void);

#endif /* _KERNEL_MULTIKERNEL_INTERNAL_H */
