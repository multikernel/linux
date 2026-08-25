/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _KERNEL_MULTIKERNEL_INTERNAL_H
#define _KERNEL_MULTIKERNEL_INTERNAL_H

#include <linux/multikernel.h>

struct mk_dt_config;
struct mk_cpu_resource_payload;

extern struct mutex mk_instance_mutex;
extern struct mutex mk_host_dtb_mutex;
extern struct idr mk_instance_idr;
extern struct list_head mk_instance_list;
extern struct mk_instance *root_instance;

/* core.c */
int mk_instance_force_halt(struct mk_instance *instance);

/* ipi.c */
int mk_send_ipi_data(struct mk_instance *instance, void *data,
		     size_t data_size, unsigned long type);
void mk_poll_ipi_messages(void);

/* kernfs.c */
extern struct kernfs_node *mk_root_kn;
extern struct kernfs_node *mk_instances_kn;
int mk_create_instance_from_dtb(const char *name, int id, const void *fdt,
				      int resources_node, size_t dtb_size);
struct mk_instance *mk_instance_find_by_name(const char *name);
int mk_instance_destroy(struct mk_instance *instance);

/* dts.c */
int mk_dt_parse_resources(const void *fdt, int resources_node,
			  const char *instance_name, struct mk_dt_config *config);
int mk_dt_generate_instance_dtb(struct mk_instance *instance,
				 void **out_dtb, size_t *out_size);

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
int mk_handle_cpu_remove(struct mk_cpu_resource_payload *payload, u32 payload_len);

/*
 * Move primitives between this kernel and the pool it manages. Valid
 * only while mk_cpu_pool is non-NULL.
 */
int mk_pool_cpu_add(mk_phys_cpu_t cpu_id);
int mk_pool_cpu_remove(mk_phys_cpu_t cpu_id, u32 numa_node, u32 flags);
int mk_pool_device_add(u16 domain, u8 bus, u8 devfn);
int mk_pool_device_remove(u16 domain, u8 bus, u8 devfn,
			  const char *driver_override, u32 flags);

/* Root pool bookkeeping for PCI devices, see core.c */
bool mk_root_has_pci_device(u16 domain, u8 bus, u8 devfn);
int mk_root_add_pci_device(u16 domain, u8 bus, u8 devfn);
int mk_root_del_pci_device(u16 domain, u8 bus, u8 devfn);

/* contig.c */
struct page *mk_alloc_contig_pages(unsigned long nr_pages, int node);
void mk_free_contig_pages(struct page *pages, unsigned long nr_pages);

/* baseline.c */
int mk_baseline_validate_and_initialize(const void *fdt, size_t fdt_size);
/*
 * Parked CPUs this kernel can assign to child instances. Created when a
 * baseline is applied to this kernel; NULL until then. Managing a pool
 * is a role, not an identity: any kernel given a baseline becomes a
 * parent, which is what allows spawn kernels to spawn in turn.
 */
extern struct mk_cpu_set *mk_cpu_pool;

/* manifest.c */
phys_addr_t mk_manifest_phys(void);

#endif /* _KERNEL_MULTIKERNEL_INTERNAL_H */
