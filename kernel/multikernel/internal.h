extern struct resource multikernel_res;
extern struct mutex mk_instance_mutex;
extern struct mutex mk_host_dtb_mutex;
extern struct idr mk_instance_idr;
extern struct list_head mk_instance_list;
extern struct mk_instance *root_instance;

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
int mk_overlay_init(void);
void mk_overlay_exit(void);
int mk_overlay_rmdir(struct kernfs_node *kn);

/* hotplug.c */
int mk_hotplug_init(void);
void mk_hotplug_cleanup(void);
int mk_handle_cpu_remove(struct mk_cpu_resource_payload *payload, u32 payload_len);

/* baseline.c */
int mk_baseline_validate_and_initialize(const void *fdt, size_t fdt_size);
