/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ARCH_X86_MULTIKERNEL_INTERNAL_H
#define _ARCH_X86_MULTIKERNEL_INTERNAL_H

#include <linux/types.h>
#include <asm/multikernel.h>

struct boot_params;
struct mk_ident_pgtable;
struct mk_instance;
struct mk_spawn_context;

/* Cell park loop, copied once into the park table's code page */
extern char mk_cell_park_start[];
extern char mk_cell_park_end[];

/* park.c: the park table */
int mk_park_table_create(void);
int mk_park_table_destroy(void);
void mk_park_table_set_boot(phys_addr_t phys);
phys_addr_t mk_park_table_phys(void);
bool mk_park_table_uses(phys_addr_t start, size_t size);
int mk_park_table_regions(u64 *pairs, int max);
phys_addr_t mk_park_code_phys(void);
int mk_park_dispatch(u32 apic_id, u32 cmd, const u64 *args, unsigned int nargs);
int mk_park_wait(u32 apic_id);
bool mk_park_parked(u32 apic_id);
void mk_park_mark_faulty(u32 apic_id);
bool mk_park_faulty(u32 apic_id);

/* spawn.c: page table helpers the park table shares with spawn */
struct mk_ident_pgtable *mk_build_arena_pgtable(void *arena, int pages);
int mk_add_trampoline_mapping(struct mk_ident_pgtable *pgt,
			      unsigned long virt, unsigned long phys);
unsigned long mk_default_page_offset(void);
int mk_ident_map_range(struct mk_ident_pgtable *pgt, unsigned long start,
		       unsigned long end);
void mk_free_identity_pgtable(struct mk_ident_pgtable *pgt);
unsigned long mk_get_identity_cr3(struct mk_ident_pgtable *pgt);

/* spawn.c: an instance's spawn context, identity page table and trampoline */
struct mk_spawn_context *mk_alloc_spawn_context(struct mk_instance *instance);
struct boot_params *mk_spawn_context_boot_params(struct mk_spawn_context *ctx);
void mk_set_spawn_context(struct mk_spawn_context *ctx,
			  unsigned long identity_cr3,
			  unsigned long kernel_entry,
			  unsigned long park_table);
struct mk_ident_pgtable *mk_build_identity_pgtable(struct mk_instance *instance);
void *mk_setup_trampoline(struct mk_instance *instance,
			  struct mk_ident_pgtable *pgt,
			  unsigned long *phys_out);

#endif /* _ARCH_X86_MULTIKERNEL_INTERNAL_H */
