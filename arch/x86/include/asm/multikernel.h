/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MULTIKERNEL_H
#define _ASM_X86_MULTIKERNEL_H

#include <linux/bits.h>

/* Park cell state, written only by the CPU the cell belongs to */
#define MK_PARK_RUNNING		0
#define MK_PARK_PARKED		1

/* Park cell commands */
#define MK_PARK_CMD_NONE	0
#define MK_PARK_CMD_BOOT	1	/* boot a kernel, see mk_cell_park */
#define MK_PARK_CMD_SECONDARY	2	/* join a running kernel, see mk_cell_park */
#define MK_PARK_CMD_MOVE	3	/* reserved: move to a new park code page */

#define MK_PARK_MAGIC		0x4b504b4d	/* "MKPK" */
#define MK_PARK_VERSION		1
#define MK_PARK_PGTABLE_PAGES	16

#ifndef __ASSEMBLY__

#include <linux/build_bug.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/sizes.h>
#include <asm/bootparam.h>
#include <asm/page_types.h>
#include <asm/smp.h>

struct mk_instance;
struct mk_spawn_context;
struct mk_ident_pgtable;

#ifdef CONFIG_MULTIKERNEL
/* Per-instance spawn state, carved from the control block on first spawn */
struct mk_instance_arch {
	struct mk_spawn_context *spawn_ctx;
	phys_addr_t spawn_ctx_phys;
	struct mk_ident_pgtable *ident_pgt;
	void *trampoline_va;
};
#endif

/*
 * Physical CPU IDs are APIC IDs, widened to the generic u64 type. The
 * parentheses keep asm/smp.h's cpu_physical_id() macro from expanding
 * over the smp_ops member of the same name.
 */
static inline u64 arch_cpu_physical_id(int cpu)
{
	return (smp_ops.cpu_physical_id)(cpu);
}

static inline int arch_cpu_from_physical_id(u64 phys_id)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		if (arch_cpu_physical_id(cpu) == phys_id)
			return cpu;
	}
	return -1;
}

/*
 * Spawn context: what a parent hands an instance it boots, around the
 * boot_params the instance's kernel starts with. The spawn kernel finds
 * it by subtracting offsetof(bp) from its boot_params pointer, so the
 * fixed-size fields come first and their offsets are a cross-kernel
 * ABI; struct boot_params can vary between builds.
 *
 * The parent writes it before every boot of the instance and the
 * instance's kernel reads it while it initializes. It is no mailbox:
 * CPUs are started through their park table cells.
 */
struct mk_spawn_context {
	unsigned long self_phys;	/* Physical address of this struct, a layout check */
	unsigned long identity_cr3;	/* Page table the boot CPU switches to */
	unsigned long kernel_entry;	/* Entry point of the instance's kernel */
	unsigned long park_table;	/* Park table every kernel parks its CPUs in */
	unsigned long ctrl_phys;	/* Host control area: this context, trampoline, */
	unsigned long ctrl_size;	/* page tables. Spawn must not reuse it */
	unsigned long reserved[2];
	struct boot_params bp;		/* Standard x86 boot params */
	/* Optional boot data belongs after boot_params, in the zeroed tail. */
	unsigned long boot_lps;		/* Host delay loops per second */
	unsigned long boot_cpu_khz;	/* Host CPU frequency calibration */
	unsigned long boot_tsc_khz;	/* Host TSC frequency calibration */
	unsigned long boot_apic_hz;	/* Host local APIC timer frequency */
} __aligned(PAGE_SIZE);

static_assert(offsetof(struct mk_spawn_context, bp) == 64);
static_assert(offsetof(struct mk_spawn_context, boot_lps) ==
	      64 + sizeof(struct boot_params));
static_assert(sizeof(struct mk_spawn_context) == 2 * PAGE_SIZE);

/*
 * The park table: where every CPU of the machine waits while no kernel
 * runs on it, one cell per CPU. The first kernel on the machine builds
 * it and every later kernel inherits it, so a CPU parks in the same
 * cell whichever kernel parked it and whichever one wakes it. Its
 * layout is a cross-kernel ABI, versioned in the header.
 *
 * One contiguous range: this header with the APIC ID of each cell's
 * CPU, the park code page, the cells, then the page table parked CPUs
 * run on, which maps the table and nothing else.
 */
struct mk_park_table {
	u32 magic;
	u32 version;
	u32 nr_cells;
	u32 reserved;
	u64 size;
	u64 code_phys;
	u64 park_cr3;
	u64 cells_phys;
	u32 apic_id[];
};

/*
 * A CPU's cell. state and cmd form one word, so that claiming a command
 * and leaving the park loop is a single atomic step, as is publishing
 * one only to a CPU that is parked. The rest of the page is the CPU's
 * own descriptor tables and fault stack while parked.
 */
struct mk_park_cell {
	union {
		struct {
			u32 state;
			u32 cmd;
		};
		u64 word;
	};
	u64 arg[6];
	u64 reserved;
	u8 gdt[16];
	u64 gdt_entries[4];
	u8 idt[16];
	u8 idt_entries[32 * 16];
} __aligned(PAGE_SIZE);

static_assert(offsetof(struct mk_park_cell, gdt) == 64);
static_assert(sizeof(struct mk_park_cell) == PAGE_SIZE);

/* Cell park loop, copied once into the park table's code page */
extern char mk_cell_park_start[];
extern char mk_cell_park_end[];

struct mk_ident_pgtable;

int mk_park_table_create(void);
int mk_park_table_destroy(void);
void mk_park_table_set_boot(phys_addr_t phys);
phys_addr_t mk_park_table_phys(void);
bool mk_park_table_uses(phys_addr_t start, size_t size);
int mk_park_table_regions(u64 *pairs, int max);
phys_addr_t mk_park_code_phys(void);
int mk_park_dispatch(u32 apic_id, u32 cmd, const u64 *args, unsigned int nargs);
int mk_park_wait(u32 apic_id);
void mk_park_this_cpu(void);
void mk_park_cpu_running(void);
bool mk_park_ready(void);

/* Page table helpers the park table shares with spawn */
struct mk_ident_pgtable *mk_build_arena_pgtable(void *arena, int pages);
int mk_add_trampoline_mapping(struct mk_ident_pgtable *pgt,
			      unsigned long virt, unsigned long phys);
unsigned long mk_default_page_offset(void);


/* Build a spawn E820 table from the instance's current memory grant */
struct mk_instance;
struct boot_params;
int mk_e820_fill(struct mk_instance *instance, struct boot_params *params);

/* Park a pool CPU leaving this kernel (play_dead path) */
void __noreturn multikernel_play_dead(void);


/*
 * Control block: spawn context, trampoline page and identity page
 * tables, plus slack for alignment. Sized once so the whole thing is
 * one contiguous range the spawn kernel can reserve with a single call.
 */
#define MK_CTRL_PGTABLE_PAGES	64
#define MK_CTRL_BLOCK_SIZE	(SZ_16K + (3 + MK_CTRL_PGTABLE_PAGES) * PAGE_SIZE)

struct mk_ident_pgtable;

/* Allocate spawn context (includes boot_params) */
struct mk_spawn_context *mk_alloc_spawn_context(struct mk_instance *instance,
						phys_addr_t *phys_out);
struct boot_params *mk_spawn_context_boot_params(struct mk_spawn_context *ctx);

/* Set up spawn context for kernel boot */
void mk_set_spawn_context(struct mk_spawn_context *ctx,
			  unsigned long identity_cr3,
			  unsigned long kernel_entry,
			  unsigned long park_table);

/* Trigger spawn on a pool CPU */
int mk_spawn_cpu(struct mk_instance *instance, int cpu,
		 struct mk_spawn_context *ctx);

/* Initialize boot context tracking in spawn kernel */
void mk_init_boot_context(phys_addr_t ctx_phys);


/* Identity page table and trampoline setup */
struct mk_ident_pgtable *mk_build_identity_pgtable(struct mk_instance *instance);
int mk_ident_map_range(struct mk_ident_pgtable *pgt, unsigned long start,
		       unsigned long end);
void mk_free_identity_pgtable(struct mk_ident_pgtable *pgt);
unsigned long mk_get_identity_cr3(struct mk_ident_pgtable *pgt);
void *mk_setup_trampoline(struct mk_instance *instance,
			  struct mk_ident_pgtable *pgt,
			  unsigned long *phys_out);

/* Secondary CPU wakeup for spawn kernels (reuses boot context) */
int multikernel_wakeup_secondary_cpu_64(u32 apicid, unsigned long start_eip,
					unsigned int cpu);

/* Restore AP to spawn context (used by hibernation/switch) */
int multikernel_restore_ap(unsigned int cpu, unsigned long cr3,
			   unsigned long gs_base, unsigned long stack,
			   unsigned long entry);

/* NMI on an offline pool CPU: honor a pending force halt */
#ifdef CONFIG_MULTIKERNEL
void mk_nmi_offline_park(void);
#else
static inline void mk_nmi_offline_park(void)
{
}
#endif

#if defined(CONFIG_MULTIKERNEL) && defined(CONFIG_DMAR_TABLE)
void mk_dmar_init(void);
#else
static inline void mk_dmar_init(void)
{
}
#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_MULTIKERNEL_H */
