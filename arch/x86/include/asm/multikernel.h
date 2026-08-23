/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MULTIKERNEL_H
#define _ASM_X86_MULTIKERNEL_H

#include <linux/bits.h>

/* Spawn context flags */
#define MK_SPAWN_F_SECONDARY	BIT(0)	/* Secondary CPU joining existing kernel */
#define MK_SPAWN_F_REPARK	BIT(1)	/* Move the CPU to another park slot */

#ifndef __ASSEMBLY__

#include <linux/build_bug.h>
#include <linux/init.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/cpumask.h>
#include <linux/sizes.h>
#include <asm/bootparam.h>
#include <asm/page_types.h>
#include <asm/smp.h>

struct mk_instance;

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
 * Spawn context - combines boot_params with spawn-specific fields.
 * Lives in shared memory (multikernel pool), reused for both primary
 * boot and secondary CPU wakeup.
 *
 * IMPORTANT: Fixed-size fields must come FIRST, before struct boot_params.
 * The size of struct boot_params can vary between kernel builds, so if it
 * comes first, the offsets of subsequent fields would differ between host
 * and spawn kernels built with different configs.
 *
 * The field offsets are a cross-kernel ABI: the pool park code reads them
 * from a page written by the host while running on CPUs parked by (possibly
 * differently built) spawn kernels.
 *
 * The fields fall into three classes that must not be mixed up:
 *
 *  - Anchor fields (self_phys, park_phys, park_cr3, ctrl_phys,
 *    ctrl_size): the context's own identity, written once when the
 *    context is set up. The spawn kernel reads them whenever it parks a
 *    CPU on halt or offline, so they must stay valid for the context's
 *    whole lifetime.
 *
 *  - Primary boot data (bp and the calibration values appended after it):
 *    written before the boot CPU is released and consumed while that kernel
 *    initializes. Secondary and repark publications do not rewrite it.
 *
 *  - Dispatch fields (the remaining fixed-size fields): the wake mailbox,
 *    rewritten for every publication and staged into registers by the CPU
 *    that claims it. Reparking gets its own repark_* dispatch fields so a
 *    repark publication never overwrites the anchor: the two used to
 *    share fields, and a repark left the anchor pointing at another
 *    kernel's park area, which triple-faulted the next halt.
 */
struct mk_spawn_context {
	/* Fixed-size fields first - offsets are same regardless of kernel config */
	unsigned long self_phys;	/* Physical address of this struct (for spawn to find itself) */
	unsigned long identity_cr3;	/* Identity-mapped page tables */
	unsigned long kernel_entry;	/* Entry point */
	unsigned long trampoline_virt;	/* Trampoline virtual address */
	unsigned long trampoline_phys;	/* Trampoline physical address (base) */
	unsigned long secondary_trampoline_phys;  /* Secondary CPU trampoline physical address */
	unsigned long gs_base;		/* Per-CPU GS base (for secondary) */
	unsigned long stack;		/* Stack pointer (for secondary) */
	unsigned long spawn_cr3;	/* Spawn kernel's CR3 (for secondary CPU final switch) */
	unsigned long park_phys;	/* Pool park code page (host owned, never reloaded) */
	unsigned long park_cr3;		/* Page table parked CPUs run on (host owned) */
	unsigned long repark_park_phys;	/* REPARK dispatch: park page to move to */
	unsigned long repark_park_cr3;	/* REPARK dispatch: page table for it */
	unsigned long repark_slot_phys;	/* REPARK dispatch: slot to watch there */
	unsigned long ctrl_phys;	/* Host control area: this context, trampoline, */
	unsigned long ctrl_size;	/* park page, page tables. Spawn must not reuse it */
	u32 target_apic_id;		/* Target CPU's APIC ID */
	u32 flags;			/* MK_SPAWN_F_* flags */
	u32 ready;			/* Signal flag */
	u32 reserved;			/* Padding for alignment */
	/* Keep all existing context offsets unchanged. */
	struct boot_params bp;		/* Standard x86 boot params */
	/* Optional boot data belongs after boot_params, in the zeroed tail. */
	unsigned long boot_lps;		/* Host delay loops per second */
	unsigned long boot_cpu_khz;	/* Host CPU frequency calibration */
	unsigned long boot_tsc_khz;	/* Host TSC frequency calibration */
	unsigned long boot_apic_hz;	/* Host local APIC timer frequency */
	u64 abi_magic;			/* Validated context producer */
} __aligned(PAGE_SIZE);

static_assert(offsetof(struct mk_spawn_context, bp) == 144);
static_assert(offsetof(struct mk_spawn_context, boot_lps) ==
	      144 + sizeof(struct boot_params));
static_assert(offsetof(struct mk_spawn_context, abi_magic) ==
	      144 + sizeof(struct boot_params) + 4 * sizeof(unsigned long));
static_assert(sizeof(struct mk_spawn_context) == 2 * PAGE_SIZE);

/* Pool park loop code, copied by the host into per-instance park pages */
extern char mk_pool_park_start[];
extern char mk_pool_park_end[];

/*
 * Park this CPU in the instance's pool park page. Returns only when no
 * park page is available (older spawn context), in which case the caller
 * must fall back to an in-kernel wait loop.
 */
void mk_park_cpu(void);

/* True only in a spawn kernel whose boot context carries a park area */
bool mk_cpu_parkable(void);

/* Build a spawn E820 table from the instance's current memory grant */
struct mk_instance;
struct boot_params;
int mk_e820_fill(struct mk_instance *instance, struct boot_params *params);

/* Park an offlined pool CPU (host park area, or instance context) */
void mk_pool_park_cpu(void);

/* Park a pool CPU leaving this kernel (play_dead path) */
void __noreturn multikernel_play_dead(void);

/*
 * Control block: spawn context, trampoline page, park page and identity
 * page tables, plus slack for alignment. Sized once so the whole thing is
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
			  unsigned long trampoline_virt,
			  unsigned long trampoline_phys,
			  unsigned long park_phys);

/* Trigger spawn on a pool CPU */
int mk_spawn_cpu(struct mk_instance *instance, int cpu,
		 struct mk_spawn_context *ctx);

/* Validate and initialize boot context tracking in spawn kernel */
struct mk_spawn_context *mk_validate_boot_context(phys_addr_t ctx_phys);
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
void *mk_setup_park_page(struct mk_instance *instance, unsigned long *phys_out);

/* Secondary CPU wakeup for spawn kernels (reuses boot context) */
int multikernel_wakeup_secondary_cpu_64(u32 apicid, unsigned long start_eip,
					unsigned int cpu);

/* Restore AP to spawn context (used by hibernation/switch) */
int multikernel_restore_ap(unsigned int cpu, unsigned long cr3,
			   unsigned long gs_base, unsigned long stack,
			   unsigned long entry);
#if defined(CONFIG_MULTIKERNEL) && defined(CONFIG_PCI)
void __init x86_multikernel_pci_platform_init(void);
#else
static inline void x86_multikernel_pci_platform_init(void) { }
#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_MULTIKERNEL_H */
