// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/x86/multikernel/spawn.c - Direct 64-bit spawn trigger via IPI
 *
 * This implements the spawn trigger mechanism for multikernel. When a spawn
 * kernel needs to be started on a pool CPU:
 *
 * 1. The pool CPU is waiting in multikernel_play_dead() with APIC enabled
 * 2. Host calls mk_spawn_cpu() which sets spawn context and sends IPI
 * 3. The CPU wakes from halt, checks spawn context, and jumps to trampoline
 * 4. Trampoline switches page tables and jumps to spawn kernel
 *
 * For secondary CPU bringup in spawn kernel:
 * - Reuse the same spawn context from primary boot
 * - Update entry point to secondary_startup_64
 * - Reuse identity page tables and trampoline
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc.
 */

#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/multikernel.h>
#include <linux/percpu.h>
#include <linux/set_memory.h>
#include <linux/sched.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/tlbflush.h>
#include <asm/msr.h>
#include <asm/special_insns.h>
#include <asm/irqflags.h>
#include <asm/processor-flags.h>
#include <asm/processor.h>
#include <asm/apic.h>
#include <asm/bootparam.h>
#include <asm/multikernel.h>
#include <asm/realmode.h>
#include <asm/cpu_entry_area.h>
#include <linux/objtool.h>
#include <linux/annotate.h>

/*
 * Spawn context - combines boot_params with spawn-specific fields.
 * Lives in shared memory (multikernel pool), reused for both primary
 * boot and secondary CPU wakeup.
 *
 * IMPORTANT: Fixed-size fields must come FIRST, before struct boot_params.
 * The size of struct boot_params can vary between kernel builds, so if it
 * comes first, the offsets of subsequent fields would differ between host
 * and spawn kernels built with different configs. This would cause spawn
 * kernel to write at different offsets than host kernel reads, corrupting
 * the communication.
 */

/*
 * Spawn context pointers:
 * - mk_boot_context: Set in spawn kernel, points to context used to boot
 * - mk_active_spawn: Set in host kernel when triggering a spawn
 */
static struct mk_spawn_context *mk_boot_context;
static struct mk_spawn_context *mk_active_spawn;

/*
 * Spawn kernel's own trampoline for secondary CPU wakeup.
 * The boot context's trampoline_phys was set by the HOST kernel and contains
 * HOST kernel's trampoline code. When host and spawn kernel binaries differ,
 * the offsets and code layout differ, causing hangs.
 *
 * The spawn kernel copies its OWN trampoline code here for secondary CPU wakeup.
 * This ensures binary compatibility - the spawn kernel doesn't rely on any
 * code from the host kernel.
 */
static void *spawn_trampoline_va;
static unsigned long spawn_trampoline_phys;

extern char multikernel_relocate_kernel_start[];
extern char multikernel_relocate_kernel_end[];
extern char mk_secondary_trampoline[];

/*
 * Multikernel secondary CPU entry point - does NOT switch CR3 to init_top_pgt.
 * Used instead of secondary_startup_64 for pool CPUs joining spawn kernel.
 */
extern void multikernel_secondary_startup(void);

/* Initial spawn trampoline: cr3, boot_params, kernel_entry, trampoline_phys */
typedef void (*mk_trampoline_fn)(unsigned long cr3, unsigned long boot_params,
				  unsigned long kernel_entry, unsigned long trampoline_phys);

/* Secondary CPU trampoline: identity_cr3, entry, gs_base, stack, trampoline_phys, spawn_cr3 */
typedef void (*mk_secondary_trampoline_fn)(unsigned long identity_cr3, unsigned long entry,
					   unsigned long gs_base, unsigned long stack,
					   unsigned long trampoline_phys, unsigned long spawn_cr3);

/*
 * Called by multikernel_play_dead() after each halt to check for spawn signal.
 */
void mk_check_spawn(void)
{
	struct mk_spawn_context *ctx;
	mk_trampoline_fn trampoline;
	mk_secondary_trampoline_fn secondary_trampoline;
	unsigned long secondary_trampoline_phys;
	u32 apic_id;
	bool is_secondary_wakeup;

	/* Check host's active spawn first, then spawn kernel's boot context */
	ctx = READ_ONCE(mk_active_spawn);
	if (!ctx)
		ctx = mk_boot_context;
	if (!ctx)
		return;

	if (!READ_ONCE(ctx->ready))
		return;

	/*
	 * Pair with smp_wmb() in multikernel_wakeup_secondary_cpu_64().
	 * Ensures we see all ctx fields written before ready was set.
	 */
	smp_rmb();

	apic_id = read_apic_id();
	if (apic_id != ctx->target_apic_id)
		return;

	/* Clear ready flag */
	WRITE_ONCE(ctx->ready, 0);
	smp_wmb();

	/* Check if this is secondary CPU joining existing kernel */
	is_secondary_wakeup = (ctx->flags & MK_SPAWN_F_SECONDARY);

	if (is_secondary_wakeup) {
		/*
		 * Secondary CPU joining existing spawn kernel.
		 * Use ctx->secondary_trampoline_phys directly - this was set by
		 * the SPAWN kernel using its own trampoline code and offset.
		 *
		 * IMPORTANT: We must NOT compute the offset ourselves because
		 * the HOST kernel's trampoline offset may differ from the spawn
		 * kernel's offset due to different code generation between
		 * different kernel configs.
		 *
		 * The trampoline runs from its direct-map virtual address initially,
		 * then jumps to identity-mapped physical address after CR3 switch.
		 */
		secondary_trampoline_phys = ctx->secondary_trampoline_phys;
		secondary_trampoline = (mk_secondary_trampoline_fn)
			__va(secondary_trampoline_phys);
		secondary_trampoline(ctx->identity_cr3, ctx->kernel_entry,
				     ctx->gs_base, ctx->stack,
				     secondary_trampoline_phys, ctx->spawn_cr3);
	} else {
		/*
		 * Initial spawn boot - use full trampoline with identity mapping.
		 */
		trampoline = (mk_trampoline_fn)ctx->trampoline_virt;
		trampoline(ctx->identity_cr3, virt_to_phys(&ctx->bp),
			   ctx->kernel_entry, ctx->trampoline_phys);
	}
}

struct mk_spawn_context *mk_alloc_spawn_context(struct mk_instance *instance,
						phys_addr_t *phys_out)
{
	struct mk_spawn_context *ctx;

	ctx = mk_instance_alloc(instance, sizeof(*ctx), PAGE_SIZE);
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	if (phys_out)
		*phys_out = virt_to_phys(ctx);
	return ctx;
}

struct boot_params *mk_spawn_context_boot_params(struct mk_spawn_context *ctx)
{
	return &ctx->bp;
}

void mk_set_spawn_context(struct mk_spawn_context *ctx,
			  unsigned long identity_cr3,
			  unsigned long kernel_entry,
			  unsigned long trampoline_virt,
			  unsigned long trampoline_phys)
{
	ctx->identity_cr3 = identity_cr3;
	ctx->kernel_entry = kernel_entry;
	ctx->trampoline_virt = trampoline_virt;
	ctx->trampoline_phys = trampoline_phys;
	ctx->gs_base = 0;
	ctx->stack = 0;
	ctx->ready = 0;
}

int mk_spawn_cpu(int cpu, struct mk_spawn_context *ctx)
{
	u32 apic_id = per_cpu(x86_cpu_to_apicid, cpu);

	ctx->target_apic_id = apic_id;
	/* Set active spawn pointer so pool CPUs can find it */
	WRITE_ONCE(mk_active_spawn, ctx);

	/* Ensure context visible before setting ready flag */
	smp_wmb();
	WRITE_ONCE(ctx->ready, 1);

	/* Send IPI to wake CPU from halt */
	apic->send_IPI(cpu, RESCHEDULE_VECTOR);
	return 0;
}

/*
 * Initialize boot context tracking in spawn kernel.
 * Called early during spawn kernel boot.
 */
void mk_init_boot_context(phys_addr_t ctx_phys)
{
	if (!ctx_phys) {
		pr_err("mk_spawn: Boot context physical address is 0!\n");
		return;
	}

	/*
	 * The spawn context is in the multikernel pool which is regular RAM,
	 * already covered by the direct map. Use __va() instead of memremap().
	 */
	mk_boot_context = __va(ctx_phys);
}

/*
 * Add a 2MB executable mapping to a page table.
 * Allocates P4D/PUD/PMD levels as needed, reusing existing entries if present.
 * Handles both 4-level and 5-level paging.
 */
static int mk_add_2mb_mapping(pgd_t *pgd, unsigned long virt, unsigned long phys)
{
	int pgd_idx = pgd_index(virt);
	int p4d_idx = p4d_index(virt);
	int pud_idx = pud_index(virt);
	int pmd_idx = pmd_index(virt);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (pgtable_l5_enabled()) {
		if (!(pgd_val(pgd[pgd_idx]) & _PAGE_PRESENT)) {
			p4d = (p4d_t *)get_zeroed_page(GFP_KERNEL);
			if (!p4d)
				return -ENOMEM;
			pgd[pgd_idx] = __pgd(__pa(p4d) | _KERNPG_TABLE);
		} else {
			p4d = (p4d_t *)__va(pgd_val(pgd[pgd_idx]) & PTE_PFN_MASK);
		}

		if (!(p4d_val(p4d[p4d_idx]) & _PAGE_PRESENT)) {
			pud = (pud_t *)get_zeroed_page(GFP_KERNEL);
			if (!pud)
				return -ENOMEM;
			p4d[p4d_idx] = __p4d(__pa(pud) | _KERNPG_TABLE);
		} else {
			pud = (pud_t *)__va(p4d_val(p4d[p4d_idx]) & PTE_PFN_MASK);
		}
	} else {
		/* 4-level paging: PGD points directly to PUD */
		if (!(pgd_val(pgd[pgd_idx]) & _PAGE_PRESENT)) {
			pud = (pud_t *)get_zeroed_page(GFP_KERNEL);
			if (!pud)
				return -ENOMEM;
			pgd[pgd_idx] = __pgd(__pa(pud) | _KERNPG_TABLE);
		} else {
			pud = (pud_t *)__va(pgd_val(pgd[pgd_idx]) & PTE_PFN_MASK);
		}
	}

	if (!(pud_val(pud[pud_idx]) & _PAGE_PRESENT)) {
		pmd = (pmd_t *)get_zeroed_page(GFP_KERNEL);
		if (!pmd)
			return -ENOMEM;
		pud[pud_idx] = __pud(__pa(pmd) | _KERNPG_TABLE);
	} else {
		pmd = (pmd_t *)__va(pud_val(pud[pud_idx]) & PTE_PFN_MASK);
	}

	pmd[pmd_idx] = __pmd((phys & PMD_MASK) | __PAGE_KERNEL_LARGE_EXEC);
	return 0;
}

/*
 * Initialize spawn kernel's trampoline (one-time setup).
 * Copies spawn kernel's trampoline code to the pool memory page
 * that was allocated by the host kernel during initial spawn boot.
 */
static void mk_init_trampoline(struct mk_spawn_context *ctx)
{
	size_t size;

	if (spawn_trampoline_phys)
		return;

	size = multikernel_relocate_kernel_end - multikernel_relocate_kernel_start;
	spawn_trampoline_phys = ctx->trampoline_phys;
	spawn_trampoline_va = __va(spawn_trampoline_phys);
	memcpy(spawn_trampoline_va, multikernel_relocate_kernel_start, size);
}

/*
 * Build identity page table for secondary CPU trampoline execution.
 * Maps the trampoline at both its virtual address and identity-mapped.
 */
static int mk_build_trampoline_pgtable(unsigned long trampoline_va,
				       unsigned long trampoline_phys,
				       unsigned long *cr3_out)
{
	pgd_t *pgd;
	int ret;

	pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL);
	if (!pgd)
		return -ENOMEM;

	/* Map trampoline at its virtual address (initial execution) */
	ret = mk_add_2mb_mapping(pgd, trampoline_va, trampoline_phys);
	if (ret)
		return ret;

	/* Map trampoline identity (virt=phys, for after CR3 switch) */
	ret = mk_add_2mb_mapping(pgd, trampoline_phys, trampoline_phys);
	if (ret)
		return ret;

	*cr3_out = __pa(pgd);
	return 0;
}

/*
 * Custom wakeup function for multikernel spawn kernels.
 * Wakes a pool CPU to join this spawn kernel as a secondary CPU.
 */
int multikernel_wakeup_secondary_cpu_64(u32 apicid, unsigned long start_eip,
					unsigned int cpu)
{
	struct mk_spawn_context *ctx = mk_boot_context;
	unsigned long trampoline_phys, trampoline_va;
	unsigned long identity_cr3;
	pgd_t *spawn_pgd;
	int ret;

	if (!ctx) {
		pr_err("mk_spawn: Boot context not initialized\n");
		return -ENODEV;
	}

	/* Initialize spawn kernel's trampoline (first call only) */
	mk_init_trampoline(ctx);
	trampoline_phys = spawn_trampoline_phys;
	trampoline_va = (unsigned long)spawn_trampoline_va;

	/* Build identity page table for two-stage CR3 switch */
	ret = mk_build_trampoline_pgtable(trampoline_va, trampoline_phys,
					  &identity_cr3);
	if (ret)
		return ret;

	/* Add identity mapping to spawn kernel's page tables */
	spawn_pgd = (pgd_t *)__va(__read_cr3() & PTE_PFN_MASK);
	ret = mk_add_2mb_mapping(spawn_pgd, trampoline_phys, trampoline_phys);
	if (ret)
		return ret;

	/* Set up spawn context for secondary CPU */
	ctx->identity_cr3 = identity_cr3;
	ctx->trampoline_phys = trampoline_phys;
	ctx->secondary_trampoline_phys = trampoline_phys +
		(mk_secondary_trampoline - multikernel_relocate_kernel_start);
	ctx->kernel_entry = (unsigned long)multikernel_secondary_startup;
	ctx->gs_base = per_cpu_offset(cpu);
	ctx->stack = (unsigned long)idle_task(cpu)->thread.sp;
	ctx->spawn_cr3 = __read_cr3();
	ctx->target_apic_id = apicid;
	ctx->flags = MK_SPAWN_F_SECONDARY;

	/* Ensure context is visible before signaling ready */
	smp_wmb();
	WRITE_ONCE(ctx->ready, 1);

	/* Wake the target CPU via IPI */
	apic_icr_write(APIC_DM_FIXED | APIC_DEST_PHYSICAL | RESCHEDULE_VECTOR,
		       apicid);

	return 0;
}

#define MK_IDENT_PGTABLE_PAGES 64

struct mk_ident_pgtable {
	unsigned long *pages[MK_IDENT_PGTABLE_PAGES];
	int next_page;
	unsigned long pgd_phys;
	struct mk_instance *instance;
};

void mk_free_identity_pgtable(struct mk_ident_pgtable *pgt);

static unsigned long *mk_alloc_pgtable_page(struct mk_ident_pgtable *pgt)
{
	unsigned long *page;

	if (pgt->next_page >= MK_IDENT_PGTABLE_PAGES)
		return NULL;

	if (!pgt->instance)
		return NULL;

	page = mk_instance_alloc(pgt->instance, PAGE_SIZE, PAGE_SIZE);
	if (page) {
		memset(page, 0, PAGE_SIZE);
		pgt->pages[pgt->next_page++] = page;
	}
	return page;
}

static int mk_build_ident_pmd(struct mk_ident_pgtable *pgt, unsigned long *pud,
			      unsigned long start, unsigned long end)
{
	unsigned long addr;
	unsigned long pud_idx, pmd_idx;
	unsigned long *pmd;
	unsigned long pmd_phys;

	for (addr = start; addr < end; addr += PMD_SIZE) {
		pud_idx = (addr >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
		pmd_idx = (addr >> PMD_SHIFT) & (PTRS_PER_PMD - 1);

		if (!(pud[pud_idx] & _PAGE_PRESENT)) {
			pmd = mk_alloc_pgtable_page(pgt);
			if (!pmd)
				return -ENOMEM;
			pmd_phys = __pa(pmd);
			pud[pud_idx] = pmd_phys | _KERNPG_TABLE;
		}

		pmd_phys = pud[pud_idx] & PTE_PFN_MASK;
		pmd = __va(pmd_phys);

		pmd[pmd_idx] = addr | __PAGE_KERNEL_LARGE_EXEC;
	}

	return 0;
}

static int mk_build_ident_pud(struct mk_ident_pgtable *pgt, unsigned long *p4d,
			      unsigned long start, unsigned long end)
{
	unsigned long addr;
	unsigned long p4d_idx;
	unsigned long *pud;
	unsigned long pud_phys;
	int ret;

	for (addr = start; addr < end; addr = round_down(addr + PUD_SIZE, PUD_SIZE)) {
		unsigned long chunk_end = min(end, round_down(addr + PUD_SIZE, PUD_SIZE));

		p4d_idx = (addr >> P4D_SHIFT) & (PTRS_PER_P4D - 1);

		if (!(p4d[p4d_idx] & _PAGE_PRESENT)) {
			pud = mk_alloc_pgtable_page(pgt);
			if (!pud)
				return -ENOMEM;
			pud_phys = __pa(pud);
			p4d[p4d_idx] = pud_phys | _KERNPG_TABLE;
		}

		pud_phys = p4d[p4d_idx] & PTE_PFN_MASK;
		pud = __va(pud_phys);

		ret = mk_build_ident_pmd(pgt, pud, addr, chunk_end);
		if (ret)
			return ret;
	}

	return 0;
}

static int mk_build_ident_p4d(struct mk_ident_pgtable *pgt, unsigned long *pgd,
			      unsigned long start, unsigned long end)
{
	unsigned long addr;
	unsigned long pgd_idx;
	unsigned long *p4d;
	unsigned long p4d_phys;
	int ret;

	start = round_down(start, PMD_SIZE);
	end = round_up(end, PMD_SIZE);

	if (pgtable_l5_enabled()) {
		for (addr = start; addr < end; addr = round_down(addr + P4D_SIZE, P4D_SIZE)) {
			unsigned long chunk_end = min(end, round_down(addr + P4D_SIZE, P4D_SIZE));

			pgd_idx = (addr >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1);

			if (!(pgd[pgd_idx] & _PAGE_PRESENT)) {
				p4d = mk_alloc_pgtable_page(pgt);
				if (!p4d)
					return -ENOMEM;
				p4d_phys = __pa(p4d);
				pgd[pgd_idx] = p4d_phys | _KERNPG_TABLE;
			}

			p4d_phys = pgd[pgd_idx] & PTE_PFN_MASK;
			p4d = __va(p4d_phys);

			ret = mk_build_ident_pud(pgt, p4d, addr, chunk_end);
			if (ret)
				return ret;
		}
	} else {
		/* 4-level paging: PGD is effectively P4D */
		ret = mk_build_ident_pud(pgt, pgd, start, end);
		if (ret)
			return ret;
	}

	return 0;
}

struct mk_ident_pgtable *mk_build_identity_pgtable(struct mk_instance *instance,
						    unsigned long start,
						    unsigned long end)
{
	struct mk_ident_pgtable *pgt;
	unsigned long *pgd;
	int ret;

	pgt = kzalloc(sizeof(*pgt), GFP_KERNEL);
	if (!pgt)
		return ERR_PTR(-ENOMEM);

	pgt->instance = instance;

	pgd = mk_alloc_pgtable_page(pgt);
	if (!pgd) {
		kfree(pgt);
		return ERR_PTR(-ENOMEM);
	}

	pgt->pgd_phys = virt_to_phys(pgd);

	ret = mk_build_ident_p4d(pgt, pgd, start, end);
	if (ret) {
		mk_free_identity_pgtable(pgt);
		return ERR_PTR(ret);
	}
	return pgt;
}

static int mk_add_trampoline_mapping(struct mk_ident_pgtable *pgt,
				     unsigned long virt, unsigned long phys)
{
	unsigned long *pgd = __va(pgt->pgd_phys);
	unsigned long pgd_idx, p4d_idx, pud_idx, pmd_idx;
	unsigned long *p4d, *pud, *pmd;
	unsigned long p4d_phys, pud_phys, pmd_phys;

	pgd_idx = (virt >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1);
	p4d_idx = (virt >> P4D_SHIFT) & (PTRS_PER_P4D - 1);
	pud_idx = (virt >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
	pmd_idx = (virt >> PMD_SHIFT) & (PTRS_PER_PMD - 1);

	if (pgtable_l5_enabled()) {
		if (!(pgd[pgd_idx] & _PAGE_PRESENT)) {
			p4d = mk_alloc_pgtable_page(pgt);
			if (!p4d)
				return -ENOMEM;
			p4d_phys = __pa(p4d);
			pgd[pgd_idx] = p4d_phys | _KERNPG_TABLE;
		}
		p4d_phys = pgd[pgd_idx] & PTE_PFN_MASK;
		p4d = __va(p4d_phys);

		if (!(p4d[p4d_idx] & _PAGE_PRESENT)) {
			pud = mk_alloc_pgtable_page(pgt);
			if (!pud)
				return -ENOMEM;
			pud_phys = __pa(pud);
			p4d[p4d_idx] = pud_phys | _KERNPG_TABLE;
		}
		pud_phys = p4d[p4d_idx] & PTE_PFN_MASK;
		pud = __va(pud_phys);
	} else {
		/* 4-level paging: PGD points directly to PUD */
		if (!(pgd[pgd_idx] & _PAGE_PRESENT)) {
			pud = mk_alloc_pgtable_page(pgt);
			if (!pud)
				return -ENOMEM;
			pud_phys = __pa(pud);
			pgd[pgd_idx] = pud_phys | _KERNPG_TABLE;
		}
		pud_phys = pgd[pgd_idx] & PTE_PFN_MASK;
		pud = __va(pud_phys);
	}

	if (!(pud[pud_idx] & _PAGE_PRESENT)) {
		pmd = mk_alloc_pgtable_page(pgt);
		if (!pmd)
			return -ENOMEM;
		pmd_phys = __pa(pmd);
		pud[pud_idx] = pmd_phys | _KERNPG_TABLE;
	}
	pmd_phys = pud[pud_idx] & PTE_PFN_MASK;
	pmd = __va(pmd_phys);

	pmd[pmd_idx] = (phys & PMD_MASK) | __PAGE_KERNEL_LARGE_EXEC;
	return 0;
}

static size_t mk_get_trampoline_size(void)
{
	return multikernel_relocate_kernel_end - multikernel_relocate_kernel_start;
}

static void *mk_get_trampoline_code(void)
{
	return multikernel_relocate_kernel_start;
}

void *mk_setup_trampoline(struct mk_instance *instance,
			  struct mk_ident_pgtable *pgt,
			  unsigned long *phys_out)
{
	void *trampoline_va;
	unsigned long trampoline_phys;
	int rc;

	trampoline_va = mk_instance_alloc(instance, PAGE_SIZE, PAGE_SIZE);
	if (!trampoline_va)
		return ERR_PTR(-ENOMEM);

	trampoline_phys = virt_to_phys(trampoline_va);

	memcpy(trampoline_va, mk_get_trampoline_code(), mk_get_trampoline_size());

	rc = set_memory_x((unsigned long)trampoline_va, 1);
	if (rc) {
		mk_instance_free(instance, trampoline_va, PAGE_SIZE);
		return ERR_PTR(rc);
	}

	rc = mk_add_trampoline_mapping(pgt, (unsigned long)trampoline_va,
				       trampoline_phys);
	if (rc) {
		mk_instance_free(instance, trampoline_va, PAGE_SIZE);
		return ERR_PTR(rc);
	}

	*phys_out = trampoline_phys;
	return trampoline_va;
}

void mk_free_identity_pgtable(struct mk_ident_pgtable *pgt)
{
	int i;

	if (!pgt)
		return;

	for (i = 0; i < pgt->next_page; i++) {
		if (pgt->pages[i])
			mk_instance_free(pgt->instance, pgt->pages[i], PAGE_SIZE);
	}

	kfree(pgt);
}

/*
 * Free only the tracking struct, not the page table pages.
 * Used on success when the spawn kernel needs the pages for the CR3 switch.
 * The pages will be reclaimed when the instance is destroyed.
 */
void mk_free_identity_pgtable_struct(struct mk_ident_pgtable *pgt)
{
	kfree(pgt);
}

unsigned long mk_get_identity_cr3(struct mk_ident_pgtable *pgt)
{
	return pgt ? pgt->pgd_phys : 0;
}

struct mk_restore_params {
	unsigned long cr3;
	unsigned long gs_base;
	unsigned long stack;
	unsigned long entry;
};

static void __noreturn __naked mk_restore_handler(void *info)
{
	asm volatile (
		"movq (%%rdi), %%rax\n\t"       /* cr3 = params->cr3 */
		"movq %%rax, %%cr3\n\t"
		"movl $0xc0000101, %%ecx\n\t"   /* MSR_GS_BASE */
		"movq 8(%%rdi), %%rax\n\t"      /* gs_base = params->gs_base */
		"movq %%rax, %%rdx\n\t"
		"shrq $32, %%rdx\n\t"
		"wrmsr\n\t"
		"movq 16(%%rdi), %%rsp\n\t"     /* stack = params->stack */
		"movq 24(%%rdi), %%rax\n\t"     /* entry = params->entry */
		ANNOTATE_RETPOLINE_SAFE "\n\t"
		"jmpq *%%rax\n\t"
		:
		:
		: "memory"
	);
	unreachable();
}

int multikernel_restore_ap(unsigned int cpu, unsigned long cr3,
			   unsigned long gs_base, unsigned long stack,
			   unsigned long entry)
{
	struct mk_restore_params params = {
		.cr3 = cr3,
		.gs_base = gs_base,
		.stack = stack,
		.entry = entry,
	};

	return smp_call_function_single(cpu, mk_restore_handler, &params, 0);
}
EXPORT_SYMBOL_GPL(multikernel_restore_ap);
