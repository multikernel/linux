// SPDX-License-Identifier: GPL-2.0-only
/*
 * Starting spawn kernels on parked CPUs
 *
 * Every CPU a kernel does not run on waits in its park table cell (see
 * park.c). The host boots an instance by sending the instance's boot
 * CPU into the trampoline, which switches to the instance's identity
 * page table and jumps to its kernel. The spawn kernel then starts its
 * secondaries from their cells the same way, through its own copy of
 * the trampoline.
 *
 * Copyright (C) 2026 Multikernel Technologies, Inc.
 */

#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/iopoll.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/mm.h>
#include <linux/mem_encrypt.h>
#include <linux/io.h>
#include <linux/kexec.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/multikernel.h>
#include <linux/percpu.h>
#include <linux/set_memory.h>
#include <linux/sched.h>

#include <asm/apic.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/tlbflush.h>
#include <asm/msr.h>
#include <asm/special_insns.h>
#include <asm/irqflags.h>
#include <asm/processor-flags.h>
#include <asm/processor.h>
#include <asm/tsc.h>
#include <asm/apic.h>
#include <asm/bootparam.h>
#include <asm/reboot.h>
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

/* Set in spawn kernels: the context this kernel booted from */
static struct mk_spawn_context *mk_boot_context;

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


struct mk_spawn_context *mk_alloc_spawn_context(struct mk_instance *instance,
						phys_addr_t *phys_out)
{
	struct mk_spawn_context *ctx;

	ctx = mk_instance_ctrl_alloc(instance, sizeof(*ctx), PAGE_SIZE);
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	/* The spawn checks this against where it found the context */
	ctx->self_phys = virt_to_phys(ctx);

	/* Tell the spawn kernel which memory it must leave alone */
	ctx->ctrl_phys = instance->ctrl_phys;
	ctx->ctrl_size = MK_CTRL_BLOCK_SIZE;

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
			  unsigned long park_table)
{
	ctx->identity_cr3 = identity_cr3;
	ctx->kernel_entry = kernel_entry;
	/* Where the instance's kernel parks its CPUs and finds them */
	ctx->park_table = park_table;
}

/* The CPUs started for an instance and not seen parked since */
static struct mk_cpu_set *mk_started_set(struct mk_instance *instance)
{
	if (!instance->cpus_started)
		instance->cpus_started = mk_cpu_set_alloc();

	return instance->cpus_started;
}

/*
 * Boot the instance on @cpu, which waits in its park cell like every
 * CPU the instance owns. The instance's kernel starts the others from
 * their cells without telling the host, so all of them count as started
 * from here on and have to be seen parked before the image is reused.
 */
int mk_spawn_cpu(struct mk_instance *instance, int cpu,
		 struct mk_spawn_context *ctx)
{
	struct mk_cpu_set *started = mk_started_set(instance);
	u32 apic_id = per_cpu(x86_cpu_to_apicid, cpu);
	const u64 args[] = {
		ctx->identity_cr3,
		virt_to_phys(&ctx->bp),
		ctx->kernel_entry,
		virt_to_phys(instance->arch.trampoline_va),
	};
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret;

	/* Make the adds below infallible before anything runs */
	if (!started)
		return -ENOMEM;
	ret = mk_cpu_set_reserve(started, mk_cpu_set_count(instance->cpus));
	if (ret)
		return ret;

	guard(mutex)(&mk_park_lock);

	ret = mk_park_dispatch(apic_id, MK_PARK_CMD_BOOT, args, ARRAY_SIZE(args));
	if (ret)
		return ret;

	mk_cpu_set_for_each(i, phys_cpu, instance->cpus)
		mk_cpu_set_add(started, phys_cpu);
	return 0;
}

/**
 * mk_arch_spawn_instance - Build boot state and start an instance's boot CPU
 * @image: Loaded kimage for the instance
 * @instance: Instance being spawned
 * @cpu: Logical CPU, currently parked in the pool, to boot the instance on
 *
 * Builds or reuses the identity page tables, trampoline and spawn
 * context, stamps in the boot parameters the loader prepared, and
 * releases the parked CPU into the trampoline.
 *
 * Each resource is stored in the instance as soon as it is built and is
 * never unwound, even when the spawn itself fails: all of them are carved
 * from the instance's control block, which only ever grows, and a partial
 * spawn may already have released its boot CPU into the trampoline, so
 * tearing it down would free memory a CPU is executing. A retry picks up exactly
 * where this attempt stopped; everything is returned to the pool together
 * when the instance's memory is torn down.
 */
int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance,
			   int cpu)
{
	phys_addr_t code_phys = mk_park_code_phys();
	struct boot_params *src_bp;
	int ret;

	if (!code_phys)
		return -ENODEV;

	if (!instance->arch.ident_pgt) {
		struct mk_ident_pgtable *pgt;
		struct mk_memory_region *region;

		pgt = mk_build_identity_pgtable(instance);
		if (IS_ERR(pgt)) {
			pr_err("Failed to build identity page table: %ld\n",
			       PTR_ERR(pgt));
			return PTR_ERR(pgt);
		}

		list_for_each_entry(region, &instance->memory_regions, list) {
			ret = mk_ident_map_range(pgt, region->res.start,
						 region->res.end + 1);
			if (ret) {
				mk_free_identity_pgtable(pgt);
				return ret;
			}
		}
		instance->arch.ident_pgt = pgt;
	}

	if (!instance->arch.trampoline_va) {
		unsigned long phys;
		void *va;

		va = mk_setup_trampoline(instance, instance->arch.ident_pgt, &phys);
		if (IS_ERR(va)) {
			pr_err("Failed to set up trampoline: %ld\n",
			       PTR_ERR(va));
			return PTR_ERR(va);
		}
		instance->arch.trampoline_va = va;
	}

	/*
	 * The boot CPU leaves its park cell on this page table, so it must
	 * map the park code. Every exec, as the table may have been rebuilt.
	 */
	ret = mk_add_trampoline_mapping(instance->arch.ident_pgt, code_phys,
					code_phys);
	if (ret)
		return ret;

	if (!instance->arch.spawn_ctx) {
		struct mk_spawn_context *ctx;
		phys_addr_t phys;

		ctx = mk_alloc_spawn_context(instance, &phys);
		if (!ctx) {
			pr_err("Failed to allocate spawn context\n");
			return -ENOMEM;
		}
		instance->arch.spawn_ctx = ctx;
		instance->arch.spawn_ctx_phys = phys;
	}

	/* Copy the boot_params the loader prepared into the spawn context */
	src_bp = memremap(image->arch.mk_boot_params,
			  sizeof(struct boot_params), MEMREMAP_WB);
	if (!src_bp) {
		pr_err("Failed to map boot_params at 0x%lx\n",
		       image->arch.mk_boot_params);
		return -ENOMEM;
	}
	memcpy(mk_spawn_context_boot_params(instance->arch.spawn_ctx), src_bp,
	       sizeof(struct boot_params));
	memunmap(src_bp);

	/*
	 * The loader's E820 reflects the grant at load time; regions added
	 * or removed since then only exist in the live region list, which
	 * the manifest is also rebuilt from on every exec. Rebuild the map
	 * too, or the spawn boots with the memory it owned at load and the
	 * difference silently vanishes.
	 */
	ret = mk_e820_fill(instance,
			   mk_spawn_context_boot_params(instance->arch.spawn_ctx));
	if (ret)
		return ret;

	mk_set_spawn_context(instance->arch.spawn_ctx,
			     mk_get_identity_cr3(instance->arch.ident_pgt),
			     image->arch.mk_kernel_entry,
			     mk_park_table_phys());
	instance->arch.spawn_ctx->boot_lps = cpu_data(cpu).loops_per_jiffy;
	if (!instance->arch.spawn_ctx->boot_lps)
		instance->arch.spawn_ctx->boot_lps = loops_per_jiffy;
	instance->arch.spawn_ctx->boot_lps *= HZ;
	instance->arch.spawn_ctx->boot_cpu_khz = cpu_khz;
	instance->arch.spawn_ctx->boot_tsc_khz = tsc_khz;
	instance->arch.spawn_ctx->boot_apic_hz =
		(unsigned long)lapic_timer_period * HZ;

	return mk_spawn_cpu(instance, cpu, instance->arch.spawn_ctx);
}

/**
 * mk_arch_release_instance - Free an instance's spawn resources
 * @instance: Instance being torn down
 *
 * Waits for every CPU the instance started to park, then frees the
 * identity page tables. The trampoline and spawn context are carved
 * from the instance's control block, which the caller returns to the
 * pool as one allocation; only the pointers are cleared here.
 *
 * Fails without releasing anything if a CPU never parked: it may still
 * run the instance's kernel, so the caller must keep its memory alive.
 */
int mk_arch_release_instance(struct mk_instance *instance)
{
	int ret;

	ret = mk_repark_instance_to_host(instance);
	if (ret) {
		char buf[256];

		mk_cpu_set_format(buf, sizeof(buf), instance->cpus_started);
		pr_err("Instance %d (%s): CPUs %s never parked, keeping spawn resources\n",
		       instance->id, instance->name, buf);
		return ret;
	}

	mk_cpu_set_free(instance->cpus_started);
	instance->cpus_started = NULL;

	mk_free_identity_pgtable(instance->arch.ident_pgt);
	instance->arch.ident_pgt = NULL;
	instance->arch.trampoline_va = NULL;
	instance->arch.spawn_ctx = NULL;
	instance->arch.spawn_ctx_phys = 0;
	return 0;
}

/**
 * mk_repark_cpu_to_instance - Hand one parked pool CPU to a live instance
 * @instance: Running instance the CPU is being hot-added to
 * @phys_cpu: Physical (APIC) ID of the CPU
 *
 * The CPU stays in its cell, where the instance's kernel starts it; the
 * host only starts counting it among the CPUs that kernel may run on.
 */
int mk_repark_cpu_to_instance(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	struct mk_cpu_set *started = mk_started_set(instance);

	if (!started)
		return -ENOMEM;

	guard(mutex)(&mk_park_lock);

	return mk_cpu_set_add(started, phys_cpu);
}

/**
 * mk_repark_cpu_to_host - Take one CPU back from an instance
 * @instance: Instance the CPU was removed from
 * @phys_cpu: Physical (APIC) ID of the CPU
 *
 * The instance's kernel reports the CPU offline before the CPU reaches
 * its cell; until it has, it stays accounted to the instance.
 */
int mk_repark_cpu_to_host(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	int ret;

	guard(mutex)(&mk_park_lock);

	if (!mk_cpu_set_contains(instance->cpus_started, phys_cpu))
		return 0;

	ret = mk_park_wait((u32)phys_cpu);
	if (!ret)
		mk_cpu_set_del(instance->cpus_started, phys_cpu);
	return ret;
}

/* 0 once @phys_cpu waits in its cell, whichever kernel parked it */
int mk_arch_confirm_parked(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	return mk_park_wait((u32)phys_cpu);
}

/**
 * mk_repark_instance_to_host - See every CPU an instance started parked
 * @instance: Instance being torn down
 *
 * A CPU that does not park stays tracked, and the caller must not free
 * the instance's memory.
 */
int mk_repark_instance_to_host(struct mk_instance *instance)
{
	struct mk_cpu_set *started = instance->cpus_started;
	unsigned int i;
	int failed = 0;

	if (mk_cpu_set_empty(started))
		return 0;

	guard(mutex)(&mk_park_lock);

	/* Back to front, so deleting never shifts entries yet to be visited */
	for (i = mk_cpu_set_count(started); i-- > 0; ) {
		mk_phys_cpu_t phys_cpu = started->ids[i];

		if (mk_park_wait((u32)phys_cpu))
			failed++;
		else
			mk_cpu_set_del(started, phys_cpu);
	}

	return failed ? -ETIMEDOUT : 0;
}

/**
 * mk_arch_register_cpu - Enumerate a pool CPU in this kernel's topology
 * @phys_id: Physical (APIC) ID of the CPU
 *
 * Called during early SMP configuration for every CPU this kernel may
 * ever own, including pool CPUs it does not own yet: the topology code
 * rejects APIC IDs it did not see during enumeration, so a CPU that is
 * not registered here can never be hot-added later.
 */
void __init mk_arch_register_cpu(u64 phys_id)
{
	topology_register_apic((u32)phys_id, CPU_ACPIID_INVALID, true);
}

/* The direct map starts at physical 0, so it already reaches any RAM */
void __init mk_arch_register_ram(phys_addr_t start, u64 size)
{
}

/*
 * Initialize boot context tracking in spawn kernel.
 * Called early during spawn kernel boot.
 */
void mk_init_boot_context(phys_addr_t ctx_phys)
{
	struct mk_spawn_context *ctx;

	if (!ctx_phys) {
		pr_err("mk_spawn: Boot context physical address is 0!\n");
		return;
	}

	/*
	 * The spawn context is in the multikernel pool which is regular RAM,
	 * already covered by the direct map. Use __va() instead of memremap().
	 */
	ctx = __va(ctx_phys);

	/*
	 * We located the context by subtracting our own offsetof(bp) from
	 * the boot_params pointer, so a layout difference from the host
	 * lands us at the wrong address. The host stamps the context with
	 * its own physical address; if that does not match, every other
	 * field we would read is garbage too. Booting anyway appears to
	 * work and then fails much later, when this kernel shuts down and
	 * its CPUs park on nonsense addresses.
	 */
	if (ctx->self_phys != ctx_phys) {
		pr_err("mk_spawn: Boot context at %pa is stamped %pa\n",
		       &ctx_phys, &ctx->self_phys);
		pr_err("mk_spawn: Spawn context layout mismatch - host and spawn kernels must be built from the same source\n");
		return;
	}

	mk_boot_context = ctx;
	/*
	 * A spawn kernel cannot calibrate against legacy timers because they
	 * belong to the host. Reuse the selected physical CPU's delay and local
	 * APIC timer calibration, while keeping explicit command-line values
	 * authoritative.
	 */
	if (!preset_lpj && ctx->boot_lps)
		preset_lpj = DIV_ROUND_CLOSEST_ULL(ctx->boot_lps, HZ);
	if (!lapic_timer_period && ctx->boot_apic_hz)
		lapic_timer_period =
			DIV_ROUND_CLOSEST_ULL(ctx->boot_apic_hz, HZ);

	mk_park_table_set_boot(ctx->park_table);

	/*
	 * The host's control area (this context, the host's boot trampoline,
	 * the identity page tables) sits in our memory and is handed to us
	 * as ordinary RAM. Keep the page allocator away from it: the next
	 * spawn of this instance boots from it.
	 */
	if (ctx->ctrl_phys && ctx->ctrl_size &&
	    memblock_reserve(ctx->ctrl_phys, ctx->ctrl_size))
		pr_err("mk_spawn: failed to reserve control area %pa (%lu bytes)\n",
		       &ctx->ctrl_phys, ctx->ctrl_size);
}

/*
 * The trampoline this kernel starts its secondaries through, in a page
 * of its own memory that no other kernel writes. The page an instance's
 * parent booted it through stays the parent's.
 */
static phys_addr_t mk_trampoline_phys;

static int __init mk_prepare_trampoline(void)
{
	unsigned long page;
	int ret;

	if (!mk_boot_context)
		return 0;

	page = __get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	memcpy((void *)page, multikernel_relocate_kernel_start,
	       multikernel_relocate_kernel_end - multikernel_relocate_kernel_start);

	ret = set_memory_rox(page, 1);
	if (ret) {
		free_page(page);
		return ret;
	}

	mk_trampoline_phys = __pa(page);
	return 0;
}
early_initcall(mk_prepare_trampoline);

/*
 * Add a 2MB executable mapping to a page table.
 * Allocates P4D/PUD/PMD levels as needed, reusing existing entries if present.
 * Handles both 4-level and 5-level paging.
 */
static int mk_add_2mb_mapping(pgd_t *pgd, unsigned long virt, unsigned long phys,
			      pteval_t prot)
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

	pmd[pmd_idx] = __pmd((phys & PMD_MASK) | prot);
	return 0;
}

/*
 * The identity page table a parked CPU switches to on its way into this
 * kernel: it leaves its cell from the park code page and continues in
 * the trampoline, both at their physical addresses.
 */
static int mk_build_trampoline_pgtable(unsigned long trampoline_phys,
				       unsigned long *cr3_out)
{
	phys_addr_t code_phys = mk_park_code_phys();
	pgd_t *pgd;
	int ret;

	if (!code_phys)
		return -ENODEV;

	pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL);
	if (!pgd)
		return -ENOMEM;

	ret = mk_add_2mb_mapping(pgd, code_phys, code_phys,
				 __PAGE_KERNEL_LARGE_EXEC);
	if (!ret)
		ret = mk_add_2mb_mapping(pgd, trampoline_phys, trampoline_phys,
					 __PAGE_KERNEL_LARGE_EXEC);
	if (ret)
		return ret;

	*cr3_out = __pa(pgd);
	return 0;
}

/* Start a CPU waiting in its park cell as a secondary of this spawn kernel */
int multikernel_wakeup_secondary_cpu_64(u32 apicid, unsigned long start_eip,
					unsigned int cpu)
{
	unsigned long trampoline_phys = mk_trampoline_phys, identity_cr3;
	u64 args[6];
	int ret;

	if (!trampoline_phys) {
		pr_err("mk_spawn: no trampoline to start CPU %u with\n", cpu);
		return -ENODEV;
	}

	ret = mk_build_trampoline_pgtable(trampoline_phys, &identity_cr3);
	if (ret)
		return ret;

	/*
	 * The trampoline switches to init_mm's page table while still
	 * running at its physical address, so map it there too, in init_mm
	 * rather than the current CR3: this runs in the cpuhp kthread,
	 * which may be borrowing a user mm (lazy TLB). The mapping stays,
	 * so it must not be writable and executable at once.
	 */
	ret = mk_add_2mb_mapping(init_mm.pgd, trampoline_phys, trampoline_phys,
				 __PAGE_KERNEL_LARGE_EXEC & ~_PAGE_RW);
	if (ret)
		return ret;

	args[0] = identity_cr3;
	args[1] = (unsigned long)multikernel_secondary_startup;
	args[2] = per_cpu_offset(cpu);
	args[3] = (unsigned long)idle_task(cpu)->thread.sp;
	args[4] = trampoline_phys +
		  (mk_secondary_trampoline - multikernel_relocate_kernel_start);
	args[5] = __sme_pa(init_mm.pgd);

	return mk_park_dispatch(apicid, MK_PARK_CMD_SECONDARY, args,
				ARRAY_SIZE(args));
}

struct mk_ident_pgtable {
	unsigned long *pages[MK_CTRL_PGTABLE_PAGES];
	int next_page;
	unsigned long pgd_phys;
	struct mk_instance *instance;
	/* Pages carved from memory the owner frees as a whole */
	void *arena;
	int arena_pages;
};

void mk_free_identity_pgtable(struct mk_ident_pgtable *pgt);

static unsigned long *mk_alloc_pgtable_page(struct mk_ident_pgtable *pgt)
{
	unsigned long *page;

	if (pgt->next_page >= MK_CTRL_PGTABLE_PAGES)
		return NULL;

	if (pgt->arena)
		page = pgt->next_page < pgt->arena_pages ?
		       pgt->arena + pgt->next_page * PAGE_SIZE : NULL;
	else
		page = mk_instance_ctrl_alloc(pgt->instance, PAGE_SIZE, PAGE_SIZE);

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

int mk_ident_map_range(struct mk_ident_pgtable *pgt, unsigned long start,
		       unsigned long end)
{
	return mk_build_ident_p4d(pgt, __va(pgt->pgd_phys), start, end);
}

static struct mk_ident_pgtable *mk_build_pgtable(struct mk_instance *instance,
						 void *arena, int arena_pages)
{
	struct mk_ident_pgtable *pgt;
	unsigned long *pgd;

	pgt = kzalloc(sizeof(*pgt), GFP_KERNEL);
	if (!pgt)
		return ERR_PTR(-ENOMEM);

	pgt->instance = instance;
	pgt->arena = arena;
	pgt->arena_pages = arena_pages;

	pgd = mk_alloc_pgtable_page(pgt);
	if (!pgd) {
		kfree(pgt);
		return ERR_PTR(-ENOMEM);
	}

	pgt->pgd_phys = virt_to_phys(pgd);
	return pgt;
}

struct mk_ident_pgtable *mk_build_identity_pgtable(struct mk_instance *instance)
{
	return mk_build_pgtable(instance, NULL, 0);
}

/* A page table whose pages all come from @arena, freed by its owner */
struct mk_ident_pgtable *mk_build_arena_pgtable(void *arena, int pages)
{
	return mk_build_pgtable(NULL, arena, pages);
}

int mk_add_trampoline_mapping(struct mk_ident_pgtable *pgt,
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

/*
 * Direct map base used by kernels that do not randomize memory layout.
 * Spawn kernels never receive KASLR_FLAG (the vmlinux boot path does not
 * set it), so this is where their direct map always sits, regardless of
 * their CONFIG_RANDOMIZE_MEMORY setting.
 */
unsigned long mk_default_page_offset(void)
{
	return pgtable_l5_enabled() ? __PAGE_OFFSET_BASE_L5 :
				      __PAGE_OFFSET_BASE_L4;
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

	trampoline_va = mk_instance_ctrl_alloc(instance, PAGE_SIZE, PAGE_SIZE);
	if (!trampoline_va)
		return ERR_PTR(-ENOMEM);

	trampoline_phys = virt_to_phys(trampoline_va);

	memcpy(trampoline_va, mk_get_trampoline_code(), mk_get_trampoline_size());

	rc = set_memory_x((unsigned long)trampoline_va, 1);
	if (rc)
		return ERR_PTR(rc);

	rc = mk_add_trampoline_mapping(pgt, (unsigned long)trampoline_va,
				       trampoline_phys);
	if (rc)
		return ERR_PTR(rc);

	/*
	 * On re-spawn, the CPU entering this trampoline is parked in the
	 * previously shut down spawn kernel and fetches through that kernel's
	 * direct map, which sits at the default base while ours may be
	 * randomized (CONFIG_RANDOMIZE_MEMORY). Map the default-base address
	 * too so those fetches survive the CR3 switch to this page table.
	 */
	rc = mk_add_trampoline_mapping(pgt,
				       mk_default_page_offset() + trampoline_phys,
				       trampoline_phys);
	if (rc)
		return ERR_PTR(rc);

	*phys_out = trampoline_phys;
	return trampoline_va;
}

int mk_arch_pool_map(phys_addr_t start, size_t size)
{
	init_memory_mapping(start, start + size, PAGE_KERNEL);
	return 0;
}

void mk_arch_pool_unmap(phys_addr_t start, size_t size)
{
	kernel_physical_mapping_remove(start, start + size);
}

int mk_arch_pool_chunk_added(phys_addr_t start, size_t size)
{
	if (!mk_pool)
		return -ENODEV;

	guard(mutex)(&mk_park_lock);

	/*
	 * A pool emptied of memory has no park table, so the chunk that
	 * refills it has to bring one back: a CPU handed to a pool with
	 * nowhere to park would halt permanently.
	 */
	return mk_park_table_create();
}

/**
 * mk_pool_park_setup() - Set up pool parking
 *
 * Called when the baseline is applied, once the memory pool exists.
 * Builds the park table in pool memory, unless this kernel inherited
 * one from the kernel that spawned it.
 */
int mk_pool_park_setup(void)
{
	if (!mk_pool)
		return -ENODEV;

	guard(mutex)(&mk_park_lock);

	if (!mk_park_table_phys() && mk_pool_empty())
		return -ENODEV;

	return mk_park_table_create();
}

/* The park table, which no later kernel may hand out, as base,size pairs */
int mk_pool_park_regions(u64 *pairs, int max)
{
	guard(mutex)(&mk_park_lock);

	return mk_park_table_regions(pairs, max);
}

/* Does the park table live in this range? */
bool mk_pool_park_uses(phys_addr_t start, size_t size)
{
	guard(mutex)(&mk_park_lock);

	return mk_park_table_uses(start, size);
}

/**
 * mk_pool_park_teardown() - Return the park table to the pool
 *
 * The table is pool memory, so the chunk holding it cannot be removed
 * while it exists, and it may only go while no CPU waits in it. The
 * next baseline builds it again, possibly elsewhere.
 *
 * Returns 0 if there was nothing to tear down, -EBUSY if a CPU may still
 * be parked.
 */
int mk_pool_park_teardown(void)
{
	if (!mk_pool)
		return 0;

	guard(mutex)(&mk_park_lock);

	if (!mk_pool_cpus_returned())
		return -EBUSY;

	return mk_park_table_destroy();
}

/* The pages live in an instance's control block or an arena, freed with it */
void mk_free_identity_pgtable(struct mk_ident_pgtable *pgt)
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

/*
 * halt/poweroff/reboot in a spawn kernel must not go through the native
 * machine ops: native_machine_halt() disables the local APICs, which
 * makes the CPUs unreachable for re-spawn, and native_machine_restart()
 * pokes the platform reset hardware, which would reset the entire
 * machine including the host. Park every CPU in the pool wait loop
 * instead, returning them to the multikernel pool.
 */
static void __noreturn mk_machine_halt(void)
{
	mk_halt_to_pool();
}

static void __noreturn mk_machine_restart(char *cmd)
{
	mk_machine_halt();
}

/*
 * stop_this_cpu() is where REBOOT_VECTOR, the smp_stop NMI and panic's
 * smp_send_stop() put a CPU on the way down. Its native tail marks the
 * CPU offline and dead-halts it inside this kernel's image: from then
 * on even the host's force-halt NMI is discarded on entry, the CPU is
 * unreachable, and the instance can never be re-spawned. Park instead.
 */
static void __noreturn mk_stop_this_cpu(void)
{
	mk_enter_pool_state(NULL);
}

static int __init mk_spawn_reboot_init(void)
{
	if (!mk_boot_context)
		return 0;

	machine_ops.halt = mk_machine_halt;
	machine_ops.power_off = mk_machine_halt;
	machine_ops.restart = mk_machine_restart;
	machine_ops.emergency_restart = mk_machine_halt;
	smp_ops.stop_this_cpu = mk_stop_this_cpu;

	/*
	 * A panicked spawn kernel spinning in the panic loop holds its
	 * CPUs hostage. "Reboot on panic" is mk_machine_halt here, which
	 * notifies the host and parks, so make it the default; the panic
	 * output has already been flushed to the console by then.
	 */
	if (!panic_timeout)
		panic_timeout = -1;
	return 0;
}
core_initcall(mk_spawn_reboot_init);
