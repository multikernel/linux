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
static phys_addr_t mk_boot_context_phys;

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
static bool spawn_trampoline_prepared;
static bool spawn_pool_park_prepared;
static bool spawn_park_ready;
static int spawn_park_error;

bool mk_arch_park_ready(void)
{
	/* Pair with publication after both executable park mappings succeed. */
	return smp_load_acquire(&spawn_park_ready);
}

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

/* Pool park loop: park_cr3, slot_phys, apic_id, park_phys, mwait_usable */
typedef void (*mk_pool_park_fn)(unsigned long park_cr3, unsigned long slot_phys,
				unsigned long apic_id, unsigned long park_phys,
				unsigned long mwait_usable);

/*
 * Host pool park area, set up when the baseline is applied. Unassigned
 * pool CPUs park here watching the host slot; once an instance first
 * spawns, its CPUs are re-parked onto the instance's own context so the
 * spawn kernel can wake secondaries by writing memory it can address.
 * The page table identity-maps the whole pool, so park pages and
 * contexts of every instance are reachable from it.
 */
static struct {
	struct mk_spawn_context *slot;
	unsigned long slot_phys;
	void *park_va;
	unsigned long park_phys;
	struct mk_ident_pgtable *pgt;
	unsigned long cr3;
} mk_host_park;

/* Nests outside the pool mutex: a growing pool maps itself in here */
static DEFINE_MUTEX(mk_host_park_lock);

struct mk_spawn_context *mk_alloc_spawn_context(struct mk_instance *instance,
						phys_addr_t *phys_out)
{
	struct mk_spawn_context *ctx;

	ctx = mk_instance_ctrl_alloc(instance, sizeof(*ctx), PAGE_SIZE);
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	/* A slot watches itself unless a publication redirects it */
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
			  unsigned long trampoline_virt,
			  unsigned long trampoline_phys,
			  unsigned long park_phys)
{
	ctx->identity_cr3 = identity_cr3;
	ctx->kernel_entry = kernel_entry;
	ctx->trampoline_virt = trampoline_virt;
	ctx->trampoline_phys = trampoline_phys;
	/*
	 * Where the instance's CPUs wait after it shuts down. The park page
	 * and the host's pool-wide page table survive re-loads of this
	 * instance, unlike the kernel image the CPUs came from. The pool
	 * page table (rather than the instance's own) is used so a re-park
	 * can move a CPU between any two park pages in the pool.
	 */
	ctx->park_phys = park_phys;
	ctx->park_cr3 = mk_host_park.cr3;
	ctx->gs_base = 0;
	ctx->stack = 0;
	ctx->flags = 0;
	ctx->ready = 0;
}

/*
 * Serializes wake publications on the host slot and on instance contexts.
 * Every mailbox is single-producer: two concurrent publications interleave
 * their dispatch fields and the parked CPU stages a mix of both. Spawn,
 * hotplug repark and parked-confirmation run from different syscall paths
 * with no common lock, so they take this one.
 */
static DEFINE_MUTEX(mk_park_mutex);

/*
 * Publish a wakeup in @slot for the CPU with @apic_id and wait for the
 * parked CPU to claim it. The dispatch fields must be set before the
 * call; parked CPUs stage them in registers before claiming, so once the
 * claim is observed the slot may be reused. On timeout the publication
 * is revoked; if the CPU claims concurrently, the wakeup proceeds.
 */
static int mk_slot_wake(struct mk_spawn_context *slot, u32 apic_id,
			const char *what)
{
	phys_addr_t slot_phys = virt_to_phys(slot);
	u32 ready;
	int ret;

	slot->target_apic_id = apic_id;
	/* Ensure the publication is visible before setting ready */
	smp_wmb();
	WRITE_ONCE(slot->ready, 1);

	ret = read_poll_timeout(READ_ONCE, ready, !ready, 100, USEC_PER_SEC,
				false, slot->ready);
	if (ret) {
		if (cmpxchg(&slot->ready, 1, 0) == 1)
			pr_err("mk_spawn: %s: CPU (APIC %u) did not claim wakeup on slot %pa - CPU is not parked there\n",
			       what, apic_id, &slot_phys);
		else
			ret = 0;
	}

	return ret;
}

/*
 * Point the instance's secondary CPUs, currently watching the host slot,
 * at the instance's own context, so the spawn kernel can wake them by
 * writing memory inside its own partition.
 */
/* The instance's set of CPUs parked on its own context, allocated on demand */
static struct mk_cpu_set *mk_slot_set(struct mk_instance *instance)
{
	if (!instance->cpus_on_slot)
		instance->cpus_on_slot = mk_cpu_set_alloc();

	return instance->cpus_on_slot;
}

/*
 * Publish a repark in @from, dispatching the CPU with @apic_id to the
 * park area described by @park_phys/@park_cr3, watching @slot_phys there.
 */
static int mk_publish_repark(struct mk_spawn_context *from, u32 apic_id,
			     unsigned long park_phys, unsigned long park_cr3,
			     unsigned long slot_phys, const char *what)
{
	lockdep_assert_held(&mk_park_mutex);

	from->repark_park_phys = park_phys;
	from->repark_park_cr3 = park_cr3;
	from->repark_slot_phys = slot_phys;
	from->flags = MK_SPAWN_F_REPARK;
	return mk_slot_wake(from, apic_id, what);
}

static int mk_repark_to_instance(struct mk_instance *instance,
				 struct mk_spawn_context *ctx, u32 boot_apic_id)
{
	struct mk_spawn_context *slot = mk_host_park.slot;
	struct mk_cpu_set *on_slot = mk_slot_set(instance);
	mk_phys_cpu_t phys_cpu;
	unsigned int i;
	int ret;

	if (!on_slot)
		return -ENOMEM;

	/*
	 * Guarantee the tracking add after each successful wake cannot
	 * fail: a CPU that moved but was not recorded would be woken
	 * through the wrong mailbox forever after.
	 */
	ret = mk_cpu_set_reserve(on_slot, mk_cpu_set_count(instance->cpus));
	if (ret)
		return ret;

	mk_cpu_set_for_each(i, phys_cpu, instance->cpus) {
		if ((u32)phys_cpu == boot_apic_id)
			continue;

		/*
		 * Skip CPUs already watching this context; the rest are on
		 * the host slot, either because the instance has never run
		 * or because they were assigned to it while it was stopped.
		 */
		if (mk_cpu_set_contains(on_slot, phys_cpu))
			continue;

		ret = mk_publish_repark(slot, (u32)phys_cpu, ctx->park_phys,
					ctx->park_cr3, virt_to_phys(ctx),
					"repark to instance");
		if (ret)
			return ret;

		mk_cpu_set_add(on_slot, phys_cpu);
	}

	return 0;
}

int mk_spawn_cpu(struct mk_instance *instance, int cpu,
		 struct mk_spawn_context *ctx)
{
	u32 apic_id = per_cpu(x86_cpu_to_apicid, cpu);
	struct mk_spawn_context *slot = mk_host_park.slot;
	int ret;

	if (!slot) {
		pr_err("mk_spawn: host pool park area not initialized\n");
		return -ENODEV;
	}

	guard(mutex)(&mk_park_mutex);

	/*
	 * Move every secondary still parked on the host slot onto the
	 * instance context, where this instance's kernel wakes them. A
	 * re-spawn can need this too: CPUs assigned while the instance was
	 * stopped are on the host slot even though the ones it already ran
	 * on are not.
	 */
	ret = mk_repark_to_instance(instance, ctx, apic_id);
	if (ret)
		return ret;

	if (mk_cpu_set_contains(instance->cpus_on_slot, apic_id)) {
		/* The boot CPU parked on this context when the instance halted */
		ctx->flags = 0;
		return mk_slot_wake(ctx, apic_id, "re-spawn boot cpu");
	}

	slot->identity_cr3 = ctx->identity_cr3;
	slot->kernel_entry = ctx->kernel_entry;
	slot->trampoline_phys = ctx->trampoline_phys;
	slot->self_phys = virt_to_phys(ctx);
	slot->flags = 0;
	ret = mk_slot_wake(slot, apic_id, "first spawn boot cpu");
	if (!ret) {
		/*
		 * It is running the instance's kernel now, and will park on
		 * that kernel's context when the instance halts. The add
		 * cannot fail: mk_repark_to_instance() reserved room for
		 * every CPU of the instance.
		 */
		mk_cpu_set_add(instance->cpus_on_slot, apic_id);
	}
	return ret;
}

/**
 * mk_arch_spawn_instance - Build boot state and start an instance's boot CPU
 * @image: Loaded kimage for the instance
 * @instance: Instance being spawned
 * @cpu: Logical CPU, currently parked in the pool, to boot the instance on
 *
 * Builds or reuses the identity page tables, trampoline, park page and
 * spawn context, stamps in the boot parameters the loader prepared, and
 * releases the parked CPU into the trampoline.
 *
 * Each resource is stored in the instance as soon as it is built and is
 * never unwound, even when the spawn itself fails: all of them are carved
 * from the instance's control block, which only ever grows, and a partial
 * spawn may already have reparked CPUs onto the new park page, so tearing
 * it down would free memory a CPU is executing. A retry picks up exactly
 * where this attempt stopped; everything is returned to the pool together
 * when the instance's memory is torn down.
 */
int mk_arch_spawn_instance(struct kimage *image, struct mk_instance *instance,
			   int cpu)
{
	struct boot_params *src_bp;
	unsigned long park_phys;
	void *park_va;
	int ret;

	if (!instance->ident_pgt) {
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
		instance->ident_pgt = pgt;
	}

	if (!instance->trampoline_va) {
		unsigned long phys;
		void *va;

		va = mk_setup_trampoline(instance, instance->ident_pgt, &phys);
		if (IS_ERR(va)) {
			pr_err("Failed to set up trampoline: %ld\n",
			       PTR_ERR(va));
			return PTR_ERR(va);
		}
		instance->trampoline_va = va;
	}

	/*
	 * The previous spawn overwrote this page with its own build's
	 * trampoline (mk_prepare_trampoline()). The CPU released below must
	 * run THIS kernel's trampoline, with this kernel's fixes; an old
	 * build's copy can fault on state the fixes handle (CR4.CET vs
	 * CR0.WP), and a fault there lands in the park page's handler and
	 * halts the CPU. Restore our copy on every exec.
	 */
	memcpy(instance->trampoline_va, multikernel_relocate_kernel_start,
	       multikernel_relocate_kernel_end - multikernel_relocate_kernel_start);

	/*
	 * Unconditional: the page itself survives a re-spawn, but the host
	 * park table it must be mapped in may have been rebuilt since.
	 */
	park_va = mk_setup_park_page(instance, &park_phys);
	if (IS_ERR(park_va)) {
		pr_err("Failed to set up pool park page: %ld\n",
		       PTR_ERR(park_va));
		return PTR_ERR(park_va);
	}
	instance->park_va = park_va;

	if (!instance->spawn_ctx) {
		struct mk_spawn_context *ctx;
		phys_addr_t phys;

		ctx = mk_alloc_spawn_context(instance, &phys);
		if (!ctx) {
			pr_err("Failed to allocate spawn context\n");
			return -ENOMEM;
		}
		instance->spawn_ctx = ctx;
		instance->spawn_ctx_phys = phys;
	}

	/* Copy the boot_params the loader prepared into the spawn context */
	src_bp = memremap(image->arch.mk_boot_params,
			  sizeof(struct boot_params), MEMREMAP_WB);
	if (!src_bp) {
		pr_err("Failed to map boot_params at 0x%lx\n",
		       image->arch.mk_boot_params);
		return -ENOMEM;
	}
	memcpy(mk_spawn_context_boot_params(instance->spawn_ctx), src_bp,
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
			   mk_spawn_context_boot_params(instance->spawn_ctx));
	if (ret)
		return ret;

	mk_set_spawn_context(instance->spawn_ctx,
			     mk_get_identity_cr3(instance->ident_pgt),
			     image->arch.mk_kernel_entry,
			     (unsigned long)instance->trampoline_va,
			     virt_to_phys(instance->trampoline_va),
			     park_phys);
	instance->spawn_ctx->boot_lps = cpu_data(cpu).loops_per_jiffy;
	if (!instance->spawn_ctx->boot_lps)
		instance->spawn_ctx->boot_lps = loops_per_jiffy;
	instance->spawn_ctx->boot_lps *= HZ;
	instance->spawn_ctx->boot_cpu_khz = cpu_khz;
	instance->spawn_ctx->boot_tsc_khz = tsc_khz;
	instance->spawn_ctx->boot_apic_hz =
		(unsigned long)lapic_timer_period * HZ;
	instance->spawn_ctx->abi_magic = MK_BOOT_CONTEXT_MAGIC;

	return mk_spawn_cpu(instance, cpu, instance->spawn_ctx);
}

/**
 * mk_arch_release_instance - Free an instance's spawn resources
 * @instance: Instance being torn down
 *
 * Returns parked CPUs to the host slot and frees the identity page
 * tables. The trampoline, park page and spawn context are carved from
 * the instance's control block, which the caller returns to the pool as
 * one allocation; only the pointers are cleared here.
 *
 * Fails without releasing anything if a CPU could not be moved off the
 * instance's context: that CPU still executes the park page and watches
 * the context, so the caller must keep the instance's memory alive.
 */
int mk_arch_release_instance(struct mk_instance *instance)
{
	int ret;

	ret = mk_repark_instance_to_host(instance);
	if (ret) {
		char buf[256];

		mk_cpu_set_format(buf, sizeof(buf), instance->cpus_on_slot);
		pr_err("Instance %d (%s): CPUs %s still watch its park area, keeping spawn resources\n",
		       instance->id, instance->name, buf);
		return ret;
	}

	mk_cpu_set_free(instance->cpus_on_slot);
	instance->cpus_on_slot = NULL;

	mk_free_identity_pgtable(instance->ident_pgt);
	instance->ident_pgt = NULL;
	instance->trampoline_va = NULL;
	instance->park_va = NULL;
	instance->spawn_ctx = NULL;
	instance->spawn_ctx_phys = 0;
	return 0;
}

/**
 * mk_repark_cpu_to_instance - Point one parked pool CPU at an instance
 * @instance: Running instance the CPU is being hot-added to
 * @phys_cpu: Physical (APIC) ID of the parked CPU
 *
 * A hot-added CPU is parked on the host slot, but the spawn kernel wakes
 * secondaries by publishing into its own context, so the CPU must watch
 * that context before the spawn's bringup can reach it. First spawn moves
 * the initial CPUs in bulk (mk_repark_to_instance); this is the per-CPU
 * variant for hotplug on a live instance.
 */
int mk_repark_cpu_to_instance(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	struct mk_spawn_context *ctx = instance->spawn_ctx;
	struct mk_spawn_context *slot = mk_host_park.slot;
	struct mk_cpu_set *on_slot = mk_slot_set(instance);
	int ret;

	if (!ctx || !slot || !ctx->park_phys || !on_slot)
		return -ENODEV;

	/* Make the tracking add below infallible before moving the CPU */
	ret = mk_cpu_set_reserve(on_slot, 1);
	if (ret)
		return ret;

	guard(mutex)(&mk_park_mutex);

	if (mk_cpu_set_contains(on_slot, phys_cpu))
		return 0;

	ret = mk_publish_repark(slot, (u32)phys_cpu, ctx->park_phys,
				ctx->park_cr3, instance->spawn_ctx_phys,
				"repark hot-added cpu");
	if (!ret)
		mk_cpu_set_add(on_slot, phys_cpu);
	return ret;
}

/**
 * mk_repark_cpu_to_host - Return one parked CPU to the host slot
 * @instance: Instance the CPU was removed from
 * @phys_cpu: Physical (APIC) ID of the parked CPU
 *
 * After the spawn kernel offlines a CPU it parks on the instance's
 * context. Move it back to the host slot so it can be spawned or
 * hot-added elsewhere. Counterpart of mk_repark_cpu_to_instance().
 */
int mk_repark_cpu_to_host(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	struct mk_spawn_context *ctx = instance->spawn_ctx;
	int ret;

	guard(mutex)(&mk_park_mutex);

	/* Already on the host slot: nothing watches this context for it */
	if (!mk_cpu_set_contains(instance->cpus_on_slot, phys_cpu))
		return 0;

	if (!ctx || !mk_host_park.slot)
		return -ENODEV;

	ret = mk_publish_repark(ctx, (u32)phys_cpu, mk_host_park.park_phys,
				mk_host_park.cr3, mk_host_park.slot_phys,
				"repark removed cpu to host");
	if (!ret)
		mk_cpu_set_del(instance->cpus_on_slot, phys_cpu);
	return ret;
}

/**
 * mk_arch_confirm_parked - Verify a CPU has reached the instance's park loop
 * @instance: Instance the CPU belongs to
 * @phys_cpu: Physical (APIC) ID of the CPU
 *
 * Publishes a repark that moves the CPU to the slot it is already on, so
 * the move itself is a no-op and the claim is the answer: only a CPU
 * sitting in the park loop can take it. A CPU still running the
 * instance's kernel, on its way down, cannot.
 *
 * Returns 0 once the CPU is known to be parked.
 */
int mk_arch_confirm_parked(struct mk_instance *instance, mk_phys_cpu_t phys_cpu)
{
	struct mk_spawn_context *ctx = instance->spawn_ctx;
	int ret;

	if (!ctx || !ctx->park_phys)
		return -ENODEV;

	guard(mutex)(&mk_park_mutex);

	ret = mk_publish_repark(ctx, (u32)phys_cpu, ctx->park_phys,
				ctx->park_cr3, instance->spawn_ctx_phys,
				"confirm parked");
	if (!ret || !mk_host_park.slot)
		return ret;

	/*
	 * Not on the context we recorded. It may still be parked on the host
	 * slot, which our bookkeeping can miss: an instance rebuilt while a
	 * CPU was elsewhere starts with an empty set. Ask the host slot the
	 * same way. A claim there answers the question this function exists
	 * for - the CPU is parked, not running the image we are about to
	 * overwrite - so believe it and correct the record.
	 */
	if (!mk_publish_repark(mk_host_park.slot, (u32)phys_cpu,
			       mk_host_park.park_phys, mk_host_park.cr3,
			       mk_host_park.slot_phys, "confirm parked (host slot)")) {
		pr_warn("mk_spawn: CPU %llu was parked on the host slot, not instance %d\n",
			phys_cpu, instance->id);
		mk_cpu_set_del(instance->cpus_on_slot, phys_cpu);
		return 0;
	}

	pr_err("mk_spawn: CPU %llu is parked nowhere: not on instance %d context %pa, not on host slot %pa\n",
		 phys_cpu, instance->id, &instance->spawn_ctx_phys,
		 &mk_host_park.slot_phys);
	return ret;
}

/**
 * mk_repark_instance_to_host - Return an instance's CPUs to the host slot
 * @instance: Instance being torn down
 *
 * Moves every CPU watching the instance's context back to the host park
 * area before the instance's park page, context and page tables are
 * freed. No-op if the CPUs never left the host slot.
 *
 * A CPU that fails to claim the repark stays tracked in cpus_on_slot: it
 * is still parked on this instance's context, so the caller must not free
 * the context or park page while the set is non-empty.
 */
int mk_repark_instance_to_host(struct mk_instance *instance)
{
	struct mk_cpu_set *on_slot = instance->cpus_on_slot;
	struct mk_spawn_context *ctx = instance->spawn_ctx;
	unsigned int i;
	int failed = 0;

	if (mk_cpu_set_empty(on_slot) || !ctx || !mk_host_park.slot)
		return 0;

	guard(mutex)(&mk_park_mutex);

	/*
	 * Only the CPUs actually watching this context: waking one that is
	 * already on the host slot would just time out, a second per CPU.
	 * Walk back-to-front so deleting the moved CPUs never shifts
	 * entries the walk has yet to visit.
	 */
	for (i = mk_cpu_set_count(on_slot); i-- > 0; ) {
		mk_phys_cpu_t phys_cpu = on_slot->ids[i];

		if (mk_publish_repark(ctx, (u32)phys_cpu,
				      mk_host_park.park_phys, mk_host_park.cr3,
				      mk_host_park.slot_phys, "repark to host"))
			failed++;
		else
			mk_cpu_set_del(on_slot, phys_cpu);
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

static __noreturn void mk_reject_spawn_context(void)
{
	/*
	 * The host context layout is unknown, so neither its park state nor any
	 * shared context field is safe to use. Keep this CPU local and inert. An NMI
	 * can wake HLT, but returns to this loop with maskable interrupts still
	 * disabled; disable them again before every halt for defense in depth.
	 */
	for (;;) {
		native_irq_disable();
		native_halt();
	}
}

struct mk_spawn_context *mk_validate_boot_context(phys_addr_t ctx_phys)
{
	struct mk_spawn_context *ctx;
	phys_addr_t stamped_phys;
	u64 abi_magic;

	if (!ctx_phys) {
		pr_err("mk_spawn: Boot context physical address is 0!\n");
		return NULL;
	}
	if (mk_boot_context) {
		if (ctx_phys != mk_boot_context_phys)
			mk_reject_spawn_context();
		return mk_boot_context;
	}
	/* Reject an invalid derived address before mapping or dereferencing it. */
	if (!IS_ALIGNED(ctx_phys, PAGE_SIZE))
		mk_reject_spawn_context();

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
	stamped_phys = READ_ONCE(ctx->self_phys);
	if (stamped_phys != ctx_phys)
		mk_reject_spawn_context();
	abi_magic = READ_ONCE(ctx->abi_magic);
	if (abi_magic != MK_BOOT_CONTEXT_MAGIC)
		mk_reject_spawn_context();

	mk_boot_context_phys = ctx_phys;
	mk_boot_context = ctx;
	return ctx;
}

/*
 * Initialize boot context tracking in spawn kernel.
 * Called early during spawn kernel boot.
 */
void mk_init_boot_context(phys_addr_t ctx_phys)
{
	struct mk_spawn_context *ctx = mk_validate_boot_context(ctx_phys);

	if (!ctx)
		return;
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

	/*
	 * The host's control area (this context, the trampoline and park
	 * pages, the identity page tables) sits in our memory and is handed
	 * to us as ordinary RAM, so it stays mapped in the direct map and
	 * we can execute from the trampoline and park pages. Keep the page
	 * allocator away from it: recycling it destroys the context our
	 * CPUs need when this kernel shuts down and they return to the pool.
	 */
	if (ctx->ctrl_phys && ctx->ctrl_size &&
	    memblock_reserve(ctx->ctrl_phys, ctx->ctrl_size))
		pr_err("mk_spawn: failed to reserve control area %pa (%lu bytes)\n",
		       &ctx->ctrl_phys, ctx->ctrl_size);
}

/*
 * Make this kernel's trampoline and park pages executable while the
 * kernel is fully alive. On the way down they are entered from an
 * offline CPU (in the forcible case straight from the NMI stop handler)
 * where changing page attributes is unsafe: CPA takes sleeping locks,
 * can allocate to split a large page, and issues TLB shootdown IPIs.
 *
 * One physical page serves every wake path of this instance: the host
 * allocates it once in mk_setup_trampoline() and reuses it across
 * re-spawns, and mk_arch_prepare_park() places our own trampoline copy
 * (including the secondary entry) in the same page.
 */
int __init mk_arch_prepare_park(void)
{
	struct mk_spawn_context *ctx = mk_boot_context;
	unsigned long virt;
	int ret;

	if (mk_arch_park_ready())
		return 0;
	if (spawn_park_error)
		return spawn_park_error;
	if (!ctx)
		return 0;
	if (!ctx->trampoline_phys || !ctx->park_phys || !ctx->park_cr3) {
		ret = -EINVAL;
		goto fail;
	}

	/*
	 * Put our own copy of the trampoline in the page the host set
	 * aside, while the kernel is fully alive: after shutdown this page
	 * is entered from an offline CPU, where changing page attributes
	 * is not allowed.
	 */
	if (!spawn_trampoline_prepared) {
		spawn_trampoline_phys = ctx->trampoline_phys;
		spawn_trampoline_va = __va(spawn_trampoline_phys);
		memcpy(spawn_trampoline_va, multikernel_relocate_kernel_start,
		       multikernel_relocate_kernel_end -
		       multikernel_relocate_kernel_start);

		/*
		 * Both pages are executed from the direct map, which is writable,
		 * so drop write before adding execute. Leaving them writable and
		 * executable trips the kernel's own W^X check.
		 */
		virt = (unsigned long)spawn_trampoline_va & PAGE_MASK;
		ret = set_memory_ro(virt, 1);
		if (!ret)
			ret = set_memory_x(virt, 1);
		if (ret)
			goto fail;
		spawn_trampoline_prepared = true;
	}

	/* The pool park page is entered the same way when this kernel dies */
	if (!spawn_pool_park_prepared) {
		virt = (unsigned long)__va(ctx->park_phys) & PAGE_MASK;
		ret = set_memory_ro(virt, 1);
		if (!ret)
			ret = set_memory_x(virt, 1);
		if (ret)
			goto fail;
		spawn_pool_park_prepared = true;
	}

	/* Publish executable mappings before any reject or abort can park. */
	smp_store_release(&spawn_park_ready, true);
	return 0;

fail:
	/* A partial W^X transition is not safe to retry. */
	spawn_park_error = ret;
	return ret;
}
early_initcall(mk_arch_prepare_park);

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
 * Initialize spawn kernel's trampoline (one-time setup).
 * Copies spawn kernel's trampoline code to the pool memory page
 * that was allocated by the host kernel during initial spawn boot.
 */

/*
 * Build identity page table for secondary CPU trampoline execution.
 * Maps the trampoline at its virtual address(es) and identity-mapped.
 */
static int mk_build_trampoline_pgtable(unsigned long trampoline_va,
				       unsigned long host_trampoline_va,
				       unsigned long trampoline_phys,
				       unsigned long *cr3_out)
{
	pgd_t *pgd;
	int ret;

	pgd = (pgd_t *)get_zeroed_page(GFP_KERNEL);
	if (!pgd)
		return -ENOMEM;

	/* Map trampoline at its virtual address (initial execution) */
	ret = mk_add_2mb_mapping(pgd, trampoline_va, trampoline_phys,
				 __PAGE_KERNEL_LARGE_EXEC);
	if (ret)
		return ret;

	/*
	 * The pool CPU enters the trampoline through the HOST kernel's
	 * direct map. With CONFIG_RANDOMIZE_MEMORY the host's
	 * page_offset_base differs from ours, so its VA of the trampoline
	 * is not covered by the mapping above. Map it too: the CPU keeps
	 * fetching from that VA right after the first CR3 switch, and an
	 * unmapped fetch there triple-faults the whole machine.
	 */
	ret = mk_add_2mb_mapping(pgd, host_trampoline_va, trampoline_phys,
				 __PAGE_KERNEL_LARGE_EXEC);
	if (ret)
		return ret;

	/* Map trampoline identity (virt=phys, for after CR3 switch) */
	ret = mk_add_2mb_mapping(pgd, trampoline_phys, trampoline_phys,
				 __PAGE_KERNEL_LARGE_EXEC);
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
	int ret;

	if (!ctx) {
		pr_err("mk_spawn: Boot context not initialized\n");
		return -ENODEV;
	}

	if (!spawn_trampoline_phys) {
		pr_err("mk_spawn: trampoline not prepared\n");
		return -ENODEV;
	}
	trampoline_phys = spawn_trampoline_phys;
	trampoline_va = (unsigned long)spawn_trampoline_va;

	/* Build identity page table for two-stage CR3 switch */
	ret = mk_build_trampoline_pgtable(trampoline_va, ctx->trampoline_virt,
					  trampoline_phys, &identity_cr3);
	if (ret)
		return ret;

	/*
	 * Add the identity mapping to init_mm, not the current CR3: this runs
	 * in the cpuhp kthread, which may be borrowing a user mm (lazy TLB).
	 * Writing into a user PGD corrupts that process, and the new CPU
	 * would come up on page tables that are freed when the process exits.
	 * swapper_pg_dir maps everything the secondary needs, including the
	 * vmalloc'ed idle stack.
	 */
	/*
	 * This one lands in the running kernel's page tables and stays
	 * there, so it must not be writable and executable at once. The
	 * secondary trampoline only executes from it; it uses the idle
	 * task stack, not this page.
	 */
	ret = mk_add_2mb_mapping(init_mm.pgd, trampoline_phys, trampoline_phys,
				 __PAGE_KERNEL_LARGE_EXEC & ~_PAGE_RW);
	if (ret)
		return ret;

	/*
	 * Revoke any unconsumed wakeup left over from a failed earlier
	 * bringup, so a parked CPU cannot wake mid-rewrite and read a mix
	 * of old and new fields. A CPU that already claimed the context
	 * still sees the old, consistent snapshot.
	 */
	cmpxchg(&ctx->ready, 1, 0);

	/* Set up spawn context for secondary CPU */
	ctx->identity_cr3 = identity_cr3;
	ctx->trampoline_phys = trampoline_phys;
	ctx->secondary_trampoline_phys = trampoline_phys +
		(mk_secondary_trampoline - multikernel_relocate_kernel_start);
	ctx->kernel_entry = (unsigned long)multikernel_secondary_startup;
	ctx->gs_base = per_cpu_offset(cpu);
	ctx->stack = (unsigned long)idle_task(cpu)->thread.sp;
	ctx->spawn_cr3 = __sme_pa(init_mm.pgd);
	ctx->target_apic_id = apicid;
	ctx->flags = MK_SPAWN_F_SECONDARY;

	/*
	 * Publish the wakeup. The parked CPU watches this context with
	 * MONITOR/MWAIT (or a poll loop), so the write itself wakes it;
	 * no IPI is needed and none could be delivered anyway, since
	 * parked CPUs keep interrupts disabled.
	 */
	smp_wmb();
	WRITE_ONCE(ctx->ready, 1);

	return 0;
}

struct mk_ident_pgtable {
	unsigned long *pages[MK_CTRL_PGTABLE_PAGES];
	int next_page;
	unsigned long pgd_phys;
	struct mk_instance *instance;
};

void mk_free_identity_pgtable(struct mk_ident_pgtable *pgt);

static unsigned long *mk_alloc_pgtable_page(struct mk_ident_pgtable *pgt)
{
	unsigned long *page;

	if (pgt->next_page >= MK_CTRL_PGTABLE_PAGES)
		return NULL;

	if (pgt->instance) {
		page = mk_instance_ctrl_alloc(pgt->instance, PAGE_SIZE, PAGE_SIZE);
	} else {
		/* Host-owned page table: allocate from the main pool */
		phys_addr_t phys = multikernel_alloc(PAGE_SIZE, NUMA_NO_NODE);

		page = phys ? __va(phys) : NULL;
	}

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

struct mk_ident_pgtable *mk_build_identity_pgtable(struct mk_instance *instance)
{
	struct mk_ident_pgtable *pgt;
	unsigned long *pgd;

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

/*
 * Direct map base used by kernels that do not randomize memory layout.
 * Spawn kernels never receive KASLR_FLAG (the vmlinux boot path does not
 * set it), so this is where their direct map always sits, regardless of
 * their CONFIG_RANDOMIZE_MEMORY setting.
 */
static unsigned long mk_default_page_offset(void)
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

/**
 * mk_setup_park_page() - Set up the per-instance pool park page
 * @instance: Instance to allocate the page for
 * @phys_out: Physical address of the park page
 *
 * Copies the pool park loop into a page the host owns for the lifetime
 * of the instance. Unlike the trampoline page, which each spawn kernel
 * overwrites with its own copy, this page is written exactly once by the
 * host and never touched again: CPUs may execute from it while a new
 * kernel image is loaded and booted, so its contents must never change.
 * The spawn context field offsets it reads are a cross-kernel ABI.
 */
void *mk_setup_park_page(struct mk_instance *instance, unsigned long *phys_out)
{
	size_t size = mk_pool_park_end - mk_pool_park_start;
	unsigned long park_phys;
	void *park_va;
	int rc;

	/* Runs under kexec_lock, which nothing takes under this mutex */
	guard(mutex)(&mk_host_park_lock);

	if (!mk_host_park.pgt)
		return ERR_PTR(-ENODEV);

	park_va = instance->park_va;
	if (!park_va) {
		park_va = mk_instance_ctrl_alloc(instance, PAGE_SIZE, PAGE_SIZE);
		if (!park_va)
			return ERR_PTR(-ENOMEM);

		memcpy(park_va, mk_pool_park_start, size);

		rc = set_memory_x((unsigned long)park_va, 1);
		if (rc)
			return ERR_PTR(rc);
	}

	park_phys = virt_to_phys(park_va);

	/*
	 * A dying spawn kernel enters the park page through its own direct
	 * map at the default base; the first instructions run at that VA
	 * until the CR3 switch, so it must be mapped in the pool park page
	 * table. The identity mapping is covered by the per-chunk build.
	 * A page table rebuilt since the last spawn carries no such mapping,
	 * so install it on every spawn rather than only on the first.
	 */
	rc = mk_add_trampoline_mapping(mk_host_park.pgt,
				       mk_default_page_offset() + park_phys,
				       park_phys);
	if (rc)
		return ERR_PTR(rc);

	*phys_out = park_phys;
	return park_va;
}

/*
 * Map the whole pool from a snapshot rather than under mk_pool_for_each_chunk():
 * mk_ident_map_range() allocates its page table pages from the pool, which
 * would recurse into the pool mutex the callback runs under.
 */
static int mk_host_park_map_pool(struct mk_ident_pgtable *pgt)
{
	struct mk_pool_chunk_range *snap = NULL;
	int max = 0, n, i, rc = 0;

	for (;;) {
		n = mk_pool_snapshot_chunks(snap, max);
		if (n <= max)
			break;
		kfree(snap);
		max = n;
		snap = kmalloc_array(max, sizeof(*snap), GFP_KERNEL);
		if (!snap)
			return -ENOMEM;
	}

	for (i = 0; i < n && !rc; i++)
		rc = mk_ident_map_range(pgt, snap[i].start,
					snap[i].start + snap[i].size);

	kfree(snap);
	return rc;
}

static int __mk_setup_host_park(void)
{
	size_t size = mk_pool_park_end - mk_pool_park_start;
	struct mk_ident_pgtable *pgt;
	phys_addr_t phys;
	int rc;

	lockdep_assert_held(&mk_host_park_lock);

	if (mk_host_park.slot)
		return 0;

	if (mk_pool_empty())
		return -ENODEV;

	pgt = mk_build_identity_pgtable(NULL);
	if (IS_ERR(pgt))
		return PTR_ERR(pgt);

	rc = mk_host_park_map_pool(pgt);
	if (rc) {
		mk_free_identity_pgtable(pgt);
		return rc;
	}
	mk_host_park.pgt = pgt;
	mk_host_park.cr3 = mk_get_identity_cr3(pgt);

	phys = multikernel_alloc(PAGE_SIZE, NUMA_NO_NODE);
	if (!phys) {
		rc = -ENOMEM;
		goto err_pgt;
	}
	mk_host_park.park_va = __va(phys);
	mk_host_park.park_phys = phys;

	memcpy(mk_host_park.park_va, mk_pool_park_start, size);

	rc = set_memory_x((unsigned long)mk_host_park.park_va, 1);
	if (rc)
		goto err_page;

	/* The host enters its park page through its own direct map */
	rc = mk_add_trampoline_mapping(pgt,
				       (unsigned long)mk_host_park.park_va,
				       mk_host_park.park_phys);
	if (rc)
		goto err_page;

	phys = multikernel_alloc(ALIGN(sizeof(struct mk_spawn_context), PAGE_SIZE),
				 NUMA_NO_NODE);
	if (!phys) {
		rc = -ENOMEM;
		goto err_page;
	}
	mk_host_park.slot_phys = phys;
	mk_host_park.slot = __va(phys);
	memset(mk_host_park.slot, 0, sizeof(*mk_host_park.slot));
	mk_host_park.slot->self_phys = phys;

	pr_info("mk_spawn: host pool park area at %pa (slot %pa)\n",
		&mk_host_park.park_phys, &mk_host_park.slot_phys);
	return 0;

err_page:
	multikernel_free(mk_host_park.park_phys, PAGE_SIZE);
	mk_host_park.park_va = NULL;
	mk_host_park.park_phys = 0;
err_pgt:
	mk_free_identity_pgtable(mk_host_park.pgt);
	mk_host_park.pgt = NULL;
	mk_host_park.cr3 = 0;
	return rc;
}

int mk_arch_pool_chunk_added(phys_addr_t start, size_t size)
{
	guard(mutex)(&mk_host_park_lock);

	/*
	 * A pool emptied of memory has no park area, so the chunk that
	 * refills it has to bring one back: a CPU handed to a pool with
	 * nowhere to park would halt permanently.
	 */
	if (!mk_host_park.pgt)
		return __mk_setup_host_park();

	return mk_ident_map_range(mk_host_park.pgt, start, start + size);
}

/**
 * mk_setup_host_park() - Set up the host pool park area
 *
 * Called when the baseline is applied, once the memory pool exists.
 * Builds the pool-wide identity page table every parked CPU runs on,
 * the host park page, and the host wake slot that unassigned pool CPUs
 * watch. All of it is host-owned pool memory, alive for as long as the
 * pool has memory.
 */
int mk_setup_host_park(void)
{
	guard(mutex)(&mk_host_park_lock);

	return __mk_setup_host_park();
}

static bool mk_phys_in_range(phys_addr_t addr, phys_addr_t start, size_t size)
{
	return addr >= start && addr - start < size;
}

static bool mk_ident_pgtable_in_range(struct mk_ident_pgtable *pgt,
				      phys_addr_t start, size_t size)
{
	int i;

	if (!pgt)
		return false;

	for (i = 0; i < pgt->next_page; i++) {
		if (pgt->pages[i] &&
		    mk_phys_in_range(virt_to_phys(pgt->pages[i]), start, size))
			return true;
	}

	return false;
}

/**
 * mk_host_park_uses() - Does the host park area live in this range?
 * @start: Physical base of the range
 * @size: Size of the range in bytes
 *
 * Covers the park page, the host wake slot and every page of the
 * pool-wide identity table.
 */
bool mk_host_park_uses(phys_addr_t start, size_t size)
{
	guard(mutex)(&mk_host_park_lock);

	if (!mk_host_park.slot)
		return false;

	return mk_phys_in_range(mk_host_park.park_phys, start, size) ||
	       mk_phys_in_range(mk_host_park.slot_phys, start, size) ||
	       mk_ident_pgtable_in_range(mk_host_park.pgt, start, size);
}

/**
 * mk_teardown_host_park() - Return the host park area to the pool
 *
 * The area is pool memory, so the chunk holding it cannot be removed
 * while it exists. Every parked CPU executes the park page and runs on
 * the identity table, whether it watches the host slot or an instance
 * context, so the area may only go back while no CPU is in the pool at
 * all. The next baseline builds it again, possibly elsewhere.
 *
 * Returns 0 if there was nothing to tear down, -EBUSY if the pool still
 * has CPUs.
 */
int mk_teardown_host_park(void)
{
	guard(mutex)(&mk_host_park_lock);

	if (!mk_host_park.slot)
		return 0;

	if (!mk_pool_cpus_returned())
		return -EBUSY;

	multikernel_free(mk_host_park.slot_phys,
			 ALIGN(sizeof(struct mk_spawn_context), PAGE_SIZE));
	mk_host_park.slot = NULL;
	mk_host_park.slot_phys = 0;

	/* Hand the page back as ordinary pool memory, not as code */
	WARN_ON_ONCE(set_memory_nx((unsigned long)mk_host_park.park_va, 1));
	multikernel_free(mk_host_park.park_phys, PAGE_SIZE);
	mk_host_park.park_va = NULL;
	mk_host_park.park_phys = 0;

	mk_free_identity_pgtable(mk_host_park.pgt);
	mk_host_park.pgt = NULL;
	mk_host_park.cr3 = 0;

	pr_info("mk_spawn: released the host pool park area\n");
	return 0;
}

/*
 * Park this offlined pool CPU. On the host, wait in the host park area
 * watching the host slot; on a spawn kernel returning a CPU to the
 * host, wait on our own instance context like any pool CPU of this
 * instance. Returns only if neither park area exists.
 */
void mk_pool_park_cpu(void)
{
	mk_pool_park_fn park;

	if (mk_host_park.slot) {
		park = (mk_pool_park_fn)mk_host_park.park_va;
		park(mk_host_park.cr3, mk_host_park.slot_phys, read_apic_id(),
		     mk_host_park.park_phys,
		     boot_cpu_has(X86_FEATURE_MWAIT));
	}

	mk_park_cpu();
}

/*
 * Park this CPU in the instance's pool park page. Called on the way into
 * pool state by a dying spawn kernel; the park page and its page table
 * are host-owned and survive re-loads of this instance, unlike the
 * kernel image this code is running from.
 */
/* True only in a spawn kernel whose boot context carries a park area */
bool mk_cpu_parkable(void)
{
	struct mk_spawn_context *ctx = mk_boot_context;

	return ctx && ctx->park_phys && ctx->park_cr3;
}

void mk_park_cpu(void)
{
	struct mk_spawn_context *ctx = mk_boot_context;
	mk_pool_park_fn park;

	if (!ctx) {
		pr_err("mk_spawn: no boot context, cannot park\n");
		return;
	}

	if (!ctx->park_phys || !ctx->park_cr3) {
		pr_err("mk_spawn: context %pa has no park area: park_phys=0x%lx park_cr3=0x%lx\n",
		       &ctx->self_phys, ctx->park_phys, ctx->park_cr3);
		return;
	}

	park = (mk_pool_park_fn)__va(ctx->park_phys);
	park(ctx->park_cr3, virt_to_phys(ctx), read_apic_id(),
	     ctx->park_phys, boot_cpu_has(X86_FEATURE_MWAIT));
}

void mk_free_identity_pgtable(struct mk_ident_pgtable *pgt)
{
	int i;

	if (!pgt)
		return;

	for (i = 0; i < pgt->next_page; i++) {
		if (!pgt->pages[i])
			continue;
		/* Instance page tables live in the control block */
		if (!pgt->instance)
			multikernel_free(virt_to_phys(pgt->pages[i]), PAGE_SIZE);
	}

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
