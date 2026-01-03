// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/pnp.h>
#include <linux/acpi.h>
#include <linux/multikernel.h>

#include <asm/acpi.h>
#include <asm/setup.h>
#include <asm/multikernel.h>
#include <asm/bios_ebda.h>
#include <asm/x86_init.h>
#include <asm/e820/api.h>
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/mpspec.h>
#include <asm/numa.h>
#include <linux/pgtable.h>
#include <asm/pgtable.h>
#include <asm/pgtable_64_types.h>
#include <asm/realmode.h>

/* External functions for page table population */
extern pmd_t *populate_extra_pmd(unsigned long vaddr);

/* Physical address of original boot_params (saved during boot) */
extern unsigned long orig_boot_params;

/*
 * Custom wakeup for multikernel spawn kernels.
 * Uses shared spawn table instead of realmode trampoline.
 */
static int multikernel_wakeup_cpu(u32 apicid, unsigned long start_eip,
				  unsigned int cpu)
{
	return multikernel_wakeup_secondary_cpu_64(apicid, start_eip, cpu);
}

#ifdef CONFIG_X86_64
/*
 * Multikernel pagetable initialization.
 *
 * On x86_64, set_pte_vaddr() expects PGD entries to already exist.
 * Normal boot relies on KASAN to create PGD[508] for CPU_ENTRY_AREA,
 * but spawn kernels may not have KASAN enabled.
 *
 * This function:
 * 1. Calls native_pagetable_init (paging_init) to set up page tables
 * 2. Ensures PGD[508] exists for CPU_ENTRY_AREA before trap_init() runs
 *
 * Without this, setup_cpu_entry_areas() silently fails because
 * set_pte_vaddr() returns early when PGD is not present.
 */
static void __init multikernel_pagetable_init(void)
{
	pgd_t *pgd;

	/* First, call the normal pagetable initialization */
	native_pagetable_init();

	/*
	 * Ensure PGD[508] exists for CPU_ENTRY_AREA.
	 * populate_extra_pmd() uses fill_p4d() which creates the PGD entry
	 * if it doesn't exist.
	 */
	pgd = pgd_offset_k(CPU_ENTRY_AREA_BASE);
	if (pgd_none(*pgd)) {
		pr_info("multikernel: creating PGD for CPU_ENTRY_AREA at index %d\n",
			(int)pgd_index(CPU_ENTRY_AREA_BASE));
		populate_extra_pmd(CPU_ENTRY_AREA_BASE);
	}
}
#endif

/*
 * Multikernel SMP configuration - similar to Jailhouse.
 * Parses CPU configuration from KHO DTB and registers CPUs.
 */
static void __init multikernel_parse_smp_config(void)
{
	register_lapic_address(APIC_DEFAULT_PHYS_BASE);

	/* Register CPUs from KHO DTB if available */
	mk_register_cpus_from_kho();

	/*
	 * Initialize boot context for secondary CPU wakeup.
	 * orig_boot_params points to ctx->bp within mk_spawn_context.
	 * Compute ctx physical address by subtracting the bp offset.
	 * No dereference - pool memory may not be mapped during early boot.
	 */
	mk_init_boot_context(orig_boot_params - offsetof(struct mk_spawn_context, bp));

	/*
	 * Set custom wakeup function for secondary CPU bringup.
	 * This uses the shared spawn table instead of realmode trampoline.
	 */
	apic_update_callback(wakeup_secondary_cpu_64, multikernel_wakeup_cpu);
}

void __init x86_early_init_platform_quirks(void)
{
	pr_info("platform-quirks: hardware_subarch=%u (MULTIKERNEL=%u)\n",
		boot_params.hdr.hardware_subarch, X86_SUBARCH_MULTIKERNEL);

	x86_platform.legacy.i8042 = X86_LEGACY_I8042_EXPECTED_PRESENT;
	x86_platform.legacy.rtc = 1;
	x86_platform.legacy.warm_reset = 1;
	x86_platform.legacy.reserve_bios_regions = 0;
	x86_platform.legacy.map_isa_ram = 0;
	x86_platform.legacy.devices.pnpbios = 1;

	switch (boot_params.hdr.hardware_subarch) {
	case X86_SUBARCH_PC:
		x86_platform.legacy.reserve_bios_regions = 1;
		x86_platform.legacy.map_isa_ram = 1;
		break;
	case X86_SUBARCH_XEN:
		x86_platform.legacy.devices.pnpbios = 0;
		x86_platform.legacy.rtc = 0;
		break;
	case X86_SUBARCH_INTEL_MID:
	case X86_SUBARCH_CE4100:
		x86_platform.legacy.devices.pnpbios = 0;
		x86_platform.legacy.rtc = 0;
		x86_platform.legacy.i8042 = X86_LEGACY_I8042_PLATFORM_ABSENT;
		break;
	case X86_SUBARCH_MULTIKERNEL:
		x86_platform.legacy.devices.pnpbios = 0;
		x86_platform.legacy.i8042 = X86_LEGACY_I8042_PLATFORM_ABSENT;
		x86_platform.legacy.rtc = 0;
		x86_platform.legacy.warm_reset = 0;
		x86_platform.legacy.no_bsp_restriction = 1;
		/*
		 * Set smp_found_config early to prevent acpi_mps_check() from
		 * disabling the APIC when ACPI is disabled but MPPARSE is not
		 * built-in. Multikernel provides SMP config via device tree.
		 */
		smp_found_config = 1;
		disable_acpi();
		x86_init.resources.memory_setup = e820__memory_setup_multikernel;
		x86_init.paging.init_direct_mapping = init_direct_mapping_sparse;
#ifdef CONFIG_X86_64
		/*
		 * Use custom pagetable_init that ensures PGD[508] exists
		 * for CPU_ENTRY_AREA before setup_cpu_entry_areas() runs.
		 */
		x86_init.paging.pagetable_init = multikernel_pagetable_init;
#endif
		x86_init.mpparse.early_parse_smp_cfg = x86_init_noop;
		x86_init.mpparse.parse_smp_cfg = multikernel_parse_smp_config;
		x86_init.timers.wallclock_init = x86_init_noop;
		x86_platform.realmode_reserve = x86_init_noop;
		x86_platform.realmode_init = x86_init_noop;
		/*
		 * Spawn kernels don't use realmode trampoline - ensure this
		 * is NULL to prevent do_boot_cpu from accessing it.
		 */
		real_mode_header = NULL;
		numa_set_off();
		break;
	}

	if (x86_platform.set_legacy_features)
		x86_platform.set_legacy_features();
}

bool __init x86_pnpbios_disabled(void)
{
	return x86_platform.legacy.devices.pnpbios == 0;
}

#if defined(CONFIG_PNPBIOS)
bool __init arch_pnpbios_disabled(void)
{
	return x86_pnpbios_disabled();
}
#endif
