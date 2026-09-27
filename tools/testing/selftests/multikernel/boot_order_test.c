// SPDX-License-Identifier: GPL-2.0-only
/* Actual setup_arch order, stopping at SBI initialization. */
#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdio.h>
#define __init
#define CONFIG_MULTIKERNEL 1
#define CONFIG_BUILTIN_DTB 0
#define CONFIG_RISCV_ISA_ZICBOM 0
#define CONFIG_RISCV_ISA_ZBB 0
#define IS_ENABLED(CONFIG_option) (CONFIG_option)
#define MK_FDT_COMPATIBLE "multikernel-v1"
#define NOTIFY_DONE 0
#define ZICBOM 0
#define ZBB 0
#define NOOP() do { } while (0)
#define setup_initial_init_mm(...) NOOP()
#define set_arch_panic_timeout(...) NOOP()
#define jump_label_init() NOOP()
#define parse_early_param() NOOP()
#define efi_init() NOOP()
#define paging_init() NOOP()
#define acpi_boot_table_init() NOOP()
#define unflatten_device_tree() NOOP()
#define misc_mem_init() NOOP()
#define init_resources() NOOP()
#define acpi_init_rintc_map() NOOP()
#define acpi_map_cpus_to_nodes() NOOP()
#define riscv_init_cbo_blocksizes() NOOP()
#define riscv_fill_hwcap() NOOP()
#define apply_boot_alternatives() NOOP()
#define init_rt_signal_env() NOOP()
#define riscv_noncoherent_supported() NOOP()
#define riscv_set_dma_cache_alignment() NOOP()
#define riscv_user_isa_enable() NOOP()
#define riscv_spinlock_init() NOOP()
#define static_branch_disable(...) NOOP()
#define riscv_isa_extension_available(...) false
static bool mapped, spawn, accepted, acpi_disabled = true;
static void *initial_boot_params;
static unsigned long dtb_early_pa = 0x80600000;
static char *boot_command_line;
static jmp_buf initialized;
struct notifier_block {
	int (*notifier_call)(struct notifier_block *nb, unsigned long event, void *data);
	int priority;
};
static struct notifier_block *registered;
static int panic_notifier_list;
static int panic_timeout;

static void parse_dtb(void) { initial_boot_params = &spawn; }
static void early_ioremap_setup(void) { mapped = true; }
static int of_get_flat_dt_root(void) { return 0; }
static bool of_flat_dt_is_compatible(int node, const char *name) { return spawn; }
static unsigned long fdt_totalsize(void *fdt) { return 4096; }
static bool mk_spawned(void) { return accepted; }
static void mk_manifest_populate(unsigned long phys, unsigned long size)
{
	assert(mapped && phys == dtb_early_pa && size == 4096);
	accepted = true;
}
static int atomic_notifier_chain_register(int *head, struct notifier_block *nb)
{
	assert(head == &panic_notifier_list);
	registered = nb;
	return 0;
}
static void machine_halt(void) { longjmp(initialized, 2); }
static void sbi_init(void)
{
	assert(mapped && accepted == spawn);
	longjmp(initialized, 1);
}

#include "setup.h"

int main(void)
{
	char *cmdline;
	int stopped;

	if (!setjmp(initialized))
		setup_arch(&cmdline);
	assert(!registered);
	spawn = true;
	mapped = false;
	if (!setjmp(initialized))
		setup_arch(&cmdline);
	assert(registered && registered->priority == INT_MAX);
	stopped = setjmp(initialized);
	if (!stopped)
		registered->notifier_call(registered, 0, NULL);
	assert(stopped == 2);
	panic_timeout = 1;
	stopped = setjmp(initialized);
	if (!stopped)
		assert(registered->notifier_call(registered, 0, NULL) == NOTIFY_DONE);
	assert(stopped == 0);
	puts("PASS: early mapping precedes manifest, spawn panic hook precedes SBI reset setup");
	return 0;
}
