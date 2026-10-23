// SPDX-License-Identifier: GPL-2.0-only
/* Actual direct-map leaf selection; page-table execution is not modeled. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef uint64_t phys_addr_t;
#define __meminit
#define IS_ENABLED(option) (option)
#define CONFIG_64BIT 1
#define PAGE_SIZE (1UL << 12)
#define PMD_SIZE (1UL << 21)
#define PUD_SIZE (1UL << 30)
#define P4D_SIZE (1UL << 39)

static bool pgtable_l4_enabled, pgtable_l5_enabled, debug_enabled;
static unsigned int checks, failures;

static bool debug_pagealloc_enabled(void)
{
	return debug_enabled;
}

#include "map-size-production.h"

static void expect(phys_addr_t pa, uintptr_t va, phys_addr_t size,
		   uintptr_t expected, const char *name)
{
	uintptr_t actual = best_map_size(pa, va, size);

	checks++;
	if (actual != expected) {
		fprintf(stderr, "FAIL MK=%d %s: %#lx != %#lx\n",
			CONFIG_MULTIKERNEL, name, (unsigned long)actual,
			(unsigned long)expected);
		failures++;
	}
}

int main(void)
{
	const uintptr_t va = 1UL << 60;
	unsigned int levels;

	for (levels = 3; levels <= 5; levels++) {
		pgtable_l4_enabled = levels >= 4;
		pgtable_l5_enabled = levels >= 5;
		expect(0, va, P4D_SIZE,
		       CONFIG_MULTIKERNEL || levels == 3 ? PMD_SIZE :
		       (levels == 5 ? P4D_SIZE : PUD_SIZE), "aligned large range");
		expect(0, va, PUD_SIZE,
		       CONFIG_MULTIKERNEL || levels == 3 ? PMD_SIZE : PUD_SIZE,
		       "aligned 1 GiB range");
		expect(PMD_SIZE, va + PMD_SIZE, PUD_SIZE, PMD_SIZE,
		       "2 MiB physical and virtual alignment");
		expect(0, va, PMD_SIZE, PMD_SIZE, "exact 2 MiB range");
		expect(0, va, PMD_SIZE - PAGE_SIZE, PAGE_SIZE, "short tail");
		expect(PAGE_SIZE, va, PMD_SIZE, PAGE_SIZE, "unaligned physical base");
		expect(0, va + PAGE_SIZE, PMD_SIZE, PAGE_SIZE, "unaligned virtual base");
		expect(0, va, PAGE_SIZE, PAGE_SIZE, "one page");
		debug_enabled = true;
		expect(0, va, P4D_SIZE, PAGE_SIZE, "debug page allocation");
		debug_enabled = false;
	}
	printf("RISC-V map size MK=%d: %u checks, %u failures\n",
	       CONFIG_MULTIKERNEL, checks, failures);
	return failures != 0;
}
