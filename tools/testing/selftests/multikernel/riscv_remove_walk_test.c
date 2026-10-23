// SPDX-License-Identifier: GPL-2.0-only
/* Actual removal walkers; table storage and lower-level removal are modeled. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define __meminit
#define PUD_SIZE (1UL << 30)
#define P4D_SIZE (1UL << 39)
struct entry { void *next; bool present, leaf; };
typedef struct entry p4d_t;
typedef struct entry pud_t;
typedef struct entry pmd_t;
struct vmem_altmap { int unused; };
static bool pgtable_l4_enabled, pgtable_l5_enabled;
static unsigned int calls, failures;
static unsigned long expected_start, expected_end;
static pmd_t *expected_pmd;

static unsigned long range_end(unsigned long addr, unsigned long end, unsigned long size)
{
	unsigned long next = (addr | (size - 1)) + 1;

	return next < end ? next : end;
}

#define pud_addr_end(a, e) range_end(a, e, PUD_SIZE)
#define p4d_addr_end(a, e) range_end(a, e, pgtable_l4_enabled ? P4D_SIZE : PUD_SIZE)
#define pud_index(a) (((a) >> 30) & 511)
#define p4d_index(a) (((a) >> (pgtable_l4_enabled ? 39 : 30)) & 511)
#define pudp_get(p) (*(p))
#define p4dp_get(p) (*(p))
#define pud_present(p) ((p).present)
#define p4d_present(p) ((p).present)
#define pud_leaf(p) ((p).leaf)
#define p4d_leaf(p) ((p).leaf)
#define pud_clear(p) memset(p, 0, sizeof(*(p)))
#define p4d_clear(p) memset(p, 0, sizeof(*(p)))
#define pud_page(p) ((p).next)
#define p4d_page(p) ((p).next)

static pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
{
	assert(!addr);
	return pud->next;
}

static pud_t *pud_offset(p4d_t *p4d, unsigned long addr)
{
	return pgtable_l4_enabled ? (pud_t *)p4d->next + pud_index(addr) : (pud_t *)p4d;
}

static void free_vmemmap_storage(void *page, unsigned long size, struct vmem_altmap *altmap)
{
	(void)page;
	(void)size;
	(void)altmap;
	assert(false);
}

static void free_pmd_table(pmd_t *pmd, pud_t *pud, bool is_vmemmap)
{
	assert(pgtable_l4_enabled && pmd == pud->next && !is_vmemmap);
}

static void free_pud_table(pud_t *pud, p4d_t *p4d)
{
	assert(pgtable_l5_enabled && pud == p4d->next);
}

static void remove_pmd_mapping(pmd_t *pmd, unsigned long addr, unsigned long end,
			       bool is_vmemmap, struct vmem_altmap *altmap)
{
	assert(pmd == expected_pmd && addr == expected_start && end == expected_end);
	assert(!is_vmemmap && !altmap);
	calls++;
}

#include "remove-walk-production.h"

int main(void)
{
	static p4d_t p4ds[512];
	static pud_t puds[512];
	static pmd_t pmds[512];
	unsigned int mode;
	p4d_t *base, *selected;

	/* Nonzero indexes expose double indexing of an already-selected entry. */
	expected_start = P4D_SIZE + 3 * PUD_SIZE + (1UL << 21);
	expected_end = expected_start + (1UL << 21);
	expected_pmd = pmds;
	for (mode = 39; mode <= 57; mode += 9) {
		memset(p4ds, 0, sizeof(p4ds));
		memset(puds, 0, sizeof(puds));
		pgtable_l4_enabled = mode >= 48;
		pgtable_l5_enabled = mode >= 57;
		base = pgtable_l5_enabled ? p4ds : &p4ds[17];
		selected = pgtable_l5_enabled ? base + p4d_index(expected_start) : base;
		selected->present = true;
		if (pgtable_l4_enabled) {
			selected->next = puds;
			puds[pud_index(expected_start)] = (pud_t) { .next = pmds, .present = true };
		} else {
			selected->next = pmds;
		}
		calls = 0;
		remove_p4d_mapping(base, expected_start, expected_end, false, NULL);
		if (calls != 1) {
			fprintf(stderr, "FAIL Sv%u: visited %u target ranges, expected 1\n", mode, calls);
			failures++;
		}
	}
	printf("RISC-V removal walker: 3 modes, %u failures (page tables modeled)\n", failures);
	return failures != 0;
}
