// SPDX-License-Identifier: GPL-2.0-only
/* Actual hooks, modeled page tables/allocator/TLB; no RISC-V CPU execution. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PMD_SHIFT 21
#define PMD_SIZE (1UL << PMD_SHIFT)
#define PTRS_PER_PTE 512
#define PAGE_KERNEL 0xfUL
#define IS_ALIGNED(x, a) (!((x) & ((a) - 1)))
#define check_add_overflow(a, b, c) __builtin_add_overflow(a, b, c)
#define __va(x) ((void *)(uintptr_t)(x))
#define __pa(x) ((unsigned long)(x))
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define PTR_ERR(x) ((long)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x) >= (uintptr_t)-4095)
#define READ_ONCE(x) (x)
typedef unsigned long phys_addr_t;
typedef struct { unsigned long val; } pte_t;
typedef pte_t pmd_t;
typedef pte_t pud_t;
typedef pte_t p4d_t;
typedef pte_t pgd_t;
struct mm_struct { int unused; };
static struct mm_struct init_mm;
struct resource { unsigned long start, end; };
struct range { unsigned long start, end; };
static struct resource chunk;
static struct range mappable;
static unsigned long online_pfn, early_pfn;
static bool have_chunk, l4, l5;
static pgd_t root[512];
static unsigned int allocs, frees, flushes, fail_alloc, live, checks;
struct page { void *data; bool reserved; unsigned int cleared_at; };
struct ptdesc { struct page *page; };
static struct page pages[64];
static struct ptdesc descs[64];

static struct page *find_page(void *data)
{
	unsigned int i;

	for (i = 0; i < 64; i++)
		if (pages[i].data == data)
			return &pages[i];
	abort();
}

static pte_t *alloc_table(void)
{
	unsigned int i;
	void *data;

	if (++allocs == fail_alloc)
		return NULL;
	for (i = 0; i < 64 && pages[i].data; i++)
		;
	assert(i < 64);
	data = aligned_alloc(PAGE_SIZE, PAGE_SIZE);
	assert(data);
	memset(data, 0, PAGE_SIZE);
	pages[i] = (struct page) { .data = data };
	descs[i].page = &pages[i];
	live++;
	return data;
}

#define pgd_none(x) (!(x).val)
#define p4d_none(x) pgd_none(x)
#define pud_none(x) pgd_none(x)
#define pmd_none(x) pgd_none(x)
#define pte_none(x) pgd_none(x)
#define pgd_leaf(x) ((x).val & 0xe)
#define p4d_leaf(x) pgd_leaf(x)
#define pud_leaf(x) pgd_leaf(x)
#define pmd_leaf(x) pgd_leaf(x)
#define pgd_bad(x) (((x).val & 0xfff) != 1)
#define p4d_bad(x) pgd_bad(x)
#define pud_bad(x) pgd_bad(x)
#define pmd_bad(x) pgd_bad(x)
#define pte_present(x) ((x).val & 1)
#define pte_pfn(x) ((x).val >> PAGE_SHIFT)
#define pfn_pte(pfn, prot) ((pte_t) { ((pfn) << PAGE_SHIFT) | (prot) })
#define set_pte(p, x) (*(p) = (x))
#define ptep_get(p) (*(p))
#define pte_clear(mm, a, p) ((void)(mm), (void)(a), (p)->val = 0)
#define pfn_valid(pfn) ((pfn) == online_pfn || (pfn) == early_pfn)
#define pfn_to_online_page(pfn) ((pfn) == online_pfn ? (void *)1 : NULL)
static pte_t *table(pte_t entry)
{
	return (void *)(entry.val & ~(PAGE_SIZE - 1));
}

static unsigned int index_at(unsigned long addr, unsigned int shift)
{
	return (addr >> shift) & 511;
}

static pgd_t *pgd_offset_k(unsigned long addr)
{
	return &root[index_at(addr, l5 ? 48 : l4 ? 39 : 30)];
}

static p4d_t *p4d_offset(pgd_t *p, unsigned long a)
{
	return l5 ? table(*p) + index_at(a, 39) : p;
}

static pud_t *pud_offset(p4d_t *p, unsigned long a)
{
	return l4 ? table(*p) + index_at(a, 30) : p;
}

static pmd_t *pmd_offset(pud_t *p, unsigned long a)
{
	return table(*p) + index_at(a, PMD_SHIFT);
}

static pte_t *pte_offset_kernel(pmd_t *p, unsigned long a)
{
	return table(*p) + index_at(a, PAGE_SHIFT);
}

static unsigned long pmd_addr_end(unsigned long a, unsigned long end)
{
	unsigned long next = (a | (PMD_SIZE - 1)) + 1;

	return next < end ? next : end;
}

static struct resource *mk_pool_chunk_resource(phys_addr_t start)
{
	return have_chunk && start >= chunk.start && start <= chunk.end ? &chunk : NULL;
}

static struct range arch_get_mappable_range(void)
{
	return mappable;
}

static void flush_tlb_all(void)
{
	flushes++;
}

static struct page *pmd_page(pmd_t p)
{
	return find_page(table(p));
}

static struct ptdesc *page_ptdesc(struct page *p)
{
	return &descs[p - pages];
}

static void pmd_clear(pmd_t *p)
{
	pmd_page(*p)->cleared_at = flushes + 1;
	p->val = 0;
}

static void pagetable_dtor(struct ptdesc *p)
{
	assert(p->page->cleared_at && flushes >= p->page->cleared_at);
}

static void pagetable_free(struct ptdesc *p)
{
	assert(p->page->cleared_at && flushes >= p->page->cleared_at);
	free(p->page->data);
	p->page->data = NULL;
	frees++;
	live--;
}

#define PageReserved(p) ((p)->reserved)
static void free_reserved_page(struct page *p)
{
	pagetable_free(page_ptdesc(p));
}

static int populate(pte_t *p)
{
	pte_t *new;

	if (p->val)
		return 0;
	new = alloc_table();
	if (!new)
		return -ENOMEM;
	p->val = (uintptr_t)new | 1;
	return 0;
}

static int apply_to_page_range(struct mm_struct *mm, unsigned long a,
			       unsigned long size, void *fn, void *data)
{
	unsigned long end = a + size;

	assert(mm == &init_mm && !fn && !data);
	for (; a < end; a = pmd_addr_end(a, end)) {
		pgd_t *pgd = pgd_offset_k(a);
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;

		if (l5 && populate(pgd))
			return -ENOMEM;
		p4d = p4d_offset(pgd, a);
		if (l4 && populate(p4d))
			return -ENOMEM;
		pud = pud_offset(p4d, a);
		if (populate(pud))
			return -ENOMEM;
		pmd = pmd_offset(pud, a);
		if (populate(pmd))
			return -ENOMEM;
	}
	return 0;
}

#include "pool-map-production.h"

static void reset(unsigned int mode)
{
	unsigned int i;

	for (i = 0; i < 64; i++)
		free(pages[i].data);
	memset(pages, 0, sizeof(pages));
	memset(root, 0, sizeof(root));
	l4 = mode >= 48;
	l5 = mode >= 57;
	chunk = (struct resource) { 0x40000000, 0x7fffffff };
	mappable = (struct range) { 0, 0x7fffffffff };
	online_pfn = early_pfn = ~0UL;
	have_chunk = true;
	allocs = 0;
	frees = 0;
	flushes = 0;
	fail_alloc = 0;
	live = 0;
}

static pmd_t *get_pmd(unsigned long a)
{
	return pmd_offset(pud_offset(p4d_offset(pgd_offset_k(a), a), a), a);
}

static pte_t *get_pte(unsigned long a)
{
	return pte_offset_kernel(get_pmd(a), a);
}

static void expect(const char *name, int got, int want)
{
	checks++;
	if (got != want) {
		fprintf(stderr, "%s: %d != %d\n", name, got, want);
		exit(1);
	}
}

int main(void)
{
	unsigned int mode, failure, tables;
	unsigned long a = 0x40200000, b = a + PMD_SIZE - PAGE_SIZE;
	pte_t saved;
	unsigned int before;

	for (mode = 39; mode <= 57; mode += 9) {
		reset(mode);
		expect("zero size", mk_arch_pool_map(a, 0), -EINVAL);
		expect("unaligned start", mk_arch_pool_map(a + 1, PAGE_SIZE), -EINVAL);
		expect("unaligned size", mk_arch_pool_map(a, PAGE_SIZE - 1), -EINVAL);
		expect("overflow", mk_arch_pool_map(~(PAGE_SIZE - 1), PAGE_SIZE), -EINVAL);
		have_chunk = false;
		expect("no pool", mk_arch_pool_map(a, PAGE_SIZE), -EINVAL);
		have_chunk = true;
		expect("outside chunk",
		       mk_arch_pool_map(chunk.start - PAGE_SIZE, PAGE_SIZE), -EINVAL);
		expect("cross chunk",
		       mk_arch_pool_map(chunk.end + 1 - PAGE_SIZE, 2 * PAGE_SIZE), -EINVAL);
		mappable.end = a - 1;
		expect("outside direct map", mk_arch_pool_map(a, PAGE_SIZE), -EINVAL);
		mappable.end = chunk.end;
		online_pfn = (a >> PAGE_SHIFT) + 1;
		expect("online tail", mk_arch_pool_map(a, 2 * PAGE_SIZE), -EBUSY);
		assert(!allocs);
		online_pfn = ~0UL;
		/* An early section keeps struct page storage after subsection removal. */
		early_pfn = a >> PAGE_SHIFT;
		assert(pfn_valid(early_pfn) && !pfn_to_online_page(early_pfn));
		expect("map removed early subsection", mk_arch_pool_map(a, PAGE_SIZE), 0);
		assert(pte_pfn(*get_pte(a)) == a >> PAGE_SHIFT && flushes);
		saved = *get_pte(a);
		online_pfn = a >> PAGE_SHIFT;
		expect("unmap online RAM", mk_arch_pool_unmap(a, PAGE_SIZE), -EBUSY);
		assert(get_pte(a)->val == saved.val);
		online_pfn = ~0UL;
		expect("overlap", mk_arch_pool_map(a, 2 * PAGE_SIZE), -EBUSY);
		assert(get_pte(a)->val == saved.val && pte_none(*get_pte(a + PAGE_SIZE)));
		expect("neighbor map", mk_arch_pool_map(a + PAGE_SIZE, PAGE_SIZE), 0);
		expect("unmap missing tail", mk_arch_pool_unmap(a, 3 * PAGE_SIZE), -EINVAL);
		assert(get_pte(a)->val == saved.val);
		get_pte(a + PAGE_SIZE)->val += PAGE_SIZE;
		expect("unmap wrong PFN", mk_arch_pool_unmap(a, 2 * PAGE_SIZE), -EINVAL);
		assert(get_pte(a)->val == saved.val);
		get_pte(a + PAGE_SIZE)->val -= PAGE_SIZE;
		expect("unmap first", mk_arch_pool_unmap(a, PAGE_SIZE), 0);
		assert(!frees && pte_none(*get_pte(a)) && !pte_none(*get_pte(a + PAGE_SIZE)));
		find_page(table(*get_pmd(a)))->reserved = true;
		expect("unmap neighbor", mk_arch_pool_unmap(a + PAGE_SIZE, PAGE_SIZE), 0);
		assert(frees == 1 && pmd_none(*get_pmd(a)));
		expect("double unmap", mk_arch_pool_unmap(a, PAGE_SIZE), -EINVAL);
		expect("reuse map", mk_arch_pool_map(a, PAGE_SIZE), 0);
		expect("reuse unmap", mk_arch_pool_unmap(a, PAGE_SIZE), 0);
		/* Model RAM re-add: create_pmd_mapping must see an empty PMD. */
		assert(pmd_none(*get_pmd(a)));
		*get_pmd(a) = pfn_pte(a >> PAGE_SHIFT, PAGE_KERNEL);
		before = flushes;
		expect("reject PMD RAM leaf", mk_arch_pool_map(a, PAGE_SIZE), -EBUSY);
		expect("reject huge unmap", mk_arch_pool_unmap(a, PAGE_SIZE), -EBUSY);
		assert(flushes == before && pmd_leaf(*get_pmd(a)));
		reset(mode);
		pgd_offset_k(a)->val = 2;
		expect("reject upper leaf", mk_arch_pool_map(a, PAGE_SIZE), -EBUSY);
		pgd_offset_k(a)->val = 0x100;
		expect("reject upper malformed", mk_arch_pool_map(a, PAGE_SIZE), -EBUSY);
		/* Fail each allocation in a fresh cross-PMD map; no leaf may escape. */
		tables = 3 + (mode >= 48) + (mode >= 57);
		for (failure = 1; failure <= tables; failure++) {
			reset(mode);
			fail_alloc = failure;
			expect("allocation rollback", mk_arch_pool_map(b, 2 * PAGE_SIZE), -ENOMEM);
			fail_alloc = 0;
			expect("retry after rollback", mk_arch_pool_map(b, 2 * PAGE_SIZE), 0);
			expect("unmap cross PMD", mk_arch_pool_unmap(b, 2 * PAGE_SIZE), 0);
			assert(pmd_none(*get_pmd(b)) && pmd_none(*get_pmd(b + PAGE_SIZE)));
		}
		reset(mode);
		expect("neighbor before failed map", mk_arch_pool_map(b - PAGE_SIZE, PAGE_SIZE), 0);
		fail_alloc = allocs + 1;
		expect("neighbor survives allocation failure",
		       mk_arch_pool_map(b, 2 * PAGE_SIZE), -ENOMEM);
		assert(!pte_none(*get_pte(b - PAGE_SIZE)) && pte_none(*get_pte(b)));
		fail_alloc = 0;
		expect("remove survivor", mk_arch_pool_unmap(b - PAGE_SIZE, PAGE_SIZE), 0);
	}
	reset(39);
	printf("RISC-V pool mapping: %u checks passed (page tables and TLB modeled)\n", checks);
	return 0;
}
