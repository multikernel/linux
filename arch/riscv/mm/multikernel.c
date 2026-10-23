// SPDX-License-Identifier: GPL-2.0-only
#include <linux/memory_hotplug.h>
#include <linux/mm.h>
#include <linux/multikernel.h>
#include <linux/overflow.h>
#include <linux/pgalloc.h>
#include <asm/tlbflush.h>

/* The caller owns the allocation and holds mk_pool_map_lock and online_mems. */
static int mk_pool_mapping_range(phys_addr_t start, size_t size)
{
	struct range range = arch_get_mappable_range();
	struct resource *chunk;
	phys_addr_t end, addr;

	if (!size || !IS_ALIGNED(start, PAGE_SIZE) ||
	    !IS_ALIGNED(size, PAGE_SIZE) || check_add_overflow(start, size, &end))
		return -EINVAL;
	chunk = mk_pool_chunk_resource(start);
	if (!chunk || end - 1 > chunk->end ||
	    start < range.start || end - 1 > range.end)
		return -EINVAL;
	/* Early sections can remain pfn_valid after their subsections are removed. */
	for (addr = start; addr < end; addr += PAGE_SIZE)
		if (pfn_to_online_page(addr >> PAGE_SHIFT))
			return -EBUSY;
	return 0;
}

/* Never let a pool mapping split or replace an existing direct-map leaf. */
static pmd_t *mk_pool_pmd(unsigned long addr)
{
	pgd_t *pgd = pgd_offset_k(addr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (pgd_none(*pgd))
		return NULL;
	if (pgd_leaf(*pgd) || pgd_bad(*pgd))
		return ERR_PTR(-EBUSY);
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;
	if (p4d_leaf(*p4d) || p4d_bad(*p4d))
		return ERR_PTR(-EBUSY);
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;
	if (pud_leaf(*pud) || pud_bad(*pud))
		return ERR_PTR(-EBUSY);
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;
	if (pmd_leaf(*pmd) || pmd_bad(*pmd))
		return ERR_PTR(-EBUSY);
	return pmd;
}

static int mk_pool_check_ptes(unsigned long addr, unsigned long end, bool unmap)
{
	for (; addr < end; addr += PAGE_SIZE) {
		pmd_t *pmd = mk_pool_pmd(addr);
		pte_t pte;

		if (IS_ERR(pmd))
			return PTR_ERR(pmd);
		if (!pmd) {
			if (unmap)
				return -EINVAL;
			continue;
		}
		pte = ptep_get(pte_offset_kernel(pmd, addr));
		if (unmap) {
			if (!pte_present(pte) || pte_pfn(pte) != __pa(addr) >> PAGE_SHIFT)
				return -EINVAL;
		} else if (!pte_none(pte)) {
			return -EBUSY;
		}
	}
	return 0;
}

static void mk_pool_free_empty_ptes(unsigned long addr, unsigned long end)
{
	for (; addr < end; addr = pmd_addr_end(addr, end)) {
		pmd_t *pmd = mk_pool_pmd(addr);
		struct ptdesc *ptdesc;
		struct page *page;
		pte_t *ptes;
		int i;

		if (IS_ERR(pmd) || !pmd)
			continue;
		ptes = pte_offset_kernel(pmd, addr & ~(PMD_SIZE - 1));
		for (i = 0; i < PTRS_PER_PTE; i++)
			if (!pte_none(ptep_get(ptes + i)))
				break;
		if (i != PTRS_PER_PTE)
			continue;

		page = pmd_page(*pmd);
		ptdesc = page_ptdesc(page);
		pmd_clear(pmd);
		/* Non-leaf removal needs a global fence before table reuse. */
		flush_tlb_all();
		pagetable_dtor(ptdesc);
		if (PageReserved(page))
			free_reserved_page(page);
		else
			pagetable_free(ptdesc);
	}
	/* Empty upper tables stay reusable; the MK direct map has no larger leaves. */
}

int mk_arch_pool_map(phys_addr_t start, size_t size)
{
	unsigned long addr = (unsigned long)__va(start), end = addr + size;
	unsigned long va;
	int ret;

	ret = mk_pool_mapping_range(start, size);
	if (ret)
		return ret;
	ret = mk_pool_check_ptes(addr, end, false);
	if (ret)
		return ret;

	/* Allocate everything first so ENOMEM cannot expose a partial mapping. */
	ret = apply_to_page_range(&init_mm, addr, size, NULL, NULL);
	if (ret) {
		mk_pool_free_empty_ptes(addr, end);
		flush_tlb_all();
		return ret;
	}
	for (va = addr; va < end; va += PAGE_SIZE) {
		pte_t *pte = pte_offset_kernel(mk_pool_pmd(va), va);

		set_pte(pte, pfn_pte(__pa(va) >> PAGE_SHIFT, PAGE_KERNEL));
	}
	flush_tlb_all();
	return 0;
}

int mk_arch_pool_unmap(phys_addr_t start, size_t size)
{
	unsigned long addr = (unsigned long)__va(start), end = addr + size;
	unsigned long va;
	int ret;

	ret = mk_pool_mapping_range(start, size);
	if (ret)
		return ret;
	ret = mk_pool_check_ptes(addr, end, true);
	if (ret)
		return ret;
	/* No failures after preflight; leave neighboring allocations mapped. */
	for (va = addr; va < end; va += PAGE_SIZE)
		pte_clear(&init_mm, va, pte_offset_kernel(mk_pool_pmd(va), va));
	flush_tlb_all();
	/* An empty PTE table would prevent PMD-sized RAM re-add in init.c. */
	mk_pool_free_empty_ptes(addr, end);
	return 0;
}
