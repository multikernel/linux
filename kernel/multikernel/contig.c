// SPDX-License-Identifier: GPL-2.0-only
/*
 * Runtime allocation of physically contiguous memory for the multikernel
 * pool. Scans zones from the top down (higher addresses are less likely to
 * hold pinned kernel allocations), ZONE_MOVABLE before ZONE_NORMAL.
 */
#include <linux/gfp.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/page-isolation.h>

#include "internal.h"

static struct page *mk_contig_try_zone(struct zone *zone, unsigned long nr_pages,
				       unsigned long align_pages)
{
	unsigned long start_pfn, end_pfn, candidate;

	if (!populated_zone(zone))
		return NULL;

	start_pfn = zone->zone_start_pfn;
	end_pfn = zone_end_pfn(zone);
	if (end_pfn - start_pfn < nr_pages)
		return NULL;

	candidate = ALIGN_DOWN(end_pfn - nr_pages, align_pages);
	while (candidate >= start_pfn) {
		if (candidate + nr_pages <= end_pfn &&
		    pfn_valid(candidate) && pfn_valid(candidate + nr_pages - 1) &&
		    !alloc_contig_range(candidate, candidate + nr_pages,
					ACR_FLAGS_CMA, GFP_KERNEL))
			return pfn_to_page(candidate);

		if (candidate < align_pages)
			break;
		candidate -= align_pages;
	}
	return NULL;
}

static struct page *mk_contig_try_nodes(unsigned long nr_pages, int node,
					unsigned long align_pages)
{
	static const enum zone_type zone_order[] = { ZONE_MOVABLE, ZONE_NORMAL };
	int nid, i;

	for_each_online_node(nid) {
		pg_data_t *pgdat = NODE_DATA(nid);

		if (node != NUMA_NO_NODE && nid != node)
			continue;

		for (i = 0; i < ARRAY_SIZE(zone_order); i++) {
			struct page *pages;

			pages = mk_contig_try_zone(&pgdat->node_zones[zone_order[i]],
						   nr_pages, align_pages);
			if (pages)
				return pages;
		}
	}
	return NULL;
}

/*
 * A running instance takes more memory through memory hotplug, which only
 * adds whole memory blocks at block-aligned addresses. Instances are carved
 * from the start of a chunk and grow upwards, so a chunk that starts on a
 * block boundary keeps block-sized growth aligned. That is worth preferring
 * but not worth failing for: a chunk that only fits elsewhere still serves
 * instances that are sized once and never grow.
 */
struct page *mk_alloc_contig_pages(unsigned long nr_pages, int node)
{
	unsigned long block_pages = PHYS_PFN(memory_block_size_bytes());
	struct page *pages = NULL;

	if (nr_pages >= block_pages)
		pages = mk_contig_try_nodes(nr_pages, node, block_pages);
	if (!pages)
		pages = mk_contig_try_nodes(nr_pages, node, pageblock_nr_pages);
	return pages;
}

void mk_free_contig_pages(struct page *pages, unsigned long nr_pages)
{
	free_contig_range(page_to_pfn(pages), nr_pages);
}
