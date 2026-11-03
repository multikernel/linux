// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multikernel memory management
 *
 * The spawn kernel memory pool is a list of physically contiguous chunks
 * the kernel allocates at runtime, one gen_pool per NUMA node.
 */

#include <linux/ioport.h>
#include <linux/kexec.h>
#include <linux/list.h>
#include <linux/memory_hotplug.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mutex.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <linux/multikernel.h>

#include "internal.h"

static struct gen_pool *mk_node_pool_get(int node)
{
	if (mk_pool->node_pools[node])
		return mk_pool->node_pools[node];

	mk_pool->node_pools[node] = gen_pool_create(PAGE_SHIFT, node);
	return mk_pool->node_pools[node];
}

/**
 * multikernel_alloc() - Allocate memory from the multikernel pool
 * @size: size to allocate
 * @node: NUMA node to allocate from, or NUMA_NO_NODE for any node
 *
 * Returns physical address of allocated memory, or 0 on failure
 */
phys_addr_t multikernel_alloc(size_t size, int node)
{
	unsigned long addr = 0;
	int nid;

	if (node != NUMA_NO_NODE && (node < 0 || node >= MAX_NUMNODES))
		return 0;
	if (!mk_pool)
		return 0;

	mutex_lock(&mk_pool->mem_lock);
	if (node != NUMA_NO_NODE) {
		if (mk_pool->node_pools[node])
			addr = gen_pool_alloc(mk_pool->node_pools[node], size);
	} else {
		for_each_online_node(nid) {
			if (!mk_pool->node_pools[nid])
				continue;
			addr = gen_pool_alloc(mk_pool->node_pools[nid], size);
			if (addr)
				break;
		}
	}
	mutex_unlock(&mk_pool->mem_lock);

	return (phys_addr_t)addr;
}

/* gen_pool_fixed_alloc() applies its offset to every chunk it tries */
static unsigned long mk_pool_algo_at(unsigned long *map, unsigned long size,
				     unsigned long start, unsigned int nr,
				     void *data, struct gen_pool *pool,
				     unsigned long start_addr)
{
	unsigned long addr = *(unsigned long *)data;
	unsigned long bit;

	if (addr < start_addr)
		return size;
	bit = (addr - start_addr) >> pool->min_alloc_order;
	if (bit >= size || bitmap_find_next_zero_area(map, size, bit, nr, 0) != bit)
		return size;
	return bit;
}

/**
 * multikernel_alloc_at() - Allocate a given range from the multikernel pool
 * @addr: physical address of the range, page aligned
 * @size: size of the range, page aligned
 *
 * Returns the NUMA node the range is on, or a negative error code: -EBUSY
 * if any of the range is not free pool memory.
 */
static int multikernel_alloc_at(phys_addr_t addr, size_t size)
{
	unsigned long start = addr;
	int nid;

	if (!mk_pool)
		return -ENODEV;
	if (!size || !PAGE_ALIGNED(addr) || !PAGE_ALIGNED(size))
		return -EINVAL;

	guard(mutex)(&mk_pool->mem_lock);
	for_each_online_node(nid) {
		struct gen_pool *pool = mk_pool->node_pools[nid];

		if (pool && gen_pool_alloc_algo(pool, size, mk_pool_algo_at,
						&start) == start)
			return nid;
	}
	return -EBUSY;
}

/**
 * multikernel_free() - Free memory back to the multikernel pool
 * @addr: physical address to free
 * @size: size to free
 */
void multikernel_free(phys_addr_t addr, size_t size)
{
	int nid;

	if (!addr || !mk_pool)
		return;

	mutex_lock(&mk_pool->mem_lock);
	for_each_online_node(nid) {
		if (mk_pool->node_pools[nid] &&
		    gen_pool_has_addr(mk_pool->node_pools[nid], addr, size)) {
			gen_pool_free(mk_pool->node_pools[nid], addr, size);
			break;
		}
	}
	mutex_unlock(&mk_pool->mem_lock);
}

static struct mk_pool_chunk *mk_pool_chunk_find(phys_addr_t addr)
{
	struct mk_pool_chunk *chunk;

	lockdep_assert_held(&mk_pool->mem_lock);
	list_for_each_entry(chunk, &mk_pool->chunks, list)
		if (addr >= chunk->res.start && addr <= chunk->res.end)
			return chunk;
	return NULL;
}

/**
 * mk_pool_chunk_resource() - Find the pool chunk resource holding an address
 * @addr: physical address inside the pool
 *
 * Returns the chunk resource, usable as an insert_resource() parent, or
 * NULL when @addr is outside the pool. The chunk cannot go away while it
 * still has child allocations, so the caller holds no reference.
 */
struct resource *mk_pool_chunk_resource(phys_addr_t addr)
{
	struct mk_pool_chunk *chunk;

	if (!mk_pool)
		return NULL;

	mutex_lock(&mk_pool->mem_lock);
	chunk = mk_pool_chunk_find(addr);
	mutex_unlock(&mk_pool->mem_lock);
	return chunk ? &chunk->res : NULL;
}

/**
 * mk_pool_empty() - Test whether the pool holds no memory at all
 */
bool mk_pool_empty(void)
{
	bool empty;

	if (!mk_pool)
		return true;

	mutex_lock(&mk_pool->mem_lock);
	empty = list_empty(&mk_pool->chunks);
	mutex_unlock(&mk_pool->mem_lock);
	return empty;
}

/**
 * mk_pool_total_bytes() - Total size of every chunk in the pool
 */
size_t mk_pool_total_bytes(void)
{
	struct mk_pool_chunk *chunk;
	size_t total = 0;

	if (!mk_pool)
		return 0;

	mutex_lock(&mk_pool->mem_lock);
	list_for_each_entry(chunk, &mk_pool->chunks, list)
		total += resource_size(&chunk->res);
	mutex_unlock(&mk_pool->mem_lock);
	return total;
}

/**
 * mk_pool_avail_bytes() - Unallocated bytes across every node pool
 */
size_t mk_pool_avail_bytes(void)
{
	size_t avail = 0;
	int nid;

	if (!mk_pool)
		return 0;

	mutex_lock(&mk_pool->mem_lock);
	for_each_online_node(nid)
		if (mk_pool->node_pools[nid])
			avail += gen_pool_avail(mk_pool->node_pools[nid]);
	mutex_unlock(&mk_pool->mem_lock);
	return avail;
}

/**
 * mk_pool_for_each_chunk() - Run a callback over every pool chunk
 * @fn: callback, stops the walk when it returns non-zero
 * @data: opaque argument passed to @fn
 *
 * @fn runs under the pool mutex, so it must not allocate from the pool.
 * Use mk_pool_snapshot_chunks() when the walk needs pool memory.
 *
 * Returns 0 or the first non-zero callback return value.
 */
int mk_pool_for_each_chunk(int (*fn)(struct mk_pool_chunk *, void *), void *data)
{
	struct mk_pool_chunk *chunk;
	int ret = 0;

	if (!mk_pool)
		return 0;

	mutex_lock(&mk_pool->mem_lock);
	list_for_each_entry(chunk, &mk_pool->chunks, list) {
		ret = fn(chunk, data);
		if (ret)
			break;
	}
	mutex_unlock(&mk_pool->mem_lock);
	return ret;
}

/**
 * mk_pool_snapshot_chunks() - Copy the chunk list into a caller-owned array
 * @out: array to fill, may be NULL when @max is 0
 * @max: entries available in @out
 *
 * Returns the number of chunks in the pool. Nothing is written when that
 * exceeds @max, so a caller sizes its array by calling with @max 0 first
 * and retries if the pool grew in between.
 */
int mk_pool_snapshot_chunks(struct mk_pool_chunk_range *out, int max)
{
	struct mk_pool_chunk *chunk;
	int n = 0;

	if (!mk_pool)
		return 0;

	mutex_lock(&mk_pool->mem_lock);
	list_for_each_entry(chunk, &mk_pool->chunks, list)
		n++;

	if (n <= max) {
		n = 0;
		list_for_each_entry(chunk, &mk_pool->chunks, list) {
			out[n].start = chunk->res.start;
			out[n].size = resource_size(&chunk->res);
			out[n].node = chunk->node;
			n++;
		}
	}
	mutex_unlock(&mk_pool->mem_lock);
	return n;
}

/**
 * Per-instance memory pool management
 *
 * Each kernel instance gets its own gen_pool for fine-grained allocations
 * (IPI data, small buffers, etc.) carved out from the main multikernel pool.
 */

/**
 * multikernel_create_instance_pool() - Create a memory pool for a kernel instance
 * @instance_id: Unique identifier for the instance
 * @pool_size: Total size of memory to allocate for this instance's pool
 * @min_alloc_order: Minimum allocation order (at least PAGE_SHIFT)
 * @node: NUMA node to allocate from, or NUMA_NO_NODE for any node
 *
 * Allocates multiple chunks from the main multikernel pool to reach the target
 * pool_size and creates a gen_pool for the instance to manage smaller allocations.
 *
 * Returns opaque handle to the instance pool, or NULL on failure
 */
void *multikernel_create_instance_pool(int instance_id, size_t pool_size,
				       int min_alloc_order, int node)
{
	struct gen_pool *instance_pool;
	size_t remaining_size = pool_size;
	size_t chunk_size;
	phys_addr_t chunk_base;
	int chunks_added = 0;

	if (mk_pool_empty()) {
		pr_err("Multikernel main pool not available for instance %d\n", instance_id);
		return NULL;
	}

	if (min_alloc_order < PAGE_SHIFT) {
		pr_err("Invalid min_alloc_order %d for instance %d (must be >= PAGE_SHIFT %d)\n",
		       min_alloc_order, instance_id, PAGE_SHIFT);
		return NULL;
	}

	instance_pool = gen_pool_create(min_alloc_order, -1);
	if (!instance_pool) {
		pr_err("Failed to create gen_pool for instance %d\n", instance_id);
		return NULL;
	}

	/* Allocate memory in chunks and add to the pool */
	while (remaining_size > 0) {
		/* Try to allocate the remaining size, but be flexible */
		chunk_size = remaining_size;
		chunk_base = multikernel_alloc(chunk_size, node);

		if (!chunk_base) {
			/*
			 * Fragmented pool: halve until a piece fits. Dropping
			 * straight to tiny chunks would splinter the grant
			 * into more regions than the spawn's memory map can carry.
			 */
			while (!chunk_base &&
			       chunk_size > (1UL << min_alloc_order)) {
				chunk_size = ALIGN_DOWN(chunk_size / 2,
							1UL << min_alloc_order);
				chunk_base = multikernel_alloc(chunk_size, node);
			}

			if (!chunk_base) {
				pr_err("Failed to allocate chunk %d for instance %d (remaining: %zu bytes)\n",
				       chunks_added + 1, instance_id, remaining_size);
				goto cleanup;
			}
		}

		/* Add the allocated chunk to the instance pool */
		if (gen_pool_add(instance_pool, chunk_base, chunk_size, -1)) {
			pr_err("Failed to add chunk %d to instance pool %d\n",
			       chunks_added + 1, instance_id);
			multikernel_free(chunk_base, chunk_size);
			goto cleanup;
		}

		chunks_added++;
		remaining_size -= chunk_size;

		pr_debug("Added chunk %d to instance pool %d: base=0x%llx, size=%zu bytes (remaining: %zu)\n",
			 chunks_added, instance_id, (unsigned long long)chunk_base,
			 chunk_size, remaining_size);
	}

	pr_info("Created instance pool %d: %d chunks, total size=%zu bytes\n",
		instance_id, chunks_added, pool_size);

	return instance_pool;

cleanup:
	/* Free all chunks that were successfully added */
	multikernel_destroy_instance_pool(instance_pool);
	return NULL;
}

/**
 * multikernel_destroy_instance_pool() - Destroy an instance memory pool
 * @pool_handle: Handle returned by multikernel_create_instance_pool()
 *
 * Frees the memory of every chunk the instance still owns back to the main
 * pool. Nothing may be allocated from the pool any more, so a chunk with no
 * space left is one whose region left the instance: its memory went back
 * then, and only the reservation holding it is dropped.
 */
void multikernel_destroy_instance_pool(void *pool_handle)
{
	struct gen_pool *instance_pool = (struct gen_pool *)pool_handle;
	struct gen_pool_chunk *chunk;

	if (!instance_pool)
		return;

	list_for_each_entry(chunk, &instance_pool->chunks, next_chunk) {
		size_t size = chunk->end_addr - chunk->start_addr + 1;

		if (!atomic_long_read(&chunk->avail)) {
			gen_pool_free(instance_pool, chunk->start_addr, size);
			continue;
		}
		multikernel_free(chunk->start_addr, size);
		pr_debug("Freed instance pool chunk: 0x%lx-0x%lx\n",
			 chunk->start_addr, chunk->end_addr);
	}

	gen_pool_destroy(instance_pool);
}

/**
 * multikernel_instance_alloc() - Allocate from an instance pool
 * @pool_handle: Handle returned by multikernel_create_instance_pool()
 * @size: Size to allocate
 * @align: Alignment requirement (must be power of 2)
 *
 * Returns physical address of allocated memory, or 0 on failure
 */
phys_addr_t multikernel_instance_alloc(void *pool_handle, size_t size, size_t align)
{
	struct gen_pool *instance_pool = (struct gen_pool *)pool_handle;
	unsigned long addr;

	if (!instance_pool)
		return 0;

	if (align <= 1) {
		addr = gen_pool_alloc(instance_pool, size);
	} else {
		/* Ensure alignment is at least the pool's minimum allocation order */
		size_t a = max_t(size_t, align, BIT(instance_pool->min_alloc_order));
		struct genpool_data_align data = { .align = a };
		addr = gen_pool_alloc_algo(instance_pool, size, gen_pool_first_fit_align, &data);
	}

	return (phys_addr_t)addr;
}

/**
 * multikernel_instance_free() - Free memory back to instance pool
 * @pool_handle: Handle returned by multikernel_create_instance_pool()
 * @addr: Physical address to free
 * @size: Size to free
 */
void multikernel_instance_free(void *pool_handle, phys_addr_t addr, size_t size)
{
	struct gen_pool *instance_pool = (struct gen_pool *)pool_handle;

	if (!instance_pool || !addr)
		return;

	gen_pool_free(instance_pool, (unsigned long)addr, size);
	pr_debug("Instance pool freed %zu bytes at 0x%llx\n", size, (unsigned long long)addr);
}

/**
 * multikernel_instance_pool_avail() - Get available space in instance pool
 * @pool_handle: Handle returned by multikernel_create_instance_pool()
 *
 * Returns available bytes in the instance pool
 */
size_t multikernel_instance_pool_avail(void *pool_handle)
{
	struct gen_pool *instance_pool = (struct gen_pool *)pool_handle;

	if (!instance_pool)
		return 0;

	return gen_pool_avail(instance_pool);
}

/*
 * Every region of an instance is one chunk of its instance pool, which is
 * where its kernel image and control block are allocated from. A region that
 * leaves the instance keeps its chunk, reserved in full, since a gen_pool
 * cannot give a chunk back.
 */
static int mk_instance_pool_add(struct mk_instance *instance, phys_addr_t phys_addr,
				size_t size, int node)
{
	if (!instance->instance_pool) {
		instance->instance_pool = gen_pool_create(PAGE_SHIFT, -1);
		if (!instance->instance_pool)
			return -ENOMEM;
	}

	if (gen_pool_add(instance->instance_pool, phys_addr, size, node))
		return -ENOMEM;
	instance->pool_size += size;
	return 0;
}

/* gen_pool algorithm: all of the chunk that starts at *data, or nothing */
static unsigned long mk_whole_chunk_algo(unsigned long *map, unsigned long size,
					 unsigned long start, unsigned int nr,
					 void *data, struct gen_pool *pool,
					 unsigned long start_addr)
{
	if (start_addr != *(unsigned long *)data || nr != size)
		return size;
	return bitmap_find_next_zero_area(map, size, 0, nr, 0) ? size : 0;
}

/* Reserve a region's whole chunk, or fail if anything is allocated in it */
static int mk_instance_pool_reserve(struct mk_instance *instance,
				    phys_addr_t phys_addr, size_t size)
{
	unsigned long start = phys_addr;

	if (gen_pool_alloc_algo(instance->instance_pool, size,
				mk_whole_chunk_algo, &start) != start)
		return -EBUSY;
	instance->pool_size -= size;
	return 0;
}

static struct mk_memory_region *mk_instance_find_region(struct mk_instance *instance,
							phys_addr_t phys_addr, size_t size)
{
	struct mk_memory_region *region;

	list_for_each_entry(region, &instance->memory_regions, list)
		if (region->res.start == phys_addr &&
		    resource_size(&region->res) == size)
			return region;
	return NULL;
}

/**
 * mk_instance_add_memory_region() - Add a memory region to an instance
 * @instance: Target instance
 * @phys_addr: Physical address of the region, page aligned
 * @size: Size of the region, page aligned
 *
 * Takes the region out of the main multikernel pool and adds it to the
 * instance's memory_regions list. The region is the one the instance's
 * kernel is told to add, so no other instance can be given it.
 *
 * Returns: 0 on success, -EBUSY if the region is not free pool memory, or
 * another negative error code
 */
int mk_instance_add_memory_region(struct mk_instance *instance,
				  phys_addr_t phys_addr, size_t size)
{
	struct mk_memory_region *region;
	struct resource *parent;
	int node, ret;

	node = multikernel_alloc_at(phys_addr, size);
	if (node < 0) {
		pr_err("Failed to take 0x%llx-0x%llx from multikernel pool for instance %d: %d\n",
		       (unsigned long long)phys_addr,
		       (unsigned long long)(phys_addr + size - 1),
		       instance->id, node);
		return node;
	}

	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region) {
		multikernel_free(phys_addr, size);
		return -ENOMEM;
	}

	region->res.name = kasprintf(GFP_KERNEL, "mk-instance-%d-%s-region-%d",
				     instance->id, instance->name, instance->region_count);
	if (!region->res.name) {
		kfree(region);
		multikernel_free(phys_addr, size);
		return -ENOMEM;
	}

	region->res.start = phys_addr;
	region->res.end = phys_addr + size - 1;
	region->res.flags = IORESOURCE_MEM | IORESOURCE_BUSY;

	parent = mk_pool_chunk_resource(phys_addr);
	ret = parent ? insert_resource(parent, &region->res) : -ENODEV;
	if (ret) {
		pr_err("Failed to insert resource for instance %d region %d: %d\n",
		       instance->id, instance->region_count, ret);
		kfree(region->res.name);
		kfree(region);
		multikernel_free(phys_addr, size);
		return ret;
	}

	ret = mk_instance_pool_add(instance, phys_addr, size, node);
	if (ret) {
		remove_resource(&region->res);
		kfree(region->res.name);
		kfree(region);
		multikernel_free(phys_addr, size);
		return ret;
	}

	INIT_LIST_HEAD(&region->list);
	list_add_tail(&region->list, &instance->memory_regions);
	instance->region_count++;

	pr_info("Added memory region 0x%llx-0x%llx (%zu MB) to instance %d (%s)\n",
		(unsigned long long)phys_addr, (unsigned long long)(phys_addr + size - 1),
		size >> 20, instance->id, instance->name);

	return 0;
}

/**
 * mk_instance_begin_memory_removal() - Take a region away from the instance pool
 * @instance: Target instance
 * @phys_addr: Physical address of the memory region
 * @size: Size of the memory region
 *
 * Reserves the region's chunk so nothing more is allocated from it. Follow
 * with mk_instance_finish_memory_removal(), or with
 * mk_instance_abort_memory_removal() if the region has to stay.
 *
 * Returns: 0 on success, -ENOENT if no region matches exactly, -EBUSY if the
 * instance's kernel image or control block lives in it
 */
int mk_instance_begin_memory_removal(struct mk_instance *instance,
				     phys_addr_t phys_addr, size_t size)
{
	if (!mk_instance_find_region(instance, phys_addr, size)) {
		pr_warn("Memory region 0x%llx-0x%llx not found in instance %d (%s)\n",
			(unsigned long long)phys_addr,
			(unsigned long long)(phys_addr + size - 1),
			instance->id, instance->name);
		return -ENOENT;
	}

	if (mk_instance_pool_reserve(instance, phys_addr, size)) {
		pr_err("Refusing to remove 0x%llx-0x%llx from instance %d (%s): its kernel image or control block lives there\n",
		       (unsigned long long)phys_addr,
		       (unsigned long long)(phys_addr + size - 1),
		       instance->id, instance->name);
		return -EBUSY;
	}
	return 0;
}

/**
 * mk_instance_abort_memory_removal() - Give a region back to the instance pool
 * @instance: Target instance
 * @phys_addr: Physical address of the memory region
 * @size: Size of the memory region
 */
void mk_instance_abort_memory_removal(struct mk_instance *instance,
				      phys_addr_t phys_addr, size_t size)
{
	gen_pool_free(instance->instance_pool, phys_addr, size);
	instance->pool_size += size;
}

/**
 * mk_instance_finish_memory_removal() - Hand a region back to the multikernel pool
 * @instance: Target instance
 * @phys_addr: Physical address of the memory region
 * @size: Size of the memory region
 *
 * The region must have been through mk_instance_begin_memory_removal().
 */
void mk_instance_finish_memory_removal(struct mk_instance *instance,
				       phys_addr_t phys_addr, size_t size)
{
	struct mk_memory_region *region;

	region = mk_instance_find_region(instance, phys_addr, size);
	list_del(&region->list);
	if (region->res.parent)
		remove_resource(&region->res);

	multikernel_free(phys_addr, size);

	kfree(region->res.name);
	kfree(region);
	instance->region_count--;

	pr_info("Removed memory region 0x%llx-0x%llx (%zu MB) from instance %d (%s)\n",
		(unsigned long long)phys_addr,
		(unsigned long long)(phys_addr + size - 1),
		size >> 20, instance->id, instance->name);
}

/**
 * mk_instance_remove_memory_region() - Remove a memory region from an instance
 * @instance: Target instance
 * @phys_addr: Physical address of the memory region
 * @size: Size of the memory region
 *
 * For instances not running a kernel, where no hotplug is involved.
 *
 * Returns: 0 on success, or an error from mk_instance_begin_memory_removal()
 */
int mk_instance_remove_memory_region(struct mk_instance *instance,
				     phys_addr_t phys_addr, size_t size)
{
	int ret;

	if (!instance)
		return -EINVAL;

	ret = mk_instance_begin_memory_removal(instance, phys_addr, size);
	if (!ret)
		mk_instance_finish_memory_removal(instance, phys_addr, size);
	return ret;
}

/*
 * Pool chunks are hot-removed from this kernel: their pages, struct
 * pages and direct mapping all go, so no stray pointer here can reach
 * memory another kernel runs on. Zones are scanned from the top down
 * (higher addresses are less likely to hold pinned kernel allocations),
 * ZONE_MOVABLE before ZONE_NORMAL.
 */
static int mk_take_from_zone(struct zone *zone, u64 size, phys_addr_t *start)
{
	const unsigned long step = PHYS_PFN(MHP_SUBSECTIONS_ALIGN);
	unsigned long nr_pages = PHYS_PFN(size);
	unsigned long first = ALIGN(zone->zone_start_pfn, step);
	unsigned long candidate;

	if (!populated_zone(zone) || zone_end_pfn(zone) < first + nr_pages)
		return -ENOMEM;

	candidate = ALIGN_DOWN(zone_end_pfn(zone) - nr_pages, step);
	for (;;) {
		if (!offline_and_remove_subsections(PFN_PHYS(candidate), size)) {
			*start = PFN_PHYS(candidate);
			return 0;
		}
		if (candidate < first + step)
			return -ENOMEM;
		candidate -= step;
		cond_resched();
	}
}

/**
 * mk_take_memory() - Hot-remove a contiguous range for the pool
 * @size: bytes, a multiple of MHP_SUBSECTIONS_ALIGN
 * @node: NUMA node to take from, or NUMA_NO_NODE for any node
 * @start: physical base of the range taken
 * @nid: node the range was taken from
 * @movable: whether it was ZONE_MOVABLE, to give it back there
 *
 * Returns 0 on success, -ENOMEM when no range of @size could be removed.
 */
static int mk_take_memory(u64 size, int node, phys_addr_t *start, int *nid,
			  bool *movable)
{
	static const enum zone_type zone_order[] = { ZONE_MOVABLE, ZONE_NORMAL };
	int n, i;

	for_each_online_node(n) {
		if (node != NUMA_NO_NODE && n != node)
			continue;

		for (i = 0; i < ARRAY_SIZE(zone_order); i++) {
			if (mk_take_from_zone(&NODE_DATA(n)->node_zones[zone_order[i]],
					      size, start))
				continue;
			*nid = n;
			*movable = zone_order[i] == ZONE_MOVABLE;
			return 0;
		}
	}
	return -ENOMEM;
}

static DEFINE_MUTEX(mk_pool_map_lock);

/**
 * mk_pool_map() - Map part of the pool back at its direct-map address
 * @start: physical base, page aligned
 * @size: bytes, page aligned
 *
 * The pool is hot-removed from this kernel. What this kernel keeps in it
 * for itself, the park area and each instance's control block, it reads,
 * writes and executes through __va(), so exactly those pages come back.
 * The lock keeps two mappers from populating the same page table page,
 * and holding the online memory stable keeps memory hotplug out of it.
 */
int mk_pool_map(phys_addr_t start, size_t size)
{
	int ret;

	guard(mutex)(&mk_pool_map_lock);
	get_online_mems();
	ret = mk_arch_pool_map(start, size);
	put_online_mems();
	return ret;
}

int mk_pool_unmap(phys_addr_t start, size_t size)
{
	int ret;

	guard(mutex)(&mk_pool_map_lock);
	get_online_mems();
	ret = mk_arch_pool_unmap(start, size);
	put_online_mems();
	return ret;
}

static void mk_pool_chunk_return(struct mk_pool_chunk *chunk)
{
	int online_type = chunk->movable ? MMOP_ONLINE_MOVABLE : MMOP_ONLINE_KERNEL;
	int ret = add_and_online_subsections(chunk->node, chunk->res.start,
					     resource_size(&chunk->res),
					     online_type, "System RAM");

	if (ret)
		pr_err("Multikernel pool: %pa-%pa could not be given back to the kernel: %d\n",
		       &chunk->res.start, &chunk->res.end, ret);
	kfree(chunk);
}

/**
 * mk_pool_mem_grow() - Take a contiguous chunk out of this kernel for the pool
 * @size: chunk size in bytes, page aligned; rounded up to MHP_SUBSECTIONS_ALIGN
 * @node: NUMA node to allocate from, or NUMA_NO_NODE for any node
 * @out_base: optional output for the physical base of the new chunk
 *
 * The chunk is hot-removed until mk_pool_mem_shrink() returns it: spawn
 * kernels execute out of it, and this kernel keeps no mapping of it
 * beyond what mk_pool_map() brings back.
 *
 * Returns 0 on success, negative error code on failure.
 */
int mk_pool_mem_grow(size_t size, int node, phys_addr_t *out_base)
{
	struct mk_pool_chunk *chunk;
	struct gen_pool *pool;
	phys_addr_t start;
	int node_id;
	int ret;

	if (!size || !PAGE_ALIGNED(size))
		return -EINVAL;
	if (!mk_pool)
		return -ENODEV;
	if (node != NUMA_NO_NODE && (node < 0 || node >= MAX_NUMNODES ||
				     !node_online(node)))
		return -EINVAL;

	chunk = kzalloc_obj(*chunk, GFP_KERNEL);
	if (!chunk)
		return -ENOMEM;

	size = ALIGN(size, MHP_SUBSECTIONS_ALIGN);
	ret = mk_take_memory(size, node, &start, &chunk->node, &chunk->movable);
	if (ret) {
		kfree(chunk);
		return ret;
	}
	chunk->res.name = "Multikernel Memory Pool";
	chunk->res.start = start;
	chunk->res.end = start + size - 1;
	chunk->res.flags = IORESOURCE_BUSY | IORESOURCE_MEM;
	chunk->res.desc = IORES_DESC_RESERVED;

	mutex_lock(&mk_pool->mem_lock);
	pool = mk_node_pool_get(chunk->node);
	if (!pool) {
		ret = -ENOMEM;
		goto err_unlock;
	}
	ret = gen_pool_add(pool, chunk->res.start, size, chunk->node);
	if (ret)
		goto err_unlock;
	if (insert_resource(&iomem_resource, &chunk->res))
		pr_warn("Multikernel pool: chunk %pa not registered in /proc/iomem\n",
			&chunk->res.start);
	list_add_tail(&chunk->list, &mk_pool->chunks);
	/* A concurrent shrink may free @chunk once the mutex is dropped */
	start = chunk->res.start;
	node_id = chunk->node;
	mutex_unlock(&mk_pool->mem_lock);

	ret = mk_arch_pool_chunk_added(start, size);
	if (ret) {
		mk_pool_mem_shrink(start, size);
		return ret;
	}

	pr_info("Multikernel pool: added %pa (%zu MB) on node %d\n",
		&start, size >> 20, node_id);
	if (out_base)
		*out_base = start;
	return 0;

err_unlock:
	mutex_unlock(&mk_pool->mem_lock);
	mk_pool_chunk_return(chunk);
	return ret;
}

/**
 * mk_pool_mem_shrink() - Remove a pool chunk and return it to the kernel
 * @start: physical base of the chunk, exactly as reported by the grow
 * @size: chunk size in bytes
 *
 * Returns 0 on success, -ENOENT when no chunk matches @start and @size,
 * -EBUSY when the chunk still has outstanding allocations.
 */
int mk_pool_mem_shrink(phys_addr_t start, size_t size)
{
	struct mk_pool_chunk *chunk;
	int ret;

	if (!mk_pool)
		return -ENOENT;

	mutex_lock(&mk_pool->mem_lock);
	chunk = mk_pool_chunk_find(start);
	if (!chunk || chunk->res.start != start ||
	    resource_size(&chunk->res) != size) {
		mutex_unlock(&mk_pool->mem_lock);
		return -ENOENT;
	}
	ret = gen_pool_remove_chunk(mk_pool->node_pools[chunk->node], start, size);
	if (ret) {
		mutex_unlock(&mk_pool->mem_lock);
		return ret;
	}
	list_del(&chunk->list);
	mutex_unlock(&mk_pool->mem_lock);

	if (chunk->res.parent)
		remove_resource(&chunk->res);
	pr_info("Multikernel pool: removed %pa-%pa (%zu MB)\n",
		&chunk->res.start, &chunk->res.end, size >> 20);
	/* The pool park table keeps the stale range mapped, but never dereferences it */
	mk_pool_chunk_return(chunk);
	return 0;
}
