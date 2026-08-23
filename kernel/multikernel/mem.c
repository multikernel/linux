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
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <linux/multikernel.h>

#include "internal.h"

static struct gen_pool *mk_node_pools[MAX_NUMNODES];
static LIST_HEAD(mk_pool_chunks);
static DEFINE_MUTEX(multikernel_mem_mutex);

static struct gen_pool *mk_node_pool_get(int node)
{
	if (mk_node_pools[node])
		return mk_node_pools[node];

	mk_node_pools[node] = gen_pool_create(PAGE_SHIFT, node);
	return mk_node_pools[node];
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

	mutex_lock(&multikernel_mem_mutex);
	if (node != NUMA_NO_NODE) {
		if (mk_node_pools[node])
			addr = gen_pool_alloc(mk_node_pools[node], size);
	} else {
		for_each_online_node(nid) {
			if (!mk_node_pools[nid])
				continue;
			addr = gen_pool_alloc(mk_node_pools[nid], size);
			if (addr)
				break;
		}
	}
	mutex_unlock(&multikernel_mem_mutex);

	return (phys_addr_t)addr;
}

/**
 * multikernel_free() - Free memory back to the multikernel pool
 * @addr: physical address to free
 * @size: size to free
 */
void multikernel_free(phys_addr_t addr, size_t size)
{
	int nid;

	if (!addr)
		return;

	mutex_lock(&multikernel_mem_mutex);
	for_each_online_node(nid) {
		if (mk_node_pools[nid] &&
		    gen_pool_has_addr(mk_node_pools[nid], addr, size)) {
			gen_pool_free(mk_node_pools[nid], addr, size);
			break;
		}
	}
	mutex_unlock(&multikernel_mem_mutex);
}

static struct mk_pool_chunk *mk_pool_chunk_find(phys_addr_t addr)
{
	struct mk_pool_chunk *chunk;

	lockdep_assert_held(&multikernel_mem_mutex);
	list_for_each_entry(chunk, &mk_pool_chunks, list)
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

	mutex_lock(&multikernel_mem_mutex);
	chunk = mk_pool_chunk_find(addr);
	mutex_unlock(&multikernel_mem_mutex);
	return chunk ? &chunk->res : NULL;
}

/**
 * mk_pool_empty() - Test whether the pool holds no memory at all
 */
bool mk_pool_empty(void)
{
	bool empty;

	mutex_lock(&multikernel_mem_mutex);
	empty = list_empty(&mk_pool_chunks);
	mutex_unlock(&multikernel_mem_mutex);
	return empty;
}

/**
 * mk_pool_total_bytes() - Total size of every chunk in the pool
 */
size_t mk_pool_total_bytes(void)
{
	struct mk_pool_chunk *chunk;
	size_t total = 0;

	mutex_lock(&multikernel_mem_mutex);
	list_for_each_entry(chunk, &mk_pool_chunks, list)
		total += resource_size(&chunk->res);
	mutex_unlock(&multikernel_mem_mutex);
	return total;
}

/**
 * mk_pool_avail_bytes() - Unallocated bytes across every node pool
 */
size_t mk_pool_avail_bytes(void)
{
	size_t avail = 0;
	int nid;

	mutex_lock(&multikernel_mem_mutex);
	for_each_online_node(nid)
		if (mk_node_pools[nid])
			avail += gen_pool_avail(mk_node_pools[nid]);
	mutex_unlock(&multikernel_mem_mutex);
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

	mutex_lock(&multikernel_mem_mutex);
	list_for_each_entry(chunk, &mk_pool_chunks, list) {
		ret = fn(chunk, data);
		if (ret)
			break;
	}
	mutex_unlock(&multikernel_mem_mutex);
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

	mutex_lock(&multikernel_mem_mutex);
	list_for_each_entry(chunk, &mk_pool_chunks, list)
		n++;

	if (n <= max) {
		n = 0;
		list_for_each_entry(chunk, &mk_pool_chunks, list) {
			out[n].start = chunk->res.start;
			out[n].size = resource_size(&chunk->res);
			out[n].node = chunk->node;
			n++;
		}
	}
	mutex_unlock(&multikernel_mem_mutex);
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
			 * into more regions than an E820 table can carry.
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
 * Frees all memory associated with the instance pool back to the main pool
 */
void multikernel_destroy_instance_pool(void *pool_handle)
{
	struct gen_pool *instance_pool = (struct gen_pool *)pool_handle;
	struct gen_pool_chunk *chunk;

	if (!instance_pool)
		return;

	/* Free all chunks back to main pool */
	list_for_each_entry(chunk, &instance_pool->chunks, next_chunk) {
		multikernel_free(chunk->start_addr, chunk->end_addr - chunk->start_addr + 1);
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

/**
 * mk_instance_add_memory_region() - Add a memory region to an instance
 * @instance: Target instance
 * @size: Size of the memory region to allocate
 * @node: NUMA node to allocate from, or NUMA_NO_NODE for any node
 *
 * Allocates memory from the main multikernel pool and adds it to the
 * instance's memory_regions list. Used for non-running instances where
 * we only need to track memory allocation without performing memory
 * hotplug operations.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_add_memory_region(struct mk_instance *instance, size_t size,
				  int node)
{
	struct mk_memory_region *region;
	struct resource *parent;
	phys_addr_t phys_addr;
	int ret;

	if (!instance)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	if (mk_pci_iommu_lease_active_locked(instance)) {
		pr_err("Cannot add memory to instance %d while an IOMMU lease is active\n",
		       instance->id);
		ret = -EBUSY;
		goto out_unlock;
	}

	phys_addr = multikernel_alloc(size, node);
	if (!phys_addr) {
		pr_err("Failed to allocate %zu bytes from multikernel pool for instance %d\n",
		       size, instance->id);
		ret = -ENOMEM;
		goto out_unlock;
	}

	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region) {
		multikernel_free(phys_addr, size);
		ret = -ENOMEM;
		goto out_unlock;
	}

	region->res.name = kasprintf(GFP_KERNEL, "mk-instance-%d-%s-region-%d",
				     instance->id, instance->name, instance->region_count);
	if (!region->res.name) {
		kfree(region);
		multikernel_free(phys_addr, size);
		ret = -ENOMEM;
		goto out_unlock;
	}

	region->res.start = phys_addr;
	region->res.end = phys_addr + size - 1;
	region->res.flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;
	region->chunk = NULL;  /* For overlay-added regions */

	parent = mk_pool_chunk_resource(phys_addr);
	ret = parent ? insert_resource(parent, &region->res) : -ENODEV;
	if (ret) {
		pr_err("Failed to insert resource for instance %d region %d: %d\n",
		       instance->id, instance->region_count, ret);
		kfree(region->res.name);
		kfree(region);
		multikernel_free(phys_addr, size);
		goto out_unlock;
	}

	INIT_LIST_HEAD(&region->list);
	list_add_tail(&region->list, &instance->memory_regions);
	instance->region_count++;

	pr_info("Added memory region 0x%llx-0x%llx (%zu MB) to instance %d (%s)\n",
		(unsigned long long)phys_addr, (unsigned long long)(phys_addr + size - 1),
		size >> 20, instance->id, instance->name);

	ret = 0;
out_unlock:
	mutex_unlock(&instance->resource_mutex);
	return ret;
}

/* Does [phys_addr, phys_addr+size) back a segment of the loaded image? */
static bool mk_range_backs_kimage(struct mk_instance *instance,
				  phys_addr_t phys_addr, size_t size)
{
	struct kimage *image = instance->kimage;
	unsigned long i;

	if (!image)
		return false;

	for (i = 0; i < image->nr_segments; i++) {
		unsigned long start = image->segment[i].mem;
		unsigned long end = start + image->segment[i].memsz;

		if (phys_addr < end && start < phys_addr + size)
			return true;
	}

	return false;
}

/**
 * mk_instance_remove_memory_region() - Remove a memory region from an instance
 * @instance: Target instance
 * @phys_addr: Physical address of the memory region
 * @size: Size of the memory region
 *
 * Removes a memory region from the instance's memory_regions list and
 * frees it back to the main multikernel pool. Used for non-running instances
 * where we only need to track memory deallocation without performing memory
 * hotplug operations.
 *
 * Returns: 0 on success, -ENOENT if region not found
 */
int mk_instance_remove_memory_region(struct mk_instance *instance,
				     phys_addr_t phys_addr, size_t size)
{
	struct mk_memory_region *region, *tmp;
	bool found = false;
	int ret;

	if (!instance)
		return -EINVAL;

	mutex_lock(&instance->resource_mutex);
	if (mk_range_backs_kimage(instance, phys_addr, size)) {
		pr_err("Refusing to remove 0x%llx-0x%llx from instance %d (%s): the loaded kernel image lives there\n",
		       (unsigned long long)phys_addr,
		       (unsigned long long)(phys_addr + size - 1),
		       instance->id, instance->name);
		ret = -EBUSY;
		goto out_unlock;
	}

	if (mk_pci_iommu_lease_active_locked(instance)) {
		pr_err("Cannot remove memory from instance %d while an IOMMU lease is active\n",
		       instance->id);
		ret = -EBUSY;
		goto out_unlock;
	}

	list_for_each_entry_safe(region, tmp, &instance->memory_regions, list) {
		if (region->res.start == phys_addr &&
		    resource_size(&region->res) == size) {
			list_del(&region->list);
			if (region->res.parent)
				remove_resource(&region->res);

			multikernel_free(phys_addr, size);

			kfree(region->res.name);
			kfree(region);
			instance->region_count--;
			found = true;

			pr_info("Removed memory region 0x%llx-0x%llx (%zu MB) from instance %d (%s)\n",
				(unsigned long long)phys_addr,
				(unsigned long long)(phys_addr + size - 1),
				size >> 20, instance->id, instance->name);
			break;
		}
	}

	if (!found) {
		pr_warn("Memory region 0x%llx-0x%llx not found in instance %d (%s)\n",
			(unsigned long long)phys_addr,
			(unsigned long long)(phys_addr + size - 1),
			instance->id, instance->name);
		ret = -ENOENT;
	} else {
		ret = 0;
	}

out_unlock:
	mutex_unlock(&instance->resource_mutex);
	return ret;
}

/**
 * mk_pool_mem_grow() - Allocate a contiguous chunk and add it to the pool
 * @size: chunk size in bytes, page aligned
 * @node: NUMA node to allocate from, or NUMA_NO_NODE for any node
 * @out_base: optional output for the physical base of the new chunk
 *
 * The chunk is owned by the kernel until mk_pool_mem_shrink() returns it,
 * and is never handed back to the buddy allocator behind the pool's back:
 * spawn kernels execute out of it.
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
	if (node != NUMA_NO_NODE && (node < 0 || node >= MAX_NUMNODES ||
				     !node_online(node)))
		return -EINVAL;

	chunk = kzalloc_obj(*chunk, GFP_KERNEL);
	if (!chunk)
		return -ENOMEM;

	chunk->nr_pages = size >> PAGE_SHIFT;
	chunk->pages = mk_alloc_contig_pages(chunk->nr_pages, node);
	if (!chunk->pages) {
		kfree(chunk);
		return -ENOMEM;
	}
	chunk->node = page_to_nid(chunk->pages);
	chunk->res.name = "Multikernel Memory Pool";
	chunk->res.start = page_to_phys(chunk->pages);
	chunk->res.end = chunk->res.start + size - 1;
	chunk->res.flags = IORESOURCE_BUSY | IORESOURCE_MEM;
	chunk->res.desc = IORES_DESC_RESERVED;

	mutex_lock(&multikernel_mem_mutex);
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
	list_add_tail(&chunk->list, &mk_pool_chunks);
	/* A concurrent shrink may free @chunk once the mutex is dropped */
	start = chunk->res.start;
	node_id = chunk->node;
	mutex_unlock(&multikernel_mem_mutex);

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
	mutex_unlock(&multikernel_mem_mutex);
	mk_free_contig_pages(chunk->pages, chunk->nr_pages);
	kfree(chunk);
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

	mutex_lock(&multikernel_mem_mutex);
	chunk = mk_pool_chunk_find(start);
	if (!chunk || chunk->res.start != start ||
	    resource_size(&chunk->res) != size) {
		mutex_unlock(&multikernel_mem_mutex);
		return -ENOENT;
	}
	ret = gen_pool_remove_chunk(mk_node_pools[chunk->node], start, size);
	if (ret) {
		mutex_unlock(&multikernel_mem_mutex);
		return ret;
	}
	list_del(&chunk->list);
	mutex_unlock(&multikernel_mem_mutex);

	if (chunk->res.parent)
		remove_resource(&chunk->res);
	/* The host park table keeps the stale range mapped, but never dereferences it */
	mk_free_contig_pages(chunk->pages, chunk->nr_pages);
	pr_info("Multikernel pool: removed %pa-%pa (%zu MB)\n",
		&chunk->res.start, &chunk->res.end, size >> 20);
	kfree(chunk);
	return 0;
}
