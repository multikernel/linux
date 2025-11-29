// SPDX-License-Identifier: GPL-2.0-only
/*
 * Multikernel memory management
 *
 * Memory pool management for multikernel spawn kernels using gen_pool
 * with mkkernel_pool= command line parameter
 */

#include <linux/memblock.h>
#include <linux/ioport.h>
#include <linux/kexec.h>
#include <linux/mutex.h>
#include <linux/genalloc.h>
#include <linux/io.h>
#include <asm/e820/api.h>
#include <linux/multikernel.h>

/* Global multikernel memory pool resource */
struct resource multikernel_res = {
	.name  = "Multikernel Memory Pool",
	.start = 0,
	.end   = 0,
	.flags = IORESOURCE_BUSY | IORESOURCE_MEM,
	.desc  = IORES_DESC_RESERVED
};

/* Generic pool for runtime memory allocation */
static struct gen_pool *multikernel_pool;

static DEFINE_MUTEX(multikernel_mem_mutex);

/**
 * multikernel_alloc() - Allocate memory from multikernel pool
 * @size: size to allocate
 *
 * Returns physical address of allocated memory, or 0 on failure
 */
phys_addr_t multikernel_alloc(size_t size)
{
	unsigned long addr;

	if (!multikernel_pool)
		return 0;

	mutex_lock(&multikernel_mem_mutex);
	addr = gen_pool_alloc(multikernel_pool, size);
	mutex_unlock(&multikernel_mem_mutex);

	return (phys_addr_t)addr;
}

/**
 * multikernel_free() - Free memory back to multikernel pool
 * @addr: physical address to free
 * @size: size to free
 */
void multikernel_free(phys_addr_t addr, size_t size)
{
	if (!multikernel_pool || !addr)
		return;

	mutex_lock(&multikernel_mem_mutex);
	gen_pool_free(multikernel_pool, (unsigned long)addr, size);
	mutex_unlock(&multikernel_mem_mutex);

	pr_debug("Multikernel freed %zu bytes at %pa\n", size, &addr);
}

/**
 * multikernel_get_pool_resource() - Get the multikernel pool resource
 *
 * Returns pointer to the multikernel pool resource for memory walking
 */
struct resource *multikernel_get_pool_resource(void)
{
	if (!multikernel_res.start)
		return NULL;

	return &multikernel_res;
}

/**
 * multikernel_pool_available() - Check if multikernel pool is available
 *
 * Returns true if multikernel pool is configured and available
 */
bool multikernel_pool_available(void)
{
	return multikernel_pool != NULL;
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
 *
 * Allocates multiple chunks from the main multikernel pool to reach the target
 * pool_size and creates a gen_pool for the instance to manage smaller allocations.
 *
 * Returns opaque handle to the instance pool, or NULL on failure
 */
void *multikernel_create_instance_pool(int instance_id, size_t pool_size, int min_alloc_order)
{
	struct gen_pool *instance_pool;
	size_t remaining_size = pool_size;
	size_t chunk_size;
	phys_addr_t chunk_base;
	int chunks_added = 0;

	if (!multikernel_pool_available()) {
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
		chunk_base = multikernel_alloc(chunk_size);

		if (!chunk_base) {
			/* If we can't get the full remaining size, try smaller chunks */
			if (chunk_size > (1024 * 1024)) {
				/* Try 1MB chunks */
				chunk_size = 1024 * 1024;
				chunk_base = multikernel_alloc(chunk_size);
			}

			if (!chunk_base && chunk_size > (256 * 1024)) {
				/* Try 256KB chunks */
				chunk_size = 256 * 1024;
				chunk_base = multikernel_alloc(chunk_size);
			}

			if (!chunk_base && chunk_size > (1 << min_alloc_order)) {
				/* Try minimum allocation size */
				chunk_size = 1 << min_alloc_order;
				chunk_base = multikernel_alloc(chunk_size);
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
 *
 * Allocates memory from the main multikernel pool and adds it to the
 * instance's memory_regions list. Used for non-running instances where
 * we only need to track memory allocation without performing memory
 * hotplug operations.
 *
 * Returns: 0 on success, negative error code on failure
 */
int mk_instance_add_memory_region(struct mk_instance *instance, size_t size)
{
	struct mk_memory_region *region;
	phys_addr_t phys_addr;
	int ret;

	phys_addr = multikernel_alloc(size);
	if (!phys_addr) {
		pr_err("Failed to allocate %zu bytes from multikernel pool for instance %d\n",
		       size, instance->id);
		return -ENOMEM;
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
	region->res.flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;
	region->chunk = NULL;  /* For overlay-added regions */

	ret = insert_resource(&multikernel_res, &region->res);
	if (ret) {
		pr_err("Failed to insert resource for instance %d region %d: %d\n",
		       instance->id, instance->region_count, ret);
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

	if (!instance)
		return -EINVAL;

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
		return -ENOENT;
	}

	return 0;
}

static int __init mkkernel_pool_setup(char *str)
{
	char *cur = str;
	unsigned long long size, start;

	if (!str)
		return -EINVAL;

	size = memparse(cur, &cur);
	if (size == 0) {
		pr_err("mkkernel_pool: invalid size\n");
		return -EINVAL;
	}

	/* Expect '@' separator, or end of string for dynamic allocation */
	if (*cur == '@') {
		cur++;
		/* Parse start address */
		start = memparse(cur, &cur);
		if (start == 0) {
			pr_err("mkkernel_pool: invalid start address\n");
			return -EINVAL;
		}
	} else if (*cur == '\0') {
		/* No address specified, use dynamic allocation */
		start = 0;
	} else {
		pr_err("mkkernel_pool: expected '@' or end of string after size\n");
		return -EINVAL;
	}

	/* Reserve the memory using the proper memblock reservation approach */
	phys_addr_t reserved_addr;
	if (start != 0) {
		/* Reserve at the user-specified address */
		pr_info("mkkernel_pool: trying to reserve at specific address %llx\n", start);
		if (memblock_reserve(start, size)) {
			pr_err("mkkernel_pool: failed to reserve at specified address %llx\n", start);
			return -ENOMEM;
		}
		reserved_addr = start;
		pr_info("mkkernel_pool: successfully reserved at requested address %llx\n", start);
	} else {
		/* Dynamic allocation */
		pr_info("mkkernel_pool: trying dynamic allocation\n");
		reserved_addr = memblock_phys_alloc(size, PAGE_SIZE);
		if (!reserved_addr) {
			pr_err("mkkernel_pool: failed to allocate %llu bytes\n", size);
			return -ENOMEM;
		}
		pr_info("mkkernel_pool: dynamic allocation succeeded at %pa\n", &reserved_addr);
	}

	multikernel_res.start = reserved_addr;
	multikernel_res.end = reserved_addr + size - 1;

	pr_info("Multikernel pool: %pa-%pa (%lluMB) allocated\n",
		    &multikernel_res.start, &multikernel_res.end, (unsigned long long)size >> 20);

	return 0;
}
early_param("mkkernel_pool", mkkernel_pool_setup);

static int __init multikernel_mem_init(void)
{
	if (multikernel_res.start) {
		/* Create the generic pool */
		multikernel_pool = gen_pool_create(PAGE_SHIFT, -1);
		if (!multikernel_pool) {
			pr_err("Failed to create multikernel memory pool\n");
			return -ENOMEM;
		}

		/* Add the reserved memory to the pool */
		if (gen_pool_add(multikernel_pool, multikernel_res.start,
				 multikernel_res.end - multikernel_res.start + 1, -1)) {
			pr_err("Failed to add memory to multikernel pool\n");
			gen_pool_destroy(multikernel_pool);
			multikernel_pool = NULL;
			return -ENOMEM;
		}

		if (insert_resource(&iomem_resource, &multikernel_res)) {
			pr_warn("mkkernel_pool: failed to register in /proc/iomem\n");
		} else {
			pr_info("mkkernel_pool: successfully registered in /proc/iomem\n");
		}

		pr_info("Multikernel memory pool initialized: %pa-%pa\n",
			&multikernel_res.start, &multikernel_res.end);
	} else {
		pr_info("No multikernel pool found - multikernel support disabled\n");
	}

	return 0;
}
core_initcall(multikernel_mem_init);
