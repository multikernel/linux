// SPDX-License-Identifier: GPL-2.0
/*
 * Multikernel DMA-BUF Heap
 *
 * Provides a DMA heap interface for allocating memory from the
 * multikernel memory pool. This allows userspace to allocate
 * shared memory via standard dma-buf APIs.
 *
 * Usage:
 *   fd = open("/dev/dma_heap/multikernel", O_RDWR);
 *   ioctl(fd, DMA_HEAP_IOCTL_ALLOC, &alloc);
 *   // alloc.fd is the dma-buf fd
 *   ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, alloc.fd, 0);
 */

#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/multikernel.h>

#include "internal.h"

struct mk_heap_buffer {
	struct dma_heap *heap;
	struct list_head attachments;
	struct mutex lock;
	unsigned long len;
	phys_addr_t phys_addr;
	void *vaddr;
	struct sg_table sg_table;
	int vmap_cnt;
	struct resource *res;		/* /proc/iomem entry */
};

struct mk_heap_attachment {
	struct device *dev;
	struct sg_table table;
	struct list_head list;
	bool mapped;
};

static struct sg_table *mk_heap_map_dma_buf(struct dma_buf_attachment *attach,
					    enum dma_data_direction dir)
{
	struct mk_heap_attachment *a = attach->priv;
	struct sg_table *table = &a->table;
	int ret;

	ret = dma_map_sgtable(attach->dev, table, dir, 0);
	if (ret)
		return ERR_PTR(ret);

	a->mapped = true;
	return table;
}

static void mk_heap_unmap_dma_buf(struct dma_buf_attachment *attach,
				  struct sg_table *table,
				  enum dma_data_direction dir)
{
	struct mk_heap_attachment *a = attach->priv;

	a->mapped = false;
	dma_unmap_sgtable(attach->dev, table, dir, 0);
}

static int mk_heap_attach(struct dma_buf *dmabuf,
			  struct dma_buf_attachment *attach)
{
	struct mk_heap_buffer *buffer = dmabuf->priv;
	struct mk_heap_attachment *a;
	struct scatterlist *sg;
	int ret;

	a = kzalloc(sizeof(*a), GFP_KERNEL);
	if (!a)
		return -ENOMEM;

	/* Create a single-entry sg_table for the contiguous buffer */
	ret = sg_alloc_table(&a->table, 1, GFP_KERNEL);
	if (ret) {
		kfree(a);
		return ret;
	}

	sg = a->table.sgl;
	sg_set_page(sg, pfn_to_page(PHYS_PFN(buffer->phys_addr)),
		    buffer->len, 0);

	a->dev = attach->dev;
	INIT_LIST_HEAD(&a->list);

	attach->priv = a;

	mutex_lock(&buffer->lock);
	list_add(&a->list, &buffer->attachments);
	mutex_unlock(&buffer->lock);

	return 0;
}

static void mk_heap_detach(struct dma_buf *dmabuf,
			   struct dma_buf_attachment *attach)
{
	struct mk_heap_buffer *buffer = dmabuf->priv;
	struct mk_heap_attachment *a = attach->priv;

	mutex_lock(&buffer->lock);
	list_del(&a->list);
	mutex_unlock(&buffer->lock);

	sg_free_table(&a->table);
	kfree(a);
}

static int mk_heap_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct mk_heap_buffer *buffer = dmabuf->priv;

	/* Map the physical memory to userspace */
	return remap_pfn_range(vma, vma->vm_start,
			       PHYS_PFN(buffer->phys_addr),
			       vma->vm_end - vma->vm_start,
			       vma->vm_page_prot);
}

static int mk_heap_vmap(struct dma_buf *dmabuf, struct iosys_map *map)
{
	struct mk_heap_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (!buffer->vaddr) {
		buffer->vaddr = memremap(buffer->phys_addr, buffer->len,
					 MEMREMAP_WB);
		if (!buffer->vaddr) {
			mutex_unlock(&buffer->lock);
			return -ENOMEM;
		}
	}
	buffer->vmap_cnt++;
	mutex_unlock(&buffer->lock);

	iosys_map_set_vaddr(map, buffer->vaddr);
	return 0;
}

static void mk_heap_vunmap(struct dma_buf *dmabuf, struct iosys_map *map)
{
	struct mk_heap_buffer *buffer = dmabuf->priv;

	mutex_lock(&buffer->lock);
	if (--buffer->vmap_cnt == 0 && buffer->vaddr) {
		memunmap(buffer->vaddr);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->lock);
}

static void mk_heap_release(struct dma_buf *dmabuf)
{
	struct mk_heap_buffer *buffer = dmabuf->priv;

	if (buffer->vaddr)
		memunmap(buffer->vaddr);

	if (buffer->res) {
		release_resource(buffer->res);
		kfree(buffer->res);
	}

	sg_free_table(&buffer->sg_table);
	multikernel_free(buffer->phys_addr, buffer->len);
	kfree(buffer);
}

static const struct dma_buf_ops mk_heap_buf_ops = {
	.attach = mk_heap_attach,
	.detach = mk_heap_detach,
	.map_dma_buf = mk_heap_map_dma_buf,
	.unmap_dma_buf = mk_heap_unmap_dma_buf,
	.mmap = mk_heap_mmap,
	.vmap = mk_heap_vmap,
	.vunmap = mk_heap_vunmap,
	.release = mk_heap_release,
};

static struct dma_buf *mk_heap_allocate(struct dma_heap *heap,
					unsigned long len,
					u32 fd_flags,
					u64 heap_flags)
{
	struct mk_heap_buffer *buffer;
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct dma_buf *dmabuf;
	struct scatterlist *sg;
	phys_addr_t phys;
	int ret;

	/* Align to page size */
	len = PAGE_ALIGN(len);

	/* Allocate from multikernel pool */
	phys = multikernel_alloc(len);
	if (!phys)
		return ERR_PTR(-ENOMEM);

	buffer = kzalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer) {
		ret = -ENOMEM;
		goto err_free_mem;
	}

	buffer->heap = heap;
	buffer->len = len;
	buffer->phys_addr = phys;
	INIT_LIST_HEAD(&buffer->attachments);
	mutex_init(&buffer->lock);

	/* Create sg_table for the contiguous buffer */
	ret = sg_alloc_table(&buffer->sg_table, 1, GFP_KERNEL);
	if (ret)
		goto err_free_buffer;

	sg = buffer->sg_table.sgl;
	sg_set_page(sg, pfn_to_page(PHYS_PFN(phys)), len, 0);

	/* Export as dma-buf */
	exp_info.ops = &mk_heap_buf_ops;
	exp_info.size = len;
	exp_info.flags = fd_flags;
	exp_info.priv = buffer;

	dmabuf = dma_buf_export(&exp_info);
	if (IS_ERR(dmabuf)) {
		ret = PTR_ERR(dmabuf);
		goto err_free_sg;
	}

	buffer->res = kzalloc(sizeof(*buffer->res), GFP_KERNEL);
	if (buffer->res) {
		struct resource *parent = multikernel_get_pool_resource();

		buffer->res->start = phys;
		buffer->res->end = phys + len - 1;
		buffer->res->name = "daxfs";
		buffer->res->flags = IORESOURCE_MEM;

		if (parent && insert_resource(parent, buffer->res)) {
			pr_warn("multikernel heap: failed to register in /proc/iomem\n");
			kfree(buffer->res);
			buffer->res = NULL;
		}
	}

	pr_info("multikernel heap: allocated %lu bytes at 0x%llx\n",
		len, (unsigned long long)phys);

	return dmabuf;

err_free_sg:
	sg_free_table(&buffer->sg_table);
err_free_buffer:
	kfree(buffer);
err_free_mem:
	multikernel_free(phys, len);
	return ERR_PTR(ret);
}

static const struct dma_heap_ops mk_heap_ops = {
	.allocate = mk_heap_allocate,
};

static struct dma_heap *mk_dma_heap;

static int __init mk_dma_heap_init(void)
{
	struct dma_heap_export_info exp_info;

	if (!multikernel_pool_available()) {
		pr_info("multikernel heap: pool not available, skipping\n");
		return 0;
	}

	exp_info.name = "multikernel";
	exp_info.ops = &mk_heap_ops;
	exp_info.priv = NULL;

	mk_dma_heap = dma_heap_add(&exp_info);
	if (IS_ERR(mk_dma_heap)) {
		pr_err("multikernel heap: failed to add heap: %ld\n",
		       PTR_ERR(mk_dma_heap));
		return PTR_ERR(mk_dma_heap);
	}

	pr_info("multikernel heap: registered /dev/dma_heap/multikernel\n");
	return 0;
}
/* DMA heap must init after dma_heap subsystem (subsys_initcall) */
late_initcall(mk_dma_heap_init);
