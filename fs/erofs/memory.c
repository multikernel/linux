// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc.
 * Memory backing layer for EROFS - enables direct memory access
 * via physical addresses (memremap) or dma-buf file descriptors.
 */
#include "internal.h"
#include <linux/io.h>
#include <linux/dma-buf.h>

int erofs_mem_init_phys(struct erofs_sb_info *sbi, phys_addr_t phys_addr,
			size_t size)
{
	struct erofs_mem_backing *mb;

	mb = kzalloc(sizeof(*mb), GFP_KERNEL);
	if (!mb)
		return -ENOMEM;

	mb->mem = memremap(phys_addr, size, MEMREMAP_WB);
	if (!mb->mem) {
		kfree(mb);
		return -ENOMEM;
	}
	mb->phys_addr = phys_addr;
	mb->size = size;
	sbi->mem_backing = mb;
	return 0;
}

int erofs_mem_init_dmabuf(struct erofs_sb_info *sbi, struct file *dmabuf_file)
{
	struct erofs_mem_backing *mb;
	struct dma_buf *dmabuf;
	int ret;

	dmabuf = dmabuf_file->private_data;
	if (!dmabuf)
		return -EINVAL;

	mb = kzalloc(sizeof(*mb), GFP_KERNEL);
	if (!mb)
		return -ENOMEM;

	get_dma_buf(dmabuf);
	ret = dma_buf_vmap(dmabuf, &mb->dma_map);
	if (ret) {
		dma_buf_put(dmabuf);
		kfree(mb);
		return ret;
	}
	mb->dmabuf = dmabuf;
	mb->mem = mb->dma_map.vaddr;
	mb->size = dmabuf->size;
	sbi->mem_backing = mb;
	return 0;
}

void erofs_mem_exit(struct erofs_sb_info *sbi)
{
	struct erofs_mem_backing *mb = sbi->mem_backing;

	if (!mb)
		return;
	if (mb->dmabuf) {
		dma_buf_vunmap(mb->dmabuf, &mb->dma_map);
		dma_buf_put(mb->dmabuf);
	} else if (mb->mem) {
		memunmap(mb->mem);
	}
	kfree(mb);
	sbi->mem_backing = NULL;
}
