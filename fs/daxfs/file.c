// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * daxfs file operations
 */

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include "daxfs.h"

static ssize_t daxfs_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct daxfs_inode_info *di = DAXFS_I(inode);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(to);
	size_t copied;

	if (pos >= inode->i_size)
		return 0;

	if (pos + count > inode->i_size)
		count = inode->i_size - pos;

	copied = copy_to_iter(info->mem + di->data_offset + pos, count, to);
	if (copied == 0)
		return -EFAULT;

	iocb->ki_pos += copied;
	return copied;
}

static vm_fault_t daxfs_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct file *file = vma->vm_file;
	struct inode *inode = file_inode(file);
	struct daxfs_inode_info *di = DAXFS_I(inode);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	loff_t offset = (loff_t)vmf->pgoff << PAGE_SHIFT;
	phys_addr_t phys;
	unsigned long pfn;

	if (offset >= inode->i_size)
		return VM_FAULT_SIGBUS;

	phys = info->phys_addr + di->data_offset + offset;
	pfn = phys >> PAGE_SHIFT;

	return vmf_insert_mixed(vma, vmf->address, pfn);
}

static const struct vm_operations_struct daxfs_vm_ops = {
	.fault = daxfs_fault,
};

static int daxfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_WRITE)
		return generic_file_mmap(file, vma);

	file_accessed(file);
	vm_flags_set(vma, VM_MIXEDMAP | VM_DONTEXPAND | VM_DONTDUMP);
	vma->vm_ops = &daxfs_vm_ops;

	return 0;
}

static int daxfs_read_folio(struct file *file, struct folio *folio)
{
	struct inode *inode = folio->mapping->host;
	struct daxfs_inode_info *di = DAXFS_I(inode);
	struct daxfs_info *info = DAXFS_SB(inode->i_sb);
	loff_t pos = folio_pos(folio);
	size_t len = folio_size(folio);
	void *src;

	if (pos >= inode->i_size) {
		folio_zero_range(folio, 0, len);
		goto out;
	}

	if (pos + len > inode->i_size) {
		size_t valid = inode->i_size - pos;
		folio_zero_range(folio, valid, len - valid);
		len = valid;
	}

	src = info->mem + di->data_offset + pos;
	memcpy_to_folio(folio, 0, src, len);

out:
	folio_mark_uptodate(folio);
	folio_unlock(folio);
	return 0;
}

const struct address_space_operations daxfs_aops = {
	.read_folio	= daxfs_read_folio,
};

const struct file_operations daxfs_file_ops = {
	.llseek		= generic_file_llseek,
	.read_iter	= daxfs_read_iter,
	.mmap		= daxfs_mmap,
	.splice_read	= filemap_splice_read,
};

const struct inode_operations daxfs_file_inode_ops = {
	.getattr	= simple_getattr,
};
