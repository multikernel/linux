// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * daxfs inode operations
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include "daxfs.h"

static struct kmem_cache *daxfs_inode_cachep;

struct inode *daxfs_alloc_inode(struct super_block *sb)
{
	struct daxfs_inode_info *di;

	di = alloc_inode_sb(sb, daxfs_inode_cachep, GFP_KERNEL);
	if (!di)
		return NULL;

	di->raw = NULL;
	di->data_offset = 0;

	return &di->vfs_inode;
}

void daxfs_free_inode(struct inode *inode)
{
	kmem_cache_free(daxfs_inode_cachep, DAXFS_I(inode));
}

static void daxfs_inode_init_once(void *obj)
{
	struct daxfs_inode_info *di = obj;

	inode_init_once(&di->vfs_inode);
}

struct inode *daxfs_iget(struct super_block *sb, u32 ino)
{
	struct daxfs_info *info = DAXFS_SB(sb);
	struct daxfs_inode *raw;
	struct daxfs_inode_info *di;
	struct inode *inode;
	struct timespec64 zerotime = {0, 0};
	u32 mode;

	if (ino == 0 || ino > le32_to_cpu(info->super->inode_count))
		return ERR_PTR(-EINVAL);

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode_state_read_once(inode) & I_NEW))
		return inode;

	raw = &info->inodes[ino - 1];
	di = DAXFS_I(inode);
	di->raw = raw;
	di->data_offset = le64_to_cpu(raw->data_offset);

	mode = le32_to_cpu(raw->mode);
	inode->i_mode = mode;
	inode->i_uid = make_kuid(&init_user_ns, le32_to_cpu(raw->uid));
	inode->i_gid = make_kgid(&init_user_ns, le32_to_cpu(raw->gid));
	inode->i_size = le64_to_cpu(raw->size);
	set_nlink(inode, le32_to_cpu(raw->nlink));

	inode_set_mtime_to_ts(inode,
		inode_set_atime_to_ts(inode,
			inode_set_ctime_to_ts(inode, zerotime)));

	switch (mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &daxfs_file_inode_ops;
		inode->i_fop = &daxfs_file_ops;
		inode->i_mapping->a_ops = &daxfs_aops;
		break;
	case S_IFDIR:
		inode->i_op = &daxfs_dir_inode_ops;
		inode->i_fop = &daxfs_dir_ops;
		break;
	case S_IFLNK:
		inode->i_op = &simple_symlink_inode_operations;
		inode->i_link = info->mem + di->data_offset;
		break;
	default:
		break;
	}

	unlock_new_inode(inode);
	return inode;
}

int __init daxfs_inode_cache_init(void)
{
	daxfs_inode_cachep = kmem_cache_create("daxfs_inode_cache",
					       sizeof(struct daxfs_inode_info),
					       0,
					       SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
					       daxfs_inode_init_once);
	if (!daxfs_inode_cachep)
		return -ENOMEM;
	return 0;
}

void daxfs_inode_cache_destroy(void)
{
	kmem_cache_destroy(daxfs_inode_cachep);
}
