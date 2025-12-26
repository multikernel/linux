// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * daxfs directory operations
 */

#include <linux/fs.h>
#include "daxfs.h"

static int daxfs_iterate(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct daxfs_inode_info *di = DAXFS_I(dir);
	struct daxfs_inode *child;
	u32 child_ino;
	int pos = 0;

	if (!dir_emit_dots(file, ctx))
		return 0;

	child_ino = le32_to_cpu(di->raw->first_child);

	while (child_ino && pos < ctx->pos - 2) {
		child = &info->inodes[child_ino - 1];
		child_ino = le32_to_cpu(child->next_sibling);
		pos++;
	}

	while (child_ino) {
		char *name;
		u32 name_len;
		u32 mode;
		unsigned char dtype;

		child = &info->inodes[child_ino - 1];
		name = info->strtab + le32_to_cpu(child->name_offset);
		name_len = le32_to_cpu(child->name_len);
		mode = le32_to_cpu(child->mode);

		switch (mode & S_IFMT) {
		case S_IFREG:
			dtype = DT_REG;
			break;
		case S_IFDIR:
			dtype = DT_DIR;
			break;
		case S_IFLNK:
			dtype = DT_LNK;
			break;
		default:
			dtype = DT_UNKNOWN;
			break;
		}

		if (!dir_emit(ctx, name, name_len, child_ino, dtype))
			return 0;

		ctx->pos++;
		child_ino = le32_to_cpu(child->next_sibling);
	}

	return 0;
}

static struct dentry *daxfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct daxfs_info *info = DAXFS_SB(dir->i_sb);
	struct daxfs_inode_info *di = DAXFS_I(dir);
	struct daxfs_inode *child;
	struct inode *inode = NULL;
	u32 child_ino;

	child_ino = le32_to_cpu(di->raw->first_child);

	while (child_ino) {
		char *name;
		u32 name_len;

		child = &info->inodes[child_ino - 1];
		name = info->strtab + le32_to_cpu(child->name_offset);
		name_len = le32_to_cpu(child->name_len);

		if (dentry->d_name.len == name_len &&
		    memcmp(dentry->d_name.name, name, name_len) == 0) {
			inode = daxfs_iget(dir->i_sb, child_ino);
			break;
		}

		child_ino = le32_to_cpu(child->next_sibling);
	}

	return d_splice_alias(inode, dentry);
}

const struct inode_operations daxfs_dir_inode_ops = {
	.lookup		= daxfs_lookup,
};

const struct file_operations daxfs_dir_ops = {
	.iterate_shared	= daxfs_iterate,
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
};
