/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FS_DAXFS_H
#define _FS_DAXFS_H

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/dma-buf.h>
#include <linux/iosys-map.h>
#include <uapi/linux/daxfs.h>

struct daxfs_info {
	void *mem;			/* Mapped memory base */
	phys_addr_t phys_addr;		/* Physical address */
	size_t size;			/* Total size */
	struct daxfs_super *super;	/* Superblock pointer */
	struct daxfs_inode *inodes;	/* Inode table base */
	char *strtab;			/* String table base */
	char *name;			/* Mount name for identification */
	struct dma_buf *dmabuf;		/* held dma-buf reference (if mounted via fd) */
	struct iosys_map dma_map;	/* vmap of dma-buf */
};

struct daxfs_inode_info {
	struct inode vfs_inode;		/* VFS inode (must be first) */
	struct daxfs_inode *raw;	/* On-disk inode */
	u64 data_offset;		/* Cached data offset */
};

static inline struct daxfs_info *DAXFS_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct daxfs_inode_info *DAXFS_I(struct inode *inode)
{
	return container_of(inode, struct daxfs_inode_info, vfs_inode);
}

/* super.c */
extern const struct super_operations daxfs_super_ops;
extern struct inode *daxfs_iget(struct super_block *sb, u32 ino);

/* dir.c */
extern const struct inode_operations daxfs_dir_inode_ops;
extern const struct file_operations daxfs_dir_ops;

/* file.c */
extern const struct inode_operations daxfs_file_inode_ops;
extern const struct file_operations daxfs_file_ops;
extern const struct address_space_operations daxfs_aops;

/* inode.c */
extern struct inode *daxfs_alloc_inode(struct super_block *sb);
extern void daxfs_free_inode(struct inode *inode);
extern int __init daxfs_inode_cache_init(void);
extern void daxfs_inode_cache_destroy(void);

#endif /* _FS_DAXFS_H */
