/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * daxfs - DAX-based filesystem for shared memory
 *
 * A simple read-only filesystem stored in shared physical memory,
 * designed for fast container rootfs sharing between multikernel instances.
 */
#ifndef _UAPI_LINUX_DAXFS_H
#define _UAPI_LINUX_DAXFS_H

#include <linux/types.h>
#include <linux/magic.h>

/* DAXFS_MAGIC is defined in linux/magic.h as 0x64646178 */
#define DAXFS_VERSION		1
#define DAXFS_BLOCK_SIZE	4096
#define DAXFS_INODE_SIZE	64
#define DAXFS_ROOT_INO		1

/*
 * Superblock - always at offset 0, padded to DAXFS_BLOCK_SIZE
 */
struct daxfs_super {
	__le32 magic;		/* DAXFS_MAGIC */
	__le32 version;		/* Format version */
	__le32 flags;		/* Feature flags */
	__le32 block_size;	/* Always DAXFS_BLOCK_SIZE */
	__le64 total_size;	/* Total image size in bytes */
	__le64 inode_offset;	/* Offset to inode table */
	__le32 inode_count;	/* Number of inodes */
	__le32 root_inode;	/* Root directory inode number */
	__le64 strtab_offset;	/* Offset to string table */
	__le64 strtab_size;	/* Size of string table */
	__le64 data_offset;	/* Offset to file data area */
	__u8   reserved[4024];	/* Pad to 4KB */
};

/*
 * Inode - fixed size for simple indexing
 *
 * Directories use first_child/next_sibling for a linked list structure.
 * Regular files store data at data_offset.
 * Symlinks store target path at data_offset.
 */
struct daxfs_inode {
	__le32 ino;		/* Inode number (1-based) */
	__le32 mode;		/* File type and permissions (S_IFREG, etc.) */
	__le32 uid;		/* Owner UID */
	__le32 gid;		/* Owner GID */
	__le64 size;		/* File size in bytes */
	__le64 data_offset;	/* Offset to file data (from image start) */
	__le32 name_offset;	/* Offset into string table for filename */
	__le32 name_len;	/* Length of filename */
	__le32 parent_ino;	/* Parent directory inode number */
	__le32 nlink;		/* Link count */
	__le32 first_child;	/* For dirs: first child inode (0 if empty) */
	__le32 next_sibling;	/* Next entry in same directory (0 if last) */
	__u8   reserved[8];	/* Pad to DAXFS_INODE_SIZE (64 bytes) */
};

/* Feature flags for daxfs_super.flags */
#define DAXFS_FLAG_NONE		0

#endif /* _UAPI_LINUX_DAXFS_H */
