// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Multikernel Technologies, Inc. All rights reserved.
 *
 * daxfs superblock operations
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include "daxfs.h"

enum daxfs_param {
	Opt_phys,
	Opt_size,
	Opt_name,
	Opt_dmabuf,
};

static const struct fs_parameter_spec daxfs_fs_parameters[] = {
	fsparam_u64("phys", Opt_phys),
	fsparam_u64("size", Opt_size),
	fsparam_string("name", Opt_name),
	fsparam_fd("dmabuf", Opt_dmabuf),
	{}
};

struct daxfs_fs_context {
	phys_addr_t phys_addr;
	size_t size;
	char *name;
	struct file *dmabuf_file;	/* dma-buf file from FSCONFIG_SET_FD */
};

static int daxfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct daxfs_fs_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, daxfs_fs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_phys:
		ctx->phys_addr = result.uint_64;
		break;
	case Opt_size:
		ctx->size = result.uint_64;
		break;
	case Opt_name:
		kfree(ctx->name);
		ctx->name = kstrdup(param->string, GFP_KERNEL);
		if (!ctx->name)
			return -ENOMEM;
		break;
	case Opt_dmabuf:
		if (ctx->dmabuf_file)
			fput(ctx->dmabuf_file);
		ctx->dmabuf_file = get_file(param->file);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}


static int daxfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct daxfs_fs_context *ctx = fc->fs_private;
	struct daxfs_info *info;
	struct inode *root_inode;
	int ret = -EINVAL;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	if (ctx->dmabuf_file) {
		struct dma_buf *dmabuf;

		dmabuf = ctx->dmabuf_file->private_data;
		if (!dmabuf || dmabuf->file != ctx->dmabuf_file) {
			pr_err("daxfs: not a dma-buf fd\n");
			ret = -EINVAL;
			goto err_free;
		}

		get_dma_buf(dmabuf);
		ret = dma_buf_vmap(dmabuf, &info->dma_map);
		if (ret) {
			dma_buf_put(dmabuf);
			goto err_free;
		}

		info->dmabuf = dmabuf;
		info->mem = info->dma_map.vaddr;
		info->size = dmabuf->size;
	} else if (ctx->phys_addr && ctx->size) {
		info->phys_addr = ctx->phys_addr;
		info->size = ctx->size;

		info->mem = memremap(info->phys_addr, info->size, MEMREMAP_WB);
		if (!info->mem) {
			pr_err("daxfs: failed to map %pa size %zu\n",
			       &info->phys_addr, info->size);
			ret = -ENOMEM;
			goto err_free;
		}
	} else {
		pr_err("daxfs: need dmabuf fd or phys/size options\n");
		ret = -EINVAL;
		goto err_free;
	}

	/* Copy name for identification */
	if (ctx->name) {
		info->name = kstrdup(ctx->name, GFP_KERNEL);
		if (!info->name) {
			ret = -ENOMEM;
			goto err_unmap;
		}
	}
	info->super = info->mem;
	sb->s_fs_info = info;
	sb->s_op = &daxfs_super_ops;
	sb->s_magic = DAXFS_MAGIC;
	sb->s_flags |= SB_RDONLY;
	sb->s_time_gran = 1;

	/* Validate and load existing image */
	if (le32_to_cpu(info->super->magic) != DAXFS_MAGIC) {
		pr_err("daxfs: invalid magic 0x%x (expected 0x%x)\n",
		       le32_to_cpu(info->super->magic), DAXFS_MAGIC);
		ret = -EINVAL;
		goto err_unmap;
	}

	if (le32_to_cpu(info->super->version) != DAXFS_VERSION) {
		pr_err("daxfs: unsupported version %u\n",
		       le32_to_cpu(info->super->version));
		ret = -EINVAL;
		goto err_unmap;
	}

	info->inodes = info->mem + le64_to_cpu(info->super->inode_offset);
	info->strtab = info->mem + le64_to_cpu(info->super->strtab_offset);

	root_inode = daxfs_iget(sb, le32_to_cpu(info->super->root_inode));
	if (IS_ERR(root_inode)) {
		ret = PTR_ERR(root_inode);
		goto err_unmap;
	}

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto err_unmap;
	}

	if (info->dmabuf)
		pr_info("daxfs: mounted from dma-buf size %zu (%u inodes)\n",
			info->size, le32_to_cpu(info->super->inode_count));
	else
		pr_info("daxfs: mounted from %pa size %zu (%u inodes)\n",
			&info->phys_addr, info->size,
			le32_to_cpu(info->super->inode_count));

	return 0;

err_unmap:
	if (info->dmabuf) {
		dma_buf_vunmap(info->dmabuf, &info->dma_map);
		dma_buf_put(info->dmabuf);
	} else if (info->mem) {
		memunmap(info->mem);
	}
	kfree(info->name);
err_free:
	sb->s_fs_info = NULL;
	kfree(info);
	return ret;
}

static int daxfs_get_tree(struct fs_context *fc)
{
	return get_tree_nodev(fc, daxfs_fill_super);
}

static void daxfs_free_fc(struct fs_context *fc)
{
	struct daxfs_fs_context *ctx = fc->fs_private;

	if (ctx) {
		if (ctx->dmabuf_file)
			fput(ctx->dmabuf_file);
		kfree(ctx->name);
		kfree(ctx);
	}
}

static const struct fs_context_operations daxfs_context_ops = {
	.parse_param	= daxfs_parse_param,
	.get_tree	= daxfs_get_tree,
	.free		= daxfs_free_fc,
};

static int daxfs_init_fs_context(struct fs_context *fc)
{
	struct daxfs_fs_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	fc->fs_private = ctx;
	fc->ops = &daxfs_context_ops;
	return 0;
}

static void daxfs_kill_sb(struct super_block *sb)
{
	struct daxfs_info *info = DAXFS_SB(sb);

	kill_anon_super(sb);

	if (info) {
		if (info->dmabuf) {
			dma_buf_vunmap(info->dmabuf, &info->dma_map);
			dma_buf_put(info->dmabuf);
		} else if (info->mem) {
			memunmap(info->mem);
		}
		kfree(info->name);
		kfree(info);
	}
}

static int daxfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct daxfs_info *info = DAXFS_SB(dentry->d_sb);

	buf->f_type = DAXFS_MAGIC;
	buf->f_bsize = DAXFS_BLOCK_SIZE;
	buf->f_blocks = info->size / DAXFS_BLOCK_SIZE;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = le32_to_cpu(info->super->inode_count);
	buf->f_ffree = 0;
	buf->f_namelen = 255;
	return 0;
}

static int daxfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct daxfs_info *info = DAXFS_SB(root->d_sb);

	if (info->name)
		seq_printf(m, ",name=%s", info->name);
	if (info->dmabuf)
		seq_puts(m, ",source=dmabuf");
	else
		seq_printf(m, ",phys=0x%llx", (unsigned long long)info->phys_addr);
	seq_printf(m, ",size=%zu", info->size);
	return 0;
}

const struct super_operations daxfs_super_ops = {
	.alloc_inode	= daxfs_alloc_inode,
	.free_inode	= daxfs_free_inode,
	.statfs		= daxfs_statfs,
	.show_options	= daxfs_show_options,
};

static struct file_system_type daxfs_fs_type = {
	.owner			= THIS_MODULE,
	.name			= "daxfs",
	.init_fs_context	= daxfs_init_fs_context,
	.parameters		= daxfs_fs_parameters,
	.kill_sb		= daxfs_kill_sb,
};

static int __init daxfs_init(void)
{
	int err;

	err = daxfs_inode_cache_init();
	if (err)
		return err;

	err = register_filesystem(&daxfs_fs_type);
	if (err) {
		daxfs_inode_cache_destroy();
		return err;
	}

	return 0;
}

static void __exit daxfs_exit(void)
{
	unregister_filesystem(&daxfs_fs_type);
	daxfs_inode_cache_destroy();
}

module_init(daxfs_init);
module_exit(daxfs_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cong Wang <cwang@multikernel.io>");
MODULE_DESCRIPTION("DAX-based filesystem for shared memory");
MODULE_IMPORT_NS("DMA_BUF");
