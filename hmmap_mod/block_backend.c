// SPDX-License-Identifier: GPL-2.0-only
/*
 * block_backend.c - hmmap block device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>

#include "block_backend.h"
#include "hmmap.h"
#include "hmmap_block.h"

int hmmap_block_init(unsigned long size, u32 page_size, unsigned long off,
		     struct hmmap_dev *dev)
{
	struct block_be_info *binfo;
	int ret = 0;

	binfo = kzalloc(sizeof(struct block_be_info), GFP_KERNEL);
	if (!binfo)
		return -ENOMEM;

	binfo->size = size;
	binfo->page_size = page_size;
	binfo->dev = dev;
	binfo->off = off;

	ret = hmmap_set_bdev(dev, &binfo->bdev);
	if (ret)
		return ret;

	binfo->data_buffer = vmalloc(page_size);
	if (!binfo->data_buffer) {
		UINFO("BLOCK BACKEND DATA BUFFER ALLOC FAIL\n");
		hmmap_put_bdev(binfo->bdev);
		ret = -ENOMEM;
	}

	dev->be_priv = (void *)binfo;
	return ret;
}

int hmmap_block_fill_cache(void *cache_address, unsigned long offset,
			   struct hmmap_dev *dev)
{
	struct block_be_info *binfo;
	if (!dev || !dev->be_priv)
		return -EINVAL;

	binfo = (struct block_be_info *)dev->be_priv;
	return hmmap_block_submit_bio(cache_address, offset + binfo->off,
				      REQ_OP_READ, NULL, true, binfo->bdev);
}

int hmmap_block_be_flush_pages(struct hmmap_dev *dev)
{
	struct block_be_info *binfo;
	if (!dev || !dev->be_priv)
		return -EINVAL;

	binfo = (struct block_be_info *)dev->be_priv;
	return hmmap_block_flush_pages(dev, binfo->bdev, binfo->off);
}

void hmmap_block_destroy(struct hmmap_dev *dev)
{
	struct block_be_info *binfo;
	fmode_t mode = FMODE_READ | FMODE_WRITE;

	if (!dev || !dev->be_priv)
		return;

	binfo = (struct block_be_info *)dev->be_priv;
	vfree(binfo->data_buffer);
	blkdev_put(binfo->bdev, mode);
	kfree(binfo);
}

static struct hmmap_backend block_backend = {
	.name = "block_backend",
	.init = hmmap_block_init,
	.get_page = NULL,
	.fill_cache = hmmap_block_fill_cache,
	.flush_pages = hmmap_block_be_flush_pages,
	.destroy = hmmap_block_destroy,
};

static int __init hmmap_block_backend_init(void)
{
	int ret = hmmap_register_backend(&block_backend);

	if (!ret)
		UINFO("BLOCK BACKEND REGISTERED\n");
	else
		UINFO("Registering BLOCK BACKEND FAILS %d\n", ret);

	return ret;
}

static void __exit hmmap_block_backend_exit(void)
{
	hmmap_unregister_backend(&block_backend);
}

module_init(hmmap_block_backend_init);
module_exit(hmmap_block_backend_exit);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");

