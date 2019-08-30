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

struct block_backend_info block_info = {};

int hmmap_block_init(unsigned long size, u32 page_size, struct hmmap_dev *dev)
{
	int ret = 0;
	block_info.size = size;
	block_info.page_size = page_size;
	block_info.dev = dev;

	ret = hmmap_set_bdev(dev, &block_info.bdev);
	if (ret)
		return ret;

	block_info.data_buffer = vmalloc(page_size);
	if (!block_info.data_buffer) {
		UINFO("BLOCK BACKEND DATA BUFFER ALLOC FAIL\n");
		hmmap_put_bdev(block_info.bdev);
		ret = -ENOMEM;
	}

	return ret;
}

int hmmap_block_fill_cache(void *cache_address, unsigned long offset)
{
	return hmmap_block_submit_bio(cache_address, offset, REQ_OP_READ, NULL,
				      true, block_info.bdev);
}

int hmmap_block_be_flush_pages(struct hmmap_dev *udev)
{
	return hmmap_block_flush_pages(udev, block_info.bdev);
}

void hmmap_block_destroy(void)
{
	fmode_t mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

	vfree(block_info.data_buffer);
	blkdev_put(block_info.bdev, mode);
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

