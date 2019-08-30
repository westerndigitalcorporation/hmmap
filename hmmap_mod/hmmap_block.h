/* SPDX-License-Identifier: GPL-2.0-only
 *
 * hmmap_block.h - hmmap block common header
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#ifndef HMMAP_BLOCK_H
#define HMMAP_BLOCK_H

#include <linux/fs.h>

#define hmmap_sect(off)	((sector_t)(off) >> SECTOR_SHIFT)

struct hmmap_block_complete_common {
	atomic_t waiters;
	struct completion done;
	struct hmmap_dev *udev;
};

struct hmmap_block_complete_private {
	struct hmmap_block_complete_common *common;
	struct task_struct *waiter;
	struct page *page;
};

int hmmap_set_bdev(struct hmmap_dev *dev, struct block_device **bdev);
void hmmap_put_bdev(struct block_device *bdev);
int hmmap_block_submit_bio(void *cache_address, unsigned long offset, int op,
			   struct hmmap_block_complete_private *done,
			   bool poll, struct block_device *bdev);
int hmmap_block_flush_pages(struct hmmap_dev *udev, struct block_device *bdev);

#endif
