/* SPDX-License-Identifier: GPL-2.0-only
 *
 * block_backend.h - hmmap block device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#ifndef HMMAP_BLOCK_BACKEND_H
#define HMMAP_BLOCK_BACKEND_H

#include <linux/fs.h>

#define hmmap_sect(off)	((sector_t)(off) >> SECTOR_SHIFT)

struct block_backend_info {
	void *data_buffer;
	struct hmmap_dev *dev;
	unsigned long size;
	u32 page_size;
	struct block_device *bdev;
};

#endif
