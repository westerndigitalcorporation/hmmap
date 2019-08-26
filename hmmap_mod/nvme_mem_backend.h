/* SPDX-License-Identifier: GPL-2.0-only
 *
 * nvme_mem_backend.h - hmmap nvme bar device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#ifndef HMMAP_NVME_MEM_BACKEND_H
#define HMMAP_NVME_MEM_BACKEND_H

#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include "hmmap.h"

#define hmmap_sect(off)	((sector_t)(off) >> SECTOR_SHIFT)

struct nvme_mem_backend {
	void *p2p_mem;
	void __iomem *mem;
	struct hmmap_dev *dev;
	unsigned long size;
	u32 page_size;
	struct block_device *bdev;
	struct hmmap_pcie_info info;
};

#endif
