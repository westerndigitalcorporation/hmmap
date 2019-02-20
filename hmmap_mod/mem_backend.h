/* SPDX-License-Identifier: GPL-2.0-only
 *
 * mem_backend.h - hmmap memory device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#ifndef MEM_BACKEND_H
#define MEM_BACKEND_H

struct mem_backend_info {
	void *mem;
	struct hmmap_dev *dev;
	unsigned long size;
	unsigned page_size;
};

#endif
