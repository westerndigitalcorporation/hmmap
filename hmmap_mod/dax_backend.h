/* SPDX-License-Identifier: GPL-2.0-only
 *
 * dax_backend.h - hmmap dax device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Alistair Francis <alistair.francis@wdc.com>
 *
 */

#ifndef DAX_BACKEND_H
#define DAX_BACKEND_H

struct dax_backend_info {
	void *mem;
	struct hmmap_dev *dev;
	unsigned long size;
	unsigned int page_size;
	struct dev_dax *dev_dax;
};

#endif
