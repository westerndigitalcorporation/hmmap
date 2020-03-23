/* SPDX-License-Identifier: GPL-2.0-only
 *
 * pcie_mem_backend.h - hmmap pcie memory device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#ifndef PCIE_MEM_BACKEND_H
#define PCIE_MEM_BACKEND_H

#include "hmmap.h"

#define CHAR_IN_AVX2 32


struct pcie_mem_be {
	void __iomem *mem;
	struct hmmap_dev *dev;
	unsigned long size;
	unsigned int page_size;
	struct hmmap_pcie_info info;
};

#endif
