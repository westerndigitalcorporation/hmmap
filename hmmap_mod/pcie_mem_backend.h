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

#define MAX_ID_SIZE 128
#define CHAR_IN_AVX2 32

struct pcie_mem_backend_info {
	void __iomem *mem;
	struct hmmap_dev *dev;
	unsigned long size;
	unsigned int page_size;
	int domain;
	unsigned int bus;
	unsigned int dev_num;
	unsigned int func;
	unsigned int res_num;
	struct pci_dev *pcie_dev;
	struct resource *res;
};

#endif
