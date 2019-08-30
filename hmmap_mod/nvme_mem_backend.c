// SPDX-License-Identifier: GPL-2.0-only
/*
 * nvme_mem_backend.c - hmmap nvme mem device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pfn_t.h>
#include <linux/pci-p2pdma.h>
#include <linux/pagemap.h>

#include "nvme_mem_backend.h"
#include "hmmap.h"
#include "hmmap_block.h"

struct nvme_mem_backend nvme_mem_be = {};

int hmmap_nvme_mem_init(unsigned long size, u32 page_size,
			struct hmmap_dev *dev)
{
	int ret = 0;
	struct hmmap_pcie_info *pcie_info = &nvme_mem_be.info;
	resource_size_t res_size;

	ret = hmmap_set_bdev(dev, &nvme_mem_be.bdev);
	if (ret)
		goto out;

	ret = hmmap_pci_get_res(dev, pcie_info, size, &res_size);
	if (ret)
		goto out_release_blkdev;

	nvme_mem_be.mem = ioremap_cache(pcie_info->res->start, res_size);
	if (!nvme_mem_be.mem) {
		UINFO("ERROR: NVME MEM BACKEND IOREMAP_WC\n");
		ret = -ENXIO;
		goto out_pci_put;
	}

	if (pci_p2pdma_add_resource(pcie_info->pcie_dev, pcie_info->res_num,
				    res_size, 0)) {
		UINFO("ERROR: NVME MEM BACKEND PCI P2PDMA ADD RESOURCE\n");
		ret = -ENXIO;
		goto out_pci_put;
	}

	nvme_mem_be.p2p_mem = pci_alloc_p2pmem(pcie_info->pcie_dev, res_size);
	if (!nvme_mem_be.p2p_mem) {
		UINFO("ERROR: NVME MEM BACKEND PCI P2PDMA ALLOC");
		ret = -ENXIO;
		goto out_pci_put;
	}

	nvme_mem_be.size = res_size;
	nvme_mem_be.page_size = page_size;
	nvme_mem_be.dev = dev;
	goto out;

out_pci_put:
	pci_dev_put(pcie_info->pcie_dev);
out_release_blkdev:
	hmmap_put_bdev(nvme_mem_be.bdev);
out:
	return ret;
}

struct page *hmmap_nvme_mem_get_page(unsigned long offset)
{
	struct page *page;

	page = virt_to_page(nvme_mem_be.p2p_mem + offset);
	if (!page) {
		UINFO("Error getting page from p2p dma\n");
		goto out;
	}

	if (page->pgmap->type != MEMORY_DEVICE_PCI_P2PDMA)
		UINFO("PAGE PGMAP TYPE NOT P2PDMA\n");

out:
	return page;
}

int hmmap_nvme_mem_fill_cache(void *cache_address, unsigned long offset)
{
	return hmmap_block_submit_bio(cache_address, offset, REQ_OP_READ,
				      NULL, true, nvme_mem_be.bdev);
}

int hmmap_nvme_mem_flush_pages(struct hmmap_dev *udev)
{
	return hmmap_block_flush_pages(udev, nvme_mem_be.bdev);
}

void hmmap_nvme_mem_destroy(void)
{
	struct hmmap_pcie_info *info = &nvme_mem_be.info;
	fmode_t mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

	iounmap(nvme_mem_be.mem);
	pci_free_p2pmem(info->pcie_dev, nvme_mem_be.p2p_mem,
			resource_size(info->res));
	pci_dev_put(info->pcie_dev);
	blkdev_put(nvme_mem_be.bdev, mode);
}

static struct hmmap_backend nvme_mem_backend = {
	.name = "nvme_mem_backend",
	.init = hmmap_nvme_mem_init,
	.get_page = hmmap_nvme_mem_get_page,
	.fill_cache = hmmap_nvme_mem_fill_cache,
	.flush_pages = hmmap_nvme_mem_flush_pages,
	.destroy = hmmap_nvme_mem_destroy,
};

static int __init hmmap_nvme_mem_backend_init(void)
{
	int ret = hmmap_register_backend(&nvme_mem_backend);

	if (!ret)
		UINFO("NVME MEM BACKEND REGISTERED\n");
	else
		UINFO("Registering NVME MEM BACKEND FAILS %d\n", ret);

	return ret;
}

static void __exit hmmap_nvme_mem_backend_exit(void)
{
	hmmap_unregister_backend(&nvme_mem_backend);
}

module_init(hmmap_nvme_mem_backend_init);
module_exit(hmmap_nvme_mem_backend_exit);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");

