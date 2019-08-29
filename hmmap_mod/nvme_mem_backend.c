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

struct nvme_mem_backend_complete_common {
	atomic_t waiters;
	struct completion done;
	struct hmmap_dev *udev;
};

struct nvme_mem_backend_complete_private {
	struct nvme_mem_backend_complete_common *common;
	struct task_struct *waiter;
	struct page *page;
};

struct nvme_mem_backend nvme_mem_be = {};

int hmmap_nvme_mem_init(unsigned long size, u32 page_size,
			struct hmmap_dev *dev)
{
	int ret = 0;
	struct resource *res;
	resource_size_t res_size;
	unsigned int dev_fn;
	struct hmmap_pcie_info *pcie_info = &nvme_mem_be.info;

	nvme_mem_be.size = size;
	nvme_mem_be.page_size = page_size;
	nvme_mem_be.dev = dev;

	ret = hmmap_set_bdev(dev, &nvme_mem_be.bdev);
	if (ret)
		goto out;

	if (!dev->pcie_slot) {
		UINFO("ERROR NVME MEM BACKEND NO PCIE SLOT\n");
		ret = -ENXIO;
		goto out;
	}

	ret = hmmap_extract_bus_from_path(dev->pcie_slot, pcie_info);
	if (ret) {
		UINFO("ERROR: NVME MEM BACKEND PARSE DOM:BUS:DEV:FN:RES\n");
		ret = -ENXIO;
		goto out;
	}

	dev_fn = PCI_DEVFN(pcie_info->dev_num, pcie_info->func);
	pcie_info->pcie_dev = pci_get_domain_bus_and_slot(pcie_info->domain,
							  pcie_info->bus,
							  dev_fn);

	if (!pcie_info->pcie_dev) {
		UINFO("ERROR: NVME MEM BACKEND GET PCI DEV\n");
		ret = -ENXIO;
		goto out_release_blkdev;
	}

	res = &pcie_info->pcie_dev->resource[pcie_info->res_num];
	if (!(res->flags & IORESOURCE_MEM)) {
		UINFO("ERROR: NVME MEM BACKEND resource %u NOT MEM\n",
		      pcie_info->res_num);
		ret = -ENXIO;
		goto out_pci_put;
	}

	res_size = resource_size(res);
	UINFO("NVME MEM BACKEND found memory resource of size: %llu\n",
	      res_size);
	if (res_size < size) {
		UINFO("ERROR: res less than hmmap dev size of %lu", size);
		goto out_pci_put;
	}

	pcie_info->res = res;
	nvme_mem_be.mem = ioremap_cache(res->start, res_size);
	if (!nvme_mem_be.mem) {
		UINFO("ERROR: NVME MEM BACKEND IOREMAP_WC\n");
		ret = -ENXIO;
		goto out_pci_put;
	}

	if (pci_p2pdma_add_resource(pcie_info->pcie_dev, pcie_info->res_num,
				    res_size, 0)) {
		UINFO("ERROR: NVME MEM BACKEND PCI P2PDMA ADD RESOURCE\n");
		goto out_pci_put;
	}

	nvme_mem_be.p2p_mem = pci_alloc_p2pmem(pcie_info->pcie_dev, res_size);
	if (!nvme_mem_be.p2p_mem) {
		UINFO("ERROR: NVME MEM BACKEND PCI P2PDMA ALLOC");
		goto out_pci_put;
	}

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

void hmmap_nvme_mem_end_io_poll(struct bio *bio)
{
	struct task_struct *waiter = bio->bi_private;

	WRITE_ONCE(bio->bi_private, NULL);
	wake_up_process(waiter);
}

void hmmap_nvme_mem_end_io(struct bio *bio)
{
	struct nvme_mem_backend_complete_private *done = bio->bi_private;
	struct nvme_mem_backend_complete_common *common = done->common;
	struct hmmap_dev *udev = common->udev;
	struct page *page = done->page;

	UDEBUG("HMMAP BLOCK END IO OFFSET: %lu\n", bio->bi_iter.bi_sector);
	if (atomic_dec_and_test(&(common->waiters)))
		complete(&common->done);

	unlock_page(hmmap_nvme_mem_get_page(page->index));
	hmmap_release_page(udev, page);
	bio_put(bio);
	kfree(done);
}

int hmmap_bio_init(void *cache_address, unsigned long offset, struct bio *bio)
{
	int ret = 0;

	bio_set_dev(bio, nvme_mem_be.bdev);
	bio->bi_iter.bi_sector = hmmap_sect(offset);
	if (!bio_add_page(bio, vmalloc_to_page(cache_address), PAGE_SIZE, 0)) {
		UINFO("ERROR adding page to bio\n");
		ret = -EIO;
	}

	return ret;
}

int hmmap_nvme_mem_submit_bio(void *cache_address, unsigned long offset, int op,
			  struct nvme_mem_backend_complete_private *done,
			  bool poll)
{
	struct bio *bio;
	int ret = 0;
	blk_qc_t qc;

	bio = bio_alloc(GFP_KERNEL, 1);
	ret = hmmap_bio_init(cache_address, offset, bio);
	if (ret)
		goto bio_put;

	bio->bi_opf = op;
	if (poll) {
		bio->bi_private = current;
		bio->bi_end_io = hmmap_nvme_mem_end_io_poll;
	} else {
		bio->bi_private = done;
		bio->bi_end_io = hmmap_nvme_mem_end_io;
	}

	qc = submit_bio(bio);

	if (poll) {
		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!READ_ONCE(bio->bi_private))
				break;
			if (!blk_poll(bdev_get_queue(nvme_mem_be.bdev), qc,
				      true))
				io_schedule();
		}
		__set_current_state(TASK_RUNNING);
		goto bio_put;
	}

	goto out;

bio_put:
	bio_put(bio);
out:
	return ret;
}

int hmmap_nvme_mem_fill_cache(void *cache_address, unsigned long offset)
{
	return hmmap_nvme_mem_submit_bio(cache_address, offset, REQ_OP_READ,
					 NULL, true);
}

int hmmap_nvme_mem_flush_pages(struct hmmap_dev *udev)
{
	unsigned long off;
	void *cache_address;
	int ret = 0;
	struct nvme_mem_backend_complete_common *cc;
	struct nvme_mem_backend_complete_private *cp;
	struct blk_plug plug;
	struct page *page;

	cc = kmalloc(sizeof(struct nvme_mem_backend_complete_common),
		       GFP_KERNEL);
	if (!cc) {
		UINFO("Flush cache error alloc common completion\n");
		ret = -ENOMEM;
		goto out;
	}

	init_completion(&(cc->done));
	atomic_set(&(cc->waiters), 0);
	cc->udev = udev;
	blk_start_plug(&plug);
	/* Iterate over the list of pages we are asked to flush out */
	while (!list_empty(&udev->dirty_pages)) {
		page = list_first_entry(&udev->dirty_pages, struct page, lru);
		off = page->index;
		cache_address = (void *)page->private;
		UDEBUG("Flushing page with index %lu\n", off);
		atomic_inc(&(cc->waiters));
		cp = kmalloc(sizeof(struct nvme_mem_backend_complete_private),
			     GFP_KERNEL);
		if (!cp) {
			UINFO("Flush cache error alloc priv completion\n");
			BUG();
		}

		cp->common = cc;
		cp->page = page;
		list_del_init(&page->lru);
		ret = hmmap_nvme_mem_submit_bio(cache_address, off,
						REQ_OP_WRITE, cp, false);
		if (ret) {
			UINFO("Error Flush page off: %lu, addr: %p\n", off,
			      cache_address);
			BUG();
		}

	}

	blk_finish_plug(&plug);
	wait_for_completion_io(&(cc->done));
	kfree(cc);

out:
	return ret;
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

