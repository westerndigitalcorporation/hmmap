// SPDX-License-Identifier: GPL-2.0-only
/*
 * dax_backend.c - hmmap dax device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Alistair Francis <alistair.francis@wdc.com>
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 */

#include <linux/module.h>
#include <linux/namei.h>
#include <linux/dax.h>
#include <linux/pfn_t.h>
#include <../drivers/dax/dax.h>
#include <../drivers/dax/dax-private.h>

#include "dax_backend.h"
#include "hmmap.h"

struct dax_backend_info dax_info = {};

int dax_init(unsigned long size, unsigned int page_size, struct hmmap_dev *dev)
{
	struct dax_device *dax;
	struct dev_dax *dev_dax;
	struct file *file = NULL;
	resource_size_t res_size;

	dax_info.size = size;
	dax_info.page_size = page_size;
	dax_info.dev = dev;

	if (!dev->path) {
		UINFO("ERROR: DAX BACKEND NO PATH SET\n");
		return -ENXIO;
	}

	file = filp_open(dev->path, O_RDWR, 0);

	if (IS_ERR(file)) {
		UINFO("ERROR: Unable to open: %s\n", dev->path);
		return PTR_ERR(file);
	}

	dax = inode_dax(file->f_inode);

	if (!dax) {
		UINFO("ERROR: DAX device not found\n");
		return -1;
	}

	dev_dax = dax_get_private(dax);

	if (!dev_dax->region || !dev_dax->region->base) {
		UINFO("ERROR: Unable to find a dax memory region\n");
		return -ENOMEM;
	}

	/* To make things simple we assume one resource */
	if (dev_dax->num_resources != 1) {
		UINFO("ERROR: Only supporting dax device with one resource\n");
		return -ENOMEM;
	}

	res_size = resource_size(&dev_dax->region->res);
	if (size > res_size) {
		UINFO("ERROR: Dax resource size:%llu smaller ", res_size);
		UINFO("than  hmmap device size:%lu\n", dax_info.size);
		return -ENOMEM;
	}

	dax_info.mem = phys_to_virt(dev_dax->region->res.start);
	if (!dax_info.mem) {
		UINFO("ERROR: DAX backend memory allocation failed\n");
		return -ENOMEM;
	}

	dax_info.dev_dax = dev_dax;

	return 0;
}

pfn_t dax_get_pfn(unsigned long offset)
{
	struct resource *res = &dax_info.dev_dax->region->res;
	phys_addr_t phys = res->start + offset;

	return phys_to_pfn_t(phys, dax_info.dev_dax->region->pfn_flags);
}

void *dax_mem(unsigned long offset)
{
	return dax_info.mem + offset;
}

int dax_fill_cache(void *cache_address, unsigned long off)
{
	memcpy(cache_address, dax_mem(off), dax_info.page_size);
	return 0;
}

int dax_flush_pages(struct hmmap_dev *udev)
{
	unsigned long off;
	void *cache_address;
	struct page *page;

	/* Iterate over the list of pages we are asked to flush out */
	while (!list_empty(&udev->dirty_pages)) {
		page = list_first_entry(&udev->dirty_pages, struct page, lru);
		off = page->index;
		cache_address = (void *)page->private;
		UDEBUG("Memcpy to dev_off:%lu, cache_addr:%p\n", off,
		       cache_address);
		memcpy(dax_mem(off), cache_address, dax_info.page_size);
		list_del_init(&page->lru);
		hmmap_release_page(udev, page);
	}

	return 0;
}

void dax_destroy(void)
{

}

static struct hmmap_backend dax_backend = {
	.name = "dax_backend",
	.init = dax_init,
	.get_pfn = dax_get_pfn,
	.fill_cache = dax_fill_cache,
	.flush_pages = dax_flush_pages,
	.destroy = dax_destroy,
};

static int __init hmmap_dax_backend_init(void)
{
	int ret = hmmap_register_backend(&dax_backend);

	if (!ret)
		UINFO("DAX backend registered\n");
	else
		UINFO("Registering DAX backend failed %d\n", ret);

	return ret;
}

static void __exit hmmap_dax_backend_exit(void)
{
	hmmap_unregister_backend(&dax_backend);

}

module_init(hmmap_dax_backend_init);
module_exit(hmmap_dax_backend_exit);

MODULE_AUTHOR("Alistair Francis");
MODULE_LICENSE("GPL");
