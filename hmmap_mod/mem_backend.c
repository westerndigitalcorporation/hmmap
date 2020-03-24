// SPDX-License-Identifier: GPL-2.0-only
/*
 * mem_backend.c - hmmap memory device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/pfn_t.h>
#include <linux/pagemap.h>
#include <linux/slab.h>

#include "mem_backend.h"
#include "hmmap.h"

int mem_backend_init(unsigned long size, unsigned page_size, unsigned long off,
		     struct hmmap_dev *dev)
{
	struct mem_be_info *minfo = kzalloc(sizeof(struct mem_be_info),
					    GFP_KERNEL);
	if (!minfo)
		return -ENOMEM;

	minfo->size = size;
	minfo->page_size = page_size;
	minfo->dev = dev;
	
	minfo->mem = vmalloc(size);

	if (!minfo->mem) {
		UINFO("MEM BACKEND DEV MEM ALLOC FAILS\n");
		return -ENOMEM;
	}

	dev->be_priv = (void *)minfo;
	return 0;
}

void *mem_get(unsigned long offset, struct mem_be_info *minfo)
{
	return minfo->mem + offset;
}

struct page *mem_get_page(unsigned long offset, struct hmmap_dev *dev)
{
	struct mem_be_info *minfo;

	if (!dev || !dev->be_priv)
		return NULL;

	minfo = dev->be_priv;

	return vmalloc_to_page(mem_get(offset, minfo));
}

int mem_fill_cache(void *cache_address, unsigned long off,
		   struct hmmap_dev *dev)
{
	struct mem_be_info *minfo;

	if (!dev || !dev->be_priv)
		return -EINVAL;

	minfo = dev->be_priv;
	memcpy(cache_address, mem_get(off, minfo), minfo->page_size);
	return 0;
}

int mem_flush_pages(struct hmmap_dev *dev)
{
	unsigned long off;
	void *cache_address;
	struct page *page;
	struct mem_be_info *minfo;

	if (!dev || !dev->be_priv)
		return -EINVAL;

	minfo = dev->be_priv;
	/* Iterate over the list of pages we are asked to flush out */
	while (!list_empty(&dev->dirty_pages)) {
		page = list_first_entry(&dev->dirty_pages, struct page, lru);
		off = page->index;
		cache_address = (void *)page->private;
		UDEBUG("Flushing page with index %lu\n", off);
		memcpy(mem_get(off, minfo), cache_address, minfo->page_size);
		list_del_init(&page->lru);
		unlock_page(mem_get_page(off, dev));
		hmmap_release_page(dev, page);
	}

	return 0;
}

void mem_destroy(struct hmmap_dev *dev)
{
	struct mem_be_info *minfo;

	if (!dev || !dev->be_priv)
		return;

	minfo = dev->be_priv;
	vfree(minfo->mem);
	kfree(minfo);
}

static struct hmmap_backend mem_backend = {
	.name = "mem_backend",
	.init = mem_backend_init,
	.get_page = mem_get_page,
	.fill_cache = mem_fill_cache,
	.flush_pages = mem_flush_pages,
	.destroy = mem_destroy,
};

static int __init hmmap_mem_backend_init(void)
{
	int ret = hmmap_register_backend(&mem_backend);

	if (!ret)
		UINFO("MEM BACKEND REGISTERED\n");
	else
		UINFO("Registering MEM BACKEND FAILS %d\n", ret);

	return ret;
}

static void __exit hmmap_mem_backend_exit(void)
{
	hmmap_unregister_backend(&mem_backend);

}

module_init(hmmap_mem_backend_init);
module_exit(hmmap_mem_backend_exit);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");
