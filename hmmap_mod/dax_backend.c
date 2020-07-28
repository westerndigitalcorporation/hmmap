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
#include <linux/slab.h>
#include <../drivers/dax/dax-private.h>

#include "dax_backend.h"
#include "hmmap.h"

int dax_init(unsigned long size, unsigned int page_size, unsigned long off,
	     struct hmmap_dev *dev)
{
	struct dax_device *dax;
	struct dev_dax *dev_dax;
	struct dax_be *d_be;
	struct file *file = NULL;
	resource_size_t res_size;
	int ret = 0;

	d_be = kzalloc(sizeof(struct dax_be), GFP_KERNEL);
	if (!d_be)
		return -ENOMEM;


	d_be->size = size;
	d_be->page_size = page_size;
	d_be->dev = dev;

	if (!dev->path) {
		UINFO("ERROR: DAX BACKEND NO PATH SET\n");
		ret = -ENXIO;
		goto cleanup;
	}

	file = filp_open(dev->path, O_RDWR, 0);

	if (IS_ERR(file)) {
		UINFO("ERROR: Unable to open: %s\n", dev->path);
		ret = PTR_ERR(file);
		goto cleanup;
	}

	dax = inode_dax(file->f_inode);

	if (!dax) {
		UINFO("ERROR: DAX device not found\n");
		ret = -EINVAL;
		goto cleanup;
	}

	dev_dax = dax_get_private(dax);

	if (!dev_dax->region) {
		UINFO("ERROR: Unable to find a dax memory region\n");
		ret = ENOMEM;
		goto cleanup;
	}

	res_size = resource_size(&dev_dax->region->res);
	if (size + off > res_size) {
		UINFO("ERROR: Dax resource size:%llu smaller ", res_size);
		UINFO("than  hmmap device size:%lu at off:%lu\n", d_be->size,
		      off);
		ret = ENOMEM;
		goto cleanup;
	}

	d_be->mem = phys_to_virt(dev_dax->region->res.start + off);
	if (!d_be->mem) {
		UINFO("ERROR: DAX backend memory allocation failed\n");
		ret = -ENOMEM;
		goto cleanup;
	}

	d_be->dev_dax = dev_dax;
	dev->be_priv = (void *)d_be;
	goto out;

cleanup:
	kfree(d_be);
out:
	return ret;
}

struct page *dax_get_page(unsigned long offset, struct hmmap_dev *dev)
{
	struct resource *res;
	phys_addr_t phys;
	pfn_t phys_pfn_t;
	struct dax_be *d_be;

	if (!dev || !dev->be_priv)
		return NULL;

	d_be = (struct dax_be *)dev->be_priv;
	res = &d_be->dev_dax->region->res;
	phys = virt_to_phys(d_be->mem) + offset;
	phys_pfn_t = phys_to_pfn_t(phys, d_be->dev_dax->region->pfn_flags);
	return pfn_t_to_page(phys_pfn_t);
}

void *dax_mem(unsigned long offset, struct dax_be *d_be)
{
	return d_be->mem + offset;
}

int dax_fill_cache(void *cache_address, unsigned long off,
		   struct hmmap_dev *dev)
{
	struct dax_be *d_be;

	if (!dev || !dev->be_priv)
		return -EINVAL;

	d_be = (struct dax_be *)dev->be_priv;
	memcpy(cache_address, dax_mem(off, d_be), d_be->page_size);
	return 0;
}

int dax_flush_pages(struct hmmap_dev *dev)
{
	unsigned long off;
	void *cache_address;
	struct page *page;
	struct dax_be *d_be;

	if (!dev || !dev->be_priv)
		return -EINVAL;

	d_be = (struct dax_be *)dev->be_priv;
	/* Iterate over the list of pages we are asked to flush out */
	while (!list_empty(&dev->dirty_pages)) {
		page = list_first_entry(&dev->dirty_pages, struct page, lru);
		off = page->index;
		cache_address = (void *)page->private;
		UDEBUG("Memcpy to dev_off:%lu, cache_addr:%p\n", off,
		       cache_address);
		memcpy(dax_mem(off, d_be), cache_address, d_be->page_size);
		list_del_init(&page->lru);
		hmmap_release_page(dev, page);
	}

	return 0;
}

void dax_destroy(struct hmmap_dev *dev)
{
	struct dax_be *d_be;

	if (!dev || !dev->be_priv)
		return;

	d_be = (struct dax_be *)dev->be_priv;
	kfree(d_be);
}

static struct hmmap_backend dax_backend = {
	.name = "dax_backend",
	.init = dax_init,
	.get_page = dax_get_page,
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
