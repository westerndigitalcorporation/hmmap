// SPDX-License-Identifier: GPL-2.0-only
/*
 * common.c - hmmap common functionality
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>

#include "hmmap.h"

void hmmap_clear_xamap(struct page *page)
{
	struct address_space *as = page->mapping;

	XA_STATE(xas, &as->i_pages, page->index);
	xas_store(&xas, NULL);
	page->mapping = NULL;
	UDEBUG("Freeing page %p at offset %lu in as %p\n", page, page->index,
	       as);
}
EXPORT_SYMBOL(hmmap_clear_xamap);

void hmmap_release_page(struct hmmap_dev *udev, struct page *page)
{
	/* Only free if we know the cache won't be using this page          */
	/* TODO look at two level cache to potentially eliminate this check */

	hmmap_clear_xamap(page);
	if (!PageUptodate(page)) {
		unlock_page(page);
		udev->cache_manager->release_page(page);
		up(&udev->cache_sem);
		UDEBUG("Up udev cache sem release dirty page\n");
	} else {
		ClearPageUptodate(page);
	}

}
EXPORT_SYMBOL(hmmap_release_page);


MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");
