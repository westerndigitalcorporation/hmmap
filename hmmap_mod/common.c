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
#include <linux/pci.h>

#include "hmmap.h"

void hmmap_clear_xamap(struct page *page)
{
	struct address_space *as = page->mapping;

	xa_lock(&as->i_pages);
	__xa_erase(&as->i_pages, page->index);
	xa_unlock(&as->i_pages);
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

int hmmap_extract_substr(char **str, unsigned int *val, bool is_signed)
{
	char *sub_str;
	const char *sep = ":";
	int ret = 0;

	if (str) {
		sub_str = strsep(&(*str), sep);
		if (sub_str && is_signed)
			ret = kstrtoint(sub_str, 0, (int *)val);
		else if (sub_str && !is_signed)
			ret = kstrtouint(sub_str, 0, val);
		else
			return -EINVAL;

		if (ret)
			return ret;
	} else
		return -EINVAL;

	return ret;
}

int hmmap_extract_bus_from_path(const char *path, struct hmmap_pcie_info *info)
{
	char *tmp_str;
	char tmp_buf[MAX_ID_SIZE];
	int ret = 0;

	memcpy(tmp_buf, path, MAX_ID_SIZE);
	tmp_str = tmp_buf;

	/* First arg is the int */
	ret = hmmap_extract_substr(&tmp_str, &info->domain, true);
	if (ret) {
		UINFO("Error extracting domain from %s\n", path);
		goto out;
	}

	ret = hmmap_extract_substr(&tmp_str, &info->bus, false);
	if (ret) {
		UINFO("Error extracting bus from %s\n", path);
		goto out;
	}

	ret = hmmap_extract_substr(&tmp_str, &info->dev_num, false);
	if (ret) {
		UINFO("Error extracting dev_num from %s\n", path);
		goto out;
	}

	ret = hmmap_extract_substr(&tmp_str, &info->func, false);
	if (ret) {
		UINFO("Error extracting function from %s\n", path);
		goto out;
	}

	ret = hmmap_extract_substr(&tmp_str, &info->res_num, false);
	if (ret) {
		UINFO("Error extracting resource from %s\n", path);
		goto out;
	}

	UINFO("HMMAP BACKEND FOUND DEV DOM:BUS:DEV:FN:RES %d:%u:%u:%u:%u\n",
	      info->domain, info->bus, info->dev_num, info->func,
	      info->res_num);
out:
	return ret;
}
EXPORT_SYMBOL(hmmap_extract_bus_from_path);

int hmmap_pci_get_res(struct hmmap_dev *dev, struct hmmap_pcie_info *info,
		      unsigned long size, resource_size_t *res_size)
{
	unsigned int dev_fn;
	int ret = 0;
	struct resource *res;

	if (!dev->pcie_slot) {
		UINFO("ERROR: HMMAP PCI GET DOM:BUS:DEV:FN:RES missing\n");
		ret = -ENXIO;
		goto out;
	}

	ret = hmmap_extract_bus_from_path(dev->pcie_slot, info);
	if (ret) {
		UINFO("ERROR: HMMAP PCI GET PARSE DOM:BUS:DEV:FN:RES\n");
		ret = -ENXIO;
		goto out;
	}

	dev_fn = PCI_DEVFN(info->dev_num, info->func);
	info->pcie_dev = pci_get_domain_bus_and_slot(info->domain, info->bus,
						     dev_fn);

	if (!info->pcie_dev) {
		UINFO("ERROR: HMMAP PCI GET NO PCI DEV\n");
		ret = -ENXIO;
		goto out;
	}

	res = &info->pcie_dev->resource[info->res_num];
	if (!(res->flags & IORESOURCE_MEM)) {
		UINFO("ERROR: HMMAP PCI GET resource %u NOT MEM\n",
		      info->res_num);
		ret = -ENXIO;
		goto out_pci_put;
	}

	info->res = res;
	*res_size = resource_size(res);
	UINFO("HMMAP PCI GET found memory resource of size: %llu\n", *res_size);
	if (*res_size < size) {
		UINFO("ERROR: res less than hmmap dev size of %lu", size);
		goto out_pci_put;
	}

out_pci_put:
	pci_dev_put(info->pcie_dev);

out:
	return ret;

}
EXPORT_SYMBOL(hmmap_pci_get_res);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");
