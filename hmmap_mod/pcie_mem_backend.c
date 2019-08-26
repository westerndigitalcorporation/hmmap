// SPDX-License-Identifier: GPL-2.0-only
/*
 * pcie_mem_backend.c - hmmap pcie memory device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/ctype.h>
#include <asm/fpu/api.h>
#include <linux/pfn_t.h>

#include "pcie_mem_backend.h"
#include "hmmap.h"

struct pcie_mem_backend_info pcie_info = {};


int pcie_mem_extract_substr(char **str, unsigned int *val, bool is_signed)
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

int pcie_mem_extract_bus_from_path(const char *path)
{
	char *tmp_str;
	char tmp_buf[MAX_ID_SIZE];
	int ret = 0;

	memcpy(tmp_buf, path, MAX_ID_SIZE);
	tmp_str = tmp_buf;

	/* First arg is the int */
	ret = pcie_mem_extract_substr(&tmp_str, &pcie_info.domain, true);
	if (ret) {
		UINFO("Error extracting domain from %s\n", path);
		goto out;
	}

	ret = pcie_mem_extract_substr(&tmp_str, &pcie_info.bus, false);
	if (ret) {
		UINFO("Error extracting bus from %s\n", path);
		goto out;
	}

	ret = pcie_mem_extract_substr(&tmp_str, &pcie_info.dev_num, false);
	if (ret) {
		UINFO("Error extracting dev_num from %s\n", path);
		goto out;
	}

	ret = pcie_mem_extract_substr(&tmp_str, &pcie_info.func, false);
	if (ret) {
		UINFO("Error extracting function from %s\n", path);
		goto out;
	}

	ret = pcie_mem_extract_substr(&tmp_str, &pcie_info.res_num, false);
	if (ret) {
		UINFO("Error extracting resource from %s\n", path);
		goto out;
	}

	UINFO("PCIE MEM BACKEND FOUND DEV DOM:BUS:DEV:FN:RES %d:%u:%u:%u:%u\n",
	      pcie_info.domain, pcie_info.bus, pcie_info.dev_num,
	      pcie_info.func, pcie_info.res_num);
out:
	return ret;
}

int pcie_mem_init(unsigned long size, unsigned int page_size,
		 struct hmmap_dev *dev)
{
	unsigned int dev_fn;
	resource_size_t res_size;
	int ret = 0;
	struct resource *res;

	if (!dev->path) {
		UINFO("ERROR: PCIE_MEM_BACKEND DOM:BUS:DEV:FN:RES missing\n");
		ret = -ENXIO;
		goto out;
	}

	ret = pcie_mem_extract_bus_from_path(dev->path);
	if (ret) {
		UINFO("ERROR: PCIE_MEM_BACKEND PARSE DOM:BUS:DEV:FN:RES\n");
		ret = -ENXIO;
		goto out;
	}

	dev_fn = PCI_DEVFN(pcie_info.dev_num, pcie_info.func);
	pcie_info.pcie_dev = pci_get_domain_bus_and_slot(pcie_info.domain,
						       pcie_info.bus, dev_fn);

	if (!pcie_info.pcie_dev) {
		UINFO("ERROR: PCIE_MEM_BACKEND GET PCI DEV\n");
		ret = -ENXIO;
		goto out;
	}

	res = &pcie_info.pcie_dev->resource[pcie_info.res_num];
	if (!(res->flags & IORESOURCE_MEM)) {
		UINFO("ERROR: PCIE_MEM_BACKEND resource %u NOT MEM\n",
		      pcie_info.res_num);
		ret = -ENXIO;
		goto out_pci_put;
	}

	res_size = resource_size(res);
	UINFO("PCIE BACKEND found memory resource of size: %llu\n", res_size);
	if (res_size < size) {
		UINFO("ERROR: res less than hmmap dev size of %lu", size);
		goto out_pci_put;
	}

	pcie_info.mem = ioremap_wc(res->start, res_size);
	if (!pcie_info.mem) {
		UINFO("ERROR: PCIE_MEM_BACKEND IOREMAP_WC\n");
		ret = -ENXIO;
		goto out_pci_put;
	}

	pcie_info.size = res_size;
	pcie_info.page_size = page_size;
	pcie_info.res = res;
	goto out;

out_pci_put:
	pci_dev_put(pcie_info.pcie_dev);
out:
	return ret;
}

void *pcie_mem(unsigned long off)
{
	return pcie_info.mem + off;
}

void pcie_mem_fill_cache_avx2(void *cache_addr, unsigned long off)
{
	unsigned int pos;
	char *dev_ptr = (char *)pcie_mem(off);
	char *cache_ptr = (char *)cache_addr;

	kernel_fpu_begin();
	for (pos = 0; pos < pcie_info.page_size; pos += CHAR_IN_AVX2) {
		asm volatile("vmovntdqa %0,%%ymm0" : : "m" (dev_ptr[pos]));
		asm volatile("vmovdqa %%ymm0,%0" : "=m" (cache_ptr[pos]));
	}
	kernel_fpu_end();
}

int pcie_mem_fill_cache(void *cache_address, unsigned long off)
{
	if (boot_cpu_has(X86_FEATURE_AVX2))
		pcie_mem_fill_cache_avx2(cache_address, off);
	else
		memcpy_fromio(cache_address, pcie_mem(off),
			      pcie_info.page_size);
	return 0;
}

int pcie_mem_flush_pages(struct hmmap_dev *udev)
{
	unsigned long off;
	void *cache_address;
	struct page *page;

	/* Iterate over the list of pages we are asked to flush out */
	while (!list_empty(&udev->dirty_pages))	{
		page = list_first_entry(&udev->dirty_pages, struct page, lru);
		off = page->index;
		cache_address = (void *)page->private;
		memcpy_toio(pcie_mem(off), cache_address,
			    pcie_info.page_size);

		list_del_init(&page->lru);
		hmmap_release_page(udev, page);
	}

	return 0;
}

void pcie_mem_destroy(void)
{
	iounmap(pcie_info.mem);
	pci_dev_put(pcie_info.pcie_dev);
}

static struct hmmap_backend pcie_mem_backend = {
	.name = "pcie_mem_backend",
	.init = pcie_mem_init,
	.get_page = NULL,
	.fill_cache = pcie_mem_fill_cache,
	.flush_pages = pcie_mem_flush_pages,
	.destroy = pcie_mem_destroy,
};

static int __init hmmap_pcie_mem_backend_init(void)
{
	int ret = hmmap_register_backend(&pcie_mem_backend);

	if (!ret)
		UINFO("PCIE MEM BACKEND REGISTERED\n");
	else
		UINFO("PCIE MEM BACKEND REGISTRATION FAILS\n");

	return ret;
}

static void __exit hmmap_pcie_mem_backend_exit(void)
{
	hmmap_unregister_backend(&pcie_mem_backend);
}

module_init(hmmap_pcie_mem_backend_init);
module_exit(hmmap_pcie_mem_backend_exit);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");
