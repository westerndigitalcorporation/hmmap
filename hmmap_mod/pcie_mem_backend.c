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

struct pcie_mem_backend pcie_membe = {};

int pcie_mem_init(unsigned long size, unsigned int page_size,
		  struct hmmap_dev *dev)
{
	int ret = 0;
	struct hmmap_pcie_info *pcie_info = &pcie_membe.info;
	resource_size_t res_size;

	ret = hmmap_pci_get_res(dev, pcie_info, size, &res_size);
	if (ret)
		goto out;

	pcie_membe.mem = ioremap_wc(pcie_info->res->start, res_size);
	if (!pcie_membe.mem) {
		UINFO("ERROR: PCIE_MEM_BACKEND IOREMAP_WC\n");
		ret = -ENXIO;
		goto out_pci_put;
	}

	pcie_membe.size = res_size;
	pcie_membe.page_size = page_size;
	pcie_membe.dev = dev;
	goto out;

out_pci_put:
	pci_dev_put(pcie_info->pcie_dev);
out:
	return ret;
}

void *pcie_mem(unsigned long off)
{
	return pcie_membe.mem + off;
}

void pcie_mem_fill_cache_avx2(void *cache_addr, unsigned long off)
{
	unsigned int pos;
	char *dev_ptr = (char *)pcie_mem(off);
	char *cache_ptr = (char *)cache_addr;

	kernel_fpu_begin();
	for (pos = 0; pos < pcie_membe.page_size; pos += CHAR_IN_AVX2) {
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
			      pcie_membe.page_size);
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
			    pcie_membe.page_size);

		list_del_init(&page->lru);
		hmmap_release_page(udev, page);
	}

	return 0;
}

void pcie_mem_destroy(void)
{
	iounmap(pcie_membe.mem);
	pci_dev_put(pcie_membe.info.pcie_dev);
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
