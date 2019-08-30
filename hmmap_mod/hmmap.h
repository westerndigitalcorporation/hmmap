/* SPDX-License-Identifier: GPL-2.0-only
 *
 * hmmap.h - hmmap
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#ifndef HMMAP_H
#define HMMAP_H

#include <linux/cdev.h>
#include <linux/semaphore.h>
#include <linux/fs.h>

#ifndef VM_RESERVED
#define VM_RESERVED  (VM_DONTEXPAND | VM_DONTDUMP)
#endif

#define DEVICE_SIZE	2097152 /* 2MiB */
#define CACHE_SIZE	1048576 /* 1MiB */
#define MIN_CACHE_SIZE 8192 /* Need to fix errors when using one page */
#define MAX_ID_SIZE 128
//#define HMMAP_DEBUG
//#define HMMAP_TRACE

#ifdef HMMAP_DEBUG
//#define UDEBUG(fmt, args...) printk( KERN_DEBUG "hmmap: " fmt, ## args)
#define UDEBUG(fmt, args...) trace_printk("hmmap: " fmt, ## args)
#else
#define UDEBUG(fmt, args...)
#endif 

#ifdef HMMAP_TRACE
#define UTRACE(fmt, args...) trace_printk("hmmap: " fmt, ## args)
#else
#define UTRACE(fmt, args...)
#endif

#define UINFO(fmt, args...) printk(KERN_INFO "hmmap: " fmt, ## args)

#define HMMAP_DEVS		1

struct hmmap_extent {
	unsigned long hmmap_off;
	unsigned long len;
	struct list_head list;
};

/*page_in MUST be set by the policy module if the faulting addr is non-DAX*/
/*page_out could be set optionally.*/
/*page_out MUST be dealt with first*/

struct hmmap_insert_info {
	struct page *page_in;	/* Page that we are going to use */
	struct page **out_pages;  /* Page that we are going to un-cache*/
	unsigned short num_pages;
	bool is_hard_pagefault; /* only hard faults requires to move data from
				 *  backend to cache
				 */
};

struct hmmap_dev {
	int reference;
	struct cdev cdev;
	const struct hmmap_backend *backend;
	const struct hmmap_cache_manager *cache_manager;
	const char *path; /* Only used if we have a backing device */
	const char *pcie_slot; /* Used to get the memory on a bar */
	bool dax;
	bool wrprotect;
	struct semaphore cache_sem;
	struct rw_semaphore rw_sem;
	atomic_t  cache_pages;
	struct list_head dirty_pages;
};

struct hmmap_cache_manager {
	const char *name;
	int (*init)(unsigned long size, unsigned page_size, 
		    struct hmmap_dev *dev, struct kobject *kobj);
	int (*reserve_page)(unsigned long offset, struct hmmap_dev *dev,
			    struct vm_area_struct *vma,
			    struct hmmap_insert_info *info);
	void (*release_page)(struct page *page);
	void (*insert_page)(struct page *page);
	int (*clear)(struct hmmap_dev *dev, struct hmmap_insert_info *info);
	void (*destroy)(struct kobject *kobj);
	struct list_head list;
};

struct hmmap_backend {
	const char *name;
	int (*init)(unsigned long size, unsigned page_size, 
		    struct hmmap_dev *dev);
	struct page *(*get_page)(unsigned long offset);
	int (*fill_cache)(void *cache_address, unsigned long offset);
	int (*flush_pages)(struct hmmap_dev *udev);
	void (*destroy)(void);
	struct list_head list;
};

struct hmmap_pcie_info {
	int domain;
	unsigned int bus;
	unsigned int dev_num;
	unsigned int func;
	unsigned int res_num;
	struct pci_dev *pcie_dev;
	struct resource *res;
};

int hmmap_register_cache_manager(struct hmmap_cache_manager *cm);
int hmmap_register_backend(struct hmmap_backend *backend);
void hmmap_unregister_cache_manager(struct hmmap_cache_manager *cm);
void hmmap_unregister_backend(struct hmmap_backend *backend);
struct hmmap_cache_manager *hmmap_find_cache_manager(const char *name);
struct hmmap_backend *hmmap_find_backend(const char *name);

void hmmap_release_page(struct hmmap_dev *udev, struct page *page);
void hmmap_clear_xamap(struct page *page);
int hmmap_extract_bus_from_path(const char *path, struct hmmap_pcie_info *info);
int hmmap_pci_get_res(struct hmmap_dev *dev, struct hmmap_pcie_info *info,
		      unsigned long size, resource_size_t *res_size);

#endif
