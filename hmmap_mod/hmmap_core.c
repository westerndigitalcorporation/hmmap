// SPDX-License-Identifier: GPL-2.0-only
/*
 * hmmap_core.c - hmmap core functionality
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 * Copyright (c) 2019 Yuanjiang Ni <yuanjiang.ni@wdc.com>
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/kobject.h>
#include <asm/pgtable.h>
#include <linux/pfn_t.h>
#include <linux/mmu_notifier.h>

#include "hmmap.h"

static struct kobject *hmmap_kobj;

int hmmap_major;
int hmmap_devs	= HMMAP_DEVS;
unsigned long cache_size = CACHE_SIZE;
unsigned long device_size = DEVICE_SIZE;
unsigned long device_delay = 0;
unsigned int cache_pages = 0;
unsigned int device_pages = 0;
static char *caching_policy = "two_level_cache";
static char *backend_device = "mem_backend";
static char *backend_path = "";
struct hmmap_extent extent_list;
struct hmmap_dev *hmmap_devices;

module_param(hmmap_devs, int, 0);
module_param(cache_size, ulong, 0);
module_param(device_size, ulong, 0);
module_param(device_delay, ulong, 0);
module_param(caching_policy, charp, 0);
module_param(backend_device, charp, 0);
module_param(backend_path, charp, 0);

static ssize_t hmmap_kobj_delay_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf,
				     size_t count)
{
	sscanf(buf, "%lu", &device_delay);
	return count;
}

static ssize_t hmmap_kobj_delay_show(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    char *buf)
{
	return sprintf(buf, "%lu\n", device_delay);
}

static struct kobj_attribute hmmap_delay_attr = __ATTR(delay, S_IWUSR | S_IRUGO,
						      hmmap_kobj_delay_show,
						      hmmap_kobj_delay_store);


#define hmmap_dev_sysfs_rw(field)					     \
static ssize_t hmmap_dev_##field##_show(struct device *dev,		     \
			     struct device_attribute *attr, char *buf)       \
{									     \
	struct hmmap_dev *hmmap_dev = hmmap_devices;			     \
	unsigned int cur_dev = 0;					     \
	ssize_t written = 0;						     \
									     \
	/* Iterate over the devices and set the dax capability */	     \
	for (cur_dev = 0; cur_dev < hmmap_devs; cur_dev++) {	             \
		written += snprintf(buf + written, PAGE_SIZE - written,      \
				    "%s:%u\n", hmmap_dev->backend->name,      \
				    hmmap_dev->field);			     \
		hmmap_dev++;						     \
	}								     \
									     \
	return written;							     \
									     \
}									     \
									     \
static ssize_t hmmap_dev_##field##_store(struct device *dev,		     \
			     struct device_attribute *attr, const char *buf, \
			     size_t count)				     \
{									     \
	unsigned int temp;						     \
	struct hmmap_dev *hmmap_dev = hmmap_devices;			     \
	unsigned int cur_dev = 0;					     \
									     \
	if (kstrtouint(buf, 0, &temp) < 0)				     \
		return count;						     \
									     \
	/* Make sure we are true or false, TODO has to be a better way */    \
	if (temp != 0 && temp != 1)					     \
		return count;						     \
									     \
	/* Iterate over the devices and set the dax capability */	     \
	for (cur_dev = 0; cur_dev < hmmap_devs; cur_dev++) {		     \
		/* Only set the dax capability on dev that can get_page */   \
		if (hmmap_dev->backend->get_page)			     \
			hmmap_dev->field = temp;			     \
									     \
		hmmap_dev++;						     \
	}								     \
									     \
	return count;							     \
}									     \
static DEVICE_ATTR_RW(hmmap_dev_##field)				     \

hmmap_dev_sysfs_rw(dax);
hmmap_dev_sysfs_rw(wrprotect);

static struct attribute *hmmap_attrs[] = {
	&dev_attr_hmmap_dev_dax.attr,
	&dev_attr_hmmap_dev_wrprotect.attr,
	&hmmap_delay_attr.attr,
	NULL
};

static const struct attribute_group hmmap_attr_group = {
	.name = "hmmap",
	.attrs = hmmap_attrs,
};

void hmmap_fault_range(struct vm_area_struct *vma, unsigned long offset)
{
	struct address_space *as = vma->vm_file->f_mapping;
	/* Remove vma mapping for given range, TODO be sure to remember
	 the page size of the cache */
	UDEBUG("Faulting out addr:%lu,as:%p\n", offset, as);
	unmap_mapping_range(as, offset, PAGE_SIZE, 1);
	return;
}

void hmmap_find_dirty_pages(struct vm_area_struct *vma,
			    struct hmmap_insert_info *info,
			    bool pte_gone,
			    struct hmmap_dev *udev)
{
	unsigned short page_idx = 0;
	unsigned short dirty_idx = 0;
	struct page *page;
	LIST_HEAD(clean_pages);

	/* This is wasteful clean me up, only need space for dirty pages */
	while (page_idx < info->num_pages) {
		page = info->out_pages[page_idx];
		if (page_idx || pte_gone)
			lock_page(page);
		page->mapping = vma->vm_file->f_mapping;
		hmmap_fault_range(vma, page->index);
		/* Check if the page is dirty */
		if (PageDirty(page)) {
			list_add_tail(&page->lru, &udev->dirty_pages);
			/* Find dirty pages not triggered by page eviction */
			if (!pte_gone && !page_idx)
				SetPageUptodate(page);

			dirty_idx++;
		} else {
			/* Don't signal that a page is free until all the */
			/* fault range calls have completed               */
			hmmap_clear_xamap(page);
			if (page_idx || pte_gone)
				list_add_tail(&page->lru, &clean_pages);
		}

		page_idx++;
	}

	while (!list_empty(&clean_pages)) {
		page = list_first_entry(&clean_pages, struct page, lru);
		list_del_init(&page->lru);
		unlock_page(page);
		udev->cache_manager->release_page(page);
		up(&udev->cache_sem);
		UDEBUG("Up udev cache sem clean page\n");
	}

	info->num_pages = dirty_idx;
	return;
}

void hmmap_handle_eviction(struct vm_area_struct *vma,
			  struct hmmap_insert_info *insert_info,
			  struct hmmap_dev *udev,
			  bool pte_gone)
{
	int ret = 0;
	struct hmmap_flush_info *finfo = NULL;

	hmmap_find_dirty_pages(vma, insert_info, pte_gone, udev);
	/* Copy data from cache to device */
	if (!list_empty(&udev->dirty_pages)) {
		UDEBUG("Flushing out dirty cache entries\n");
		ret = udev->backend->flush_pages(udev);
		if (ret) {
			UINFO("Flush cache fails\n");
			BUG();
		}

		kfree(finfo);
	}
}

vm_fault_t hmmap_handle_fault(unsigned long off, struct vm_fault *vmf,
			     struct hmmap_dev *udev)
{
	int ret;
	void *cache_address;
	struct page *page_in = NULL, *page;
	struct hmmap_insert_info *insert_info = NULL;
	struct vm_area_struct *vma = vmf->vma;
	bool read = true;
	unsigned short num_pages = 0;
	struct address_space *as = vma->vm_file->f_mapping;
	bool race = false;
	unsigned long flags;
	spinlock_t *ptl;
	pte_t *pte;
	XA_STATE(xas, &as->i_pages, off);
	struct mmu_notifier_range range;

	UDEBUG("Entering hmmap handle fault\n");
	UDEBUG("Down sem cache sem attempt\n");
	down(&udev->cache_sem);
	UDEBUG("Down sem cache sem success\n");
	if (atomic_dec_and_test(&udev->cache_pages)) {
		UDEBUG("Attempt write rw_sem\n");
		down_write(&udev->rw_sem);
		read = false;
		UDEBUG("Grabbed write rw sem\n");
	} else {
		UDEBUG("Attempt read rw_sem\n");
		down_read(&udev->rw_sem);
		UDEBUG("Grabbed read rw sem\n");
	}

	insert_info = kzalloc(sizeof(struct hmmap_insert_info), GFP_KERNEL);
	if (!insert_info) {
		UINFO("INSERT INFO ALLOC FAILS\n");
		ret = VM_FAULT_OOM;
		goto out;
	}

	ret = udev->cache_manager->reserve_page(off, udev, vma, insert_info);
	if (ret) {
		UINFO("Failed to find a cache spot\n");
		ret = VM_FAULT_OOM; /* TODO  informative ret ? */
		goto out;
	}

	if (!read)
		downgrade_write(&udev->rw_sem);

	page_in = insert_info->page_in;
	/* Attempt to reserve the spot */
	xas_lock_irqsave(&xas, flags);
	page = xas_store(&xas, page_in);
	xas_unlock_irqrestore(&xas, flags);
	UDEBUG("Attempting to store page %p at offset %lu in as %p\n", page_in,
	       off, as);
	/* Something existed so no need to do IO */
	if (page) {
		race = true;
		UDEBUG("RACE on a page\n");
	} else {
		UDEBUG("Free spot in xarray\n");
		lock_page(page_in);
	}

	/* Only hande an eviction if we need to */
	if (insert_info->out_pages) {
		num_pages = insert_info->num_pages;
		hmmap_handle_eviction(vma, insert_info, udev, false);
		atomic_set(&udev->cache_pages, num_pages);
	}

	/* If we encountered a race, wait for winner to install pte */
	if (race) {
		udev->cache_manager->release_page(page_in);
		atomic_inc(&udev->cache_pages);
		up(&udev->cache_sem);
		UDEBUG("Up udev cache sem race\n");
		ret = VM_FAULT_NOPAGE;
		wait_on_page_locked(page);
		goto out;
	}

	cache_address = (void *)insert_info->page_in->private;
	UDEBUG("Map dev addr: %lu cache addr %p\n", off, cache_address);
	/* Copy backend contents to new cache location */
	if (insert_info->is_hard_pagefault) {
		ret = udev->backend->fill_cache(cache_address, off);
		if (ret) {
			UINFO("ERROR fill cache offset %lu", off);
			BUG();
		}
	}

	ret = vm_insert_page(vma, vmf->address, page_in);
	while (ret == -EBUSY) {
		ptl = pte_lockptr(vma->vm_mm, vmf->pmd);
		spin_lock(ptl);
		pte = pte_offset_map(vmf->pmd, vmf->address);
		if (pte)
			pte_clear(vma->vm_mm, vmf->address, pte);

		spin_unlock(ptl);
		range.mm = vma->vm_mm;
		range.start = vmf->address;
		range.end = vmf->address + PAGE_SIZE;
		range.flags |= MMU_NOTIFIER_RANGE_BLOCKABLE;
		mmu_notifier_invalidate_range_start(&range);
		ret = vm_insert_page(vma, vmf->address, page_in);
		mmu_notifier_invalidate_range_end(&range);
	}

	if (ret) {
		UINFO("Insert page fails:%d,addr:%lu\n", ret, vmf->address);
		BUG();
	}

	udev->cache_manager->insert_page(page_in);
	page_in->index = off;
	ClearPageDirty(page_in);
	unlock_page(page_in);
	ret = VM_FAULT_NOPAGE;

out:
	if (insert_info->out_pages) {
		up(&udev->cache_sem);
		UDEBUG("Up cache sem clean evict list\n");
	}

	up_read(&udev->rw_sem);
	UDEBUG("Up read rw sem\n");
	kfree(insert_info);

	return ret;
}

vm_fault_t hmmap_handle_dax_fault(unsigned long off, struct vm_fault *vmf,
				 struct hmmap_dev *udev)
{
	struct page *page, *xa_page;
	pgprot_t pgprot;
	struct address_space *as = vmf->vma->vm_file->f_mapping;
	XA_STATE(xas, &as->i_pages, off);
	unsigned long flags;

	/*direct mapping ask the backend for the page */
	page = udev->backend->get_page(off);
	if (!page)
		return VM_FAULT_OOM;

	if (udev->wrprotect) {
		/* Write during write protect go straight to cache */
		if (vmf->flags & FAULT_FLAG_WRITE)
			return hmmap_handle_fault(off, vmf, udev);

		pgprot = PAGE_READONLY;
	} else
		pgprot = PAGE_SHARED;

	UDEBUG("Dax insert at off %lu\n", off);
	wait_on_page_locked(page);
	xas_lock_irqsave(&xas, flags);
	xa_page = xas_store(&xas, page);
	xas_unlock_irqrestore(&xas, flags);
	if (xa_page) {
		wait_on_page_locked(xa_page);
		return VM_FAULT_NOPAGE;
	} else
		return vmf_insert_pfn_prot(vmf->vma, vmf->address,
					   page_to_pfn(page), pgprot);
}

vm_fault_t hmmap_vm_fault(struct vm_fault *vmf)
{
	unsigned long off = vmf->pgoff << PAGE_SHIFT;
	struct vm_area_struct *vma = vmf->vma;
	struct hmmap_dev *udev =  (struct hmmap_dev *)vma->vm_private_data;
	int ret;

	UDEBUG("Fault at address %lu, offset: %lu\n", vmf->address, off);
	if (udev->dax)
		ret = hmmap_handle_dax_fault(off, vmf, udev);
	else
		ret = hmmap_handle_fault(off, vmf, udev);

	UDEBUG("Map dev addr: %lu vma addr %lu\n", off, vmf->address);
	return ret;
}

vm_fault_t hmmap_vm_pfn_mkwrite(struct vm_fault *vmf)
{
	unsigned long off = vmf->pgoff << PAGE_SHIFT;
	struct vm_area_struct *vma = vmf->vma;
	struct hmmap_dev *udev = (struct hmmap_dev *)vma->vm_private_data;
	int ret;
	unsigned long vma_address;
	struct address_space *as = vma->vm_file->f_mapping;
	XA_STATE(xas, &as->i_pages, off);
	unsigned long flags;

	vma_address = vma->vm_start + (off - (vma->vm_pgoff << PAGE_SHIFT));
	UDEBUG("Write Fault at addr:%lu,off:%lu\n", vmf->address, off);
	xas_lock_irqsave(&xas, flags);
	xas_store(&xas, NULL);
	xas_unlock_irqrestore(&xas, flags);
	ret = hmmap_handle_fault(off, vmf, udev);

	return ret;
}

int hmmap_fop_open(struct inode *inode, struct file *filp)
{
	int minor = iminor(inode);
	if (minor < 0 || minor > hmmap_devs - 1)
		return -ENOMEM;

	filp->private_data = &hmmap_devices[iminor(inode)];
	return 0;
}

int hmmap_fop_close(struct inode *inode, struct file *filp)
{
	filp->private_data = NULL;
	return 0;
}

void hmmap_vm_open(struct vm_area_struct *vma)
{
	struct hmmap_dev *udev = (struct hmmap_dev *)vma->vm_private_data;
	struct hmmap_insert_info insert_info;

	udev->reference++;
	/* In case the the mmap sem is not held during when we are called */
	/* Returns the number of pages to flush */
	down_write(&udev->rw_sem);
	while (udev->cache_manager->clear(udev, &insert_info)) {
		hmmap_handle_eviction(vma, &insert_info, udev, true);
		up(&udev->cache_sem);
	}

	xa_destroy(&vma->vm_file->f_mapping->i_pages);
	up_write(&udev->rw_sem);
	atomic_set(&udev->cache_pages, cache_pages + 1);
	UDEBUG("Set cache pages atomic to:%u\n", cache_pages + 1);
	sema_init(&udev->cache_sem, cache_pages + 1);
	/* Handled by eviction */
	//unmap_mapping_range(vma->vm_file->f_mapping, 0, device_size -1, 1);
	UDEBUG("HMMAP VM OPEN FINISH\n");
}

void hmmap_vm_close(struct vm_area_struct *vma)
{
	struct hmmap_extent *cur_extent;
	struct hmmap_dev *udev = (struct hmmap_dev *)vma->vm_private_data;
	unsigned long dev_offset = vma->vm_pgoff << PAGE_SHIFT;
	struct hmmap_insert_info insert_info;

	UDEBUG("Closing vma %p, with as: %p\n", vma, vma->vm_file->f_mapping);
	list_for_each_entry(cur_extent, &extent_list.list, list) {
		if (cur_extent->hmmap_off == dev_offset)
			goto del;
	}
	return;

del:
	UDEBUG("Deleting a chunk with offset: %lu, len: %lu\n", dev_offset,
	       cur_extent->len);
	/* Persist cache back to device TODO make optional */
	UDEBUG("Attempt write rw sem in vm close\n");
	down_write(&udev->rw_sem);
	UDEBUG("Grab write rw sem in vm close\n");
	while (udev->cache_manager->clear(udev, &insert_info)) {
		hmmap_handle_eviction(vma, &insert_info, udev, true);
		up(&udev->cache_sem);
	}

	xa_destroy(&vma->vm_file->f_mapping->i_pages);
	up_write(&udev->rw_sem);
	list_del(&cur_extent->list);
	kfree(cur_extent);
	udev->reference--;
	atomic_set(&udev->cache_pages, cache_pages + 1);
	sema_init(&udev->cache_sem, cache_pages + 1);
	UDEBUG("MMAP close called\n");
}

struct vm_operations_struct hmmap_vm_ops =
{
	.open		= hmmap_vm_open,
	.close		= hmmap_vm_close,
	.fault		= hmmap_vm_fault,
	.pfn_mkwrite	= hmmap_vm_pfn_mkwrite,
};

/* Calculate available space left */
void hmmap_space_allocated(unsigned long *available)
{
	struct hmmap_extent *cur_extent;

	list_for_each_entry(cur_extent, &extent_list.list, list) {
		*available -= cur_extent->len;
	}
}

int hmmap_space_allocate(unsigned long len, unsigned long offset)
{
	struct hmmap_extent *extent = kmalloc(sizeof(struct hmmap_extent), 0);

	if (!extent)
		return -ENOMEM;

	UDEBUG("Adding a new extent of len:%lu and offset %lu\n",
	       len,offset);
	INIT_LIST_HEAD(&extent->list);
	extent->len = len;
	extent->hmmap_off = offset;
	list_add(&extent->list, &extent_list.list);

	return 0;
}

int hmmap_fop_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret = 0;
	unsigned long vsize = vma->vm_end - vma->vm_start;
	unsigned long allocatable_size = device_size;
	unsigned long device_offset = 0;
	struct hmmap_dev *udev = (struct hmmap_dev *)filp->private_data;
	UDEBUG("MMAP on Device File\n");
	
	if (!list_empty(&extent_list.list)) {
		hmmap_space_allocated(&allocatable_size);
		device_offset = device_size - allocatable_size;
	}
	/* We can only expose a max of device_pages
	 * can't map past this value
	 */
	if (vsize > allocatable_size){
		ret = -ENOMEM;
		goto out;
	}

	hmmap_space_allocate(vsize, device_offset);
	vma->vm_ops = &hmmap_vm_ops;
	vma->vm_flags |= VM_SHARED | VM_MIXEDMAP;
	vma->vm_private_data = udev;
	vma->vm_pgoff = device_offset >> PAGE_SHIFT;

	UDEBUG("Calling mmap open\n");
	hmmap_vm_open(vma);
	
out:
	return ret;
}

static const struct file_operations hmmap_fops =
{
	.owner		= THIS_MODULE,
	.open		= hmmap_fop_open,
	.release	= hmmap_fop_close,
	.mmap		= hmmap_fop_mmap,
};

static void hmmap_setup_cdev(struct hmmap_dev *dev, int index)
{
	int ret, devno = MKDEV(hmmap_major, index);

	cdev_init(&dev->cdev, &hmmap_fops);
	dev->cdev.owner = THIS_MODULE;
	/* dev->cdev.ops = &hmmap_fops; */
	ret = cdev_add(&dev->cdev, devno, 1);
	if (ret)
		UINFO("Error adding device %d\n", index);
	else
		UINFO("added device %d:%d\n", hmmap_major, index);
}

static int __init hmmap_module_init(void)
{
	int ret = 0, i;
	struct hmmap_dev *hmmap_dev;
	dev_t dev = MKDEV(hmmap_major, 0);

	UINFO("Module INIT\n");
	device_pages = device_size / PAGE_SIZE;
	cache_pages = cache_size / PAGE_SIZE;
	
	/* Basic checks */
	if (cache_size > device_size) {
		UINFO("Cache size can not be greater than device size\n");
		ret = -EINVAL;
		goto out;
	}

	if (cache_size < MIN_CACHE_SIZE) {
		UINFO("Cache size must be at least %u\n", MIN_CACHE_SIZE);
		ret = -EINVAL;
		goto out;
	}

	if ((device_size % PAGE_SIZE) != 0) {
		UINFO("Device size must be a multiple of the page size\n");
		ret = -EINVAL;
		goto out;
	}

	if ((cache_size % PAGE_SIZE) != 0) {
		UINFO("Cache size must be a multiple of the page size\n");
		ret = -EINVAL;
		goto out;
	}

	/*  Get a major number */
	ret = alloc_chrdev_region(&dev, 0, hmmap_devs, "hmmap");

	if (ret < 0) {
		UINFO("Error registering chrdev region.\n");
		goto out;
	}
	
	hmmap_major = MAJOR(dev);
	
	/* Allocate devices, # a module parameter */
	hmmap_devices = kmalloc_array(hmmap_devs, sizeof(struct hmmap_dev),
				     GFP_KERNEL);

	if (!hmmap_devices) {
		UINFO("DEVICES KMALLOC FAILS\n");
		ret = -ENOMEM;
		goto unregister_out;
	}

	/* Create this before initializing the cache and backend */
	/* Hang module sysfs entries off the hmmap entries */
	hmmap_kobj = kobject_create_and_add("hmmap", kernel_kobj);
	if (!hmmap_kobj) {
		UINFO("KOBJECT CREATE FAIL\n");
		ret = -ENOMEM;
		goto dev_cleanup;
	}

	memset(hmmap_devices, 0, sizeof(struct hmmap_dev) * hmmap_devs);
	hmmap_dev = hmmap_devices; /* Current device is the first device */
	ret = request_module("hmmap_%s", caching_policy);
	if (ret) {
		UINFO("Request Module:%s, Ret:%d\n", caching_policy, ret);
		goto kobj_cleanup;
	}

	ret = request_module("hmmap_%s", backend_device);
	if (ret) {
		UINFO("Request Module:%s, Ret:%d\n", backend_device, ret);
		goto kobj_cleanup;
	}

	for (i = 0; i < hmmap_devs; ++i) {
		hmmap_dev->path = backend_path;
		sema_init(&hmmap_dev->cache_sem, cache_pages + 1);
		init_rwsem(&hmmap_dev->rw_sem);
		atomic_set(&hmmap_dev->cache_pages, cache_pages + 1);
		INIT_LIST_HEAD(&hmmap_dev->dirty_pages);
		hmmap_dev->cache_manager =
			hmmap_find_cache_manager(caching_policy);
		if (!hmmap_dev->cache_manager) {
			UINFO("Cache Manager: %s NOT FOUND\n", caching_policy);
			ret = -ENOENT;
			goto kobj_cleanup;
		}

		ret = hmmap_dev->cache_manager->init(cache_size, PAGE_SIZE,
						    hmmap_dev, hmmap_kobj);
		if (ret)
			goto kobj_cleanup;

		hmmap_dev->backend = hmmap_find_backend(backend_device);
		if (!hmmap_dev->backend) {
			hmmap_dev->cache_manager->destroy(hmmap_kobj);
			UINFO("Backend: %s NOT FOUND\n", backend_device);
			ret = -ENOENT;
			goto kobj_cleanup;
		}

		ret = hmmap_dev->backend->init(device_size, PAGE_SIZE,
					       hmmap_dev);
		if (ret)
			goto cache_cleanup;

		hmmap_setup_cdev(hmmap_dev, i);
		hmmap_dev++; /* Move onto the next device in the list */
	}

	INIT_LIST_HEAD(&extent_list.list);	
	ret = sysfs_create_group(hmmap_kobj, &hmmap_attr_group);
	if (ret) {
		UINFO("HMMAP SYSFS CREATE GROUP FAILS\n");
		kobject_put(hmmap_kobj);
		goto unregister_out;
	}

	UINFO("INIT SUCCESS\n");
	UINFO("Device Size:%lu Pages: %u, Cache Size:%lu Pages:%u\n",
	       device_size,device_pages,cache_size,cache_pages);
	goto out;

cache_cleanup:
	hmmap_dev->cache_manager->destroy(hmmap_kobj);
kobj_cleanup:
	kobject_put(hmmap_kobj);
dev_cleanup:
	kfree(hmmap_devices);
unregister_out:
	UINFO("INIT ERROR UNREGESTERING THE DEVICE\n");
	unregister_chrdev_region(dev, hmmap_devs);
out:
	return ret;
}

static void __exit hmmap_module_exit(void)
{
	int i;
	struct hmmap_dev *dev;
	UINFO("MODULE EXIT\n");
	dev = hmmap_devices;
	for (i = 0; i < hmmap_devs; ++i) {
		cdev_del(&hmmap_devices[i].cdev);
		dev->cache_manager->destroy(hmmap_kobj);
		dev->backend->destroy();

	}
	kfree(hmmap_devices);
	kobject_put(hmmap_kobj);
	unregister_chrdev_region(MKDEV(hmmap_major, 0), hmmap_devs);
}

module_init(hmmap_module_init);
module_exit(hmmap_module_exit);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");
