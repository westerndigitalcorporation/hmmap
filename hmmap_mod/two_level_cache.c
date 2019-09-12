// SPDX-License-Identifier: GPL-2.0-only
/*
 * two_level_cache.c - hmmap lru2q cache
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "two_level_cache.h"
#include "hmmap.h"

#define PAGES_TO_CLEAR 2 /* Minimum number of pages to clear */
static struct two_level_data *tl_data;
static struct page **evict_list;
static DEFINE_SPINLOCK(two_level_lock);

#define two_level_sysfs_tl_da_ro(field)					     \
static ssize_t tl_da_##field##_show(struct device *dev,			     \
			     struct device_attribute *attr, char *buf)       \
{									     \
	return snprintf(buf, PAGE_SIZE, "%u\n", tl_data->field);	     \
}									     \
static DEVICE_ATTR_RO(tl_da_##field);

two_level_sysfs_tl_da_ro(active_size);
two_level_sysfs_tl_da_ro(inactive_size);

#define two_level_sysfs_tl_list_show(field)				     \
static ssize_t tl_da_##field##_list_show(struct device *dev,		     \
				         struct device_attribute *attr,      \
					 char *buf)			     \
{	struct page* page;						     \
	ssize_t written = 0;						     \
									     \
	list_for_each_entry(page, &tl_data->field, lru) {		     \
		written += snprintf(buf + written, PAGE_SIZE - written,      \
				    "%lu:%d->", page->index,		     \
				    PageActive(page));			     \
	}								     \
	written += snprintf(buf + written, PAGE_SIZE - written, "\n");	     \
	return written;							     \
}									     \
static DEVICE_ATTR_RO(tl_da_##field##_list);

two_level_sysfs_tl_list_show(active);
two_level_sysfs_tl_list_show(inactive);

static unsigned long recharge_processed_count;
static unsigned long evict_processed_count;

#define two_level_sysfs_rw(field)					     \
static ssize_t field##_show(struct device *dev,				     \
			     struct device_attribute *attr, char *buf)       \
{									     \
	return snprintf(buf, PAGE_SIZE, "%lu\n", field);		     \
}									     \
									     \
static ssize_t field##_store(struct device *dev,			     \
			     struct device_attribute *attr, const char *buf, \
			     size_t count)				     \
{									     \
	int rc = kstrtoul(buf, 0, &field);				     \
	if (rc)								     \
		count = rc;						     \
	return count;							     \
}									     \
static DEVICE_ATTR_RW(field);

two_level_sysfs_rw(recharge_processed_count);
two_level_sysfs_rw(evict_processed_count);


static unsigned int evict_list_size = PAGES_TO_CLEAR;

static ssize_t two_level_evict_list_size_store(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       const char *buf,
					       size_t count)
{

	unsigned int tmp_val;

	if (tl_data->active_size || tl_data->inactive_size) {
		UINFO("ERROR: Only updating evict size when cache is empty\n");
		goto out;
	}

	sscanf(buf, "%u", &tmp_val);
	if (tmp_val > tl_data->num_entries) {
		UINFO("ERROR: Evict list size > cache size:%lu\n",
		      tl_data->num_entries);
		goto out;
	}

	evict_list_size = tmp_val;
	evict_list = krealloc(evict_list,
			      evict_list_size * sizeof(struct page *),
			      GFP_KERNEL);
	if (!evict_list) {
		UINFO("unable to realloc evict list\n");
		BUG();
	}

out:
	return count;

}

static ssize_t two_level_evict_list_size_show(struct kobject *kobj,
					      struct kobj_attribute *attr,
					      char *buf)
{
	return sprintf(buf, "%u\n", evict_list_size);
}

static struct kobj_attribute
two_level_evict_list_size_attr = __ATTR(evict_list_size, S_IWUSR | S_IRUGO,
					two_level_evict_list_size_show,
					two_level_evict_list_size_store);


static ssize_t two_level_evict_list_show(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *buf)
{
	unsigned int count;
	ssize_t written = 0;
	struct page *page;

	for (count = 0; count < evict_list_size; count++) {
		page = evict_list[count];
		written += snprintf(buf + written, PAGE_SIZE - written,
				    "page idx:%lu\n", page->index);
	}

	return written;
}

static struct kobj_attribute
two_level_evict_list_attr = __ATTR(evict_list, S_IRUGO,
				  two_level_evict_list_show, NULL);

static struct page **evict_list;
static struct attribute *two_level_attrs[] = {
	&dev_attr_recharge_processed_count.attr,
	&dev_attr_evict_processed_count.attr,
	&dev_attr_tl_da_active_size.attr,
	&dev_attr_tl_da_inactive_size.attr,
	&dev_attr_tl_da_active_list.attr,
	&dev_attr_tl_da_inactive_list.attr,
	&two_level_evict_list_size_attr.attr,
	&two_level_evict_list_attr.attr,
	NULL
};

static const struct attribute_group two_level_attr_group = {
	.name = "two_level",
	.attrs = two_level_attrs,
};

/* Write back cache data and clear management lists */
int two_level_clear(struct hmmap_dev *dev, struct hmmap_insert_info *info)
{
	struct page *page = NULL;

	info->num_pages = 0;
	info->out_pages = evict_list;

	while (!list_empty(&tl_data->active) &&
	      info->num_pages != evict_list_size) {
		page = list_first_entry(&tl_data->active, struct page, lru);
		list_del_init(&page->lru);
		info->out_pages[info->num_pages] = page;
		tl_data->active_size--;
		info->num_pages++;
	}

	while (!list_empty(&tl_data->inactive) &&
	      info->num_pages != evict_list_size) {
		page = list_first_entry(&tl_data->inactive, struct page, lru);
		list_del_init(&page->lru);
		info->out_pages[info->num_pages] = page;
		tl_data->inactive_size--;
		info->num_pages++;
	}

	return info->num_pages;
}

void two_level_recharge_inactive(struct vm_area_struct *vma,
				 unsigned num_to_process)
{
	unsigned int page_idx;
	struct page* page;
	struct list_head *dest = &tl_data->active;
	pte_t pte, *ptep = NULL;
	pmd_t *pmdp = NULL;
	spinlock_t *ptl;
	unsigned long address;

	/* Update num_to_process items, ideally we move to inactive list */
	for (page_idx = 0; page_idx < num_to_process; page_idx++) {
		page = list_first_entry_or_null(&tl_data->active, struct page,
						lru);
		if (!page) {
			UINFO("Hot list smaller than expected bailing\n");
			BUG();
		}

		list_del_init(&page->lru);
		address = vma->vm_start +
			(page->index - (vma->vm_pgoff << PAGE_SHIFT));

		UDEBUG("Page:%p,dev off:%lu,lru addr:%p\n",
		       page, page->index, &page->lru);
		UDEBUG("VMA: %p\n", vma);

		if (follow_pte_pmd(vma->vm_mm, address, NULL, &ptep, &pmdp,
				   &ptl))
		{
			UDEBUG("unable to find the ptep for address %lu\n",
			       address);
			list_add_tail(&page->lru, dest);
			continue;
		}

		/* Hot page that needs to stay active list */
		if (pte_young(*ptep)) {
			pte = pte_mkold(*ptep);
			dest = &tl_data->active;
		} else { /* Hot page that has cooled down */
			pte = pte_mkold(*ptep);
			dest = &tl_data->inactive;
			tl_data->active_size--;
			tl_data->inactive_size++;
			UDEBUG("Page dev offset %ld demoted to inactive\n",
			       page->index);
		}
		set_pte_at(vma->vm_mm, address, ptep, pte);
		pte_unmap_unlock(ptep, ptl);
		list_add_tail(&page->lru, dest);
		recharge_processed_count++;
	}	
}

/* Examines the head and decides what to do with it next */
void two_level_update_inactive(struct vm_area_struct *vma)
{
	struct page *page;
	struct list_head *dest = &tl_data->inactive;
	pte_t pte,*ptep = NULL;
	pmd_t *pmdp = NULL; /* could be removed, no current huge page supp */
	spinlock_t *ptl;
	unsigned long address;

	UTRACE("start\n");
	page = list_first_entry_or_null(&tl_data->inactive, struct page, lru);
	if (!page) {
		UINFO("List empty in two_level_update_inactive\n");
		BUG();
	}

	UDEBUG("First page %p dev offset %lu, page lru addr %p\n", page,
	       page->index, &page->lru);
	UDEBUG("VMA: %p\n", vma);
	list_del_init(&page->lru);
	/* Dev offsets should always be on page boundaries */
	address = vma->vm_start + (page->index - (vma->vm_pgoff << PAGE_SHIFT));
	if (follow_pte_pmd(vma->vm_mm, address, NULL, &ptep, &pmdp, &ptl))
	{
		/* Race problem here if we look for the pte but the thread */
		/* that has inserted the page has not yet inserted the pte */
		/* we need to put the page back in the lru		   */
		UDEBUG("unable to find the ptep for address %lu\n",
		       address);
		list_add_tail(&page->lru, dest);
		return;
	}

	/* Hot page that needs to be moved to the Active list */
	if (pte_young(*ptep) && PageActive(page)) {
		ClearPageActive(page);
		pte = pte_mkold(*ptep);
		dest = &tl_data->active;
		tl_data->inactive_size--;
		tl_data->active_size++;
		UDEBUG("Page dev offset %ld promoted to active\n", page->index);

	} else if(pte_young(*ptep) && !PageActive(page)) {
		/* Page warming up */
		pte = pte_mkold(*ptep);
		SetPageActive(page);
		UDEBUG("Page dev offset %ld With Accessed Bit Set\n",
		       page->index);
	} else {
		/* Page is cool so stay cool */
		pte = pte_mkold(*ptep);
		ClearPageActive(page);
		UDEBUG("Page dev offset %ld not accessed\n", page->index);
	}

	set_pte_at(vma->vm_mm, address, ptep, pte);
	pte_unmap_unlock(ptep, ptl);
	UDEBUG("Page %p offset %lu, lru addr %p being placed on list.\n", page,
	       page->index, &page->lru);
	list_add_tail(&page->lru,dest);
	UTRACE("exit\n");
	return;
}

int two_level_init(unsigned long size, unsigned page_size, 
		   struct hmmap_dev *dev, struct kobject *kobj)
{
	unsigned long num_items = size / page_size;
	unsigned long cur_item;
	void *cache_addr;
	int ret = 0;
	struct page *page;

	tl_data = kzalloc(sizeof(struct two_level_data), GFP_KERNEL);
	if (!tl_data) {
		UINFO("TWO LEVEL DATA ALLOCATION FAILS\n");
		ret = -ENOMEM;
		goto out;
	}

	tl_data->size = size;
	tl_data->page_size = page_size;
	tl_data->dev = dev;
	tl_data->active_size = 0;
	tl_data->inactive_size = 0;
	tl_data->num_entries = num_items;
	INIT_LIST_HEAD(&tl_data->active);
	INIT_LIST_HEAD(&tl_data->inactive);
	INIT_LIST_HEAD(&tl_data->free);
	recharge_processed_count = 0;
	evict_processed_count = 0;

	/* Vzalloc the cache to guarantee that the page will exist */
	tl_data->cache = vzalloc(size);
	if (!tl_data->cache) {
		UINFO("TWO LEVEL CACHE INIT ALLOCATION FAILS\n");
		ret = -ENOMEM;
		goto out_free_data;
	}

	evict_list = kmalloc(evict_list_size * sizeof(struct page *),
				GFP_KERNEL);
	if (!evict_list) {
		UINFO("TWO LEVEL EVICTION LIST FAILS\n");
		ret = -ENOMEM;
		goto out_free_cache;
	}

	/* Initialize the free list */
	cache_addr = tl_data->cache;
	for (cur_item = 0; cur_item < num_items; cur_item++) {
		page = vmalloc_to_page(cache_addr);
		if (!page) {
			UINFO("TWO LEVEL FREE LIST INIT NO PAGE!\n");
			ret = -EINVAL;
			goto out_free_list;
		}
		get_page(page);
		page->private = (unsigned long)cache_addr;
		ClearPageUptodate(page);
		INIT_LIST_HEAD(&page->lru);
		list_add_tail(&page->lru, &tl_data->free);
		cache_addr += PAGE_SIZE;
	}

	ret = sysfs_create_group(kobj, &two_level_attr_group);
	if (ret) {
		UINFO("TWO LEVEL CACHE INIT SYSFS CREATE GROUP FAILS\n");
		ret = -EINVAL;
		goto out_free_list;
	}

	goto out;

out_free_list:
	kfree(evict_list);
out_free_cache:
	vfree(tl_data->cache);
out_free_data:
	kfree(tl_data);
out:
	return ret;
}

/* Add a new entry to the inactive list, assumes item is not on any other list */
void two_level_insert_inactive(struct page* page)
{
	UDEBUG("Inserting page: %p, lru: %p into inactive\n", page, &page->lru);
	ClearPageActive(page);
	list_add_tail(&page->lru, &tl_data->inactive);
	tl_data->inactive_size++;
}

/* Add a new entry to inactive list, assumes item is not on any other list */
void two_level_insert_free(struct page *page)
{
	ClearPageActive(page);
	list_add_tail(&page->lru, &tl_data->free);
}

/* TODO improve the processing here */
struct page* two_level_find_evict_item(struct list_head *lh, bool remove_first)
{
	struct page *page = NULL;

	list_for_each_entry(page, lh, lru) {
		/* No good candidates found return first item */
		evict_processed_count++;
		if (remove_first)
			goto page_del;

		if (!PageActive(page))
			goto page_del;
	}

	page = NULL;

page_del:
	if (page) {
		UDEBUG("Deleting page %p from lru %p\n", page, &page->lru);
		list_del_init(&page->lru);
	}

	return page;
}

void two_level_insert_info_add_page(struct hmmap_insert_info *info,
				    struct page *page)
{
	info->out_pages[info->num_pages] = page;
	info->num_pages++;
}

int two_level_evict_items(struct hmmap_insert_info *info)
{
	int ret = 0;
	struct page *page = NULL;

	info->num_pages = 0;
	info->out_pages = evict_list;

	while (info->num_pages < evict_list_size) {
		UDEBUG("Page: %p, before call to evict item inactive, false\n",
		       page);
		UDEBUG("NUM pages %u : Out pages: %p\n", info->num_pages,
		       info->out_pages);
		page = two_level_find_evict_item(&tl_data->inactive, false);
		UDEBUG("Page: %p, after call to evict item inactive, false\n",
		       page);
		if (page) {
			tl_data->inactive_size--;
			two_level_insert_info_add_page(info, page);
			continue;
		}
	
		UDEBUG("Cur before call to evict active, false %p\n", page);
		page = two_level_find_evict_item(&tl_data->active, false);
		UDEBUG("Cur after call to evict_item_active_false %p\n", page);
		if (page) {
			tl_data->active_size--;
			two_level_insert_info_add_page(info, page);
			continue;
		}

		UDEBUG("Cur bef call to evict item inactive, true %p\n", page);
		page = two_level_find_evict_item(&tl_data->inactive, true);
		UDEBUG("Cur aft call to evict item inactive, true %p\n", page);
		if (page) {
			tl_data->inactive_size--;
			two_level_insert_info_add_page(info, page);
			continue;
		}

		UDEBUG("Cur before call to evict item active, true %p\n", page);
		page = two_level_find_evict_item(&tl_data->active, true);
		UDEBUG("Cur after call to evict item active, true %p\n", page);
		if (page) {
			tl_data->active_size--;
			two_level_insert_info_add_page(info, page);
			continue;
		} else {
			/* No more pages left to evict */
			goto out_cleanup;
		}
	}
	
	/* Success skip over cleanup code */
	goto out;

out_cleanup:
	UINFO("TWO LEVEL EVICT PAGE FINDS NO CANDIDATE\n");
	info->out_pages = NULL;
	info->num_pages = 0;
	ret = -EINVAL;
out:
	return ret;

}

/* Assumes the insert info is zeroed out before a call to insert */
int two_level_reserve_page(unsigned long offset, struct hmmap_dev *dev,
			   struct vm_area_struct *vma,
			   struct hmmap_insert_info *info)
{
	struct page *page;
	unsigned items_to_process;
	unsigned long watermark;
	int ret = 0;
	unsigned long flags = 0;

	UTRACE("enter\n");
	/* Sanity Check */
	if (dev != tl_data->dev) {
		UINFO("TWO LEVEL INSERT: INSERT DEV != INIT DEV\n");
		ret = -EINVAL;
		goto out;
	}
	/* Make sure the cache exists */
	if (!tl_data->cache) {
		UINFO("TWO LEVEL INSERT: Cache not initialized\n");
		ret = -EINVAL;
		goto out;
	}
	
	spin_lock_irqsave(&two_level_lock, flags);
	/* Free list not empty grab a free page */
	if (!list_empty(&tl_data->free)) {
		/* Move data from inactive to active if inactive is greater 
		   than 1/3 of the entries */
		watermark = tl_data->num_entries / 3;
		if (tl_data->inactive_size > watermark)
			two_level_update_inactive(vma);

		page = list_first_entry(&tl_data->free, struct page, lru);
		list_del_init(&page->lru);
		info->page_in = page;
		info->out_pages = NULL;
		info->num_pages = 0;
		info->is_hard_pagefault = true;
	} else { /* Need to evict something */
		/* Keep 2/3 of the cache active, > move items to inactive */
		watermark = (tl_data->num_entries / 3) * 2;
		if (tl_data->active_size > watermark) {
			items_to_process = tl_data->active_size - watermark;
			two_level_recharge_inactive(vma, items_to_process);
		} else {
			/* Else update inactive */
			two_level_update_inactive(vma);
		}
		
		ret  = two_level_evict_items(info);
		if (ret)
			goto out;

		/* First free page is the one we will populate */
		info->page_in = info->out_pages[0];
		info->is_hard_pagefault = true;
	}

out:
	/* Contains 0 on success and insert_info is valid, on error 
	   insert_info is meaningless */
	spin_unlock_irqrestore(&two_level_lock, flags);
	UTRACE("exit\n");
	return ret; 
}

void two_level_destroy(struct kobject *kobj)
{
	unsigned int cur_item;
	void *cache_addr = tl_data->cache;
	struct page *page;
	/* Free the pages we were using */
	for (cur_item = 0; cur_item < tl_data->num_entries; cur_item++) {
		page = vmalloc_to_page(cache_addr);
		if (!page)
			UINFO("TWO LEVEL DESTROY NO PAGE!\n");

		put_page(page);
		cache_addr += PAGE_SIZE;
	}

	vfree(tl_data->cache);
	kfree(evict_list);
	kfree(tl_data);
	sysfs_remove_group(kobj, &two_level_attr_group);
}

void two_level_release(struct page *page)
{
	unsigned long flags;

	spin_lock_irqsave(&two_level_lock, flags);
	two_level_insert_free(page);
	spin_unlock_irqrestore(&two_level_lock, flags);
}

void two_level_insert_page(struct page *page)
{
	unsigned long flags;

	spin_lock_irqsave(&two_level_lock, flags);
	two_level_insert_inactive(page);
	spin_unlock_irqrestore(&two_level_lock, flags);
}

static struct hmmap_cache_manager two_level = {
	.name		= "two_level_cache",
	.init		= two_level_init,
	.reserve_page	= two_level_reserve_page,
	.clear		= two_level_clear,
	.destroy	= two_level_destroy,
	.release_page	= two_level_release,
	.insert_page	= two_level_insert_page,
};


static int __init hmmap_two_level_init(void)
{
	int ret = hmmap_register_cache_manager(&two_level);

	if (!ret)
		UINFO("TWO LEVEL CACHE MANAGER REGISTERED");
	else
		UINFO("Registering TWO LEVEL CACHE MANAGER FAILS %d\n", ret);

	return ret;
}

static void __exit hmmap_two_level_exit(void)
{
	hmmap_unregister_cache_manager(&two_level);
}

module_init(hmmap_two_level_init);
module_exit(hmmap_two_level_exit);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");
