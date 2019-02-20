// SPDX-License-Identifier: GPL-2.0-only
/*
 * dimmap_cache.c - hmmap dimmap like cache
 *
 * Inspired by https://bitbucket.org/vanessen/di-mmap
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Yuanjiang Ni <yuanjiang.ni@wdc.com>
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/mm.h>
#include <asm/pgtable.h>
#include <linux/module.h>

#include "dimmap_cache.h"
#include "hmmap.h"

#define DIMMAP_OUT_PAGES 1
static struct dimmap_data dm_data = {}; /* Intending to zero out fields */
struct page *out_page[DIMMAP_OUT_PAGES];

#define dimmap_sysfs_dm_da_ro(field)					     \
static ssize_t dm_da_##field##_show(struct device *dev,			     \
			     struct device_attribute *attr, char *buf)       \
{									     \
	return snprintf(buf, PAGE_SIZE, "%lu\n", dm_data.field);	     \
}									     \
static DEVICE_ATTR_RO(dm_da_##field);

dimmap_sysfs_dm_da_ro(free_size);
dimmap_sysfs_dm_da_ro(primary_size);
dimmap_sysfs_dm_da_ro(hotpage_size);
dimmap_sysfs_dm_da_ro(eviction_size);
dimmap_sysfs_dm_da_ro(global_faults);
dimmap_sysfs_dm_da_ro(recovery_counts);


static struct attribute *dimmap_attrs[] = {
	&dev_attr_dm_da_free_size.attr,
	&dev_attr_dm_da_primary_size.attr,
	&dev_attr_dm_da_hotpage_size.attr,
	&dev_attr_dm_da_eviction_size.attr,
	&dev_attr_dm_da_global_faults.attr,
	&dev_attr_dm_da_recovery_counts.attr,
	NULL
};

static const struct attribute_group dimmap_attr_group = {
	.name = "dimmap",
	.attrs = dimmap_attrs,
};

int dimmap_init(unsigned long size, u32 page_size,
		struct hmmap_dev *dev, struct kobject *kobj)
{
	int ret = 0;
	unsigned long i;
	struct dimmap_page *di_pages;

	dm_data.page_size = page_size;
	dm_data.capacity_in_bytes = size;
	dm_data.total_capacity  = size / page_size;
	dm_data.primary_capacity = dm_data.total_capacity
					* PRIMARY_RATIO / 100;
	dm_data.hotpage_capacity = dm_data.total_capacity
					* HOTPAGE_RATIO / 100;
	dm_data.eviction_capacity = dm_data.total_capacity
		- dm_data.primary_capacity -  dm_data.hotpage_capacity;

	UDEBUG("TOT CACHE: %lu, PMY: %lu, HOT: %lu, EVICT %lu\n",
	       dm_data.total_capacity, dm_data.primary_capacity,
	       dm_data.hotpage_capacity, dm_data.eviction_capacity);

	dm_data.dev = dev;
	dm_data.free_size = 0;
	dm_data.primary_size = 0;
	dm_data.hotpage_size = 0;
	dm_data.eviction_size = 0;
	INIT_LIST_HEAD(&dm_data.free);
	INIT_LIST_HEAD(&dm_data.primary);
	INIT_LIST_HEAD(&dm_data.hotpage);
	INIT_LIST_HEAD(&dm_data.eviction);

	/* Malloc the cache */
	dm_data.cache = vmalloc(size);
	if (!dm_data.cache) {
		UINFO("DIMMAP CACHE INIT ALLOCATION FAILS\n");
		ret = -ENOMEM;
		goto out;
	}
	dm_data.di_pages = vmalloc(sizeof(struct dimmap_page) *
				   dm_data.total_capacity);
	if (!dm_data.di_pages) {
		UINFO("DIMMAP DI_PAGES INIT ALLOCATION FAILS\n");
		ret = -ENOMEM;
		goto fail1;

	}

	di_pages = dm_data.di_pages;

	/*Initialize the free list*/
	for (i = 0; i < dm_data.total_capacity; i++) {

		di_pages[i].page = vmalloc_to_page((void *)(dm_data.cache
							+ i * page_size));
		list_add_tail(&di_pages[i].list, &dm_data.free);
		INIT_HLIST_NODE(&di_pages[i].hlist);
		di_pages[i].flag = FREE;
		di_pages[i].faults = 0;
		dm_data.free_size++;
	}

	ret = sysfs_create_group(kobj, &dimmap_attr_group);
	if (ret) {
		UINFO("DI-MMAP CACHE INIT SYSFS CREATE GROUP FAILS\n");
		ret = -EINVAL;
		goto fail2;
	}

	/*Initialize the page location table*/
	hash_init(dm_data.location_table);
	memset(dm_data.fault_couts, 0,
	       sizeof(u32) * (1 << HASH_SIZE_BIT));
	dm_data.global_faults = 0;

	/*stats info*/
	dm_data.recovery_counts = 0;
	goto out;

fail2:
	vfree(dm_data.di_pages);
fail1:
	vfree(dm_data.cache);
out:
	return ret;
}

struct dimmap_page *dimmap_location_table_lookup(struct dimmap_data *data,
					  unsigned long offset)
{
	struct dimmap_page *di_page;

	hash_for_each_possible(data->location_table, di_page,
			       hlist, offset) {
		/*index will be set in *core**/
		if (di_page->page->index == offset)
			return di_page;
	}

	return NULL;
}

unsigned long dimmap_compute_cache_addr(struct dimmap_data *data,
				 struct dimmap_page *page)
{
	/*Get the offset within the cache address space*/
	unsigned long off = (unsigned long) (page - data->di_pages);

	return (unsigned long)data->cache + off * data->page_size;
}

void dimmap_increase_fault_counts(struct dimmap_data *data,
				  unsigned long offset, u32 delta)
{
	unsigned long bucket = hash_min(offset, HASH_SIZE_BIT);

	data->fault_couts[bucket] += delta;
	data->global_faults += delta;
}

void dimmap_decay_fault_counts(struct dimmap_data *data, unsigned long offset)
{
	unsigned long bucket = hash_min(offset, HASH_SIZE_BIT);

	BUG_ON(data->fault_couts[bucket] == 0);
	data->fault_couts[bucket]--;
	data->global_faults--; /*decrease global faults also? */
}


u32 dimmap_get_fault_counts(struct dimmap_data *data,
				 unsigned long offset)
{
	unsigned long bucket = hash_min(offset, HASH_SIZE_BIT);

	return data->fault_couts[bucket];
}

struct dimmap_page *dimmap_page_get(struct dimmap_data *data)
{
	struct dimmap_page *di_page;

	if (data->free_size == 0)
		return NULL;

	di_page = list_first_entry(&data->free, struct dimmap_page, list);
	BUG_ON(di_page == NULL);
	BUG_ON(!(di_page->flag & FREE));
	list_del(&di_page->list);
	di_page->flag = 0;
	data->free_size--;
	return di_page;
}

void dimmap_page_put(struct dimmap_data *data, struct dimmap_page *di_page)
{
	INIT_HLIST_NODE(&di_page->hlist);
	di_page->flag = 0;
	di_page->flag = FREE;
	di_page->faults = 0;

	list_add_tail(&di_page->list, &data->free);
	data->free_size++;
}


void dimmap_move_to_eviction(struct dimmap_data *data,
			     struct dimmap_page *di_page)
{
	UDEBUG("Eviction size %lu and Eviction capacity %lu\n",
		 dm_data.eviction_size, dm_data.eviction_capacity);

	if (data->eviction_size >= data->eviction_capacity) {
		struct dimmap_page *oldest = NULL;
		//TODO: batch TLB invalidation
		while (data->eviction_size > 0) {
			u32 fault_couts =
				dimmap_get_fault_counts(data,
							di_page->page->index);

			oldest = list_first_entry(&data->eviction,
						 struct dimmap_page, list);
			BUG_ON(!(oldest->flag &= EVICTON));

			UDEBUG("Oldest evicted from eviction, dev offset ");
			UDEBUG("%lu and cache offset %lu\n",
			       oldest->page->index,
			       (unsigned long)(oldest - dm_data.di_pages));

			if (oldest->faults == fault_couts
			    && fault_couts > 0) {
				/*decay the per-bucket fault counts*/
				dimmap_decay_fault_counts(data,
							  di_page->page->index);
			} else if (oldest->faults > fault_couts) {
				/*update the per-bucket fault counts*/
				dimmap_increase_fault_counts(data,
					di_page->page->index,
					oldest->faults - fault_couts);
			}
			list_del(&oldest->list);
			oldest->flag = 0;
			data->eviction_size--;
			hash_del(&oldest->hlist);
			dimmap_page_put(data, oldest);
		}
	}

	UDEBUG("Move page dev offset %lu to eviction.\n", di_page->page->index);
	di_page->flag = EVICTON;
	list_add_tail(&di_page->list, &data->eviction);
	data->eviction_size++;
}

/*
 * return:
 *    NULL -- no page be moved to eviction
 *    Or the page be moved
 */
struct dimmap_page *dimmap_move_to_hotpage(struct dimmap_data *data,
					   struct dimmap_page *di_page)
{
	struct dimmap_page *victim = NULL;

	UDEBUG("Hotpage size %lu and Hotpage capacity %lu\n",
		 dm_data.hotpage_size, dm_data.hotpage_capacity);

	if (data->hotpage_size >= data->hotpage_capacity) {
		// Make room in the hotpage queue
		victim = list_first_entry(&data->hotpage,
					 struct dimmap_page, list);

		UDEBUG("Oldest evicted from hotpage, dev offset ");
		UDEBUG("%lu and cache offset %lu\n", victim->page->index,
		       (unsigned long)(victim - dm_data.di_pages));

		BUG_ON(!(victim->flag &= HOTPAGE));
		list_del(&victim->list);
		victim->flag = 0;
		data->hotpage_size--;
		dimmap_move_to_eviction(data, victim);
	}

	UDEBUG("Move page dev offset %lu to hotpage.\n", di_page->page->index);
	di_page->flag = HOTPAGE;
	list_add_tail(&di_page->list, &data->hotpage);
	data->hotpage_size++;
	return victim;
}

int dimmap_insert(unsigned long offset, struct hmmap_dev *dev,
		     struct vm_area_struct *vma, struct hmmap_insert_info *info)
{
	int ret = 0;
	struct dimmap_page *di_page = NULL;
	struct dimmap_page *victim;

	info->is_hard_pagefault = true;
	info->out_pages = NULL;
	info->num_pages = 0;
	/* Sanity Check */
	if (dev != dm_data.dev) {
		UINFO("DIMMAP INSERT: INSERT DEV != INIT DEV\n");
		ret = -EINVAL;
		goto out;
	}
	/* Make sure the cache exists */
	if (!dm_data.cache) {
		UINFO("DIMMAP INSERT: Cache not initialized\n");
		ret = -EINVAL;
		goto out;
	}

	UTRACE("enter\n");


	/* Check if the faulting page already cached somethere in our system */
	di_page = dimmap_location_table_lookup(&dm_data, offset);
	if (di_page) {
		info->is_hard_pagefault = false;

		UDEBUG("Page dev offset %lu already cached\n",
			di_page->page->index);
		di_page->faults++;
		if (!(di_page->flag & EVICTON))
			goto done;

		UDEBUG("Page dev offset %lu need recovery\n",
			di_page->page->index);
		/* do recovery */
		BUG_ON(!(di_page->flag & EVICTON));
		list_del(&di_page->list);
		di_page->flag = 0;
		dm_data.eviction_size--;
		dm_data.recovery_counts++;
	}

	UDEBUG("Primary size %lu and Primary capacity %lu\n",
		 dm_data.primary_size, dm_data.primary_capacity);

	/* Check if the primary queue is full */
	/* We might triger eviction queue reclaimation if space is tight */
	if (dm_data.primary_size >= dm_data.primary_capacity) {
		/*Make room in the primary queue*/
		/*Get the oldest entry in primary queue*/
		struct dimmap_page *oldest = list_first_entry(&dm_data.primary,
					 struct dimmap_page, list);
		BUG_ON(!(oldest->flag & PRIMARY));
		list_del(&oldest->list);
		oldest->flag = 0;
		dm_data.primary_size--;

		UDEBUG("Oldest evicted from primary, dev offset ");
		UDEBUG("%lu and cache offset %lu\n", oldest->page->index,
		       (unsigned long)(oldest - dm_data.di_pages));
		UDEBUG("GLBLFLT CNT %lu, BUCKETS %lu, PGFLT CNT %u\n",
		       dm_data.global_faults, (1ul << HASH_SIZE_BIT),
		       oldest->faults);

		if (oldest->faults >
		   (dm_data.global_faults / (1 << HASH_SIZE_BIT))) {
			/*move the oldest entry to the hotpage queue*/
			victim = dimmap_move_to_hotpage(&dm_data, oldest);
			/* A entry being moved out of hotpage */
			if (victim != NULL) {
				out_page[0] = victim->page;
				info->out_pages = out_page;
				info->num_pages = 1;
			}

		} else {
			/*move the oldest entry to the eviction queue*/
			dimmap_move_to_eviction(&dm_data, oldest);
			out_page[0] = oldest->page;
			info->out_pages = out_page;
			info->num_pages = 1;
		}
	}

	/*di_page == NULL -> new page*/
	/*di_page != NULL -> recovering page*/

	if (!di_page) {
		di_page = dimmap_page_get(&dm_data);
		BUG_ON(!di_page); /*This should never happen!*/
		/*Remember, there is a "global history"*/
		di_page->faults = dimmap_get_fault_counts(&dm_data, offset);
		hash_add(dm_data.location_table, &di_page->hlist, offset);
		UDEBUG("Page dev offset %lu cached, initial fault counts %u\n",
		       offset, di_page->faults);
	}
	UDEBUG("Move page dev offset %lu to primary.\n", offset);
	di_page->flag = PRIMARY;
	list_add_tail(&di_page->list, &dm_data.primary);
	dm_data.primary_size++;
done:
	di_page->page->private = dimmap_compute_cache_addr(&dm_data, di_page);
	info->page_in = di_page->page;

out:
	/* Contains 0 on success and insert_info is valid, on error
	 * insert_info is meaningless
	 */
	UTRACE("exit\n");
	return ret;

}

/* Currently not safe, we need to write back the data but I will hope this */
/* gets open source soon and yj can fix this up.			   */
int dimmap_clear(struct hmmap_dev *dev, struct hmmap_insert_info *info)
{
	struct dimmap_page *page;
	struct dimmap_page *n;

	list_for_each_entry_safe(page, n, &dm_data.hotpage, list) {
		list_del(&page->list);
		page->flag = 0;
		dm_data.hotpage_size--;
		hash_del(&page->hlist);
		dimmap_page_put(&dm_data, page);
	}

	list_for_each_entry_safe(page, n, &dm_data.primary, list) {
		list_del(&page->list);
		page->flag = 0;
		dm_data.primary_size--;
		hash_del(&page->hlist);
		dimmap_page_put(&dm_data, page);
	}

	list_for_each_entry_safe(page, n, &dm_data.eviction, list) {
		list_del(&page->list);
		page->flag = 0;
		dm_data.eviction_size--;
		hash_del(&page->hlist);
		dimmap_page_put(&dm_data, page);
	}

	/*clearing history*/
	dm_data.global_faults = 0;
	memset(dm_data.fault_couts, 0,
	       sizeof(u32) * (1 << HASH_SIZE_BIT));

	/*clearing stats*/
	dm_data.recovery_counts = 0;

	/* return 0 for now, TODO update clear method to return valid pages */
	info->num_pages = 0;
	return 0;
}

void dimmap_destroy(struct kobject *kobj)
{
	vfree(dm_data.cache);
	sysfs_remove_group(kobj, &dimmap_attr_group);
}

static struct hmmap_cache_manager dimmap = {
	.name			= "dimmap_cache",
	.init			= dimmap_init,
	.reserve_page		= dimmap_insert,
	.clear			= dimmap_clear,
	.destroy		= dimmap_destroy,
};

static int __init hmmap_dimmap_init(void)
{
	int ret = hmmap_register_cache_manager(&dimmap);

	if (!ret)
		UINFO("DIMMAP CACHE REGISTERED\n");
	else
		UINFO("Registering DIMMAP fails %d\n", ret);

	return ret;
}

static void __exit hmmap_dimmap_exit(void)
{
	hmmap_unregister_cache_manager(&dimmap);
}

module_init(hmmap_dimmap_init);
module_exit(hmmap_dimmap_exit);

MODULE_AUTHOR("Yuanjiang Ni");
MODULE_LICENSE("GPL");
