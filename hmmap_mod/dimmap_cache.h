/* SPDX-License-Identifier: GPL-2.0-only
 *
 * dimmap.h - hmmap dimmap like cache
 *
 * Inspired by https://bitbucket.org/vanessen/di-mmap
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Yuanjiang Ni <yuanjiang.ni@wdc.com>
 *
 */

#ifndef DIMMAP_CACHE_H
#define DIMMAP_CACHE_H

#include <linux/hashtable.h>
#include "hmmap.h"

#define HASH_SIZE_BIT 10
#define PRIMARY_RATIO 40
#define HOTPAGE_RATIO 40


// which queue am i in?
enum status {
	IN_FREE = 0,
	IN_PRIMARY,
	IN_HOTPAGE,
	IN_EVICTION,
	NUM_OF_STATUS
};

//They are exclusive!
#define FREE (1 << IN_FREE)
#define PRIMARY (1 << IN_PRIMARY)
#define HOTPAGE (1 << IN_HOTPAGE)
#define EVICTON (1 << IN_EVICTION)

// Since the "private" field is already being used to store the
// cache address. I use a "wrapper" to store dimmap-related per-page
// info.

struct dimmap_page {
	struct page *page;
	struct hlist_node hlist;
	struct list_head list;
	u32 flag;
	u32 faults;
};

struct dimmap_data {
	void *cache;
	struct hmmap_dev *dev;
	u32 page_size;
	unsigned long capacity_in_bytes;
	unsigned long total_capacity;
	unsigned long primary_capacity;
	unsigned long eviction_capacity;
	unsigned long hotpage_capacity;

	struct list_head free; //free page list
	struct list_head primary; //primary FIFO
	struct list_head hotpage; // Hotpage FIFO
	struct list_head eviction; //eviction queue
	unsigned long free_size;
	unsigned long primary_size;
	unsigned long hotpage_size;
	unsigned long eviction_size;

	DECLARE_HASHTABLE(location_table, HASH_SIZE_BIT); // page location table
	u32 fault_couts[1 << (HASH_SIZE_BIT)]; // fault counts per bucket
	unsigned long global_faults;
	struct dimmap_page *di_pages;

	/*statistic info goes here*/
	unsigned long recovery_counts;
};

#endif
