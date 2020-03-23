/* SPDX-License-Identifier: GPL-2.0-only
 *
 * two_level_cache.h - hmmap lru2q cache
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#ifndef TWO_LEVEL_CACHE_H
#define TWO_LEVEL_CACHE_H

#include "hmmap.h"

struct two_level_data {
	void *cache;
	struct hmmap_dev *dev;
	unsigned long size;
	unsigned long num_entries;
	unsigned page_size;
	struct list_head active;
	struct list_head inactive;
	struct list_head free;
	unsigned active_size;
	unsigned inactive_size;
	unsigned long recharge_processed;
	unsigned long evict_processed;
	spinlock_t c_lock;
	struct page **evict_list;
	unsigned int evict_list_size;
};

enum two_level_list_type {
	INACTIVE	= 0,
	ACTIVE		= 1,
	FREE		= 2,

};

enum two_level_migrate_work {
	INACTIVE_ACTIVE		= 0,
	ACTIVE_INACTIVE		= 1,
};

#endif
