// SPDX-License-Identifier: GPL-2.0-only
/*
 * list.c - hmmap pluggable infrastructure handling
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */


#include <linux/kernel.h>
#include <linux/module.h>

#include "hmmap.h"

static LIST_HEAD(hmmap_cache_managers);
static LIST_HEAD(hmmap_backends);

struct hmmap_cache_manager *hmmap_find_cache_manager(const char *name)
{
	struct hmmap_cache_manager *cm;

	UDEBUG("Looking for cache manager: %s\n", name);
	list_for_each_entry(cm, &hmmap_cache_managers, list)
		if (!strcmp(name, cm->name)) {
			UDEBUG("Found cache manager: %s\n", cm->name);
			return cm;
		}
	return NULL;
}
EXPORT_SYMBOL(hmmap_find_cache_manager);

struct hmmap_backend *hmmap_find_backend(const char *name)
{
	struct hmmap_backend *be;

	list_for_each_entry(be, &hmmap_backends, list)
		if (!strcmp(name, be->name))
			return be;
	return NULL;
}
EXPORT_SYMBOL(hmmap_find_backend);

int hmmap_register_cache_manager(struct hmmap_cache_manager *cm)
{
	int ret = 0;

	if (hmmap_find_cache_manager(cm->name))
		ret = -EEXIST;
	else
		list_add(&cm->list, &hmmap_cache_managers);

	return ret;
}
EXPORT_SYMBOL(hmmap_register_cache_manager);

int hmmap_register_backend(struct hmmap_backend *be)
{
	int ret = 0;

	if (hmmap_find_backend(be->name))
		ret = -EEXIST;
	else
		list_add(&be->list, &hmmap_backends);

	return ret;
}
EXPORT_SYMBOL(hmmap_register_backend);

void hmmap_unregister_cache_manager(struct hmmap_cache_manager *cm)
{
	if (!hmmap_find_cache_manager(cm->name)) {
		UINFO("unregister unknown cache manager %s\n", cm->name);
		BUG();
	}

	list_del(&cm->list);
}
EXPORT_SYMBOL(hmmap_unregister_cache_manager);

void hmmap_unregister_backend(struct hmmap_backend *be)
{
	if (!hmmap_find_backend(be->name)) {
		UINFO("unregister unknown backend %s\n", be->name);
		BUG();
	}

	list_del(&be->list);
}
EXPORT_SYMBOL(hmmap_unregister_backend);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");
