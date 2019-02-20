// SPDX-License-Identifier: GPL-2.0-only
/*
 * block_backend.c - hmmap block device backend
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/module.h>

#include "block_backend.h"
#include "hmmap.h"

struct block_backend_complete_common {
	atomic_t waiters;
	struct completion done;
	struct hmmap_dev *udev;
};

struct block_backend_complete_private {
	struct block_backend_complete_common *common;
	struct task_struct *waiter;
	struct page *page;
};

struct block_backend_info block_info = {};

int hmmap_block_init(unsigned long size, u32 page_size, struct hmmap_dev *dev)
{
	int ret = 0;
	struct block_device *bdev = NULL;
	fmode_t mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

	block_info.size = size;
	block_info.page_size = page_size;
	block_info.dev = dev;

	if (!dev->path) {
		UINFO("ERROR BLOCK BACKEND NO PATH SET\n");
		ret = -ENXIO;
		goto out;
	}

	bdev = blkdev_get_by_path(dev->path, mode, dev);
	if (!bdev) {
		ret = PTR_ERR(bdev);
		UINFO("ERROR: %d, Blkdev get by path: %s\n", ret, dev->path);
		goto out;
	}

	if (!bdev->bd_disk) {
		UINFO("Block dev %s has no bi_disk\n", dev->path);
		ret = -ENXIO;
		goto out;
	}

	block_info.data_buffer = vmalloc(page_size);
	if (!block_info.data_buffer) {
		UINFO("BLOCK BACKEND DATA BUFFER ALLOC FAIL\n");
		ret = -ENOMEM;
		goto out_release_blkdev;
	}

	block_info.bdev = bdev;
	goto out;

out_release_blkdev:
	blkdev_put(bdev, mode);
out:
	return ret;
}

void hmmap_block_end_io_poll(struct bio *bio)
{
	struct task_struct *waiter = bio->bi_private;

	WRITE_ONCE(bio->bi_private, NULL);
	wake_up_process(waiter);
}

void hmmap_block_end_io(struct bio *bio)
{
	struct block_backend_complete_private *done = bio->bi_private;
	struct block_backend_complete_common *common = done->common;
	struct hmmap_dev *udev = common->udev;
	struct page *page = done->page;

	UDEBUG("HMMAP BLOCK END IO OFFSET: %lu\n", bio->bi_iter.bi_sector);
	if (atomic_dec_and_test(&(common->waiters)))
		complete(&common->done);

	hmmap_release_page(udev, page);
	bio_put(bio);
	kfree(done);
}

int hmmap_bio_init(void *cache_address, unsigned long offset, struct bio *bio)
{
	int ret = 0;

	bio_set_dev(bio, block_info.bdev);
	bio->bi_iter.bi_sector = hmmap_sect(offset);
	if (!bio_add_page(bio, vmalloc_to_page(cache_address), PAGE_SIZE, 0)) {
		UINFO("ERROR adding page to bio\n");
		ret = -EIO;
	}

	return ret;
}

int hmmap_block_submit_bio(void *cache_address, unsigned long offset, int op,
			  struct block_backend_complete_private *done,
			  bool poll)
{
	struct bio *bio;
	int ret = 0;
	blk_qc_t qc;

	bio = bio_alloc(GFP_KERNEL, 1);
	ret = hmmap_bio_init(cache_address, offset, bio);
	if (ret)
		goto bio_put;

	bio->bi_opf = op;
	if (poll) {
		bio->bi_private = current;
		bio->bi_end_io = hmmap_block_end_io_poll;
	} else {
		bio->bi_private = done;
		bio->bi_end_io = hmmap_block_end_io;
	}

	qc = submit_bio(bio);

	if (poll) {
		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!READ_ONCE(bio->bi_private))
				break;
			if (!blk_poll(bdev_get_queue(block_info.bdev), qc))
				io_schedule();
		}
		__set_current_state(TASK_RUNNING);
		goto bio_put;
	}

	goto out;

bio_put:
	bio_put(bio);
out:
	return ret;
}

int hmmap_block_fill_cache(void *cache_address, unsigned long offset)
{
	return hmmap_block_submit_bio(cache_address, offset, REQ_OP_READ, NULL,
				     true);
}

int hmmap_block_flush_pages(struct hmmap_dev *udev)
{
	unsigned long off;
	void *cache_address;
	int ret = 0;
	struct block_backend_complete_common *cc;
	struct block_backend_complete_private *cp;
	struct blk_plug plug;
	struct page *page;

	cc = kmalloc(sizeof(struct block_backend_complete_common),
		       GFP_KERNEL);
	if (!cc) {
		UINFO("Flush cache error alloc common completion\n");
		ret = -ENOMEM;
		goto out;
	}

	init_completion(&(cc->done));
	atomic_set(&(cc->waiters), 0);
	cc->udev = udev;
	blk_start_plug(&plug);
	/* Iterate over the list of pages we are asked to flush out */
	while (!list_empty(&udev->dirty_pages)) {
		page = list_first_entry(&udev->dirty_pages, struct page, lru);
		off = page->index;
		cache_address = (void *)page->private;
		UDEBUG("Flushing page with index %lu\n", off);
		atomic_inc(&(cc->waiters));
		cp = kmalloc(sizeof(struct block_backend_complete_private),
			     GFP_KERNEL);
		if (!cp) {
			UINFO("Flush cache error alloc priv completion\n");
			BUG();
		}

		cp->common = cc;
		cp->page = page;
		list_del_init(&page->lru);
		ret = hmmap_block_submit_bio(cache_address, off, REQ_OP_WRITE,
					    cp, false);
		if (ret) {
			UINFO("Error Flush page off: %lu, addr: %p\n", off,
			      cache_address);
			BUG();
		}

	}

	blk_finish_plug(&plug);
	wait_for_completion_io(&(cc->done));
	kfree(cc);

out:
	return ret;
}

void hmmap_block_destroy(void)
{
	fmode_t mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

	vfree(block_info.data_buffer);
	blkdev_put(block_info.bdev, mode);

}

static struct hmmap_backend block_backend = {
	.name = "block_backend",
	.init = hmmap_block_init,
	.get_pfn = NULL,
	.fill_cache = hmmap_block_fill_cache,
	.flush_pages = hmmap_block_flush_pages,
	.destroy = hmmap_block_destroy,
};

static int __init hmmap_block_backend_init(void)
{
	int ret = hmmap_register_backend(&block_backend);

	if (!ret)
		UINFO("BLOCK BACKEND REGISTERED\n");
	else
		UINFO("Registering BLOCK BACKEND FAILS %d\n", ret);

	return ret;
}

static void __exit hmmap_block_backend_exit(void)
{
	hmmap_unregister_backend(&block_backend);
}

module_init(hmmap_block_backend_init);
module_exit(hmmap_block_backend_exit);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");

