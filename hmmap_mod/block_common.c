// SPDX-License-Identifier: GPL-2.0-only
/*
 * block_common.c - hmmap block device common functionality
 *
 * Copyright (c) 2019 Western Digital Corporation or its affiliates
 * Copyright (c) 2019 Adam Manzanares <adam.manzanares@wdc.com>
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/bio.h>
#include <linux/blkdev.h>

#include "hmmap.h"
#include "hmmap_block.h"

void hmmap_block_end_io_poll(struct bio *bio)
{
	struct task_struct *waiter = bio->bi_private;

	WRITE_ONCE(bio->bi_private, NULL);
	wake_up_process(waiter);
}

void hmmap_block_end_io(struct bio *bio)
{
	struct hmmap_block_complete_private *done = bio->bi_private;
	struct hmmap_block_complete_common *common = done->common;
	struct hmmap_dev *udev = common->udev;
	struct page *page = done->page;

	UDEBUG("HMMAP BLOCK END IO OFFSET: %llu\n", bio->bi_iter.bi_sector);
	if (atomic_dec_and_test(&(common->waiters)))
		complete(&common->done);

	hmmap_release_page(udev, page);
	bio_put(bio);
	kfree(done);
}

int hmmap_block_bio_init(void *cache_address, unsigned long offset,
			 struct bio *bio, struct block_device *bdev)
{
	int ret = 0;

	bio_set_dev(bio, bdev);
	bio->bi_iter.bi_sector = hmmap_sect(offset);
	if (!bio_add_page(bio, vmalloc_to_page(cache_address), PAGE_SIZE, 0)) {
		UINFO("ERROR adding page to bio\n");
		ret = -EIO;
	}

	return ret;
}

int hmmap_block_submit_bio(void *cache_address, unsigned long offset, int op,
			   struct hmmap_block_complete_private *done,
			   bool poll, struct block_device *bdev)
{
	struct bio *bio;
	int ret = 0;
	blk_qc_t qc;

	bio = bio_alloc(GFP_KERNEL, 1);
	ret = hmmap_block_bio_init(cache_address, offset, bio, bdev);
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
			if (!blk_poll(bdev_get_queue(bdev), qc,
				      true))
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
EXPORT_SYMBOL(hmmap_block_submit_bio);


int hmmap_set_bdev(struct hmmap_dev *dev, struct block_device **bdev)
{
	fmode_t mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

	if (!dev->path) {
		UINFO("ERROR HMMAP SET BDEV NO PATH SET\n");
		return -ENXIO;
	}

	*bdev = blkdev_get_by_path(dev->path, mode, dev);
	if (IS_ERR(*bdev)) {
		UINFO("ERROR: %ld, Blkdev get by path: %s\n", PTR_ERR(*bdev),
		      dev->path);
		return PTR_ERR(*bdev);
	}

	if (!(*bdev)->bd_disk) {
		UINFO("Block dev %s has no bi_disk\n", dev->path);
		return -ENXIO;
	}

	return 0;
}
EXPORT_SYMBOL(hmmap_set_bdev);

int hmmap_block_flush_pages(struct hmmap_dev *udev, struct block_device *bdev)
{
	unsigned long off;
	void *cache_address;
	int ret = 0;
	struct hmmap_block_complete_common *cc;
	struct hmmap_block_complete_private *cp;
	struct blk_plug plug;
	struct page *page;

	cc = kmalloc(sizeof(struct hmmap_block_complete_common),
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
		cp = kmalloc(sizeof(struct hmmap_block_complete_private),
			     GFP_KERNEL);
		if (!cp) {
			UINFO("Flush cache error alloc priv completion\n");
			BUG();
		}

		cp->common = cc;
		cp->page = page;
		list_del_init(&page->lru);
		ret = hmmap_block_submit_bio(cache_address, off, REQ_OP_WRITE,
					     cp, false, bdev);
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
EXPORT_SYMBOL(hmmap_block_flush_pages);

void hmmap_put_bdev(struct block_device *bdev)
{
	fmode_t mode = FMODE_READ | FMODE_WRITE | FMODE_EXCL;

	blkdev_put(bdev, mode);
}
EXPORT_SYMBOL(hmmap_put_bdev);

MODULE_AUTHOR("Adam Manzanares");
MODULE_LICENSE("GPL");
