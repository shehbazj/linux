// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2016 CNEX Labs
 * Initial release: Javier Gonzalez <javier@cnexlabs.com>
 *                  Matias Bjorling <matias@cnexlabs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * pblk-cache.c - pblk's write cache
 */

#include "pblk.h"

int pblk_write_to_cache(struct pblk *pblk, struct bio *bio, unsigned long flags)
{
	struct request_queue *q = pblk->dev->q;
	// w_ctx is used per entry of buffer. each entry has bio, lba and ppa
	// associated with it.
	struct pblk_w_ctx w_ctx;
	// get lba from the bio
	sector_t lba = pblk_get_lba(bio);
	unsigned long start_time = jiffies;
	unsigned int bpos, pos;
	// pblk_write_to_cache is called for each bio write
	int nr_entries = pblk_get_secs(bio);
	int i, ret;

	generic_start_io_acct(q, REQ_OP_WRITE, bio_sectors(bio),
			      &pblk->disk->part0);

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:

	// ppa mapping initialized here (bpos is initialized to mem here)
	// nr_entries - number of sectors in bio to be written
	ret = pblk_rb_may_write_user(&pblk->rwb, bio, nr_entries, &bpos);
	// this will return NVM_IO_REQUEUE if sanity checks on rb such as
	// insufficient space on rb is detected. 
	// returns NVM_IO_OK or NVM_IO_DONE if things are set to be written
	// correctly to rb eg. flush point pointer. 
	// 
	switch (ret) {
	case NVM_IO_REQUEUE:
		io_schedule();
		goto retry;
	case NVM_IO_ERR:
		pblk_pipeline_stop(pblk);
		goto out;
	}

	// write context ppa set empty here. no writes have been performed yet.
	// all sanity checks have been done. space has been made in rb to 
	// accomodate the writes.
	
	pblk_ppa_set_empty(&w_ctx.ppa);
	w_ctx.flags = flags;
	// kick write thread if preflush is required.
	if (bio->bi_opf & REQ_PREFLUSH) {
		w_ctx.flags |= PBLK_FLUSH_ENTRY;
		pblk_write_kick(pblk);
	}

	if (unlikely(!bio_has_data(bio)))
		goto out;

	for (i = 0; i < nr_entries; i++) {
		void *data = bio_data(bio);

		w_ctx.lba = lba + i;

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + i);
//		pr_info("lba = %llu pos = %u\n", w_ctx.lba, pos);
		// this is where writes happen to cache, and 
		// mapping between lbas in bio blocks and ppas
		// of the cache are stored in the l2pmap.
		pblk_rb_write_entry_user(&pblk->rwb, data, w_ctx, pos);

		bio_advance(bio, PBLK_EXPOSED_PAGE_SIZE);
	}

	atomic64_add(nr_entries, &pblk->user_wa);

#ifdef CONFIG_NVM_PBLK_DEBUG
	atomic_long_add(nr_entries, &pblk->inflight_writes);
	atomic_long_add(nr_entries, &pblk->req_writes);
#endif

	pblk_rl_inserted(&pblk->rl, nr_entries);

out:
	generic_end_io_acct(q, REQ_OP_WRITE, &pblk->disk->part0, start_time);
	pblk_write_should_kick(pblk);
	return ret;
}

/*
 * On GC the incoming lbas are not necessarily sequential. Also, some of the
 * lbas might not be valid entries, which are marked as empty by the GC thread
 */
int pblk_write_gc_to_cache(struct pblk *pblk, struct pblk_gc_rq *gc_rq)
{
	struct pblk_w_ctx w_ctx;
	unsigned int bpos, pos;
	void *data = gc_rq->data;
	int i, valid_entries;

	/* Update the write buffer head (mem) with the entries that we can
	 * write. The write in itself cannot fail, so there is no need to
	 * rollback from here on.
	 */
retry:
	if (!pblk_rb_may_write_gc(&pblk->rwb, gc_rq->secs_to_gc, &bpos)) {
		io_schedule();
		goto retry;
	}

	w_ctx.flags = PBLK_IOTYPE_GC;
	pblk_ppa_set_empty(&w_ctx.ppa);

	for (i = 0, valid_entries = 0; i < gc_rq->nr_secs; i++) {
		if (gc_rq->lba_list[i] == ADDR_EMPTY)
			continue;

		w_ctx.lba = gc_rq->lba_list[i];

		pos = pblk_rb_wrap_pos(&pblk->rwb, bpos + valid_entries);
		pblk_rb_write_entry_gc(&pblk->rwb, data, w_ctx, gc_rq->line,
						gc_rq->paddr_list[i], pos);

		data += PBLK_EXPOSED_PAGE_SIZE;
		valid_entries++;
	}

	WARN_ONCE(gc_rq->secs_to_gc != valid_entries,
					"pblk: inconsistent GC write\n");

	atomic64_add(valid_entries, &pblk->gc_wa);

#ifdef CONFIG_NVM_PBLK_DEBUG
	atomic_long_add(valid_entries, &pblk->inflight_writes);
	atomic_long_add(valid_entries, &pblk->recov_gc_writes);
#endif

	pblk_write_should_kick(pblk);
	return NVM_IO_OK;
}
