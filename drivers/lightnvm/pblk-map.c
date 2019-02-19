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
 * pblk-map.c - pblk's lba-ppa mapping strategy
 *
 */

#include "pblk.h"

static void get_secs_reqd_per_lun(__le64 *lba_list, int *nr_secs_per_lun)
{
	int i;
	for (i = 0; i < 20 ;  i++){
		nr_secs_per_lun[i] = 2;
	}
}

// sentry = rb smem offset. ppa_list- populated in this function
// meta_list = OOB region buffer for only valid_secs
// valid_secs = map_secs = min secs to map or valid % min secs

static int pblk_map_page_data(struct pblk *pblk, unsigned int sentry,
			      struct ppa_addr *ppa_list,
			      unsigned long *lun_bitmap,
			      void *meta_list,
			      unsigned int valid_secs)
{
	// get l_mg.data line
	struct pblk_line *line = pblk_line_get_data(pblk);
	struct pblk_emeta *emeta;
	struct pblk_w_ctx *w_ctx;

	__le64 *lba_list, all_lbas[8];
	int nr_secs = pblk->min_write_pgs;
	int i;

	// XXX change 20 to nr_luns
	int nr_secs_per_lun[20];
	// XXX change 20 to nr_secs / pblk->min_write_pgs;
	u64 paddr_list[20];

	BUG_ON(nr_secs > 20);

	if (!line)
		return -ENOSPC;

	// line->left_msecs = 0, open new line.
	if (pblk_line_is_full(line, pblk)) {
		struct pblk_line *prev_line = line;

		/* If we cannot allocate a new line, make sure to store metadata
		 * on current line and then fail
		 */
		pr_info("%s():calling line replace data\n",__func__);
		line = pblk_line_replace_data(pblk);
		pr_info("%s():calling line close meta\n",__func__);
		pblk_line_close_meta(pblk, prev_line);
		//pblk_line_close(pblk, prev_line);

		if (!line) {
			pblk_pipeline_stop(pblk);
			return -ENOSPC;
		}
	}

	// end meta
	emeta = line->emeta;
	// this is to store lbas from [rb w_ctx->lba] in the endmeta buffer
	lba_list = emeta_to_lbas(pblk, emeta->buf);
	get_secs_reqd_per_lun(lba_list, nr_secs_per_lun);

	// get all lbas first:
	for (i = 0 ; i < valid_secs ; i++) {
		w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
		all_lbas[i] = cpu_to_le64(w_ctx->lba);
//		pr_info("%s():mapping lba %llu\n", __func__,all_lbas[i]);
	}

	// nr_secs = min write pages = 8

//	pr_info("%s():calling pblk alloc page data\n",__func__);
	pblk_alloc_page_data(pblk, line, nr_secs_per_lun, paddr_list, nr_secs);
//	for(i = 0 ; i < nr_secs; i++ ){
//		pr_info("%s(): paddr returned = %llu\n",__func__, paddr_list[i]);
//	}
//	paddr = pblk_alloc_page(pblk, line, nr_secs);

	for (i = 0; i < nr_secs; i++ /*, paddr++ */) {
		struct pblk_sec_meta *meta = pblk_get_meta(pblk, meta_list, i);
		__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

		/* ppa to be sent to the device */
		//pr_info("%s():paddr=%llu\n", __func__,paddr_list[i]);

		/* Write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and a single writer thread have access to each specific entry
		 * at a time. Thus, it is safe to modify the context for the
		 * entry we are setting up for submission without taking any
		 * lock or memory barrier.
		 */
		if (i < valid_secs) {
		//	ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);
			ppa_list[i] = addr_to_gen_ppa(pblk, paddr_list[i], line->id);
			kref_get(&line->ref);
			w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
			w_ctx->ppa = ppa_list[i];
			meta->lba = cpu_to_le64(w_ctx->lba);
			lba_list[paddr_list[i]] = cpu_to_le64(w_ctx->lba);
//			pr_info("%s():lba = %llu ppa = %llu\n", __func__, lba_list[paddr_list[i]], paddr_list[i]);
			if (lba_list[paddr_list[i]] != addr_empty)
				line->nr_valid_lbas++;
			else
				atomic64_inc(&pblk->pad_wa);
		} else {
			lba_list[paddr_list[i]] = addr_empty;
			meta->lba = addr_empty;
			__pblk_map_invalidate(pblk, line, paddr_list[i]);
		}
	}

	pblk_down_rq(pblk, ppa_list[0], lun_bitmap);
//	pr_info("%s():exit\n",__func__);
	return 0;
}

// sentry = old subm. valid_secs = secs_available, off = 0
// return 0 - good execution. might return -ENOSPC.
int pblk_map_rq(struct pblk *pblk, struct nvm_rq *rqd, unsigned int sentry,
		 unsigned long *lun_bitmap, unsigned int valid_secs,
		 unsigned int off)
{
	// get OOB area that contains page metadata
	void *meta_list = pblk_get_meta_for_writes(pblk, rqd);
	void *meta_buffer;
	struct ppa_addr *ppa_list = nvm_rq_to_ppa_list(rqd);
	unsigned int map_secs;
	int min = pblk->min_write_pgs;
	int i;
	int ret;

//	pr_info("%s():init\n",__func__);
	for (i = off; i < rqd->nr_ppas; i += min) {
		// keep mapping min secs at a time. other than the last
		// write where we map only valid secs % min.
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		// query the OOB metalist that returns i offset of the list
		meta_buffer = pblk_get_meta(pblk, meta_list, i);
		// map each buffer in cacheline to write context.
		ret = pblk_map_page_data(pblk, sentry + i, &ppa_list[i],
					lun_bitmap, meta_buffer, map_secs);
		if (ret) {
			pr_info("%s():exit with ret %d\n",__func__, ret);
			return ret;
		}
	}

//	pr_info("%s():exit\n",__func__);
	return 0;
}

/* only if erase_ppa is set, acquire erase semaphore */
int pblk_map_erase_rq(struct pblk *pblk, struct nvm_rq *rqd,
		       unsigned int sentry, unsigned long *lun_bitmap,
		       unsigned int valid_secs, struct ppa_addr *erase_ppa)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line_meta *lm = &pblk->lm;
	void *meta_list = pblk_get_meta_for_writes(pblk, rqd);
	void *meta_buffer;
	struct ppa_addr *ppa_list = nvm_rq_to_ppa_list(rqd);
	struct pblk_line *e_line, *d_line;
	unsigned int map_secs;
	int min = pblk->min_write_pgs;
	int i, erase_lun;
	int ret;

	pr_info("%s():nr_ppas=%d\n",__func__,rqd->nr_ppas);
	for (i = 0; i < rqd->nr_ppas; i += min) {
		map_secs = (i + min > valid_secs) ? (valid_secs % min) : min;
		// get meta for only 1 ppa.
		pr_info("%s():pblk_sec meta size %lu oobsize %d\n",__func__,sizeof(struct pblk_sec_meta), pblk->oob_meta_size);
		meta_buffer = pblk_get_meta(pblk, meta_list, i);
		// map sectors after sentry in write context - sentry + i
		// of size map_secs.	
		ret = pblk_map_page_data(pblk, sentry + i, &ppa_list[i],
					lun_bitmap, meta_buffer, map_secs);
		if (ret) {
			pr_info("%s():failed to map page data\n",__func__);
			return ret;
		}

		erase_lun = pblk_ppa_to_pos(geo, ppa_list[i]);

		/* line can change after page map. We might also be writing the
		 * last line.
		 */
		e_line = pblk_line_get_erase(pblk);
		if (!e_line) {
			pr_info("%s():did not get erase line call and return pblk_map_rq\n",__func__);
			return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
							valid_secs, i + min);
		}else {
			pr_info("%s():got next erase line %d\n", __func__,e_line->id);
		}

		spin_lock(&e_line->lock);
		if (!test_bit(erase_lun, e_line->erase_bitmap)) {
			pr_info("%s():erase_lun %d was unset\n", __func__, erase_lun);
			set_bit(erase_lun, e_line->erase_bitmap);
			atomic_dec(&e_line->left_eblks);

			*erase_ppa = ppa_list[i];
			erase_ppa->a.blk = e_line->id;

			spin_unlock(&e_line->lock);

			/* Avoid evaluating e_line->left_eblks */
			return pblk_map_rq(pblk, rqd, sentry, lun_bitmap,
							valid_secs, i + min);
		}
		spin_unlock(&e_line->lock);
	}

	d_line = pblk_line_get_data(pblk);
	pr_info("%s():data line = %d\n",__func__, d_line->id);

	/* line can change after page map. We might also be writing the
	 * last line.
	 */
	e_line = pblk_line_get_erase(pblk);
	pr_info("%s():erase line = %d\n",__func__, e_line->id);
	if (!e_line)
		return -ENOSPC;

	/* Erase blocks that are bad in this line but might not be in next */
	if (unlikely(pblk_ppa_empty(*erase_ppa)) && 
		bitmap_weight(d_line->blk_bitmap, lm->blk_per_line)) {
		int bit = -1;

retry:
		pr_info("%s():retry\n",__func__);
		bit = find_next_bit(d_line->blk_bitmap,
						lm->blk_per_line, bit + 1);
		if (bit >= lm->blk_per_line)
			return 0;

		spin_lock(&e_line->lock);
		if (test_bit(bit, e_line->erase_bitmap)) {
			spin_unlock(&e_line->lock);
			goto retry;
		}
		spin_unlock(&e_line->lock);

		set_bit(bit, e_line->erase_bitmap);
		atomic_dec(&e_line->left_eblks);
		*erase_ppa = pblk->luns[bit].bppa; /* set ch and lun */
		erase_ppa->a.blk = e_line->id;
	}else {
		pr_info("%s():exit():bitmap weight %d\n",__func__, bitmap_weight(d_line->blk_bitmap, lm->blk_per_line));
	}

	return 0;
}
