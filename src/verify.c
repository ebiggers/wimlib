/*
 * verify.c
 *
 * Verify WIM files.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/progress.h"
#include "wimlib/security.h"

static int
lte_fix_refcnt(struct wim_lookup_table_entry *lte, void *ctr)
{
	if (lte->refcnt != lte->real_refcnt) {
		lte->refcnt = lte->real_refcnt;
		++*(unsigned long *)ctr;
	}
	return 0;
}

static void
tally_inode_refcnts(const struct wim_inode *inode,
		    const struct wim_lookup_table *lookup_table)
{
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		struct wim_lookup_table_entry *lte;
		lte = inode_stream_lte(inode, i, lookup_table);
		if (lte)
			lte->real_refcnt += inode->i_nlink;
	}
}


static int
tally_image_refcnts(WIMStruct *wim)
{
	const struct wim_image_metadata *imd;
	const struct wim_inode *inode;

	imd = wim_get_current_image_metadata(wim);
	image_for_each_inode(inode, imd)
		tally_inode_refcnts(inode, wim->lookup_table);
	return 0;
}


/* Ideally this would be unnecessary... however, the WIMs for Windows 8 are
 * screwed up because some lookup table entries are referenced more times than
 * their stated reference counts.  So theoretically, if we delete all the
 * references to a stream and then remove it, it might still be referenced
 * somewhere else, making a file be missing from the WIM... So, work around this
 * problem by looking at ALL the images to re-calculate the reference count of
 * EVERY lookup table entry.  This only absolutely has to be done before an image
 * is deleted or before an image is mounted read-write. */
int
wim_recalculate_refcnts(WIMStruct *wim)
{
	unsigned long num_ltes_with_bogus_refcnt = 0;
	int ret;

	for_lookup_table_entry(wim->lookup_table, lte_zero_real_refcnt, NULL);
	ret = for_image(wim, WIMLIB_ALL_IMAGES, tally_image_refcnts);
	if (ret)
		return ret;
	num_ltes_with_bogus_refcnt = 0;
	for_lookup_table_entry(wim->lookup_table, lte_fix_refcnt,
			       &num_ltes_with_bogus_refcnt);
	if (num_ltes_with_bogus_refcnt != 0) {
		WARNING("%lu stream(s) had incorrect reference count.",
			num_ltes_with_bogus_refcnt);
	}
	wim->refcnts_ok = 1;
	return 0;
}

static int
append_lte_to_list(struct wim_lookup_table_entry *lte, void *_list)
{
	list_add(&lte->extraction_list, (struct list_head *)_list);
	return 0;
}

struct verify_stream_list_ctx {
	wimlib_progress_func_t progfunc;
	void *progctx;
	union wimlib_progress_info *progress;
};

static int
end_verify_stream(struct wim_lookup_table_entry *lte, int status, void *_ctx)
{
	struct verify_stream_list_ctx *ctx = _ctx;

	if (status)
		return status;

	ctx->progress->verify_streams.completed_streams++;
	ctx->progress->verify_streams.completed_bytes += lte->size;

	return call_progress(ctx->progfunc, WIMLIB_PROGRESS_MSG_VERIFY_STREAMS,
			     ctx->progress, ctx->progctx);
}

static int
verify_image_streams_present(struct wim_image_metadata *imd,
			     struct wim_lookup_table *lookup_table)
{
	struct wim_inode *inode;
	int ret;

	image_for_each_inode(inode, imd) {
		ret = inode_resolve_streams(inode, lookup_table, false);
		if (ret)
			return ret;
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_verify_wim(WIMStruct *wim, int verify_flags)
{
	int ret;
	LIST_HEAD(stream_list);
	union wimlib_progress_info progress;
	struct verify_stream_list_ctx ctx;
	struct wim_lookup_table_entry *lte;
	struct read_stream_list_callbacks cbs = {
		.end_stream = end_verify_stream,
		.end_stream_ctx = &ctx,
	};

	/* Check parameters  */

	if (!wim)
		return WIMLIB_ERR_INVALID_PARAM;

	if (verify_flags)
		return WIMLIB_ERR_INVALID_PARAM;

	/* Verify the images  */

	if (wim_has_metadata(wim)) {

		memset(&progress, 0, sizeof(progress));
		progress.verify_image.wimfile = wim->filename;
		progress.verify_image.total_images = wim->hdr.image_count;

		for (int i = 1; i <= wim->hdr.image_count; i++) {

			progress.verify_image.current_image = i;

			ret = call_progress(wim->progfunc, WIMLIB_PROGRESS_MSG_BEGIN_VERIFY_IMAGE,
					    &progress, wim->progctx);
			if (ret)
				return ret;

			ret = select_wim_image(wim, i);
			if (ret)
				return ret;

			ret = verify_image_streams_present(wim_get_current_image_metadata(wim),
							   wim->lookup_table);
			if (ret)
				return ret;

			ret = call_progress(wim->progfunc, WIMLIB_PROGRESS_MSG_END_VERIFY_IMAGE,
					    &progress, wim->progctx);
			if (ret)
				return ret;
		}
	} else {
		WARNING("\"%"TS"\" does not contain image metadata.  Skipping image verification.",
			wim->filename);
	}

	/* Verify the streams  */

	for_lookup_table_entry(wim->lookup_table, append_lte_to_list, &stream_list);

	memset(&progress, 0, sizeof(progress));

	progress.verify_streams.wimfile = wim->filename;
	list_for_each_entry(lte, &stream_list, extraction_list) {
		progress.verify_streams.total_streams++;
		progress.verify_streams.total_bytes += lte->size;
	}

	ctx.progfunc = wim->progfunc;
	ctx.progctx = wim->progctx;
	ctx.progress = &progress;

	ret = call_progress(ctx.progfunc, WIMLIB_PROGRESS_MSG_VERIFY_STREAMS,
			    ctx.progress, ctx.progctx);
	if (ret)
		return ret;

	return read_stream_list(&stream_list,
				offsetof(struct wim_lookup_table_entry,
					 extraction_list),
				&cbs, VERIFY_STREAM_HASHES);
}
