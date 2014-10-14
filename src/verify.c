/*
 * verify.c
 *
 * Verify WIM files.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
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
append_lte_to_list(struct wim_lookup_table_entry *lte, void *_list)
{
	list_add(&lte->extraction_list, (struct list_head *)_list);
	return 0;
}

struct verify_stream_list_ctx {
	wimlib_progress_func_t progfunc;
	void *progctx;
	union wimlib_progress_info *progress;
	u64 next_progress;
};

static int
end_verify_stream(struct wim_lookup_table_entry *lte, int status, void *_ctx)
{
	struct verify_stream_list_ctx *ctx = _ctx;
	union wimlib_progress_info *progress = ctx->progress;

	if (status)
		return status;

	progress->verify_streams.completed_streams++;
	progress->verify_streams.completed_bytes += lte->size;

	/* Handle rate-limiting of progress messages  */

	if (progress->verify_streams.completed_bytes < ctx->next_progress)
		return 0;

	/* Time for another progress message.  */

	status = call_progress(ctx->progfunc, WIMLIB_PROGRESS_MSG_VERIFY_STREAMS,
			       progress, ctx->progctx);
	if (status)
		return status;

	if (ctx->next_progress == progress->verify_streams.total_bytes) {
		ctx->next_progress = ~(uint64_t)0;
		return 0;
	}

	/* Send new message as soon as another 1/128 of the total has
	 * been verified.  (Arbitrary number.)  */
	ctx->next_progress = progress->verify_streams.completed_bytes +
			     progress->verify_streams.total_bytes / 128;

	/* ... Unless that would be more than 5000000 bytes, in which case send
	 * the next after the next 5000000 bytes. (Another arbitrary number.) */
	if (progress->verify_streams.completed_bytes + 5000000 < ctx->next_progress)
		ctx->next_progress = progress->verify_streams.completed_bytes + 5000000;

	/* ... But always send a message as soon as we're completely
	 * done.  */
	if (progress->verify_streams.total_bytes < ctx->next_progress)
		ctx->next_progress = progress->verify_streams.total_bytes;
	return 0;
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
	ctx.next_progress = 0;

	ret = call_progress(ctx.progfunc, WIMLIB_PROGRESS_MSG_VERIFY_STREAMS,
			    ctx.progress, ctx.progctx);
	if (ret)
		return ret;

	return read_stream_list(&stream_list,
				offsetof(struct wim_lookup_table_entry,
					 extraction_list),
				&cbs, VERIFY_STREAM_HASHES);
}
