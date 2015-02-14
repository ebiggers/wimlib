/*
 * split.c
 *
 * Split a WIM file into parts.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include "wimlib.h"
#include "wimlib/alloca.h"
#include "wimlib/error.h"
#include "wimlib/list.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/progress.h"
#include "wimlib/resource.h"
#include "wimlib/wim.h"
#include "wimlib/write.h"

struct swm_part_info {
	struct list_head stream_list;
	u64 size;
};

static void
copy_part_info(struct swm_part_info *dst, struct swm_part_info *src)
{
	list_transfer(&src->stream_list, &dst->stream_list);
	dst->size = src->size;
}

struct swm_info {
	struct swm_part_info *parts;
	unsigned num_parts;
	unsigned num_alloc_parts;
	u64 total_bytes;
	u64 max_part_size;
};

static int
write_split_wim(WIMStruct *orig_wim, const tchar *swm_name,
		struct swm_info *swm_info, int write_flags)
{
	size_t swm_name_len;
	tchar *swm_name_buf;
	const tchar *dot;
	tchar *swm_suffix;
	size_t swm_base_name_len;

	union wimlib_progress_info progress;
	unsigned part_number;
	int ret;
	u8 guid[WIMLIB_GUID_LEN];

	swm_name_len = tstrlen(swm_name);
	swm_name_buf = alloca((swm_name_len + 20) * sizeof(tchar));
	tstrcpy(swm_name_buf, swm_name);
	dot = tstrchr(swm_name_buf, T('.'));
	if (dot) {
		swm_base_name_len = dot - swm_name_buf;
		swm_suffix = alloca((tstrlen(dot) + 1) * sizeof(tchar));
		tstrcpy(swm_suffix, dot);
	} else {
		swm_base_name_len = swm_name_len;
		swm_suffix = alloca(1 * sizeof(tchar));
		swm_suffix[0] = T('\0');
	}

	progress.split.completed_bytes = 0;
	progress.split.total_bytes = 0;
	for (part_number = 1; part_number <= swm_info->num_parts; part_number++)
		progress.split.total_bytes += swm_info->parts[part_number - 1].size;
	progress.split.total_parts = swm_info->num_parts;

	randomize_byte_array(guid, WIMLIB_GUID_LEN);

	for (part_number = 1; part_number <= swm_info->num_parts; part_number++) {
		int part_write_flags;
		wimlib_progress_func_t progfunc;

		if (part_number != 1) {
			tsprintf(swm_name_buf + swm_base_name_len,
				 T("%u%"TS), part_number, swm_suffix);
		}

		progress.split.cur_part_number = part_number;
		progress.split.part_name = swm_name_buf;

		ret = call_progress(orig_wim->progfunc,
				    WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART,
				    &progress,
				    orig_wim->progctx);
		if (ret)
			return ret;

		part_write_flags = write_flags;
		part_write_flags |= WIMLIB_WRITE_FLAG_USE_EXISTING_TOTALBYTES;
		if (part_number != 1)
			part_write_flags |= WIMLIB_WRITE_FLAG_NO_METADATA;

		progfunc = orig_wim->progfunc;
		orig_wim->progfunc = NULL;
		ret = write_wim_part(orig_wim,
				     progress.split.part_name,
				     WIMLIB_ALL_IMAGES,
				     part_write_flags,
				     1,
				     part_number,
				     swm_info->num_parts,
				     &swm_info->parts[part_number - 1].stream_list,
				     guid);
		orig_wim->progfunc = progfunc;
		if (ret)
			return ret;

		progress.split.completed_bytes += swm_info->parts[part_number - 1].size;

		ret = call_progress(orig_wim->progfunc,
				    WIMLIB_PROGRESS_MSG_SPLIT_END_PART,
				    &progress,
				    orig_wim->progctx);
		if (ret)
			return ret;
	}
	return 0;
}

static int
add_stream_to_swm(struct wim_lookup_table_entry *lte, void *_swm_info)
{
	struct swm_info *swm_info = _swm_info;
	u64 stream_size;

	if (lte_is_partial(lte)) {
		ERROR("Splitting of WIM containing solid resources is not supported.\n"
		      "        Export it in non-solid format first.");
		return WIMLIB_ERR_UNSUPPORTED;
	}
	if (lte->resource_location == RESOURCE_IN_WIM)
		stream_size = lte->rspec->size_in_wim;
	else
		stream_size = lte->size;

	/* - Start first part if no parts have been started so far;
	 * - Start next part if adding this stream exceeds maximum part size,
	 *   UNLESS the stream is metadata or if no streams at all have been
	 *   added to the current part.
	 */
	if (swm_info->num_parts == 0 ||
	    ((swm_info->parts[swm_info->num_parts - 1].size +
			stream_size >= swm_info->max_part_size)
	     && !((lte->flags & WIM_RESHDR_FLAG_METADATA) ||
		   swm_info->parts[swm_info->num_parts - 1].size == 0)))
	{
		if (swm_info->num_parts == swm_info->num_alloc_parts) {
			struct swm_part_info *parts;
			size_t num_alloc_parts = swm_info->num_alloc_parts;

			num_alloc_parts += 8;
			parts = MALLOC(num_alloc_parts * sizeof(parts[0]));
			if (!parts)
				return WIMLIB_ERR_NOMEM;

			for (unsigned i = 0; i < swm_info->num_parts; i++)
				copy_part_info(&parts[i], &swm_info->parts[i]);

			FREE(swm_info->parts);
			swm_info->parts = parts;
			swm_info->num_alloc_parts = num_alloc_parts;
		}
		swm_info->num_parts++;
		INIT_LIST_HEAD(&swm_info->parts[swm_info->num_parts - 1].stream_list);
		swm_info->parts[swm_info->num_parts - 1].size = 0;
	}
	swm_info->parts[swm_info->num_parts - 1].size += stream_size;
	if (!(lte->flags & WIM_RESHDR_FLAG_METADATA)) {
		list_add_tail(&lte->write_streams_list,
			      &swm_info->parts[swm_info->num_parts - 1].stream_list);
	}
	swm_info->total_bytes += stream_size;
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_split(WIMStruct *wim, const tchar *swm_name,
	     u64 part_size, int write_flags)
{
	struct swm_info swm_info;
	unsigned i;
	int ret;

	if (swm_name == NULL || swm_name[0] == T('\0') || part_size == 0)
		return WIMLIB_ERR_INVALID_PARAM;

	if (write_flags & ~WIMLIB_WRITE_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;

	if (!wim_has_metadata(wim))
		return WIMLIB_ERR_METADATA_NOT_FOUND;

	memset(&swm_info, 0, sizeof(swm_info));
	swm_info.max_part_size = part_size;

	for (i = 0; i < wim->hdr.image_count; i++) {
		ret = add_stream_to_swm(wim->image_metadata[i]->metadata_lte,
					&swm_info);
		if (ret)
			goto out_free_swm_info;
	}

	ret = for_lookup_table_entry_pos_sorted(wim->lookup_table,
						add_stream_to_swm,
						&swm_info);
	if (ret)
		goto out_free_swm_info;

	ret = write_split_wim(wim, swm_name, &swm_info, write_flags);
out_free_swm_info:
	FREE(swm_info.parts);
	return ret;
}
