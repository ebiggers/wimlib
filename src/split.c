/*
 * split.c
 *
 * Split a WIM file into parts.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include "wimlib.h"
#include "wimlib/buffer_io.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/types.h"
#include "wimlib/write.h"
#include "wimlib/list.h"

#include <fcntl.h> /* for open() */
#include <unistd.h> /* for close() */

struct split_args {
	WIMStruct *w;
	tchar *swm_base_name;
	size_t swm_base_name_len;
	const tchar *swm_suffix;
	struct list_head lte_list;
	int cur_part_number;
	int write_flags;
	long size_remaining;
	size_t part_size;
	wimlib_progress_func_t progress_func;
	union wimlib_progress_info progress;
};

static int
finish_swm(WIMStruct *w, struct list_head *lte_list,
	   int write_flags, wimlib_progress_func_t progress_func)
{
	int ret;

	ret = write_lookup_table_from_stream_list(lte_list, w->out_fd,
						  &w->hdr.lookup_table_res_entry);
	if (ret)
		return ret;
	return finish_write(w, WIMLIB_ALL_IMAGES,
			    write_flags | WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE,
			    progress_func);
}

static int
copy_resource_to_swm(struct wim_lookup_table_entry *lte, void *_args)
{
	struct split_args *args = (struct split_args*)_args;
	WIMStruct *w = args->w;
	int ret;

	/* metadata resources were already written. */
	if (lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA)
		return 0;

	if (args->size_remaining < 0 ||
			(u64)args->size_remaining < lte->resource_entry.size) {

		/* No space for this resource.  Finish the previous swm and
		 * start a new one. */

		ret = finish_swm(w, &args->lte_list, args->write_flags,
				 args->progress_func);
		if (ret)
			return ret;

		if (args->progress_func) {
			args->progress_func(WIMLIB_PROGRESS_MSG_SPLIT_END_PART,
					    &args->progress);
		}

		INIT_LIST_HEAD(&args->lte_list);
		args->cur_part_number++;

		tsprintf(args->swm_base_name + args->swm_base_name_len, T("%d%"TS),
			 args->cur_part_number, args->swm_suffix);

		w->hdr.part_number = args->cur_part_number;

		if (args->progress_func) {
			args->progress.split.cur_part_number = args->cur_part_number;
			args->progress_func(WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART,
					    &args->progress);
		}

		ret = begin_write(w, args->swm_base_name, args->write_flags);
		if (ret)
			return ret;
		args->size_remaining = args->part_size;
	}
	args->size_remaining -= lte->resource_entry.size;
	args->progress.split.completed_bytes += lte->resource_entry.size;
	list_add_tail(&lte->swm_stream_list, &args->lte_list);
	return copy_resource(lte, w);
}

/* Splits the WIM file @w into multiple parts prefixed by @swm_name with size at
 * most @part_size bytes. */
WIMLIBAPI int
wimlib_split(WIMStruct *w, const tchar *swm_name,
	     size_t part_size, int write_flags,
	     wimlib_progress_func_t progress_func)
{
	int ret;
	struct wim_header hdr_save;
	struct split_args args;
	const tchar *swm_suffix;
	size_t swm_name_len;
	size_t swm_base_name_len;

	if (!swm_name || part_size == 0)
		return WIMLIB_ERR_INVALID_PARAM;

	if (w->hdr.total_parts != 1)
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;

	write_flags &= WIMLIB_WRITE_MASK_PUBLIC;

	ret = wim_checksum_unhashed_streams(w);
	if (ret)
		return ret;

	swm_name_len = tstrlen(swm_name);
	tchar swm_base_name[swm_name_len + 20];

	memcpy(&hdr_save, &w->hdr, sizeof(struct wim_header));
	w->hdr.flags |= WIM_HDR_FLAG_SPANNED;
	w->hdr.boot_idx = 0;
	randomize_byte_array(w->hdr.guid, WIM_GID_LEN);
	ret = begin_write(w, swm_name, write_flags);
	if (ret)
		goto out;

	tmemcpy(swm_base_name, swm_name, swm_name_len + 1);

	swm_suffix = tstrchr(swm_name, T('.'));
	if (swm_suffix) {
		swm_base_name_len = swm_suffix - swm_name;
	} else {
		swm_base_name_len = swm_name_len;
		swm_base_name[ARRAY_LEN(swm_base_name) - 1] = T('\0');
		swm_suffix = &swm_base_name[ARRAY_LEN(swm_base_name) - 1];
	}

	args.w                              = w;
	args.swm_base_name                  = swm_base_name;
	args.swm_base_name_len              = swm_base_name_len;
	args.swm_suffix                     = swm_suffix;
	INIT_LIST_HEAD(&args.lte_list);
	args.cur_part_number                = 1;
	args.write_flags                    = write_flags;
	args.size_remaining                 = part_size;
	args.part_size                      = part_size;
	args.progress_func                  = progress_func;
	args.progress.split.total_bytes     = lookup_table_total_stream_size(w->lookup_table);
	args.progress.split.cur_part_number = 1;
	args.progress.split.completed_bytes = 0;
	args.progress.split.part_name       = swm_base_name;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_SPLIT_BEGIN_PART,
			      &args.progress);
	}

	for (int i = 0; i < w->hdr.image_count; i++) {
		struct wim_lookup_table_entry *metadata_lte;
		metadata_lte = w->image_metadata[i]->metadata_lte;
		ret = copy_resource(metadata_lte, w);
		if (ret)
			goto out;
		args.size_remaining -= metadata_lte->resource_entry.size;
		args.progress.split.completed_bytes += metadata_lte->resource_entry.size;
		/* Careful: The metadata lookup table entries must be added in
		 * order of the images. */
		list_add_tail(&metadata_lte->swm_stream_list, &args.lte_list);
	}

	ret = for_lookup_table_entry_pos_sorted(w->lookup_table,
						copy_resource_to_swm,
						&args);
	if (ret)
		goto out;

	ret = finish_swm(w, &args.lte_list, write_flags, progress_func);
	if (ret)
		goto out;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_SPLIT_END_PART,
			      &args.progress);
	}

	/* The swms are all ready now, except the total_parts and part_number
	 * fields in their headers are wrong (since we don't know the total
	 * parts until they are all written).  Fix them. */
	int total_parts = args.cur_part_number;
	for (int i = 1; i <= total_parts; i++) {
		const tchar *part_name;
		int part_fd;
		u8 part_data_buf[4];
		size_t bytes_written;

		if (i == 1) {
			part_name = swm_name;
		} else {
			tsprintf(swm_base_name + swm_base_name_len, T("%d%"TS),
				 i, swm_suffix);
			part_name = swm_base_name;
		}

		part_fd = topen(part_name, O_WRONLY | O_BINARY);
		if (part_fd == -1) {
			ERROR_WITH_ERRNO("Failed to open `%"TS"'", part_name);
			ret = WIMLIB_ERR_OPEN;
			goto out;
		}
		put_u16(&part_data_buf[0], i);
		put_u16(&part_data_buf[2], total_parts);

		bytes_written = full_pwrite(part_fd, part_data_buf,
					    sizeof(part_data_buf), 40);
		ret = close(part_fd);
		if (bytes_written != sizeof(part_data_buf) || ret != 0) {
			ERROR_WITH_ERRNO("Error updating header of `%"TS"'",
					 part_name);
			ret = WIMLIB_ERR_WRITE;
			goto out;
		}
	}
	ret = 0;
out:
	close_wim_writable(w);
	memcpy(&w->hdr, &hdr_save, sizeof(struct wim_header));
	return ret;
}
