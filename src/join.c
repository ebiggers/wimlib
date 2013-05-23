/*
 * join.c
 *
 * Join split WIMs (sometimes named as .swm files) together into one WIM.
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
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/swm.h"
#include "wimlib/write.h"
#include "wimlib/xml.h"

#include <stdlib.h> /* for qsort() */

static int
join_wims(WIMStruct **swms, unsigned num_swms,
	  WIMStruct *joined_wim, int write_flags,
	  wimlib_progress_func_t progress_func)
{
	int ret;
	unsigned i;
	union wimlib_progress_info progress;
	u64 total_bytes = 0;
	u64 part_bytes;
	u64 swm_part_sizes[num_swms];

	/* Calculate total size of the streams in the split WIM parts. */
	for (i = 0; i < num_swms; i++) {
		part_bytes = lookup_table_total_stream_size(swms[i]->lookup_table);
		swm_part_sizes[i] = part_bytes;
		total_bytes += part_bytes;
	}

	if (progress_func) {
		progress.join.total_bytes     = total_bytes;
		progress.join.total_parts     = swms[0]->hdr.total_parts;
		progress.join.completed_bytes = 0;
		progress.join.completed_parts = 0;
		progress_func(WIMLIB_PROGRESS_MSG_JOIN_STREAMS, &progress);
	}

	/* Write the non-metadata resources from each SWM part */
	for (i = 0; i < num_swms; i++) {
		ret = reopen_wim(swms[i]);
		if (ret)
			return ret;
		swms[i]->out_fd = joined_wim->out_fd;
		swms[i]->hdr.part_number = 1;

		ret = for_lookup_table_entry_pos_sorted(swms[i]->lookup_table,
							copy_resource,
							swms[i]);
		swms[i]->out_fd = -1;
		if (i != 0)
			close_wim(swms[i]);

		if (ret)
			return ret;

		if (progress_func) {
			progress.join.completed_bytes += swm_part_sizes[i];
			progress.join.completed_parts++;
			progress_func(WIMLIB_PROGRESS_MSG_JOIN_STREAMS, &progress);
		}
	}

	/* Copy the metadata resources from the first SWM part */
	joined_wim->hdr.image_count = swms[0]->hdr.image_count;
	for (i = 0; i < joined_wim->hdr.image_count; i++) {
		ret = copy_resource(swms[0]->image_metadata[i]->metadata_lte,
				    joined_wim);
		if (ret)
			return ret;
	}

	/* Write lookup table, XML data, and optional integrity table */
	merge_lookup_tables(joined_wim, swms, num_swms);
	free_wim_info(joined_wim->wim_info);
	joined_wim->wim_info = swms[0]->wim_info;
	joined_wim->image_metadata = swms[0]->image_metadata;
	ret = finish_write(joined_wim, WIMLIB_ALL_IMAGES, write_flags, progress_func);
	joined_wim->wim_info = NULL;
	joined_wim->image_metadata = NULL;
	return ret;
}

static int
cmp_swms_by_part_number(const void *swm1, const void *swm2)
{
	u16 partno_1 = (*(const WIMStruct**)swm1)->hdr.part_number;
	u16 partno_2 = (*(const WIMStruct**)swm2)->hdr.part_number;
	return (int)partno_1 - (int)partno_2;
}

/*
 * Join a set of split WIMs into a stand-alone WIM.
 */
WIMLIBAPI int
wimlib_join(const tchar * const *swm_names,
	    unsigned num_swms,
	    const tchar *output_path,
	    int swm_open_flags,
	    int wim_write_flags,
	    wimlib_progress_func_t progress_func)
{
	int ret;
	WIMStruct *joined_wim = NULL;
	unsigned i;

	swm_open_flags |= WIMLIB_OPEN_FLAG_SPLIT_OK;
	wim_write_flags &= WIMLIB_WRITE_MASK_PUBLIC;

	if (num_swms < 1 || num_swms > 0xffff)
		return WIMLIB_ERR_INVALID_PARAM;

	WIMStruct *swms[num_swms];
	ZERO_ARRAY(swms);

	for (i = 0; i < num_swms; i++) {
		ret = wimlib_open_wim(swm_names[i], swm_open_flags, &swms[i],
				      progress_func);
		if (ret)
			goto out_free_wims;

		/* Don't open all the parts at the same time, in case there are
		 * a lot of them */
		close_wim(swms[i]);
	}

	qsort(swms, num_swms, sizeof(swms[0]), cmp_swms_by_part_number);

	ret = verify_swm_set(swms[0], &swms[1], num_swms - 1);
	if (ret)
		goto out_free_wims;

	ret = wimlib_create_new_wim(swms[0]->compression_type, &joined_wim);
	if (ret)
		goto out_free_wims;

	ret = begin_write(joined_wim, output_path, wim_write_flags);
	if (ret)
		goto out_free_wims;
	ret = join_wims(swms, num_swms, joined_wim, wim_write_flags,
			progress_func);
out_free_wims:
	for (i = 0; i < num_swms; i++)
		wimlib_free(swms[i]);
	wimlib_free(joined_wim);
	return ret;
}
