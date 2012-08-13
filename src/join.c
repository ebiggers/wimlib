/*
 * join.c
 *
 * Join split WIMs (sometimes named as .swm files) together into one WIM.
 */

/*
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "wimlib_internal.h"
#include "lookup_table.h"
#include "xml.h"

static int join_wims(WIMStruct **swms, uint num_swms, WIMStruct *joined_wim,
		     int write_flags)
{
	uint i;
	int ret;
	FILE *out_fp = joined_wim->out_fp;
	u64 total_bytes = wim_info_get_total_bytes(swms[0]->wim_info);

	swms[0]->write_metadata = false;
	for (i = 0; i < num_swms; i++) {
		if (write_flags & WIMLIB_WRITE_FLAG_SHOW_PROGRESS) {
			off_t cur_offset = ftello(out_fp);
			printf("Writing resources from part %u of %u "
			       "(%"PRIu64" of %"PRIu64" bytes, %.0f%% done)\n",
			       i + 1, num_swms, cur_offset, total_bytes,
			       (double)cur_offset / total_bytes * 100.0);
		}
		swms[i]->fp = fopen(swms[i]->filename, "rb");
		if (!swms[i]->fp) {
			ERROR_WITH_ERRNO("Failed to reopen `%s'",
					 swms[i]->filename);
			return WIMLIB_ERR_OPEN;
		}
		swms[i]->out_fp = out_fp;
		swms[i]->hdr.part_number = 1;
		ret = for_lookup_table_entry(swms[i]->lookup_table, 
					     copy_resource, swms[i]);
		if (ret != 0)
			return ret;
		if (i != 0) {
			fclose(swms[i]->fp);
			swms[i]->fp = NULL;
		}
	}
	swms[0]->write_metadata = true;
	if (write_flags & WIMLIB_WRITE_FLAG_SHOW_PROGRESS)
		printf("Writing %d metadata resources\n", 
			swms[0]->hdr.image_count);

	for (i = 0; i < swms[0]->hdr.image_count; i++) {
		ret = copy_resource(swms[0]->image_metadata[i].metadata_lte, 
				    swms[0]);
		if (ret != 0)
			return ret;
	}

	off_t lookup_table_offset = ftello(out_fp);

	if (write_flags & WIMLIB_WRITE_FLAG_SHOW_PROGRESS)
		printf("Writing lookup tables, XML data, and header\n");
	/* Now write the lookup table for the joined wim.  Since the lookup
	 * table has no header, we can just concatenate the lookup tables of all
	 * the SWM parts. */
	for (i = 0; i < num_swms; i++) {
		ret = write_lookup_table(swms[i]->lookup_table, out_fp);
		if (ret != 0)
			return ret;
	}
	off_t xml_data_offset = ftello(out_fp);

	if (lookup_table_offset == -1 || xml_data_offset == -1) {
		ERROR_WITH_ERRNO("Failed to get file offset");
		return WIMLIB_ERR_WRITE;
	}
	swms[0]->hdr.lookup_table_res_entry.offset = lookup_table_offset;
	swms[0]->hdr.lookup_table_res_entry.size = 
					xml_data_offset - lookup_table_offset;


	/* finish_write is called on the first swm, not the joined_wim, because
	 * the first swm is the one that has the image metadata and XML data
	 * attached to it.  */
	swms[0]->hdr.flags &= ~WIM_HDR_FLAG_SPANNED;
	swms[0]->hdr.total_parts = 1;
	return finish_write(swms[0], WIM_ALL_IMAGES, write_flags, 0);
}


WIMLIBAPI int wimlib_join(const char **swm_names, int num_swms, 
			  const char *output_path, int flags)
{
	int i;
	int ret;
	int part_idx;
	int write_flags = 0;
	WIMStruct *w;
	WIMStruct *joined_wim = NULL;
	WIMStruct *swms[num_swms];

	/* keep track of ctype and guid just to make sure they are the same for
	 * all the WIMs. */
	int ctype;
	u8 *guid;

	ZERO_ARRAY(swms);
	for (i = 0; i < num_swms; i++) {
		ret = wimlib_open_wim(swm_names[i], 
				      flags | WIMLIB_OPEN_FLAG_SPLIT_OK, &w);
		if (ret != 0)
			goto err;

		/* don't open all the parts at the same time, in case there are
		 * a lot af them */
		fclose(w->fp);
		w->fp = NULL;

		if (i == 0) {
			ctype = wimlib_get_compression_type(w);
			guid = w->hdr.guid;
		} else {
			if (wimlib_get_compression_type(w) != ctype) {
				ERROR("The split WIMs do not all have the same "
				      "compression type");
				ret = WIMLIB_ERR_SPLIT_INVALID;
				goto err;
			}
			if (memcmp(guid, w->hdr.guid, WIM_GID_LEN) != 0) {
				ERROR("The split WIMs do not all have the same "
				      "GUID");
				ret = WIMLIB_ERR_SPLIT_INVALID;
				goto err;
			}
		}
		if (w->hdr.total_parts != num_swms) {
			ERROR("`%s' (part %d) says there are %d total parts, "
			      "but %d parts were specified",
			      swm_names[i], w->hdr.part_number,
			      w->hdr.total_parts, num_swms);
			ret = WIMLIB_ERR_SPLIT_INVALID;
			goto err;
		}
		if (w->hdr.part_number == 0 || w->hdr.part_number > num_swms) {
			ERROR("`%s' says it is part %d, but expected a number "
			      "between 1 and %d",
			      swm_names[i], w->hdr.part_number, num_swms);
			ret = WIMLIB_ERR_SPLIT_INVALID;
			goto err;
		}
		part_idx = w->hdr.part_number - 1;
		if (swms[part_idx] != NULL) {
			ERROR("`%s' and `%s' both say they are part %d of %d",
			      swm_names[i], swms[part_idx]->filename,
			      w->hdr.part_number, num_swms);
			ret = WIMLIB_ERR_SPLIT_INVALID;
			goto err;
		}
		swms[part_idx] = w;

	}
	joined_wim = new_wim_struct();
	if (!joined_wim) {
		ret = WIMLIB_ERR_NOMEM;
		goto err;
	}

	if (flags & WIMLIB_OPEN_FLAG_CHECK_INTEGRITY)
		write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
	if (flags & WIMLIB_OPEN_FLAG_SHOW_PROGRESS)
		write_flags |= WIMLIB_WRITE_FLAG_SHOW_PROGRESS;

	ret = begin_write(joined_wim, output_path, write_flags);
	if (ret != 0)
		goto err;
	ret = join_wims(swms, num_swms, joined_wim, write_flags);
err:
	for (i = 0; i < num_swms; i++) {
		/* out_fp is the same in all the swms and joined_wim; only close
		 * it one time, when freeing joined_wim. */
		if (swms[i]) {
			swms[i]->out_fp = NULL;
			wimlib_free(swms[i]);
		}
	}
	wimlib_free(joined_wim);
	return ret;
}
