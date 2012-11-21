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

#include "wimlib_internal.h"
#include "lookup_table.h"
#include "xml.h"
#include <stdlib.h>

static int move_lte_to_table(struct lookup_table_entry *lte,
			     void *other_tab)
{
	hlist_del(&lte->hash_list);
	lookup_table_insert((struct lookup_table*)other_tab, lte);
	return 0;
}

static int lookup_table_join(struct lookup_table *table,
			     struct lookup_table *new)
{
	return for_lookup_table_entry(new, move_lte_to_table, table);
}

/*
 * Sanity checks to make sure a set of WIMs correctly correspond to a spanned
 * set.
 *
 * @w:
 * 	Part 1 of the set.
 *
 * @additional_swms:
 * 	All parts of the set other than part 1.
 *
 * @num_additional_swms:
 * 	Number of WIMStructs in @additional_swms.  Or, the total number of parts
 * 	in the set minus 1.
 *
 * @return:
 * 	0 on success; WIMLIB_ERR_SPLIT_INVALID if the set is not valid.
 */
int verify_swm_set(WIMStruct *w, WIMStruct **additional_swms,
		   unsigned num_additional_swms)
{
	unsigned total_parts = w->hdr.total_parts;
	int ctype;
	const u8 *guid;

	if (total_parts != num_additional_swms + 1) {
		ERROR("`%s' says there are %u parts in the spanned set, "
		      "but %s%u part%s provided",
		      w->filename, total_parts,
		      (num_additional_swms + 1 < total_parts) ? "only " : "",
		      num_additional_swms + 1,
		      (num_additional_swms) ? "s were" : " was");
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	if (w->hdr.part_number != 1) {
		ERROR("WIM `%s' is not the first part of the split WIM.",
		      w->filename);
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	for (unsigned i = 0; i < num_additional_swms; i++) {
		if (additional_swms[i]->hdr.total_parts != total_parts) {
			ERROR("WIM `%s' says there are %u parts in the spanned set, "
			      "but %u parts were provided",
			      additional_swms[i]->filename,
			      additional_swms[i]->hdr.total_parts,
			      total_parts);
			return WIMLIB_ERR_SPLIT_INVALID;
		}
	}

	/* keep track of ctype and guid just to make sure they are the same for
	 * all the WIMs. */
	ctype = wimlib_get_compression_type(w);
	guid = w->hdr.guid;

	WIMStruct *parts_to_swms[num_additional_swms];
	ZERO_ARRAY(parts_to_swms);
	for (unsigned i = 0; i < num_additional_swms; i++) {

		WIMStruct *swm = additional_swms[i];

		if (wimlib_get_compression_type(swm) != ctype) {
			ERROR("The split WIMs do not all have the same "
			      "compression type");
			return WIMLIB_ERR_SPLIT_INVALID;
		}
		if (memcmp(guid, swm->hdr.guid, WIM_GID_LEN) != 0) {
			ERROR("The split WIMs do not all have the same "
			      "GUID");
			return WIMLIB_ERR_SPLIT_INVALID;
		}
		if (swm->hdr.part_number == 1) {
			ERROR("WIMs `%s' and `%s' both are marked as the "
			      "first WIM in the spanned set",
			      w->filename, swm->filename);
			return WIMLIB_ERR_SPLIT_INVALID;
		}
		if (swm->hdr.part_number == 0 ||
		    swm->hdr.part_number > total_parts)
		{
			ERROR("WIM `%s' says it is part %u in the spanned set, "
			      "but the part number must be in the range "
			      "[1, %u]",
			      swm->filename, swm->hdr.part_number, total_parts);
			return WIMLIB_ERR_SPLIT_INVALID;
		}
		if (parts_to_swms[swm->hdr.part_number - 2])
		{
			ERROR("`%s' and `%s' are both marked as part %u of %u "
			      "in the spanned set",
			      parts_to_swms[swm->hdr.part_number - 2]->filename,
			      swm->filename,
			      swm->hdr.part_number,
			      total_parts);
			return WIMLIB_ERR_SPLIT_INVALID;
		} else {
			parts_to_swms[swm->hdr.part_number - 2] = swm;
		}
	}
	return 0;
}

/*
 * Joins lookup tables from the parts of a split WIM.
 *
 * @w specifies the first part, while @additional_swms and @num_additional_swms
 * specify an array of pointers to the WIMStruct's for additional split WIM parts.
 *
 * The lookup table entries are *moved* to the new table.
 *
 * On success, 0 is returned on a pointer to the joined lookup table is returned
 * in @table_ret.
 *
 * The reason we join the lookup tables is so:
 * 	- We only have to search one lookup table to find the location of a
 * 	resource in the entire split WIM.
 * 	- Each lookup table entry will have a pointer to its split WIM part (and
 * 	a part number field, although we don't really use it).
 */
int new_joined_lookup_table(WIMStruct *w,
			    WIMStruct **additional_swms,
			    unsigned num_additional_swms,
			    struct lookup_table **table_ret)
{
	struct lookup_table *table;
	int ret;
	unsigned i;

	table = new_lookup_table(9001);
	if (!table)
		return WIMLIB_ERR_NOMEM;

	if (w)
		lookup_table_join(table, w->lookup_table);

	for (i = 0; i < num_additional_swms; i++) {
		ret = lookup_table_join(table, additional_swms[i]->lookup_table);
		if (ret != 0)
			goto out_free_table;
	}
	*table_ret = table;
	return 0;
out_free_table:
	free_lookup_table(table);
	return ret;
}


static int join_wims(WIMStruct **swms, unsigned num_swms,
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
		progress.join.total_bytes        = total_bytes;
		progress.join.total_parts        = swms[0]->hdr.total_parts;
		progress.join.completed_bytes    = 0;
		progress.join.completed_parts    = 0;
		progress_func(WIMLIB_PROGRESS_MSG_JOIN_STREAMS, &progress);
	}

	/* Write the resources (streams and metadata resources) from each SWM
	 * part */
	swms[0]->write_metadata = true;
	for (i = 0; i < num_swms; i++) {
		swms[i]->fp = fopen(swms[i]->filename, "rb");
		if (!swms[i]->fp) {
			ERROR_WITH_ERRNO("Failed to reopen `%s'",
					 swms[i]->filename);
			return WIMLIB_ERR_OPEN;
		}
		swms[i]->out_fp = joined_wim->out_fp;
		swms[i]->hdr.part_number = 1;
		ret = for_lookup_table_entry(swms[i]->lookup_table,
					     copy_resource, swms[i]);
		swms[i]->out_fp = NULL;
		fclose(swms[i]->fp);
		swms[i]->fp = NULL;

		if (ret != 0)
			return ret;

		if (progress_func) {
			progress.join.completed_bytes += swm_part_sizes[i];
			progress.join.completed_parts++;
			progress_func(WIMLIB_PROGRESS_MSG_JOIN_STREAMS, &progress);
		}
	}

	joined_wim->hdr.image_count = swms[0]->hdr.image_count;
	for (i = 0; i < num_swms; i++)
		lookup_table_join(joined_wim->lookup_table, swms[i]->lookup_table);

	free_wim_info(joined_wim->wim_info);
	joined_wim->wim_info = swms[0]->wim_info;
	ret = finish_write(joined_wim, WIMLIB_ALL_IMAGES, write_flags, progress_func);
	joined_wim->wim_info = NULL;
	return ret;
}

static int cmp_swms_by_part_number(const void *swm1, const void *swm2)
{
	u16 partno_1 = (*(const WIMStruct**)swm1)->hdr.part_number;
	u16 partno_2 = (*(const WIMStruct**)swm2)->hdr.part_number;
	return (int)partno_1 - (int)partno_2;
}

/*
 * Join a set of split WIMs into a stand-alone WIM.
 */
WIMLIBAPI int wimlib_join(const char **swm_names, unsigned num_swms,
			  const char *output_path, int swm_open_flags,
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
		if (ret != 0)
			goto out;

		/* Don't open all the parts at the same time, in case there are
		 * a lot of them */
		fclose(swms[i]->fp);
		swms[i]->fp = NULL;
	}

	qsort(swms, num_swms, sizeof(swms[0]), cmp_swms_by_part_number);

	ret = verify_swm_set(swms[0], &swms[1], num_swms - 1);
	if (ret != 0)
		goto out;

	ret = wimlib_create_new_wim(wimlib_get_compression_type(swms[0]),
				    &joined_wim);
	if (ret != 0)
		goto out;

	ret = begin_write(joined_wim, output_path, wim_write_flags);
	if (ret != 0)
		goto out;
	ret = join_wims(swms, num_swms, joined_wim, wim_write_flags,
			progress_func);
out:
	for (i = 0; i < num_swms; i++)
		wimlib_free(swms[i]);
	wimlib_free(joined_wim);
	return ret;
}
