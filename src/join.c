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

static int copy_lte_to_table(struct lookup_table_entry *lte, void *table)
{
	struct lookup_table_entry *copy;
	copy = MALLOC(sizeof(struct lookup_table_entry));
	if (!copy)
		return WIMLIB_ERR_NOMEM;
	memcpy(copy, lte, sizeof(struct lookup_table_entry));
	lookup_table_insert(table, copy);
	return 0;
}

static int lookup_table_join(struct lookup_table *table,
			     struct lookup_table *new)
{
	return for_lookup_table_entry(new, copy_lte_to_table, table);
}


static int cmp_swms_by_part_number(const void *swm1, const void *swm2)
{
	u16 partno_1 = (*(WIMStruct**)swm1)->hdr.part_number;
	u16 partno_2 = (*(WIMStruct**)swm2)->hdr.part_number;
	return (int)partno_1 - (int)partno_2;
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
 * specify an array of points to the WIMStruct's for additional split WIM parts.
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
	ret = lookup_table_join(table, w->lookup_table);
	if (ret != 0)
		goto out_free_table;
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
		ret = for_lookup_table_entry(swms[i]->lookup_table,
					     write_lookup_table_entry,
					     out_fp);
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
	swms[0]->hdr.lookup_table_res_entry.original_size =
					xml_data_offset - lookup_table_offset;
	swms[0]->hdr.lookup_table_res_entry.flags =
					WIM_RESHDR_FLAG_METADATA;


	/* finish_write is called on the first swm, not the joined_wim, because
	 * the first swm is the one that has the image metadata and XML data
	 * attached to it.  */
	swms[0]->hdr.flags &= ~WIM_HDR_FLAG_SPANNED;
	swms[0]->hdr.total_parts = 1;
	return finish_write(swms[0], WIM_ALL_IMAGES,
			    write_flags | WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE);
}


WIMLIBAPI int wimlib_join(const char **swm_names, unsigned num_swms,
			  const char *output_path, int flags)
{
	int ret;
	int write_flags = 0;
	WIMStruct *joined_wim = NULL;
	WIMStruct *swms[num_swms];

	if (num_swms < 1)
		return WIMLIB_ERR_INVALID_PARAM;

	ZERO_ARRAY(swms);

	for (unsigned i = 0; i < num_swms; i++) {
		ret = wimlib_open_wim(swm_names[i],
				      flags | WIMLIB_OPEN_FLAG_SPLIT_OK, &swms[i]);
		if (ret != 0)
			goto out;

		/* don't open all the parts at the same time, in case there are
		 * a lot of them */
		fclose(swms[i]->fp);
		swms[i]->fp = NULL;
	}

	qsort(swms, num_swms, sizeof(swms[0]), cmp_swms_by_part_number);

	ret = verify_swm_set(swms[0], &swms[1], num_swms - 1);
	if (ret != 0)
		goto out;

	joined_wim = new_wim_struct();
	if (!joined_wim) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	if (flags & WIMLIB_OPEN_FLAG_CHECK_INTEGRITY)
		write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
	if (flags & WIMLIB_OPEN_FLAG_SHOW_PROGRESS)
		write_flags |= WIMLIB_WRITE_FLAG_SHOW_PROGRESS;

	ret = begin_write(joined_wim, output_path, write_flags);
	if (ret != 0)
		goto out;
	ret = join_wims(swms, num_swms, joined_wim, write_flags);
out:
	/* out_fp is the same in all the swms and joined_wim.  And it was
	 * already closed in the call to finish_write(). */
	for (unsigned i = 0; i < num_swms; i++) {
		swms[i]->out_fp = NULL;
		wimlib_free(swms[i]);
	}
	joined_wim->out_fp = NULL;
	wimlib_free(joined_wim);
	return ret;
}
