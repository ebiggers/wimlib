/*
 * swm.c
 *
 * Functions to help handle split WIMs.
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

#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/swm.h"
#include "wimlib/wim.h"

static int
move_lte_to_table(struct wim_lookup_table_entry *lte, void *combined_table)
{
	hlist_del(&lte->hash_list);
	lookup_table_insert((struct wim_lookup_table*)combined_table, lte);
	return 0;
}

static void
lookup_table_join(struct wim_lookup_table *combined_table,
		  struct wim_lookup_table *part_table)
{
	for_lookup_table_entry(part_table, move_lte_to_table, combined_table);
	part_table->num_entries = 0;
}

/*
 * merge_lookup_tables() - Merge lookup tables from the parts of a split WIM.
 *
 * @w specifies the first part, while @additional_swms and @num_additional_swms
 * specify an array of pointers to the WIMStruct's for additional split WIM parts.
 *
 * The reason we join the lookup tables is so we only have to search one lookup
 * table to find the location of a resource in the entire WIM.
 */
void
merge_lookup_tables(WIMStruct *w,
		    WIMStruct **additional_swms,
		    unsigned num_additional_swms)
{
	for (unsigned i = 0; i < num_additional_swms; i++)
		lookup_table_join(w->lookup_table, additional_swms[i]->lookup_table);
}

static int
move_lte_to_orig_table(struct wim_lookup_table_entry *lte, void *_wim)
{
	WIMStruct *wim = _wim;
	if (lte->wim != wim) {
		move_lte_to_table(lte, lte->wim->lookup_table);
		wim->lookup_table->num_entries--;
	}
	return 0;
}

/* Undo merge_lookup_tables(), given the first WIM part that contains the merged
 * lookup table. */
void
unmerge_lookup_table(WIMStruct *wim)
{
	for_lookup_table_entry(wim->lookup_table, move_lte_to_orig_table, wim);
}

/*
 * verify_swm_set: - Sanity checks to make sure a set of WIMs correctly
 *		     correspond to a spanned set.
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
int
verify_swm_set(WIMStruct *w, WIMStruct **additional_swms,
	       unsigned num_additional_swms)
{
	unsigned total_parts = w->hdr.total_parts;
	int ctype;
	const u8 *guid;

	if (total_parts != num_additional_swms + 1) {
		ERROR("`%"TS"' says there are %u parts in the spanned set, "
		      "but %"TS"%u part%"TS" provided",
		      w->filename, total_parts,
		      (num_additional_swms + 1 < total_parts) ? T("only ") : T(""),
		      num_additional_swms + 1,
		      (num_additional_swms) ? T("s were") : T(" was"));
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	if (w->hdr.part_number != 1) {
		ERROR("WIM `%"TS"' is not the first part of the split WIM.",
		      w->filename);
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	for (unsigned i = 0; i < num_additional_swms; i++) {
		if (additional_swms[i]->hdr.total_parts != total_parts) {
			ERROR("WIM `%"TS"' says there are %u parts in the "
			      "spanned set, but %u parts were provided",
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

	{
		/* parts_to_swms is not allocated at function scope because it
		 * should only be allocated after num_additional_swms was
		 * checked to be the same as w->hdr.total_parts.  Otherwise, it
		 * could be unexpectedly high and cause a stack overflow. */
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
				ERROR("WIMs `%"TS"' and `%"TS"' both are marked "
				      "as the first WIM in the spanned set",
				      w->filename, swm->filename);
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (swm->hdr.part_number == 0 ||
			    swm->hdr.part_number > total_parts)
			{
				ERROR("WIM `%"TS"' says it is part %u in the "
				      "spanned set, but the part number must "
				      "be in the range [1, %u]",
				      swm->filename, swm->hdr.part_number, total_parts);
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (parts_to_swms[swm->hdr.part_number - 2])
			{
				ERROR("`%"TS"' and `%"TS"' are both marked as "
				      "part %u of %u in the spanned set",
				      parts_to_swms[swm->hdr.part_number - 2]->filename,
				      swm->filename,
				      swm->hdr.part_number,
				      total_parts);
				return WIMLIB_ERR_SPLIT_INVALID;
			} else {
				parts_to_swms[swm->hdr.part_number - 2] = swm;
			}
		}
	}
	return 0;
}
