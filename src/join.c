/*
 * join.c
 *
 * Join split WIMs (sometimes named as .swm files) together into one WIM.
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
#include "wimlib/error.h"
#include "wimlib/types.h"
#include "wimlib/util.h"
#include "wimlib/wim.h"

/*
 * verify_swm_set: - Sanity checks to make sure a set of WIMs correctly
 *		     correspond to a spanned set.
 *
 * @wim:
 *	Part 1 of the set.
 *
 * @additional_swms:
 *	All parts of the set other than part 1.
 *
 * @num_additional_swms:
 *	Number of WIMStructs in @additional_swms.  Or, the total number of parts
 *	in the set minus 1.
 *
 * @return:
 *	0 on success; WIMLIB_ERR_SPLIT_INVALID if the set is not valid.
 */
static int
verify_swm_set(WIMStruct *wim, WIMStruct **additional_swms,
	       unsigned num_additional_swms)
{
	unsigned total_parts = wim->hdr.total_parts;
	int ctype;
	u32 chunk_size;
	const u8 *guid;

	if (total_parts != num_additional_swms + 1) {
		ERROR("`%"TS"' says there are %u parts in the spanned set, "
		      "but %"TS"%u part%"TS" provided",
		      wim->filename, total_parts,
		      (num_additional_swms + 1 < total_parts) ? T("only ") : T(""),
		      num_additional_swms + 1,
		      (num_additional_swms) ? T("s were") : T(" was"));
		return WIMLIB_ERR_SPLIT_INVALID;
	}
	if (wim->hdr.part_number != 1) {
		ERROR("WIM `%"TS"' is not the first part of the split WIM.",
		      wim->filename);
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

	/* Keep track of the compression type, chunk size, and GUID to make sure
	 * they are the same for all the WIMs.  */
	ctype = wim->compression_type;
	chunk_size = wim->chunk_size;
	guid = wim->hdr.guid;

	{
		/* parts_to_swms is not allocated at function scope because it
		 * should only be allocated after num_additional_swms was
		 * checked to be the same as wim->hdr.total_parts.  Otherwise, it
		 * could be unexpectedly high and cause a stack overflow. */
		WIMStruct *parts_to_swms[num_additional_swms];
		memset(parts_to_swms, 0, sizeof(parts_to_swms));
		for (unsigned i = 0; i < num_additional_swms; i++) {

			WIMStruct *swm = additional_swms[i];

			if (swm->compression_type != ctype) {
				ERROR("The split WIMs do not all have the same "
				      "compression type");
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (swm->chunk_size != chunk_size &&
			    ctype != WIMLIB_COMPRESSION_TYPE_NONE) {
				ERROR("The split WIMs do not all have the same "
				      "chunk size");
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (!guids_equal(guid, swm->hdr.guid)) {
				ERROR("The split WIMs do not all have the same "
				      "GUID");
				return WIMLIB_ERR_SPLIT_INVALID;
			}
			if (swm->hdr.part_number == 1) {
				ERROR("WIMs `%"TS"' and `%"TS"' both are marked "
				      "as the first WIM in the spanned set",
				      wim->filename, swm->filename);
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

WIMLIBAPI int
wimlib_join_with_progress(const tchar * const *swm_names,
			  unsigned num_swms,
			  const tchar *output_path,
			  int swm_open_flags,
			  int wim_write_flags,
			  wimlib_progress_func_t progfunc,
			  void *progctx)
{
	int ret;
	unsigned i;
	unsigned j;
	WIMStruct *swm0;
	WIMStruct **additional_swms;
	unsigned num_additional_swms;

	if (num_swms < 1 || num_swms > 0xffff)
		return WIMLIB_ERR_INVALID_PARAM;
	num_additional_swms = num_swms - 1;

	additional_swms = CALLOC((num_additional_swms + 1),
				 sizeof(additional_swms[0]));
	if (!additional_swms)
		return WIMLIB_ERR_NOMEM;

	swm0 = NULL;
	for (i = 0, j = 0; i < num_swms; i++) {
		WIMStruct *swm;

		ret = wimlib_open_wim_with_progress(swm_names[i],
						    swm_open_flags,
						    &swm,
						    progfunc,
						    progctx);
		if (ret)
			goto out_free_swms;
		if (swm->hdr.part_number == 1 && swm0 == NULL)
			swm0 = swm;
		else
			additional_swms[j++] = swm;
	}

	if (!swm0) {
		ERROR("Part 1 of the split WIM was not specified!");
		ret = WIMLIB_ERR_SPLIT_INVALID;
		goto out_free_swms;
	}

	ret = verify_swm_set(swm0, additional_swms, num_additional_swms);
	if (ret)
		goto out_free_swms;

	ret = wimlib_reference_resources(swm0, additional_swms,
					 num_additional_swms, 0);
	if (ret)
		goto out_free_swms;

	/* It is reasonably safe to provide, WIMLIB_WRITE_FLAG_STREAMS_OK, as we
	 * have verified that the specified split WIM parts form a spanned set.
	 */
	ret = wimlib_write(swm0, output_path, WIMLIB_ALL_IMAGES,
			   wim_write_flags |
				WIMLIB_WRITE_FLAG_STREAMS_OK |
				WIMLIB_WRITE_FLAG_RETAIN_GUID,
			   1);
out_free_swms:
	for (i = 0; i < num_additional_swms + 1; i++)
		wimlib_free(additional_swms[i]);
	FREE(additional_swms);
	wimlib_free(swm0);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_join(const tchar * const *swm_names,
	    unsigned num_swms,
	    const tchar *output_path,
	    int swm_open_flags,
	    int wim_write_flags)
{
	return wimlib_join_with_progress(swm_names, num_swms, output_path,
					 swm_open_flags, wim_write_flags,
					 NULL, NULL);
}
