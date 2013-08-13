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
#include "wimlib/types.h"
#include "wimlib/util.h"
#include "wimlib/wim.h"

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_join(const tchar * const *swm_names,
	    unsigned num_swms,
	    const tchar *output_path,
	    int swm_open_flags,
	    int wim_write_flags,
	    wimlib_progress_func_t progress_func)
{
	int ret;
	unsigned i;
	unsigned j;
	WIMStruct *swm0;
	WIMStruct **swms;
	unsigned num_additional_swms;
	WIMStruct *wim;

	swm_open_flags |= WIMLIB_OPEN_FLAG_SPLIT_OK;

	if (num_swms < 1 || num_swms > 0xffff)
		return WIMLIB_ERR_INVALID_PARAM;
	num_additional_swms = num_swms - 1;

	swms = CALLOC(num_additional_swms, sizeof(swms[0]));
	if (!swms)
		return WIMLIB_ERR_NOMEM;

	swm0 = NULL;
	for (i = 0, j = 0; i < num_swms; i++) {
		WIMStruct *swm;

		ret = wimlib_open_wim(swm_names[i], swm_open_flags, &swm,
				      progress_func);
		if (ret)
			goto out_free_swms;
		if (swm->hdr.part_number == 1 && swm0 == NULL)
			swm0 = swm;
		else
			swms[j++] = swm;
	}

	if (!swm0) {
		ret = WIMLIB_ERR_SPLIT_INVALID;
		goto out_free_swms;
	}

	ret = wimlib_create_new_wim(swm0->compression_type, &wim);
	if (ret)
		goto out_free_swms;

	ret = wimlib_export_image(swm0, WIMLIB_ALL_IMAGES,
				  wim, NULL, NULL, 0,
				  swms, num_additional_swms,
				  progress_func);
	if (ret)
		goto out_free_wim;

	wim->hdr.flags |= swm0->hdr.flags & (WIM_HDR_FLAG_RP_FIX |
					     WIM_HDR_FLAG_READONLY);
	if (!(wim_write_flags & (WIMLIB_WRITE_FLAG_CHECK_INTEGRITY |
				 WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY)))
	{
		if (wim_has_integrity_table(swm0))
			wim_write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
	}
	if (!(wim_write_flags & (WIMLIB_WRITE_FLAG_PIPABLE |
				 WIMLIB_WRITE_FLAG_NOT_PIPABLE)))
	{
		if (wim_is_pipable(swm0))
			wim_write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
	}


	ret = wimlib_write(wim, output_path, WIMLIB_ALL_IMAGES,
			   wim_write_flags, 1, progress_func);
out_free_wim:
	wimlib_free(wim);
out_free_swms:
	for (i = 0; i < num_additional_swms; i++)
		wimlib_free(swms[i]);
	FREE(swms);
	wimlib_free(swm0);
	return ret;
}
