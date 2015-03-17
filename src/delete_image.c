/*
 * delete_image.c
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

#include <string.h>

#include "wimlib.h"
#include "wimlib/metadata.h"
#include "wimlib/wim.h"
#include "wimlib/xml.h"

/* Internal method for single-image deletion.  This doesn't set the
 * image_deletion_occurred' flag on the WIMStruct.  */
int
delete_wim_image(WIMStruct *wim, int image)
{
	int ret;

	/* Load the metadata for the image to be deleted.  This is necessary
	 * because blobs referenced by files in the image need to have their
	 * reference counts decremented.  */
	ret = select_wim_image(wim, image);
	if (ret)
		return ret;

	/* Release the reference to the image metadata and decrement reference
	 * counts on the blobs referenced by files in the image.  */
	put_image_metadata(wim->image_metadata[image - 1], wim->blob_table);

	/* Remove the empty slot from the image metadata array.  */
	memmove(&wim->image_metadata[image - 1], &wim->image_metadata[image],
		(wim->hdr.image_count - image) *
			sizeof(wim->image_metadata[0]));

	/* Decrement the image count. */
	--wim->hdr.image_count;

	/* Remove the image from the XML information. */
	xml_delete_image(&wim->wim_info, image);

	/* Fix the boot index. */
	if (wim->hdr.boot_idx == image)
		wim->hdr.boot_idx = 0;
	else if (wim->hdr.boot_idx > image)
		wim->hdr.boot_idx--;

	/* The image is no longer valid.  */
	wim->current_image = WIMLIB_NO_IMAGE;
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_delete_image(WIMStruct *wim, int image)
{
	int ret;
	int first, last;

	if (image == WIMLIB_ALL_IMAGES) {
		/* Deleting all images  */
		last = wim->hdr.image_count;
		first = 1;
	} else {
		/* Deleting one image  */
		last = image;
		first = image;
	}

	for (image = last; image >= first; image--) {
		ret = delete_wim_image(wim, image);
		if (ret)
			return ret;
		wim->image_deletion_occurred = 1;
	}
	return 0;
}
