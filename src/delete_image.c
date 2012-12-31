/*
 * delete_image.c
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
#include "xml.h"
#include <string.h>

/*
 * Deletes an image from the WIM.
 */
WIMLIBAPI int wimlib_delete_image(WIMStruct *w, int image)
{
	int i;
	int ret;

	if (w->hdr.total_parts != 1) {
		ERROR("Deleting an image from a split WIM is not supported.");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	if (image == WIMLIB_ALL_IMAGES) {
		for (i = w->hdr.image_count; i >= 1; i--) {
			ret = wimlib_delete_image(w, i);
			if (ret != 0)
				return ret;
		}
		return 0;
	}

	if (!w->all_images_verified) {
		ret = wim_run_full_verifications(w);
		if (ret != 0)
			return ret;
	}

	DEBUG("Deleting image %d", image);

	/* Even if the dentry tree is not allocated, we must select it (and
	 * therefore allocate it) so that we can decrement the reference counts
	 * in the lookup table.  */
	ret = select_wim_image(w, image);
	if (ret != 0)
		return ret;

	/* Free the dentry tree, any lookup table entries that have their refcnt
	 * decremented to 0, and the security data. */
	destroy_image_metadata(&w->image_metadata[image - 1], w->lookup_table);

	/* Get rid of the empty slot in the image metadata array. */
	memmove(&w->image_metadata[image - 1], &w->image_metadata[image],
		(w->hdr.image_count - image) * sizeof(struct wim_image_metadata));

	/* Decrement the image count. */
	if (--w->hdr.image_count == 0) {
		FREE(w->image_metadata);
		w->image_metadata = NULL;
	}

	/* Fix the boot index. */
	if (w->hdr.boot_idx == image)
		w->hdr.boot_idx = 0;
	else if (w->hdr.boot_idx > image)
		w->hdr.boot_idx--;

	w->current_image = WIMLIB_NO_IMAGE;

	/* Remove the image from the XML information. */
	xml_delete_image(&w->wim_info, image);

	w->deletion_occurred = 1;
	return 0;
}
