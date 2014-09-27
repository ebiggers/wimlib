/*
 * export_image.c
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
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/inode.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/xml.h"
#include <stdlib.h>

static int
inode_export_streams(struct wim_inode *inode,
		     struct wim_lookup_table *src_lookup_table,
		     struct wim_lookup_table *dest_lookup_table,
		     bool gift)
{
	unsigned i;
	const u8 *hash;
	struct wim_lookup_table_entry *src_lte, *dest_lte;

	inode_unresolve_streams(inode);
	for (i = 0; i <= inode->i_num_ads; i++) {

		/* Retrieve SHA1 message digest of stream to export.  */
		hash = inode_stream_hash(inode, i);
		if (is_zero_hash(hash))  /* Empty stream?  */
			continue;

		/* Search for the stream (via SHA1 message digest) in the
		 * destination WIM.  */
		dest_lte = lookup_stream(dest_lookup_table, hash);
		if (!dest_lte) {
			/* Stream not yet present in destination WIM.  Search
			 * for it in the source WIM, then export it into the
			 * destination WIM.  */
			src_lte = lookup_stream(src_lookup_table, hash);
			if (!src_lte)
				return stream_not_found_error(inode, hash);

			if (gift) {
				dest_lte = src_lte;
				lookup_table_unlink(src_lookup_table, src_lte);
			} else {
				dest_lte = clone_lookup_table_entry(src_lte);
				if (!dest_lte)
					return WIMLIB_ERR_NOMEM;
			}
			dest_lte->refcnt = 0;
			dest_lte->out_refcnt = 0;
			lookup_table_insert(dest_lookup_table, dest_lte);
		}

		/* Stream is present in destination WIM (either pre-existing,
		 * already exported, or just exported above).  Increment its
		 * reference count appropriately.   Note: we use 'refcnt' for
		 * the raw reference count, but 'out_refcnt' for references
		 * arising just from the export operation; this is used to roll
		 * back a failed export if needed.  */
		dest_lte->refcnt += inode->i_nlink;
		dest_lte->out_refcnt += inode->i_nlink;
	}
	return 0;
}

static int
lte_unexport(struct wim_lookup_table_entry *lte, void *_lookup_table)
{
	struct wim_lookup_table *lookup_table = _lookup_table;

	if (lte->out_refcnt) {
		lte->refcnt -= lte->out_refcnt;
		if (lte->refcnt == 0) {
			lookup_table_unlink(lookup_table, lte);
			free_lookup_table_entry(lte);
		}
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_export_image(WIMStruct *src_wim,
		    int src_image,
		    WIMStruct *dest_wim,
		    const tchar *dest_name,
		    const tchar *dest_description,
		    int export_flags)
{
	int ret;
	int start_image;
	int end_image;
	int image;
	u32 orig_dest_boot_idx;
	u32 orig_dest_image_count;

	/* Check for sane parameters.  */
	if (export_flags & ~(WIMLIB_EXPORT_FLAG_BOOT |
			     WIMLIB_EXPORT_FLAG_NO_NAMES |
			     WIMLIB_EXPORT_FLAG_NO_DESCRIPTIONS |
			     WIMLIB_EXPORT_FLAG_GIFT |
			     WIMLIB_EXPORT_FLAG_WIMBOOT))
		return WIMLIB_ERR_INVALID_PARAM;

	if (src_wim == NULL || dest_wim == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	if (!wim_has_metadata(dest_wim))
		return WIMLIB_ERR_METADATA_NOT_FOUND;

	/* Destination WIM must be writable.  */
	ret = can_modify_wim(dest_wim);
	if (ret)
		return ret;

	if (src_image == WIMLIB_ALL_IMAGES) {
		/* Multi-image export.  */
		if ((!(export_flags & WIMLIB_EXPORT_FLAG_NO_NAMES) &&
			dest_name) ||
		    (!(export_flags & WIMLIB_EXPORT_FLAG_NO_DESCRIPTIONS) &&
			dest_description))
		{
			ERROR("Image name or image description was "
			      "specified, but we are exporting "
			      "multiple images");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		start_image = 1;
		end_image = src_wim->hdr.image_count;
	} else {
		start_image = src_image;
		end_image = src_image;
	}

	/* Stream checksums must be known before proceeding.  */
	ret = wim_checksum_unhashed_streams(src_wim);
	if (ret)
		return ret;
	ret = wim_checksum_unhashed_streams(dest_wim);
	if (ret)
		return ret;

	/* Zero 'out_refcnt' in all lookup table entries in the destination WIM;
	 * this tracks the number of references found from the source WIM
	 * image(s).  */
	for_lookup_table_entry(dest_wim->lookup_table, lte_zero_out_refcnt,
			       NULL);

	/* Save the original count of images in the destination WIM and the boot
	 * index (used if rollback necessary).  */
	orig_dest_image_count = dest_wim->hdr.image_count;
	orig_dest_boot_idx = dest_wim->hdr.boot_idx;

	/* Export each requested image.  */
	for (image = start_image; image <= end_image; image++) {
		const tchar *next_dest_name, *next_dest_description;
		struct wim_image_metadata *src_imd;
		struct wim_inode *inode;

		DEBUG("Exporting image %d from \"%"TS"\"",
		      image, src_wim->filename);

		/* Determine destination image name and description.  */

		if (export_flags & WIMLIB_EXPORT_FLAG_NO_NAMES) {
			next_dest_name = T("");
		} else if (dest_name) {
			next_dest_name = dest_name;
		} else {
			next_dest_name = wimlib_get_image_name(src_wim,
							       image);
		}

		DEBUG("Using name \"%"TS"\"", next_dest_name);

		if (export_flags & WIMLIB_EXPORT_FLAG_NO_DESCRIPTIONS) {
			next_dest_description = T("");
		} else if (dest_description) {
			next_dest_description = dest_description;
		} else {
			next_dest_description = wimlib_get_image_description(
							src_wim, image);
		}

		DEBUG("Using description \"%"TS"\"", next_dest_description);

		/* Check for name conflict.  */
		if (wimlib_image_name_in_use(dest_wim, next_dest_name)) {
			ERROR("There is already an image named \"%"TS"\" "
			      "in the destination WIM", next_dest_name);
			ret = WIMLIB_ERR_IMAGE_NAME_COLLISION;
			goto out_rollback;
		}

		/* Load metadata for source image into memory.  */
		ret = select_wim_image(src_wim, image);
		if (ret)
			goto out_rollback;

		src_imd = wim_get_current_image_metadata(src_wim);

		/* Iterate through inodes in the source image and export their
		 * streams into the destination WIM.  */
		image_for_each_inode(inode, src_imd) {
			ret = inode_export_streams(inode,
						   src_wim->lookup_table,
						   dest_wim->lookup_table,
						   export_flags & WIMLIB_EXPORT_FLAG_GIFT);
			if (ret)
				goto out_rollback;
		}

		/* Export XML information into the destination WIM.  */
		ret = xml_export_image(src_wim->wim_info, image,
				       &dest_wim->wim_info, next_dest_name,
				       next_dest_description);
		if (ret)
			goto out_rollback;

		/* Reference the source image metadata from the destination WIM.
		 */
		ret = append_image_metadata(dest_wim, src_imd);
		if (ret)
			goto out_rollback;
		src_imd->refcnt++;

		/* Lock the metadata into memory.  XXX: need better solution for
		 * this.  */
		src_imd->modified = 1;

		/* Set boot index in destination WIM.  */
		if ((export_flags & WIMLIB_EXPORT_FLAG_BOOT) &&
		    (src_image != WIMLIB_ALL_IMAGES ||
		     image == src_wim->hdr.boot_idx))
		{
			DEBUG("Marking destination image %u as bootable.",
			      dest_wim->hdr.image_count);
			dest_wim->hdr.boot_idx = dest_wim->hdr.image_count;
		}

		/* Possibly set WIMBoot flag  */
		if (export_flags & WIMLIB_EXPORT_FLAG_WIMBOOT) {
			wim_info_set_wimboot(dest_wim->wim_info,
					     dest_wim->hdr.image_count,
					     true);
		}

	}
	/* Set the reparse point fixup flag on the destination WIM if the flag
	 * is set on the source WIM. */
	if (src_wim->hdr.flags & WIM_HDR_FLAG_RP_FIX)
		dest_wim->hdr.flags |= WIM_HDR_FLAG_RP_FIX;

	if (export_flags & WIMLIB_EXPORT_FLAG_GIFT) {
		free_lookup_table(src_wim->lookup_table);
		src_wim->lookup_table = NULL;
	}
	DEBUG("Export operation successful.");
	return 0;

out_rollback:
	while ((image = wim_info_get_num_images(dest_wim->wim_info))
	       > orig_dest_image_count)
	{
		xml_delete_image(&dest_wim->wim_info, image);
	}
	while (dest_wim->hdr.image_count > orig_dest_image_count)
	{
		put_image_metadata(dest_wim->image_metadata[
					--dest_wim->hdr.image_count], NULL);
	}
	for_lookup_table_entry(dest_wim->lookup_table, lte_unexport,
			       dest_wim->lookup_table);
	dest_wim->hdr.boot_idx = orig_dest_boot_idx;
	return ret;
}
