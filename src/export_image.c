/*
 * export_image.c
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
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/swm.h"
#include "wimlib/xml.h"

static int
inode_allocate_needed_ltes(struct wim_inode *inode,
			   struct wim_lookup_table *src_lookup_table,
			   struct wim_lookup_table *dest_lookup_table,
			   struct list_head *lte_list_head)
{
	struct wim_lookup_table_entry *src_lte, *dest_lte;
	unsigned i;

	inode_unresolve_ltes(inode);
	for (i = 0; i <= inode->i_num_ads; i++) {
		src_lte = inode_stream_lte_unresolved(inode, i,
						      src_lookup_table);
		if (src_lte && src_lte->out_refcnt == 0) {
			src_lte->out_refcnt = 1;
			dest_lte = inode_stream_lte_unresolved(inode, i,
							       dest_lookup_table);
			if (!dest_lte) {
				dest_lte = clone_lookup_table_entry(src_lte);
				if (!dest_lte)
					return WIMLIB_ERR_NOMEM;
				list_add_tail(&dest_lte->export_stream_list,
					      lte_list_head);
			}
		}
	}
	return 0;
}

static void
inode_move_ltes_to_table(struct wim_inode *inode,
			 struct wim_lookup_table *src_lookup_table,
			 struct wim_lookup_table *dest_lookup_table,
			 struct list_head *lte_list_head)
{
	struct wim_lookup_table_entry *src_lte, *dest_lte;
	unsigned i;

	for (i = 0; i <= inode->i_num_ads; i++) {
		src_lte = inode_stream_lte_unresolved(inode, i, src_lookup_table);
		if (src_lte) {
			dest_lte = inode_stream_lte_unresolved(inode, i,
							       dest_lookup_table);
			if (!dest_lte) {
				struct list_head *next;

				wimlib_assert(!list_empty(lte_list_head));
				next = lte_list_head->next;
				list_del(next);
				dest_lte = container_of(next,
							struct wim_lookup_table_entry,
							export_stream_list);
				dest_lte->part_number = 1;
				dest_lte->refcnt = 0;
				wimlib_assert(hashes_equal(dest_lte->hash, src_lte->hash));
				lookup_table_insert(dest_lookup_table, dest_lte);
			}
			dest_lte->refcnt += inode->i_nlink;
		}
	}
}

/*
 * Exports an image, or all the images, from a WIM file, into another WIM file.
 */
WIMLIBAPI int
wimlib_export_image(WIMStruct *src_wim,
		    int src_image,
		    WIMStruct *dest_wim,
		    const tchar *dest_name,
		    const tchar *dest_description,
		    int export_flags,
		    WIMStruct **additional_swms,
		    unsigned num_additional_swms,
		    wimlib_progress_func_t progress_func)
{
	int ret;
	struct wim_image_metadata *src_imd;
	struct list_head lte_list_head;
	struct wim_inode *inode;

	ret = can_modify_wim(dest_wim);
	if (ret)
		return ret;

	if (src_image == WIMLIB_ALL_IMAGES) {
		if (src_wim->hdr.image_count > 1) {

			/* multi-image export. */

			if ((export_flags & WIMLIB_EXPORT_FLAG_BOOT) &&
			      (src_wim->hdr.boot_idx == 0))
			{
				/* Specifying the boot flag on a multi-image
				 * source WIM makes the boot index default to
				 * the bootable image in the source WIM.  It is
				 * an error if there is no such bootable image.
				 * */
				ERROR("Cannot specify `boot' flag when "
				      "exporting multiple images from a WIM "
				      "with no bootable images");
				return WIMLIB_ERR_INVALID_PARAM;
			}
			if (dest_name || dest_description) {
				ERROR("Image name or image description was "
				      "specified, but we are exporting "
				      "multiple images");
				return WIMLIB_ERR_INVALID_PARAM;
			}
			for (int i = 1; i <= src_wim->hdr.image_count; i++) {
				int new_flags = export_flags;

				if (i != src_wim->hdr.boot_idx)
					new_flags &= ~WIMLIB_EXPORT_FLAG_BOOT;

				ret = wimlib_export_image(src_wim, i, dest_wim,
							  NULL, NULL,
							  new_flags,
							  additional_swms,
							  num_additional_swms,
							  progress_func);
				if (ret)
					return ret;
			}
			return 0;
		} else if (src_wim->hdr.image_count == 1) {
			src_image = 1;
		} else {
			return 0;
		}
	}

	if (!dest_name) {
		dest_name = wimlib_get_image_name(src_wim, src_image);
		DEBUG("Using name `%"TS"' for source image %d",
		      dest_name, src_image);
	}

	if (!dest_description) {
		dest_description = wimlib_get_image_description(src_wim,
								src_image);
		DEBUG("Using description `%"TS"' for source image %d",
		      dest_description, src_image);
	}

	DEBUG("Exporting image %d from `%"TS"'", src_image, src_wim->filename);

	if (wimlib_image_name_in_use(dest_wim, dest_name)) {
		ERROR("There is already an image named `%"TS"' in the "
		      "destination WIM", dest_name);
		return WIMLIB_ERR_IMAGE_NAME_COLLISION;
	}

	ret = verify_swm_set(src_wim, additional_swms, num_additional_swms);
	if (ret)
		return ret;

	ret = wim_checksum_unhashed_streams(src_wim);
	if (ret)
		return ret;
	ret = wim_checksum_unhashed_streams(dest_wim);
	if (ret)
		return ret;

	if (num_additional_swms)
		merge_lookup_tables(src_wim, additional_swms, num_additional_swms);

	ret = select_wim_image(src_wim, src_image);
	if (ret) {
		ERROR("Could not select image %d from the WIM `%"TS"' "
		      "to export it", src_image, src_wim->filename);
		goto out;
	}

	/* Pre-allocate the new lookup table entries that will be needed.  This
	 * way, it's not possible to run out of memory part-way through
	 * modifying the lookup table of the destination WIM. */
	for_lookup_table_entry(src_wim->lookup_table, lte_zero_out_refcnt, NULL);
	src_imd = wim_get_current_image_metadata(src_wim);
	INIT_LIST_HEAD(&lte_list_head);
	image_for_each_inode(inode, src_imd) {
		ret = inode_allocate_needed_ltes(inode,
						 src_wim->lookup_table,
						 dest_wim->lookup_table,
						 &lte_list_head);
		if (ret)
			goto out_free_ltes;
	}

	ret = xml_export_image(src_wim->wim_info, src_image,
			       &dest_wim->wim_info, dest_name,
			       dest_description);
	if (ret)
		goto out_free_ltes;

	ret = append_image_metadata(dest_wim, src_imd);
	if (ret)
		goto out_xml_delete_image;

	/* The `struct image_metadata' is now referenced by both the @src_wim
	 * and the @dest_wim. */
	src_imd->refcnt++;
	src_imd->modified = 1;

	/* All memory allocations have been taken care of, so it's no longer
	 * possible for this function to fail.  Go ahead and update the lookup
	 * table of the destination WIM and the boot index, if needed. */
	image_for_each_inode(inode, src_imd) {
		inode_move_ltes_to_table(inode,
					 src_wim->lookup_table,
					 dest_wim->lookup_table,
					 &lte_list_head);
	}

	if (export_flags & WIMLIB_EXPORT_FLAG_BOOT)
		dest_wim->hdr.boot_idx = dest_wim->hdr.image_count;
	if (src_wim->hdr.flags & WIM_HDR_FLAG_RP_FIX)
	{
		/* Set the reparse point fixup flag on the destination WIM if
		 * the flag is set on the source WIM. */
		dest_wim->hdr.flags |= WIM_HDR_FLAG_RP_FIX;
	}
	ret = 0;
	goto out;
out_xml_delete_image:
	xml_delete_image(&dest_wim->wim_info, dest_wim->hdr.image_count + 1);
out_free_ltes:
	{
		struct wim_lookup_table_entry *lte, *tmp;
		list_for_each_entry_safe(lte, tmp, &lte_list_head, export_stream_list)
			free_lookup_table_entry(lte);
	}
out:
	if (num_additional_swms)
		unmerge_lookup_table(src_wim);
	return ret;
}
