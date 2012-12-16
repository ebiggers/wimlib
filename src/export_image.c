/*
 * export_image.c
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
#include "dentry.h"
#include "lookup_table.h"
#include "xml.h"

struct wim_pair {
	WIMStruct *src_wim;
	WIMStruct *dest_wim;
	struct list_head lte_list_head;
};

static int allocate_lte_if_needed(struct dentry *dentry, void *arg)
{
	const WIMStruct *src_wim, *dest_wim;
	struct list_head *lte_list_head;
	struct inode *inode;

	src_wim = ((struct wim_pair*)arg)->src_wim;
	dest_wim = ((struct wim_pair*)arg)->dest_wim;
	lte_list_head = &((struct wim_pair*)arg)->lte_list_head;
	inode = dentry->d_inode;

	wimlib_assert(!inode->resolved);

	for (unsigned i = 0; i <= inode->num_ads; i++) {
		struct lookup_table_entry *src_lte, *dest_lte;
		src_lte = inode_stream_lte_unresolved(inode, i,
						      src_wim->lookup_table);

		if (src_lte && ++src_lte->out_refcnt == 1) {
			dest_lte = inode_stream_lte_unresolved(inode, i,
							       dest_wim->lookup_table);

			if (!dest_lte) {
				dest_lte = clone_lookup_table_entry(src_lte);
				if (!dest_lte)
					return WIMLIB_ERR_NOMEM;
				list_add_tail(&dest_lte->staging_list, lte_list_head);
			}
		}
	}
	return 0;
}

/*
 * This function takes in a dentry that was previously located only in image(s)
 * in @src_wim, but now is being added to @dest_wim.  For each stream associated
 * with the dentry, if there is already a lookup table entry for that stream in
 * the lookup table of the destination WIM file, its reference count is
 * incrementej.  Otherwise, a new lookup table entry is created that points back
 * to the stream in the source WIM file (through the @hash field combined with
 * the @wim field of the lookup table entry.)
 */
static int add_lte_to_dest_wim(struct dentry *dentry, void *arg)
{
	WIMStruct *src_wim, *dest_wim;
	struct inode *inode;

	src_wim = ((struct wim_pair*)arg)->src_wim;
	dest_wim = ((struct wim_pair*)arg)->dest_wim;
	inode = dentry->d_inode;

	wimlib_assert(!inode->resolved);

	for (unsigned i = 0; i <= inode->num_ads; i++) {
		struct lookup_table_entry *src_lte, *dest_lte;
		src_lte = inode_stream_lte_unresolved(inode, i,
						      src_wim->lookup_table);

		if (!src_lte) /* Empty or nonexistent stream. */
			continue;

		dest_lte = inode_stream_lte_unresolved(inode, i,
						       dest_wim->lookup_table);
		if (dest_lte) {
			dest_lte->refcnt++;
		} else {
			struct list_head *lte_list_head;
			struct list_head *next;

			lte_list_head = &((struct wim_pair*)arg)->lte_list_head;
			wimlib_assert(!list_empty(lte_list_head));

			next = lte_list_head->next;
			list_del(next);
			dest_lte = container_of(next, struct lookup_table_entry,
						staging_list);
			dest_lte->part_number = 1;
			dest_lte->refcnt = 1;
			wimlib_assert(hashes_equal(dest_lte->hash, src_lte->hash));

			lookup_table_insert(dest_wim->lookup_table, dest_lte);
		}
	}
	return 0;
}

/*
 * Copies an image, or all the images, from a WIM file, into another WIM file.
 */
WIMLIBAPI int wimlib_export_image(WIMStruct *src_wim,
				  int src_image,
				  WIMStruct *dest_wim,
				  const char *dest_name,
				  const char *dest_description,
				  int export_flags,
				  WIMStruct **additional_swms,
				  unsigned num_additional_swms,
				  wimlib_progress_func_t progress_func)
{
	int i;
	int ret;
	struct dentry *root;
	struct wim_pair wims;
	struct wim_security_data *sd;
	struct lookup_table *joined_tab, *src_wim_tab_save;

	if (dest_wim->hdr.total_parts != 1) {
		ERROR("Exporting an image to a split WIM is "
		      "unsupported");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

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
			for (i = 1; i <= src_wim->hdr.image_count; i++) {
				int new_flags = export_flags;

				if (i != src_wim->hdr.boot_idx)
					new_flags &= ~WIMLIB_EXPORT_FLAG_BOOT;

				ret = wimlib_export_image(src_wim, i, dest_wim,
							  NULL, NULL,
							  new_flags,
							  additional_swms,
							  num_additional_swms,
							  progress_func);
				if (ret != 0)
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
		DEBUG("Using name `%s' for source image %d",
		      dest_name, src_image);
	}

	if (!dest_description) {
		dest_description = wimlib_get_image_description(src_wim,
								src_image);
		DEBUG("Using description `%s' for source image %d",
		      dest_description, src_image);
	}

	DEBUG("Exporting image %d from `%s'", src_image, src_wim->filename);

	if (wimlib_image_name_in_use(dest_wim, dest_name)) {
		ERROR("There is already an image named `%s' in the "
		      "destination WIM", dest_name);
		return WIMLIB_ERR_IMAGE_NAME_COLLISION;
	}

	ret = verify_swm_set(src_wim, additional_swms, num_additional_swms);
	if (ret != 0)
		return ret;

	if (num_additional_swms) {
		ret = new_joined_lookup_table(src_wim, additional_swms,
					      num_additional_swms,
					      &joined_tab);
		if (ret != 0)
			return ret;
		src_wim_tab_save = src_wim->lookup_table;
		src_wim->lookup_table = joined_tab;
	}

	ret = select_wim_image(src_wim, src_image);
	if (ret != 0) {
		ERROR("Could not select image %d from the WIM `%s' "
		      "to export it", src_image, src_wim->filename);
		goto out;
	}

	/* Pre-allocate the new lookup table entries that will be needed.  This
	 * way, it's not possible to run out of memory part-way through
	 * modifying the lookup table of the destination WIM. */
	wims.src_wim = src_wim;
	wims.dest_wim = dest_wim;
	INIT_LIST_HEAD(&wims.lte_list_head);
	for_lookup_table_entry(src_wim->lookup_table, lte_zero_out_refcnt, NULL);
	root = wim_root_dentry(src_wim);
	for_dentry_in_tree(root, dentry_unresolve_ltes, NULL);
	ret = for_dentry_in_tree(root, allocate_lte_if_needed, &wims);
	if (ret != 0)
		goto out_free_ltes;

	ret = xml_export_image(src_wim->wim_info, src_image,
			       &dest_wim->wim_info, dest_name, dest_description);
	if (ret != 0)
		goto out_free_ltes;

	sd = wim_security_data(src_wim);
	ret = add_new_dentry_tree(dest_wim, root, sd);
	if (ret != 0)
		goto out_xml_delete_image;


	/* All memory allocations have been taken care of, so it's no longer
	 * possible for this function to fail.  Go ahead and increment the
	 * reference counts of the dentry tree and security data, then update
	 * the lookup table of the destination WIM and the boot index, if
	 * needed. */
	for_dentry_in_tree(root, increment_dentry_refcnt, NULL);
	sd->refcnt++;
	for_dentry_in_tree(root, add_lte_to_dest_wim, &wims);
	wimlib_assert(list_empty(&wims.lte_list_head));

	if (export_flags & WIMLIB_EXPORT_FLAG_BOOT) {
		DEBUG("Setting boot_idx to %d", dest_wim->hdr.image_count);
		wimlib_set_boot_idx(dest_wim, dest_wim->hdr.image_count);
	}
	ret = 0;
	goto out;

out_xml_delete_image:
	xml_delete_image(&dest_wim->wim_info, dest_wim->hdr.image_count);
out_free_ltes:
	{
		struct lookup_table_entry *lte, *tmp;
		list_for_each_entry_safe(lte, tmp, &wims.lte_list_head, staging_list)
			free_lookup_table_entry(lte);
	}

out:
	if (num_additional_swms) {
		free_lookup_table(src_wim->lookup_table);
		src_wim->lookup_table = src_wim_tab_save;
	}
	return ret;
}
