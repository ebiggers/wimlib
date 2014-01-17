/*
 * template.c
 *
 * API to reference a template image to optimize later writing of a WIM file.
 */

/*
 * Copyright (C) 2013 Eric Biggers
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
#include "wimlib/util.h"

/* Returns %true iff the metadata of @inode and @template_inode are reasonably
 * consistent with them being the same, unmodified file.  */
static bool
inode_metadata_consistent(const struct wim_inode *inode,
			  const struct wim_inode *template_inode,
			  const struct wim_lookup_table *template_lookup_table)
{
	/* Must have exact same creation time and last write time.  */
	if (inode->i_creation_time != template_inode->i_creation_time ||
	    inode->i_last_write_time != template_inode->i_last_write_time)
		return false;

	/* Last access time may have stayed the same or increased, but certainly
	 * shouldn't have decreased.  */
	if (inode->i_last_access_time < template_inode->i_last_access_time)
		return false;

	/* Must have same number of alternate data stream entries.  */
	if (inode->i_num_ads != template_inode->i_num_ads)
		return false;

	/* If the stream entries for the inode are for some reason not resolved,
	 * then the hashes are already available and the point of this function
	 * is defeated.  */
	if (!inode->i_resolved)
		return false;

	/* Iterate through each stream and do some more checks.  */
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		const struct wim_lookup_table_entry *lte, *template_lte;

		lte = inode_stream_lte_resolved(inode, i);
		template_lte = inode_stream_lte(template_inode, i,
						template_lookup_table);

		/* Compare stream sizes.  */
		if (lte && template_lte) {
			if (lte->size != template_lte->size)
				return false;

			/* If hash happens to be available, compare with template.  */
			if (!lte->unhashed && !template_lte->unhashed &&
			    !hashes_equal(lte->hash, template_lte->hash))
				return false;

		} else if (lte && lte->size) {
			return false;
		} else if (template_lte && template_lte->size) {
			return false;
		}
	}

	/* All right, barring a full checksum and given that the inodes share a
	 * path and the user isn't trying to trick us, these inodes most likely
	 * refer to the same file.  */
	return true;
}

/**
 * Given an inode @inode that has been determined to be "the same" as another
 * inode @template_inode in either the same WIM or another WIM, retrieve some
 * useful stream information (e.g. checksums) from @template_inode.
 *
 * This assumes that the streams for @inode have been resolved (to point
 * directly to the appropriate `struct wim_lookup_table_entry's)  but do not
 * necessarily have checksum information filled in.
 */
static int
inode_copy_checksums(struct wim_inode *inode,
		     struct wim_inode *template_inode,
		     WIMStruct *wim,
		     WIMStruct *template_wim)
{
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		struct wim_lookup_table_entry *lte, *template_lte;
		struct wim_lookup_table_entry *replace_lte;

		lte = inode_stream_lte_resolved(inode, i);
		template_lte = inode_stream_lte(template_inode, i,
						template_wim->lookup_table);

		/* Only take action if both entries exist, the entry for @inode
		 * has no checksum calculated, but the entry for @template_inode
		 * does.  */
		if (lte == NULL || template_lte == NULL ||
		    !lte->unhashed || template_lte->unhashed)
			continue;

		wimlib_assert(lte->refcnt == inode->i_nlink);

		/* If the WIM of the template image is the same as the WIM of
		 * the new image, then @template_lte can be used directly.
		 *
		 * Otherwise, look for a stream with the same hash in the WIM of
		 * the new image.  If found, use it; otherwise re-use the entry
		 * being discarded, filling in the hash.  */

		if (wim == template_wim)
			replace_lte = template_lte;
		else
			replace_lte = lookup_stream(wim->lookup_table,
						    template_lte->hash);

		list_del(&lte->unhashed_list);
		if (replace_lte) {
			free_lookup_table_entry(lte);
		} else {
			copy_hash(lte->hash, template_lte->hash);
			lte->unhashed = 0;
			lookup_table_insert(wim->lookup_table, lte);
			lte->refcnt = 0;
			replace_lte = lte;
		}

		if (i == 0)
			inode->i_lte = replace_lte;
		else
			inode->i_ads_entries[i - 1].lte = replace_lte;

		replace_lte->refcnt += inode->i_nlink;
	}
	return 0;
}

struct reference_template_args {
	WIMStruct *wim;
	WIMStruct *template_wim;
};

static int
dentry_reference_template(struct wim_dentry *dentry, void *_args)
{
	int ret;
	struct wim_dentry *template_dentry;
	struct wim_inode *inode, *template_inode;
	struct reference_template_args *args = _args;
	WIMStruct *wim = args->wim;
	WIMStruct *template_wim = args->template_wim;

	if (dentry->d_inode->i_visited)
		return 0;

	ret = calculate_dentry_full_path(dentry);
	if (ret)
		return ret;

	template_dentry = get_dentry(template_wim, dentry->_full_path,
				     WIMLIB_CASE_SENSITIVE);
	if (template_dentry == NULL) {
		DEBUG("\"%"TS"\": newly added file", dentry->_full_path);
		return 0;
	}

	inode = dentry->d_inode;
	template_inode = template_dentry->d_inode;

	if (inode_metadata_consistent(inode, template_inode,
				      template_wim->lookup_table)) {
		/*DEBUG("\"%"TS"\": No change detected", dentry->_full_path);*/
		ret = inode_copy_checksums(inode, template_inode,
					   wim, template_wim);
		inode->i_visited = 1;
	} else {
		DEBUG("\"%"TS"\": change detected!", dentry->_full_path);
		ret = 0;
	}
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_reference_template_image(WIMStruct *wim, int new_image,
				WIMStruct *template_wim, int template_image,
				int flags, wimlib_progress_func_t progress_func)
{
	int ret;
	struct wim_image_metadata *new_imd;

	if (flags != 0)
		return WIMLIB_ERR_INVALID_PARAM;

	if (wim == NULL || template_wim == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	if (wim == template_wim && new_image == template_image)
		return WIMLIB_ERR_INVALID_PARAM;

	if (new_image < 1 || new_image > wim->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;

	if (!wim_has_metadata(wim))
		return WIMLIB_ERR_METADATA_NOT_FOUND;

	new_imd = wim->image_metadata[new_image - 1];
	if (!new_imd->modified)
		return WIMLIB_ERR_INVALID_PARAM;

	ret = select_wim_image(template_wim, template_image);
	if (ret)
		return ret;

	struct reference_template_args args = {
		.wim = wim,
		.template_wim = template_wim,
	};

	ret = for_dentry_in_tree(new_imd->root_dentry,
				 dentry_reference_template, &args);
	dentry_tree_clear_inode_visited(new_imd->root_dentry);
	return ret;
}
