/*
 * template.c
 *
 * API to reference a template image to optimize later writing of a WIM file.
 */

/*
 * Copyright (C) 2013, 2015 Eric Biggers
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
#include "wimlib/blob_table.h"
#include "wimlib/assert.h"
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/metadata.h"
#include "wimlib/util.h"

static u64
stream_size(const struct wim_inode_stream *strm,
	    const struct blob_table *blob_table)
{
	const struct blob_descriptor *blob;

	blob = stream_blob(strm, blob_table);
	if (!blob)
		return 0;
	return blob->size;
}

/* Returns %true iff the metadata of @inode and @template_inode are reasonably
 * consistent with them being the same, unmodified file.  */
static bool
inode_metadata_consistent(const struct wim_inode *inode,
			  const struct wim_inode *template_inode,
			  const struct blob_table *blob_table,
			  const struct blob_table *template_blob_table)
{
	/* Must have exact same creation time and last write time.  */
	if (inode->i_creation_time != template_inode->i_creation_time ||
	    inode->i_last_write_time != template_inode->i_last_write_time)
		return false;

	/* Last access time may have stayed the same or increased, but certainly
	 * shouldn't have decreased.  */
	if (inode->i_last_access_time < template_inode->i_last_access_time)
		return false;

	/* All stream sizes must match.  */
	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		const struct wim_inode_stream *strm, *template_strm;

		strm = &inode->i_streams[i];
		template_strm = inode_get_stream(template_inode,
						 strm->stream_type,
						 strm->stream_name);
		if (!template_strm)
			return false;

		if (stream_size(strm, blob_table) !=
		    stream_size(template_strm, template_blob_table))
			return false;
	}

	return true;
}

/**
 * Given an inode @inode that has been determined to be "the same" as another
 * inode @template_inode in either the same WIM or another WIM, copy stream
 * checksums from @template_inode to @inode.
 */
static void
inode_copy_checksums(struct wim_inode *inode,
		     struct wim_inode *template_inode,
		     struct blob_table *blob_table,
		     struct blob_table *template_blob_table)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		const struct wim_inode_stream *strm, *template_strm;
		struct blob_descriptor *blob, *template_blob, **back_ptr;

		strm = &inode->i_streams[i];
		template_strm = inode_get_stream(template_inode,
						 strm->stream_type,
						 strm->stream_name);

		blob = stream_blob(strm, blob_table);
		template_blob = stream_blob(template_strm, template_blob_table);

		/* To copy hashes: both blobs must exist, the blob for @inode
		 * must be unhashed, and the blob for @template_inode must be
		 * hashed.  */
		if (!blob || !template_blob ||
		    !blob->unhashed || template_blob->unhashed)
			continue;

		back_ptr = retrieve_pointer_to_unhashed_blob(blob);
		copy_hash(blob->hash, template_blob->hash);
		if (after_blob_hashed(blob, back_ptr, blob_table) != blob)
			free_blob_descriptor(blob);
	}
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

	template_dentry = get_dentry(template_wim, dentry->d_full_path,
				     WIMLIB_CASE_SENSITIVE);
	if (template_dentry == NULL) {
		DEBUG("\"%"TS"\": newly added file", dentry->d_full_path);
		return 0;
	}

	inode = dentry->d_inode;
	template_inode = template_dentry->d_inode;

	if (inode_metadata_consistent(inode, template_inode, wim->blob_table,
				      template_wim->blob_table))
	{
		DEBUG("\"%"TS"\": No change detected", dentry->d_full_path);
		inode_copy_checksums(inode, template_inode, wim->blob_table,
				     template_wim->blob_table);
		inode->i_visited = 1;
	} else {
		DEBUG("\"%"TS"\": change detected!", dentry->d_full_path);
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_reference_template_image(WIMStruct *wim, int new_image,
				WIMStruct *template_wim, int template_image,
				int flags)
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
