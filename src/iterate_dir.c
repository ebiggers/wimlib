/*
 * iterate_dir.c
 *
 * Iterate through files in a WIM image.
 * This is the stable API; internal code can just use for_dentry_in_tree().
 */

/*
 * Copyright (C) 2013 Eric Biggers
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
#include "wimlib/encoding.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/security.h"
#include "wimlib/timestamp.h"
#include "wimlib/unix_data.h"
#include "wimlib/util.h"
#include "wimlib/wim.h"

static int
init_wimlib_dentry(struct wimlib_dir_entry *wdentry, struct wim_dentry *dentry,
		   WIMStruct *wim, int flags)
{
	int ret;
	size_t dummy;
	const struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;
	const u8 *hash;
	struct wimlib_unix_data unix_data;

	ret = utf16le_get_tstr(dentry->file_name, dentry->file_name_nbytes,
			       &wdentry->filename, &dummy);
	if (ret)
		return ret;

	ret = utf16le_get_tstr(dentry->short_name, dentry->short_name_nbytes,
			       &wdentry->dos_name, &dummy);
	if (ret)
		return ret;

	ret = calculate_dentry_full_path(dentry);
	if (ret)
		return ret;
	wdentry->full_path = dentry->_full_path;

	for (struct wim_dentry *d = dentry; !dentry_is_root(d); d = d->d_parent)
		wdentry->depth++;

	if (inode->i_security_id >= 0) {
		struct wim_security_data *sd;

		sd = wim_get_current_security_data(wim);
		wdentry->security_descriptor = sd->descriptors[inode->i_security_id];
		wdentry->security_descriptor_size = sd->sizes[inode->i_security_id];
	}
	wdentry->reparse_tag = inode->i_reparse_tag;
	wdentry->num_links = inode->i_nlink;
	wdentry->attributes = inode->i_attributes;
	wdentry->hard_link_group_id = inode->i_ino;
	wdentry->creation_time = wim_timestamp_to_timespec(inode->i_creation_time);
	wdentry->last_write_time = wim_timestamp_to_timespec(inode->i_last_write_time);
	wdentry->last_access_time = wim_timestamp_to_timespec(inode->i_last_access_time);
	if (inode_get_unix_data(inode, &unix_data)) {
		wdentry->unix_uid = unix_data.uid;
		wdentry->unix_gid = unix_data.gid;
		wdentry->unix_mode = unix_data.mode;
		wdentry->unix_rdev = unix_data.rdev;
	}

	lte = inode_unnamed_lte(inode, wim->lookup_table);
	if (lte) {
		lte_to_wimlib_resource_entry(lte, &wdentry->streams[0].resource);
	} else if (!is_zero_hash(hash = inode_unnamed_stream_hash(inode))) {
		if (flags & WIMLIB_ITERATE_DIR_TREE_FLAG_RESOURCES_NEEDED)
			return stream_not_found_error(inode, hash);
		copy_hash(wdentry->streams[0].resource.sha1_hash, hash);
		wdentry->streams[0].resource.is_missing = 1;
	}

	for (unsigned i = 0; i < inode->i_num_ads; i++) {
		if (!inode->i_ads_entries[i].stream_name_nbytes)
			continue;
		lte = inode_stream_lte(inode, i + 1, wim->lookup_table);
		wdentry->num_named_streams++;
		if (lte) {
			lte_to_wimlib_resource_entry(lte, &wdentry->streams[
								wdentry->num_named_streams].resource);
		} else if (!is_zero_hash(hash = inode_stream_hash(inode, i + 1))) {
			if (flags & WIMLIB_ITERATE_DIR_TREE_FLAG_RESOURCES_NEEDED)
				return stream_not_found_error(inode, hash);
			copy_hash(wdentry->streams[
				  wdentry->num_named_streams].resource.sha1_hash, hash);
			wdentry->streams[
				wdentry->num_named_streams].resource.is_missing = 1;
		}

		size_t dummy;

		ret = utf16le_get_tstr(inode->i_ads_entries[i].stream_name,
				       inode->i_ads_entries[i].stream_name_nbytes,
				       &wdentry->streams[
					       wdentry->num_named_streams].stream_name,
				       &dummy);
		if (ret)
			return ret;
	}
	return 0;
}

static void
free_wimlib_dentry(struct wimlib_dir_entry *wdentry)
{
	utf16le_put_tstr(wdentry->filename);
	utf16le_put_tstr(wdentry->dos_name);
	for (unsigned i = 1; i <= wdentry->num_named_streams; i++)
		utf16le_put_tstr(wdentry->streams[i].stream_name);
	FREE(wdentry);
}

static int
do_iterate_dir_tree(WIMStruct *wim,
		    struct wim_dentry *dentry, int flags,
		    wimlib_iterate_dir_tree_callback_t cb,
		    void *user_ctx)
{
	struct wimlib_dir_entry *wdentry;
	int ret = WIMLIB_ERR_NOMEM;


	wdentry = CALLOC(1, sizeof(struct wimlib_dir_entry) +
				  (1 + dentry->d_inode->i_num_ads) *
					sizeof(struct wimlib_stream_entry));
	if (wdentry == NULL)
		goto out;

	ret = init_wimlib_dentry(wdentry, dentry, wim, flags);
	if (ret)
		goto out_free_wimlib_dentry;

	if (!(flags & WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN)) {
		ret = (*cb)(wdentry, user_ctx);
		if (ret)
			goto out_free_wimlib_dentry;
	}

	if (flags & (WIMLIB_ITERATE_DIR_TREE_FLAG_RECURSIVE |
		     WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN))
	{
		struct wim_dentry *child;

		ret = 0;
		if (default_ignore_case) {
			for_dentry_child_case_insensitive(child, dentry) {
				ret = do_iterate_dir_tree(wim, child,
							  flags & ~WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN,
							  cb, user_ctx);
				if (ret)
					break;
			}
		} else {
			for_dentry_child(child, dentry) {
				ret = do_iterate_dir_tree(wim, child,
							  flags & ~WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN,
							  cb, user_ctx);
				if (ret)
					break;
			}
		}
	}
out_free_wimlib_dentry:
	free_wimlib_dentry(wdentry);
out:
	return ret;
}

struct image_iterate_dir_tree_ctx {
	const tchar *path;
	int flags;
	wimlib_iterate_dir_tree_callback_t cb;
	void *user_ctx;
};


static int
image_do_iterate_dir_tree(WIMStruct *wim)
{
	struct image_iterate_dir_tree_ctx *ctx = wim->private;
	struct wim_dentry *dentry;

	dentry = get_dentry(wim, ctx->path, WIMLIB_CASE_PLATFORM_DEFAULT);
	if (dentry == NULL)
		return WIMLIB_ERR_PATH_DOES_NOT_EXIST;
	return do_iterate_dir_tree(wim, dentry, ctx->flags, ctx->cb, ctx->user_ctx);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_iterate_dir_tree(WIMStruct *wim, int image, const tchar *_path,
			int flags,
			wimlib_iterate_dir_tree_callback_t cb, void *user_ctx)
{
	tchar *path;
	int ret;

	if (flags & ~(WIMLIB_ITERATE_DIR_TREE_FLAG_RECURSIVE |
		      WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN |
		      WIMLIB_ITERATE_DIR_TREE_FLAG_RESOURCES_NEEDED))
		return WIMLIB_ERR_INVALID_PARAM;

	path = canonicalize_wim_path(_path);
	if (path == NULL)
		return WIMLIB_ERR_NOMEM;
	struct image_iterate_dir_tree_ctx ctx = {
		.path = path,
		.flags = flags,
		.cb = cb,
		.user_ctx = user_ctx,
	};
	wim->private = &ctx;
	ret = for_image(wim, image, image_do_iterate_dir_tree);
	FREE(path);
	return ret;
}
