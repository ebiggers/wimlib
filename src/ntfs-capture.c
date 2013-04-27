/*
 * ntfs-capture.c
 *
 * Capture a WIM image from a NTFS volume.  We capture everything we can,
 * including security data and alternate data streams.
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


#include "config.h"

#include <ntfs-3g/endians.h>
#include <ntfs-3g/types.h>

#include "buffer_io.h"
#include "dentry.h"
#include "lookup_table.h"
#include "security.h"
#include "wimlib_internal.h"

#include <ntfs-3g/layout.h>
#include <ntfs-3g/acls.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/misc.h>
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/security.h> /* ntfs-3g/security.h before ntfs-3g/xattrs.h */
#include <ntfs-3g/xattrs.h>
#include <ntfs-3g/volume.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

static inline ntfschar *
attr_record_name(ATTR_RECORD *ar)
{
	return (ntfschar*)((u8*)ar + le16_to_cpu(ar->name_offset));
}

static ntfs_attr *
open_ntfs_attr(ntfs_inode *ni, struct ntfs_location *loc)
{
	ntfs_attr *na;

	na = ntfs_attr_open(ni,
			    loc->is_reparse_point ? AT_REPARSE_POINT : AT_DATA,
			    loc->stream_name,
			    loc->stream_name_nchars);
	if (!na) {
		ERROR_WITH_ERRNO("Failed to open attribute of \"%"TS"\" in "
				 "NTFS volume", loc->path);
	}
	return na;
}

int
read_ntfs_file_prefix(const struct wim_lookup_table_entry *lte,
		      u64 size,
		      consume_data_callback_t cb,
		      void *ctx_or_buf,
		      int _ignored_flags)
{
	struct ntfs_location *loc = lte->ntfs_loc;
	ntfs_volume *vol = loc->ntfs_vol;
	ntfs_inode *ni;
	ntfs_attr *na;
	s64 pos;
	s64 bytes_remaining;
	void *out_buf;
	int ret;

 	ni = ntfs_pathname_to_inode(vol, NULL, loc->path);
	if (!ni) {
		ERROR_WITH_ERRNO("Can't find NTFS inode for \"%"TS"\"", loc->path);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	na = open_ntfs_attr(ni, loc);
	if (!na) {
		ret = WIMLIB_ERR_NTFS_3G;
		goto out_close_ntfs_inode;
	}

	if (cb)
		out_buf = alloca(WIM_CHUNK_SIZE);
	else
		out_buf = ctx_or_buf;
	pos = (loc->is_reparse_point) ? 8 : 0;
	bytes_remaining = size;
	while (bytes_remaining) {
		s64 to_read = min(bytes_remaining, WIM_CHUNK_SIZE);
		if (ntfs_attr_pread(na, pos, to_read, out_buf) != to_read) {
			ERROR_WITH_ERRNO("Error reading \"%"TS"\"", loc->path);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out_close_ntfs_attr;
		}
		pos += to_read;
		bytes_remaining -= to_read;
		if (cb) {
			ret = cb(out_buf, to_read, ctx_or_buf);
			if (ret)
				goto out_close_ntfs_attr;
		} else {
			out_buf += to_read;
		}
	}
	ret = 0;
out_close_ntfs_attr:
	ntfs_attr_close(na);
out_close_ntfs_inode:
	ntfs_inode_close(ni);
out:
	return ret;
}

static int
read_reparse_tag(ntfs_inode *ni, struct ntfs_location *loc,
		 u32 *reparse_tag_ret)
{
	int ret;
	u8 buf[8];
	ntfs_attr *na;

	na = open_ntfs_attr(ni, loc);
	if (!na) {
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	if (ntfs_attr_pread(na, 0, 8, buf) != 8) {
		ERROR_WITH_ERRNO("Error reading reparse data");
		ret = WIMLIB_ERR_NTFS_3G;
		goto out_close_ntfs_attr;
	}
	*reparse_tag_ret = le32_to_cpu(*(u32*)buf);
	DEBUG("ReparseTag = %#x", *reparse_tag_ret);
	ret = 0;
out_close_ntfs_attr:
	ntfs_attr_close(na);
out:
	return ret;

}

/* Load the streams from a file or reparse point in the NTFS volume into the WIM
 * lookup table */
static int
capture_ntfs_streams(struct wim_inode *inode,
		     ntfs_inode *ni,
		     char *path,
		     size_t path_len,
		     struct wim_lookup_table *lookup_table,
		     ntfs_volume *vol,
		     ATTR_TYPES type)
{
	ntfs_attr_search_ctx *actx;
	struct ntfs_location *ntfs_loc;
	int ret;
	struct wim_lookup_table_entry *lte;

	DEBUG2("Capturing NTFS data streams from `%s'", path);

	/* Get context to search the streams of the NTFS file. */
	actx = ntfs_attr_get_search_ctx(ni, NULL);
	if (!actx) {
		ERROR_WITH_ERRNO("Cannot get NTFS attribute search "
				 "context");
		return WIMLIB_ERR_NTFS_3G;
	}

	/* Capture each data stream or reparse data stream. */
	while (!ntfs_attr_lookup(type, NULL, 0,
				 CASE_SENSITIVE, 0, NULL, 0, actx))
	{
		u64 data_size = ntfs_get_attribute_value_length(actx->attr);
		u64 name_length = actx->attr->name_length;
		u32 stream_id;

		if (data_size == 0) {
			/* Empty stream.  No lookup table entry is needed. */
			lte = NULL;
			ntfs_loc = NULL;
		} else {
			ntfs_loc = CALLOC(1, sizeof(*ntfs_loc));
			if (!ntfs_loc) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_put_actx;
			}
			ntfs_loc->ntfs_vol = vol;
			ntfs_loc->path = MALLOC(path_len + 1);
			if (!ntfs_loc->path) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_ntfs_loc;
			}
			memcpy(ntfs_loc->path, path, path_len + 1);
			if (name_length) {
				ntfs_loc->stream_name = MALLOC(name_length * 2);
				if (!ntfs_loc->stream_name) {
					ret = WIMLIB_ERR_NOMEM;
					goto out_free_ntfs_loc;
				}
				memcpy(ntfs_loc->stream_name,
				       attr_record_name(actx->attr),
				       actx->attr->name_length * 2);
				ntfs_loc->stream_name_nchars = name_length;
			}

			lte = new_lookup_table_entry();
			if (!lte) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_ntfs_loc;
			}
			lte->resource_location = RESOURCE_IN_NTFS_VOLUME;
			lte->ntfs_loc = ntfs_loc;
			ntfs_loc = NULL;
			if (type == AT_REPARSE_POINT) {
				if (data_size < 8) {
					ERROR("Invalid reparse data (only %u bytes)!",
					      (unsigned)data_size);
					ret = WIMLIB_ERR_NTFS_3G;
					goto out_free_lte;
				}
				lte->ntfs_loc->is_reparse_point = true;
				lte->resource_entry.original_size = data_size - 8;
				ret = read_reparse_tag(ni, lte->ntfs_loc,
						       &inode->i_reparse_tag);
				if (ret)
					goto out_free_lte;
			} else {
				lte->ntfs_loc->is_reparse_point = false;
				lte->resource_entry.original_size = data_size;
			}
		}
		if (name_length == 0) {
			/* Unnamed data stream.  Put the reference to it in the
			 * dentry's inode. */
			if (inode->i_lte) {
				ERROR("Found two un-named data streams for `%s'",
				      path);
				ret = WIMLIB_ERR_NTFS_3G;
				goto out_free_lte;
			}
			stream_id = 0;
			inode->i_lte = lte;
		} else {
			/* Named data stream.  Put the reference to it in the
			 * alternate data stream entries */
			struct wim_ads_entry *new_ads_entry;

			new_ads_entry = inode_add_ads_utf16le(inode,
							      attr_record_name(actx->attr),
							      name_length * 2);
			if (!new_ads_entry) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_lte;
			}
			wimlib_assert(new_ads_entry->stream_name_nbytes == name_length * 2);
			stream_id = new_ads_entry->stream_id;
			new_ads_entry->lte = lte;
		}
		if (lte) {
			lookup_table_insert_unhashed(lookup_table, lte,
						     inode, stream_id);
		}
	}
	if (errno == ENOENT) {
		ret = 0;
	} else {
		ERROR_WITH_ERRNO("Error listing NTFS attributes from `%s'",
				 path);
		ret = WIMLIB_ERR_NTFS_3G;
	}
	goto out_put_actx;
out_free_lte:
	free_lookup_table_entry(lte);
out_free_ntfs_loc:
	if (ntfs_loc) {
		FREE(ntfs_loc->path);
		FREE(ntfs_loc->stream_name);
		FREE(ntfs_loc);
	}
out_put_actx:
	ntfs_attr_put_search_ctx(actx);
	if (ret == 0)
		DEBUG2("Successfully captured NTFS streams from `%s'", path);
	else
		ERROR("Failed to capture NTFS streams from `%s'", path);
	return ret;
}

/* Red-black tree that maps NTFS inode numbers to DOS names */
struct dos_name_map {
	struct rb_root rb_root;
};

struct dos_name_node {
	struct rb_node rb_node;
	char dos_name[24];
	int name_nbytes;
	u64 ntfs_ino;
};

/* Inserts a new DOS name into the map */
static int
insert_dos_name(struct dos_name_map *map, const ntfschar *dos_name,
		size_t name_nbytes, u64 ntfs_ino)
{
	struct dos_name_node *new_node;
	struct rb_node **p;
	struct rb_root *root;
	struct rb_node *rb_parent;

	DEBUG("DOS name_len = %zu", name_nbytes);
	new_node = MALLOC(sizeof(struct dos_name_node));
	if (!new_node)
		return -1;

	/* DOS names are supposed to be 12 characters max (that's 24 bytes,
	 * assuming 2-byte ntfs characters) */
	wimlib_assert(name_nbytes <= sizeof(new_node->dos_name));

	/* Initialize the DOS name, DOS name length, and NTFS inode number of
	 * the red-black tree node */
	memcpy(new_node->dos_name, dos_name, name_nbytes);
	new_node->name_nbytes = name_nbytes;
	new_node->ntfs_ino = ntfs_ino;

	/* Insert the red-black tree node */
	root = &map->rb_root;
	p = &root->rb_node;
	rb_parent = NULL;
	while (*p) {
		struct dos_name_node *this;

		this = container_of(*p, struct dos_name_node, rb_node);
		rb_parent = *p;
		if (new_node->ntfs_ino < this->ntfs_ino)
			p = &((*p)->rb_left);
		else if (new_node->ntfs_ino > this->ntfs_ino)
			p = &((*p)->rb_right);
		else {
			/* This should be impossible since a NTFS inode cannot
			 * have multiple DOS names, and we only should get each
			 * DOS name entry once from the ntfs_readdir() calls. */
			ERROR("NTFS inode %"PRIu64" has multiple DOS names",
			      ntfs_ino);
			return -1;
		}
	}
	rb_link_node(&new_node->rb_node, rb_parent, p);
	rb_insert_color(&new_node->rb_node, root);
	DEBUG("Inserted DOS name for inode %"PRIu64, ntfs_ino);
	return 0;
}

/* Returns a structure that contains the DOS name and its length for a NTFS
 * inode, or NULL if the inode has no DOS name. */
static struct dos_name_node *
lookup_dos_name(const struct dos_name_map *map, u64 ntfs_ino)
{
	struct rb_node *node = map->rb_root.rb_node;
	while (node) {
		struct dos_name_node *this;
		this = container_of(node, struct dos_name_node, rb_node);
		if (ntfs_ino < this->ntfs_ino)
			node = node->rb_left;
		else if (ntfs_ino > this->ntfs_ino)
			node = node->rb_right;
		else
			return this;
	}
	return NULL;
}

static int
set_dentry_dos_name(struct wim_dentry *dentry, void *arg)
{
	const struct dos_name_map *map = arg;
	const struct dos_name_node *node;

	if (dentry->is_win32_name) {
		node = lookup_dos_name(map, dentry->d_inode->i_ino);
		if (node) {
			dentry->short_name = MALLOC(node->name_nbytes + 2);
			if (!dentry->short_name)
				return WIMLIB_ERR_NOMEM;
			memcpy(dentry->short_name, node->dos_name,
			       node->name_nbytes);
			dentry->short_name[node->name_nbytes / 2] = 0;
			dentry->short_name_nbytes = node->name_nbytes;
			DEBUG("Assigned DOS name to ino %"PRIu64,
			      dentry->d_inode->i_ino);
		} else {
			WARNING("NTFS inode %"PRIu64" has Win32 name with no "
				"corresponding DOS name",
				dentry->d_inode->i_ino);
		}
	}
	return 0;
}

static void
free_dos_name_tree(struct rb_node *node) {
	if (node) {
		free_dos_name_tree(node->rb_left);
		free_dos_name_tree(node->rb_right);
		FREE(container_of(node, struct dos_name_node, rb_node));
	}
}

static void
destroy_dos_name_map(struct dos_name_map *map)
{
	free_dos_name_tree(map->rb_root.rb_node);
}

struct readdir_ctx {
	struct wim_dentry *parent;
	ntfs_inode *dir_ni;
	char *path;
	size_t path_len;
	struct dos_name_map *dos_name_map;
	ntfs_volume *vol;
	struct add_image_params *params;
};

static int
build_dentry_tree_ntfs_recursive(struct wim_dentry **root_p,
				 ntfs_inode *dir_ni,
				 ntfs_inode *ni,
				 char *path,
				 size_t path_len,
				 int name_type,
				 ntfs_volume *ntfs_vol,
				 struct add_image_params *params);

static int
wim_ntfs_capture_filldir(void *dirent, const ntfschar *name,
			 const int name_nchars, const int name_type,
			 const s64 pos, const MFT_REF mref,
			 const unsigned dt_type)
{
	struct readdir_ctx *ctx;
	size_t mbs_name_nbytes;
	char *mbs_name;
	struct wim_dentry *child;
	int ret;
	size_t path_len;
	size_t name_nbytes = name_nchars * sizeof(ntfschar);

	ctx = dirent;
	if (name_type & FILE_NAME_DOS) {
		/* If this is the entry for a DOS name, store it for later. */
		ret = insert_dos_name(ctx->dos_name_map, name,
				      name_nbytes, mref & MFT_REF_MASK_CPU);

		/* Return now if an error occurred or if this is just a DOS name
		 * and not a Win32+DOS name. */
		if (ret != 0 || name_type == FILE_NAME_DOS)
			goto out;
	}
	ret = utf16le_to_tstr(name, name_nbytes,
			      &mbs_name, &mbs_name_nbytes);
	if (ret)
		goto out;

	if (mbs_name[0] == '.' &&
	     (mbs_name[1] == '\0' ||
	      (mbs_name[1] == '.' && mbs_name[2] == '\0'))) {
		/* . or .. entries
		 *
		 * note: name_type is POSIX for these, so DOS names will not
		 * have been inserted for them.  */
		ret = 0;
		goto out_free_mbs_name;
	}

	/* Open the inode for this directory entry and recursively capture the
	 * directory tree rooted at it */
	ntfs_inode *ni = ntfs_inode_open(ctx->dir_ni->vol, mref);
	if (!ni) {
		ERROR_WITH_ERRNO("Failed to open NTFS inode");
		ret = -1;
		goto out_free_mbs_name;
	}
	path_len = ctx->path_len;
	if (path_len != 1)
		ctx->path[path_len++] = '/';
	memcpy(ctx->path + path_len, mbs_name, mbs_name_nbytes + 1);
	path_len += mbs_name_nbytes;
	child = NULL;
	ret = build_dentry_tree_ntfs_recursive(&child, ctx->dir_ni,
					       ni, ctx->path, path_len, name_type,
					       ctx->vol, ctx->params);
	if (child)
		dentry_add_child(ctx->parent, child);
	ntfs_inode_close(ni);
out_free_mbs_name:
	FREE(mbs_name);
out:
	return ret;
}

/* Recursively build a WIM dentry tree corresponding to a NTFS volume.
 * At the same time, update the WIM lookup table with lookup table entries for
 * the NTFS streams, and build an array of security descriptors.
 */
static int
build_dentry_tree_ntfs_recursive(struct wim_dentry **root_ret,
				 ntfs_inode *dir_ni,
				 ntfs_inode *ni,
				 char *path,
				 size_t path_len,
				 int name_type,
				 ntfs_volume *vol,
				 struct add_image_params *params)
{
	u32 attributes;
	int ret;
	struct wim_dentry *root;
	struct wim_inode *inode;
	ATTR_TYPES stream_type;

	if (exclude_path(path, path_len, params->config, false)) {
		/* Exclude a file or directory tree based on the capture
		 * configuration file */
		if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE)
		    && params->progress_func)
		{
			union wimlib_progress_info info;
			info.scan.cur_path = path;
			info.scan.excluded = true;
			params->progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
		}
		root = NULL;
		ret = 0;
		goto out;
	}

	/* Get file attributes */
	struct SECURITY_CONTEXT ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.vol = vol;
	ret = ntfs_xattr_system_getxattr(&ctx, XATTR_NTFS_ATTRIB,
					 ni, dir_ni, (char *)&attributes,
					 sizeof(u32));
	if (ret != 4) {
		ERROR_WITH_ERRNO("Failed to get NTFS attributes from `%s'",
				 path);
		return WIMLIB_ERR_NTFS_3G;
	}

	if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
	    && params->progress_func)
	{
		union wimlib_progress_info info;
		info.scan.cur_path = path;
		info.scan.excluded = false;
		params->progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
	}

	/* Create a WIM dentry with an associated inode, which may be shared */
	ret = inode_table_new_dentry(params->inode_table,
				     path_basename_with_len(path, path_len),
				     ni->mft_no, 0, false, &root);
	if (ret)
		return ret;

	inode = root->d_inode;

	if (inode->i_nlink > 1) /* Shared inode; nothing more to do */
		goto out;

	if (name_type & FILE_NAME_WIN32) /* Win32 or Win32+DOS name (rather than POSIX) */
		root->is_win32_name = 1;
	inode->i_creation_time    = le64_to_cpu(ni->creation_time);
	inode->i_last_write_time  = le64_to_cpu(ni->last_data_change_time);
	inode->i_last_access_time = le64_to_cpu(ni->last_access_time);
	inode->i_attributes       = le32_to_cpu(attributes);
	inode->i_resolved         = 1;

	if (attributes & FILE_ATTR_REPARSE_POINT)
		stream_type = AT_REPARSE_POINT;
	else
		stream_type = AT_DATA;

	/* Capture the file's streams; more specifically, this is supposed to:
	 *
	 * - Regular files: capture unnamed data stream and any named data
	 *   streams
	 * - Directories: capture any named data streams
	 * - Reparse points: capture reparse data only
	 */
	ret = capture_ntfs_streams(inode, ni, path, path_len,
				   params->lookup_table, vol, stream_type);
	if (ret)
		goto out;

	if (ni->mrec->flags & MFT_RECORD_IS_DIRECTORY) {

		/* Recurse to directory children */
		s64 pos = 0;
		struct dos_name_map dos_name_map = { .rb_root = {.rb_node = NULL} };
		struct readdir_ctx ctx = {
			.parent          = root,
			.dir_ni          = ni,
			.path            = path,
			.path_len        = path_len,
			.dos_name_map    = &dos_name_map,
			.vol             = vol,
			.params          = params,
		};
		ret = ntfs_readdir(ni, &pos, &ctx, wim_ntfs_capture_filldir);
		if (ret) {
			ERROR_WITH_ERRNO("ntfs_readdir()");
			ret = WIMLIB_ERR_NTFS_3G;
		} else {
			ret = for_dentry_child(root, set_dentry_dos_name,
					       &dos_name_map);
		}
		destroy_dos_name_map(&dos_name_map);
		if (ret)
			goto out;
	}

	if (!(params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NO_ACLS)) {
		/* Get security descriptor */
		char _sd[1];
		char *sd = _sd;
		errno = 0;
		ret = ntfs_xattr_system_getxattr(&ctx, XATTR_NTFS_ACL,
						 ni, dir_ni, sd,
						 sizeof(sd));
		if (ret > sizeof(sd)) {
			sd = alloca(ret);
			ret = ntfs_xattr_system_getxattr(&ctx, XATTR_NTFS_ACL,
							 ni, dir_ni, sd, ret);
		}
		if (ret > 0) {
			inode->i_security_id = sd_set_add_sd(params->sd_set,
							     sd, ret);
			if (inode->i_security_id == -1) {
				ERROR("Out of memory");
				ret = WIMLIB_ERR_NOMEM;
				goto out;
			}
			DEBUG("Added security ID = %u for `%s'",
			      inode->i_security_id, path);
			ret = 0;
		} else if (ret < 0) {
			ERROR_WITH_ERRNO("Failed to get security information from "
					 "`%s'", path);
			ret = WIMLIB_ERR_NTFS_3G;
		} else {
			inode->i_security_id = -1;
			DEBUG("No security ID for `%s'", path);
		}
	}
out:
	if (ret == 0)
		*root_ret = root;
	else
		free_dentry_tree(root, params->lookup_table);
	return ret;
}


int
do_ntfs_umount(struct _ntfs_volume *vol)
{
	DEBUG("Unmounting NTFS volume");
	if (ntfs_umount(vol, FALSE))
		return WIMLIB_ERR_NTFS_3G;
	else
		return 0;
}

int
build_dentry_tree_ntfs(struct wim_dentry **root_p,
		       const char *device,
		       struct add_image_params *params)
{
	ntfs_volume *vol;
	ntfs_inode *root_ni;
	int ret;

	DEBUG("Mounting NTFS volume `%s' read-only", device);

#ifdef HAVE_NTFS_MNT_RDONLY
	/* NTFS-3g 2013 */
	vol = ntfs_mount(device, NTFS_MNT_RDONLY);
#else
	/* NTFS-3g 2011, 2012 */
	vol = ntfs_mount(device, MS_RDONLY);
#endif
	if (!vol) {
		ERROR_WITH_ERRNO("Failed to mount NTFS volume `%s' read-only",
				 device);
		return WIMLIB_ERR_NTFS_3G;
	}
	ntfs_open_secure(vol);

	/* We don't want to capture the special NTFS files such as $Bitmap.  Not
	 * to be confused with "hidden" or "system" files which are real files
	 * that we do need to capture.  */
	NVolClearShowSysFiles(vol);

	DEBUG("Opening root NTFS dentry");
	root_ni = ntfs_inode_open(vol, FILE_root);
	if (!root_ni) {
		ERROR_WITH_ERRNO("Failed to open root inode of NTFS volume "
				 "`%s'", device);
		ret = WIMLIB_ERR_NTFS_3G;
		goto out;
	}

	/* Currently we assume that all the paths fit into this length and there
	 * is no check for overflow. */
	char *path = MALLOC(32768);
	if (!path) {
		ERROR("Could not allocate memory for NTFS pathname");
		ret = WIMLIB_ERR_NOMEM;
		goto out_cleanup;
	}

	path[0] = '/';
	path[1] = '\0';
	ret = build_dentry_tree_ntfs_recursive(root_p, NULL, root_ni, path, 1,
					       FILE_NAME_POSIX, vol, params);
out_cleanup:
	FREE(path);
	ntfs_inode_close(root_ni);
out:
	ntfs_index_ctx_put(vol->secure_xsii);
	ntfs_index_ctx_put(vol->secure_xsdh);
	ntfs_inode_close(vol->secure_ni);

	if (ret) {
		if (do_ntfs_umount(vol)) {
			ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%s'",
					 device);
			if (ret == 0)
				ret = WIMLIB_ERR_NTFS_3G;
		}
	} else {
		/* We need to leave the NTFS volume mounted so that we can read
		 * the NTFS files again when we are actually writing the WIM */
		*(ntfs_volume**)params->extra_arg = vol;
	}
	return ret;
}
