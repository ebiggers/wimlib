/*
 * ntfs-3g_apply.c
 *
 * Apply a WIM image directly to an NTFS volume using libntfs-3g.  Restore as
 * much information as possible, including security data, file attributes, DOS
 * names, alternate data streams, and object IDs.
 *
 * Note: because NTFS-3G offers inode-based interfaces, we actually don't need
 * to deal with paths at all!  (Other than for error messages.)
 */

/*
 * Copyright (C) 2012-2016 Eric Biggers
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

#include <errno.h>
#include <locale.h>
#include <string.h>

#include <ntfs-3g/attrib.h>
#include <ntfs-3g/object_id.h>
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/security.h>

#include "wimlib/assert.h"
#include "wimlib/apply.h"
#include "wimlib/blob_table.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/metadata.h"
#include "wimlib/ntfs_3g.h"
#include "wimlib/object_id.h"
#include "wimlib/reparse.h"
#include "wimlib/security.h"

static int
ntfs_3g_get_supported_features(const char *target,
			       struct wim_features *supported_features)
{
	supported_features->readonly_files            = 1;
	supported_features->hidden_files              = 1;
	supported_features->system_files              = 1;
	supported_features->archive_files             = 1;
	supported_features->compressed_files          = 1;
	supported_features->not_context_indexed_files = 1;
	supported_features->named_data_streams        = 1;
	supported_features->hard_links                = 1;
	supported_features->reparse_points            = 1;
	supported_features->security_descriptors      = 1;
	supported_features->short_names               = 1;
	supported_features->object_ids                = 1;
	supported_features->timestamps                = 1;
	supported_features->case_sensitive_filenames  = 1;
	return 0;
}

struct ntfs_3g_apply_ctx {
	/* Extract flags, the pointer to the WIMStruct, etc.  */
	struct apply_ctx common;

	/* Pointer to the open NTFS volume  */
	ntfs_volume *vol;

	ntfs_attr *open_attrs[MAX_OPEN_FILES];
	unsigned num_open_attrs;
	ntfs_inode *open_inodes[MAX_OPEN_FILES];
	unsigned num_open_inodes;

	struct reparse_buffer_disk rpbuf;
	u8 *reparse_ptr;

	/* Offset in the blob currently being read  */
	u64 offset;

	unsigned num_reparse_inodes;
	ntfs_inode *ntfs_reparse_inodes[MAX_OPEN_FILES];
	struct wim_inode *wim_reparse_inodes[MAX_OPEN_FILES];
};

static int
ntfs_3g_set_timestamps(ntfs_inode *ni, const struct wim_inode *inode)
{
	u64 times[3] = {
		inode->i_creation_time,
		inode->i_last_write_time,
		inode->i_last_access_time,
	};

	if (ntfs_inode_set_times(ni, (const char *)times, sizeof(times), 0))
		return WIMLIB_ERR_SET_TIMESTAMPS;
	return 0;
}

/* Restore the timestamps on the NTFS inode corresponding to @inode.  */
static int
ntfs_3g_restore_timestamps(ntfs_volume *vol, const struct wim_inode *inode)
{
	ntfs_inode *ni;
	int res;

	ni = ntfs_inode_open(vol, inode->i_mft_no);
	if (!ni)
		goto fail;

	res = ntfs_3g_set_timestamps(ni, inode);

	if (ntfs_inode_close(ni) || res)
		goto fail;

	return 0;

fail:
	ERROR_WITH_ERRNO("Failed to update timestamps of \"%s\" in NTFS volume",
			 dentry_full_path(inode_first_extraction_dentry(inode)));
	return WIMLIB_ERR_SET_TIMESTAMPS;
}

/* Restore the DOS name of the @dentry.
 * This closes both @ni and @dir_ni.
 * If either is NULL, then they are opened temporarily.  */
static int
ntfs_3g_restore_dos_name(ntfs_inode *ni, ntfs_inode *dir_ni,
			 struct wim_dentry *dentry, ntfs_volume *vol)
{
	int ret;
	const char *dos_name;
	size_t dos_name_nbytes;

	/* Note: ntfs_set_ntfs_dos_name() closes both inodes (even if it fails).
	 * And it takes in a multibyte string, even though it translates it to
	 * UTF-16LE internally... which is annoying because we currently have
	 * the UTF-16LE string but not the multibyte string.  */

	ret = utf16le_get_tstr(dentry->d_short_name, dentry->d_short_name_nbytes,
			       &dos_name, &dos_name_nbytes);
	if (ret)
		goto out_close;

	if (!dir_ni)
		dir_ni = ntfs_inode_open(vol, dentry->d_parent->d_inode->i_mft_no);
	if (!ni)
		ni = ntfs_inode_open(vol, dentry->d_inode->i_mft_no);
	if (dir_ni && ni) {
		ret = ntfs_set_ntfs_dos_name(ni, dir_ni,
					     dos_name, dos_name_nbytes, 0);
		dir_ni = NULL;
		ni = NULL;
	} else {
		ret = -1;
	}
	utf16le_put_tstr(dos_name);
	if (ret) {
		int err = errno;
		ERROR_WITH_ERRNO("Failed to set DOS name of \"%s\" in NTFS "
				 "volume", dentry_full_path(dentry));
		if (err == EILSEQ) {
			ERROR("This error may have been caused by a known "
			      "bug in libntfs-3g where it is unable to set "
			      "DOS names on files whose long names contain "
			      "unpaired surrogate characters.  This bug "
			      "was fixed in the development version of "
			      "NTFS-3G in June 2016.");
		}
		ret = WIMLIB_ERR_SET_SHORT_NAME;
		goto out_close;
	}

	/* Unlike most other NTFS-3G functions, ntfs_set_ntfs_dos_name()
	 * changes the directory's last modification timestamp...
	 * Change it back.  */
	return ntfs_3g_restore_timestamps(vol, dentry->d_parent->d_inode);

out_close:
	/* ntfs_inode_close() can take a NULL argument, but it's probably best
	 * not to rely on this behavior.  */
	if (ni)
		ntfs_inode_close(ni);
	if (dir_ni)
		ntfs_inode_close(dir_ni);
	return ret;
}

static int
ntfs_3g_restore_reparse_point(ntfs_inode *ni, const struct wim_inode *inode,
			      unsigned blob_size, struct ntfs_3g_apply_ctx *ctx)
{
	complete_reparse_point(&ctx->rpbuf, inode, blob_size);

	if (ntfs_set_ntfs_reparse_data(ni, (const char *)&ctx->rpbuf,
				       REPARSE_DATA_OFFSET + blob_size, 0))
	{
		int err = errno;
		ERROR_WITH_ERRNO("Failed to set reparse data on \"%s\"",
				 dentry_full_path(
					inode_first_extraction_dentry(inode)));
		if (err == EINVAL && !(inode->i_reparse_tag & 0x80000000)) {
			WARNING("This reparse point had a non-Microsoft reparse "
				"tag.  The preceding error may have been caused "
				"by a known bug in libntfs-3g where it does not "
				"correctly validate non-Microsoft reparse "
				"points.  This bug was fixed in NTFS-3G version "
				"2016.2.22.");
		}
		return WIMLIB_ERR_SET_REPARSE_DATA;
	}

	return 0;
}

static bool
ntfs_3g_has_empty_attributes(const struct wim_inode *inode)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++) {
		const struct wim_inode_stream *strm = &inode->i_streams[i];

		if (stream_blob_resolved(strm) == NULL &&
		    (strm->stream_type == STREAM_TYPE_REPARSE_POINT ||
		     stream_is_named_data_stream(strm)))
			return true;
	}
	return false;
}

/*
 * Create empty attributes (named data streams and potentially a reparse point)
 * for the specified file, if there are any.
 *
 * Since these won't have blob descriptors, they won't show up in the call to
 * extract_blob_list().  Hence the need for the special case.
 *
 * Keep this in sync with ntfs_3g_has_empty_attributes()!
 */
static int
ntfs_3g_create_empty_attributes(ntfs_inode *ni,
				const struct wim_inode *inode,
				struct ntfs_3g_apply_ctx *ctx)
{
	for (unsigned i = 0; i < inode->i_num_streams; i++) {

		const struct wim_inode_stream *strm = &inode->i_streams[i];
		int ret;

		if (stream_blob_resolved(strm) != NULL)
			continue;

		if (strm->stream_type == STREAM_TYPE_REPARSE_POINT) {
			ret = ntfs_3g_restore_reparse_point(ni, inode, 0, ctx);
			if (ret)
				return ret;
		} else if (stream_is_named_data_stream(strm)) {
			if (ntfs_attr_add(ni, AT_DATA, strm->stream_name,
					  utf16le_len_chars(strm->stream_name),
					  NULL, 0))
			{
				ERROR_WITH_ERRNO("Failed to create named data "
						 "stream of \"%s\"",
						 dentry_full_path(
					inode_first_extraction_dentry(inode)));
				return WIMLIB_ERR_NTFS_3G;
			}
		}
	}
	return 0;
}

/* Set attributes, security descriptor, and timestamps on the NTFS inode @ni.
 */
static int
ntfs_3g_set_metadata(ntfs_inode *ni, const struct wim_inode *inode,
		     const struct ntfs_3g_apply_ctx *ctx)
{
	int extract_flags;
	const struct wim_security_data *sd;
	struct wim_dentry *one_dentry;
	int ret;

	extract_flags = ctx->common.extract_flags;
	sd = wim_get_current_security_data(ctx->common.wim);
	one_dentry = inode_first_extraction_dentry(inode);

	/* Object ID */
	{
		u32 len;
		const void *object_id = inode_get_object_id(inode, &len);
		if (unlikely(object_id != NULL) &&
		    ntfs_set_ntfs_object_id(ni, object_id, len, 0))
		{
			if (errno == EEXIST) {
				WARNING("Duplicate object ID on file \"%s\"",
					dentry_full_path(one_dentry));
			} else {
				ERROR_WITH_ERRNO("Failed to set object ID on "
						 "\"%s\" in NTFS volume",
						 dentry_full_path(one_dentry));
				return WIMLIB_ERR_NTFS_3G;
			}
		}
	}

	/* Attributes  */
	if (!(extract_flags & WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES)) {
		u32 attrib = inode->i_attributes;

		attrib &= ~(FILE_ATTRIBUTE_SPARSE_FILE |
			    FILE_ATTRIBUTE_ENCRYPTED);

		if (ntfs_set_ntfs_attrib(ni, (const char *)&attrib,
					 sizeof(attrib), 0))
		{
			ERROR_WITH_ERRNO("Failed to set attributes on \"%s\" "
					 "in NTFS volume",
					 dentry_full_path(one_dentry));
			return WIMLIB_ERR_SET_ATTRIBUTES;
		}
	}

	/* Security descriptor  */
	if (inode_has_security_descriptor(inode)
	    && !(extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS))
	{
		struct SECURITY_CONTEXT sec_ctx = { ctx->vol };
		const void *desc;
		size_t desc_size;

		desc = sd->descriptors[inode->i_security_id];
		desc_size = sd->sizes[inode->i_security_id];

		ret = ntfs_set_ntfs_acl(&sec_ctx, ni, desc, desc_size, 0);

		if (unlikely(ret)) {
			int err = errno;
			ERROR_WITH_ERRNO("Failed to set security descriptor on "
					 "\"%s\" in NTFS volume",
					 dentry_full_path(one_dentry));
			if (err == EINVAL && wimlib_print_errors) {
				fprintf(wimlib_error_file,
					"The security descriptor is: ");
				print_byte_field(desc, desc_size, wimlib_error_file);
				fprintf(wimlib_error_file,
					"\n\nThis error occurred because libntfs-3g thinks "
					"the security descriptor is invalid.  There "
					"are several known bugs with libntfs-3g's "
					"security descriptor validation logic in older "
					"versions.  Please upgrade to NTFS-3G version "
					"2016.2.22 or later if you haven't already.\n");
			}
			return WIMLIB_ERR_SET_SECURITY;
		}
	}

	/* Timestamps  */
	ret = ntfs_3g_set_timestamps(ni, inode);
	if (ret) {
		ERROR_WITH_ERRNO("Failed to set timestamps on \"%s\" "
				 "in NTFS volume",
				 dentry_full_path(one_dentry));
		return ret;
	}
	return 0;
}

/* Recursively creates all the subdirectories of @dir, which has been created as
 * the NTFS inode @dir_ni.  */
static int
ntfs_3g_create_dirs_recursive(ntfs_inode *dir_ni, struct wim_dentry *dir,
			      struct ntfs_3g_apply_ctx *ctx)
{
	struct wim_dentry *child;

	for_dentry_child(child, dir) {
		ntfs_inode *ni;
		int ret;

		if (!(child->d_inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY))
			continue;
		if (!will_extract_dentry(child))
			continue;

		ni = ntfs_create(dir_ni, 0, child->d_extraction_name,
				 child->d_extraction_name_nchars, S_IFDIR);
		if (!ni) {
			ERROR_WITH_ERRNO("Error creating \"%s\" in NTFS volume",
					 dentry_full_path(child));
			return WIMLIB_ERR_NTFS_3G;
		}

		child->d_inode->i_mft_no = ni->mft_no;

		ret = report_file_created(&ctx->common);
		if (!ret)
			ret = ntfs_3g_set_metadata(ni, child->d_inode, ctx);
		if (!ret)
			ret = ntfs_3g_create_dirs_recursive(ni, child, ctx);

		if (ntfs_inode_close_in_dir(ni, dir_ni) && !ret) {
			ERROR_WITH_ERRNO("Error closing \"%s\" in NTFS volume",
					 dentry_full_path(child));
			ret = WIMLIB_ERR_NTFS_3G;
		}
		if (ret)
			return ret;
	}
	return 0;
}

/* For each WIM dentry in the @root tree that represents a directory, create the
 * corresponding directory in the NTFS volume @ctx->vol.  */
static int
ntfs_3g_create_directories(struct wim_dentry *root,
			   struct list_head *dentry_list,
			   struct ntfs_3g_apply_ctx *ctx)
{
	ntfs_inode *root_ni;
	int ret;
	struct wim_dentry *dentry;

	/* Create the directories using POSIX names.  */

	root_ni = ntfs_inode_open(ctx->vol, FILE_root);
	if (!root_ni) {
		ERROR_WITH_ERRNO("Can't open root of NTFS volume");
		return WIMLIB_ERR_NTFS_3G;
	}

	root->d_inode->i_mft_no = FILE_root;

	ret = ntfs_3g_set_metadata(root_ni, root->d_inode, ctx);
	if (!ret)
		ret = ntfs_3g_create_dirs_recursive(root_ni, root, ctx);

	if (ntfs_inode_close(root_ni) && !ret) {
		ERROR_WITH_ERRNO("Error closing root of NTFS volume");
		ret = WIMLIB_ERR_NTFS_3G;
	}
	if (ret)
		return ret;

	/* Set the DOS name of any directory that has one.  In addition, create
	 * empty attributes for directories that have them.  Note that creating
	 * an empty reparse point attribute must happen *after* setting the DOS
	 * name in order to work around a case where ntfs_set_ntfs_dos_name()
	 * fails with EOPNOTSUPP.  This bug was fixed in NTFS-3G version
	 * 2016.2.22.  */
	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		const struct wim_inode *inode = dentry->d_inode;

		if (!(inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY))
			continue;
		if (dentry_has_short_name(dentry)) {
			ret = ntfs_3g_restore_dos_name(NULL, NULL, dentry,
						       ctx->vol);
			if (ret)
				return ret;
			ret = report_file_created(&ctx->common);
			if (ret)
				return ret;
		}
		if (ntfs_3g_has_empty_attributes(inode)) {
			ntfs_inode *ni;

			ret = WIMLIB_ERR_NTFS_3G;
			ni = ntfs_inode_open(ctx->vol, inode->i_mft_no);
			if (ni) {
				ret = ntfs_3g_create_empty_attributes(ni, inode,
								      ctx);
				if (ntfs_inode_close(ni) && !ret)
					ret = WIMLIB_ERR_NTFS_3G;
			}
			if (ret) {
				ERROR_WITH_ERRNO("Failed to create empty "
						 "attributes of directory "
						 "\"%s\" in NTFS volume",
						 dentry_full_path(dentry));
				return ret;
			}
		}
	}
	return 0;
}

/* When creating an inode that will have a short (DOS) name, we create it using
 * the long name associated with the short name.  This ensures that the short
 * name gets associated with the correct long name.  */
static struct wim_dentry *
ntfs_3g_first_extraction_alias(struct wim_inode *inode)
{
	struct wim_dentry *dentry;

	inode_for_each_extraction_alias(dentry, inode)
		if (dentry_has_short_name(dentry))
			return dentry;
	return inode_first_extraction_dentry(inode);
}

/*
 * Add a hard link for the NTFS inode @ni at the location corresponding to the
 * WIM dentry @dentry.
 *
 * The parent directory must have already been created on the NTFS volume.
 *
 * Returns 0 on success; returns WIMLIB_ERR_NTFS_3G and sets errno on failure.
 */
static int
ntfs_3g_add_link(ntfs_inode *ni, struct wim_dentry *dentry)
{
	ntfs_inode *dir_ni;
	int res;

	/* Open the inode of the parent directory.  */
	dir_ni = ntfs_inode_open(ni->vol, dentry->d_parent->d_inode->i_mft_no);
	if (!dir_ni)
		goto fail;

	/* Create the link.  */
	res = ntfs_link(ni, dir_ni, dentry->d_extraction_name,
			dentry->d_extraction_name_nchars);

	/* Close the parent directory.  */
	if (ntfs_inode_close(dir_ni) || res)
		goto fail;

	return 0;

fail:
	ERROR_WITH_ERRNO("Can't create link \"%s\" in NTFS volume",
			 dentry_full_path(dentry));
	return WIMLIB_ERR_NTFS_3G;
}

static int
ntfs_3g_create_nondirectory(struct wim_inode *inode,
			    struct ntfs_3g_apply_ctx *ctx)
{
	struct wim_dentry *first_dentry;
	ntfs_inode *dir_ni;
	ntfs_inode *ni;
	struct wim_dentry *dentry;
	int ret;

	first_dentry = ntfs_3g_first_extraction_alias(inode);

	/* Create first link.  */

	dir_ni = ntfs_inode_open(ctx->vol, first_dentry->d_parent->d_inode->i_mft_no);
	if (!dir_ni) {
		ERROR_WITH_ERRNO("Can't open \"%s\" in NTFS volume",
				 dentry_full_path(first_dentry->d_parent));
		return WIMLIB_ERR_NTFS_3G;
	}

	ni = ntfs_create(dir_ni, 0, first_dentry->d_extraction_name,
			 first_dentry->d_extraction_name_nchars, S_IFREG);

	if (!ni) {
		ERROR_WITH_ERRNO("Can't create \"%s\" in NTFS volume",
				 dentry_full_path(first_dentry));
		ntfs_inode_close(dir_ni);
		return WIMLIB_ERR_NTFS_3G;
	}

	inode->i_mft_no = ni->mft_no;

	/* Set short name if present.  */
	if (dentry_has_short_name(first_dentry)) {

		ret = ntfs_3g_restore_dos_name(ni, dir_ni, first_dentry, ctx->vol);

		/* ntfs_3g_restore_dos_name() closed both 'ni' and 'dir_ni'.  */

		if (ret)
			return ret;

		/* Reopen the inode.  */
		ni = ntfs_inode_open(ctx->vol, inode->i_mft_no);
		if (!ni) {
			ERROR_WITH_ERRNO("Failed to reopen \"%s\" "
					 "in NTFS volume",
					 dentry_full_path(first_dentry));
			return WIMLIB_ERR_NTFS_3G;
		}
	} else {
		/* Close the directory in which the first link was created.  */
		if (ntfs_inode_close(dir_ni)) {
			ERROR_WITH_ERRNO("Failed to close \"%s\" in NTFS volume",
					 dentry_full_path(first_dentry->d_parent));
			ret = WIMLIB_ERR_NTFS_3G;
			goto out_close_ni;
		}
	}

	/* Create additional links if present.  */
	inode_for_each_extraction_alias(dentry, inode) {
		if (dentry != first_dentry) {
			ret = ntfs_3g_add_link(ni, dentry);
			if (ret)
				goto out_close_ni;
		}
	}

	/* Set metadata.  */
	ret = ntfs_3g_set_metadata(ni, inode, ctx);
	if (ret)
		goto out_close_ni;

	ret = ntfs_3g_create_empty_attributes(ni, inode, ctx);

out_close_ni:
	/* Close the inode.  */
	if (ntfs_inode_close(ni) && !ret) {
		ERROR_WITH_ERRNO("Error closing \"%s\" in NTFS volume",
				 dentry_full_path(first_dentry));
		ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}

/* For each WIM dentry in the @dentry_list that represents a nondirectory file,
 * create the corresponding nondirectory file in the NTFS volume.
 *
 * Directories must have already been created.  */
static int
ntfs_3g_create_nondirectories(struct list_head *dentry_list,
			      struct ntfs_3g_apply_ctx *ctx)
{
	struct wim_dentry *dentry;
	struct wim_inode *inode;
	int ret;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		inode = dentry->d_inode;
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;
		if (dentry == inode_first_extraction_dentry(inode)) {
			ret = ntfs_3g_create_nondirectory(inode, ctx);
			if (ret)
				return ret;
		}
		ret = report_file_created(&ctx->common);
		if (ret)
			return ret;
	}
	return 0;
}

static int
ntfs_3g_begin_extract_blob_instance(struct blob_descriptor *blob,
				    ntfs_inode *ni,
				    struct wim_inode *inode,
				    const struct wim_inode_stream *strm,
				    struct ntfs_3g_apply_ctx *ctx)
{
	struct wim_dentry *one_dentry = inode_first_extraction_dentry(inode);
	ntfschar *stream_name;
	size_t stream_name_nchars;
	ntfs_attr *attr;

	if (unlikely(strm->stream_type == STREAM_TYPE_REPARSE_POINT)) {

		if (blob->size > REPARSE_DATA_MAX_SIZE) {
			ERROR("Reparse data of \"%s\" has size "
			      "%"PRIu64" bytes (exceeds %u bytes)",
			      dentry_full_path(one_dentry),
			      blob->size, REPARSE_DATA_MAX_SIZE);
			return WIMLIB_ERR_INVALID_REPARSE_DATA;
		}
		ctx->reparse_ptr = ctx->rpbuf.rpdata;
		ctx->ntfs_reparse_inodes[ctx->num_reparse_inodes] = ni;
		ctx->wim_reparse_inodes[ctx->num_reparse_inodes] = inode;
		ctx->num_reparse_inodes++;
		return 0;
	}

	/* It's a data stream (may be unnamed or named).  */
	wimlib_assert(strm->stream_type == STREAM_TYPE_DATA);

	if (unlikely(stream_is_named(strm))) {
		stream_name = strm->stream_name;
		stream_name_nchars = utf16le_len_chars(stream_name);

		if (ntfs_attr_add(ni, AT_DATA, stream_name,
				  stream_name_nchars, NULL, 0))
		{
			ERROR_WITH_ERRNO("Failed to create named data stream of \"%s\"",
					 dentry_full_path(one_dentry));
			return WIMLIB_ERR_NTFS_3G;
		}
	} else {
		/* Don't pass an empty string other than AT_UNNAMED to
		 * ntfs_attr_open() --- it violates assumptions made by
		 * libntfs-3g.  */
		stream_name = AT_UNNAMED;
		stream_name_nchars = 0;
	}

	/* This should be ensured by extract_blob_list()  */
	wimlib_assert(ctx->num_open_attrs < MAX_OPEN_FILES);

	attr = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_nchars);
	if (!attr) {
		ERROR_WITH_ERRNO("Failed to open data stream of \"%s\"",
				 dentry_full_path(one_dentry));
		return WIMLIB_ERR_NTFS_3G;
	}
	ctx->open_attrs[ctx->num_open_attrs++] = attr;
	ntfs_attr_truncate_solid(attr, blob->size);
	return 0;
}

static int
ntfs_3g_cleanup_blob_extract(struct ntfs_3g_apply_ctx *ctx)
{
	int ret = 0;

	for (unsigned i = 0; i < ctx->num_open_attrs; i++) {
		if (ntfs_attr_pclose(ctx->open_attrs[i]))
			ret = -1;
		ntfs_attr_close(ctx->open_attrs[i]);
	}

	ctx->num_open_attrs = 0;

	for (unsigned i = 0; i < ctx->num_open_inodes; i++) {
		if (ntfs_inode_close(ctx->open_inodes[i]))
			ret = -1;
	}
	ctx->num_open_inodes = 0;

	ctx->offset = 0;
	ctx->reparse_ptr = NULL;
	ctx->num_reparse_inodes = 0;
	return ret;
}

static ntfs_inode *
ntfs_3g_open_inode(struct wim_inode *inode, struct ntfs_3g_apply_ctx *ctx)
{
	ntfs_inode *ni;

	/* If the same blob is being extracted to multiple streams of the same
	 * inode, then we must only open the inode once.  */
	if (unlikely(inode->i_num_streams > 1)) {
		for (unsigned i = 0; i < ctx->num_open_inodes; i++) {
			if (ctx->open_inodes[i]->mft_no == inode->i_mft_no) {
				return ctx->open_inodes[i];
			}
		}
	}

	ni = ntfs_inode_open(ctx->vol, inode->i_mft_no);
	if (unlikely(!ni)) {
		ERROR_WITH_ERRNO("Can't open \"%s\" in NTFS volume",
				 dentry_full_path(
					inode_first_extraction_dentry(inode)));
		return NULL;
	}

	ctx->open_inodes[ctx->num_open_inodes++] = ni;
	return ni;
}

static int
ntfs_3g_begin_extract_blob(struct blob_descriptor *blob, void *_ctx)
{
	struct ntfs_3g_apply_ctx *ctx = _ctx;
	const struct blob_extraction_target *targets = blob_extraction_targets(blob);
	int ret;
	ntfs_inode *ni;

	for (u32 i = 0; i < blob->out_refcnt; i++) {
		ret = WIMLIB_ERR_NTFS_3G;
		ni = ntfs_3g_open_inode(targets[i].inode, ctx);
		if (!ni)
			goto out_cleanup;

		ret = ntfs_3g_begin_extract_blob_instance(blob, ni,
							  targets[i].inode,
							  targets[i].stream, ctx);
		if (ret)
			goto out_cleanup;
	}
	ret = 0;
	goto out;

out_cleanup:
	ntfs_3g_cleanup_blob_extract(ctx);
out:
	return ret;
}

/* Note: contrary to its documentation, ntfs_attr_pwrite() can return a short
 * count in non-error cases --- specifically, when writing to a compressed
 * attribute and the requested count exceeds the size of an NTFS "compression
 * block".  Therefore, we must continue calling ntfs_attr_pwrite() until all
 * bytes have been written or a real error has occurred.  */
static bool
ntfs_3g_full_pwrite(ntfs_attr *na, u64 offset, size_t size, const u8 *data)
{
	while (size) {
		s64 res = ntfs_attr_pwrite(na, offset, size, data);
		if (unlikely(res <= 0))
			return false;
		wimlib_assert(res <= size);
		offset += res;
		size -= res;
		data += res;
	}
	return true;
}

static int
ntfs_3g_extract_chunk(const void *chunk, size_t size, void *_ctx)
{
	struct ntfs_3g_apply_ctx *ctx = _ctx;

	for (unsigned i = 0; i < ctx->num_open_attrs; i++) {
		if (!ntfs_3g_full_pwrite(ctx->open_attrs[i],
					 ctx->offset, size, chunk))
		{
			ERROR_WITH_ERRNO("Error writing data to NTFS volume");
			return WIMLIB_ERR_NTFS_3G;
		}
	}
	if (ctx->reparse_ptr)
		ctx->reparse_ptr = mempcpy(ctx->reparse_ptr, chunk, size);
	ctx->offset += size;
	return 0;
}

static int
ntfs_3g_end_extract_blob(struct blob_descriptor *blob, int status, void *_ctx)
{
	struct ntfs_3g_apply_ctx *ctx = _ctx;
	int ret;

	if (status) {
		ret = status;
		goto out;
	}

	for (u32 i = 0; i < ctx->num_reparse_inodes; i++) {
		ret = ntfs_3g_restore_reparse_point(ctx->ntfs_reparse_inodes[i],
						    ctx->wim_reparse_inodes[i],
						    blob->size, ctx);
		if (ret)
			goto out;
	}
	ret = 0;
out:
	if (ntfs_3g_cleanup_blob_extract(ctx) && !ret) {
		ERROR_WITH_ERRNO("Error writing data to NTFS volume");
		ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}

static u64
ntfs_3g_count_dentries(const struct list_head *dentry_list)
{
	const struct wim_dentry *dentry;
	u64 count = 0;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		count++;
		if ((dentry->d_inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) &&
		    dentry_has_short_name(dentry))
		{
			count++;
		}
	}

	return count;
}

static int
ntfs_3g_extract(struct list_head *dentry_list, struct apply_ctx *_ctx)
{
	struct ntfs_3g_apply_ctx *ctx = (struct ntfs_3g_apply_ctx *)_ctx;
	ntfs_volume *vol;
	struct wim_dentry *root;
	int ret;

	/* For NTFS-3G extraction mode we require that the dentries to extract
	 * form a single tree.  */
	root = list_first_entry(dentry_list, struct wim_dentry,
				d_extraction_list_node);

	/* Mount the NTFS volume.  */
	vol = ntfs_mount(ctx->common.target, 0);
	if (!vol) {
		ERROR_WITH_ERRNO("Failed to mount \"%s\" with NTFS-3G",
				 ctx->common.target);
		return WIMLIB_ERR_NTFS_3G;
	}
	ctx->vol = vol;

	/* Create all inodes and aliases, including short names, and set
	 * metadata (attributes, security descriptors, and timestamps).  */

	ret = start_file_structure_phase(&ctx->common,
					 ntfs_3g_count_dentries(dentry_list));
	if (ret)
		goto out_unmount;

	ret = ntfs_3g_create_directories(root, dentry_list, ctx);
	if (ret)
		goto out_unmount;

	ret = ntfs_3g_create_nondirectories(dentry_list, ctx);
	if (ret)
		goto out_unmount;

	ret = end_file_structure_phase(&ctx->common);
	if (ret)
		goto out_unmount;

	/* Extract blobs.  */
	struct read_blob_callbacks cbs = {
		.begin_blob	= ntfs_3g_begin_extract_blob,
		.consume_chunk	= ntfs_3g_extract_chunk,
		.end_blob	= ntfs_3g_end_extract_blob,
		.ctx		= ctx,
	};
	ret = extract_blob_list(&ctx->common, &cbs);

	/* We do not need a final pass to set timestamps because libntfs-3g does
	 * not update timestamps automatically (exception:
	 * ntfs_set_ntfs_dos_name() does, but we handle this elsewhere).  */

out_unmount:
	if (ntfs_umount(ctx->vol, FALSE) && !ret) {
		ERROR_WITH_ERRNO("Failed to unmount \"%s\" with NTFS-3G",
				 ctx->common.target);
		ret = WIMLIB_ERR_NTFS_3G;
	}
	return ret;
}

const struct apply_operations ntfs_3g_apply_ops = {
	.name			= "NTFS-3G",
	.get_supported_features = ntfs_3g_get_supported_features,
	.extract                = ntfs_3g_extract,
	.context_size           = sizeof(struct ntfs_3g_apply_ctx),
	.single_tree_only	= true,
};
