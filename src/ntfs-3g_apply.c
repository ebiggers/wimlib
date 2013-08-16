/*
 * ntfs-3g_apply.c
 *
 * Apply a WIM image directly to a NTFS volume using libntfs-3g.  Restore as
 * much information as possible, including security data, file attributes, DOS
 * names, and alternate data streams.
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

#ifdef WITH_NTFS_3G

#include <locale.h>
#include <string.h>
#include <time.h> /* NTFS-3g headers are missing <time.h> include */

#include <ntfs-3g/attrib.h>
#include <ntfs-3g/reparse.h>
#include <ntfs-3g/security.h>
#include <errno.h>

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#else
#  include <stdlib.h>
#endif

#include "wimlib/apply.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/ntfs_3g.h"
#include "wimlib/paths.h"
#include "wimlib/resource.h"

static ntfs_volume *
ntfs_3g_apply_ctx_get_volume(struct apply_ctx *ctx)
{
	return (ntfs_volume*)ctx->private[0];
}

static void
ntfs_3g_apply_ctx_set_volume(struct apply_ctx *ctx, ntfs_volume *vol)
{
	ctx->private[0] = (intptr_t)vol;
}

static ntfs_inode *
ntfs_3g_apply_pathname_to_inode(const char *path, struct apply_ctx *ctx)
{
	ntfs_volume *vol = ntfs_3g_apply_ctx_get_volume(ctx);
	return ntfs_pathname_to_inode(vol, NULL, path);
}

struct ntfs_attr_extract_ctx {
	u64 offset;
	ntfs_attr *na;
};

static int
ntfs_3g_extract_wim_chunk(const void *buf, size_t len, void *_ctx)
{
	struct ntfs_attr_extract_ctx *ctx = _ctx;

	if (ntfs_attr_pwrite(ctx->na, ctx->offset, len, buf) != len)
		return WIMLIB_ERR_WRITE;
	ctx->offset += len;
	return 0;
}

static ntfs_inode *
ntfs_3g_open_parent_inode(const char *path, ntfs_volume *vol)
{
	char *p;
	ntfs_inode *dir_ni;

	p = strrchr(path, '/');
	*p = '\0';
	dir_ni = ntfs_pathname_to_inode(vol, NULL, path);
	*p = '/';
	return dir_ni;
}

static int
ntfs_3g_create(const char *path, struct apply_ctx *ctx, mode_t mode)
{
	ntfs_volume *vol;
	ntfs_inode *dir_ni, *ni;
	const char *name;
	utf16lechar *name_utf16le;
	size_t name_utf16le_nbytes;
	int ret;

	vol = ntfs_3g_apply_ctx_get_volume(ctx);

	ret = WIMLIB_ERR_NTFS_3G;
	dir_ni = ntfs_3g_open_parent_inode(path, vol);
	if (!dir_ni)
		goto out;

	name = path_basename(path);
	ret = tstr_to_utf16le(name, strlen(name),
			      &name_utf16le, &name_utf16le_nbytes);
	if (ret)
		goto out_close_dir_ni;

	ret = 0;
	ni = ntfs_create(dir_ni, 0, name_utf16le,
			 name_utf16le_nbytes / 2, mode);
	if (!ni || ntfs_inode_close_in_dir(ni, dir_ni))
		ret = WIMLIB_ERR_NTFS_3G;
	FREE(name_utf16le);
out_close_dir_ni:
	if (ntfs_inode_close(dir_ni))
		ret = WIMLIB_ERR_NTFS_3G;
out:
	return ret;
}

static int
ntfs_3g_create_file(const char *path, struct apply_ctx *ctx)
{
	return ntfs_3g_create(path, ctx, S_IFREG);
}

static int
ntfs_3g_create_directory(const char *path, struct apply_ctx *ctx)
{
	return ntfs_3g_create(path, ctx, S_IFDIR);
}

static int
ntfs_3g_create_hardlink(const char *oldpath, const char *newpath,
			struct apply_ctx *ctx)
{
	ntfs_volume *vol;
	ntfs_inode *dir_ni, *ni;
	const char *name;
	utf16lechar *name_utf16le;
	size_t name_utf16le_nbytes;
	int ret;

	vol = ntfs_3g_apply_ctx_get_volume(ctx);

	ret = WIMLIB_ERR_NTFS_3G;
	ni = ntfs_pathname_to_inode(vol, NULL, oldpath);
	if (!ni)
		goto out;

	ret = WIMLIB_ERR_NTFS_3G;
	dir_ni = ntfs_3g_open_parent_inode(newpath, vol);
	if (!dir_ni)
		goto out_close_ni;

	name = path_basename(newpath);
	ret = tstr_to_utf16le(name, strlen(name),
			      &name_utf16le, &name_utf16le_nbytes);
	if (ret)
		goto out_close_dir_ni;
	ret = 0;
	if (ntfs_link(ni, dir_ni, name_utf16le, name_utf16le_nbytes / 2))
		ret = WIMLIB_ERR_NTFS_3G;
	FREE(name_utf16le);
out_close_dir_ni:
	if (ntfs_inode_close(dir_ni))
		ret = WIMLIB_ERR_NTFS_3G;
out_close_ni:
	if (ntfs_inode_close(ni))
		ret = WIMLIB_ERR_NTFS_3G;
out:
	return ret;
}

/*
 * Extract a stream (default or alternate data) to an attribute of a NTFS file.
 */
static int
ntfs_3g_extract_stream(const char *path, const utf16lechar *raw_stream_name,
		       size_t stream_name_nchars,
		       struct wim_lookup_table_entry *lte, struct apply_ctx *ctx)
{
	ntfs_inode *ni;
	ntfs_attr *na;
	int ret;
	struct ntfs_attr_extract_ctx extract_ctx;
	utf16lechar *stream_name;

	if (stream_name_nchars == 0) {
		stream_name = AT_UNNAMED;
	} else {
		stream_name = alloca((stream_name_nchars + 1) * sizeof(utf16lechar));
		memcpy(stream_name, raw_stream_name,
		       stream_name_nchars * sizeof(utf16lechar));
		stream_name[stream_name_nchars] = 0;
	}

	ret = 0;
	if (!stream_name_nchars && !lte)
		goto out;

	/* Look up NTFS inode to which to extract the stream.  */
	ret = WIMLIB_ERR_NTFS_3G;
	ni = ntfs_3g_apply_pathname_to_inode(path, ctx);
	if (!ni)
		goto out;

	/* Add the stream if it's not the default (unnamed) stream.  */
	ret = WIMLIB_ERR_NTFS_3G;
	if (stream_name_nchars)
		if (ntfs_attr_add(ni, AT_DATA, stream_name,
				  stream_name_nchars, NULL, 0))
			goto out_close;

	/* If stream is empty, no need to open and extract it.  */
	ret = 0;
	if (!lte)
		goto out_close;

	/* Open the stream (NTFS attribute).  */
	ret = WIMLIB_ERR_NTFS_3G;
	na = ntfs_attr_open(ni, AT_DATA, stream_name, stream_name_nchars);
	if (!na)
		goto out_close;

	/* (Optional) Immediately resize attribute to size of stream.  */
	ret = WIMLIB_ERR_NTFS_3G;
	if (ntfs_attr_truncate_solid(na, wim_resource_size(lte)))
		goto out_attr_close;

	/* Extract stream data to the NTFS attribute.  */
	extract_ctx.na = na;
	extract_ctx.offset = 0;
	ret = extract_wim_resource(lte, wim_resource_size(lte),
				   ntfs_3g_extract_wim_chunk, &extract_ctx);
	/* Clean up and return.  */
out_attr_close:
	ntfs_attr_close(na);
out_close:
	if (ntfs_inode_close(ni))
		ret = WIMLIB_ERR_NTFS_3G;
out:
	if (ret && !errno)
		errno = -1;
	return ret;
}

static int
ntfs_3g_extract_unnamed_stream(const char *path,
			       struct wim_lookup_table_entry *lte,
			       struct apply_ctx *ctx)
{
	return ntfs_3g_extract_stream(path, NULL, 0, lte, ctx);
}

static int
ntfs_3g_extract_named_stream(const char *path, const utf16lechar *stream_name,
			     size_t stream_name_nchars,
			     struct wim_lookup_table_entry *lte, struct apply_ctx *ctx)
{
	return ntfs_3g_extract_stream(path, stream_name,
				      stream_name_nchars, lte, ctx);
}

static int
ntfs_3g_set_file_attributes(const char *path, u32 attributes,
			    struct apply_ctx *ctx)
{
	ntfs_inode *ni;
	int ret = 0;

	ni = ntfs_3g_apply_pathname_to_inode(path, ctx);
	if (!ni)
		return WIMLIB_ERR_NTFS_3G;
	if (ntfs_set_ntfs_attrib(ni, (const char*)&attributes, sizeof(u32), 0))
		ret = WIMLIB_ERR_NTFS_3G;
	if (ntfs_inode_close(ni))
		ret = WIMLIB_ERR_NTFS_3G;
	return ret;
}

static int
ntfs_3g_set_reparse_data(const char *path, const u8 *rpbuf, u16 rpbuflen,
			 struct apply_ctx *ctx)
{
	ntfs_inode *ni;
	int ret = 0;

	ni = ntfs_3g_apply_pathname_to_inode(path, ctx);
	if (!ni)
		return WIMLIB_ERR_NTFS_3G;
	if (ntfs_set_ntfs_reparse_data(ni, rpbuf, rpbuflen, 0))
		ret = WIMLIB_ERR_NTFS_3G;
	if (ntfs_inode_close(ni))
		ret = WIMLIB_ERR_NTFS_3G;
	return ret;
}

static int
ntfs_3g_set_short_name(const char *path, const utf16lechar *short_name,
		       size_t short_name_nchars, struct apply_ctx *ctx)
{
	ntfs_inode *ni, *dir_ni;
	ntfs_volume *vol;
	int ret;
	char *dosname = NULL;
	size_t dosname_nbytes;

	ret = 0;
	if (short_name_nchars == 0)
		goto out;

	vol = ntfs_3g_apply_ctx_get_volume(ctx);

	ret = WIMLIB_ERR_NTFS_3G;
	dir_ni = ntfs_3g_open_parent_inode(path, vol);
	if (!dir_ni)
		goto out;

	ret = WIMLIB_ERR_NTFS_3G;
	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		goto out_close_dir_ni;

	ret = utf16le_to_tstr(short_name, short_name_nchars * 2,
			      &dosname, &dosname_nbytes);
	if (ret)
		goto out_close_ni;

	ret = 0;
	if (ntfs_set_ntfs_dos_name(ni, dir_ni, dosname,
				   dosname_nbytes, 0))
		ret = WIMLIB_ERR_NTFS_3G;
	/* ntfs_set_ntfs_dos_name() always closes the inodes.  */
	FREE(dosname);
	goto out;
out_close_ni:
	if (ntfs_inode_close_in_dir(ni, dir_ni))
		ret = WIMLIB_ERR_NTFS_3G;
out_close_dir_ni:
	if (ntfs_inode_close(dir_ni))
		ret = WIMLIB_ERR_NTFS_3G;
out:
	return ret;
}

static int
ntfs_3g_set_security_descriptor(const char *path, const u8 *desc, size_t desc_size,
				struct apply_ctx *ctx)
{
	ntfs_volume *vol;
	ntfs_inode *ni;
	struct SECURITY_CONTEXT sec_ctx;
	int ret = 0;

	vol = ntfs_3g_apply_ctx_get_volume(ctx);

	ni = ntfs_pathname_to_inode(vol, NULL, path);
	if (!ni)
		return WIMLIB_ERR_NTFS_3G;

	memset(&sec_ctx, 0, sizeof(sec_ctx));
	sec_ctx.vol = vol;

	if (ntfs_set_ntfs_acl(&sec_ctx, ni, desc, desc_size, 0))
		ret = WIMLIB_ERR_NTFS_3G;
	if (ntfs_inode_close(ni))
		ret = WIMLIB_ERR_NTFS_3G;
	return ret;
}

static int
ntfs_3g_set_timestamps(const char *path, u64 creation_time,
		       u64 last_write_time, u64 last_access_time,
		       struct apply_ctx *ctx)
{
	u64 ntfs_timestamps[3];
	ntfs_inode *ni;
	int ret = 0;

	ni = ntfs_3g_apply_pathname_to_inode(path, ctx);
	if (!ni)
		return WIMLIB_ERR_NTFS_3G;

	/* Note: ntfs_inode_set_times() expects the times in native byte order,
	 * not little endian. */
	ntfs_timestamps[0] = creation_time;
	ntfs_timestamps[1] = last_write_time;
	ntfs_timestamps[2] = last_access_time;

	if (ntfs_inode_set_times(ni, (const char*)ntfs_timestamps,
				 sizeof(ntfs_timestamps), 0))
		ret = WIMLIB_ERR_NTFS_3G;
	if (ntfs_inode_close(ni))
		ret = WIMLIB_ERR_NTFS_3G;
	return ret;
}

static bool
ntfs_3g_target_is_root(const char *target)
{
	/* We always extract to the root of the NTFS volume.  */
	return true;
}

static int
ntfs_3g_start_extract(const char *path, struct apply_ctx *ctx)
{
	ntfs_volume *vol;

	vol = ntfs_mount(ctx->target, 0);
	if (!vol) {
		ERROR_WITH_ERRNO("Failed to mount \"%"TS"\" with NTFS-3g", ctx->target);
		return WIMLIB_ERR_NTFS_3G;
	}
	ntfs_3g_apply_ctx_set_volume(ctx, vol);

	ctx->supported_features.archive_files             = 1;
	ctx->supported_features.hidden_files              = 1;
	ctx->supported_features.system_files              = 1;
	ctx->supported_features.compressed_files          = 1;
	ctx->supported_features.encrypted_files           = 0;
	ctx->supported_features.not_context_indexed_files = 1;
	ctx->supported_features.sparse_files              = 1;
	ctx->supported_features.named_data_streams        = 1;
	ctx->supported_features.hard_links                = 1;
	ctx->supported_features.reparse_points            = 1;
	ctx->supported_features.security_descriptors      = 1;
	ctx->supported_features.short_names               = 1;
	return 0;
}

static int
ntfs_3g_finish_or_abort_extract(struct apply_ctx *ctx)
{
	ntfs_volume *vol;

	vol = ntfs_3g_apply_ctx_get_volume(ctx);
	if (ntfs_umount(vol, FALSE)) {
		ERROR_WITH_ERRNO("Failed to unmount \"%"TS"\" with NTFS-3g",
				 ctx->target);
		return WIMLIB_ERR_NTFS_3G;
	}
	return 0;
}

void
libntfs3g_global_init(void)
{
	ntfs_set_char_encoding(setlocale(LC_ALL, ""));
}

const struct apply_operations ntfs_3g_apply_ops = {
	.name = "NTFS-3g",

	.target_is_root          = ntfs_3g_target_is_root,
	.start_extract           = ntfs_3g_start_extract,
	.create_file             = ntfs_3g_create_file,
	.create_directory        = ntfs_3g_create_directory,
	.create_hardlink         = ntfs_3g_create_hardlink,
	.extract_unnamed_stream  = ntfs_3g_extract_unnamed_stream,
	.extract_named_stream    = ntfs_3g_extract_named_stream,
	.set_file_attributes     = ntfs_3g_set_file_attributes,
	.set_reparse_data        = ntfs_3g_set_reparse_data,
	.set_short_name          = ntfs_3g_set_short_name,
	.set_security_descriptor = ntfs_3g_set_security_descriptor,
	.set_timestamps          = ntfs_3g_set_timestamps,
	.abort_extract           = ntfs_3g_finish_or_abort_extract,
	.finish_extract          = ntfs_3g_finish_or_abort_extract,

	.path_prefix = "/",
	.path_prefix_nchars = 1,
	.path_separator = '/',
	.path_max = 32768,

	.supports_case_sensitive_filenames = 1,
	.root_directory_is_special = 1,
};

#endif /* WITH_NTFS_3G */
