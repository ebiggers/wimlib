/*
 * extract.c
 *
 * Support for extracting WIM images, or files or directories contained in a WIM
 * image.
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

/*
 * This file provides the API functions wimlib_extract_image(),
 * wimlib_extract_files(), and wimlib_extract_image_from_pipe().  Internally,
 * all end up calling extract_tree() zero or more times to extract a tree of
 * files from the currently selected WIM image to the specified target directory
 * or NTFS volume.
 *
 * Although wimlib supports multiple extraction modes/backends (NTFS-3g, UNIX,
 * Win32), this file does not itself have code to extract files or directories
 * to any specific target; instead, it handles generic functionality and relies
 * on lower-level callback functions declared in `struct apply_operations' to do
 * the actual extraction.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/apply.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/reparse.h"
#include "wimlib/resource.h"
#include "wimlib/security.h"
#ifdef __WIN32__
#  include "wimlib/win32.h" /* for realpath() equivalent */
#endif
#include "wimlib/xml.h"
#include "wimlib/wim.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define WIMLIB_EXTRACT_FLAG_MULTI_IMAGE 0x80000000
#define WIMLIB_EXTRACT_FLAG_FROM_PIPE   0x40000000
#define WIMLIB_EXTRACT_MASK_PUBLIC      0x3fffffff

/* Given a WIM dentry in the tree to be extracted, resolve all streams in the
 * corresponding inode and set 'out_refcnt' in each to 0.  */
static int
dentry_resolve_and_zero_lte_refcnt(struct wim_dentry *dentry, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;
	struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;
	int ret;
	bool force = false;

	if (dentry->extraction_skipped)
		return 0;

	/* Special case:  when extracting from a pipe, the WIM lookup table is
	 * initially empty, so "resolving" an inode's streams is initially not
	 * possible.  However, we still need to keep track of which streams,
	 * identified by SHA1 message digests, need to be extracted, so we
	 * "resolve" the inode's streams anyway by allocating new entries.  */
	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_FROM_PIPE)
		force = true;
	ret = inode_resolve_ltes(inode, ctx->wim->lookup_table, force);
	if (ret)
		return ret;
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		lte = inode_stream_lte_resolved(inode, i);
		if (lte)
			lte->out_refcnt = 0;
	}
	return 0;
}

static inline bool
is_linked_extraction(const struct apply_ctx *ctx)
{
	return 0 != (ctx->extract_flags & (WIMLIB_EXTRACT_FLAG_HARDLINK |
					   WIMLIB_EXTRACT_FLAG_SYMLINK));
}

static inline bool
can_extract_named_data_streams(const struct apply_ctx *ctx)
{
	return ctx->supported_features.named_data_streams &&
		!is_linked_extraction(ctx);
}

static int
ref_stream_to_extract(struct wim_lookup_table_entry *lte,
		      struct wim_dentry *dentry, struct apply_ctx *ctx)
{
	if (!lte)
		return 0;

	/* Tally the size only for each extraction of the stream (not hard
	 * links).  */
	if (!(dentry->d_inode->i_visited &&
	      ctx->supported_features.hard_links) &&
	    (!is_linked_extraction(ctx) || (lte->out_refcnt == 0 &&
					    lte->extracted_file == NULL)))
	{
		ctx->progress.extract.total_bytes += lte->size;
		ctx->progress.extract.num_streams++;
	}

	/* Add stream to the extraction_list only one time, even if it's going
	 * to be extracted to multiple locations.  */
	if (lte->out_refcnt == 0) {
		list_add_tail(&lte->extraction_list, &ctx->stream_list);
		ctx->num_streams_remaining++;
	}

	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL) {
		struct wim_dentry **lte_dentries;

		/* Append dentry to this stream's array of dentries referencing
		 * it.  Use inline array to avoid memory allocation until the
		 * number of dentries becomes too large.  */
		if (lte->out_refcnt < ARRAY_LEN(lte->inline_lte_dentries)) {
			lte_dentries = lte->inline_lte_dentries;
		} else {
			struct wim_dentry **prev_lte_dentries;
			size_t alloc_lte_dentries;

			if (lte->out_refcnt == ARRAY_LEN(lte->inline_lte_dentries)) {
				prev_lte_dentries = NULL;
				alloc_lte_dentries = ARRAY_LEN(lte->inline_lte_dentries);
			} else {
				prev_lte_dentries = lte->lte_dentries;
				alloc_lte_dentries = lte->alloc_lte_dentries;
			}

			if (lte->out_refcnt == alloc_lte_dentries) {
				alloc_lte_dentries *= 2;
				lte_dentries = REALLOC(prev_lte_dentries,
						       alloc_lte_dentries *
							sizeof(lte_dentries[0]));
				if (lte_dentries == NULL)
					return WIMLIB_ERR_NOMEM;
				if (prev_lte_dentries == NULL) {
					memcpy(lte_dentries,
					       lte->inline_lte_dentries,
					       sizeof(lte->inline_lte_dentries));
				}
				lte->lte_dentries = lte_dentries;
				lte->alloc_lte_dentries = alloc_lte_dentries;
			}
			lte_dentries = lte->lte_dentries;
		}
		lte_dentries[lte->out_refcnt] = dentry;
	}
	lte->out_refcnt++;
	return 0;
}

/* Given a WIM dentry in the tree to be extracted, iterate through streams that
 * need to be extracted.  For each one, add it to the list of streams to be
 * extracted (ctx->stream_list) if not already done so, and also update the
 * progress information (ctx->progress) with the stream.  Furthermore, if doing
 * a sequential extraction, build a mapping from each the stream to the dentries
 * referencing it.
 *
 * This uses the i_visited member of the inodes (assumed to be 0 initially).  */
static int
dentry_add_streams_to_extract(struct wim_dentry *dentry, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;
	struct wim_inode *inode = dentry->d_inode;
	int ret;

	/* Don't process dentries marked as skipped.  */
	if (dentry->extraction_skipped)
		return 0;

	/* The unnamed data stream will always be extracted, except in an
	 * unlikely case.  */
	if (!inode_is_encrypted_directory(inode)) {
		ret = ref_stream_to_extract(inode_unnamed_lte_resolved(inode),
					    dentry, ctx);
		if (ret)
			return ret;
	}

	/* Named data streams will be extracted only if supported in the current
	 * extraction mode and volume, and to avoid complications, if not doing
	 * a linked extraction.  */
	if (can_extract_named_data_streams(ctx)) {
		for (u16 i = 0; i < inode->i_num_ads; i++) {
			if (!ads_entry_is_named_stream(&inode->i_ads_entries[i]))
				continue;
			ret = ref_stream_to_extract(inode->i_ads_entries[i].lte,
						    dentry, ctx);
			if (ret)
				return ret;
		}
	}
	inode->i_visited = 1;
	return 0;
}

/* Inform library user of progress of stream extraction following the successful
 * extraction of a copy of the stream specified by @lte.  */
static void
update_extract_progress(struct apply_ctx *ctx,
			const struct wim_lookup_table_entry *lte)
{
	wimlib_progress_func_t progress_func = ctx->progress_func;
	union wimlib_progress_info *progress = &ctx->progress;

	progress->extract.completed_bytes += lte->size;
	if (progress_func &&
	    progress->extract.completed_bytes >= ctx->next_progress)
	{
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS, progress);
		if (progress->extract.completed_bytes >=
		    progress->extract.total_bytes)
		{
			ctx->next_progress = ~0ULL;
		} else {
			ctx->next_progress += progress->extract.total_bytes / 128;
			if (ctx->next_progress > progress->extract.total_bytes)
				ctx->next_progress = progress->extract.total_bytes;
		}
	}
}

#ifndef __WIN32__
/* Extract a symbolic link (not directly as reparse data), handling fixing up
 * the target of absolute symbolic links and updating the extract progress.
 *
 * @inode must specify the WIM inode for a symbolic link or junction reparse
 * point.
 *
 * @lte_override overrides the resource used as the reparse data for the
 * symbolic link.  */
static int
extract_symlink(const tchar *path, struct apply_ctx *ctx,
		struct wim_inode *inode,
		struct wim_lookup_table_entry *lte_override)
{
	ssize_t bufsize = ctx->ops->path_max;
	tchar target[bufsize];
	tchar *buf = target;
	tchar *fixed_target;
	ssize_t sret;
	int ret;

	/* If absolute symbolic link fixups requested, reserve space in the link
	 * target buffer for the absolute path of the target directory.  */
	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX)
	{
		buf += ctx->realtarget_nchars;
		bufsize -= ctx->realtarget_nchars;
	}

	/* Translate the WIM inode's reparse data into the link target.  */
	sret = wim_inode_readlink(inode, buf, bufsize - 1, lte_override);
	if (sret < 0) {
		errno = -sret;
		return WIMLIB_ERR_READLINK;
	}
	buf[sret] = '\0';

	if ((ctx->extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX) &&
	    buf[0] == '/')
	{
		/* Fix absolute symbolic link target to point into the
		 * actual extraction destination.  */
		tmemcpy(target, ctx->realtarget, ctx->realtarget_nchars);
		fixed_target = target;
	} else {
		/* Keep same link target.  */
		fixed_target = buf;
	}

	/* Call into the apply_operations to create the symbolic link.  */
	DEBUG("Creating symlink \"%"TS"\" => \"%"TS"\"",
	      path, fixed_target);
	ret = ctx->ops->create_symlink(fixed_target, path, ctx);
	if (ret) {
		ERROR_WITH_ERRNO("Failed to create symlink "
				 "\"%"TS"\" => \"%"TS"\"", path, fixed_target);
		return ret;
	}

	/* Account for reparse data consumed.  */
	update_extract_progress(ctx,
				(lte_override ? lte_override :
				      inode_unnamed_lte_resolved(inode)));
	return 0;
}
#endif /* !__WIN32__ */

/* Create a file, directory, or symbolic link.  */
static int
extract_inode(const tchar *path, struct apply_ctx *ctx, struct wim_inode *inode)
{
	int ret;

#ifndef __WIN32__
	if (ctx->supported_features.symlink_reparse_points &&
	    !ctx->supported_features.reparse_points &&
	    inode_is_symlink(inode))
	{
		ret = extract_symlink(path, ctx, inode, NULL);
	} else
#endif /* !__WIN32__ */
	if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
		ret = ctx->ops->create_directory(path, ctx, &inode->extract_cookie);
		if (ret) {
			ERROR_WITH_ERRNO("Failed to create the directory "
					 "\"%"TS"\"", path);
		}
	} else if ((inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED) &&
		    ctx->ops->extract_encrypted_stream_creates_file &&
		    ctx->supported_features.encrypted_files) {
		ret = ctx->ops->extract_encrypted_stream(
				path, inode_unnamed_lte_resolved(inode), ctx);
		if (ret) {
			ERROR_WITH_ERRNO("Failed to create and extract "
					 "encrypted file \"%"TS"\"", path);
		}
	} else {
		ret = ctx->ops->create_file(path, ctx, &inode->extract_cookie);
		if (ret) {
			ERROR_WITH_ERRNO("Failed to create the file "
					 "\"%"TS"\"", path);
		}
	}
	return ret;
}

static int
extract_hardlink(const tchar *oldpath, const tchar *newpath,
		 struct apply_ctx *ctx)
{
	int ret;

	DEBUG("Creating hardlink \"%"TS"\" => \"%"TS"\"", newpath, oldpath);
	ret = ctx->ops->create_hardlink(oldpath, newpath, ctx);
	if (ret) {
		ERROR_WITH_ERRNO("Failed to create hardlink "
				 "\"%"TS"\" => \"%"TS"\"",
				 newpath, oldpath);
	}
	return ret;
}

#ifdef __WIN32__
static int
try_extract_rpfix(u8 *rpbuf,
		  u16 *rpbuflen_p,
		  const wchar_t *extract_root_realpath,
		  unsigned extract_root_realpath_nchars)
{
	struct reparse_data rpdata;
	wchar_t *target;
	size_t target_nchars;
	size_t stripped_nchars;
	wchar_t *stripped_target;
	wchar_t stripped_target_nchars;
	int ret;

	utf16lechar *new_target;
	utf16lechar *new_print_name;
	size_t new_target_nchars;
	size_t new_print_name_nchars;
	utf16lechar *p;

	ret = parse_reparse_data(rpbuf, *rpbuflen_p, &rpdata);
	if (ret)
		return ret;

	if (extract_root_realpath[0] == L'\0' ||
	    extract_root_realpath[1] != L':' ||
	    extract_root_realpath[2] != L'\\')
		return WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED;

	ret = parse_substitute_name(rpdata.substitute_name,
				    rpdata.substitute_name_nbytes,
				    rpdata.rptag);
	if (ret < 0)
		return 0;
	stripped_nchars = ret;
	target = rpdata.substitute_name;
	target_nchars = rpdata.substitute_name_nbytes / sizeof(utf16lechar);
	stripped_target = target + stripped_nchars;
	stripped_target_nchars = target_nchars - stripped_nchars;

	new_target = alloca((6 + extract_root_realpath_nchars +
			     stripped_target_nchars) * sizeof(utf16lechar));

	p = new_target;
	if (stripped_nchars == 6) {
		/* Include \??\ prefix if it was present before */
		p = wmempcpy(p, L"\\??\\", 4);
	}

	/* Print name excludes the \??\ if present. */
	new_print_name = p;
	if (stripped_nchars != 0) {
		/* Get drive letter from real path to extract root, if a drive
		 * letter was present before. */
		*p++ = extract_root_realpath[0];
		*p++ = extract_root_realpath[1];
	}
	/* Copy the rest of the extract root */
	p = wmempcpy(p, extract_root_realpath + 2, extract_root_realpath_nchars - 2);

	/* Append the stripped target */
	p = wmempcpy(p, stripped_target, stripped_target_nchars);
	new_target_nchars = p - new_target;
	new_print_name_nchars = p - new_print_name;

	if (new_target_nchars * sizeof(utf16lechar) >= REPARSE_POINT_MAX_SIZE ||
	    new_print_name_nchars * sizeof(utf16lechar) >= REPARSE_POINT_MAX_SIZE)
		return WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED;

	rpdata.substitute_name = new_target;
	rpdata.substitute_name_nbytes = new_target_nchars * sizeof(utf16lechar);
	rpdata.print_name = new_print_name;
	rpdata.print_name_nbytes = new_print_name_nchars * sizeof(utf16lechar);
	return make_reparse_buffer(&rpdata, rpbuf, rpbuflen_p);
}
#endif /* __WIN32__ */

/* Set reparse data on extracted file or directory that has
 * FILE_ATTRIBUTE_REPARSE_POINT set.  */
static int
extract_reparse_data(const tchar *path, struct apply_ctx *ctx,
		     struct wim_inode *inode,
		     struct wim_lookup_table_entry *lte_override)
{
	int ret;
	u8 rpbuf[REPARSE_POINT_MAX_SIZE];
	u16 rpbuflen;

	ret = wim_inode_get_reparse_data(inode, rpbuf, &rpbuflen, lte_override);
	if (ret)
		goto error;

#ifdef __WIN32__
	/* Fix up target of absolute symbolic link or junction points so
	 * that they point into the actual extraction target.  */
	if ((ctx->extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX) &&
	    (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
	     inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT) &&
	    !inode->i_not_rpfixed)
	{
		ret = try_extract_rpfix(rpbuf, &rpbuflen, ctx->realtarget,
					ctx->realtarget_nchars);
		if (ret && !(ctx->extract_flags &
			     WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS))
		{
			WARNING("Reparse point fixup of \"%"TS"\" "
				"failed", path);
			ret = 0;
		}
		if (ret)
			goto error;
	}
#endif

	ret = ctx->ops->set_reparse_data(path, rpbuf, rpbuflen, ctx);

	/* On Windows, the SeCreateSymbolicLink privilege is required to create
	 * symbolic links.  To be more friendly towards non-Administrator users,
	 * we merely warn the user if symbolic links cannot be created due to
	 * insufficient permissions or privileges, unless
	 * WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS was provided.  */
#ifdef __WIN32__
	if (ret && inode_is_symlink(inode) &&
	    (errno == EACCES || errno == EPERM) &&
	    !(ctx->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS))
	{
		WARNING("Can't set reparse data on \"%"TS"\": "
			"Access denied!\n"
			"          You may be trying to "
			"extract a symbolic link without the\n"
			"          SeCreateSymbolicLink privilege, "
			"which by default non-Administrator\n"
			"          accounts do not have.",
			path);
		ret = 0;
	}
#endif
	if (ret)
		goto error;

	/* Account for reparse data consumed.  */
	update_extract_progress(ctx,
				(lte_override ? lte_override :
				      inode_unnamed_lte_resolved(inode)));
	return 0;

error:
	ERROR_WITH_ERRNO("Failed to set reparse data on \"%"TS"\"", path);
	return ret;
}

/*
 * Extract zero or more streams to a file.
 *
 * This function operates slightly differently depending on whether @lte_spec is
 * NULL or not.  When @lte_spec is NULL, the behavior is to extract the default
 * file contents (unnamed stream), and, if named data streams are supported in
 * the extract mode and volume, any named data streams.  When @lte_spec is NULL,
 * the behavior is to extract only all copies of the stream @lte_spec, and in
 * addition use @lte_spec to set the reparse data or create the symbolic link if
 * appropriate.
 *
 * @path
 *	Path to file to extract (as can be passed to apply_operations
 *	functions).
 * @ctx
 *	Apply context.
 * @dentry
 *	WIM dentry that corresponds to the file being extracted.
 * @lte_spec
 *	If non-NULL, specifies the lookup table entry for a stream to extract,
 *	and only that stream will be extracted (although there may be more than
 *	one instance of it).
 * @lte_override
 *	Used only if @lte_spec != NULL; it is passed to the extraction functions
 *	rather than @lte_spec, allowing the location of the stream to be
 *	overridden.  (This is used when the WIM is being read from a nonseekable
 *	file, such as a pipe, when streams need to be used more than once; each
 *	such stream is extracted to a temporary file.)
 */
static int
extract_streams(const tchar *path, struct apply_ctx *ctx,
		struct wim_dentry *dentry,
		struct wim_lookup_table_entry *lte_spec,
		struct wim_lookup_table_entry *lte_override)
{
	struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;
	file_spec_t file_spec;
	int ret;

	if (dentry->was_hardlinked)
		return 0;

#ifdef ENABLE_DEBUG
	if (lte_spec) {
		char sha1_str[100];
		char *p = sha1_str;
		for (unsigned i = 0; i < SHA1_HASH_SIZE; i++)
			p += sprintf(p, "%02x", lte_override->hash[i]);
		DEBUG("Extracting stream SHA1=%s to \"%"TS"\"",
		      sha1_str, path, inode->i_ino);
	} else {
		DEBUG("Extracting streams to \"%"TS"\"", path, inode->i_ino);
	}
#endif

	if (ctx->ops->uses_cookies)
		file_spec.cookie = inode->extract_cookie;
	else
		file_spec.path = path;

	/* Unnamed data stream.  */
	lte = inode_unnamed_lte_resolved(inode);
	if (lte && (!lte_spec || lte == lte_spec)) {
		if (lte_spec)
			lte = lte_override;
		if (!(inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
					     FILE_ATTRIBUTE_REPARSE_POINT)))
		{
			if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED &&
			    ctx->supported_features.encrypted_files) {
				if (!ctx->ops->extract_encrypted_stream_creates_file) {
					ret = ctx->ops->extract_encrypted_stream(
								path, lte, ctx);
					if (ret)
						goto error;
				}
			} else {
				ret = ctx->ops->extract_unnamed_stream(
							file_spec, lte, ctx);
				if (ret)
					goto error;
			}
			update_extract_progress(ctx, lte);
		}
		else if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		{
			ret = 0;
			if (ctx->supported_features.reparse_points)
				ret = extract_reparse_data(path, ctx, inode, lte);
		#ifndef __WIN32__
			else if ((inode_is_symlink(inode) &&
				  ctx->supported_features.symlink_reparse_points))
				ret = extract_symlink(path, ctx, inode, lte);
		#endif
			if (ret)
				return ret;
		}
	}

	/* Named data streams.  */
	if (can_extract_named_data_streams(ctx)) {
		for (u16 i = 0; i < inode->i_num_ads; i++) {
			struct wim_ads_entry *entry = &inode->i_ads_entries[i];

			if (!ads_entry_is_named_stream(entry))
				continue;
			lte = entry->lte;
			if (!lte)
				continue;
			if (lte_spec && lte_spec != lte)
				continue;
			if (lte_spec)
				lte = lte_override;
			ret = ctx->ops->extract_named_stream(file_spec, entry->stream_name,
							     entry->stream_name_nbytes / 2,
							     lte, ctx);
			if (ret)
				goto error;
			update_extract_progress(ctx, lte);
		}
	}
	return 0;

error:
	ERROR_WITH_ERRNO("Failed to extract data of \"%"TS"\"", path);
	return ret;
}

/* Set attributes on an extracted file or directory if supported by the
 * extraction mode.  */
static int
extract_file_attributes(const tchar *path, struct apply_ctx *ctx,
			struct wim_dentry *dentry, unsigned pass)
{
	int ret;

	if (ctx->ops->set_file_attributes &&
	    !(dentry == ctx->extract_root && ctx->root_dentry_is_special)) {
		u32 attributes = dentry->d_inode->i_attributes;

		/* Clear unsupported attributes.  */
		attributes &= ctx->supported_attributes_mask;

		if ((attributes & FILE_ATTRIBUTE_DIRECTORY &&
		     !ctx->supported_features.encrypted_directories) ||
		    (!(attributes & FILE_ATTRIBUTE_DIRECTORY) &&
		     !ctx->supported_features.encrypted_files))
		{
			attributes &= ~FILE_ATTRIBUTE_ENCRYPTED;
		}

		if (attributes == 0)
			attributes = FILE_ATTRIBUTE_NORMAL;

		ret = ctx->ops->set_file_attributes(path, attributes, ctx, pass);
		if (ret) {
			ERROR_WITH_ERRNO("Failed to set attributes on "
					 "\"%"TS"\"", path);
			return ret;
		}
	}
	return 0;
}


/* Set or remove the short (DOS) name on an extracted file or directory if
 * supported by the extraction mode.  Since DOS names are unimportant and it's
 * easy to run into problems setting them on Windows (SetFileShortName()
 * requires SE_RESTORE privilege, which only the Administrator can request, and
 * also requires DELETE access to the file), failure is ignored unless
 * WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES is set.  */
static int
extract_short_name(const tchar *path, struct apply_ctx *ctx,
		   struct wim_dentry *dentry)
{
	int ret;

	/* The root of the dentry tree being extracted may not be extracted to
	 * its original name, so its short name should be ignored.  */
	if (dentry == ctx->extract_root)
		return 0;

	if (ctx->supported_features.short_names) {
		ret = ctx->ops->set_short_name(path,
					       dentry->short_name,
					       dentry->short_name_nbytes / 2,
					       ctx);
		if (ret && (ctx->extract_flags &
			    WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES))
		{
			ERROR_WITH_ERRNO("Failed to set short name of "
					 "\"%"TS"\"", path);
			return ret;
		}
	}
	return 0;
}

/* Set security descriptor, UNIX data, or neither on an extracted file, taking
 * into account the current extraction mode and flags.  */
static int
extract_security(const tchar *path, struct apply_ctx *ctx,
		 struct wim_dentry *dentry)
{
	int ret;
	struct wim_inode *inode = dentry->d_inode;

	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS)
		return 0;

	if ((ctx->extract_root == dentry) && ctx->root_dentry_is_special)
		return 0;

#ifndef __WIN32__
	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		struct wimlib_unix_data data;

		ret = inode_get_unix_data(inode, &data, NULL);
		if (ret < 0)
			ret = 0;
		else if (ret == 0)
			ret = ctx->ops->set_unix_data(path, &data, ctx);
		if (ret) {
			if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS) {
				ERROR_WITH_ERRNO("Failed to set UNIX owner, "
						 "group, and/or mode on "
						 "\"%"TS"\"", path);
				return ret;
			} else {
				WARNING_WITH_ERRNO("Failed to set UNIX owner, "
						   "group, and/or/mode on "
						   "\"%"TS"\"", path);
			}
		}
	}
	else
#endif /* __WIN32__ */
	if (ctx->supported_features.security_descriptors &&
	    inode->i_security_id != -1)
	{
		const struct wim_security_data *sd;
		const u8 *desc;
		size_t desc_size;

		sd = wim_const_security_data(ctx->wim);
		desc = sd->descriptors[inode->i_security_id];
		desc_size = sd->sizes[inode->i_security_id];

		ret = ctx->ops->set_security_descriptor(path, desc,
							desc_size, ctx);
		if (ret) {
			if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS) {
				ERROR_WITH_ERRNO("Failed to set security "
						 "descriptor on \"%"TS"\"", path);
				return ret;
			} else {
			#if 0
				if (errno != EACCES) {
					WARNING_WITH_ERRNO("Failed to set "
							   "security descriptor "
							   "on \"%"TS"\"", path);
				}
			#endif
				ctx->no_security_descriptors++;
			}
		}
	}
	return 0;
}

/* Set timestamps on an extracted file.  Failure is warning-only unless
 * WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS is set.  */
static int
extract_timestamps(const tchar *path, struct apply_ctx *ctx,
		   struct wim_dentry *dentry)
{
	struct wim_inode *inode = dentry->d_inode;
	int ret;

	if ((ctx->extract_root == dentry) && ctx->root_dentry_is_special)
		return 0;

	if (ctx->ops->set_timestamps) {
		ret = ctx->ops->set_timestamps(path,
					       inode->i_creation_time,
					       inode->i_last_write_time,
					       inode->i_last_access_time,
					       ctx);
		if (ret) {
			if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS) {
				ERROR_WITH_ERRNO("Failed to set timestamps "
						 "on \"%"TS"\"", path);
				return ret;
			} else {
				WARNING_WITH_ERRNO("Failed to set timestamps "
						   "on \"%"TS"\"", path);
			}
		}
	}
	return 0;
}

/* Check whether the extraction of a dentry should be skipped completely.  */
static bool
dentry_is_supported(struct wim_dentry *dentry,
		    const struct wim_features *supported_features)
{
	struct wim_inode *inode = dentry->d_inode;

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		return supported_features->reparse_points ||
			(inode_is_symlink(inode) &&
			 supported_features->symlink_reparse_points);
	}
	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED) {
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
			return supported_features->encrypted_directories != 0;
		else
			return supported_features->encrypted_files != 0;
	}
	return true;
}

/* Given a WIM dentry to extract, build the path to which to extract it, in the
 * format understood by the callbacks in the apply_operations being used.
 *
 * Write the resulting path into @path, which must have room for at least
 * ctx->ops->max_path characters including the null-terminator.
 *
 * Return %true if successful; %false if this WIM dentry doesn't actually need
 * to be extracted or if the calculated path exceeds ctx->ops->max_path
 * characters.
 *
 * This function clobbers the tmp_list member of @dentry and its ancestors up
 * until the extraction root.  */
static bool
build_extraction_path(tchar path[], struct wim_dentry *dentry,
		      struct apply_ctx *ctx)
{
	size_t path_nchars;
	LIST_HEAD(ancestor_list);
	tchar *p = path;
	const tchar *target_prefix;
	size_t target_prefix_nchars;
	struct wim_dentry *d;

	if (dentry->extraction_skipped)
		return false;

	path_nchars = ctx->ops->path_prefix_nchars;

	if (ctx->ops->requires_realtarget_in_paths) {
		target_prefix        = ctx->realtarget;
		target_prefix_nchars = ctx->realtarget_nchars;
	} else if (ctx->ops->requires_target_in_paths) {
		target_prefix        = ctx->target;
		target_prefix_nchars = ctx->target_nchars;
	} else {
		target_prefix        = NULL;
		target_prefix_nchars = 0;
	}
	path_nchars += target_prefix_nchars;

	for (d = dentry; d != ctx->extract_root; d = d->parent) {
		path_nchars += d->extraction_name_nchars + 1;
		list_add(&d->tmp_list, &ancestor_list);
	}

	path_nchars++; /* null terminator */

	if (path_nchars > ctx->ops->path_max) {
		WARNING("\"%"TS"\": Path too long to extract",
			dentry_full_path(dentry));
		return false;
	}

	p = tmempcpy(p, ctx->ops->path_prefix, ctx->ops->path_prefix_nchars);
	p = tmempcpy(p, target_prefix, target_prefix_nchars);
	list_for_each_entry(d, &ancestor_list, tmp_list) {
		*p++ = ctx->ops->path_separator;
		p = tmempcpy(p, d->extraction_name, d->extraction_name_nchars);
	}
	*p++ = T('\0');
	wimlib_assert(p - path == path_nchars);
	return true;
}

static unsigned
get_num_path_components(const tchar *path, tchar path_separator)
{
	unsigned num_components = 0;
#ifdef __WIN32__
	/* Ignore drive letter.  */
	if (path[0] != L'\0' && path[1] == L':')
		path += 2;
#endif

	while (*path) {
		while (*path == path_separator)
			path++;
		if (*path)
			num_components++;
		while (*path && *path != path_separator)
			path++;
	}
	return num_components;
}

static int
extract_multiimage_symlink(const tchar *oldpath, const tchar *newpath,
			   struct apply_ctx *ctx, struct wim_dentry *dentry)
{
	size_t num_raw_path_components;
	const struct wim_dentry *d;
	size_t num_target_path_components;
	tchar *p;
	const tchar *p_old;
	int ret;

	num_raw_path_components = 0;
	for (d = dentry; d != ctx->extract_root; d = d->parent)
		num_raw_path_components++;

	if (ctx->ops->requires_realtarget_in_paths)
		num_target_path_components = get_num_path_components(ctx->realtarget,
								     ctx->ops->path_separator);
	else if (ctx->ops->requires_target_in_paths)
		num_target_path_components = get_num_path_components(ctx->target,
								     ctx->ops->path_separator);
	else
		num_target_path_components = 0;

	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE) {
		wimlib_assert(num_target_path_components > 0);
		num_raw_path_components++;
		num_target_path_components--;
	}

	p_old = oldpath + ctx->ops->path_prefix_nchars;
#ifdef __WIN32__
	if (p_old[0] != L'\0' && p_old[1] == ':')
		p_old += 2;
#endif
	while (*p_old == ctx->ops->path_separator)
		p_old++;
	while (--num_target_path_components) {
		while (*p_old != ctx->ops->path_separator)
			p_old++;
		while (*p_old == ctx->ops->path_separator)
			p_old++;
	}

	tchar symlink_target[tstrlen(p_old) + 3 * num_raw_path_components + 1];

	p = &symlink_target[0];
	while (num_raw_path_components--) {
		*p++ = '.';
		*p++ = '.';
		*p++ = ctx->ops->path_separator;
	}
	tstrcpy(p, p_old);
	DEBUG("Creating symlink \"%"TS"\" => \"%"TS"\"",
	      newpath, symlink_target);
	ret = ctx->ops->create_symlink(symlink_target, newpath, ctx);
	if (ret) {
		ERROR_WITH_ERRNO("Failed to create symlink "
				 "\"%"TS"\" => \"%"TS"\"",
				 newpath, symlink_target);
	}
	return ret;
}

/* Create the "skeleton" of an extracted file or directory.  Don't yet extract
 * data streams, reparse data (including symbolic links), timestamps, and
 * security descriptors.  Basically, everything that doesn't require reading
 * non-metadata resources from the WIM file and isn't delayed until the final
 * pass.  */
static int
do_dentry_extract_skeleton(tchar path[], struct wim_dentry *dentry,
			   struct apply_ctx *ctx)
{
	struct wim_inode *inode = dentry->d_inode;
	int ret;
	const tchar *oldpath;

	if (unlikely(is_linked_extraction(ctx))) {
		struct wim_lookup_table_entry *unnamed_lte;

		unnamed_lte = inode_unnamed_lte_resolved(dentry->d_inode);
		if (unnamed_lte && unnamed_lte->extracted_file) {
			oldpath = unnamed_lte->extracted_file;
			if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_HARDLINK)
				goto hardlink;
			else
				goto symlink;
		}
	}

	/* Create hard link if this dentry corresponds to an already-extracted
	 * inode.  */
	if (inode->i_extracted_file) {
		oldpath = inode->i_extracted_file;
		goto hardlink;
	}

	/* Skip symlinks unless they can be extracted as reparse points rather
	 * than created directly.  */
	if (inode_is_symlink(inode) && !ctx->supported_features.reparse_points)
		return 0;

	/* Create this file or directory unless it's the extraction root, which
	 * was already created if necessary.  */
	if (dentry != ctx->extract_root) {
		ret = extract_inode(path, ctx, inode);
		if (ret)
			return ret;
	}

	/* Create empty named data streams.  */
	if (can_extract_named_data_streams(ctx)) {
		for (u16 i = 0; i < inode->i_num_ads; i++) {
			file_spec_t file_spec;
			struct wim_ads_entry *entry = &inode->i_ads_entries[i];

			if (!ads_entry_is_named_stream(entry))
				continue;
			if (entry->lte)
				continue;
			if (ctx->ops->uses_cookies)
				file_spec.cookie = inode->extract_cookie;
			else
				file_spec.path = path;
			ret = ctx->ops->extract_named_stream(file_spec,
							     entry->stream_name,
							     entry->stream_name_nbytes / 2,
							     entry->lte, ctx);
			if (ret) {
				ERROR_WITH_ERRNO("\"%"TS"\": failed to create "
						 "empty named data stream",
						 path);
				return ret;
			}
		}
	}

	/* Set file attributes (if supported).  */
	ret = extract_file_attributes(path, ctx, dentry, 0);
	if (ret)
		return ret;

	/* Set or remove file short name (if supported).  */
	ret = extract_short_name(path, ctx, dentry);
	if (ret)
		return ret;

	/* If inode has multiple links and hard links are supported in this
	 * extraction mode and volume, save the path to the extracted file in
	 * case it's needed to create a hard link.  */
	if (unlikely(is_linked_extraction(ctx))) {
		struct wim_lookup_table_entry *unnamed_lte;

		unnamed_lte = inode_unnamed_lte_resolved(dentry->d_inode);
		if (unnamed_lte) {
			unnamed_lte->extracted_file = TSTRDUP(path);
			if (!unnamed_lte->extracted_file)
				return WIMLIB_ERR_NOMEM;
		}
	} else if (inode->i_nlink > 1 && ctx->supported_features.hard_links) {
		inode->i_extracted_file = TSTRDUP(path);
		if (!inode->i_extracted_file)
			return WIMLIB_ERR_NOMEM;
	}
	return 0;

symlink:
	ret = extract_multiimage_symlink(oldpath, path, ctx, dentry);
	if (ret)
		return ret;
	dentry->was_hardlinked = 1;
	return 0;

hardlink:
	ret = extract_hardlink(oldpath, path, ctx);
	if (ret)
		return ret;
	dentry->was_hardlinked = 1;
	return 0;
}

/* This is a wrapper around do_dentry_extract_skeleton() that handles building
 * the path, doing short name reordering.  This is also idempotent; dentries
 * already processed have skeleton_extracted set and no action is taken.  See
 * apply_operations.requires_short_name_reordering for more details about short
 * name reordering.  */
static int
dentry_extract_skeleton(struct wim_dentry *dentry, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;
	tchar path[ctx->ops->path_max];
	struct wim_dentry *orig_dentry;
	struct wim_dentry *other_dentry;
	int ret;

	if (dentry->skeleton_extracted)
		return 0;

	orig_dentry = NULL;
	if (ctx->supported_features.short_names
	    && ctx->ops->requires_short_name_reordering
	    && !dentry_has_short_name(dentry)
	    && !dentry->d_inode->i_dos_name_extracted)
	{
		inode_for_each_dentry(other_dentry, dentry->d_inode) {
			if (dentry_has_short_name(other_dentry)
			    && !other_dentry->skeleton_extracted
			    && other_dentry->in_extraction_tree)
			{
				DEBUG("Creating %"TS" before %"TS" "
				      "to guarantee correct DOS name extraction",
				      dentry_full_path(other_dentry),
				      dentry_full_path(dentry));
				orig_dentry = dentry;
				dentry = other_dentry;
				break;
			}
		}
	}
again:
	if (!build_extraction_path(path, dentry, ctx))
		return 0;
	ret = do_dentry_extract_skeleton(path, dentry, ctx);
	if (ret)
		return ret;

	dentry->skeleton_extracted = 1;

	if (orig_dentry) {
		dentry = orig_dentry;
		orig_dentry = NULL;
		goto again;
	}
	dentry->d_inode->i_dos_name_extracted = 1;
	return 0;
}

static int
dentry_extract_dir_skeleton(struct wim_dentry *dentry, void *_ctx)
{
	if (dentry->d_inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
		return dentry_extract_skeleton(dentry, _ctx);
	return 0;
}

/* Create a file or directory, then immediately extract all streams.  This
 * assumes that WIMLIB_EXTRACT_FLAG_SEQUENTIAL is not specified, since the WIM
 * may not be read sequentially by this function.  */
static int
dentry_extract(struct wim_dentry *dentry, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;
	tchar path[ctx->ops->path_max];
	int ret;

	ret = dentry_extract_skeleton(dentry, ctx);
	if (ret)
		return ret;

	if (!build_extraction_path(path, dentry, ctx))
		return 0;

	return extract_streams(path, ctx, dentry, NULL, NULL);
}

/* Creates a temporary file opened for writing.  The open file descriptor is
 * returned in @fd_ret and its name is returned in @name_ret (dynamically
 * allocated).  */
static int
create_temporary_file(struct filedes *fd_ret, tchar **name_ret)
{
	tchar *name;
	int raw_fd;

retry:
	name = ttempnam(NULL, T("wimlib"));
	if (name == NULL) {
		ERROR_WITH_ERRNO("Failed to create temporary filename");
		return WIMLIB_ERR_NOMEM;
	}

	raw_fd = topen(name, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0600);

	if (raw_fd < 0) {
		if (errno == EEXIST) {
			FREE(name);
			goto retry;
		}
		ERROR_WITH_ERRNO("Failed to open temporary file \"%"TS"\"", name);
		FREE(name);
		return WIMLIB_ERR_OPEN;
	}

	filedes_init(fd_ret, raw_fd);
	*name_ret = name;
	return 0;
}

/* Extract all instances of the stream @lte that are being extracted in this
 * call of extract_tree(), but actually read the stream data from @lte_override.
 */
static int
extract_stream_instances(struct wim_lookup_table_entry *lte,
			 struct wim_lookup_table_entry *lte_override,
			 struct apply_ctx *ctx)
{
	struct wim_dentry **lte_dentries;
	tchar path[ctx->ops->path_max];
	size_t i;
	int ret;

	if (lte->out_refcnt <= ARRAY_LEN(lte->inline_lte_dentries))
		lte_dentries = lte->inline_lte_dentries;
	else
		lte_dentries = lte->lte_dentries;

	for (i = 0; i < lte->out_refcnt; i++) {
		struct wim_dentry *dentry = lte_dentries[i];

		if (dentry->tmp_flag)
			continue;
		if (!build_extraction_path(path, dentry, ctx))
			continue;
		ret = extract_streams(path, ctx, dentry, lte, lte_override);
		if (ret)
			goto out_clear_tmp_flags;
		dentry->tmp_flag = 1;
	}
	ret = 0;
out_clear_tmp_flags:
	for (i = 0; i < lte->out_refcnt; i++)
		lte_dentries[i]->tmp_flag = 0;
	return ret;
}

/* Determine whether the specified stream needs to be extracted to a temporary
 * file or not.
 *
 * @lte->out_refcnt specifies the number of instances of this stream that must
 * be extracted.
 *
 * @is_partial_res is %true if this stream is just one of multiple in a single
 * WIM resource being extracted.  */
static bool
need_tmpfile_to_extract(struct wim_lookup_table_entry *lte,
			bool is_partial_res)
{
	/* Temporary file is always required when reading a partial resource,
	 * since in that case we retrieve all the contained streams in one pass.
	 * */
	if (is_partial_res)
		return true;

	/* Otherwise we don't need a temporary file if only a single instance of
	 * the stream is needed.  */
	if (lte->out_refcnt == 1)
		return false;

	wimlib_assert(lte->out_refcnt >= 2);

	/* We also don't need a temporary file if random access to the stream is
	 * allowed.  */
	if (lte->resource_location != RESOURCE_IN_WIM ||
	    filedes_is_seekable(&lte->rspec->wim->in_fd))
		return false;

	return true;
}

static int
begin_extract_stream_to_tmpfile(struct wim_lookup_table_entry *lte,
				bool is_partial_res,
				void *_ctx)
{
	struct apply_ctx *ctx = _ctx;
	int ret;

	if (!need_tmpfile_to_extract(lte, is_partial_res)) {
		DEBUG("Temporary file not needed "
		      "for stream (size=%"PRIu64")", lte->size);
		ret = extract_stream_instances(lte, lte, ctx);
		if (ret)
			return ret;

		return BEGIN_STREAM_STATUS_SKIP_STREAM;
	}

	DEBUG("Temporary file needed for stream (size=%"PRIu64")", lte->size);
	return create_temporary_file(&ctx->tmpfile_fd, &ctx->tmpfile_name);
}

static int
end_extract_stream_to_tmpfile(struct wim_lookup_table_entry *lte,
			      int status, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;
	struct wim_lookup_table_entry lte_override;
	int ret;
	int errno_save = errno;

	ret = filedes_close(&ctx->tmpfile_fd);

	if (status) {
		ret = status;
		errno = errno_save;
		goto out_delete_tmpfile;
	}

	if (ret) {
		ERROR_WITH_ERRNO("Error writing temporary file %"TS, ctx->tmpfile_name);
		ret = WIMLIB_ERR_WRITE;
		goto out_delete_tmpfile;
	}

	/* Now that a full stream has been extracted to a temporary file,
	 * extract all instances of it to the actual target.  */

	memcpy(&lte_override, lte, sizeof(struct wim_lookup_table_entry));
	lte_override.resource_location = RESOURCE_IN_FILE_ON_DISK;
	lte_override.file_on_disk = ctx->tmpfile_name;

	ret = extract_stream_instances(lte, &lte_override, ctx);

out_delete_tmpfile:
	errno_save = errno;
	tunlink(ctx->tmpfile_name);
	FREE(ctx->tmpfile_name);
	errno = errno_save;
	return ret;
}

/* Extracts a list of streams (ctx.stream_list), assuming that the directory
 * structure and empty files were already created.  This relies on the
 * per-`struct wim_lookup_table_entry' list of dentries that reference each
 * stream that was constructed earlier.  */
static int
extract_stream_list(struct apply_ctx *ctx)
{
	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL) {
		/* Sequential extraction: read the streams in the order in which
		 * they appear in the WIM file.  */
		struct read_stream_list_callbacks cbs = {
			.begin_stream		= begin_extract_stream_to_tmpfile,
			.begin_stream_ctx	= ctx,
			.consume_chunk		= extract_chunk_to_fd,
			.consume_chunk_ctx	= &ctx->tmpfile_fd,
			.end_stream		= end_extract_stream_to_tmpfile,
			.end_stream_ctx		= ctx,
		};
		return read_stream_list(&ctx->stream_list,
					offsetof(struct wim_lookup_table_entry, extraction_list),
					&cbs, VERIFY_STREAM_HASHES);
	} else {
		/* Extract the streams in unsorted order.  */
		struct wim_lookup_table_entry *lte;
		int ret;

		list_for_each_entry(lte, &ctx->stream_list, extraction_list) {
			ret = extract_stream_instances(lte, lte, ctx);
			if (ret)
				return ret;
		}
		return 0;
	}
}

#define PWM_ALLOW_WIM_HDR 0x00001
#define PWM_SILENT_EOF	  0x00002

/* Read the header from a stream in a pipable WIM.  */
static int
read_pwm_stream_header(WIMStruct *pwm, struct wim_lookup_table_entry *lte,
		       struct wim_resource_spec *rspec,
		       int flags, struct wim_header_disk *hdr_ret)
{
	union {
		struct pwm_stream_hdr stream_hdr;
		struct wim_header_disk pwm_hdr;
	} buf;
	struct wim_reshdr reshdr;
	int ret;

	ret = full_read(&pwm->in_fd, &buf.stream_hdr, sizeof(buf.stream_hdr));
	if (ret)
		goto read_error;

	if ((flags & PWM_ALLOW_WIM_HDR) && buf.stream_hdr.magic == PWM_MAGIC) {
		BUILD_BUG_ON(sizeof(buf.pwm_hdr) < sizeof(buf.stream_hdr));
		ret = full_read(&pwm->in_fd, &buf.stream_hdr + 1,
				sizeof(buf.pwm_hdr) - sizeof(buf.stream_hdr));

		if (ret)
			goto read_error;
		lte->resource_location = RESOURCE_NONEXISTENT;
		memcpy(hdr_ret, &buf.pwm_hdr, sizeof(buf.pwm_hdr));
		return 0;
	}

	if (buf.stream_hdr.magic != PWM_STREAM_MAGIC) {
		ERROR("Data read on pipe is invalid (expected stream header).");
		return WIMLIB_ERR_INVALID_PIPABLE_WIM;
	}

	copy_hash(lte->hash, buf.stream_hdr.hash);

	reshdr.size_in_wim = 0;
	reshdr.flags = le32_to_cpu(buf.stream_hdr.flags);
	reshdr.offset_in_wim = pwm->in_fd.offset;
	reshdr.uncompressed_size = le64_to_cpu(buf.stream_hdr.uncompressed_size);
	wim_res_hdr_to_spec(&reshdr, pwm, rspec);
	lte_bind_wim_resource_spec(lte, rspec);
	lte->flags = rspec->flags;
	lte->size = rspec->uncompressed_size;
	lte->offset_in_res = 0;
	return 0;

read_error:
	if (ret != WIMLIB_ERR_UNEXPECTED_END_OF_FILE || !(flags & PWM_SILENT_EOF))
		ERROR_WITH_ERRNO("Error reading pipable WIM from pipe");
	return ret;
}

static int
extract_streams_from_pipe(struct apply_ctx *ctx)
{
	struct wim_lookup_table_entry *found_lte;
	struct wim_resource_spec *rspec;
	struct wim_lookup_table_entry *needed_lte;
	struct wim_lookup_table *lookup_table;
	struct wim_header_disk pwm_hdr;
	int ret;
	int pwm_flags;

	ret = WIMLIB_ERR_NOMEM;
	found_lte = new_lookup_table_entry();
	if (found_lte == NULL)
		goto out;

	rspec = MALLOC(sizeof(struct wim_resource_spec));
	if (rspec == NULL)
		goto out_free_found_lte;

	lookup_table = ctx->wim->lookup_table;
	pwm_flags = PWM_ALLOW_WIM_HDR;
	if ((ctx->extract_flags & WIMLIB_EXTRACT_FLAG_RESUME))
		pwm_flags |= PWM_SILENT_EOF;
	memcpy(ctx->progress.extract.guid, ctx->wim->hdr.guid, WIM_GID_LEN);
	ctx->progress.extract.part_number = ctx->wim->hdr.part_number;
	ctx->progress.extract.total_parts = ctx->wim->hdr.total_parts;
	if (ctx->progress_func)
		ctx->progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN,
				   &ctx->progress);
	while (ctx->num_streams_remaining) {
		if (found_lte->resource_location != RESOURCE_NONEXISTENT)
			lte_unbind_wim_resource_spec(found_lte);
		ret = read_pwm_stream_header(ctx->wim, found_lte, rspec,
					     pwm_flags, &pwm_hdr);
		if (ret) {
			if (ret == WIMLIB_ERR_UNEXPECTED_END_OF_FILE &&
			    (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_RESUME))
			{
				goto resume_done;
			}
			goto out_free_found_lte;
		}

		if ((found_lte->resource_location != RESOURCE_NONEXISTENT)
		    && !(found_lte->flags & WIM_RESHDR_FLAG_METADATA)
		    && (needed_lte = lookup_resource(lookup_table, found_lte->hash))
		    && (needed_lte->out_refcnt))
		{
			char *tmpfile_name = NULL;
			struct wim_lookup_table_entry *lte_override;
			struct wim_lookup_table_entry tmpfile_lte;

			needed_lte->offset_in_res = found_lte->offset_in_res;
			needed_lte->flags = found_lte->flags;
			needed_lte->size = found_lte->size;

			lte_unbind_wim_resource_spec(found_lte);
			lte_bind_wim_resource_spec(needed_lte, rspec);

			if (needed_lte->out_refcnt > 1) {

				struct filedes tmpfile_fd;

				/* Extract stream to temporary file.  */
				ret = create_temporary_file(&tmpfile_fd, &tmpfile_name);
				if (ret)
					goto out_free_found_lte;

				ret = extract_stream_to_fd(needed_lte, &tmpfile_fd,
							   needed_lte->size);
				if (ret) {
					filedes_close(&tmpfile_fd);
					goto delete_tmpfile;
				}

				if (filedes_close(&tmpfile_fd)) {
					ERROR_WITH_ERRNO("Error writing to temporary "
							 "file \"%"TS"\"", tmpfile_name);
					ret = WIMLIB_ERR_WRITE;
					goto delete_tmpfile;
				}
				memcpy(&tmpfile_lte, needed_lte,
				       sizeof(struct wim_lookup_table_entry));
				tmpfile_lte.resource_location = RESOURCE_IN_FILE_ON_DISK;
				tmpfile_lte.file_on_disk = tmpfile_name;
				lte_override = &tmpfile_lte;
			} else {
				lte_override = needed_lte;
			}

			ret = extract_stream_instances(needed_lte, lte_override, ctx);
		delete_tmpfile:
			lte_unbind_wim_resource_spec(needed_lte);
			if (tmpfile_name) {
				tunlink(tmpfile_name);
				FREE(tmpfile_name);
			}
			if (ret)
				goto out_free_found_lte;
			ctx->num_streams_remaining--;
		} else if (found_lte->resource_location != RESOURCE_NONEXISTENT) {
			ret = skip_wim_stream(found_lte);
			if (ret)
				goto out_free_found_lte;
		} else {
			u16 part_number = le16_to_cpu(pwm_hdr.part_number);
			u16 total_parts = le16_to_cpu(pwm_hdr.total_parts);

			if (part_number != ctx->progress.extract.part_number ||
			    total_parts != ctx->progress.extract.total_parts ||
			    memcmp(pwm_hdr.guid, ctx->progress.extract.guid,
				   WIM_GID_LEN))
			{
				ctx->progress.extract.part_number = part_number;
				ctx->progress.extract.total_parts = total_parts;
				memcpy(ctx->progress.extract.guid,
				       pwm_hdr.guid, WIM_GID_LEN);
				if (ctx->progress_func) {
					ctx->progress_func(
						WIMLIB_PROGRESS_MSG_EXTRACT_SPWM_PART_BEGIN,
							   &ctx->progress);
				}

			}
		}
	}
	ret = 0;
out_free_found_lte:
	if (found_lte->resource_location != RESOURCE_IN_WIM)
		FREE(rspec);
	free_lookup_table_entry(found_lte);
out:
	return ret;

resume_done:
	/* TODO */
	return 0;
}

/* Finish extracting a file, directory, or symbolic link by setting file
 * security and timestamps.  */
static int
dentry_extract_final(struct wim_dentry *dentry, void *_ctx)
{
	struct apply_ctx *ctx = _ctx;
	int ret;
	tchar path[ctx->ops->path_max];

	if (!build_extraction_path(path, dentry, ctx))
		return 0;

	ret = extract_security(path, ctx, dentry);
	if (ret)
		return ret;

	if (ctx->ops->requires_final_set_attributes_pass) {
		/* Set file attributes (if supported).  */
		ret = extract_file_attributes(path, ctx, dentry, 1);
		if (ret)
			return ret;
	}

	return extract_timestamps(path, ctx, dentry);
}

/*
 * Extract a WIM dentry to standard output.
 *
 * This obviously doesn't make sense in all cases.  We return an error if the
 * dentry does not correspond to a regular file.  Otherwise we extract the
 * unnamed data stream only.
 */
static int
extract_dentry_to_stdout(struct wim_dentry *dentry)
{
	int ret = 0;
	if (dentry->d_inode->i_attributes & (FILE_ATTRIBUTE_REPARSE_POINT |
					     FILE_ATTRIBUTE_DIRECTORY))
	{
		ERROR("\"%"TS"\" is not a regular file and therefore cannot be "
		      "extracted to standard output", dentry_full_path(dentry));
		ret = WIMLIB_ERR_NOT_A_REGULAR_FILE;
	} else {
		struct wim_lookup_table_entry *lte;

		lte = inode_unnamed_lte_resolved(dentry->d_inode);
		if (lte) {
			struct filedes _stdout;
			filedes_init(&_stdout, STDOUT_FILENO);
			ret = extract_stream_to_fd(lte, &_stdout, lte->size);
		}
	}
	return ret;
}

#ifdef __WIN32__
static const utf16lechar replacement_char = cpu_to_le16(0xfffd);
#else
static const utf16lechar replacement_char = cpu_to_le16('?');
#endif

static bool
file_name_valid(utf16lechar *name, size_t num_chars, bool fix)
{
	size_t i;

	if (num_chars == 0)
		return true;
	for (i = 0; i < num_chars; i++) {
		switch (name[i]) {
	#ifdef __WIN32__
		case cpu_to_le16('\\'):
		case cpu_to_le16(':'):
		case cpu_to_le16('*'):
		case cpu_to_le16('?'):
		case cpu_to_le16('"'):
		case cpu_to_le16('<'):
		case cpu_to_le16('>'):
		case cpu_to_le16('|'):
	#endif
		case cpu_to_le16('/'):
		case cpu_to_le16('\0'):
			if (fix)
				name[i] = replacement_char;
			else
				return false;
		}
	}

#ifdef __WIN32__
	if (name[num_chars - 1] == cpu_to_le16(' ') ||
	    name[num_chars - 1] == cpu_to_le16('.'))
	{
		if (fix)
			name[num_chars - 1] = replacement_char;
		else
			return false;
	}
#endif
	return true;
}

static bool
dentry_is_dot_or_dotdot(const struct wim_dentry *dentry)
{
	const utf16lechar *file_name = dentry->file_name;
	return file_name != NULL &&
		file_name[0] == cpu_to_le16('.') &&
		(file_name[1] == cpu_to_le16('\0') ||
		 (file_name[1] == cpu_to_le16('.') &&
		  file_name[2] == cpu_to_le16('\0')));
}

static int
dentry_mark_skipped(struct wim_dentry *dentry, void *_ignore)
{
	dentry->extraction_skipped = 1;
	return 0;
}

/*
 * dentry_calculate_extraction_path-
 *
 * Calculate the actual filename component at which a WIM dentry will be
 * extracted, handling invalid filenames "properly".
 *
 * dentry->extraction_name usually will be set the same as dentry->file_name (on
 * UNIX, converted into the platform's multibyte encoding).  However, if the
 * file name contains characters that are not valid on the current platform or
 * has some other format that is not valid, leave dentry->extraction_name as
 * NULL and set dentry->extraction_skipped to indicate that this dentry should
 * not be extracted, unless the appropriate flag
 * WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES is set in the extract flags, in
 * which case a substitute filename will be created and set instead.
 *
 * Conflicts with case-insensitive names on Windows are handled similarly; see
 * below.
 */
static int
dentry_calculate_extraction_path(struct wim_dentry *dentry, void *_args)
{
	struct apply_ctx *ctx = _args;
	int ret;

	dentry->in_extraction_tree = 1;

	if (dentry == ctx->extract_root || dentry->extraction_skipped)
		return 0;

	if (!dentry_is_supported(dentry, &ctx->supported_features))
		goto skip_dentry;

	if (dentry_is_dot_or_dotdot(dentry)) {
		/* WIM files shouldn't contain . or .. entries.  But if they are
		 * there, don't attempt to extract them. */
		WARNING("Skipping extraction of unexpected . or .. file "
			"\"%"TS"\"", dentry_full_path(dentry));
		goto skip_dentry;
	}

#ifdef __WIN32__
	if (!ctx->ops->supports_case_sensitive_filenames)
	{
		struct wim_dentry *other;
		list_for_each_entry(other, &dentry->case_insensitive_conflict_list,
				    case_insensitive_conflict_list)
		{
			if (ctx->extract_flags &
			    WIMLIB_EXTRACT_FLAG_ALL_CASE_CONFLICTS) {
				WARNING("\"%"TS"\" has the same "
					"case-insensitive name as "
					"\"%"TS"\"; extracting "
					"dummy name instead",
					dentry_full_path(dentry),
					dentry_full_path(other));
				goto out_replace;
			} else {
				WARNING("Not extracting \"%"TS"\": "
					"has same case-insensitive "
					"name as \"%"TS"\"",
					dentry_full_path(dentry),
					dentry_full_path(other));
				goto skip_dentry;
			}
		}
	}
#else	/* __WIN32__ */
	wimlib_assert(ctx->ops->supports_case_sensitive_filenames);
#endif	/* !__WIN32__ */

	if (file_name_valid(dentry->file_name, dentry->file_name_nbytes / 2, false)) {
#ifdef __WIN32__
		dentry->extraction_name = dentry->file_name;
		dentry->extraction_name_nchars = dentry->file_name_nbytes / 2;
		return 0;
#else
		return utf16le_to_tstr(dentry->file_name,
				       dentry->file_name_nbytes,
				       &dentry->extraction_name,
				       &dentry->extraction_name_nchars);
#endif
	} else {
		if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_REPLACE_INVALID_FILENAMES)
		{
			WARNING("\"%"TS"\" has an invalid filename "
				"that is not supported on this platform; "
				"extracting dummy name instead",
				dentry_full_path(dentry));
			goto out_replace;
		} else {
			WARNING("Not extracting \"%"TS"\": has an invalid filename "
				"that is not supported on this platform",
				dentry_full_path(dentry));
			goto skip_dentry;
		}
	}

out_replace:
	{
		utf16lechar utf16_name_copy[dentry->file_name_nbytes / 2];

		memcpy(utf16_name_copy, dentry->file_name, dentry->file_name_nbytes);
		file_name_valid(utf16_name_copy, dentry->file_name_nbytes / 2, true);

		tchar *tchar_name;
		size_t tchar_nchars;
	#ifdef __WIN32__
		tchar_name = utf16_name_copy;
		tchar_nchars = dentry->file_name_nbytes / 2;
	#else
		ret = utf16le_to_tstr(utf16_name_copy,
				      dentry->file_name_nbytes,
				      &tchar_name, &tchar_nchars);
		if (ret)
			return ret;
	#endif
		size_t fixed_name_num_chars = tchar_nchars;
		tchar fixed_name[tchar_nchars + 50];

		tmemcpy(fixed_name, tchar_name, tchar_nchars);
		fixed_name_num_chars += tsprintf(fixed_name + tchar_nchars,
						 T(" (invalid filename #%lu)"),
						 ++ctx->invalid_sequence);
	#ifndef __WIN32__
		FREE(tchar_name);
	#endif
		dentry->extraction_name = memdup(fixed_name,
						 2 * fixed_name_num_chars + 2);
		if (!dentry->extraction_name)
			return WIMLIB_ERR_NOMEM;
		dentry->extraction_name_nchars = fixed_name_num_chars;
	}
	return 0;

skip_dentry:
	for_dentry_in_tree(dentry, dentry_mark_skipped, NULL);
	return 0;
}

/* Clean up dentry and inode structure after extraction.  */
static int
dentry_reset_needs_extraction(struct wim_dentry *dentry, void *_ignore)
{
	struct wim_inode *inode = dentry->d_inode;

	dentry->in_extraction_tree = 0;
	dentry->extraction_skipped = 0;
	dentry->was_hardlinked = 0;
	dentry->skeleton_extracted = 0;
	inode->i_visited = 0;
	FREE(inode->i_extracted_file);
	inode->i_extracted_file = NULL;
	inode->i_dos_name_extracted = 0;
	if ((void*)dentry->extraction_name != (void*)dentry->file_name)
		FREE(dentry->extraction_name);
	dentry->extraction_name = NULL;
	return 0;
}

/* Tally features necessary to extract a dentry and the corresponding inode.  */
static int
dentry_tally_features(struct wim_dentry *dentry, void *_features)
{
	struct wim_features *features = _features;
	struct wim_inode *inode = dentry->d_inode;

	if (inode->i_attributes & FILE_ATTRIBUTE_ARCHIVE)
		features->archive_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_HIDDEN)
		features->hidden_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_SYSTEM)
		features->system_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_COMPRESSED)
		features->compressed_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED) {
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
			features->encrypted_directories++;
		else
			features->encrypted_files++;
	}
	if (inode->i_attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
		features->not_context_indexed_files++;
	if (inode->i_attributes & FILE_ATTRIBUTE_SPARSE_FILE)
		features->sparse_files++;
	if (inode_has_named_stream(inode))
		features->named_data_streams++;
	if (inode->i_visited)
		features->hard_links++;
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		features->reparse_points++;
		if (inode_is_symlink(inode))
			features->symlink_reparse_points++;
		else
			features->other_reparse_points++;
	}
	if (inode->i_security_id != -1)
		features->security_descriptors++;
	if (dentry->short_name_nbytes)
		features->short_names++;
	if (inode_has_unix_data(inode))
		features->unix_data++;
	inode->i_visited = 1;
	return 0;
}

/* Tally the features necessary to extract a dentry tree.  */
static void
dentry_tree_get_features(struct wim_dentry *root, struct wim_features *features)
{
	memset(features, 0, sizeof(struct wim_features));
	for_dentry_in_tree(root, dentry_tally_features, features);
	dentry_tree_clear_inode_visited(root);
}

static u32
compute_supported_attributes_mask(const struct wim_features *supported_features)
{
	u32 mask = ~(u32)0;

	if (!supported_features->archive_files)
		mask &= ~FILE_ATTRIBUTE_ARCHIVE;

	if (!supported_features->hidden_files)
		mask &= ~FILE_ATTRIBUTE_HIDDEN;

	if (!supported_features->system_files)
		mask &= ~FILE_ATTRIBUTE_SYSTEM;

	if (!supported_features->not_context_indexed_files)
		mask &= ~FILE_ATTRIBUTE_NOT_CONTENT_INDEXED;

	if (!supported_features->compressed_files)
		mask &= ~FILE_ATTRIBUTE_COMPRESSED;

	if (!supported_features->sparse_files)
		mask &= ~FILE_ATTRIBUTE_SPARSE_FILE;

	if (!supported_features->reparse_points)
		mask &= ~FILE_ATTRIBUTE_REPARSE_POINT;

	return mask;
}

static int
do_feature_check(const struct wim_features *required_features,
		 const struct wim_features *supported_features,
		 int extract_flags,
		 const struct apply_operations *ops,
		 const tchar *wim_source_path)
{
	const tchar *loc;
	const tchar *mode = T("this extraction mode");

	if (wim_source_path[0] == '\0')
		loc = T("the WIM image");
	else
		loc = wim_source_path;

	/* We're an archive program, so theoretically we can do what we want
	 * with FILE_ATTRIBUTE_ARCHIVE (which is a dumb flag anyway).  Don't
	 * bother the user about it.  */
#if 0
	if (required_features->archive_files && !supported_features->archive_files)
	{
		WARNING(
          "%lu files in %"TS" are marked as archived, but this attribute\n"
"          is not supported in %"TS".",
			required_features->archive_files, loc, mode);
	}
#endif

	if (required_features->hidden_files && !supported_features->hidden_files)
	{
		WARNING(
          "%lu files in %"TS" are marked as hidden, but this\n"
"          attribute is not supported in %"TS".",
			required_features->hidden_files, loc, mode);
	}

	if (required_features->system_files && !supported_features->system_files)
	{
		WARNING(
          "%lu files in %"TS" are marked as system files,\n"
"          but this attribute is not supported in %"TS".",
			required_features->system_files, loc, mode);
	}

	if (required_features->compressed_files && !supported_features->compressed_files)
	{
		WARNING(
          "%lu files in %"TS" are marked as being transparently\n"
"          compressed, but transparent compression is not supported in\n"
"          %"TS".  These files will be extracted as uncompressed.",
			required_features->compressed_files, loc, mode);
	}

	if (required_features->encrypted_files && !supported_features->encrypted_files)
	{
		WARNING(
          "%lu files in %"TS" are marked as being encrypted,\n"
"           but encryption is not supported in %"TS".  These files\n"
"           will not be extracted.",
			required_features->encrypted_files, loc, mode);
	}

	if (required_features->encrypted_directories &&
	    !supported_features->encrypted_directories)
	{
		WARNING(
          "%lu directories in %"TS" are marked as being encrypted,\n"
"           but encryption is not supported in %"TS".\n"
"           These directories will be extracted as unencrypted.",
			required_features->encrypted_directories, loc, mode);
	}

	if (required_features->not_context_indexed_files &&
	    !supported_features->not_context_indexed_files)
	{
		WARNING(
          "%lu files in %"TS" are marked as not content indexed,\n"
"          but this attribute is not supported in %"TS".",
			required_features->not_context_indexed_files, loc, mode);
	}

	if (required_features->sparse_files && !supported_features->sparse_files)
	{
		WARNING(
          "%lu files in %"TS" are marked as sparse, but creating\n"
"           sparse files is not supported in %"TS".  These files\n"
"           will be extracted as non-sparse.",
			required_features->sparse_files, loc, mode);
	}

	if (required_features->named_data_streams &&
	    !supported_features->named_data_streams)
	{
		WARNING(
          "%lu files in %"TS" contain one or more alternate (named)\n"
"          data streams, which are not supported in %"TS".\n"
"          Alternate data streams will NOT be extracted.",
			required_features->named_data_streams, loc, mode);
	}

	if (unlikely(extract_flags & (WIMLIB_EXTRACT_FLAG_HARDLINK |
				      WIMLIB_EXTRACT_FLAG_SYMLINK)) &&
	    required_features->named_data_streams &&
	    supported_features->named_data_streams)
	{
		WARNING(
          "%lu files in %"TS" contain one or more alternate (named)\n"
"          data streams, which are not supported in linked extraction mode.\n"
"          Alternate data streams will NOT be extracted.",
			required_features->named_data_streams, loc);
	}

	if (required_features->hard_links && !supported_features->hard_links)
	{
		WARNING(
          "%lu files in %"TS" are hard links, but hard links are\n"
"          not supported in %"TS".  Hard links will be extracted as\n"
"          duplicate copies of the linked files.",
			required_features->hard_links, loc, mode);
	}

	if (required_features->reparse_points && !supported_features->reparse_points)
	{
		if (supported_features->symlink_reparse_points) {
			if (required_features->other_reparse_points) {
				WARNING(
          "%lu files in %"TS" are reparse points that are neither\n"
"          symbolic links nor junction points and are not supported in\n"
"          %"TS".  These reparse points will not be extracted.",
					required_features->other_reparse_points, loc,
					mode);
			}
		} else {
			WARNING(
          "%lu files in %"TS" are reparse points, which are\n"
"          not supported in %"TS" and will not be extracted.",
				required_features->reparse_points, loc, mode);
		}
	}

	if (required_features->security_descriptors &&
	    !supported_features->security_descriptors)
	{
		WARNING(
          "%lu files in %"TS" have Windows NT security descriptors,\n"
"          but extracting security descriptors is not supported in\n"
"          %"TS".  No security descriptors will be extracted.",
			required_features->security_descriptors, loc, mode);
	}

	if (required_features->short_names && !supported_features->short_names)
	{
		WARNING(
          "%lu files in %"TS" have short (DOS) names, but\n"
"          extracting short names is not supported in %"TS".\n"
"          Short names will not be extracted.\n",
			required_features->short_names, loc, mode);
	}

	if ((extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) &&
	    required_features->unix_data && !supported_features->unix_data)
	{
		ERROR("Extracting UNIX data is not supported in %"TS, mode);
		return WIMLIB_ERR_UNSUPPORTED;
	}
	if ((extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES) &&
	    required_features->short_names && !supported_features->short_names)
	{
		ERROR("Extracting short names is not supported in %"TS"", mode);
		return WIMLIB_ERR_UNSUPPORTED;
	}
	if ((extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_TIMESTAMPS) &&
	    !ops->set_timestamps)
	{
		ERROR("Extracting timestamps is not supported in %"TS"", mode);
		return WIMLIB_ERR_UNSUPPORTED;
	}
	if (((extract_flags & (WIMLIB_EXTRACT_FLAG_STRICT_ACLS |
			       WIMLIB_EXTRACT_FLAG_UNIX_DATA))
	     == WIMLIB_EXTRACT_FLAG_STRICT_ACLS) &&
	    required_features->security_descriptors &&
	    !supported_features->security_descriptors)
	{
		ERROR("Extracting security descriptors is not supported in %"TS, mode);
		return WIMLIB_ERR_UNSUPPORTED;
	}

	if ((extract_flags & WIMLIB_EXTRACT_FLAG_HARDLINK) &&
	    !supported_features->hard_links)
	{
		ERROR("Hard link extraction mode requested, but "
		      "%"TS" does not support hard links!", mode);
		return WIMLIB_ERR_UNSUPPORTED;
	}

	if ((extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS) &&
	    required_features->symlink_reparse_points &&
	    !(supported_features->symlink_reparse_points ||
	      supported_features->reparse_points))
	{
		ERROR("Extracting symbolic links is not supported in %"TS, mode);
		return WIMLIB_ERR_UNSUPPORTED;
	}

	if ((extract_flags & WIMLIB_EXTRACT_FLAG_SYMLINK) &&
	    !supported_features->symlink_reparse_points)
	{
		ERROR("Symbolic link extraction mode requested, but "
		      "%"TS" does not support symbolic "
		      "links!", mode);
		return WIMLIB_ERR_UNSUPPORTED;
	}
	return 0;
}

static void
do_extract_warnings(struct apply_ctx *ctx)
{
	if (ctx->partial_security_descriptors == 0 &&
	    ctx->no_security_descriptors == 0)
		return;

	WARNING("Extraction to \"%"TS"\" complete, but with one or more warnings:",
		ctx->target);
	if (ctx->partial_security_descriptors != 0) {
		WARNING("- Could only partially set the security descriptor\n"
			"            on %lu files or directories.",
			ctx->partial_security_descriptors);
	}
	if (ctx->no_security_descriptors != 0) {
		WARNING("- Could not set security descriptor at all\n"
			"            on %lu files or directories.",
			ctx->no_security_descriptors);
	}
#ifdef __WIN32__
	WARNING("To fully restore all security descriptors, run the program\n"
		"          with Administrator rights.");
#endif
}

/*
 * extract_tree - Extract a file or directory tree from the currently selected
 *		  WIM image.
 *
 * @wim:	WIMStruct for the WIM file, with the desired image selected
 *		(as wim->current_image).
 *
 * @wim_source_path:
 *		"Canonical" (i.e. no leading or trailing slashes, path
 *		separators WIM_PATH_SEPARATOR) path inside the WIM image to
 *		extract.  An empty string means the full image.
 *
 * @target:
 *		Filesystem path to extract the file or directory tree to.
 *		(Or, with WIMLIB_EXTRACT_FLAG_NTFS: the name of a NTFS volume.)
 *
 * @extract_flags:
 *		WIMLIB_EXTRACT_FLAG_*.  Also, the private flag
 *		WIMLIB_EXTRACT_FLAG_MULTI_IMAGE will be set if this is being
 *		called through wimlib_extract_image() with WIMLIB_ALL_IMAGES as
 *		the image.
 *
 * @progress_func:
 *		If non-NULL, progress function for the extraction.  The messages
 *		that may be sent in this function are:
 *
 *		WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN or
 *			WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS;
 *		WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END or
 *			WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END.
 *
 * Returns 0 on success; a positive WIMLIB_ERR_* code on failure.
 */
static int
extract_tree(WIMStruct *wim, const tchar *wim_source_path, const tchar *target,
	     int extract_flags, wimlib_progress_func_t progress_func)
{
	struct wim_dentry *root;
	struct wim_features required_features;
	struct apply_ctx ctx;
	int ret;
	struct wim_lookup_table_entry *lte;

	/* Start initializing the apply_ctx.  */
	memset(&ctx, 0, sizeof(struct apply_ctx));
	ctx.wim = wim;
	ctx.extract_flags = extract_flags;
	ctx.target = target;
	ctx.target_nchars = tstrlen(target);
	ctx.progress_func = progress_func;
	if (progress_func) {
		ctx.progress.extract.wimfile_name = wim->filename;
		ctx.progress.extract.image = wim->current_image;
		ctx.progress.extract.extract_flags = (extract_flags &
						      WIMLIB_EXTRACT_MASK_PUBLIC);
		ctx.progress.extract.image_name = wimlib_get_image_name(wim,
									wim->current_image);
		ctx.progress.extract.extract_root_wim_source_path = wim_source_path;
		ctx.progress.extract.target = target;
	}
	INIT_LIST_HEAD(&ctx.stream_list);

	/* Translate the path to extract into the corresponding
	 * `struct wim_dentry', which will be the root of the
	 * "dentry tree" to extract.  */
	root = get_dentry(wim, wim_source_path);
	if (!root) {
		ERROR("Path \"%"TS"\" does not exist in WIM image %d",
		      wim_source_path, wim->current_image);
		ret = WIMLIB_ERR_PATH_DOES_NOT_EXIST;
		goto out;
	}

	ctx.extract_root = root;

	/* Select the appropriate apply_operations based on the
	 * platform and extract_flags.  */
#ifdef __WIN32__
	ctx.ops = &win32_apply_ops;
#else
	ctx.ops = &unix_apply_ops;
#endif

#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS)
		ctx.ops = &ntfs_3g_apply_ops;
#endif

	/* Call the start_extract() callback.  This gives the apply_operations
	 * implementation a chance to do any setup needed to access the volume.
	 * Furthermore, it's expected to set the supported features of this
	 * extraction mode (ctx.supported_features), which are determined at
	 * runtime as they may vary depending on the actual volume.  These
	 * features are then compared with the actual features extracting this
	 * dentry tree requires.  Some mismatches will merely produce warnings
	 * and the unsupported data will be ignored; others will produce errors.
	 */
	ret = ctx.ops->start_extract(target, &ctx);
	if (ret)
		goto out;

	dentry_tree_get_features(root, &required_features);
	ret = do_feature_check(&required_features, &ctx.supported_features,
			       extract_flags, ctx.ops, wim_source_path);
	if (ret)
		goto out_finish_or_abort_extract;

	ctx.supported_attributes_mask =
		compute_supported_attributes_mask(&ctx.supported_features);

	/* Figure out whether the root dentry is being extracted to the root of
	 * a volume and therefore needs to be treated "specially", for example
	 * not being explicitly created and not having attributes set.  */
	if (ctx.ops->target_is_root && ctx.ops->root_directory_is_special)
		ctx.root_dentry_is_special = ctx.ops->target_is_root(target);

	/* Calculate the actual filename component of each extracted dentry.  In
	 * the process, set the dentry->extraction_skipped flag on dentries that
	 * are being skipped for some reason (e.g. invalid filename).  */
	ret = for_dentry_in_tree(root, dentry_calculate_extraction_path, &ctx);
	if (ret)
		goto out_dentry_reset_needs_extraction;

	/* Build the list of the streams that need to be extracted and
	 * initialize ctx.progress.extract with stream information.  */
	ret = for_dentry_in_tree(ctx.extract_root,
				 dentry_resolve_and_zero_lte_refcnt, &ctx);
	if (ret)
		goto out_dentry_reset_needs_extraction;

	ret = for_dentry_in_tree(ctx.extract_root,
				 dentry_add_streams_to_extract, &ctx);
	if (ret)
		goto out_teardown_stream_list;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_FROM_PIPE) {
		/* When extracting from a pipe, the number of bytes of data to
		 * extract can't be determined in the normal way (examining the
		 * lookup table), since at this point all we have is a set of
		 * SHA1 message digests of streams that need to be extracted.
		 * However, we can get a reasonably accurate estimate by taking
		 * <TOTALBYTES> from the corresponding <IMAGE> in the WIM XML
		 * data.  This does assume that a full image is being extracted,
		 * but currently there is no API for doing otherwise.  (Also,
		 * subtract <HARDLINKBYTES> from this if hard links are
		 * supported by the extraction mode.)  */
		ctx.progress.extract.total_bytes =
			wim_info_get_image_total_bytes(wim->wim_info,
						       wim->current_image);
		if (ctx.supported_features.hard_links) {
			ctx.progress.extract.total_bytes -=
				wim_info_get_image_hard_link_bytes(wim->wim_info,
								   wim->current_image);
		}
	}

	/* Handle the special case of extracting a file to standard
	 * output.  In that case, "root" should be a single file, not a
	 * directory tree.  (If not, extract_dentry_to_stdout() will
	 * return an error.)  */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_TO_STDOUT) {
		ret = extract_dentry_to_stdout(root);
		goto out_teardown_stream_list;
	}

	if (ctx.ops->realpath_works_on_nonexisting_files &&
	    ((extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX) ||
	     ctx.ops->requires_realtarget_in_paths))
	{
		ctx.realtarget = realpath(target, NULL);
		if (!ctx.realtarget) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_teardown_stream_list;
		}
		ctx.realtarget_nchars = tstrlen(ctx.realtarget);
	}

	if (progress_func) {
		progress_func(*wim_source_path ? WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN :
						 WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN,
			      &ctx.progress);
	}

	if (!ctx.root_dentry_is_special)
	{
		tchar path[ctx.ops->path_max];
		if (build_extraction_path(path, root, &ctx))
		{
			ret = extract_inode(path, &ctx, root->d_inode);
			if (ret)
				goto out_free_realtarget;
		}
	}

	/* If we need to fix up the targets of absolute symbolic links
	 * (WIMLIB_EXTRACT_FLAG_RPFIX) or the extraction mode requires paths to
	 * be absolute, use realpath() (or its replacement on Windows) to get
	 * the absolute path to the extraction target.  Note that this requires
	 * the target directory to exist, unless
	 * realpath_works_on_nonexisting_files is set in the apply_operations.
	 * */
	if (!ctx.realtarget &&
	    (((extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX) &&
	      required_features.symlink_reparse_points) ||
	     ctx.ops->requires_realtarget_in_paths))
	{
		ctx.realtarget = realpath(target, NULL);
		if (!ctx.realtarget) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_realtarget;
		}
		ctx.realtarget_nchars = tstrlen(ctx.realtarget);
	}

	if (ctx.ops->requires_short_name_reordering) {
		ret = for_dentry_in_tree(root, dentry_extract_dir_skeleton,
					 &ctx);
		if (ret)
			goto out_free_realtarget;
	}

	/* Finally, the important part: extract the tree of files.  */
	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SEQUENTIAL |
			     WIMLIB_EXTRACT_FLAG_FROM_PIPE)) {
		/* Sequential extraction requested, so two passes are needed
		 * (one for directory structure, one for streams.)  */
		if (progress_func)
			progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,
				      &ctx.progress);

		if (!(extract_flags & WIMLIB_EXTRACT_FLAG_RESUME)) {
			ret = for_dentry_in_tree(root, dentry_extract_skeleton, &ctx);
			if (ret)
				goto out_free_realtarget;
		}
		if (progress_func)
			progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,
				      &ctx.progress);
		if (extract_flags & WIMLIB_EXTRACT_FLAG_FROM_PIPE)
			ret = extract_streams_from_pipe(&ctx);
		else
			ret = extract_stream_list(&ctx);
		if (ret)
			goto out_free_realtarget;
	} else {
		/* Sequential extraction was not requested, so we can make do
		 * with one pass where we both create the files and extract
		 * streams.   */
		if (progress_func)
			progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,
				      &ctx.progress);
		ret = for_dentry_in_tree(root, dentry_extract, &ctx);
		if (ret)
			goto out_free_realtarget;
		if (progress_func)
			progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,
				      &ctx.progress);
	}

	/* If the total number of bytes to extract was miscalculated, just jump
	 * to the calculated number in order to avoid confusing the progress
	 * function.  This should only occur when extracting from a pipe.  */
	if (ctx.progress.extract.completed_bytes != ctx.progress.extract.total_bytes)
	{
		DEBUG("Calculated %"PRIu64" bytes to extract, but actually "
		      "extracted %"PRIu64,
		      ctx.progress.extract.total_bytes,
		      ctx.progress.extract.completed_bytes);
	}
	if (progress_func &&
	    ctx.progress.extract.completed_bytes < ctx.progress.extract.total_bytes)
	{
		ctx.progress.extract.completed_bytes = ctx.progress.extract.total_bytes;
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS, &ctx.progress);
	}

	/* Apply security descriptors and timestamps.  This is done at the end,
	 * and in a depth-first manner, to prevent timestamps from getting
	 * changed by subsequent extract operations and to minimize the chance
	 * of the restored security descriptors getting in our way.  */
	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS,
			      &ctx.progress);
	ret = for_dentry_in_tree_depth(root, dentry_extract_final, &ctx);
	if (ret)
		goto out_free_realtarget;

	if (progress_func) {
		progress_func(*wim_source_path ? WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END :
			      WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END,
			      &ctx.progress);
	}

	do_extract_warnings(&ctx);

	ret = 0;
out_free_realtarget:
	FREE(ctx.realtarget);
out_teardown_stream_list:
	/* Free memory allocated as part of the mapping from each
	 * wim_lookup_table_entry to the dentries that reference it.  */
	if (ctx.extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL)
		list_for_each_entry(lte, &ctx.stream_list, extraction_list)
			if (lte->out_refcnt > ARRAY_LEN(lte->inline_lte_dentries))
				FREE(lte->lte_dentries);
out_dentry_reset_needs_extraction:
	for_dentry_in_tree(root, dentry_reset_needs_extraction, NULL);
out_finish_or_abort_extract:
	if (ret) {
		if (ctx.ops->abort_extract)
			ctx.ops->abort_extract(&ctx);
	} else {
		if (ctx.ops->finish_extract)
			ret = ctx.ops->finish_extract(&ctx);
	}
out:
	return ret;
}

/* Validates a single wimlib_extract_command, mostly checking to make sure the
 * extract flags make sense. */
static int
check_extract_command(struct wimlib_extract_command *cmd, int wim_header_flags)
{
	int extract_flags;

	/* Empty destination path? */
	if (cmd->fs_dest_path[0] == T('\0'))
		return WIMLIB_ERR_INVALID_PARAM;

	extract_flags = cmd->extract_flags;

	/* Check for invalid flag combinations  */
	if ((extract_flags &
	     (WIMLIB_EXTRACT_FLAG_SYMLINK |
	      WIMLIB_EXTRACT_FLAG_HARDLINK)) == (WIMLIB_EXTRACT_FLAG_SYMLINK |
						 WIMLIB_EXTRACT_FLAG_HARDLINK))
		return WIMLIB_ERR_INVALID_PARAM;

	if ((extract_flags &
	     (WIMLIB_EXTRACT_FLAG_NO_ACLS |
	      WIMLIB_EXTRACT_FLAG_STRICT_ACLS)) == (WIMLIB_EXTRACT_FLAG_NO_ACLS |
						    WIMLIB_EXTRACT_FLAG_STRICT_ACLS))
		return WIMLIB_ERR_INVALID_PARAM;

	if ((extract_flags &
	     (WIMLIB_EXTRACT_FLAG_RPFIX |
	      WIMLIB_EXTRACT_FLAG_NORPFIX)) == (WIMLIB_EXTRACT_FLAG_RPFIX |
						WIMLIB_EXTRACT_FLAG_NORPFIX))
		return WIMLIB_ERR_INVALID_PARAM;

	if ((extract_flags &
	     (WIMLIB_EXTRACT_FLAG_RESUME |
	      WIMLIB_EXTRACT_FLAG_FROM_PIPE)) == WIMLIB_EXTRACT_FLAG_RESUME)
		return WIMLIB_ERR_INVALID_PARAM;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
#ifndef WITH_NTFS_3G
		ERROR("wimlib was compiled without support for NTFS-3g, so\n"
		      "        we cannot apply a WIM image directly to a NTFS volume.");
		return WIMLIB_ERR_UNSUPPORTED;
#endif
	}

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_RPFIX |
			      WIMLIB_EXTRACT_FLAG_NORPFIX)) == 0)
	{
		/* Do reparse point fixups by default if the WIM header says
		 * they are enabled and we are extracting a full image. */
		if (wim_header_flags & WIM_HDR_FLAG_RP_FIX)
			extract_flags |= WIMLIB_EXTRACT_FLAG_RPFIX;
	}

	/* TODO: Since UNIX data entries are stored in the file resources, in a
	 * completely sequential extraction they may come up before the
	 * corresponding file or symbolic link data.  This needs to be handled
	 * better.  */
	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_UNIX_DATA |
			      WIMLIB_EXTRACT_FLAG_SEQUENTIAL))
				    == (WIMLIB_EXTRACT_FLAG_UNIX_DATA |
					WIMLIB_EXTRACT_FLAG_SEQUENTIAL))
	{
		if (extract_flags & WIMLIB_EXTRACT_FLAG_FROM_PIPE) {
			WARNING("Setting UNIX file/owner group may "
				"be impossible on some\n"
				"          symbolic links "
				"when applying from a pipe.");
		} else {
			extract_flags &= ~WIMLIB_EXTRACT_FLAG_SEQUENTIAL;
			WARNING("Disabling sequential extraction for "
				"UNIX data mode");
		}
	}

	cmd->extract_flags = extract_flags;
	return 0;
}


/* Internal function to execute extraction commands for a WIM image.  The paths
 * in the extract commands are expected to be already "canonicalized".  */
static int
do_wimlib_extract_files(WIMStruct *wim,
			int image,
			struct wimlib_extract_command *cmds,
			size_t num_cmds,
			wimlib_progress_func_t progress_func)
{
	int ret;
	bool found_link_cmd = false;
	bool found_nolink_cmd = false;

	/* Select the image from which we are extracting files */
	ret = select_wim_image(wim, image);
	if (ret)
		return ret;

	/* Make sure there are no streams in the WIM that have not been
	 * checksummed yet.  */
	ret = wim_checksum_unhashed_streams(wim);
	if (ret)
		return ret;

	/* Check for problems with the extraction commands */
	for (size_t i = 0; i < num_cmds; i++) {
		ret = check_extract_command(&cmds[i], wim->hdr.flags);
		if (ret)
			return ret;
		if (cmds[i].extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
					     WIMLIB_EXTRACT_FLAG_HARDLINK)) {
			found_link_cmd = true;
		} else {
			found_nolink_cmd = true;
		}
		if (found_link_cmd && found_nolink_cmd) {
			ERROR("Symlink or hardlink extraction mode must "
			      "be set on all extraction commands");
			return WIMLIB_ERR_INVALID_PARAM;
		}
	}

	/* Execute the extraction commands */
	for (size_t i = 0; i < num_cmds; i++) {
		ret = extract_tree(wim,
				   cmds[i].wim_source_path,
				   cmds[i].fs_dest_path,
				   cmds[i].extract_flags,
				   progress_func);
		if (ret)
			return ret;
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_extract_files(WIMStruct *wim,
		     int image,
		     const struct wimlib_extract_command *cmds,
		     size_t num_cmds,
		     int default_extract_flags,
		     wimlib_progress_func_t progress_func)
{
	int ret;
	struct wimlib_extract_command *cmds_copy;
	int all_flags = 0;

	default_extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	if (num_cmds == 0)
		return 0;

	cmds_copy = CALLOC(num_cmds, sizeof(cmds[0]));
	if (!cmds_copy)
		return WIMLIB_ERR_NOMEM;

	for (size_t i = 0; i < num_cmds; i++) {
		cmds_copy[i].extract_flags = (default_extract_flags |
						 cmds[i].extract_flags)
						& WIMLIB_EXTRACT_MASK_PUBLIC;
		all_flags |= cmds_copy[i].extract_flags;

		cmds_copy[i].wim_source_path = canonicalize_wim_path(cmds[i].wim_source_path);
		if (!cmds_copy[i].wim_source_path) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_cmds_copy;
		}

		cmds_copy[i].fs_dest_path = canonicalize_fs_path(cmds[i].fs_dest_path);
		if (!cmds_copy[i].fs_dest_path) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_cmds_copy;
		}

	}
	ret = do_wimlib_extract_files(wim, image,
				      cmds_copy, num_cmds,
				      progress_func);

	if (all_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			 WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(wim->lookup_table,
				       lte_free_extracted_file, NULL);
	}
out_free_cmds_copy:
	for (size_t i = 0; i < num_cmds; i++) {
		FREE(cmds_copy[i].wim_source_path);
		FREE(cmds_copy[i].fs_dest_path);
	}
	FREE(cmds_copy);
	return ret;
}

/*
 * Extracts an image from a WIM file.
 *
 * @wim:		WIMStruct for the WIM file.
 *
 * @image:		Number of the single image to extract.
 *
 * @target:		Directory or NTFS volume to extract the image to.
 *
 * @extract_flags:	Bitwise or of WIMLIB_EXTRACT_FLAG_*.
 *
 * @progress_func:	If non-NULL, a progress function to be called
 *			periodically.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
extract_single_image(WIMStruct *wim, int image,
		     const tchar *target, int extract_flags,
		     wimlib_progress_func_t progress_func)
{
	int ret;
	tchar *target_copy = canonicalize_fs_path(target);
	if (target_copy == NULL)
		return WIMLIB_ERR_NOMEM;
	struct wimlib_extract_command cmd = {
		.wim_source_path = T(""),
		.fs_dest_path = target_copy,
		.extract_flags = extract_flags,
	};
	ret = do_wimlib_extract_files(wim, image, &cmd, 1, progress_func);
	FREE(target_copy);
	return ret;
}

static const tchar * const filename_forbidden_chars =
T(
#ifdef __WIN32__
"<>:\"/\\|?*"
#else
"/"
#endif
);

/* This function checks if it is okay to use a WIM image's name as a directory
 * name.  */
static bool
image_name_ok_as_dir(const tchar *image_name)
{
	return image_name && *image_name &&
		!tstrpbrk(image_name, filename_forbidden_chars) &&
		tstrcmp(image_name, T(".")) &&
		tstrcmp(image_name, T(".."));
}

/* Extracts all images from the WIM to the directory @target, with the images
 * placed in subdirectories named by their image names. */
static int
extract_all_images(WIMStruct *wim,
		   const tchar *target,
		   int extract_flags,
		   wimlib_progress_func_t progress_func)
{
	size_t image_name_max_len = max(xml_get_max_image_name_len(wim), 20);
	size_t output_path_len = tstrlen(target);
	tchar buf[output_path_len + 1 + image_name_max_len + 1];
	int ret;
	int image;
	const tchar *image_name;
	struct stat stbuf;

	extract_flags |= WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		ERROR("Cannot extract multiple images in NTFS extraction mode.");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (tstat(target, &stbuf)) {
		if (errno == ENOENT) {
			if (tmkdir(target, 0755)) {
				ERROR_WITH_ERRNO("Failed to create directory \"%"TS"\"", target);
				return WIMLIB_ERR_MKDIR;
			}
		} else {
			ERROR_WITH_ERRNO("Failed to stat \"%"TS"\"", target);
			return WIMLIB_ERR_STAT;
		}
	} else if (!S_ISDIR(stbuf.st_mode)) {
		ERROR("\"%"TS"\" is not a directory", target);
		return WIMLIB_ERR_NOTDIR;
	}

	tmemcpy(buf, target, output_path_len);
	buf[output_path_len] = OS_PREFERRED_PATH_SEPARATOR;
	for (image = 1; image <= wim->hdr.image_count; image++) {
		image_name = wimlib_get_image_name(wim, image);
		if (image_name_ok_as_dir(image_name)) {
			tstrcpy(buf + output_path_len + 1, image_name);
		} else {
			/* Image name is empty or contains forbidden characters.
			 * Use image number instead. */
			tsprintf(buf + output_path_len + 1, T("%d"), image);
		}
		ret = extract_single_image(wim, image, buf, extract_flags,
					   progress_func);
		if (ret)
			return ret;
	}
	return 0;
}

static int
do_wimlib_extract_image(WIMStruct *wim,
			int image,
			const tchar *target,
			int extract_flags,
			wimlib_progress_func_t progress_func)
{
	int ret;

	if (image == WIMLIB_ALL_IMAGES) {
		ret = extract_all_images(wim, target, extract_flags,
					 progress_func);
	} else {
		ret = extract_single_image(wim, image, target, extract_flags,
					   progress_func);
	}

	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(wim->lookup_table,
				       lte_free_extracted_file,
				       NULL);
	}
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_extract_image_from_pipe(int pipe_fd, const tchar *image_num_or_name,
			       const tchar *target, int extract_flags,
			       wimlib_progress_func_t progress_func)
{
	int ret;
	WIMStruct *pwm;
	struct filedes *in_fd;
	int image;
	unsigned i;

	extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_TO_STDOUT)
		return WIMLIB_ERR_INVALID_PARAM;

	extract_flags |= WIMLIB_EXTRACT_FLAG_SEQUENTIAL;

	/* Read the WIM header from the pipe and get a WIMStruct to represent
	 * the pipable WIM.  Caveats:  Unlike getting a WIMStruct with
	 * wimlib_open_wim(), getting a WIMStruct in this way will result in
	 * an empty lookup table, no XML data read, and no filename set.  */
	ret = open_wim_as_WIMStruct(&pipe_fd,
				    WIMLIB_OPEN_FLAG_FROM_PIPE,
				    &pwm, progress_func);
	if (ret)
		return ret;

	/* Sanity check to make sure this is a pipable WIM.  */
	if (pwm->hdr.magic != PWM_MAGIC) {
		ERROR("The WIM being read from file descriptor %d "
		      "is not pipable!", pipe_fd);
		ret = WIMLIB_ERR_NOT_PIPABLE;
		goto out_wimlib_free;
	}

	/* Sanity check to make sure the first part of a pipable split WIM is
	 * sent over the pipe first.  */
	if (pwm->hdr.part_number != 1) {
		ERROR("The first part of the split WIM must be "
		      "sent over the pipe first.");
		ret = WIMLIB_ERR_INVALID_PIPABLE_WIM;
		goto out_wimlib_free;
	}

	in_fd = &pwm->in_fd;
	wimlib_assert(in_fd->offset == WIM_HEADER_DISK_SIZE);

	/* As mentioned, the WIMStruct we created from the pipe does not have
	 * XML data yet.  Fix this by reading the extra copy of the XML data
	 * that directly follows the header in pipable WIMs.  (Note: see
	 * write_pipable_wim() for more details about the format of pipable
	 * WIMs.)  */
	{
		struct wim_lookup_table_entry xml_lte;
		struct wim_resource_spec xml_rspec;
		ret = read_pwm_stream_header(pwm, &xml_lte, &xml_rspec, 0, NULL);
		if (ret)
			goto out_wimlib_free;

		if (!(xml_lte.flags & WIM_RESHDR_FLAG_METADATA))
		{
			ERROR("Expected XML data, but found non-metadata "
			      "stream.");
			ret = WIMLIB_ERR_INVALID_PIPABLE_WIM;
			goto out_wimlib_free;
		}

		wim_res_spec_to_hdr(&xml_rspec, &pwm->hdr.xml_data_reshdr);

		ret = read_wim_xml_data(pwm);
		if (ret)
			goto out_wimlib_free;

		if (wim_info_get_num_images(pwm->wim_info) != pwm->hdr.image_count) {
			ERROR("Image count in XML data is not the same as in WIM header.");
			ret = WIMLIB_ERR_XML;
			goto out_wimlib_free;
		}
	}

	/* Get image index (this may use the XML data that was just read to
	 * resolve an image name).  */
	if (image_num_or_name) {
		image = wimlib_resolve_image(pwm, image_num_or_name);
		if (image == WIMLIB_NO_IMAGE) {
			ERROR("\"%"TS"\" is not a valid image in the pipable WIM!",
			      image_num_or_name);
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out_wimlib_free;
		} else if (image == WIMLIB_ALL_IMAGES) {
			ERROR("Applying all images from a pipe is not supported.");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out_wimlib_free;
		}
	} else {
		if (pwm->hdr.image_count != 1) {
			ERROR("No image was specified, but the pipable WIM "
			      "did not contain exactly 1 image");
			ret = WIMLIB_ERR_INVALID_IMAGE;
			goto out_wimlib_free;
		}
		image = 1;
	}

	/* Load the needed metadata resource.  */
	for (i = 1; i <= pwm->hdr.image_count; i++) {
		struct wim_lookup_table_entry *metadata_lte;
		struct wim_image_metadata *imd;
		struct wim_resource_spec *metadata_rspec;

		metadata_lte = new_lookup_table_entry();
		if (metadata_lte == NULL) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_wimlib_free;
		}
		metadata_rspec = MALLOC(sizeof(struct wim_resource_spec));
		if (metadata_rspec == NULL) {
			ret = WIMLIB_ERR_NOMEM;
			free_lookup_table_entry(metadata_lte);
			goto out_wimlib_free;
		}

		ret = read_pwm_stream_header(pwm, metadata_lte, metadata_rspec, 0, NULL);
		imd = pwm->image_metadata[i - 1];
		imd->metadata_lte = metadata_lte;
		if (ret) {
			FREE(metadata_rspec);
			goto out_wimlib_free;
		}

		if (!(metadata_lte->flags & WIM_RESHDR_FLAG_METADATA)) {
			ERROR("Expected metadata resource, but found "
			      "non-metadata stream.");
			ret = WIMLIB_ERR_INVALID_PIPABLE_WIM;
			goto out_wimlib_free;
		}

		if (i == image) {
			/* Metadata resource is for the images being extracted.
			 * Parse it and save the metadata in memory.  */
			ret = read_metadata_resource(pwm, imd);
			if (ret)
				goto out_wimlib_free;
			imd->modified = 1;
		} else {
			/* Metadata resource is not for the image being
			 * extracted.  Skip over it.  */
			ret = skip_wim_stream(metadata_lte);
			if (ret)
				goto out_wimlib_free;
		}
	}
	/* Extract the image.  */
	extract_flags |= WIMLIB_EXTRACT_FLAG_FROM_PIPE;
	ret = do_wimlib_extract_image(pwm, image, target,
				      extract_flags, progress_func);
	/* Clean up and return.  */
out_wimlib_free:
	wimlib_free(pwm);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_extract_image(WIMStruct *wim,
		     int image,
		     const tchar *target,
		     int extract_flags,
		     wimlib_progress_func_t progress_func)
{
	extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;
	return do_wimlib_extract_image(wim, image, target, extract_flags,
				       progress_func);
}
