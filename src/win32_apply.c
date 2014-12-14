/*
 * win32_apply.c - Windows-specific code for applying files from a WIM image.
 */

/*
 * Copyright (C) 2013, 2014 Eric Biggers
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

#ifdef __WIN32__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/win32_common.h"

#include "wimlib/apply.h"
#include "wimlib/capture.h" /* for mangle_pat() and match_pattern_list()  */
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/reparse.h"
#include "wimlib/textfile.h"
#include "wimlib/xml.h"
#include "wimlib/wildcard.h"
#include "wimlib/wimboot.h"

struct win32_apply_ctx {

	/* Extract flags, the pointer to the WIMStruct, etc.  */
	struct apply_ctx common;

	/* WIMBoot information, only filled in if WIMLIB_EXTRACT_FLAG_WIMBOOT
	 * was provided  */
	struct {
		u64 data_source_id;
		struct string_set *prepopulate_pats;
		void *mem_prepopulate_pats;
		u8 wim_lookup_table_hash[SHA1_HASH_SIZE];
		bool wof_running;
		bool tried_to_load_prepopulate_list;
	} wimboot;

	/* Open handle to the target directory  */
	HANDLE h_target;

	/* NT namespace path to the target directory (buffer allocated)  */
	UNICODE_STRING target_ntpath;

	/* Temporary buffer for building paths (buffer allocated)  */
	UNICODE_STRING pathbuf;

	/* Object attributes to reuse for opening files in the target directory.
	 * (attr.ObjectName == &pathbuf) and (attr.RootDirectory == h_target).
	 */
	OBJECT_ATTRIBUTES attr;

	/* Temporary I/O status block for system calls  */
	IO_STATUS_BLOCK iosb;

	/* Allocated buffer for creating "printable" paths from our
	 * target-relative NT paths  */
	wchar_t *print_buffer;

	/* Allocated buffer for reading stream data when it cannot be extracted
	 * directly  */
	u8 *data_buffer;

	/* Pointer to the next byte in @data_buffer to fill  */
	u8 *data_buffer_ptr;

	/* Size allocated in @data_buffer  */
	size_t data_buffer_size;

	/* Current offset in the raw encrypted file being written  */
	size_t encrypted_offset;

	/* Current size of the raw encrypted file being written  */
	size_t encrypted_size;

	/* Temporary buffer for reparse data  */
	struct reparse_buffer_disk rpbuf;

	/* Temporary buffer for reparse data of "fixed" absolute symbolic links
	 * and junctions  */
	struct reparse_buffer_disk rpfixbuf;

	/* Array of open handles to filesystem streams currently being written
	 */
	HANDLE open_handles[MAX_OPEN_STREAMS];

	/* Number of handles in @open_handles currently open (filled in from the
	 * beginning of the array)  */
	unsigned num_open_handles;

	/* List of dentries, joined by @tmp_list, that need to have reparse data
	 * extracted as soon as the whole stream has been read into
	 * @data_buffer.  */
	struct list_head reparse_dentries;

	/* List of dentries, joined by @tmp_list, that need to have raw
	 * encrypted data extracted as soon as the whole stream has been read
	 * into @data_buffer.  */
	struct list_head encrypted_dentries;

	/* Number of files for which we didn't have permission to set the full
	 * security descriptor.  */
	unsigned long partial_security_descriptors;

	/* Number of files for which we didn't have permission to set any part
	 * of the security descriptor.  */
	unsigned long no_security_descriptors;

	/* Number of files for which we couldn't set the short name.  */
	unsigned long num_set_short_name_failures;

	/* Number of files for which we couldn't remove the short name.  */
	unsigned long num_remove_short_name_failures;

	/* Have we tried to enable short name support on the target volume yet?
	 */
	bool tried_to_enable_short_names;
};

/* Get the drive letter from a Windows path, or return the null character if the
 * path is relative.  */
static wchar_t
get_drive_letter(const wchar_t *path)
{
	/* Skip \\?\ prefix  */
	if (!wcsncmp(path, L"\\\\?\\", 4))
		path += 4;

	/* Return drive letter if valid  */
	if (((path[0] >= L'a' && path[0] <= L'z') ||
	     (path[0] >= L'A' && path[0] <= L'Z')) && path[1] == L':')
		return path[0];

	return L'\0';
}

static void
get_vol_flags(const wchar_t *target, DWORD *vol_flags_ret,
	      bool *short_names_supported_ret)
{
	wchar_t filesystem_name[MAX_PATH + 1];
	wchar_t drive[4];
	wchar_t *volume = NULL;

	*vol_flags_ret = 0;
	*short_names_supported_ret = false;

	drive[0] = get_drive_letter(target);
	if (drive[0]) {
		drive[1] = L':';
		drive[2] = L'\\';
		drive[3] = L'\0';
		volume = drive;
	}

	if (!GetVolumeInformation(volume, NULL, 0, NULL, NULL,
				  vol_flags_ret, filesystem_name,
				  ARRAY_LEN(filesystem_name)))
	{
		DWORD err = GetLastError();
		set_errno_from_win32_error(err);
		WARNING_WITH_ERRNO("Failed to get volume information for "
				   "\"%ls\" (err=%"PRIu32")",
				   target, (u32)err);
		return;
	}

	if (wcsstr(filesystem_name, L"NTFS")) {
		/* FILE_SUPPORTS_HARD_LINKS is only supported on Windows 7 and
		 * later.  Force it on anyway if filesystem is NTFS.  */
		*vol_flags_ret |= FILE_SUPPORTS_HARD_LINKS;

		/* There's no volume flag for short names, but according to the
		 * MS documentation they are only user-settable on NTFS.  */
		*short_names_supported_ret = true;
	}
}

static const wchar_t *
current_path(struct win32_apply_ctx *ctx);

static void
build_extraction_path(const struct wim_dentry *dentry,
		      struct win32_apply_ctx *ctx);

static int
report_dentry_apply_error(const struct wim_dentry *dentry,
			  struct win32_apply_ctx *ctx, int ret)
{
	build_extraction_path(dentry, ctx);
	return report_apply_error(&ctx->common, ret, current_path(ctx));
}

static inline int
check_apply_error(const struct wim_dentry *dentry,
		  struct win32_apply_ctx *ctx, int ret)
{
	if (unlikely(ret))
		ret = report_dentry_apply_error(dentry, ctx, ret);
	return ret;
}

static int
win32_get_supported_features(const wchar_t *target,
			     struct wim_features *supported_features)
{
	DWORD vol_flags;
	bool short_names_supported;

	/* Query the features of the target volume.  */

	get_vol_flags(target, &vol_flags, &short_names_supported);

	supported_features->archive_files = 1;
	supported_features->hidden_files = 1;
	supported_features->system_files = 1;

	if (vol_flags & FILE_FILE_COMPRESSION)
		supported_features->compressed_files = 1;

	if (vol_flags & FILE_SUPPORTS_ENCRYPTION) {
		supported_features->encrypted_files = 1;
		supported_features->encrypted_directories = 1;
	}

	supported_features->not_context_indexed_files = 1;

	/* Don't do anything with FILE_SUPPORTS_SPARSE_FILES.  */

	if (vol_flags & FILE_NAMED_STREAMS)
		supported_features->named_data_streams = 1;

	if (vol_flags & FILE_SUPPORTS_HARD_LINKS)
		supported_features->hard_links = 1;

	if (vol_flags & FILE_SUPPORTS_REPARSE_POINTS)
		supported_features->reparse_points = 1;

	if (vol_flags & FILE_PERSISTENT_ACLS)
		supported_features->security_descriptors = 1;

	if (short_names_supported)
		supported_features->short_names = 1;

	supported_features->timestamps = 1;

	/* Note: Windows does not support case sensitive filenames!  At least
	 * not without changing the registry and rebooting...  */

	return 0;
}

/* Load the patterns from [PrepopulateList] of WimBootCompress.ini in the WIM
 * image being extracted.  */
static int
load_prepopulate_pats(struct win32_apply_ctx *ctx)
{
	const wchar_t *path = L"\\Windows\\System32\\WimBootCompress.ini";
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	int ret;
	void *buf;
	struct string_set *s;
	void *mem;
	struct text_file_section sec;

	ctx->wimboot.tried_to_load_prepopulate_list = true;

	dentry = get_dentry(ctx->common.wim, path, WIMLIB_CASE_INSENSITIVE);
	if (!dentry ||
	    (dentry->d_inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
					      FILE_ATTRIBUTE_REPARSE_POINT |
					      FILE_ATTRIBUTE_ENCRYPTED)) ||
	    !(lte = inode_unnamed_lte(dentry->d_inode, ctx->common.wim->lookup_table)))
	{
		WARNING("%ls does not exist in WIM image!", path);
		return WIMLIB_ERR_PATH_DOES_NOT_EXIST;
	}

	ret = read_full_stream_into_alloc_buf(lte, &buf);
	if (ret)
		return ret;

	s = CALLOC(1, sizeof(struct string_set));
	if (!s) {
		FREE(buf);
		return WIMLIB_ERR_NOMEM;
	}

	sec.name = T("PrepopulateList");
	sec.strings = s;

	ret = do_load_text_file(path, buf, lte->size, &mem, &sec, 1,
				LOAD_TEXT_FILE_REMOVE_QUOTES |
					LOAD_TEXT_FILE_NO_WARNINGS,
				mangle_pat);
	BUILD_BUG_ON(OS_PREFERRED_PATH_SEPARATOR != WIM_PATH_SEPARATOR);
	FREE(buf);
	if (ret) {
		FREE(s);
		return ret;
	}
	ctx->wimboot.prepopulate_pats = s;
	ctx->wimboot.mem_prepopulate_pats = mem;
	return 0;
}

/* Returns %true if the specified absolute path to a file in the WIM image
 * matches a pattern in [PrepopulateList] of WimBootCompress.ini.  Otherwise
 * returns %false.  */
static bool
in_prepopulate_list(const wchar_t *path, size_t path_nchars,
		    const struct win32_apply_ctx *ctx)
{
	const struct string_set *pats = ctx->wimboot.prepopulate_pats;

	if (!pats || !pats->num_strings)
		return false;

	return match_pattern_list(path, path_nchars, pats);
}

/* Returns %true if the specified absolute path to a file in the WIM image can
 * be subject to external backing when extracted.  Otherwise returns %false.  */
static bool
can_externally_back_path(const wchar_t *path, size_t path_nchars,
			 const struct win32_apply_ctx *ctx)
{
	if (in_prepopulate_list(path, path_nchars, ctx))
		return false;

	/* Since we attempt to modify the SYSTEM registry after it's extracted
	 * (see end_wimboot_extraction()), it can't be extracted as externally
	 * backed.  This extends to associated files such as SYSTEM.LOG that
	 * also must be writable in order to write to the registry.  Normally,
	 * SYSTEM is in [PrepopulateList], and the SYSTEM.* files match patterns
	 * in [ExclusionList] and therefore are not captured in the WIM at all.
	 * However, a WIM that wasn't specifically captured in "WIMBoot mode"
	 * may contain SYSTEM.* files.  So to make things "just work", hard-code
	 * the pattern.  */
	if (match_path(path, path_nchars, L"\\Windows\\System32\\config\\SYSTEM*",
		       OS_PREFERRED_PATH_SEPARATOR, false))
		return false;

	return true;
}

#define WIM_BACKING_NOT_ENABLED		-1
#define WIM_BACKING_NOT_POSSIBLE	-2
#define WIM_BACKING_EXCLUDED		-3

static int
will_externally_back_inode(struct wim_inode *inode, struct win32_apply_ctx *ctx,
			   const struct wim_dentry **excluded_dentry_ret)
{
	struct list_head *next;
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *stream;
	int ret;

	if (inode->i_can_externally_back)
		return 0;

	/* This may do redundant checks because the cached value
	 * i_can_externally_back is 2-state (as opposed to 3-state:
	 * unknown/no/yes).  But most files can be externally backed, so this
	 * way is fine.  */

	if (inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				   FILE_ATTRIBUTE_REPARSE_POINT |
				   FILE_ATTRIBUTE_ENCRYPTED))
		return WIM_BACKING_NOT_POSSIBLE;

	stream = inode_unnamed_lte_resolved(inode);

	if (!stream ||
	    stream->resource_location != RESOURCE_IN_WIM ||
	    stream->rspec->wim != ctx->common.wim ||
	    stream->size != stream->rspec->uncompressed_size)
		return WIM_BACKING_NOT_POSSIBLE;

	/*
	 * We need to check the patterns in [PrepopulateList] against every name
	 * of the inode, in case any of them match.
	 */
	next = inode->i_extraction_aliases.next;
	do {
		dentry = list_entry(next, struct wim_dentry,
				    d_extraction_alias_node);

		ret = calculate_dentry_full_path(dentry);
		if (ret)
			return ret;

		if (!can_externally_back_path(dentry->_full_path,
					      wcslen(dentry->_full_path), ctx))
		{
			if (excluded_dentry_ret)
				*excluded_dentry_ret = dentry;
			return WIM_BACKING_EXCLUDED;
		}
		next = next->next;
	} while (next != &inode->i_extraction_aliases);

	inode->i_can_externally_back = 1;
	return 0;
}

/*
 * Determines if the unnamed data stream of a file will be created as an
 * external backing, as opposed to a standard extraction.
 */
static int
win32_will_externally_back(struct wim_dentry *dentry, struct apply_ctx *_ctx)
{
	struct win32_apply_ctx *ctx = (struct win32_apply_ctx *)_ctx;

	if (!(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_WIMBOOT))
		return WIM_BACKING_NOT_ENABLED;

	if (!ctx->wimboot.tried_to_load_prepopulate_list)
		if (load_prepopulate_pats(ctx) == WIMLIB_ERR_NOMEM)
			return WIMLIB_ERR_NOMEM;

	return will_externally_back_inode(dentry->d_inode, ctx, NULL);
}

static int
set_external_backing(HANDLE h, struct wim_inode *inode, struct win32_apply_ctx *ctx)
{
	int ret;
	const struct wim_dentry *excluded_dentry;

	ret = will_externally_back_inode(inode, ctx, &excluded_dentry);
	if (ret > 0) /* Error.  */
		return ret;

	if (ret < 0 && ret != WIM_BACKING_EXCLUDED)
		return 0; /* Not externally backing, other than due to exclusion.  */

	if (unlikely(ret == WIM_BACKING_EXCLUDED)) {
		/* Not externally backing due to exclusion.  */
		union wimlib_progress_info info;

		build_extraction_path(excluded_dentry, ctx);

		info.wimboot_exclude.path_in_wim = excluded_dentry->_full_path;
		info.wimboot_exclude.extraction_path = current_path(ctx);

		return call_progress(ctx->common.progfunc,
				     WIMLIB_PROGRESS_MSG_WIMBOOT_EXCLUDE,
				     &info, ctx->common.progctx);
	} else {
		/* Externally backing.  */
		if (unlikely(!wimboot_set_pointer(h,
						  inode_unnamed_lte_resolved(inode),
						  ctx->wimboot.data_source_id,
						  ctx->wimboot.wim_lookup_table_hash,
						  ctx->wimboot.wof_running)))
		{
			const DWORD err = GetLastError();

			build_extraction_path(inode_first_extraction_dentry(inode), ctx);
			set_errno_from_win32_error(err);
			ERROR_WITH_ERRNO("\"%ls\": Couldn't set WIMBoot "
					 "pointer data (err=%"PRIu32")",
					 current_path(ctx), (u32)err);
			return WIMLIB_ERR_WIMBOOT;
		}
		return 0;
	}
}

/* Calculates the SHA-1 message digest of the WIM's lookup table.  */
static int
hash_lookup_table(WIMStruct *wim, u8 hash[SHA1_HASH_SIZE])
{
	return wim_reshdr_to_hash(&wim->hdr.lookup_table_reshdr, wim, hash);
}

/* Prepare for doing a "WIMBoot" extraction by loading patterns from
 * [PrepopulateList] of WimBootCompress.ini and allocating a WOF data source ID
 * on the target volume.  */
static int
start_wimboot_extraction(struct win32_apply_ctx *ctx)
{
	int ret;
	WIMStruct *wim = ctx->common.wim;

	if (!ctx->wimboot.tried_to_load_prepopulate_list)
		if (load_prepopulate_pats(ctx) == WIMLIB_ERR_NOMEM)
			return WIMLIB_ERR_NOMEM;

	if (!wim_info_get_wimboot(wim->wim_info, wim->current_image))
		WARNING("Image is not marked as WIMBoot compatible!");

	ret = hash_lookup_table(ctx->common.wim,
				ctx->wimboot.wim_lookup_table_hash);
	if (ret)
		return ret;

	return wimboot_alloc_data_source_id(wim->filename,
					    wim->hdr.guid,
					    wim->current_image,
					    ctx->common.target,
					    &ctx->wimboot.data_source_id,
					    &ctx->wimboot.wof_running);
}

static void
build_win32_extraction_path(const struct wim_dentry *dentry,
			    struct win32_apply_ctx *ctx);

/* Sets WimBoot=1 in the extracted SYSTEM registry hive.
 *
 * WIMGAPI does this, and it's possible that it's important.
 * But I don't know exactly what this value means to Windows.  */
static int
end_wimboot_extraction(struct win32_apply_ctx *ctx)
{
	struct wim_dentry *dentry;
	wchar_t subkeyname[32];
	LONG res;
	LONG res2;
	HKEY key;
	DWORD value;

	dentry = get_dentry(ctx->common.wim, L"\\Windows\\System32\\config\\SYSTEM",
			    WIMLIB_CASE_INSENSITIVE);

	if (!dentry || !will_extract_dentry(dentry))
		goto out;

	if (!will_extract_dentry(wim_get_current_root_dentry(ctx->common.wim)))
		goto out;

	/* Not bothering to use the native routines (e.g. NtLoadKey()) for this.
	 * If this doesn't work, you probably also have many other problems.  */

	build_win32_extraction_path(dentry, ctx);

	randomize_char_array_with_alnum(subkeyname, 20);
	subkeyname[20] = L'\0';

	res = RegLoadKey(HKEY_LOCAL_MACHINE, subkeyname, ctx->pathbuf.Buffer);
	if (res)
		goto out_check_res;

	wcscpy(&subkeyname[20], L"\\Setup");

	res = RegCreateKeyEx(HKEY_LOCAL_MACHINE, subkeyname, 0, NULL,
			     REG_OPTION_BACKUP_RESTORE, 0, NULL, &key, NULL);
	if (res)
		goto out_unload_key;

	value = 1;

	res = RegSetValueEx(key, L"WimBoot", 0, REG_DWORD,
			    (const BYTE *)&value, sizeof(DWORD));
	if (res)
		goto out_close_key;

	res = RegFlushKey(key);

out_close_key:
	res2 = RegCloseKey(key);
	if (!res)
		res = res2;
out_unload_key:
	subkeyname[20] = L'\0';
	RegUnLoadKey(HKEY_LOCAL_MACHINE, subkeyname);
out_check_res:
	if (res) {
		/* Warning only.  */
		set_errno_from_win32_error(res);
		WARNING_WITH_ERRNO("Failed to set \\Setup: dword \"WimBoot\"=1 value "
				   "in registry hive \"%ls\" (err=%"PRIu32")",
				   ctx->pathbuf.Buffer, (u32)res);
	}
out:
	return 0;
}

/* Returns the number of wide characters needed to represent the path to the
 * specified @dentry, relative to the target directory, when extracted.
 *
 * Does not include null terminator (not needed for NtCreateFile).  */
static size_t
dentry_extraction_path_length(const struct wim_dentry *dentry)
{
	size_t len = 0;
	const struct wim_dentry *d;

	d = dentry;
	do {
		len += d->d_extraction_name_nchars + 1;
		d = d->d_parent;
	} while (!dentry_is_root(d) && will_extract_dentry(d));

	return --len;  /* No leading slash  */
}

/* Returns the length of the longest string that might need to be appended to
 * the path to an alias of an inode to open or create a named data stream.
 *
 * If the inode has no named data streams, this will be 0.  Otherwise, this will
 * be 1 plus the length of the longest-named data stream, since the data stream
 * name must be separated from the path by the ':' character.  */
static size_t
inode_longest_named_data_stream_spec(const struct wim_inode *inode)
{
	size_t max = 0;
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		size_t len = inode->i_ads_entries[i].stream_name_nbytes;
		if (len > max)
			max = len;
	}
	if (max)
		max = 1 + (max / sizeof(wchar_t));
	return max;
}

/* Find the length, in wide characters, of the longest path needed for
 * extraction of any file in @dentry_list relative to the target directory.
 *
 * Accounts for named data streams, but does not include null terminator (not
 * needed for NtCreateFile).  */
static size_t
compute_path_max(struct list_head *dentry_list)
{
	size_t max = 0;
	const struct wim_dentry *dentry;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		size_t len;

		len = dentry_extraction_path_length(dentry);

		/* Account for named data streams  */
		len += inode_longest_named_data_stream_spec(dentry->d_inode);

		if (len > max)
			max = len;
	}

	return max;
}

/* Build the path at which to extract the @dentry, relative to the target
 * directory.
 *
 * The path is saved in ctx->pathbuf.  */
static void
build_extraction_path(const struct wim_dentry *dentry,
		      struct win32_apply_ctx *ctx)
{
	size_t len;
	wchar_t *p;
	const struct wim_dentry *d;

	len = dentry_extraction_path_length(dentry);

	ctx->pathbuf.Length = len * sizeof(wchar_t);
	p = ctx->pathbuf.Buffer + len;
	for (d = dentry;
	     !dentry_is_root(d->d_parent) && will_extract_dentry(d->d_parent);
	     d = d->d_parent)
	{
		p -= d->d_extraction_name_nchars;
		wmemcpy(p, d->d_extraction_name, d->d_extraction_name_nchars);
		*--p = '\\';
	}
	/* No leading slash  */
	p -= d->d_extraction_name_nchars;
	wmemcpy(p, d->d_extraction_name, d->d_extraction_name_nchars);
}

/* Build the path at which to extract the @dentry, relative to the target
 * directory, adding the suffix for a named data stream.
 *
 * The path is saved in ctx->pathbuf.  */
static void
build_extraction_path_with_ads(const struct wim_dentry *dentry,
			       struct win32_apply_ctx *ctx,
			       const wchar_t *stream_name,
			       size_t stream_name_nchars)
{
	wchar_t *p;

	build_extraction_path(dentry, ctx);

	/* Add :NAME for named data stream  */
	p = ctx->pathbuf.Buffer + (ctx->pathbuf.Length / sizeof(wchar_t));
	*p++ = L':';
	wmemcpy(p, stream_name, stream_name_nchars);
	ctx->pathbuf.Length += (1 + stream_name_nchars) * sizeof(wchar_t);
}

/* Build the Win32 namespace path to the specified @dentry when extracted.
 *
 * The path is saved in ctx->pathbuf and will be null terminated.
 *
 * XXX: We could get rid of this if it wasn't needed for the file encryption
 * APIs, and the registry manipulation in WIMBoot mode.  */
static void
build_win32_extraction_path(const struct wim_dentry *dentry,
			    struct win32_apply_ctx *ctx)
{
	build_extraction_path(dentry, ctx);

	/* Prepend target_ntpath to our relative path, then change \??\ into \\?\  */

	memmove(ctx->pathbuf.Buffer +
			(ctx->target_ntpath.Length / sizeof(wchar_t)) + 1,
		ctx->pathbuf.Buffer, ctx->pathbuf.Length);
	memcpy(ctx->pathbuf.Buffer, ctx->target_ntpath.Buffer,
		ctx->target_ntpath.Length);
	ctx->pathbuf.Buffer[ctx->target_ntpath.Length / sizeof(wchar_t)] = L'\\';
	ctx->pathbuf.Length += ctx->target_ntpath.Length + sizeof(wchar_t);
	ctx->pathbuf.Buffer[ctx->pathbuf.Length / sizeof(wchar_t)] = L'\0';

	wimlib_assert(ctx->pathbuf.Length >= 4 * sizeof(wchar_t) &&
		      !wmemcmp(ctx->pathbuf.Buffer, L"\\??\\", 4));

	ctx->pathbuf.Buffer[1] = L'\\';

}

/* Returns a "printable" representation of the last relative NT path that was
 * constructed with build_extraction_path() or build_extraction_path_with_ads().
 *
 * This will be overwritten by the next call to this function.  */
static const wchar_t *
current_path(struct win32_apply_ctx *ctx)
{
	wchar_t *p = ctx->print_buffer;

	p = wmempcpy(p, ctx->common.target, ctx->common.target_nchars);
	*p++ = L'\\';
	p = wmempcpy(p, ctx->pathbuf.Buffer, ctx->pathbuf.Length / sizeof(wchar_t));
	*p = L'\0';
	return ctx->print_buffer;
}

/*
 * Ensures the target directory exists and opens a handle to it, in preparation
 * of using paths relative to it.
 */
static int
prepare_target(struct list_head *dentry_list, struct win32_apply_ctx *ctx)
{
	int ret;
	NTSTATUS status;
	size_t path_max;

	/* Open handle to the target directory (possibly creating it).  */

	ret = win32_path_to_nt_path(ctx->common.target, &ctx->target_ntpath);
	if (ret)
		return ret;

	ctx->attr.Length = sizeof(ctx->attr);
	ctx->attr.ObjectName = &ctx->target_ntpath;

	status = (*func_NtCreateFile)(&ctx->h_target,
				      FILE_TRAVERSE,
				      &ctx->attr,
				      &ctx->iosb,
				      NULL,
				      0,
				      FILE_SHARE_VALID_FLAGS,
				      FILE_OPEN_IF,
				      FILE_DIRECTORY_FILE |
					      FILE_OPEN_REPARSE_POINT |
					      FILE_OPEN_FOR_BACKUP_INTENT,
				      NULL,
				      0);

	if (!NT_SUCCESS(status)) {
		set_errno_from_nt_status(status);
		ERROR_WITH_ERRNO("Can't open or create directory \"%ls\" "
				 "(status=0x%08"PRIx32")",
				 ctx->common.target, (u32)status);
		return WIMLIB_ERR_OPENDIR;
	}

	path_max = compute_path_max(dentry_list);

	/* Add some extra for building Win32 paths for the file encryption APIs,
	 * and ensure we have at least enough to potentially use a 8.3 name for
	 * the last component.  */
	path_max += max(2 + (ctx->target_ntpath.Length / sizeof(wchar_t)),
			8 + 1 + 3);

	ctx->pathbuf.MaximumLength = path_max * sizeof(wchar_t);
	ctx->pathbuf.Buffer = MALLOC(ctx->pathbuf.MaximumLength);
	if (!ctx->pathbuf.Buffer)
		return WIMLIB_ERR_NOMEM;

	ctx->attr.RootDirectory = ctx->h_target;
	ctx->attr.ObjectName = &ctx->pathbuf;

	ctx->print_buffer = MALLOC((ctx->common.target_nchars + 1 + path_max + 1) *
				   sizeof(wchar_t));
	if (!ctx->print_buffer)
		return WIMLIB_ERR_NOMEM;

	return 0;
}

/* When creating an inode that will have a short (DOS) name, we create it using
 * the long name associated with the short name.  This ensures that the short
 * name gets associated with the correct long name.  */
static struct wim_dentry *
first_extraction_alias(const struct wim_inode *inode)
{
	struct list_head *next = inode->i_extraction_aliases.next;
	struct wim_dentry *dentry;

	do {
		dentry = list_entry(next, struct wim_dentry,
				    d_extraction_alias_node);
		if (dentry_has_short_name(dentry))
			break;
		next = next->next;
	} while (next != &inode->i_extraction_aliases);
	return dentry;
}

/*
 * Set or clear FILE_ATTRIBUTE_COMPRESSED if the inherited value is different
 * from the desired value.
 *
 * Note that you can NOT override the inherited value of
 * FILE_ATTRIBUTE_COMPRESSED directly with NtCreateFile().
 */
static int
adjust_compression_attribute(HANDLE h, const struct wim_dentry *dentry,
			     struct win32_apply_ctx *ctx)
{
	const bool compressed = (dentry->d_inode->i_attributes &
				 FILE_ATTRIBUTE_COMPRESSED);

	if (ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES)
		return 0;

	if (!ctx->common.supported_features.compressed_files)
		return 0;

	FILE_BASIC_INFORMATION info;
	NTSTATUS status;
	USHORT compression_state;

	/* Get current attributes  */
	status = (*func_NtQueryInformationFile)(h, &ctx->iosb,
						&info, sizeof(info),
						FileBasicInformation);
	if (NT_SUCCESS(status) &&
	    compressed == !!(info.FileAttributes & FILE_ATTRIBUTE_COMPRESSED))
	{
		/* Nothing needs to be done.  */
		return 0;
	}

	/* Set the new compression state  */

	if (compressed)
		compression_state = COMPRESSION_FORMAT_DEFAULT;
	else
		compression_state = COMPRESSION_FORMAT_NONE;

	status = (*func_NtFsControlFile)(h,
					 NULL,
					 NULL,
					 NULL,
					 &ctx->iosb,
					 FSCTL_SET_COMPRESSION,
					 &compression_state,
					 sizeof(USHORT),
					 NULL,
					 0);
	if (NT_SUCCESS(status))
		return 0;

	set_errno_from_nt_status(status);
	ERROR_WITH_ERRNO("Can't %s compression attribute on \"%ls\" "
			 "(status=0x%08"PRIx32")",
			 (compressed ? "set" : "clear"),
			 current_path(ctx), status);
	return WIMLIB_ERR_SET_ATTRIBUTES;
}

/*
 * Clear FILE_ATTRIBUTE_ENCRYPTED if the file or directory is not supposed to be
 * encrypted.
 *
 * You can provide FILE_ATTRIBUTE_ENCRYPTED to NtCreateFile() to set it on the
 * created file.  However, the file or directory will otherwise default to the
 * encryption state of the parent directory.  This function works around this
 * limitation by using DecryptFile() to remove FILE_ATTRIBUTE_ENCRYPTED on files
 * (and directories) that are not supposed to have it set.
 *
 * Regardless of whether it succeeds or fails, this function may close the
 * handle to the file.  If it does, it sets it to NULL.
 */
static int
maybe_clear_encryption_attribute(HANDLE *h_ptr, const struct wim_dentry *dentry,
				 struct win32_apply_ctx *ctx)
{
	if (dentry->d_inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED)
		return 0;

	if (ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES)
		return 0;

	if (!ctx->common.supported_features.encrypted_files)
		return 0;

	FILE_BASIC_INFORMATION info;
	NTSTATUS status;
	BOOL bret;

	/* Get current attributes  */
	status = (*func_NtQueryInformationFile)(*h_ptr, &ctx->iosb,
						&info, sizeof(info),
						FileBasicInformation);
	if (NT_SUCCESS(status) &&
	    !(info.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED))
	{
		/* Nothing needs to be done.  */
		return 0;
	}

	/* Set the new encryption state  */

	/* Due to Windows' crappy file encryption APIs, we need to close the
	 * handle to the file so we don't get ERROR_SHARING_VIOLATION.  We also
	 * hack together a Win32 path, although we will use the \\?\ prefix so
	 * it will actually be a NT path in disguise...  */
	(*func_NtClose)(*h_ptr);
	*h_ptr = NULL;

	build_win32_extraction_path(dentry, ctx);

	bret = DecryptFile(ctx->pathbuf.Buffer, 0);

	/* Restore the NT namespace path  */
	build_extraction_path(dentry, ctx);

	if (!bret) {
		DWORD err = GetLastError();
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Can't decrypt file \"%ls\" (err=%"PRIu32")",
				  current_path(ctx), (u32)err);
		return WIMLIB_ERR_SET_ATTRIBUTES;
	}
	return 0;
}

/* Try to enable short name support on the target volume.  If successful, return
 * true.  If unsuccessful, issue a warning and return false.  */
static bool
try_to_enable_short_names(const wchar_t *volume)
{
	HANDLE h;
	FILE_FS_PERSISTENT_VOLUME_INFORMATION info;
	BOOL bret;
	DWORD bytesReturned;

	h = CreateFile(volume, GENERIC_WRITE,
		       FILE_SHARE_VALID_FLAGS, NULL, OPEN_EXISTING,
		       FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (h == INVALID_HANDLE_VALUE)
		goto fail;

	info.VolumeFlags = 0;
	info.FlagMask = PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED;
	info.Version = 1;
	info.Reserved = 0;

	bret = DeviceIoControl(h, FSCTL_SET_PERSISTENT_VOLUME_STATE,
			       &info, sizeof(info), NULL, 0,
			       &bytesReturned, NULL);

	CloseHandle(h);

	if (!bret)
		goto fail;
	return true;

fail:
	WARNING("Failed to enable short name support on %ls "
		"(err=%"PRIu32")", volume + 4, (u32)GetLastError());
	return false;
}

static NTSTATUS
remove_conflicting_short_name(const struct wim_dentry *dentry, struct win32_apply_ctx *ctx)
{
	wchar_t *name;
	wchar_t *end;
	NTSTATUS status;
	HANDLE h;
	size_t bufsize = offsetof(FILE_NAME_INFORMATION, FileName) +
			 (13 * sizeof(wchar_t));
	u8 buf[bufsize] _aligned_attribute(8);
	bool retried = false;
	FILE_NAME_INFORMATION *info = (FILE_NAME_INFORMATION *)buf;

	memset(buf, 0, bufsize);

	/* Build the path with the short name.  */
	name = &ctx->pathbuf.Buffer[ctx->pathbuf.Length / sizeof(wchar_t)];
	while (name != ctx->pathbuf.Buffer && *(name - 1) != L'\\')
		name--;
	end = mempcpy(name, dentry->short_name, dentry->short_name_nbytes);
	ctx->pathbuf.Length = ((u8 *)end - (u8 *)ctx->pathbuf.Buffer);

	/* Open the conflicting file (by short name).  */
	status = (*func_NtOpenFile)(&h, GENERIC_WRITE | DELETE,
				    &ctx->attr, &ctx->iosb,
				    FILE_SHARE_VALID_FLAGS,
				    FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT);
	if (!NT_SUCCESS(status)) {
		WARNING("Can't open \"%ls\" (status=0x%08"PRIx32")",
			current_path(ctx), (u32)status);
		goto out;
	}

#if 0
	WARNING("Overriding conflicting short name; path=\"%ls\"",
		current_path(ctx));
#endif

	/* Try to remove the short name on the conflicting file.  */

retry:
	status = (*func_NtSetInformationFile)(h, &ctx->iosb, info, bufsize,
					      FileShortNameInformation);

	if (status == STATUS_INVALID_PARAMETER && !retried) {

		/* Microsoft forgot to make it possible to remove short names
		 * until Windows 7.  Oops.  Use a random short name instead.  */

		info->FileNameLength = 12 * sizeof(wchar_t);
		for (int i = 0; i < 8; i++)
			info->FileName[i] = 'A' + (rand() % 26);
		info->FileName[8] = L'.';
		info->FileName[9] = L'W';
		info->FileName[10] = L'L';
		info->FileName[11] = L'B';
		info->FileName[12] = L'\0';
		retried = true;
		goto retry;
	}
	(*func_NtClose)(h);
out:
	build_extraction_path(dentry, ctx);
	return status;
}

/* Set the short name on the open file @h which has been created at the location
 * indicated by @dentry.
 *
 * Note that this may add, change, or remove the short name.
 *
 * @h must be opened with DELETE access.
 *
 * Returns 0 or WIMLIB_ERR_SET_SHORT_NAME.  The latter only happens in
 * STRICT_SHORT_NAMES mode.
 */
static int
set_short_name(HANDLE h, const struct wim_dentry *dentry,
	       struct win32_apply_ctx *ctx)
{

	if (!ctx->common.supported_features.short_names)
		return 0;

	/*
	 * Note: The size of the FILE_NAME_INFORMATION buffer must be such that
	 * FileName contains at least 2 wide characters (4 bytes).  Otherwise,
	 * NtSetInformationFile() will return STATUS_INFO_LENGTH_MISMATCH.  This
	 * is despite the fact that FileNameLength can validly be 0 or 2 bytes,
	 * with the former case being removing the existing short name if
	 * present, rather than setting one.
	 *
	 * The null terminator is seemingly optional, but to be safe we include
	 * space for it and zero all unused space.
	 */

	size_t bufsize = offsetof(FILE_NAME_INFORMATION, FileName) +
			 max(dentry->short_name_nbytes, sizeof(wchar_t)) +
			 sizeof(wchar_t);
	u8 buf[bufsize] _aligned_attribute(8);
	FILE_NAME_INFORMATION *info = (FILE_NAME_INFORMATION *)buf;
	NTSTATUS status;
	bool tried_to_remove_existing = false;

	memset(buf, 0, bufsize);

	info->FileNameLength = dentry->short_name_nbytes;
	memcpy(info->FileName, dentry->short_name, dentry->short_name_nbytes);

retry:
	status = (*func_NtSetInformationFile)(h, &ctx->iosb, info, bufsize,
					      FileShortNameInformation);
	if (NT_SUCCESS(status))
		return 0;

	if (status == STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME) {
		if (dentry->short_name_nbytes == 0)
			return 0;
		if (!ctx->tried_to_enable_short_names) {
			wchar_t volume[7];
			int ret;

			ctx->tried_to_enable_short_names = true;

			ret = win32_get_drive_path(ctx->common.target,
						   volume);
			if (ret)
				return ret;
			if (try_to_enable_short_names(volume))
				goto retry;
		}
	}

	/*
	 * Short names can conflict in several cases:
	 *
	 * - a file being extracted has a short name conflicting with an
	 *   existing file
	 *
	 * - a file being extracted has a short name conflicting with another
	 *   file being extracted (possible, but shouldn't happen)
	 *
	 * - a file being extracted has a short name that conflicts with the
	 *   automatically generated short name of a file we previously
	 *   extracted, but failed to set the short name for.  Sounds unlikely,
	 *   but this actually does happen fairly often on versions of Windows
	 *   prior to Windows 7 because they do not support removing short names
	 *   from files.
	 */
	if (unlikely(status == STATUS_OBJECT_NAME_COLLISION) &&
	    dentry->short_name_nbytes && !tried_to_remove_existing)
	{
		tried_to_remove_existing = true;
		status = remove_conflicting_short_name(dentry, ctx);
		if (NT_SUCCESS(status))
			goto retry;
	}

	/* By default, failure to set short names is not an error (since short
	 * names aren't too important anymore...).  */
	if (!(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_SHORT_NAMES)) {
		if (dentry->short_name_nbytes)
			ctx->num_set_short_name_failures++;
		else
			ctx->num_remove_short_name_failures++;
		return 0;
	}

	if (status == STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME) {
		ERROR("Can't set short name when short "
		      "names are not enabled on the volume!");
	} else {
		ERROR("Can't set short name on \"%ls\" (status=0x%08"PRIx32")",
		      current_path(ctx), (u32)status);
	}
	return WIMLIB_ERR_SET_SHORT_NAME;
}

/*
 * A wrapper around NtCreateFile() to make it slightly more usable...
 * This uses the path currently constructed in ctx->pathbuf.
 *
 * Also, we always specify FILE_OPEN_FOR_BACKUP_INTENT and
 * FILE_OPEN_REPARSE_POINT.
 */
static NTSTATUS
do_create_file(PHANDLE FileHandle,
	       ACCESS_MASK DesiredAccess,
	       PLARGE_INTEGER AllocationSize,
	       ULONG FileAttributes,
	       ULONG CreateDisposition,
	       ULONG CreateOptions,
	       struct win32_apply_ctx *ctx)
{
	return (*func_NtCreateFile)(FileHandle,
				    DesiredAccess,
				    &ctx->attr,
				    &ctx->iosb,
				    AllocationSize,
				    FileAttributes,
				    FILE_SHARE_VALID_FLAGS,
				    CreateDisposition,
				    CreateOptions |
					FILE_OPEN_FOR_BACKUP_INTENT |
					FILE_OPEN_REPARSE_POINT,
				    NULL,
				    0);
}

/* Like do_create_file(), but builds the extraction path of the @dentry first.
 */
static NTSTATUS
create_file(PHANDLE FileHandle,
	    ACCESS_MASK DesiredAccess,
	    PLARGE_INTEGER AllocationSize,
	    ULONG FileAttributes,
	    ULONG CreateDisposition,
	    ULONG CreateOptions,
	    const struct wim_dentry *dentry,
	    struct win32_apply_ctx *ctx)
{
	build_extraction_path(dentry, ctx);
	return do_create_file(FileHandle,
			      DesiredAccess,
			      AllocationSize,
			      FileAttributes,
			      CreateDisposition,
			      CreateOptions,
			      ctx);
}

/* Create empty named data streams.
 *
 * Since these won't have 'struct wim_lookup_table_entry's, they won't show up
 * in the call to extract_stream_list().  Hence the need for the special case.
 */
static int
create_any_empty_ads(const struct wim_dentry *dentry,
		     struct win32_apply_ctx *ctx)
{
	const struct wim_inode *inode = dentry->d_inode;
	LARGE_INTEGER allocation_size;
	bool path_modified = false;
	int ret = 0;

	if (!ctx->common.supported_features.named_data_streams)
		return 0;

	for (u16 i = 0; i < inode->i_num_ads; i++) {
		const struct wim_ads_entry *entry;
		NTSTATUS status;
		HANDLE h;
		bool retried;
		DWORD disposition;

		entry = &inode->i_ads_entries[i];

		/* Not named?  */
		if (!entry->stream_name_nbytes)
			continue;

		/* Not empty?  */
		if (entry->lte)
			continue;

		/* Probably setting the allocation size to 0 has no effect, but
		 * we might as well try.  */
		allocation_size.QuadPart = 0;

		build_extraction_path_with_ads(dentry, ctx,
					       entry->stream_name,
					       entry->stream_name_nbytes /
							sizeof(wchar_t));
		path_modified = true;

		retried = false;
		disposition = FILE_SUPERSEDE;
	retry:
		status = do_create_file(&h, FILE_WRITE_DATA, &allocation_size,
					0, disposition, 0, ctx);
		if (unlikely(!NT_SUCCESS(status))) {
			if (status == STATUS_OBJECT_NAME_NOT_FOUND && !retried) {
				/* Workaround for defect in the Windows PE
				 * in-memory filesystem implementation:
				 * FILE_SUPERSEDE does not create the file, as
				 * expected and documented, when the named file
				 * does not exist.  */
				retried = true;
				disposition = FILE_CREATE;
				goto retry;
			}
			set_errno_from_nt_status(status);
			ERROR_WITH_ERRNO("Can't create \"%ls\" "
					 "(status=0x%08"PRIx32")",
					 current_path(ctx), (u32)status);
			ret = WIMLIB_ERR_OPEN;
			break;
		}
		(*func_NtClose)(h);
	}
	/* Restore the path to the dentry itself  */
	if (path_modified)
		build_extraction_path(dentry, ctx);
	return ret;
}

/*
 * Creates the directory named by @dentry, or uses an existing directory at that
 * location.  If necessary, sets the short name and/or fixes compression and
 * encryption attributes.
 *
 * Returns 0, WIMLIB_ERR_MKDIR, or WIMLIB_ERR_SET_SHORT_NAME.
 */
static int
create_directory(const struct wim_dentry *dentry,
		 struct win32_apply_ctx *ctx)
{
	HANDLE h;
	NTSTATUS status;
	int ret;
	ULONG attrib;

	/* Special attributes:
	 *
	 * Use FILE_ATTRIBUTE_ENCRYPTED if the directory needs to have it set.
	 * This doesn't work for FILE_ATTRIBUTE_COMPRESSED (unfortunately).
	 *
	 * Don't specify FILE_ATTRIBUTE_DIRECTORY; it gets set anyway as a
	 * result of the FILE_DIRECTORY_FILE option.  */
	attrib = (dentry->d_inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED);

	/* DELETE is needed for set_short_name().
	 * GENERIC_READ and GENERIC_WRITE are needed for
	 * adjust_compression_attribute().  */
	status = create_file(&h, GENERIC_READ | GENERIC_WRITE | DELETE, NULL,
			     attrib, FILE_OPEN_IF, FILE_DIRECTORY_FILE,
			     dentry, ctx);
	if (!NT_SUCCESS(status)) {
		set_errno_from_nt_status(status);
		ERROR_WITH_ERRNO("Can't create directory \"%ls\" "
				 "(status=0x%08"PRIx32")",
				 current_path(ctx), (u32)status);
		return WIMLIB_ERR_MKDIR;
	}

	ret = set_short_name(h, dentry, ctx);

	if (!ret)
		ret = adjust_compression_attribute(h, dentry, ctx);

	if (!ret)
		ret = maybe_clear_encryption_attribute(&h, dentry, ctx);
		/* May close the handle!!! */

	if (h)
		(*func_NtClose)(h);
	return ret;
}

/*
 * Create all the directories being extracted, other than the target directory
 * itself.
 *
 * Note: we don't honor directory hard links.  However, we don't allow them to
 * exist in WIM images anyway (see inode_fixup.c).
 */
static int
create_directories(struct list_head *dentry_list,
		   struct win32_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	int ret;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {

		if (!(dentry->d_inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY))
			continue;

		/* Note: Here we include files with
		 * FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT, but we
		 * wait until later to actually set the reparse data.  */

		/* If the root dentry is being extracted, it was already done so
		 * in prepare_target().  */
		if (!dentry_is_root(dentry)) {
			ret = create_directory(dentry, ctx);
			ret = check_apply_error(dentry, ctx, ret);
			if (ret)
				return ret;

			ret = create_any_empty_ads(dentry, ctx);
			ret = check_apply_error(dentry, ctx, ret);
			if (ret)
				return ret;
		}

		ret = report_file_created(&ctx->common);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Creates the nondirectory file named by @dentry.
 *
 * On success, returns an open handle to the file in @h_ret, with GENERIC_READ,
 * GENERIC_WRITE, and DELETE access.  Also, the path to the file will be saved
 * in ctx->pathbuf.  On failure, returns WIMLIB_ERR_OPEN.
 */
static int
create_nondirectory_inode(HANDLE *h_ret, const struct wim_dentry *dentry,
			  struct win32_apply_ctx *ctx)
{
	const struct wim_inode *inode;
	ULONG attrib;
	NTSTATUS status;
	bool retried = false;
	DWORD disposition;

	inode = dentry->d_inode;

	/* If the file already exists and has FILE_ATTRIBUTE_SYSTEM and/or
	 * FILE_ATTRIBUTE_HIDDEN, these must be specified in order to supersede
	 * the file.
	 *
	 * Normally the user shouldn't be trying to overwrite such files anyway,
	 * but we at least provide FILE_ATTRIBUTE_SYSTEM and
	 * FILE_ATTRIBUTE_HIDDEN if the WIM inode has those attributes so that
	 * we catch the case where the user extracts the same files to the same
	 * location more than one time.
	 *
	 * Also specify FILE_ATTRIBUTE_ENCRYPTED if the file needs to be
	 * encrypted.
	 *
	 * In NO_ATTRIBUTES mode just don't specify any attributes at all.
	 */
	if (ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES) {
		attrib = 0;
	} else {
		attrib = (inode->i_attributes & (FILE_ATTRIBUTE_SYSTEM |
						 FILE_ATTRIBUTE_HIDDEN |
						 FILE_ATTRIBUTE_ENCRYPTED));
	}
	build_extraction_path(dentry, ctx);
	disposition = FILE_SUPERSEDE;
retry:
	status = do_create_file(h_ret, GENERIC_READ | GENERIC_WRITE | DELETE,
				NULL, attrib, disposition,
				FILE_NON_DIRECTORY_FILE, ctx);
	if (likely(NT_SUCCESS(status))) {
		int ret;

		ret = adjust_compression_attribute(*h_ret, dentry, ctx);
		if (ret) {
			(*func_NtClose)(*h_ret);
			return ret;
		}

		ret = maybe_clear_encryption_attribute(h_ret, dentry, ctx);
		/* May close the handle!!! */

		if (ret) {
			if (*h_ret)
				(*func_NtClose)(*h_ret);
			return ret;
		}

		if (!*h_ret) {
			/* Re-open the handle so that we can return it on
			 * success.  */
			status = do_create_file(h_ret,
						GENERIC_READ |
							GENERIC_WRITE | DELETE,
						NULL, 0, FILE_OPEN,
						FILE_NON_DIRECTORY_FILE, ctx);
			if (!NT_SUCCESS(status))
				goto fail;
		}

		ret = create_any_empty_ads(dentry, ctx);
		if (ret) {
			(*func_NtClose)(*h_ret);
			return ret;
		}
		return 0;
	}

	if (status == STATUS_OBJECT_NAME_NOT_FOUND && !retried) {
		/* Workaround for defect in the Windows PE in-memory filesystem
		 * implementation: FILE_SUPERSEDE does not create the file, as
		 * expected and documented, when the named file does not exist.
		 */
		retried = true;
		disposition = FILE_CREATE;
		goto retry;
	}

	if (status == STATUS_ACCESS_DENIED && !retried) {
		/* We also can't supersede an existing file that has
		 * FILE_ATTRIBUTE_READONLY set; doing so causes NtCreateFile()
		 * to return STATUS_ACCESS_DENIED .  The only workaround seems
		 * to be to explicitly remove FILE_ATTRIBUTE_READONLY on the
		 * existing file, then try again.  */

		FILE_BASIC_INFORMATION info;
		HANDLE h;

		status = do_create_file(&h, FILE_WRITE_ATTRIBUTES, NULL, 0,
					FILE_OPEN, FILE_NON_DIRECTORY_FILE, ctx);
		if (!NT_SUCCESS(status))
			goto fail;

		memset(&info, 0, sizeof(info));
		info.FileAttributes = FILE_ATTRIBUTE_NORMAL;

		status = (*func_NtSetInformationFile)(h, &ctx->iosb,
						      &info, sizeof(info),
						      FileBasicInformation);
		(*func_NtClose)(h);
		if (!NT_SUCCESS(status))
			goto fail;
		retried = true;
		goto retry;
	}
fail:
	set_errno_from_nt_status(status);
	ERROR_WITH_ERRNO("Can't create file \"%ls\" (status=0x%08"PRIx32")",
			 current_path(ctx), (u32)status);
	return WIMLIB_ERR_OPEN;
}

/* Creates a hard link at the location named by @dentry to the file represented
 * by the open handle @h.  Or, if the target volume does not support hard links,
 * create a separate file instead.  */
static int
create_link(HANDLE h, const struct wim_dentry *dentry,
	    struct win32_apply_ctx *ctx)
{
	if (ctx->common.supported_features.hard_links) {

		build_extraction_path(dentry, ctx);

		size_t bufsize = offsetof(FILE_LINK_INFORMATION, FileName) +
				 ctx->pathbuf.Length + sizeof(wchar_t);
		u8 buf[bufsize] _aligned_attribute(8);
		FILE_LINK_INFORMATION *info = (FILE_LINK_INFORMATION *)buf;
		NTSTATUS status;

		info->ReplaceIfExists = TRUE;
		info->RootDirectory = ctx->attr.RootDirectory;
		info->FileNameLength = ctx->pathbuf.Length;
		memcpy(info->FileName, ctx->pathbuf.Buffer, ctx->pathbuf.Length);
		info->FileName[info->FileNameLength / 2] = L'\0';

		/* Note: the null terminator isn't actually necessary,
		 * but if you don't add the extra character, you get
		 * STATUS_INFO_LENGTH_MISMATCH when FileNameLength
		 * happens to be 2  */

		status = (*func_NtSetInformationFile)(h, &ctx->iosb,
						      info, bufsize,
						      FileLinkInformation);
		if (NT_SUCCESS(status))
			return 0;
		ERROR("Failed to create link \"%ls\" (status=0x%08"PRIx32")",
		      current_path(ctx), (u32)status);
		return WIMLIB_ERR_LINK;
	} else {
		HANDLE h2;
		int ret;

		ret = create_nondirectory_inode(&h2, dentry, ctx);
		if (ret)
			return ret;

		(*func_NtClose)(h2);
		return 0;
	}
}

/* Given an inode (represented by the open handle @h) for which one link has
 * been created (named by @first_dentry), create the other links.
 *
 * Or, if the target volume does not support hard links, create separate files.
 *
 * Note: This uses ctx->pathbuf and does not reset it.
 */
static int
create_links(HANDLE h, const struct wim_dentry *first_dentry,
	     struct win32_apply_ctx *ctx)
{
	const struct wim_inode *inode;
	const struct list_head *next;
	const struct wim_dentry *dentry;
	int ret;

	inode = first_dentry->d_inode;
	next = inode->i_extraction_aliases.next;
	do {
		dentry = list_entry(next, struct wim_dentry,
				    d_extraction_alias_node);
		if (dentry != first_dentry) {
			ret = create_link(h, dentry, ctx);
			if (ret)
				return ret;
		}
		next = next->next;
	} while (next != &inode->i_extraction_aliases);
	return 0;
}

/* Create a nondirectory file, including all links.  */
static int
create_nondirectory(struct wim_inode *inode, struct win32_apply_ctx *ctx)
{
	struct wim_dentry *first_dentry;
	HANDLE h;
	int ret;

	first_dentry = first_extraction_alias(inode);

	/* Create first link.  */
	ret = create_nondirectory_inode(&h, first_dentry, ctx);
	if (ret)
		return ret;

	/* Set short name.  */
	ret = set_short_name(h, first_dentry, ctx);

	/* Create additional links, OR if hard links are not supported just
	 * create more files.  */
	if (!ret)
		ret = create_links(h, first_dentry, ctx);

	/* "WIMBoot" extraction: set external backing by the WIM file if needed.  */
	if (!ret && unlikely(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_WIMBOOT))
		ret = set_external_backing(h, inode, ctx);

	(*func_NtClose)(h);
	return ret;
}

/* Create all the nondirectory files being extracted, including all aliases
 * (hard links).  */
static int
create_nondirectories(struct list_head *dentry_list, struct win32_apply_ctx *ctx)
{
	struct wim_dentry *dentry;
	struct wim_inode *inode;
	int ret;

	list_for_each_entry(dentry, dentry_list, d_extraction_list_node) {
		inode = dentry->d_inode;
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;
		/* Call create_nondirectory() only once per inode  */
		if (dentry == inode_first_extraction_dentry(inode)) {
			ret = create_nondirectory(inode, ctx);
			ret = check_apply_error(dentry, ctx, ret);
			if (ret)
				return ret;
		}
		ret = report_file_created(&ctx->common);
		if (ret)
			return ret;
	}
	return 0;
}

static void
close_handles(struct win32_apply_ctx *ctx)
{
	for (unsigned i = 0; i < ctx->num_open_handles; i++)
		(*func_NtClose)(ctx->open_handles[i]);
}

/* Prepare to read the next stream, which has size @stream_size, into an
 * in-memory buffer.  */
static bool
prepare_data_buffer(struct win32_apply_ctx *ctx, u64 stream_size)
{
	if (stream_size > ctx->data_buffer_size) {
		/* Larger buffer needed.  */
		void *new_buffer;
		if ((size_t)stream_size != stream_size)
			return false;
		new_buffer = REALLOC(ctx->data_buffer, stream_size);
		if (!new_buffer)
			return false;
		ctx->data_buffer = new_buffer;
		ctx->data_buffer_size = stream_size;
	}
	/* On the first call this changes data_buffer_ptr from NULL, which tells
	 * extract_chunk() that the data buffer needs to be filled while reading
	 * the stream data.  */
	ctx->data_buffer_ptr = ctx->data_buffer;
	return true;
}

static int
begin_extract_stream_instance(const struct wim_lookup_table_entry *stream,
			      struct wim_dentry *dentry,
			      const wchar_t *stream_name,
			      struct win32_apply_ctx *ctx)
{
	const struct wim_inode *inode = dentry->d_inode;
	size_t stream_name_nchars = 0;
	FILE_ALLOCATION_INFORMATION alloc_info;
	HANDLE h;
	NTSTATUS status;

	if (unlikely(stream_name))
		stream_name_nchars = wcslen(stream_name);

	if (unlikely(stream_name_nchars)) {
		build_extraction_path_with_ads(dentry, ctx,
					       stream_name, stream_name_nchars);
	} else {
		build_extraction_path(dentry, ctx);
	}

	/* Reparse point?  */
	if (unlikely(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
	    && (stream_name_nchars == 0))
	{
		if (!ctx->common.supported_features.reparse_points)
			return 0;

		/* We can't write the reparse stream directly; we must set it
		 * with FSCTL_SET_REPARSE_POINT, which requires that all the
		 * data be available.  So, stage the data in a buffer.  */

		if (!prepare_data_buffer(ctx, stream->size))
			return WIMLIB_ERR_NOMEM;
		list_add_tail(&dentry->tmp_list, &ctx->reparse_dentries);
		return 0;
	}

	/* Encrypted file?  */
	if (unlikely(inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED)
	    && (stream_name_nchars == 0))
	{
		if (!ctx->common.supported_features.encrypted_files)
			return 0;

		/* We can't write encrypted file streams directly; we must use
		 * WriteEncryptedFileRaw(), which requires providing the data
		 * through a callback function.  This can't easily be combined
		 * with our own callback-based approach.
		 *
		 * The current workaround is to simply read the stream into
		 * memory and write the encrypted file from that.
		 *
		 * TODO: This isn't sufficient for extremely large encrypted
		 * files.  Perhaps we should create an extra thread to write
		 * such files...  */
		if (!prepare_data_buffer(ctx, stream->size))
			return WIMLIB_ERR_NOMEM;
		list_add_tail(&dentry->tmp_list, &ctx->encrypted_dentries);
		return 0;
	}

	if (ctx->num_open_handles == MAX_OPEN_STREAMS) {
		/* XXX: Fix this.  But because of the checks in
		 * extract_stream_list(), this can now only happen on a
		 * filesystem that does not support hard links.  */
		ERROR("Can't extract data: too many open files!");
		return WIMLIB_ERR_UNSUPPORTED;
	}

	/* Open a new handle  */
	status = do_create_file(&h,
				FILE_WRITE_DATA | SYNCHRONIZE,
				NULL, 0, FILE_OPEN_IF,
				FILE_SEQUENTIAL_ONLY |
					FILE_SYNCHRONOUS_IO_NONALERT,
				ctx);
	if (!NT_SUCCESS(status)) {
		set_errno_from_nt_status(status);
		ERROR_WITH_ERRNO("Can't open \"%ls\" for writing "
				 "(status=0x%08"PRIx32")",
				 current_path(ctx), (u32)status);
		return WIMLIB_ERR_OPEN;
	}

	ctx->open_handles[ctx->num_open_handles++] = h;

	/* Allocate space for the data.  */
	alloc_info.AllocationSize.QuadPart = stream->size;
	(*func_NtSetInformationFile)(h, &ctx->iosb,
				     &alloc_info, sizeof(alloc_info),
				     FileAllocationInformation);
	return 0;
}

/* Set the reparse data @rpbuf of length @rpbuflen on the extracted file
 * corresponding to the WIM dentry @dentry.  */
static int
do_set_reparse_data(const struct wim_dentry *dentry,
		    const void *rpbuf, u16 rpbuflen,
		    struct win32_apply_ctx *ctx)
{
	NTSTATUS status;
	HANDLE h;

	status = create_file(&h, GENERIC_WRITE, NULL,
			     0, FILE_OPEN, 0, dentry, ctx);
	if (!NT_SUCCESS(status))
		goto fail;

	status = (*func_NtFsControlFile)(h, NULL, NULL, NULL,
					 &ctx->iosb, FSCTL_SET_REPARSE_POINT,
					 (void *)rpbuf, rpbuflen,
					 NULL, 0);
	(*func_NtClose)(h);

	if (NT_SUCCESS(status))
		return 0;

	/* On Windows, by default only the Administrator can create symbolic
	 * links for some reason.  By default we just issue a warning if this
	 * appears to be the problem.  Use WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS
	 * to get a hard error.  */
	if (!(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_SYMLINKS)
	    && (status == STATUS_PRIVILEGE_NOT_HELD ||
		status == STATUS_ACCESS_DENIED)
	    && (dentry->d_inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
		dentry->d_inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT))
	{
		WARNING("Can't create symbolic link \"%ls\"!              \n"
			"          (Need Administrator rights, or at least "
			"the\n"
			"          SeCreateSymbolicLink privilege.)",
			current_path(ctx));
		return 0;
	}

fail:
	set_errno_from_nt_status(status);
	ERROR_WITH_ERRNO("Can't set reparse data on \"%ls\" "
			 "(status=0x%08"PRIx32")",
			 current_path(ctx), (u32)status);
	return WIMLIB_ERR_SET_REPARSE_DATA;
}

/* Given a Windows NT namespace path, such as \??\e:\Windows\System32, return a
 * pointer to the suffix of the path that begins with the device directly, such
 * as e:\Windows\System32.  */
static const wchar_t *
skip_nt_toplevel_component(const wchar_t *path, size_t path_nchars)
{
	static const wchar_t * const dirs[] = {
		L"\\??\\",
		L"\\DosDevices\\",
		L"\\Device\\",
	};
	size_t first_dir_len = 0;
	const wchar_t * const end = path + path_nchars;

	for (size_t i = 0; i < ARRAY_LEN(dirs); i++) {
		size_t len = wcslen(dirs[i]);
		if (len <= (end - path) && !wcsnicmp(path, dirs[i], len)) {
			first_dir_len = len;
			break;
		}
	}
	if (first_dir_len == 0)
		return path;
	path += first_dir_len;
	while (path != end && *path == L'\\')
		path++;
	return path;
}

/* Given a Windows NT namespace path, such as \??\e:\Windows\System32, return a
 * pointer to the suffix of the path that is device-relative, such as
 * Windows\System32.
 *
 * The path has an explicit length and is not necessarily null terminated.
 *
 * If the path just something like \??\e: then the returned pointer will point
 * just past the colon.  In this case the length of the result will be 0
 * characters.  */
static const wchar_t *
get_device_relative_path(const wchar_t *path, size_t path_nchars)
{
	const wchar_t * const orig_path = path;
	const wchar_t * const end = path + path_nchars;

	path = skip_nt_toplevel_component(path, path_nchars);
	if (path == orig_path)
		return orig_path;

	path = wmemchr(path, L'\\', (end - path));
	if (!path)
		return end;
	do {
		path++;
	} while (path != end && *path == L'\\');
	return path;
}

/*
 * Given a reparse point buffer for a symbolic link or junction, adjust its
 * contents so that the target of the link is consistent with the new location
 * of the files.
 */
static void
try_rpfix(u8 *rpbuf, u16 *rpbuflen_p, struct win32_apply_ctx *ctx)
{
	struct reparse_data rpdata;
	size_t orig_subst_name_nchars;
	const wchar_t *relpath;
	size_t relpath_nchars;
	size_t target_ntpath_nchars;
	size_t fixed_subst_name_nchars;
	const wchar_t *fixed_print_name;
	size_t fixed_print_name_nchars;

	if (parse_reparse_data(rpbuf, *rpbuflen_p, &rpdata)) {
		/* Do nothing if the reparse data is invalid.  */
		return;
	}

	if (rpdata.rptag == WIM_IO_REPARSE_TAG_SYMLINK &&
	    (rpdata.rpflags & SYMBOLIC_LINK_RELATIVE))
	{
		/* Do nothing if it's a relative symbolic link.  */
		return;
	}

	/* Build the new substitute name from the NT namespace path to the
	 * target directory, then a path separator, then the "device relative"
	 * part of the old substitute name.  */

	orig_subst_name_nchars = rpdata.substitute_name_nbytes / sizeof(wchar_t);

	relpath = get_device_relative_path(rpdata.substitute_name,
					   orig_subst_name_nchars);
	relpath_nchars = orig_subst_name_nchars -
			 (relpath - rpdata.substitute_name);

	target_ntpath_nchars = ctx->target_ntpath.Length / sizeof(wchar_t);

	fixed_subst_name_nchars = target_ntpath_nchars;
	if (relpath_nchars)
		fixed_subst_name_nchars += 1 + relpath_nchars;
	wchar_t fixed_subst_name[fixed_subst_name_nchars];

	wmemcpy(fixed_subst_name, ctx->target_ntpath.Buffer,
		target_ntpath_nchars);
	if (relpath_nchars) {
		fixed_subst_name[target_ntpath_nchars] = L'\\';
		wmemcpy(&fixed_subst_name[target_ntpath_nchars + 1],
			relpath, relpath_nchars);
	}
	/* Doesn't need to be null-terminated.  */

	/* Print name should be Win32, but not all NT names can even be
	 * translated to Win32 names.  But we can at least delete the top-level
	 * directory, such as \??\, and this will have the expected result in
	 * the usual case.  */
	fixed_print_name = skip_nt_toplevel_component(fixed_subst_name,
						      fixed_subst_name_nchars);
	fixed_print_name_nchars = fixed_subst_name_nchars - (fixed_print_name -
							     fixed_subst_name);

	rpdata.substitute_name = fixed_subst_name;
	rpdata.substitute_name_nbytes = fixed_subst_name_nchars * sizeof(wchar_t);
	rpdata.print_name = (wchar_t *)fixed_print_name;
	rpdata.print_name_nbytes = fixed_print_name_nchars * sizeof(wchar_t);
	make_reparse_buffer(&rpdata, rpbuf, rpbuflen_p);
}

/* Sets reparse data on the specified file.  This handles "fixing" the targets
 * of absolute symbolic links and junctions if WIMLIB_EXTRACT_FLAG_RPFIX was
 * specified.  */
static int
set_reparse_data(const struct wim_dentry *dentry,
		 const void *_rpbuf, u16 rpbuflen, struct win32_apply_ctx *ctx)
{
	const struct wim_inode *inode = dentry->d_inode;
	const void *rpbuf = _rpbuf;

	if ((ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX)
	    && !inode->i_not_rpfixed
	    && (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
		inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT))
	{
		memcpy(&ctx->rpfixbuf, _rpbuf, rpbuflen);
		try_rpfix((u8 *)&ctx->rpfixbuf, &rpbuflen, ctx);
		rpbuf = &ctx->rpfixbuf;
	}
	return do_set_reparse_data(dentry, rpbuf, rpbuflen, ctx);

}

/* Import the next block of raw encrypted data  */
static DWORD WINAPI
import_encrypted_data(PBYTE pbData, PVOID pvCallbackContext, PULONG Length)
{
	struct win32_apply_ctx *ctx = pvCallbackContext;
	ULONG copy_len;

	copy_len = min(ctx->encrypted_size - ctx->encrypted_offset, *Length);
	memcpy(pbData, &ctx->data_buffer[ctx->encrypted_offset], copy_len);
	ctx->encrypted_offset += copy_len;
	*Length = copy_len;
	return ERROR_SUCCESS;
}

/* Write the raw encrypted data to the already-created file corresponding to
 * @dentry.
 *
 * The raw encrypted data is provided in ctx->data_buffer, and its size is
 * ctx->encrypted_size.  */
static int
extract_encrypted_file(const struct wim_dentry *dentry,
		       struct win32_apply_ctx *ctx)
{
	void *rawctx;
	DWORD err;

	/* Temporarily build a Win32 path for OpenEncryptedFileRaw()  */
	build_win32_extraction_path(dentry, ctx);

	err = OpenEncryptedFileRaw(ctx->pathbuf.Buffer,
				   CREATE_FOR_IMPORT, &rawctx);

	/* Restore the NT namespace path  */
	build_extraction_path(dentry, ctx);

	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Can't open \"%ls\" for encrypted import "
				 "(err=%"PRIu32")", current_path(ctx), (u32)err);
		return WIMLIB_ERR_OPEN;
	}

	ctx->encrypted_offset = 0;

	err = WriteEncryptedFileRaw(import_encrypted_data, ctx, rawctx);

	CloseEncryptedFileRaw(rawctx);

	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Can't import encrypted file \"%ls\" "
				 "(err=%"PRIu32")", current_path(ctx), (u32)err);
		return WIMLIB_ERR_WRITE;
	}

	return 0;
}

/* Called when starting to read a stream for extraction on Windows  */
static int
begin_extract_stream(struct wim_lookup_table_entry *stream, void *_ctx)
{
	struct win32_apply_ctx *ctx = _ctx;
	const struct stream_owner *owners = stream_owners(stream);
	int ret;

	ctx->num_open_handles = 0;
	ctx->data_buffer_ptr = NULL;
	INIT_LIST_HEAD(&ctx->reparse_dentries);
	INIT_LIST_HEAD(&ctx->encrypted_dentries);

	for (u32 i = 0; i < stream->out_refcnt; i++) {
		const struct wim_inode *inode = owners[i].inode;
		const wchar_t *stream_name = owners[i].stream_name;
		struct wim_dentry *dentry;

		/* A copy of the stream needs to be extracted to @inode.  */

		if (ctx->common.supported_features.hard_links) {
			dentry = inode_first_extraction_dentry(inode);
			ret = begin_extract_stream_instance(stream, dentry,
							    stream_name, ctx);
			ret = check_apply_error(dentry, ctx, ret);
			if (ret)
				goto fail;
		} else {
			/* Hard links not supported.  Extract the stream
			 * separately to each alias of the inode.  */
			struct list_head *next;

			next = inode->i_extraction_aliases.next;
			do {
				dentry = list_entry(next, struct wim_dentry,
						    d_extraction_alias_node);
				ret = begin_extract_stream_instance(stream,
								    dentry,
								    stream_name,
								    ctx);
				ret = check_apply_error(dentry, ctx, ret);
				if (ret)
					goto fail;
				next = next->next;
			} while (next != &inode->i_extraction_aliases);
		}
	}

	return 0;

fail:
	close_handles(ctx);
	return ret;
}

/* Called when the next chunk of a stream has been read for extraction on
 * Windows  */
static int
extract_chunk(const void *chunk, size_t size, void *_ctx)
{
	struct win32_apply_ctx *ctx = _ctx;

	/* Write the data chunk to each open handle  */
	for (unsigned i = 0; i < ctx->num_open_handles; i++) {
		u8 *bufptr = (u8 *)chunk;
		size_t bytes_remaining = size;
		NTSTATUS status;
		while (bytes_remaining) {
			ULONG count = min(0xFFFFFFFF, bytes_remaining);

			status = (*func_NtWriteFile)(ctx->open_handles[i],
						     NULL, NULL, NULL,
						     &ctx->iosb, bufptr, count,
						     NULL, NULL);
			if (!NT_SUCCESS(status)) {
				set_errno_from_nt_status(status);
				ERROR_WITH_ERRNO("Error writing data to target "
						 "volume (status=0x%08"PRIx32")",
						 (u32)status);
				return WIMLIB_ERR_WRITE;
			}
			bufptr += ctx->iosb.Information;
			bytes_remaining -= ctx->iosb.Information;
		}
	}

	/* Copy the data chunk into the buffer (if needed)  */
	if (ctx->data_buffer_ptr)
		ctx->data_buffer_ptr = mempcpy(ctx->data_buffer_ptr,
					       chunk, size);
	return 0;
}

/* Called when a stream has been fully read for extraction on Windows  */
static int
end_extract_stream(struct wim_lookup_table_entry *stream, int status, void *_ctx)
{
	struct win32_apply_ctx *ctx = _ctx;
	int ret;
	const struct wim_dentry *dentry;

	close_handles(ctx);

	if (status)
		return status;

	if (likely(!ctx->data_buffer_ptr))
		return 0;

	if (!list_empty(&ctx->reparse_dentries)) {
		if (stream->size > REPARSE_DATA_MAX_SIZE) {
			dentry = list_first_entry(&ctx->reparse_dentries,
						  struct wim_dentry, tmp_list);
			build_extraction_path(dentry, ctx);
			ERROR("Reparse data of \"%ls\" has size "
			      "%"PRIu64" bytes (exceeds %u bytes)",
			      current_path(ctx), stream->size,
			      REPARSE_DATA_MAX_SIZE);
			ret = WIMLIB_ERR_INVALID_REPARSE_DATA;
			return check_apply_error(dentry, ctx, ret);
		}
		/* In the WIM format, reparse streams are just the reparse data
		 * and omit the header.  But we can reconstruct the header.  */
		memcpy(ctx->rpbuf.rpdata, ctx->data_buffer, stream->size);
		ctx->rpbuf.rpdatalen = stream->size;
		ctx->rpbuf.rpreserved = 0;
		list_for_each_entry(dentry, &ctx->reparse_dentries, tmp_list) {
			ctx->rpbuf.rptag = dentry->d_inode->i_reparse_tag;
			ret = set_reparse_data(dentry, &ctx->rpbuf,
					       stream->size + REPARSE_DATA_OFFSET,
					       ctx);
			ret = check_apply_error(dentry, ctx, ret);
			if (ret)
				return ret;
		}
	}

	if (!list_empty(&ctx->encrypted_dentries)) {
		ctx->encrypted_size = stream->size;
		list_for_each_entry(dentry, &ctx->encrypted_dentries, tmp_list) {
			ret = extract_encrypted_file(dentry, ctx);
			ret = check_apply_error(dentry, ctx, ret);
			if (ret)
				return ret;
		}
	}

	return 0;
}

/* Attributes that can't be set directly  */
#define SPECIAL_ATTRIBUTES			\
	(FILE_ATTRIBUTE_REPARSE_POINT	|	\
	 FILE_ATTRIBUTE_DIRECTORY	|	\
	 FILE_ATTRIBUTE_ENCRYPTED	|	\
	 FILE_ATTRIBUTE_SPARSE_FILE	|	\
	 FILE_ATTRIBUTE_COMPRESSED)

/* Set the security descriptor @desc, of @desc_size bytes, on the file with open
 * handle @h.  */
static NTSTATUS
set_security_descriptor(HANDLE h, const void *_desc,
			size_t desc_size, struct win32_apply_ctx *ctx)
{
	SECURITY_INFORMATION info;
	NTSTATUS status;
	SECURITY_DESCRIPTOR_RELATIVE *desc;

	/*
	 * Ideally, we would just pass in the security descriptor buffer as-is.
	 * But it turns out that Windows can mess up the security descriptor
	 * even when using the low-level NtSetSecurityObject() function:
	 *
	 * - Windows will clear SE_DACL_AUTO_INHERITED if it is set in the
	 *   passed buffer.  To actually get Windows to set
	 *   SE_DACL_AUTO_INHERITED, the application must set the non-persistent
	 *   flag SE_DACL_AUTO_INHERIT_REQ.  As usual, Microsoft didn't bother
	 *   to properly document either of these flags.  It's unclear how
	 *   important SE_DACL_AUTO_INHERITED actually is, but to be safe we use
	 *   the SE_DACL_AUTO_INHERIT_REQ workaround to set it if needed.
	 *
	 * - The above also applies to the equivalent SACL flags,
	 *   SE_SACL_AUTO_INHERITED and SE_SACL_AUTO_INHERIT_REQ.
	 *
	 * - If the application says that it's setting
	 *   DACL_SECURITY_INFORMATION, then Windows sets SE_DACL_PRESENT in the
	 *   resulting security descriptor, even if the security descriptor the
	 *   application provided did not have a DACL.  This seems to be
	 *   unavoidable, since omitting DACL_SECURITY_INFORMATION would cause a
	 *   default DACL to remain.  Fortunately, this behavior seems harmless,
	 *   since the resulting DACL will still be "null" --- but it will be
	 *   "the other representation of null".
	 *
	 * - The above also applies to SACL_SECURITY_INFORMATION and
	 *   SE_SACL_PRESENT.  Again, it's seemingly unavoidable but "harmless"
	 *   that Windows changes the representation of a "null SACL".
	 */
	if (likely(desc_size <= STACK_MAX)) {
		desc = alloca(desc_size);
	} else {
		desc = MALLOC(desc_size);
		if (!desc)
			return STATUS_NO_MEMORY;
	}

	memcpy(desc, _desc, desc_size);

	if (likely(desc_size >= 4)) {

		if (desc->Control & SE_DACL_AUTO_INHERITED)
			desc->Control |= SE_DACL_AUTO_INHERIT_REQ;

		if (desc->Control & SE_SACL_AUTO_INHERITED)
			desc->Control |= SE_SACL_AUTO_INHERIT_REQ;
	}

	/*
	 * More API insanity.  We want to set the entire security descriptor
	 * as-is.  But all available APIs require specifying the specific parts
	 * of the security descriptor being set.  Especially annoying is that
	 * mandatory integrity labels are part of the SACL, but they aren't set
	 * with SACL_SECURITY_INFORMATION.  Instead, applications must also
	 * specify LABEL_SECURITY_INFORMATION (Windows Vista, Windows 7) or
	 * BACKUP_SECURITY_INFORMATION (Windows 8).  But at least older versions
	 * of Windows don't error out if you provide these newer flags...
	 *
	 * Also, if the process isn't running as Administrator, then it probably
	 * doesn't have SE_RESTORE_PRIVILEGE.  In this case, it will always get
	 * the STATUS_PRIVILEGE_NOT_HELD error by trying to set the SACL, even
	 * if the security descriptor it provided did not have a SACL.  By
	 * default, in this case we try to recover and set as much of the
	 * security descriptor as possible --- potentially excluding the DACL, and
	 * even the owner, as well as the SACL.
	 */

	info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
	       DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION |
	       LABEL_SECURITY_INFORMATION | BACKUP_SECURITY_INFORMATION;


	/*
	 * It's also worth noting that SetFileSecurity() is unusable because it
	 * doesn't request "backup semantics" when it opens the file internally.
	 * NtSetSecurityObject() seems to be the best function to use in backup
	 * applications.  (SetSecurityInfo() should also work, but it's harder
	 * to use and must call NtSetSecurityObject() internally anyway.
	 * BackupWrite() is theoretically usable as well, but it's inflexible
	 * and poorly documented.)
	 */

retry:
	status = (*func_NtSetSecurityObject)(h, info, desc);
	if (NT_SUCCESS(status))
		goto out_maybe_free_desc;

	/* Failed to set the requested parts of the security descriptor.  If the
	 * error was permissions-related, try to set fewer parts of the security
	 * descriptor, unless WIMLIB_EXTRACT_FLAG_STRICT_ACLS is enabled.  */
	if ((status == STATUS_PRIVILEGE_NOT_HELD ||
	     status == STATUS_ACCESS_DENIED) &&
	    !(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS))
	{
		if (info & SACL_SECURITY_INFORMATION) {
			info &= ~(SACL_SECURITY_INFORMATION |
				  LABEL_SECURITY_INFORMATION |
				  BACKUP_SECURITY_INFORMATION);
			ctx->partial_security_descriptors++;
			goto retry;
		}
		if (info & DACL_SECURITY_INFORMATION) {
			info &= ~DACL_SECURITY_INFORMATION;
			goto retry;
		}
		if (info & OWNER_SECURITY_INFORMATION) {
			info &= ~OWNER_SECURITY_INFORMATION;
			goto retry;
		}
		/* Nothing left except GROUP, and if we removed it we
		 * wouldn't have anything at all.  */
	}

	/* No part of the security descriptor could be set, or
	 * WIMLIB_EXTRACT_FLAG_STRICT_ACLS is enabled and the full security
	 * descriptor could not be set.  */
	if (!(info & SACL_SECURITY_INFORMATION))
		ctx->partial_security_descriptors--;
	ctx->no_security_descriptors++;

out_maybe_free_desc:
	if (unlikely(desc_size > STACK_MAX))
		FREE(desc);
	return status;
}

/* Set metadata on the open file @h from the WIM inode @inode.  */
static int
do_apply_metadata_to_file(HANDLE h, const struct wim_inode *inode,
			  struct win32_apply_ctx *ctx)
{
	FILE_BASIC_INFORMATION info;
	NTSTATUS status;

	/* Set security descriptor if present and not in NO_ACLS mode  */
	if (inode->i_security_id >= 0 &&
	    !(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS))
	{
		const struct wim_security_data *sd;
		const void *desc;
		size_t desc_size;

		sd = wim_get_current_security_data(ctx->common.wim);
		desc = sd->descriptors[inode->i_security_id];
		desc_size = sd->sizes[inode->i_security_id];

		status = set_security_descriptor(h, desc, desc_size, ctx);
		if (!NT_SUCCESS(status) &&
		    (ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS))
		{
			set_errno_from_nt_status(status);
			ERROR_WITH_ERRNO("Can't set security descriptor "
					 "on \"%ls\" (status=0x%08"PRIx32")",
					 current_path(ctx), (u32)status);
			return WIMLIB_ERR_SET_SECURITY;
		}
	}

	/* Set attributes and timestamps  */
	info.CreationTime.QuadPart = inode->i_creation_time;
	info.LastAccessTime.QuadPart = inode->i_last_access_time;
	info.LastWriteTime.QuadPart = inode->i_last_write_time;
	info.ChangeTime.QuadPart = 0;
	if (ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_NO_ATTRIBUTES)
		info.FileAttributes = 0;
	else
		info.FileAttributes = inode->i_attributes & ~SPECIAL_ATTRIBUTES;

	status = (*func_NtSetInformationFile)(h, &ctx->iosb,
					      &info, sizeof(info),
					      FileBasicInformation);
	/* On FAT volumes we get STATUS_INVALID_PARAMETER if we try to set
	 * attributes on the root directory.  (Apparently because FAT doesn't
	 * actually have a place to store those attributes!)  */
	if (!NT_SUCCESS(status)
	    && !(status == STATUS_INVALID_PARAMETER &&
		 dentry_is_root(inode_first_extraction_dentry(inode))))
	{
		set_errno_from_nt_status(status);
		ERROR_WITH_ERRNO("Can't set basic metadata on \"%ls\" "
				 "(status=0x%08"PRIx32")",
				 current_path(ctx), (u32)status);
		return WIMLIB_ERR_SET_ATTRIBUTES;
	}

	return 0;
}

static int
apply_metadata_to_file(const struct wim_dentry *dentry,
		       struct win32_apply_ctx *ctx)
{
	const struct wim_inode *inode = dentry->d_inode;
	DWORD perms;
	HANDLE h;
	NTSTATUS status;
	int ret;

	perms = FILE_WRITE_ATTRIBUTES | WRITE_DAC |
		WRITE_OWNER | ACCESS_SYSTEM_SECURITY;

	build_extraction_path(dentry, ctx);

	/* Open a handle with as many relevant permissions as possible.  */
	while (!NT_SUCCESS(status = do_create_file(&h, perms, NULL,
						   0, FILE_OPEN, 0, ctx)))
	{
		if (status == STATUS_PRIVILEGE_NOT_HELD ||
		    status == STATUS_ACCESS_DENIED)
		{
			if (perms & ACCESS_SYSTEM_SECURITY) {
				perms &= ~ACCESS_SYSTEM_SECURITY;
				continue;
			}
			if (perms & WRITE_DAC) {
				perms &= ~WRITE_DAC;
				continue;
			}
			if (perms & WRITE_OWNER) {
				perms &= ~WRITE_OWNER;
				continue;
			}
		}
		set_errno_from_nt_status(status);
		ERROR_WITH_ERRNO("Can't open \"%ls\" to set metadata "
				 "(status=0x%08"PRIx32")",
				 current_path(ctx), (u32)status);
		return WIMLIB_ERR_OPEN;
	}

	ret = do_apply_metadata_to_file(h, inode, ctx);

	(*func_NtClose)(h);

	return ret;
}

static int
apply_metadata(struct list_head *dentry_list, struct win32_apply_ctx *ctx)
{
	const struct wim_dentry *dentry;
	int ret;

	/* We go in reverse so that metadata is set on all a directory's
	 * children before the directory itself.  This avoids any potential
	 * problems with attributes, timestamps, or security descriptors.  */
	list_for_each_entry_reverse(dentry, dentry_list, d_extraction_list_node)
	{
		ret = apply_metadata_to_file(dentry, ctx);
		ret = check_apply_error(dentry, ctx, ret);
		if (ret)
			return ret;
		ret = report_file_metadata_applied(&ctx->common);
		if (ret)
			return ret;
	}
	return 0;
}

/* Issue warnings about problems during the extraction for which warnings were
 * not already issued (due to the high number of potential warnings if we issued
 * them per-file).  */
static void
do_warnings(const struct win32_apply_ctx *ctx)
{
	if (ctx->partial_security_descriptors == 0
	    && ctx->no_security_descriptors == 0
	    && ctx->num_set_short_name_failures == 0
	#if 0
	    && ctx->num_remove_short_name_failures == 0
	#endif
	    )
		return;

	WARNING("Extraction to \"%ls\" complete, but with one or more warnings:",
		ctx->common.target);
	if (ctx->num_set_short_name_failures) {
		WARNING("- Could not set short names on %lu files or directories",
			ctx->num_set_short_name_failures);
	}
#if 0
	if (ctx->num_remove_short_name_failures) {
		WARNING("- Could not remove short names on %lu files or directories"
			"          (This is expected on Vista and earlier)",
			ctx->num_remove_short_name_failures);
	}
#endif
	if (ctx->partial_security_descriptors) {
		WARNING("- Could only partially set the security descriptor\n"
			"            on %lu files or directories.",
			ctx->partial_security_descriptors);
	}
	if (ctx->no_security_descriptors) {
		WARNING("- Could not set security descriptor at all\n"
			"            on %lu files or directories.",
			ctx->no_security_descriptors);
	}
	if (ctx->partial_security_descriptors || ctx->no_security_descriptors) {
		WARNING("To fully restore all security descriptors, run the program\n"
			"          with Administrator rights.");
	}
}

static uint64_t
count_dentries(const struct list_head *dentry_list)
{
	const struct list_head *cur;
	uint64_t count = 0;

	list_for_each(cur, dentry_list)
		count++;

	return count;
}

/* Extract files from a WIM image to a directory on Windows  */
static int
win32_extract(struct list_head *dentry_list, struct apply_ctx *_ctx)
{
	int ret;
	struct win32_apply_ctx *ctx = (struct win32_apply_ctx *)_ctx;
	uint64_t dentry_count;

	ret = prepare_target(dentry_list, ctx);
	if (ret)
		goto out;

	if (unlikely(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_WIMBOOT)) {
		ret = start_wimboot_extraction(ctx);
		if (ret)
			goto out;
	}

	dentry_count = count_dentries(dentry_list);

	ret = start_file_structure_phase(&ctx->common, dentry_count);
	if (ret)
		goto out;

	ret = create_directories(dentry_list, ctx);
	if (ret)
		goto out;

	ret = create_nondirectories(dentry_list, ctx);
	if (ret)
		goto out;

	ret = end_file_structure_phase(&ctx->common);
	if (ret)
		goto out;

	struct read_stream_list_callbacks cbs = {
		.begin_stream      = begin_extract_stream,
		.begin_stream_ctx  = ctx,
		.consume_chunk     = extract_chunk,
		.consume_chunk_ctx = ctx,
		.end_stream        = end_extract_stream,
		.end_stream_ctx    = ctx,
	};
	ret = extract_stream_list(&ctx->common, &cbs);
	if (ret)
		goto out;

	ret = start_file_metadata_phase(&ctx->common, dentry_count);
	if (ret)
		goto out;

	ret = apply_metadata(dentry_list, ctx);
	if (ret)
		goto out;

	ret = end_file_metadata_phase(&ctx->common);
	if (ret)
		goto out;

	if (unlikely(ctx->common.extract_flags & WIMLIB_EXTRACT_FLAG_WIMBOOT)) {
		ret = end_wimboot_extraction(ctx);
		if (ret)
			goto out;
	}

	do_warnings(ctx);
out:
	if (ctx->h_target)
		(*func_NtClose)(ctx->h_target);
	if (ctx->target_ntpath.Buffer)
		HeapFree(GetProcessHeap(), 0, ctx->target_ntpath.Buffer);
	FREE(ctx->pathbuf.Buffer);
	FREE(ctx->print_buffer);
	if (ctx->wimboot.prepopulate_pats) {
		FREE(ctx->wimboot.prepopulate_pats->strings);
		FREE(ctx->wimboot.prepopulate_pats);
	}
	FREE(ctx->wimboot.mem_prepopulate_pats);
	FREE(ctx->data_buffer);
	return ret;
}

const struct apply_operations win32_apply_ops = {
	.name			= "Windows",
	.get_supported_features = win32_get_supported_features,
	.extract                = win32_extract,
	.will_externally_back   = win32_will_externally_back,
	.context_size           = sizeof(struct win32_apply_ctx),
};

#endif /* __WIN32__ */
