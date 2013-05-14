/*
 * win32_capture.c - Windows-specific code for capturing files into a WIM image.
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

#ifdef __WIN32__

#include "win32_common.h"
#include "wimlib_internal.h"
#include "lookup_table.h"
#include "security.h"
#include "endianness.h"

#define MAX_GET_SD_ACCESS_DENIED_WARNINGS 1
#define MAX_GET_SACL_PRIV_NOTHELD_WARNINGS 1
struct win32_capture_state {
	unsigned long num_get_sd_access_denied;
	unsigned long num_get_sacl_priv_notheld;
};


static const wchar_t *capture_access_denied_msg =
L"         If you are not running this program as the administrator, you may\n"
 "         need to do so, so that all data and metadata can be backed up.\n"
 "         Otherwise, there may be no way to access the desired data or\n"
 "         metadata without taking ownership of the file or directory.\n"
 ;

int
read_win32_file_prefix(const struct wim_lookup_table_entry *lte,
		       u64 size,
		       consume_data_callback_t cb,
		       void *ctx_or_buf,
		       int _ignored_flags)
{
	int ret = 0;
	void *out_buf;
	DWORD err;
	u64 bytes_remaining;

	HANDLE hFile = win32_open_file_data_only(lte->file_on_disk);
	if (hFile == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		ERROR("Failed to open \"%ls\"", lte->file_on_disk);
		win32_error(err);
		return WIMLIB_ERR_OPEN;
	}

	if (cb)
		out_buf = alloca(WIM_CHUNK_SIZE);
	else
		out_buf = ctx_or_buf;

	bytes_remaining = size;
	while (bytes_remaining) {
		DWORD bytesToRead, bytesRead;

		bytesToRead = min(WIM_CHUNK_SIZE, bytes_remaining);
		if (!ReadFile(hFile, out_buf, bytesToRead, &bytesRead, NULL) ||
		    bytesRead != bytesToRead)
		{
			err = GetLastError();
			ERROR("Failed to read data from \"%ls\"", lte->file_on_disk);
			win32_error(err);
			ret = WIMLIB_ERR_READ;
			break;
		}
		bytes_remaining -= bytesRead;
		if (cb) {
			ret = (*cb)(out_buf, bytesRead, ctx_or_buf);
			if (ret)
				break;
		} else {
			out_buf += bytesRead;
		}
	}
	CloseHandle(hFile);
	return ret;
}

struct win32_encrypted_read_ctx {
	consume_data_callback_t read_prefix_cb;
	void *read_prefix_ctx_or_buf;
	int wimlib_err_code;
	void *buf;
	size_t buf_filled;
	u64 bytes_remaining;
};

static DWORD WINAPI
win32_encrypted_export_cb(unsigned char *_data, void *_ctx, unsigned long len)
{
	const void *data = _data;
	struct win32_encrypted_read_ctx *ctx = _ctx;
	int ret;

	DEBUG("len = %lu", len);
	if (ctx->read_prefix_cb) {
		/* The length of the buffer passed to the ReadEncryptedFileRaw()
		 * export callback is undocumented, so we assume it may be of
		 * arbitrary size. */
		size_t bytes_to_buffer = min(ctx->bytes_remaining - ctx->buf_filled,
					     len);
		while (bytes_to_buffer) {
			size_t bytes_to_copy_to_buf =
				min(bytes_to_buffer, WIM_CHUNK_SIZE - ctx->buf_filled);

			memcpy(ctx->buf + ctx->buf_filled, data,
			       bytes_to_copy_to_buf);
			ctx->buf_filled += bytes_to_copy_to_buf;
			data += bytes_to_copy_to_buf;
			bytes_to_buffer -= bytes_to_copy_to_buf;

			if (ctx->buf_filled == WIM_CHUNK_SIZE ||
			    ctx->buf_filled == ctx->bytes_remaining)
			{
				ret = (*ctx->read_prefix_cb)(ctx->buf,
							     ctx->buf_filled,
							     ctx->read_prefix_ctx_or_buf);
				if (ret) {
					ctx->wimlib_err_code = ret;
					/* Shouldn't matter what error code is returned
					 * here, as long as it isn't ERROR_SUCCESS. */
					return ERROR_READ_FAULT;
				}
				ctx->bytes_remaining -= ctx->buf_filled;
				ctx->buf_filled = 0;
			}
		}
	} else {
		size_t len_to_copy = min(len, ctx->bytes_remaining);
		memcpy(ctx->read_prefix_ctx_or_buf, data, len_to_copy);
		ctx->bytes_remaining -= len_to_copy;
		ctx->read_prefix_ctx_or_buf += len_to_copy;
	}
	return ERROR_SUCCESS;
}

int
read_win32_encrypted_file_prefix(const struct wim_lookup_table_entry *lte,
				 u64 size,
				 consume_data_callback_t cb,
				 void *ctx_or_buf,
				 int _ignored_flags)
{
	struct win32_encrypted_read_ctx export_ctx;
	DWORD err;
	void *file_ctx;
	int ret;

	DEBUG("Reading %"PRIu64" bytes from encryted file \"%ls\"",
	      size, lte->file_on_disk);

	export_ctx.read_prefix_cb = cb;
	export_ctx.read_prefix_ctx_or_buf = ctx_or_buf;
	export_ctx.wimlib_err_code = 0;
	if (cb) {
		export_ctx.buf = MALLOC(WIM_CHUNK_SIZE);
		if (!export_ctx.buf)
			return WIMLIB_ERR_NOMEM;
	} else {
		export_ctx.buf = NULL;
	}
	export_ctx.buf_filled = 0;
	export_ctx.bytes_remaining = size;

	err = OpenEncryptedFileRawW(lte->file_on_disk, 0, &file_ctx);
	if (err != ERROR_SUCCESS) {
		ERROR("Failed to open encrypted file \"%ls\" for raw read",
		      lte->file_on_disk);
		win32_error(err);
		ret = WIMLIB_ERR_OPEN;
		goto out_free_buf;
	}
	err = ReadEncryptedFileRaw(win32_encrypted_export_cb,
				   &export_ctx, file_ctx);
	if (err != ERROR_SUCCESS) {
		ERROR("Failed to read encrypted file \"%ls\"",
		      lte->file_on_disk);
		win32_error(err);
		ret = export_ctx.wimlib_err_code;
		if (ret == 0)
			ret = WIMLIB_ERR_READ;
	} else if (export_ctx.bytes_remaining != 0) {
		ERROR("Only could read %"PRIu64" of %"PRIu64" bytes from "
		      "encryted file \"%ls\"",
		      size - export_ctx.bytes_remaining, size,
		      lte->file_on_disk);
		ret = WIMLIB_ERR_READ;
	} else {
		ret = 0;
	}
	CloseEncryptedFileRaw(file_ctx);
out_free_buf:
	FREE(export_ctx.buf);
	return ret;
}


static u64
FILETIME_to_u64(const FILETIME *ft)
{
	return ((u64)ft->dwHighDateTime << 32) | (u64)ft->dwLowDateTime;
}

static int
win32_get_short_name(struct wim_dentry *dentry, const wchar_t *path)
{
	WIN32_FIND_DATAW dat;
	HANDLE hFind;
	int ret = 0;

	/* If we can't read the short filename for some reason, we just ignore
	 * the error and assume the file has no short name.  I don't think this
	 * should be an issue, since the short names are essentially obsolete
	 * anyway. */
	hFind = FindFirstFileW(path, &dat);
	if (hFind != INVALID_HANDLE_VALUE) {
		if (dat.cAlternateFileName[0] != L'\0') {
			DEBUG("\"%ls\": short name \"%ls\"", path, dat.cAlternateFileName);
			size_t short_name_nbytes = wcslen(dat.cAlternateFileName) *
						   sizeof(wchar_t);
			size_t n = short_name_nbytes + sizeof(wchar_t);
			dentry->short_name = MALLOC(n);
			if (dentry->short_name) {
				memcpy(dentry->short_name, dat.cAlternateFileName, n);
				dentry->short_name_nbytes = short_name_nbytes;
			} else {
				ret = WIMLIB_ERR_NOMEM;
			}
		}
		FindClose(hFind);
	}
	return ret;
}

static int
win32_get_security_descriptor(struct wim_dentry *dentry,
			      struct sd_set *sd_set,
			      const wchar_t *path,
			      struct win32_capture_state *state,
			      int add_flags)
{
	SECURITY_INFORMATION requestedInformation;
	DWORD lenNeeded = 0;
	BOOL status;
	DWORD err;
	unsigned long n;

	requestedInformation = DACL_SECURITY_INFORMATION |
			       SACL_SECURITY_INFORMATION |
			       OWNER_SECURITY_INFORMATION |
			       GROUP_SECURITY_INFORMATION;
again:
	/* Request length of security descriptor */
	status = GetFileSecurityW(path, requestedInformation,
				  NULL, 0, &lenNeeded);
	err = GetLastError();
	if (!status && err == ERROR_INSUFFICIENT_BUFFER) {
		DWORD len = lenNeeded;
		char buf[len];
		if (GetFileSecurityW(path, requestedInformation,
				     (PSECURITY_DESCRIPTOR)buf, len, &lenNeeded))
		{
			int security_id = sd_set_add_sd(sd_set, buf, len);
			if (security_id < 0)
				return WIMLIB_ERR_NOMEM;
			else {
				dentry->d_inode->i_security_id = security_id;
				return 0;
			}
		} else {
			err = GetLastError();
		}
	}

	if (add_flags & WIMLIB_ADD_FLAG_STRICT_ACLS)
		goto fail;

	switch (err) {
	case ERROR_PRIVILEGE_NOT_HELD:
		if (requestedInformation & SACL_SECURITY_INFORMATION) {
			n = state->num_get_sacl_priv_notheld++;
			requestedInformation &= ~SACL_SECURITY_INFORMATION;
			if (n < MAX_GET_SACL_PRIV_NOTHELD_WARNINGS) {
				WARNING(
"We don't have enough privileges to read the full security\n"
"          descriptor of \"%ls\"!\n"
"          Re-trying with SACL omitted.\n", path);
			} else if (n == MAX_GET_SACL_PRIV_NOTHELD_WARNINGS) {
				WARNING(
"Suppressing further privileges not held error messages when reading\n"
"          security descriptors.");
			}
			goto again;
		}
		/* Fall through */
	case ERROR_ACCESS_DENIED:
		n = state->num_get_sd_access_denied++;
		if (n < MAX_GET_SD_ACCESS_DENIED_WARNINGS) {
			WARNING("Failed to read security descriptor of \"%ls\": "
				"Access denied!\n%ls", path, capture_access_denied_msg);
		} else if (n == MAX_GET_SD_ACCESS_DENIED_WARNINGS) {
			WARNING("Suppressing further access denied errors messages i"
				"when reading security descriptors");
		}
		return 0;
	default:
fail:
		ERROR("Failed to read security descriptor of \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_READ;
	}
}

static int
win32_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				  wchar_t *path,
				  size_t path_num_chars,
				  struct add_image_params *params,
				  struct win32_capture_state *state,
				  unsigned vol_flags);

/* Reads the directory entries of directory using a Win32 API and recursively
 * calls win32_build_dentry_tree() on them. */
static int
win32_recurse_directory(struct wim_dentry *root,
			wchar_t *dir_path,
			size_t dir_path_num_chars,
			struct add_image_params *params,
			struct win32_capture_state *state,
			unsigned vol_flags)
{
	WIN32_FIND_DATAW dat;
	HANDLE hFind;
	DWORD err;
	int ret;

	DEBUG("Recurse to directory \"%ls\"", dir_path);

	/* Begin reading the directory by calling FindFirstFileW.  Unlike UNIX
	 * opendir(), FindFirstFileW has file globbing built into it.  But this
	 * isn't what we actually want, so just add a dummy glob to get all
	 * entries. */
	dir_path[dir_path_num_chars] = L'/';
	dir_path[dir_path_num_chars + 1] = L'*';
	dir_path[dir_path_num_chars + 2] = L'\0';
	hFind = FindFirstFileW(dir_path, &dat);
	dir_path[dir_path_num_chars] = L'\0';

	if (hFind == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			return 0;
		} else {
			ERROR("Failed to read directory \"%ls\"", dir_path);
			win32_error(err);
			return WIMLIB_ERR_READ;
		}
	}
	ret = 0;
	do {
		/* Skip . and .. entries */
		if (dat.cFileName[0] == L'.' &&
		    (dat.cFileName[1] == L'\0' ||
		     (dat.cFileName[1] == L'.' &&
		      dat.cFileName[2] == L'\0')))
			continue;
		size_t filename_len = wcslen(dat.cFileName);

		dir_path[dir_path_num_chars] = L'/';
		wmemcpy(dir_path + dir_path_num_chars + 1,
			dat.cFileName,
			filename_len + 1);

		struct wim_dentry *child;
		size_t path_len = dir_path_num_chars + 1 + filename_len;
		ret = win32_build_dentry_tree_recursive(&child,
							dir_path,
							path_len,
							params,
							state,
							vol_flags);
		dir_path[dir_path_num_chars] = L'\0';
		if (ret)
			goto out_find_close;
		if (child)
			dentry_add_child(root, child);
	} while (FindNextFileW(hFind, &dat));
	err = GetLastError();
	if (err != ERROR_NO_MORE_FILES) {
		ERROR("Failed to read directory \"%ls\"", dir_path);
		win32_error(err);
		if (ret == 0)
			ret = WIMLIB_ERR_READ;
	}
out_find_close:
	FindClose(hFind);
	return ret;
}

int
win32_get_file_and_vol_ids(const wchar_t *path, u64 *ino_ret, u64 *dev_ret)
{
	HANDLE hFile;
	DWORD err;
	BY_HANDLE_FILE_INFORMATION file_info;
	int ret;

 	hFile = win32_open_existing_file(path, FILE_READ_ATTRIBUTES);
	if (hFile == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err != ERROR_FILE_NOT_FOUND) {
			WARNING("Failed to open \"%ls\" to get file "
				"and volume IDs", path);
			win32_error(err);
		}
		return WIMLIB_ERR_OPEN;
	}

	if (!GetFileInformationByHandle(hFile, &file_info)) {
		err = GetLastError();
		ERROR("Failed to get file information for \"%ls\"", path);
		win32_error(err);
		ret = WIMLIB_ERR_STAT;
	} else {
		*ino_ret = ((u64)file_info.nFileIndexHigh << 32) |
			    (u64)file_info.nFileIndexLow;
		*dev_ret = file_info.dwVolumeSerialNumber;
		ret = 0;
	}
	CloseHandle(hFile);
	return ret;
}

/* Reparse point fixup status code */
enum rp_status {
	/* Reparse point corresponded to an absolute symbolic link or junction
	 * point that pointed outside the directory tree being captured, and
	 * therefore was excluded. */
	RP_EXCLUDED       = 0x0,

	/* Reparse point was not fixed as it was either a relative symbolic
	 * link, a mount point, or something else we could not understand. */
	RP_NOT_FIXED      = 0x1,

	/* Reparse point corresponded to an absolute symbolic link or junction
	 * point that pointed inside the directory tree being captured, where
	 * the target was specified by a "full" \??\ prefixed path, and
	 * therefore was fixed to be relative to the root of the directory tree
	 * being captured. */
	RP_FIXED_FULLPATH = 0x2,

	/* Same as RP_FIXED_FULLPATH, except the absolute link target did not
	 * have the \??\ prefix.  It may have begun with a drive letter though.
	 * */
	RP_FIXED_ABSPATH  = 0x4,

	/* Either RP_FIXED_FULLPATH or RP_FIXED_ABSPATH. */
	RP_FIXED          = RP_FIXED_FULLPATH | RP_FIXED_ABSPATH,
};

/* Given the "substitute name" target of a Windows reparse point, try doing a
 * fixup where we change it to be absolute relative to the root of the directory
 * tree being captured.
 *
 * Note that this is only executed when WIMLIB_ADD_FLAG_RPFIX has been
 * set.
 *
 * @capture_root_ino and @capture_root_dev indicate the inode number and device
 * of the root of the directory tree being captured.  They are meant to identify
 * this directory (as an alternative to its actual path, which could potentially
 * be reached via multiple destinations due to other symbolic links).  This may
 * not work properly on FAT, which doesn't seem to supply proper inode numbers
 * or file IDs.  However, FAT doesn't support reparse points so this function
 * wouldn't even be called anyway.
 */
static enum rp_status
win32_capture_maybe_rpfix_target(wchar_t *target, u16 *target_nbytes_p,
				 u64 capture_root_ino, u64 capture_root_dev,
				 u32 rptag)
{
	u16 target_nchars = *target_nbytes_p / 2;
	size_t stripped_chars;
	wchar_t *orig_target;
	int ret;

	ret = parse_substitute_name(target, *target_nbytes_p, rptag);
	if (ret < 0)
		return RP_NOT_FIXED;
	stripped_chars = ret;
	if (stripped_chars)
		stripped_chars -= 2;
	target[target_nchars] = L'\0';
	orig_target = target;
	target = capture_fixup_absolute_symlink(target + stripped_chars,
						capture_root_ino, capture_root_dev);
	if (!target)
		return RP_EXCLUDED;
	target_nchars = wcslen(target);
	wmemmove(orig_target + stripped_chars, target, target_nchars + 1);
	*target_nbytes_p = (target_nchars + stripped_chars) * sizeof(wchar_t);
	DEBUG("Fixed reparse point (new target: \"%ls\")", orig_target);
	if (stripped_chars)
		return RP_FIXED_FULLPATH;
	else
		return RP_FIXED_ABSPATH;
}

/* Returns: `enum rp_status' value on success; negative WIMLIB_ERR_* value on
 * failure. */
static int
win32_capture_try_rpfix(u8 *rpbuf, u16 *rpbuflen_p,
			u64 capture_root_ino, u64 capture_root_dev,
			const wchar_t *path)
{
	struct reparse_data rpdata;
	DWORD rpbuflen;
	int ret;
	enum rp_status rp_status;

	rpbuflen = *rpbuflen_p;
	ret = parse_reparse_data(rpbuf, rpbuflen, &rpdata);
	if (ret)
		return -ret;

	rp_status = win32_capture_maybe_rpfix_target(rpdata.substitute_name,
						     &rpdata.substitute_name_nbytes,
						     capture_root_ino,
						     capture_root_dev,
						     le32_to_cpu(*(u32*)rpbuf));
	if (rp_status & RP_FIXED) {
		wimlib_assert(rpdata.substitute_name_nbytes % 2 == 0);
		utf16lechar substitute_name_copy[rpdata.substitute_name_nbytes / 2];
		wmemcpy(substitute_name_copy, rpdata.substitute_name,
			rpdata.substitute_name_nbytes / 2);
		rpdata.substitute_name = substitute_name_copy;
		rpdata.print_name = substitute_name_copy;
		rpdata.print_name_nbytes = rpdata.substitute_name_nbytes;
		if (rp_status == RP_FIXED_FULLPATH) {
			/* "full path", meaning \??\ prefixed.  We should not
			 * include this prefix in the print name, as it is
			 * apparently meant for the filesystem driver only. */
			rpdata.print_name += 4;
			rpdata.print_name_nbytes -= 8;
		}
		ret = make_reparse_buffer(&rpdata, rpbuf);
		if (ret == 0)
			ret = rp_status;
		else
			ret = -ret;
	} else {
		if (rp_status == RP_EXCLUDED) {
			size_t print_name_nchars = rpdata.print_name_nbytes / 2;
			wchar_t print_name0[print_name_nchars + 1];
			print_name0[print_name_nchars] = L'\0';
			wmemcpy(print_name0, rpdata.print_name, print_name_nchars);
			WARNING("Ignoring %ls pointing out of capture directory:\n"
				"          \"%ls\" -> \"%ls\"\n"
				"          (Use --norpfix to capture all symbolic links "
				"and junction points as-is)",
				(rpdata.rptag == WIM_IO_REPARSE_TAG_SYMLINK) ?
					L"absolute symbolic link" : L"junction point",
				path, print_name0);
		}
		ret = rp_status;
	}
	return ret;
}

/*
 * Loads the reparse point data from a reparse point into memory, optionally
 * fixing the targets of absolute symbolic links and junction points to be
 * relative to the root of capture.
 *
 * @hFile:  Open handle to the reparse point.
 * @path:   Path to the reparse point.  Used for error messages only.
 * @params: Additional parameters, including whether to do reparse point fixups
 *          or not.
 * @rpbuf:  Buffer of length at least REPARSE_POINT_MAX_SIZE bytes into which
 *          the reparse point buffer will be loaded.
 * @rpbuflen_ret:  On success, the length of the reparse point buffer in bytes
 *                 is written to this location.
 *
 * Returns:
 *	On success, returns an `enum rp_status' value that indicates if and/or
 *	how the reparse point fixup was done.
 *
 *	On failure, returns a negative value that is a negated WIMLIB_ERR_*
 *	code.
 */
static int
win32_get_reparse_data(HANDLE hFile, const wchar_t *path,
		       struct add_image_params *params,
		       u8 *rpbuf, u16 *rpbuflen_ret)
{
	DWORD bytesReturned;
	u32 reparse_tag;
	int ret;
	u16 rpbuflen;

	DEBUG("Loading reparse data from \"%ls\"", path);
	if (!DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT,
			     NULL, /* "Not used with this operation; set to NULL" */
			     0, /* "Not used with this operation; set to 0" */
			     rpbuf, /* "A pointer to a buffer that
						   receives the reparse point data */
			     REPARSE_POINT_MAX_SIZE, /* "The size of the output
							buffer, in bytes */
			     &bytesReturned,
			     NULL))
	{
		DWORD err = GetLastError();
		ERROR("Failed to get reparse data of \"%ls\"", path);
		win32_error(err);
		return -WIMLIB_ERR_READ;
	}
	if (bytesReturned < 8 || bytesReturned > REPARSE_POINT_MAX_SIZE) {
		ERROR("Reparse data on \"%ls\" is invalid", path);
		return -WIMLIB_ERR_INVALID_REPARSE_DATA;
	}

	rpbuflen = bytesReturned;
	reparse_tag = le32_to_cpu(*(u32*)rpbuf);
	if (params->add_flags & WIMLIB_ADD_FLAG_RPFIX &&
	    (reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
	     reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT))
	{
		/* Try doing reparse point fixup */
		ret = win32_capture_try_rpfix(rpbuf,
					      &rpbuflen,
					      params->capture_root_ino,
					      params->capture_root_dev,
					      path);
	} else {
		ret = RP_NOT_FIXED;
	}
	*rpbuflen_ret = rpbuflen;
	return ret;
}

static DWORD WINAPI
win32_tally_encrypted_size_cb(unsigned char *_data, void *_ctx,
			      unsigned long len)
{
	*(u64*)_ctx += len;
	return ERROR_SUCCESS;
}

static int
win32_get_encrypted_file_size(const wchar_t *path, u64 *size_ret)
{
	DWORD err;
	void *file_ctx;
	int ret;

	*size_ret = 0;
	err = OpenEncryptedFileRawW(path, 0, &file_ctx);
	if (err != ERROR_SUCCESS) {
		ERROR("Failed to open encrypted file \"%ls\" for raw read", path);
		win32_error(err);
		return WIMLIB_ERR_OPEN;
	}
	err = ReadEncryptedFileRaw(win32_tally_encrypted_size_cb,
				   size_ret, file_ctx);
	if (err != ERROR_SUCCESS) {
		ERROR("Failed to read raw encrypted data from \"%ls\"", path);
		win32_error(err);
		ret = WIMLIB_ERR_READ;
	} else {
		ret = 0;
	}
	CloseEncryptedFileRaw(file_ctx);
	return ret;
}

/* Scans an unnamed or named stream of a Win32 file (not a reparse point
 * stream); calculates its SHA1 message digest and either creates a `struct
 * wim_lookup_table_entry' in memory for it, or uses an existing 'struct
 * wim_lookup_table_entry' for an identical stream.
 *
 * @path:               Path to the file (UTF-16LE).
 *
 * @path_num_chars:     Number of 2-byte characters in @path.
 *
 * @inode:              WIM inode to save the stream into.
 *
 * @lookup_table:       Stream lookup table for the WIM.
 *
 * @dat:                A `WIN32_FIND_STREAM_DATA' structure that specifies the
 *                      stream name.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_capture_stream(const wchar_t *path,
		     size_t path_num_chars,
		     struct wim_inode *inode,
		     struct wim_lookup_table *lookup_table,
		     WIN32_FIND_STREAM_DATA *dat)
{
	struct wim_ads_entry *ads_entry;
	struct wim_lookup_table_entry *lte;
	int ret;
	wchar_t *stream_name, *colon;
	size_t stream_name_nchars;
	bool is_named_stream;
	wchar_t *spath;
	size_t spath_nchars;
	size_t spath_buf_nbytes;
	const wchar_t *relpath_prefix;
	const wchar_t *colonchar;

	DEBUG("Capture \"%ls\" stream \"%ls\"", path, dat->cStreamName);

	/* The stream name should be returned as :NAME:TYPE */
	stream_name = dat->cStreamName;
	if (*stream_name != L':')
		goto out_invalid_stream_name;
	stream_name += 1;
	colon = wcschr(stream_name, L':');
	if (colon == NULL)
		goto out_invalid_stream_name;

	if (wcscmp(colon + 1, L"$DATA")) {
		/* Not a DATA stream */
		ret = 0;
		goto out;
	}

	*colon = '\0';

	stream_name_nchars = colon - stream_name;
	is_named_stream = (stream_name_nchars != 0);

	if (is_named_stream) {
		/* Allocate an ADS entry for the named stream. */
		ads_entry = inode_add_ads_utf16le(inode, stream_name,
						  stream_name_nchars * sizeof(wchar_t));
		if (!ads_entry) {
			ret = WIMLIB_ERR_NOMEM;
			goto out;
		}
	}

	/* If zero length stream, no lookup table entry needed. */
	if ((u64)dat->StreamSize.QuadPart == 0) {
		ret = 0;
		goto out;
	}

	/* Create a UTF-16LE string @spath that gives the filename, then a
	 * colon, then the stream name.  Or, if it's an unnamed stream, just the
	 * filename.  It is MALLOC()'ed so that it can be saved in the
	 * wim_lookup_table_entry if needed.
	 *
	 * As yet another special case, relative paths need to be changed to
	 * begin with an explicit "./" so that, for example, a file t:ads, where
	 * :ads is the part we added, is not interpreted as a file on the t:
	 * drive. */
	spath_nchars = path_num_chars;
	relpath_prefix = L"";
	colonchar = L"";
	if (is_named_stream) {
		spath_nchars += 1 + stream_name_nchars;
		colonchar = L":";
		if (path_num_chars == 1 &&
		    path[0] != L'/' &&
		    path[0] != L'\\')
		{
			spath_nchars += 2;
			relpath_prefix = L"./";
		}
	}

	spath_buf_nbytes = (spath_nchars + 1) * sizeof(wchar_t);
	spath = MALLOC(spath_buf_nbytes);

	swprintf(spath, L"%ls%ls%ls%ls",
		 relpath_prefix, path, colonchar, stream_name);

	/* Make a new wim_lookup_table_entry */
	lte = new_lookup_table_entry();
	if (!lte) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_spath;
	}
	lte->file_on_disk = spath;
	spath = NULL;
	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED && !is_named_stream) {
		u64 encrypted_size;
		lte->resource_location = RESOURCE_WIN32_ENCRYPTED;
		ret = win32_get_encrypted_file_size(path, &encrypted_size);
		if (ret)
			goto out_free_spath;
		lte->resource_entry.original_size = encrypted_size;
	} else {
		lte->resource_location = RESOURCE_WIN32;
		lte->resource_entry.original_size = (u64)dat->StreamSize.QuadPart;
	}

	u32 stream_id;
	if (is_named_stream) {
		stream_id = ads_entry->stream_id;
		ads_entry->lte = lte;
	} else {
		stream_id = 0;
		inode->i_lte = lte;
	}
	lookup_table_insert_unhashed(lookup_table, lte, inode, stream_id);
	ret = 0;
out_free_spath:
	FREE(spath);
out:
	return ret;
out_invalid_stream_name:
	ERROR("Invalid stream name: \"%ls:%ls\"", path, dat->cStreamName);
	ret = WIMLIB_ERR_READ;
	goto out;
}

/* Scans a Win32 file for unnamed and named data streams (not reparse point
 * streams).
 *
 * @path:               Path to the file (UTF-16LE).
 *
 * @path_num_chars:     Number of 2-byte characters in @path.
 *
 * @inode:              WIM inode to save the stream into.
 *
 * @lookup_table:       Stream lookup table for the WIM.
 *
 * @file_size:		Size of unnamed data stream.  (Used only if alternate
 *                      data streams API appears to be unavailable.)
 *
 * @vol_flags:          Flags that specify features of the volume being
 *			captured.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_capture_streams(const wchar_t *path,
		      size_t path_num_chars,
		      struct wim_inode *inode,
		      struct wim_lookup_table *lookup_table,
		      u64 file_size,
		      unsigned vol_flags)
{
	WIN32_FIND_STREAM_DATA dat;
	int ret;
	HANDLE hFind;
	DWORD err;

	DEBUG("Capturing streams from \"%ls\"", path);

	if (win32func_FindFirstStreamW == NULL ||
	    !(vol_flags & FILE_NAMED_STREAMS))
		goto unnamed_only;

	hFind = win32func_FindFirstStreamW(path, FindStreamInfoStandard, &dat, 0);
	if (hFind == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_CALL_NOT_IMPLEMENTED)
			goto unnamed_only;

		/* Seems legal for this to return ERROR_HANDLE_EOF on reparse
		 * points and directories */
		if ((inode->i_attributes &
		    (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
		    && err == ERROR_HANDLE_EOF)
		{
			DEBUG("ERROR_HANDLE_EOF (ok)");
			return 0;
		} else {
			if (err == ERROR_ACCESS_DENIED) {
				WARNING("Failed to look up data streams "
					"of \"%ls\": Access denied!\n%ls",
					path, capture_access_denied_msg);
				return 0;
			} else {
				ERROR("Failed to look up data streams "
				      "of \"%ls\"", path);
				win32_error(err);
				return WIMLIB_ERR_READ;
			}
		}
	}
	do {
		ret = win32_capture_stream(path,
					   path_num_chars,
					   inode, lookup_table,
					   &dat);
		if (ret)
			goto out_find_close;
	} while (win32func_FindNextStreamW(hFind, &dat));
	err = GetLastError();
	if (err != ERROR_HANDLE_EOF) {
		ERROR("Win32 API: Error reading data streams from \"%ls\"", path);
		win32_error(err);
		ret = WIMLIB_ERR_READ;
	}
out_find_close:
	FindClose(hFind);
	return ret;
unnamed_only:
	/* FindFirstStreamW() API is not available, or the volume does not
	 * support named streams.  Only capture the unnamed data stream. */
	DEBUG("Only capturing unnamed data stream");
	if (inode->i_attributes &
	     (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
	{
		ret = 0;
	} else {
		/* Just create our own WIN32_FIND_STREAM_DATA for an unnamed
		 * stream to reduce the code to a call to the
		 * already-implemented win32_capture_stream() */
		wcscpy(dat.cStreamName, L"::$DATA");
		dat.StreamSize.QuadPart = file_size;
		ret = win32_capture_stream(path,
					   path_num_chars,
					   inode, lookup_table,
					   &dat);
	}
	return ret;
}

static int
win32_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				  wchar_t *path,
				  size_t path_num_chars,
				  struct add_image_params *params,
				  struct win32_capture_state *state,
				  unsigned vol_flags)
{
	struct wim_dentry *root = NULL;
	struct wim_inode *inode;
	DWORD err;
	u64 file_size;
	int ret;
	u8 *rpbuf;
	u16 rpbuflen;
	u16 not_rpfixed;

	if (exclude_path(path, path_num_chars, params->config, true)) {
		if (params->add_flags & WIMLIB_ADD_FLAG_ROOT) {
			ERROR("Cannot exclude the root directory from capture");
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
			goto out;
		}
		if ((params->add_flags & WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE)
		    && params->progress_func)
		{
			union wimlib_progress_info info;
			info.scan.cur_path = path;
			info.scan.excluded = true;
			params->progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
		}
		ret = 0;
		goto out;
	}

	if ((params->add_flags & WIMLIB_ADD_FLAG_VERBOSE)
	    && params->progress_func)
	{
		union wimlib_progress_info info;
		info.scan.cur_path = path;
		info.scan.excluded = false;
		params->progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
	}

	HANDLE hFile = win32_open_existing_file(path,
						FILE_READ_DATA | FILE_READ_ATTRIBUTES);
	if (hFile == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		ERROR("Win32 API: Failed to open \"%ls\"", path);
		win32_error(err);
		ret = WIMLIB_ERR_OPEN;
		goto out;
	}

	BY_HANDLE_FILE_INFORMATION file_info;
	if (!GetFileInformationByHandle(hFile, &file_info)) {
		err = GetLastError();
		ERROR("Win32 API: Failed to get file information for \"%ls\"",
		      path);
		win32_error(err);
		ret = WIMLIB_ERR_STAT;
		goto out_close_handle;
	}

	if (file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		rpbuf = alloca(REPARSE_POINT_MAX_SIZE);
		ret = win32_get_reparse_data(hFile, path, params,
					     rpbuf, &rpbuflen);
		if (ret < 0) {
			/* WIMLIB_ERR_* (inverted) */
			ret = -ret;
			goto out_close_handle;
		} else if (ret & RP_FIXED) {
			not_rpfixed = 0;
		} else if (ret == RP_EXCLUDED) {
			ret = 0;
			goto out_close_handle;
		} else {
			not_rpfixed = 1;
		}
	}

	/* Create a WIM dentry with an associated inode, which may be shared.
	 *
	 * However, we need to explicitly check for directories and files with
	 * only 1 link and refuse to hard link them.  This is because Windows
	 * has a bug where it can return duplicate File IDs for files and
	 * directories on the FAT filesystem. */
	ret = inode_table_new_dentry(params->inode_table,
				     path_basename_with_len(path, path_num_chars),
				     ((u64)file_info.nFileIndexHigh << 32) |
					 (u64)file_info.nFileIndexLow,
				     file_info.dwVolumeSerialNumber,
				     (file_info.nNumberOfLinks <= 1 ||
				        (file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)),
				     &root);
	if (ret)
		goto out_close_handle;

	ret = win32_get_short_name(root, path);
	if (ret)
		goto out_close_handle;

	inode = root->d_inode;

	if (inode->i_nlink > 1) /* Shared inode; nothing more to do */
		goto out_close_handle;

	inode->i_attributes = file_info.dwFileAttributes;
	inode->i_creation_time = FILETIME_to_u64(&file_info.ftCreationTime);
	inode->i_last_write_time = FILETIME_to_u64(&file_info.ftLastWriteTime);
	inode->i_last_access_time = FILETIME_to_u64(&file_info.ftLastAccessTime);
	inode->i_resolved = 1;

	params->add_flags &= ~WIMLIB_ADD_FLAG_ROOT;

	if (!(params->add_flags & WIMLIB_ADD_FLAG_NO_ACLS)
	    && (vol_flags & FILE_PERSISTENT_ACLS))
	{
		ret = win32_get_security_descriptor(root, params->sd_set,
						    path, state,
						    params->add_flags);
		if (ret)
			goto out_close_handle;
	}

	file_size = ((u64)file_info.nFileSizeHigh << 32) |
		     (u64)file_info.nFileSizeLow;

	CloseHandle(hFile);

	/* Capture the unnamed data stream (only should be present for regular
	 * files) and any alternate data streams. */
	ret = win32_capture_streams(path,
				    path_num_chars,
				    inode,
				    params->lookup_table,
				    file_size,
				    vol_flags);
	if (ret)
		goto out;

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		/* Reparse point: set the reparse data (which we read already)
		 * */
		inode->i_not_rpfixed = not_rpfixed;
		inode->i_reparse_tag = le32_to_cpu(*(u32*)rpbuf);
		ret = inode_set_unnamed_stream(inode, rpbuf + 8, rpbuflen - 8,
					       params->lookup_table);
	} else if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
		/* Directory (not a reparse point) --- recurse to children */
		ret = win32_recurse_directory(root,
					      path,
					      path_num_chars,
					      params,
					      state,
					      vol_flags);
	}
	goto out;
out_close_handle:
	CloseHandle(hFile);
out:
	if (ret == 0)
		*root_ret = root;
	else
		free_dentry_tree(root, params->lookup_table);
	return ret;
}

static void
win32_do_capture_warnings(const struct win32_capture_state *state,
			  int add_flags)
{
	if (state->num_get_sacl_priv_notheld == 0 &&
	    state->num_get_sd_access_denied == 0)
		return;

	WARNING("");
	WARNING("Built dentry tree successfully, but with the following problem(s):");
	if (state->num_get_sacl_priv_notheld != 0) {
		WARNING("Could not capture SACL (System Access Control List)\n"
			"          on %lu files or directories.",
			state->num_get_sacl_priv_notheld);
	}
	if (state->num_get_sd_access_denied != 0) {
		WARNING("Could not capture security descriptor at all\n"
			"          on %lu files or directories.",
			state->num_get_sd_access_denied);
	}
	WARNING(
          "Try running the program as the Administrator to make sure all the\n"
"          desired metadata has been captured exactly.  However, if you\n"
"          do not care about capturing security descriptors correctly, then\n"
"          nothing more needs to be done%ls\n",
	(add_flags & WIMLIB_ADD_FLAG_NO_ACLS) ? L"." :
         L", although you might consider\n"
"          using the --no-acls option to explicitly capture no security\n"
"          descriptors.\n");
}

/* Win32 version of capturing a directory tree */
int
win32_build_dentry_tree(struct wim_dentry **root_ret,
			const wchar_t *root_disk_path,
			struct add_image_params *params)
{
	size_t path_nchars;
	wchar_t *path;
	int ret;
	struct win32_capture_state state;
	unsigned vol_flags;

	if (!win32func_FindFirstStreamW) {
		WARNING("Running on Windows XP or earlier; "
			"alternate data streams will not be captured.");
	}

	path_nchars = wcslen(root_disk_path);
	if (path_nchars > 32767)
		return WIMLIB_ERR_INVALID_PARAM;

	if (GetFileAttributesW(root_disk_path) == INVALID_FILE_ATTRIBUTES &&
	    GetLastError() == ERROR_FILE_NOT_FOUND)
	{
		ERROR("Capture directory \"%ls\" does not exist!",
		      root_disk_path);
		return WIMLIB_ERR_OPENDIR;
	}

	ret = win32_get_file_and_vol_ids(root_disk_path,
					 &params->capture_root_ino,
					 &params->capture_root_dev);
	if (ret)
		return ret;

	win32_get_vol_flags(root_disk_path, &vol_flags);

	/* There is no check for overflow later when this buffer is being used!
	 * But the max path length on NTFS is 32767 characters, and paths need
	 * to be written specially to even go past 260 characters, so we should
	 * be okay with 32770 characters. */
	path = MALLOC(32770 * sizeof(wchar_t));
	if (!path)
		return WIMLIB_ERR_NOMEM;

	wmemcpy(path, root_disk_path, path_nchars + 1);

	memset(&state, 0, sizeof(state));
	ret = win32_build_dentry_tree_recursive(root_ret, path,
						path_nchars, params,
						&state, vol_flags);
	FREE(path);
	if (ret == 0)
		win32_do_capture_warnings(&state, params->add_flags);
	return ret;
}

#endif /* __WIN32__ */
