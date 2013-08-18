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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/win32_common.h"

#include "wimlib/capture.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/paths.h"
#include "wimlib/reparse.h"

#ifdef WITH_NTDLL
#  include <winternl.h>
#  include <ntstatus.h>

NTSTATUS WINAPI
NtQuerySecurityObject(HANDLE handle,
		      SECURITY_INFORMATION SecurityInformation,
		      PSECURITY_DESCRIPTOR SecurityDescriptor,
		      ULONG Length,
		      PULONG LengthNeeded);
NTSTATUS WINAPI
NtQueryDirectoryFile(HANDLE FileHandle,
		     HANDLE Event,
		     PIO_APC_ROUTINE ApcRoutine,
		     PVOID ApcContext,
		     PIO_STATUS_BLOCK IoStatusBlock,
		     PVOID FileInformation,
		     ULONG Length,
		     FILE_INFORMATION_CLASS FileInformationClass,
		     BOOLEAN ReturnSingleEntry,
		     PUNICODE_STRING FileName,
		     BOOLEAN RestartScan);
#endif

#define MAX_GET_SD_ACCESS_DENIED_WARNINGS 1
#define MAX_GET_SACL_PRIV_NOTHELD_WARNINGS 1
#define MAX_CAPTURE_LONG_PATH_WARNINGS 5

struct win32_capture_state {
	unsigned long num_get_sd_access_denied;
	unsigned long num_get_sacl_priv_notheld;
	unsigned long num_long_path_warnings;
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

	HANDLE hFile = win32_open_existing_file(lte->file_on_disk,
						FILE_READ_DATA);
	if (hFile == INVALID_HANDLE_VALUE) {
		set_errno_from_GetLastError();
		ERROR_WITH_ERRNO("Failed to open \"%ls\"", lte->file_on_disk);
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
			set_errno_from_GetLastError();
			ERROR_WITH_ERRNO("Failed to read data from \"%ls\"",
					 lte->file_on_disk);
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
		ctx->read_prefix_ctx_or_buf = mempcpy(ctx->read_prefix_ctx_or_buf,
						      data,
						      len_to_copy);
		ctx->bytes_remaining -= len_to_copy;
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
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to open encrypted file \"%ls\" "
				 "for raw read", lte->file_on_disk);
		ret = WIMLIB_ERR_OPEN;
		goto out_free_buf;
	}
	err = ReadEncryptedFileRaw(win32_encrypted_export_cb,
				   &export_ctx, file_ctx);
	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to read encrypted file \"%ls\"",
				 lte->file_on_disk);
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

/* Load the short name of a file into a WIM dentry.
 *
 * If we can't read the short filename for some reason, we just ignore the error
 * and assume the file has no short name.  This shouldn't be an issue, since the
 * short names are essentially obsolete anyway.
 */
static int
win32_get_short_name(HANDLE hFile, const wchar_t *path, struct wim_dentry *dentry)
{

	/* It's not any harder to just make the NtQueryInformationFile() system
	 * call ourselves, and it saves a dumb call to FindFirstFile() which of
	 * course has to create its own handle.  */
#ifdef WITH_NTDLL
	NTSTATUS status;
	IO_STATUS_BLOCK io_status;
	u8 buf[128] _aligned_attribute(8);
	const FILE_NAME_INFORMATION *info;

	status = NtQueryInformationFile(hFile, &io_status, buf, sizeof(buf),
					FileAlternateNameInformation);
	info = (const FILE_NAME_INFORMATION*)buf;
	if (status == STATUS_SUCCESS && info->FileNameLength != 0) {
		dentry->short_name = MALLOC(info->FileNameLength + 2);
		if (!dentry->short_name)
			return WIMLIB_ERR_NOMEM;
		memcpy(dentry->short_name, info->FileName,
		       info->FileNameLength);
		dentry->short_name[info->FileNameLength / 2] = L'\0';
		dentry->short_name_nbytes = info->FileNameLength;
	}
	return 0;
#else
	WIN32_FIND_DATAW dat;
	HANDLE hFind;
	int ret = 0;

	hFind = FindFirstFile(path, &dat);
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
#endif
}

/*
 * win32_query_security_descriptor() - Query a file's security descriptor
 *
 * We need the file's security descriptor in SECURITY_DESCRIPTOR_RELATIVE
 * format, and we currently have a handle opened with as many relevant
 * permissions as possible.  At this point, on Windows there are a number of
 * options for reading a file's security descriptor:
 *
 * GetFileSecurity():  This takes in a path and returns the
 * SECURITY_DESCRIPTOR_RELATIVE.  Problem: this uses an internal handle, not
 * ours, and the handle created internally doesn't specify
 * FILE_FLAG_BACKUP_SEMANTICS.  Therefore there can be access denied errors on
 * some files and directories, even when running as the Administrator.
 *
 * GetSecurityInfo():  This takes in a handle and returns the security
 * descriptor split into a bunch of different parts.  This should work, but it's
 * dumb because we have to put the security descriptor back together again.
 *
 * BackupRead():  This can read the security descriptor, but this is a
 * difficult-to-use API, probably only works as the Administrator, and the
 * format of the returned data is not well documented.
 *
 * NtQuerySecurityObject():  This is exactly what we need, as it takes in a
 * handle and returns the security descriptor in SECURITY_DESCRIPTOR_RELATIVE
 * format.  Only problem is that it's a ntdll function and therefore not
 * officially part of the Win32 API.  Oh well.
 */
static DWORD
win32_query_security_descriptor(HANDLE hFile, const wchar_t *path,
				SECURITY_INFORMATION requestedInformation,
				SECURITY_DESCRIPTOR *buf,
				DWORD bufsize, DWORD *lengthNeeded)
{
#ifdef WITH_NTDLL
	NTSTATUS status;

	status = NtQuerySecurityObject(hFile, requestedInformation, buf,
				       bufsize, lengthNeeded);
	/* Since it queries an already-open handle, NtQuerySecurityObject()
	 * apparently returns STATUS_ACCESS_DENIED rather than
	 * STATUS_PRIVILEGE_NOT_HELD.  */
	if (status == STATUS_ACCESS_DENIED)
		return ERROR_PRIVILEGE_NOT_HELD;
	else
		return RtlNtStatusToDosError(status);
#else
	if (GetFileSecurity(path, requestedInformation, buf,
			    bufsize, lengthNeeded))
		return ERROR_SUCCESS;
	else
		return GetLastError();
#endif
}

static int
win32_get_security_descriptor(HANDLE hFile,
			      const wchar_t *path,
			      struct wim_inode *inode,
			      struct wim_sd_set *sd_set,
			      struct win32_capture_state *state,
			      int add_flags)
{
	SECURITY_INFORMATION requestedInformation;
	u8 _buf[4096];
	u8 *buf;
	size_t bufsize;
	DWORD lenNeeded;
	DWORD err;
	int ret;

	requestedInformation = DACL_SECURITY_INFORMATION |
			       SACL_SECURITY_INFORMATION |
			       OWNER_SECURITY_INFORMATION |
			       GROUP_SECURITY_INFORMATION;
	buf = _buf;
	bufsize = sizeof(_buf);
	for (;;) {
		err = win32_query_security_descriptor(hFile, path,
						      requestedInformation,
						      (SECURITY_DESCRIPTOR*)buf,
						      bufsize, &lenNeeded);
		switch (err) {
		case ERROR_SUCCESS:
			goto have_descriptor;
		case ERROR_INSUFFICIENT_BUFFER:
			wimlib_assert(buf == _buf);
			buf = MALLOC(lenNeeded);
			if (!buf)
				return WIMLIB_ERR_NOMEM;
			bufsize = lenNeeded;
			break;
		case ERROR_PRIVILEGE_NOT_HELD:
			if (add_flags & WIMLIB_ADD_FLAG_STRICT_ACLS)
				goto fail;
			if (requestedInformation & SACL_SECURITY_INFORMATION) {
				state->num_get_sacl_priv_notheld++;
				requestedInformation &= ~SACL_SECURITY_INFORMATION;
				break;
			}
			/* Fall through */
		case ERROR_ACCESS_DENIED:
			if (add_flags & WIMLIB_ADD_FLAG_STRICT_ACLS)
				goto fail;
			state->num_get_sd_access_denied++;
			ret = 0;
			goto out_free_buf;
		default:
		fail:
			set_errno_from_win32_error(err);
			ERROR("Failed to read security descriptor of \"%ls\"", path);
			ret = WIMLIB_ERR_READ;
			goto out_free_buf;
		}
	}

have_descriptor:
	inode->i_security_id = sd_set_add_sd(sd_set, buf, lenNeeded);
	if (inode->i_security_id < 0)
		ret = WIMLIB_ERR_NOMEM;
	else
		ret = 0;
out_free_buf:
	if (buf != _buf)
		FREE(buf);
	return ret;
}

static int
win32_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				  wchar_t *path,
				  size_t path_num_chars,
				  struct add_image_params *params,
				  struct win32_capture_state *state,
				  unsigned vol_flags);

/* Reads the directory entries of directory and recursively calls
 * win32_build_dentry_tree() on them.  */
static int
win32_recurse_directory(HANDLE hDir,
			wchar_t *dir_path,
			size_t dir_path_num_chars,
			struct wim_dentry *root,
			struct add_image_params *params,
			struct win32_capture_state *state,
			unsigned vol_flags)
{
	int ret;

	DEBUG("Recurse to directory \"%ls\"", dir_path);

	/* Using NtQueryDirectoryFile() we can re-use the same open handle,
	 * which we opened with FILE_FLAG_BACKUP_SEMANTICS (probably not the
	 * case for the FindFirstFile() API; it's not documented).  */
#ifdef WITH_NTDLL
	NTSTATUS status;
	IO_STATUS_BLOCK io_status;
	const size_t bufsize = 8192;
	u8 *buf;
	BOOL restartScan = TRUE;
	const FILE_NAMES_INFORMATION *info;

	buf = MALLOC(bufsize);
	if (!buf)
		return WIMLIB_ERR_NOMEM;
	for (;;) {
		status = NtQueryDirectoryFile(hDir, NULL, NULL, NULL,
					      &io_status, buf, bufsize,
					      FileNamesInformation,
					      FALSE, NULL, restartScan);
		restartScan = FALSE;
		if (status != STATUS_SUCCESS) {
			if (status == STATUS_NO_MORE_FILES ||
			    status == STATUS_NO_MORE_ENTRIES ||
			    status == STATUS_NO_MORE_MATCHES) {
				ret = 0;
			} else {
				set_errno_from_nt_status(status);
				ERROR_WITH_ERRNO("Failed to read directory "
						 "\"%ls\"", dir_path);
				ret = WIMLIB_ERR_READ;
			}
			goto out_free_buf;
		}
		wimlib_assert(io_status.Information != 0);
		info = (const FILE_NAMES_INFORMATION*)buf;
		for (;;) {
			if (!(info->FileNameLength == 2 && info->FileName[0] == L'.') &&
			    !(info->FileNameLength == 4 && info->FileName[0] == L'.' &&
							   info->FileName[1] == L'.'))
			{
				wchar_t *p;
				struct wim_dentry *child;

				p = dir_path + dir_path_num_chars;
				*p++ = L'\\';
				p = wmempcpy(p, info->FileName,
					     info->FileNameLength / 2);
				*p = '\0';

				ret = win32_build_dentry_tree_recursive(
								&child,
								dir_path,
								p - dir_path,
								params,
								state,
								vol_flags);

				dir_path[dir_path_num_chars] = L'\0';

				if (ret)
					goto out_free_buf;
				if (child)
					dentry_add_child(root, child);
			}
			if (info->NextEntryOffset == 0)
				break;
			info = (const FILE_NAMES_INFORMATION*)
					((const u8*)info + info->NextEntryOffset);
		}
	}
out_free_buf:
	FREE(buf);
	return ret;
#else
	WIN32_FIND_DATAW dat;
	HANDLE hFind;
	DWORD err;

	/* Begin reading the directory by calling FindFirstFileW.  Unlike UNIX
	 * opendir(), FindFirstFileW has file globbing built into it.  But this
	 * isn't what we actually want, so just add a dummy glob to get all
	 * entries. */
	dir_path[dir_path_num_chars] = OS_PREFERRED_PATH_SEPARATOR;
	dir_path[dir_path_num_chars + 1] = L'*';
	dir_path[dir_path_num_chars + 2] = L'\0';
	hFind = FindFirstFileW(dir_path, &dat);
	dir_path[dir_path_num_chars] = L'\0';

	if (hFind == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			return 0;
		} else {
			set_errno_from_win32_error(err);
			ERROR_WITH_ERRNO("Failed to read directory \"%ls\"",
					 dir_path);
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

		dir_path[dir_path_num_chars] = OS_PREFERRED_PATH_SEPARATOR;
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
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to read directory \"%ls\"", dir_path);
		if (ret == 0)
			ret = WIMLIB_ERR_READ;
	}
out_find_close:
	FindClose(hFind);
	return ret;
#endif
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
	int ret;
	enum rp_status rp_status;

	ret = parse_reparse_data(rpbuf, *rpbuflen_p, &rpdata);
	if (ret)
		return -ret;

	rp_status = win32_capture_maybe_rpfix_target(rpdata.substitute_name,
						     &rpdata.substitute_name_nbytes,
						     capture_root_ino,
						     capture_root_dev,
						     le32_to_cpu(*(le32*)rpbuf));
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
		ret = make_reparse_buffer(&rpdata, rpbuf, rpbuflen_p);
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
		set_errno_from_GetLastError();
		ERROR_WITH_ERRNO("Failed to get reparse data of \"%ls\"", path);
		return -WIMLIB_ERR_READ;
	}
	if (bytesReturned < 8 || bytesReturned > REPARSE_POINT_MAX_SIZE) {
		ERROR("Reparse data on \"%ls\" is invalid", path);
		return -WIMLIB_ERR_INVALID_REPARSE_DATA;
	}

	rpbuflen = bytesReturned;
	reparse_tag = le32_to_cpu(*(le32*)rpbuf);
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
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to open encrypted file \"%ls\" "
				 "for raw read", path);
		return WIMLIB_ERR_OPEN;
	}
	err = ReadEncryptedFileRaw(win32_tally_encrypted_size_cb,
				   size_ret, file_ctx);
	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Failed to read raw encrypted data from "
				 "\"%ls\"", path);
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
		if (path_num_chars == 1 && !is_any_path_separator(path[0])) {
			spath_nchars += 2;
			static const wchar_t _relpath_prefix[] =
				{L'.', OS_PREFERRED_PATH_SEPARATOR, L'\0'};
			relpath_prefix = _relpath_prefix;
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
		lte->resource_location = RESOURCE_IN_FILE_ON_DISK;
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

/* Load information about the streams of an open file into a WIM inode.
 *
 * By default, we use the NtQueryInformationFile() system call instead of
 * FindFirstStream() and FindNextStream().  This is done for two reasons:
 *
 * - FindFirstStream() opens its own handle to the file or directory and
 *   apparently does so without specifying FILE_FLAG_BACKUP_SEMANTICS, thereby
 *   causing access denied errors on certain files (even when running as the
 *   Administrator).
 * - FindFirstStream() and FindNextStream() is only available on Windows Vista
 *   and later, whereas the stream support in NtQueryInformationFile() was
 *   already present in Windows XP.
 */
static int
win32_capture_streams(HANDLE hFile,
		      const wchar_t *path,
		      size_t path_num_chars,
		      struct wim_inode *inode,
		      struct wim_lookup_table *lookup_table,
		      u64 file_size,
		      unsigned vol_flags)
{
	WIN32_FIND_STREAM_DATA dat;
	int ret;
#ifdef WITH_NTDLL
	u8 _buf[8192] _aligned_attribute(8);
	u8 *buf;
	size_t bufsize;
	IO_STATUS_BLOCK io_status;
	NTSTATUS status;
	const FILE_STREAM_INFORMATION *info;
#else
	HANDLE hFind;
	DWORD err;
#endif

	DEBUG("Capturing streams from \"%ls\"", path);

	if (!(vol_flags & FILE_NAMED_STREAMS))
		goto unnamed_only;
#ifndef WITH_NTDLL
	if (win32func_FindFirstStreamW == NULL)
		goto unnamed_only;
#endif

#ifdef WITH_NTDLL
	buf = _buf;
	bufsize = sizeof(_buf);

	/* Get a buffer containing the stream information.  */
	for (;;) {
		status = NtQueryInformationFile(hFile, &io_status, buf, bufsize,
						FileStreamInformation);
		if (status == STATUS_SUCCESS) {
			break;
		} else if (status == STATUS_BUFFER_OVERFLOW) {
			u8 *newbuf;

			bufsize *= 2;
			if (buf == _buf)
				newbuf = MALLOC(bufsize);
			else
				newbuf = REALLOC(buf, bufsize);

			if (!newbuf) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_buf;
			}
			buf = newbuf;
		} else {
			set_errno_from_nt_status(status);
			ERROR_WITH_ERRNO("Failed to read streams of %ls", path);
			ret = WIMLIB_ERR_READ;
			goto out_free_buf;
		}
	}

	if (io_status.Information == 0) {
		/* No stream information.  */
		ret = 0;
		goto out_free_buf;
	}

	/* Parse one or more stream information structures.  */
	info = (const FILE_STREAM_INFORMATION*)buf;
	for (;;) {
		if (info->StreamNameLength <= sizeof(dat.cStreamName) - 2) {
			dat.StreamSize = info->StreamSize;
			memcpy(dat.cStreamName, info->StreamName, info->StreamNameLength);
			dat.cStreamName[info->StreamNameLength / 2] = L'\0';

			/* Capture the stream.  */
			ret = win32_capture_stream(path, path_num_chars, inode,
						   lookup_table, &dat);
			if (ret)
				goto out_free_buf;
		}
		if (info->NextEntryOffset == 0) {
			/* No more stream information.  */
			ret = 0;
			break;
		}
		/* Advance to next stream information.  */
		info = (const FILE_STREAM_INFORMATION*)
				((const u8*)info + info->NextEntryOffset);
	}
out_free_buf:
	/* Free buffer if allocated on heap.  */
	if (buf != _buf)
		FREE(buf);
	return ret;

#else /* WITH_NTDLL */
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
				set_errno_from_win32_error(err);
				ERROR_WITH_ERRNO("Failed to look up data streams "
						 "of \"%ls\"", path);
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
		set_errno_from_win32_error(err);
		ERROR_WITH_ERRNO("Error reading data streams from "
				 "\"%ls\"", path);
		ret = WIMLIB_ERR_READ;
	}
out_find_close:
	FindClose(hFind);
	return ret;
#endif /* !WITH_NTDLL */

unnamed_only:
	/* FindFirstStreamW() API is not available, or the volume does not
	 * support named streams.  Only capture the unnamed data stream. */
	DEBUG("Only capturing unnamed data stream");
	if (!(inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				     FILE_ATTRIBUTE_REPARSE_POINT)))
	{
		wcscpy(dat.cStreamName, L"::$DATA");
		dat.StreamSize.QuadPart = file_size;
		ret = win32_capture_stream(path,
					   path_num_chars,
					   inode, lookup_table,
					   &dat);
		if (ret)
			return ret;
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
	HANDLE hFile;
	DWORD desiredAccess;

	params->progress.scan.cur_path = path;

	if (exclude_path(path, path_num_chars, params->config, true)) {
		if (params->add_flags & WIMLIB_ADD_FLAG_ROOT) {
			ERROR("Cannot exclude the root directory from capture");
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
			goto out;
		}
		do_capture_progress(params, WIMLIB_SCAN_DENTRY_EXCLUDED);
		ret = 0;
		goto out;
	}

#if 0
	if (path_num_chars >= 4 &&
	    !wmemcmp(path, L"\\\\?\\", 4) &&
	    path_num_chars + 1 - 4 > MAX_PATH &&
	    state->num_long_path_warnings < MAX_CAPTURE_LONG_PATH_WARNINGS)
	{
		WARNING("Path \"%ls\" exceeds MAX_PATH", path);
		if (++state->num_long_path_warnings == MAX_CAPTURE_LONG_PATH_WARNINGS)
			WARNING("Suppressing further warnings about long paths.");
	}
#endif

	do_capture_progress(params, WIMLIB_SCAN_DENTRY_OK);

	desiredAccess = FILE_READ_DATA | FILE_READ_ATTRIBUTES |
			READ_CONTROL | ACCESS_SYSTEM_SECURITY;
again:
	hFile = win32_open_existing_file(path, desiredAccess);
	if (hFile == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD) {
			if (desiredAccess & ACCESS_SYSTEM_SECURITY) {
				desiredAccess &= ~ACCESS_SYSTEM_SECURITY;
				goto again;
			}
			if (desiredAccess & READ_CONTROL) {
				desiredAccess &= ~READ_CONTROL;
				goto again;
			}
		}
		set_errno_from_GetLastError();
		ERROR_WITH_ERRNO("Failed to open \"%ls\" for reading", path);
		ret = WIMLIB_ERR_OPEN;
		goto out;
	}

	BY_HANDLE_FILE_INFORMATION file_info;
	if (!GetFileInformationByHandle(hFile, &file_info)) {
		set_errno_from_GetLastError();
		ERROR_WITH_ERRNO("Failed to get file information for \"%ls\"",
				 path);
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
	ret = inode_table_new_dentry(&params->inode_table,
				     path_basename_with_len(path, path_num_chars),
				     ((u64)file_info.nFileIndexHigh << 32) |
					 (u64)file_info.nFileIndexLow,
				     file_info.dwVolumeSerialNumber,
				     (file_info.nNumberOfLinks <= 1 ||
				        (file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)),
				     &root);
	if (ret)
		goto out_close_handle;

	ret = win32_get_short_name(hFile, path, root);
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
		ret = win32_get_security_descriptor(hFile, path, inode,
						    &params->sd_set, state,
						    params->add_flags);
		if (ret)
			goto out_close_handle;
	}

	file_size = ((u64)file_info.nFileSizeHigh << 32) |
		     (u64)file_info.nFileSizeLow;


	/* Capture the unnamed data stream (only should be present for regular
	 * files) and any alternate data streams. */
	ret = win32_capture_streams(hFile,
				    path,
				    path_num_chars,
				    inode,
				    params->lookup_table,
				    file_size,
				    vol_flags);
	if (ret)
		goto out_close_handle;

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		/* Reparse point: set the reparse data (which we read already)
		 * */
		inode->i_not_rpfixed = not_rpfixed;
		inode->i_reparse_tag = le32_to_cpu(*(le32*)rpbuf);
		ret = inode_set_unnamed_stream(inode, rpbuf + 8, rpbuflen - 8,
					       params->lookup_table);
	} else if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
		/* Directory (not a reparse point) --- recurse to children */
		ret = win32_recurse_directory(hFile,
					      path,
					      path_num_chars,
					      root,
					      params,
					      state,
					      vol_flags);
	}
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
win32_do_capture_warnings(const wchar_t *path,
			  const struct win32_capture_state *state,
			  int add_flags)
{
	if (state->num_get_sacl_priv_notheld == 0 &&
	    state->num_get_sd_access_denied == 0)
		return;

	WARNING("Scan of \"%ls\" complete, but with one or more warnings:", path);
	if (state->num_get_sacl_priv_notheld != 0) {
		WARNING("- Could not capture SACL (System Access Control List)\n"
			"            on %lu files or directories.",
			state->num_get_sacl_priv_notheld);
	}
	if (state->num_get_sd_access_denied != 0) {
		WARNING("- Could not capture security descriptor at all\n"
			"            on %lu files or directories.",
			state->num_get_sd_access_denied);
	}
	WARNING("To fully capture all security descriptors, run the program\n"
		"          with Administrator rights.");
}

#define WINDOWS_NT_MAX_PATH 32768

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
	DWORD dret;
	bool need_prefix_free = false;

#ifndef WITH_NTDLL
	if (!win32func_FindFirstStreamW) {
		WARNING("Running on Windows XP or earlier; "
			"alternate data streams will not be captured.");
	}
#endif

	path_nchars = wcslen(root_disk_path);
	if (path_nchars > WINDOWS_NT_MAX_PATH)
		return WIMLIB_ERR_INVALID_PARAM;

	ret = win32_get_file_and_vol_ids(root_disk_path,
					 &params->capture_root_ino,
					 &params->capture_root_dev);
	if (ret) {
		ERROR_WITH_ERRNO("Can't open %ls", root_disk_path);
		return ret;
	}

	win32_get_vol_flags(root_disk_path, &vol_flags, NULL);

	/* WARNING: There is no check for overflow later when this buffer is
	 * being used!  But it's as long as the maximum path length understood
	 * by Windows NT (which is NOT the same as MAX_PATH). */
	path = MALLOC(WINDOWS_NT_MAX_PATH * sizeof(wchar_t));
	if (!path)
		return WIMLIB_ERR_NOMEM;

	/* Work around defective behavior in Windows where paths longer than 260
	 * characters are not supported by default; instead they need to be
	 * turned into absolute paths and prefixed with "\\?\".  */

	if (wcsncmp(root_disk_path, L"\\\\?\\", 4)) {
		dret = GetFullPathName(root_disk_path, WINDOWS_NT_MAX_PATH - 4,
				       &path[4], NULL);

		if (dret == 0 || dret >= WINDOWS_NT_MAX_PATH - 4) {
			WARNING("Can't get full path name for \"%ls\"", root_disk_path);
			wmemcpy(path, root_disk_path, path_nchars + 1);
		} else {
			wmemcpy(path, L"\\\\?\\", 4);
			path_nchars = 4 + dret;
			/* Update pattern prefix */
			if (params->config != NULL)
			{
				params->config->_prefix = TSTRDUP(path);
				params->config->_prefix_num_tchars = path_nchars;
				if (params->config->_prefix == NULL)
				{
					ret = WIMLIB_ERR_NOMEM;
					goto out_free_path;
				}
				need_prefix_free = true;
			}
		}
	} else {
		wmemcpy(path, root_disk_path, path_nchars + 1);
	}

	memset(&state, 0, sizeof(state));
	ret = win32_build_dentry_tree_recursive(root_ret, path,
						path_nchars, params,
						&state, vol_flags);
	if (need_prefix_free)
		FREE(params->config->_prefix);
out_free_path:
	FREE(path);
	if (ret == 0)
		win32_do_capture_warnings(root_disk_path, &state, params->add_flags);
	return ret;
}

#endif /* __WIN32__ */
