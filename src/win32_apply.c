/*
 * win32_apply.c - Windows-specific code for applying files from a WIM image.
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

#include "wimlib/apply.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"

static int
win32_start_extract(const wchar_t *path, struct apply_ctx *ctx)
{
	int ret;
	unsigned vol_flags;
	bool supports_SetFileShortName;

	ret = win32_get_vol_flags(path, &vol_flags, &supports_SetFileShortName);
	if (ret)
		return ret;

	ctx->supported_features.archive_files = 1;
	ctx->supported_features.hidden_files = 1;
	ctx->supported_features.system_files = 1;

	if (vol_flags & FILE_FILE_COMPRESSION)
		ctx->supported_features.compressed_files = 1;

	if (vol_flags & FILE_SUPPORTS_ENCRYPTION) {
		ctx->supported_features.encrypted_files = 1;
		ctx->supported_features.encrypted_directories = 1;
	}

	ctx->supported_features.not_context_indexed_files = 1;

	if (vol_flags & FILE_SUPPORTS_SPARSE_FILES)
		ctx->supported_features.sparse_files = 1;

	if (vol_flags & FILE_NAMED_STREAMS)
		ctx->supported_features.named_data_streams = 1;

	if (vol_flags & FILE_SUPPORTS_HARD_LINKS)
		ctx->supported_features.hard_links = 1;

	if (vol_flags & FILE_SUPPORTS_REPARSE_POINTS) {
		ctx->supported_features.reparse_points = 1;
		if (win32func_CreateSymbolicLinkW)
			ctx->supported_features.symlink_reparse_points = 1;
	}

	if (vol_flags & FILE_PERSISTENT_ACLS)
		ctx->supported_features.security_descriptors = 1;

	if (supports_SetFileShortName)
		ctx->supported_features.short_names = 1;
	return 0;
}

/* Create a normal file, overwriting one already present.  */
static int
win32_create_file(const wchar_t *path, struct apply_ctx *ctx, u64 *cookie_ret)
{
	HANDLE h;
	unsigned retry_count = 0;
	DWORD dwFlagsAndAttributes = FILE_FLAG_BACKUP_SEMANTICS;

retry:
	/* WRITE_OWNER and WRITE_DAC privileges are required for some reason,
	 * even through we're creating a new file.  */
	h = CreateFile(path, WRITE_OWNER | WRITE_DAC, 0, NULL,
		       CREATE_ALWAYS, dwFlagsAndAttributes, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		/* File couldn't be created.  */
		DWORD err = GetLastError();
		if (err == ERROR_ACCESS_DENIED && retry_count == 0) {

			/* Access denied error for the first time.  Try
			 * adjusting file attributes.  */

			/* Get attributes of the existing file.  */
			DWORD attribs = GetFileAttributes(path);
			if (attribs != INVALID_FILE_ATTRIBUTES &&
			    (attribs & (FILE_ATTRIBUTE_HIDDEN |
					FILE_ATTRIBUTE_SYSTEM |
					FILE_ATTRIBUTE_READONLY)))
			{
				/* If the existing file has
				 * FILE_ATTRIBUTE_HIDDEN and/or
				 * FILE_ATTRIBUTE_SYSTEM, they must be set in
				 * the call to CreateFile().  This is true even
				 * when FILE_ATTRIBUTE_NORMAL was not specified,
				 * contrary to the MS "documentation".  */
				dwFlagsAndAttributes |= (attribs &
							 (FILE_ATTRIBUTE_HIDDEN |
							  FILE_ATTRIBUTE_SYSTEM));
				/* If the existing file has
				 * FILE_ATTRIBUTE_READONLY, it must be cleared
				 * before attempting to create a new file over
				 * it.  This is true even when the process has
				 * the SE_RESTORE_NAME privilege and requested
				 * the FILE_FLAG_BACKUP_SEMANTICS flag to
				 * CreateFile().  */
				if (attribs & FILE_ATTRIBUTE_READONLY) {
					SetFileAttributes(path,
							  attribs & ~FILE_ATTRIBUTE_READONLY);
				}
				retry_count++;
				goto retry;
			}
		}
		set_errno_from_win32_error(err);
		return WIMLIB_ERR_OPEN;
	}
	CloseHandle(h);
	return 0;
}

static int
win32_create_directory(const wchar_t *path, struct apply_ctx *ctx,
		       u64 *cookie_ret)
{
	if (!CreateDirectory(path, NULL))
		if (GetLastError() != ERROR_ALREADY_EXISTS)
			goto error;
	return 0;

error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_MKDIR;
}

static int
win32_create_hardlink(const wchar_t *oldpath, const wchar_t *newpath,
		      struct apply_ctx *ctx)
{
	if (!CreateHardLink(newpath, oldpath, NULL)) {
		if (GetLastError() != ERROR_ALREADY_EXISTS)
			goto error;
		if (!DeleteFile(newpath))
			goto error;
		if (!CreateHardLink(newpath, oldpath, NULL))
			goto error;
	}
	return 0;

error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_LINK;
}

static int
win32_create_symlink(const wchar_t *oldpath, const wchar_t *newpath,
		     struct apply_ctx *ctx)
{
	if (!(*win32func_CreateSymbolicLinkW)(newpath, oldpath, 0)) {
		if (GetLastError() != ERROR_ALREADY_EXISTS)
			goto error;
		if (!DeleteFile(newpath))
			goto error;
		if (!(*win32func_CreateSymbolicLinkW)(newpath, oldpath, 0))
			goto error;
	}
	return 0;

error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_LINK;
}

static int
win32_extract_wim_chunk(const void *buf, size_t len, void *arg)
{
	HANDLE h = (HANDLE)arg;
	DWORD nbytes_written;

	if (unlikely(!WriteFile(h, buf, len, &nbytes_written, NULL)))
		goto error;
	if (unlikely(nbytes_written != len))
		goto error;
	return 0;

error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_WRITE;
}

static int
win32_extract_stream(const wchar_t *path, const wchar_t *stream_name,
		     size_t stream_name_nchars,
		     struct wim_lookup_table_entry *lte, struct apply_ctx *ctx)
{
	DWORD creationDisposition = OPEN_EXISTING;
	wchar_t *stream_path = (wchar_t*)path;
	HANDLE h;
	int ret;

	if (stream_name_nchars) {
		creationDisposition = CREATE_ALWAYS;
		stream_path = alloca(sizeof(wchar_t) *
				     (wcslen(path) + 1 +
				      wcslen(stream_name) + 1));
		tsprintf(stream_path, L"%ls:%ls", path, stream_name);
	}

	h = CreateFile(stream_path, FILE_WRITE_DATA, 0, NULL,
		       creationDisposition, FILE_FLAG_BACKUP_SEMANTICS |
					    FILE_FLAG_OPEN_REPARSE_POINT,
		       NULL);
	if (h == INVALID_HANDLE_VALUE)
		goto error;

	ret = 0;
	if (!lte)
		goto out_close_handle;
	ret = extract_stream(lte, lte->size, win32_extract_wim_chunk, h);
out_close_handle:
	if (!CloseHandle(h))
		goto error;
	if (ret && !errno)
		errno = -1;
	return ret;

error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_WRITE;
}

static int
win32_extract_unnamed_stream(file_spec_t file,
			     struct wim_lookup_table_entry *lte,
			     struct apply_ctx *ctx)
{
	return win32_extract_stream(file.path, NULL, 0, lte, ctx);
}

static int
win32_extract_named_stream(file_spec_t file, const wchar_t *stream_name,
			   size_t stream_name_nchars,
			   struct wim_lookup_table_entry *lte, struct apply_ctx *ctx)
{
	return win32_extract_stream(file.path, stream_name,
				    stream_name_nchars, lte, ctx);
}

struct win32_encrypted_extract_ctx {
	const struct wim_lookup_table_entry *lte;
	u64 offset;
};

static DWORD WINAPI
win32_encrypted_import_cb(unsigned char *data, void *_import_ctx,
			  unsigned long *len_p)
{
	struct win32_encrypted_extract_ctx *import_ctx = _import_ctx;
	unsigned long len = *len_p;
	const struct wim_lookup_table_entry *lte = import_ctx->lte;

	len = min(len, lte->size - import_ctx->offset);

	if (read_partial_wim_stream_into_buf(lte, len, import_ctx->offset, data))
		return ERROR_READ_FAULT;

	import_ctx->offset += len;
	*len_p = len;
	return ERROR_SUCCESS;
}

static int
win32_extract_encrypted_stream(const wchar_t *path,
			       struct wim_lookup_table_entry *lte,
			       struct apply_ctx *ctx)
{
	void *file_ctx;
	DWORD err;
	int ret;
	struct win32_encrypted_extract_ctx extract_ctx;

	err = OpenEncryptedFileRaw(path, CREATE_FOR_IMPORT, &file_ctx);
	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ret = WIMLIB_ERR_OPEN;
		goto out;
	}

	extract_ctx.lte = lte;
	extract_ctx.offset = 0;
	err = WriteEncryptedFileRaw(win32_encrypted_import_cb, &extract_ctx,
				    file_ctx);
	if (err != ERROR_SUCCESS) {
		set_errno_from_win32_error(err);
		ret = WIMLIB_ERR_WRITE;
		goto out_close;
	}

	ret = 0;
out_close:
	CloseEncryptedFileRaw(file_ctx);
out:
	return ret;
}

static BOOL
win32_set_special_file_attributes(const wchar_t *path, u32 attributes)
{
	HANDLE h;
	DWORD err;
	USHORT compression_format = COMPRESSION_FORMAT_DEFAULT;
	DWORD bytes_returned;

	h = win32_open_existing_file(path, GENERIC_READ | GENERIC_WRITE);
	if (h == INVALID_HANDLE_VALUE)
		goto error;

	if (attributes & FILE_ATTRIBUTE_SPARSE_FILE)
		if (!DeviceIoControl(h, FSCTL_SET_SPARSE,
				     NULL, 0,
				     NULL, 0,
				     &bytes_returned, NULL))
			goto error_close_handle;

	if (attributes & FILE_ATTRIBUTE_COMPRESSED)
		if (!DeviceIoControl(h, FSCTL_SET_COMPRESSION,
				     &compression_format, sizeof(USHORT),
				     NULL, 0,
				     &bytes_returned, NULL))
			goto error_close_handle;

	if (!CloseHandle(h))
		goto error;

	if (attributes & FILE_ATTRIBUTE_ENCRYPTED)
		if (!EncryptFile(path))
			goto error;

	return TRUE;

error_close_handle:
	err = GetLastError();
	CloseHandle(h);
	SetLastError(err);
error:
	return FALSE;
}

static int
win32_set_file_attributes(const wchar_t *path, u32 attributes,
			  struct apply_ctx *ctx, unsigned pass)
{
	u32 special_attributes =
		FILE_ATTRIBUTE_REPARSE_POINT |
		FILE_ATTRIBUTE_DIRECTORY |
		FILE_ATTRIBUTE_SPARSE_FILE |
		FILE_ATTRIBUTE_COMPRESSED |
		FILE_ATTRIBUTE_ENCRYPTED;
	u32 actual_attributes;

	/* Delay setting FILE_ATTRIBUTE_READONLY on the initial pass (when files
	 * are created, but data not extracted); otherwise the system will
	 * refuse access to the file even if the process has SeRestorePrivilege.
	 */
	if (pass == 0)
		attributes &= ~FILE_ATTRIBUTE_READONLY;

	if (!SetFileAttributes(path, attributes & ~special_attributes))
		goto error;

	if (pass != 0)
		return 0;

	if (attributes & (FILE_ATTRIBUTE_SPARSE_FILE |
			  FILE_ATTRIBUTE_ENCRYPTED |
			  FILE_ATTRIBUTE_COMPRESSED))
		if (!win32_set_special_file_attributes(path, attributes))
			goto error;

	/* If file is not supposed to be encrypted or compressed, remove
	 * defaulted encrypted or compressed attributes (from creating file in
	 * encrypted or compressed directory).  */
	actual_attributes = GetFileAttributes(path);
	if (actual_attributes == INVALID_FILE_ATTRIBUTES)
		goto error;

	if ((actual_attributes & FILE_ATTRIBUTE_ENCRYPTED) &&
	    !(attributes & FILE_ATTRIBUTE_ENCRYPTED))
		if (!DecryptFile(path, 0))
			goto error;
	if ((actual_attributes & FILE_ATTRIBUTE_COMPRESSED) &&
	    !(attributes & FILE_ATTRIBUTE_COMPRESSED))
	{
		HANDLE h;
		DWORD bytes_returned;
		USHORT compression_format = COMPRESSION_FORMAT_NONE;

		h = win32_open_existing_file(path, GENERIC_READ | GENERIC_WRITE);
		if (h == INVALID_HANDLE_VALUE)
			goto error;

		if (!DeviceIoControl(h, FSCTL_SET_COMPRESSION,
				     &compression_format, sizeof(USHORT),
				     NULL, 0,
				     &bytes_returned, NULL))
		{
			DWORD err = GetLastError();
			CloseHandle(h);
			SetLastError(err);
			goto error;
		}

		if (!CloseHandle(h))
			goto error;
	}

	return 0;

error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_SET_ATTRIBUTES;
}

static int
win32_set_reparse_data(const wchar_t *path, const u8 *rpbuf, u16 rpbuflen,
		       struct apply_ctx *ctx)
{
	HANDLE h;
	DWORD err;
	DWORD bytes_returned;

	h = win32_open_existing_file(path, GENERIC_WRITE);
	if (h == INVALID_HANDLE_VALUE)
		goto error;

	if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT,
			     (void*)rpbuf, rpbuflen,
			     NULL, 0, &bytes_returned, NULL))
		goto error_close_handle;

	if (!CloseHandle(h))
		goto error;

	return 0;

error_close_handle:
	err = GetLastError();
	CloseHandle(h);
	SetLastError(err);
error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_WRITE; /* XXX: need better error code */
}

static int
win32_set_short_name(const wchar_t *path, const wchar_t *short_name,
		     size_t short_name_nchars, struct apply_ctx *ctx)
{
	HANDLE h;
	DWORD err;

	h = win32_open_existing_file(path, GENERIC_WRITE | DELETE);
	if (h == INVALID_HANDLE_VALUE)
		goto error;

	if (short_name_nchars) {
		if (!SetFileShortName(h, short_name))
			goto error_close_handle;
	} else if (running_on_windows_7_or_later()) {
		if (!SetFileShortName(h, L""))
			goto error_close_handle;
	}

	if (!CloseHandle(h))
		goto error;

	return 0;

error_close_handle:
	err = GetLastError();
	CloseHandle(h);
	SetLastError(err);
error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_WRITE; /* XXX: need better error code */
}

static DWORD
do_win32_set_security_descriptor(HANDLE h, const wchar_t *path,
				 SECURITY_INFORMATION info,
				 PSECURITY_DESCRIPTOR desc)
{
#ifdef WITH_NTDLL
	if (func_NtSetSecurityObject) {
		return (*func_RtlNtStatusToDosError)(
				(*func_NtSetSecurityObject)(h, info, desc));
	}
#endif
	if (SetFileSecurity(path, info, desc))
		return ERROR_SUCCESS;
	else
		return GetLastError();
}

static int
win32_set_security_descriptor(const wchar_t *path, const u8 *desc,
			      size_t desc_size, struct apply_ctx *ctx)
{
	SECURITY_INFORMATION info;
	HANDLE h;
	DWORD err;
	int ret;

	info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
	       DACL_SECURITY_INFORMATION  | SACL_SECURITY_INFORMATION;
	h = INVALID_HANDLE_VALUE;

#ifdef WITH_NTDLL
	if (func_NtSetSecurityObject) {
		h = win32_open_existing_file(path, MAXIMUM_ALLOWED);
		if (h == INVALID_HANDLE_VALUE) {
			ERROR_WITH_ERRNO("Can't open %ls (%u)", path, GetLastError());
			goto error;
		}
	}
#endif

	for (;;) {
		err = do_win32_set_security_descriptor(h, path, info,
						       (PSECURITY_DESCRIPTOR)desc);
		if (err == ERROR_SUCCESS)
			break;
		if ((err == ERROR_PRIVILEGE_NOT_HELD ||
		     err == ERROR_ACCESS_DENIED) &&
		    !(ctx->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS))
		{
			if (info & SACL_SECURITY_INFORMATION) {
				info &= ~SACL_SECURITY_INFORMATION;
				ctx->partial_security_descriptors++;
				continue;
			}
			if (info & DACL_SECURITY_INFORMATION) {
				info &= ~DACL_SECURITY_INFORMATION;
				continue;
			}
			if (info & OWNER_SECURITY_INFORMATION) {
				info &= ~OWNER_SECURITY_INFORMATION;
				continue;
			}
			ctx->partial_security_descriptors--;
			ctx->no_security_descriptors++;
			break;
		}
		SetLastError(err);
		goto error;
	}
	ret = 0;
out_close:
#ifdef WITH_NTDLL
	if (func_NtSetSecurityObject && h != INVALID_HANDLE_VALUE)
		CloseHandle(h);
#endif
	return ret;

error:
	set_errno_from_GetLastError();
	ret = WIMLIB_ERR_SET_SECURITY;
	goto out_close;
}

static int
win32_set_timestamps(const wchar_t *path, u64 creation_time,
		     u64 last_write_time, u64 last_access_time,
		     struct apply_ctx *ctx)
{
	HANDLE h;
	DWORD err;
	FILETIME creationTime = {.dwLowDateTime = creation_time & 0xffffffff,
				 .dwHighDateTime = creation_time >> 32};
	FILETIME lastAccessTime = {.dwLowDateTime = last_access_time & 0xffffffff,
				  .dwHighDateTime = last_access_time >> 32};
	FILETIME lastWriteTime = {.dwLowDateTime = last_write_time & 0xffffffff,
				  .dwHighDateTime = last_write_time >> 32};

	h = win32_open_existing_file(path, FILE_WRITE_ATTRIBUTES);
	if (h == INVALID_HANDLE_VALUE)
		goto error;

	if (!SetFileTime(h, &creationTime, &lastAccessTime, &lastWriteTime))
		goto error_close_handle;

	if (!CloseHandle(h))
		goto error;

	return 0;

error_close_handle:
	err = GetLastError();
	CloseHandle(h);
	SetLastError(err);
error:
	set_errno_from_GetLastError();
	return WIMLIB_ERR_SET_TIMESTAMPS;
}

const struct apply_operations win32_apply_ops = {
	.name = L"Win32",

	.target_is_root           = win32_path_is_root_of_drive,
	.start_extract            = win32_start_extract,
	.create_file              = win32_create_file,
	.create_directory         = win32_create_directory,
	.create_hardlink          = win32_create_hardlink,
	.create_symlink		  = win32_create_symlink,
	.extract_unnamed_stream   = win32_extract_unnamed_stream,
	.extract_named_stream     = win32_extract_named_stream,
	.extract_encrypted_stream = win32_extract_encrypted_stream,
	.set_file_attributes      = win32_set_file_attributes,
	.set_reparse_data         = win32_set_reparse_data,
	.set_short_name           = win32_set_short_name,
	.set_security_descriptor  = win32_set_security_descriptor,
	.set_timestamps           = win32_set_timestamps,

	.path_prefix = L"\\\\?\\",
	.path_prefix_nchars = 4,
	.path_separator = L'\\',
	.path_max = 32768,

	.requires_realtarget_in_paths = 1,
	.realpath_works_on_nonexisting_files = 1,
	.root_directory_is_special = 1,
	.requires_final_set_attributes_pass = 1,
	.extract_encrypted_stream_creates_file = 1,
	.requires_short_name_reordering = 1, /* TODO: check if this is really needed  */
};

#endif /* __WIN32__ */
