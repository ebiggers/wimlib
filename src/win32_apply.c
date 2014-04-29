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
#include "wimlib/capture.h" /* for mangle_pat()  */
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/resource.h"
#include "wimlib/textfile.h"
#include "wimlib/xml.h"
#include "wimlib/wildcard.h"
#include "wimlib/wim.h"
#include "wimlib/wimboot.h"

struct win32_apply_private_data {
	u64 data_source_id;
	struct string_set *prepopulate_pats;
	void *mem_prepopulate_pats;
	u8 wim_lookup_table_hash[SHA1_HASH_SIZE];
	bool wof_running;
};

static struct win32_apply_private_data *
get_private_data(struct apply_ctx *ctx)
{
	BUILD_BUG_ON(sizeof(ctx->private) < sizeof(struct win32_apply_private_data));
	return (struct win32_apply_private_data *)(ctx->private);
}

static void
free_prepopulate_pats(struct win32_apply_private_data *dat)
{
	if (dat->prepopulate_pats) {
		FREE(dat->prepopulate_pats->strings);
		FREE(dat->prepopulate_pats);
		dat->prepopulate_pats = NULL;
	}

	if (dat->mem_prepopulate_pats) {
		FREE(dat->mem_prepopulate_pats);
		dat->mem_prepopulate_pats = NULL;
	}
}

static int
load_prepopulate_pats(struct apply_ctx *ctx)
{
	int ret;
	struct wim_dentry *dentry;
	struct wim_lookup_table_entry *lte;
	struct string_set *s;
	const tchar *path = WIMLIB_WIM_PATH_SEPARATOR_STRING T("Windows")
			    WIMLIB_WIM_PATH_SEPARATOR_STRING T("System32")
			    WIMLIB_WIM_PATH_SEPARATOR_STRING T("WimBootCompress.ini");
	void *buf;
	void *mem;
	struct text_file_section sec;
	struct win32_apply_private_data *dat = get_private_data(ctx);

	dentry = get_dentry(ctx->wim, path, WIMLIB_CASE_INSENSITIVE);
	if (!dentry ||
	    (dentry->d_inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
					      FILE_ATTRIBUTE_REPARSE_POINT |
					      FILE_ATTRIBUTE_ENCRYPTED)) ||
	    !(lte = inode_unnamed_lte(dentry->d_inode, ctx->wim->lookup_table)))
	{
		WARNING("%"TS" does not exist in WIM image!", path);
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
	dat->prepopulate_pats = s;
	dat->mem_prepopulate_pats = mem;
	return 0;
}

static bool
in_prepopulate_list(struct wim_dentry *dentry, struct apply_ctx *ctx)
{
	struct string_set *pats;
	const tchar *path;
	size_t path_nchars;

	pats = get_private_data(ctx)->prepopulate_pats;
	if (!pats || !pats->num_strings)
		return false;

	path = dentry_full_path(dentry);
	if (!path)
		return false;

	path_nchars = tstrlen(path);

	for (size_t i = 0; i < pats->num_strings; i++)
		if (match_path(path, path_nchars, pats->strings[i],
			       OS_PREFERRED_PATH_SEPARATOR, true))
			return true;

	return false;
}

static int
hash_lookup_table(WIMStruct *wim, u8 hash[SHA1_HASH_SIZE])
{
	return wim_reshdr_to_hash(&wim->hdr.lookup_table_reshdr, wim, hash);
}

static int
win32_start_extract(const wchar_t *path, struct apply_ctx *ctx)
{
	int ret;
	unsigned vol_flags;
	bool supports_SetFileShortName;
	struct win32_apply_private_data *dat = get_private_data(ctx);

	ret = win32_get_vol_flags(path, &vol_flags, &supports_SetFileShortName);
	if (ret)
		goto err;

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

	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_WIMBOOT) {

		ret = load_prepopulate_pats(ctx);
		if (ret == WIMLIB_ERR_NOMEM)
			goto err;

		if (!wim_info_get_wimboot(ctx->wim->wim_info,
					  ctx->wim->current_image))
			WARNING("Image is not marked as WIMBoot compatible!");


		ret = hash_lookup_table(ctx->wim, dat->wim_lookup_table_hash);
		if (ret)
			goto err;

		ret = wimboot_alloc_data_source_id(ctx->wim->filename,
						   ctx->wim->hdr.guid,
						   ctx->wim->current_image,
						   path,
						   &dat->data_source_id,
						   &dat->wof_running);
		if (ret)
			goto err;
	}

	return 0;

err:
	free_prepopulate_pats(dat);
	return ret;
}

static int
win32_finish_extract(struct apply_ctx *ctx)
{
	free_prepopulate_pats(get_private_data(ctx));
	return 0;
}

/* Delete a non-directory file, working around Windows quirks.  */
static BOOL
win32_delete_file_wrapper(const wchar_t *path)
{
	DWORD err;
	DWORD attrib;

	if (DeleteFile(path))
		return TRUE;

	err = GetLastError();
	attrib = GetFileAttributes(path);
	if ((attrib != INVALID_FILE_ATTRIBUTES) &&
	    (attrib & FILE_ATTRIBUTE_READONLY))
	{
		/* Try again with FILE_ATTRIBUTE_READONLY cleared.  */
		attrib &= ~FILE_ATTRIBUTE_READONLY;
		if (SetFileAttributes(path, attrib)) {
			if (DeleteFile(path))
				return TRUE;
			else
				err = GetLastError();
		}
	}

	SetLastError(err);
	return FALSE;
}


/* Create a normal file, overwriting one already present.  */
static int
win32_create_file(const wchar_t *path, struct apply_ctx *ctx, u64 *cookie_ret)
{
	HANDLE h;

	/* Notes:
	 *
	 * WRITE_OWNER and WRITE_DAC privileges are required for some reason,
	 * even through we're creating a new file.
	 *
	 * FILE_FLAG_OPEN_REPARSE_POINT is required to prevent an existing
	 * reparse point from redirecting the creation of the new file
	 * (potentially to an arbitrary location).
	 *
	 * CREATE_ALWAYS could be used instead of CREATE_NEW.  However, there
	 * are quirks that would need to be handled (e.g. having to set
	 * FILE_ATTRIBUTE_HIDDEN and/or FILE_ATTRIBUTE_SYSTEM if the existing
	 * file had them specified, and/or having to clear
	 * FILE_ATTRIBUTE_READONLY on the existing file).  It's simpler to just
	 * call win32_delete_file_wrapper() to delete the existing file in such
	 * a way that already handles the FILE_ATTRIBUTE_READONLY quirk.
	 */
retry:
	h = CreateFile(path, WRITE_OWNER | WRITE_DAC, 0, NULL, CREATE_NEW,
		       FILE_FLAG_BACKUP_SEMANTICS |
				FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		DWORD err = GetLastError();

		if (err == ERROR_FILE_EXISTS && win32_delete_file_wrapper(path))
			goto retry;
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
		if (!win32_delete_file_wrapper(newpath))
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
		if (!win32_delete_file_wrapper(newpath))
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
			     struct apply_ctx *ctx,
			     struct wim_dentry *dentry)
{
	if (ctx->extract_flags & WIMLIB_EXTRACT_FLAG_WIMBOOT
	    && lte
	    && lte->resource_location == RESOURCE_IN_WIM
	    && lte->rspec->wim == ctx->wim
	    && lte->size == lte->rspec->uncompressed_size
	    && !in_prepopulate_list(dentry, ctx))
	{
		const struct win32_apply_private_data *dat;

		dat = get_private_data(ctx);
		return wimboot_set_pointer(file.path, lte,
					   dat->data_source_id,
					   dat->wim_lookup_table_hash,
					   dat->wof_running);
	}

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

/*
 * Set an arbitrary security descriptor on an arbitrary file (or directory),
 * working around bugs and design flaws in the Windows operating system.
 *
 * On success, return 0.  On failure, return WIMLIB_ERR_SET_SECURITY and set
 * errno.  Note: if WIMLIB_EXTRACT_FLAG_STRICT_ACLS is not set in
 * ctx->extract_flags, this function succeeds iff any part of the security
 * descriptor was successfully set.
 */
static int
win32_set_security_descriptor(const wchar_t *path, const u8 *desc,
			      size_t desc_size, struct apply_ctx *ctx)
{
	SECURITY_INFORMATION info;
	HANDLE h;
	int ret;

	/* We really just want to set entire the security descriptor as-is, but
	 * all available APIs require specifying the specific parts of the
	 * descriptor being set.  Start out by requesting all parts be set.  If
	 * permissions problems are encountered, fall back to omitting some
	 * parts (first the SACL, then the DACL, then the owner), unless the
	 * WIMLIB_EXTRACT_FLAG_STRICT_ACLS flag has been enabled.  */
	info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
	       DACL_SECURITY_INFORMATION  | SACL_SECURITY_INFORMATION;

	h = INVALID_HANDLE_VALUE;

	/* Prefer NtSetSecurityObject() to SetFileSecurity().  SetFileSecurity()
	 * itself necessarily uses NtSetSecurityObject() as the latter is the
	 * underlying system call for setting security information, but
	 * SetFileSecurity() opens the handle with NtCreateFile() without
	 * FILE_OPEN_FILE_BACKUP_INTENT.  Hence, access checks are done and due
	 * to the Windows security model, even a process running as the
	 * Administrator can have access denied.  (Of course, this not mentioned
	 * in the MS "documentation".)  */

#ifdef WITH_NTDLL
	if (func_NtSetSecurityObject) {
		DWORD dwDesiredAccess;

		/* Open a handle for NtSetSecurityObject() with as many relevant
		 * access rights as possible.
		 *
		 * We don't know which rights will be actually granted.  It
		 * could be less than what is needed to actually assign the full
		 * security descriptor, especially if the process is running as
		 * a non-Administrator.  However, by default we just do the best
		 * we can, unless WIMLIB_EXTRACT_FLAG_STRICT_ACLS has been
		 * enabled.  The MAXIMUM_ALLOWED access right is seemingly
		 * designed for this use case; however, it does not work
		 * properly in all cases: it can cause CreateFile() to fail with
		 * ERROR_ACCESS_DENIED, even though by definition
		 * MAXIMUM_ALLOWED access only requests access rights that are
		 * *not* denied.  (Needless to say, MS does not document this
		 * bug.)  */

		dwDesiredAccess = WRITE_DAC |
				  WRITE_OWNER |
				  ACCESS_SYSTEM_SECURITY;
		for (;;) {
			DWORD err;

			h = win32_open_existing_file(path, dwDesiredAccess);
			if (h != INVALID_HANDLE_VALUE)
				break;
			err = GetLastError();
			if (err == ERROR_ACCESS_DENIED ||
			    err == ERROR_PRIVILEGE_NOT_HELD)
			{
				/* Don't increment partial_security_descriptors
				 * here or check WIMLIB_EXTRACT_FLAG_STRICT_ACLS
				 * here.  It will be done later if needed; here
				 * we are just trying to get as many relevant
				 * access rights as possible.  */
				if (dwDesiredAccess & ACCESS_SYSTEM_SECURITY) {
					dwDesiredAccess &= ~ACCESS_SYSTEM_SECURITY;
					continue;
				}
				if (dwDesiredAccess & WRITE_DAC) {
					dwDesiredAccess &= ~WRITE_DAC;
					continue;
				}
				if (dwDesiredAccess & WRITE_OWNER) {
					dwDesiredAccess &= ~WRITE_OWNER;
					continue;
				}
			}
			/* Other error, or couldn't open the file even with no
			 * access rights specified.  Something else must be
			 * wrong.  */
			set_errno_from_win32_error(err);
			return WIMLIB_ERR_SET_SECURITY;
		}
	}
#endif

	/* Try setting the security descriptor.  */
	for (;;) {
		DWORD err;

		err = do_win32_set_security_descriptor(h, path, info,
						       (PSECURITY_DESCRIPTOR)desc);
		if (err == ERROR_SUCCESS) {
			ret = 0;
			break;
		}

		/* Failed to set the requested parts of the security descriptor.
		 * If the error was permissions-related, try to set fewer parts
		 * of the security descriptor, unless
		 * WIMLIB_EXTRACT_FLAG_STRICT_ACLS is enabled.  */
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
			/* Nothing left except GROUP, and if we removed it we
			 * wouldn't have anything at all.  */
		}
		/* No part of the security descriptor could be set, or
		 * WIMLIB_EXTRACT_FLAG_STRICT_ACLS is enabled and the full
		 * security descriptor could not be set.  */
		if (!(info & SACL_SECURITY_INFORMATION))
			ctx->partial_security_descriptors--;
		set_errno_from_win32_error(err);
		ret = WIMLIB_ERR_SET_SECURITY;
		break;
	}

	/* Close handle opened for NtSetSecurityObject().  */
#ifdef WITH_NTDLL
	if (func_NtSetSecurityObject)
		CloseHandle(h);
#endif
	return ret;
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
	.finish_extract		  = win32_finish_extract,
	.abort_extract		  = win32_finish_extract,
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
