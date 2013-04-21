/*
 * win32.c
 *
 * All the library code specific to native Windows builds is in here.
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

#include "config.h"
#include <windows.h>
#include <ntdef.h>
#include <wchar.h>
#include <shlwapi.h> /* shlwapi.h for PathMatchSpecW() */
#ifdef ERROR /* windows.h defines this */
#  undef ERROR
#endif

#include "win32.h"
#include "dentry.h"
#include "lookup_table.h"
#include "security.h"
#include "endianness.h"
#include <pthread.h>

#include <errno.h>

#define MAX_GET_SD_ACCESS_DENIED_WARNINGS 1
#define MAX_GET_SACL_PRIV_NOTHELD_WARNINGS 1
struct win32_capture_state {
	unsigned long num_get_sd_access_denied;
	unsigned long num_get_sacl_priv_notheld;
};

#define MAX_SET_SD_ACCESS_DENIED_WARNINGS 1
#define MAX_SET_SACL_PRIV_NOTHELD_WARNINGS 1

#ifdef ENABLE_ERROR_MESSAGES
static void
win32_error(u32 err_code)
{
	wchar_t *buffer;
	DWORD nchars;
	nchars = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM |
				    FORMAT_MESSAGE_ALLOCATE_BUFFER,
				NULL, err_code, 0,
				(wchar_t*)&buffer, 0, NULL);
	if (nchars == 0) {
		ERROR("Error printing error message! "
		      "Computer will self-destruct in 3 seconds.");
	} else {
		ERROR("Win32 error: %ls", buffer);
		LocalFree(buffer);
	}
}
#else /* ENABLE_ERROR_MESSAGES */
#  define win32_error(err_code)
#endif /* !ENABLE_ERROR_MESSAGES */

/* Pointers to functions that are not available on all targetted versions of
 * Windows (XP and later).  NOTE: The WINAPI annotations seem to be important; I
 * assume it specifies a certain calling convention. */

/* Vista and later */
static HANDLE (WINAPI *win32func_FindFirstStreamW)(LPCWSTR lpFileName,
					    STREAM_INFO_LEVELS InfoLevel,
					    LPVOID lpFindStreamData,
					    DWORD dwFlags) = NULL;

/* Vista and later */
static BOOL (WINAPI *win32func_FindNextStreamW)(HANDLE hFindStream,
					 LPVOID lpFindStreamData) = NULL;

static HMODULE hKernel32 = NULL;

/* Try to dynamically load some functions */
void
win32_global_init()
{
	DWORD err;

	if (hKernel32 == NULL) {
		DEBUG("Loading Kernel32.dll");
		hKernel32 = LoadLibraryW(L"Kernel32.dll");
		if (hKernel32 == NULL) {
			err = GetLastError();
			WARNING("Can't load Kernel32.dll");
			win32_error(err);
			return;
		}
	}

	DEBUG("Looking for FindFirstStreamW");
	win32func_FindFirstStreamW = (void*)GetProcAddress(hKernel32, "FindFirstStreamW");
	if (!win32func_FindFirstStreamW) {
		WARNING("Could not find function FindFirstStreamW() in Kernel32.dll!");
		WARNING("Capturing alternate data streams will not be supported.");
		return;
	}

	DEBUG("Looking for FindNextStreamW");
	win32func_FindNextStreamW = (void*)GetProcAddress(hKernel32, "FindNextStreamW");
	if (!win32func_FindNextStreamW) {
		WARNING("Could not find function FindNextStreamW() in Kernel32.dll!");
		WARNING("Capturing alternate data streams will not be supported.");
		win32func_FindFirstStreamW = NULL;
	}
}

void
win32_global_cleanup()
{
	if (hKernel32 != NULL) {
		DEBUG("Closing Kernel32.dll");
		FreeLibrary(hKernel32);
		hKernel32 = NULL;
	}
}

static const wchar_t *capture_access_denied_msg =
L"         If you are not running this program as the administrator, you may\n"
 "         need to do so, so that all data and metadata can be backed up.\n"
 "         Otherwise, there may be no way to access the desired data or\n"
 "         metadata without taking ownership of the file or directory.\n"
 ;

static const wchar_t *apply_access_denied_msg =
L"If you are not running this program as the administrator, you may\n"
 "          need to do so, so that all data and metadata can be extracted\n"
 "          exactly as the origignal copy.  However, if you do not care that\n"
 "          the security descriptors are extracted correctly, you could run\n"
 "          `wimlib-imagex apply' with the --no-acls flag instead.\n"
 ;

static HANDLE
win32_open_existing_file(const wchar_t *path, DWORD dwDesiredAccess)
{
	return CreateFileW(path,
			   dwDesiredAccess,
			   FILE_SHARE_READ,
			   NULL, /* lpSecurityAttributes */
			   OPEN_EXISTING,
			   FILE_FLAG_BACKUP_SEMANTICS |
			       FILE_FLAG_OPEN_REPARSE_POINT,
			   NULL /* hTemplateFile */);
}

HANDLE
win32_open_file_data_only(const wchar_t *path)
{
	return win32_open_existing_file(path, FILE_READ_DATA);
}

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

/* Given a path, which may not yet exist, get a set of flags that describe the
 * features of the volume the path is on. */
static int
win32_get_vol_flags(const wchar_t *path, unsigned *vol_flags_ret)
{
	wchar_t *volume;
	BOOL bret;
	DWORD vol_flags;

	if (path[0] != L'\0' && path[0] != L'\\' &&
	    path[0] != L'/' && path[1] == L':')
	{
		/* Path starts with a drive letter; use it. */
		volume = alloca(4 * sizeof(wchar_t));
		volume[0] = path[0];
		volume[1] = path[1];
		volume[2] = L'\\';
		volume[3] = L'\0';
	} else {
		/* Path does not start with a drive letter; use the volume of
		 * the current working directory. */
		volume = NULL;
	}
	bret = GetVolumeInformationW(volume, /* lpRootPathName */
				     NULL,  /* lpVolumeNameBuffer */
				     0,     /* nVolumeNameSize */
				     NULL,  /* lpVolumeSerialNumber */
				     NULL,  /* lpMaximumComponentLength */
				     &vol_flags, /* lpFileSystemFlags */
				     NULL,  /* lpFileSystemNameBuffer */
				     0);    /* nFileSystemNameSize */
	if (!bret) {
		DWORD err = GetLastError();
		WARNING("Failed to get volume information for path \"%ls\"", path);
		win32_error(err);
		vol_flags = 0xffffffff;
	}

	DEBUG("using vol_flags = %x", vol_flags);
	*vol_flags_ret = vol_flags;
	return 0;
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
	if (FindFirstFileW(path, &dat) && dat.cAlternateFileName[0] != L'\0') {
		DEBUG("\"%ls\": short name \"%ls\"", path, dat.cAlternateFileName);
		size_t short_name_nbytes = wcslen(dat.cAlternateFileName) *
					   sizeof(wchar_t);
		size_t n = short_name_nbytes + sizeof(wchar_t);
		dentry->short_name = MALLOC(n);
		if (!dentry->short_name)
			return WIMLIB_ERR_NOMEM;
		memcpy(dentry->short_name, dat.cAlternateFileName, n);
		dentry->short_name_nbytes = short_name_nbytes;
	}
	/* If we can't read the short filename for some reason, we just ignore
	 * the error and assume the file has no short name.  I don't think this
	 * should be an issue, since the short names are essentially obsolete
	 * anyway. */
	return 0;
}

static int
win32_get_security_descriptor(struct wim_dentry *dentry,
			      struct sd_set *sd_set,
			      const wchar_t *path,
			      struct win32_capture_state *state,
			      int add_image_flags)
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

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_STRICT_ACLS)
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
				  struct wim_lookup_table *lookup_table,
				  struct wim_inode_table *inode_table,
				  struct sd_set *sd_set,
				  const struct wimlib_capture_config *config,
				  int add_image_flags,
				  wimlib_progress_func_t progress_func,
				  struct win32_capture_state *state,
				  unsigned vol_flags);

/* Reads the directory entries of directory using a Win32 API and recursively
 * calls win32_build_dentry_tree() on them. */
static int
win32_recurse_directory(struct wim_dentry *root,
			wchar_t *dir_path,
			size_t dir_path_num_chars,
			struct wim_lookup_table *lookup_table,
			struct wim_inode_table *inode_table,
			struct sd_set *sd_set,
			const struct wimlib_capture_config *config,
			int add_image_flags,
			wimlib_progress_func_t progress_func,
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
							lookup_table,
							inode_table,
							sd_set,
							config,
							add_image_flags,
							progress_func,
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

/* Load a reparse point into a WIM inode.  It is just stored in memory.
 *
 * @hFile:  Open handle to a reparse point, with permission to read the reparse
 *          data.
 *
 * @inode:  WIM inode for the reparse point.
 *
 * @lookup_table:  Stream lookup table for the WIM; an entry will be added to it
 *                 for the reparse point unless an entry already exists for
 *                 the exact same data stream.
 *
 * @path:  External path to the reparse point.  Used for error messages only.
 *
 * Returns 0 on success; nonzero on failure. */
static int
win32_capture_reparse_point(HANDLE hFile,
			    struct wim_inode *inode,
			    struct wim_lookup_table *lookup_table,
			    const wchar_t *path)
{
	DEBUG("Capturing reparse point \"%ls\"", path);

	/* "Reparse point data, including the tag and optional GUID,
	 * cannot exceed 16 kilobytes." - MSDN  */
	char reparse_point_buf[16 * 1024];
	DWORD bytesReturned;

	if (!DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT,
			     NULL, /* "Not used with this operation; set to NULL" */
			     0, /* "Not used with this operation; set to 0" */
			     reparse_point_buf, /* "A pointer to a buffer that
						   receives the reparse point data */
			     sizeof(reparse_point_buf), /* "The size of the output
							   buffer, in bytes */
			     &bytesReturned,
			     NULL))
	{
		DWORD err = GetLastError();
		ERROR("Failed to get reparse data of \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_READ;
	}
	if (bytesReturned < 8) {
		ERROR("Reparse data on \"%ls\" is invalid", path);
		return WIMLIB_ERR_READ;
	}
	inode->i_reparse_tag = le32_to_cpu(*(u32*)reparse_point_buf);
	return inode_add_ads_with_data(inode, L"",
				       reparse_point_buf + 8,
				       bytesReturned - 8, lookup_table);
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
	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED && !is_named_stream)
		lte->resource_location = RESOURCE_WIN32_ENCRYPTED;
	else
		lte->resource_location = RESOURCE_WIN32;
	lte->resource_entry.original_size = (u64)dat->StreamSize.QuadPart;

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
				ERROR("Failed to look up data streams "
				      "of \"%ls\": Access denied!\n%ls",
				      path, capture_access_denied_msg);
				return WIMLIB_ERR_READ;
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
				  struct wim_lookup_table *lookup_table,
				  struct wim_inode_table *inode_table,
				  struct sd_set *sd_set,
				  const struct wimlib_capture_config *config,
				  int add_image_flags,
				  wimlib_progress_func_t progress_func,
				  struct win32_capture_state *state,
				  unsigned vol_flags)
{
	struct wim_dentry *root = NULL;
	struct wim_inode *inode;
	DWORD err;
	u64 file_size;
	int ret = 0;

	if (exclude_path(path, path_num_chars, config, true)) {
		if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) {
			ERROR("Cannot exclude the root directory from capture");
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
			goto out;
		}
		if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE)
		    && progress_func)
		{
			union wimlib_progress_info info;
			info.scan.cur_path = path;
			info.scan.excluded = true;
			progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
		}
		goto out;
	}

	if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
	    && progress_func)
	{
		union wimlib_progress_info info;
		info.scan.cur_path = path;
		info.scan.excluded = false;
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
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

	/* Create a WIM dentry with an associated inode, which may be shared */
	ret = inode_table_new_dentry(inode_table,
				     path_basename_with_len(path, path_num_chars),
				     ((u64)file_info.nFileIndexHigh << 32) |
				         (u64)file_info.nFileIndexLow,
				     file_info.dwVolumeSerialNumber,
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

	add_image_flags &= ~(WIMLIB_ADD_IMAGE_FLAG_ROOT | WIMLIB_ADD_IMAGE_FLAG_SOURCE);

	if (!(add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NO_ACLS)
	    && (vol_flags & FILE_PERSISTENT_ACLS))
	{
		ret = win32_get_security_descriptor(root, sd_set, path, state,
						    add_image_flags);
		if (ret)
			goto out_close_handle;
	}

	file_size = ((u64)file_info.nFileSizeHigh << 32) |
		     (u64)file_info.nFileSizeLow;

	if (inode_is_directory(inode)) {
		/* Directory (not a reparse point) --- recurse to children */

		/* But first... directories may have alternate data streams that
		 * need to be captured. */
		ret = win32_capture_streams(path,
					    path_num_chars,
					    inode,
					    lookup_table,
					    file_size,
					    vol_flags);
		if (ret)
			goto out_close_handle;
		ret = win32_recurse_directory(root,
					      path,
					      path_num_chars,
					      lookup_table,
					      inode_table,
					      sd_set,
					      config,
					      add_image_flags,
					      progress_func,
					      state,
					      vol_flags);
	} else if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		/* Reparse point: save the reparse tag and data.  Alternate data
		 * streams are not captured, if it's even possible for a reparse
		 * point to have alternate data streams... */
		ret = win32_capture_reparse_point(hFile,
						  inode,
						  lookup_table,
						  path);
	} else {
		/* Not a directory, not a reparse point; capture the default
		 * file contents and any alternate data streams. */
		ret = win32_capture_streams(path,
					    path_num_chars,
					    inode,
					    lookup_table,
					    file_size,
					    vol_flags);
	}
out_close_handle:
	CloseHandle(hFile);
out:
	if (ret == 0)
		*root_ret = root;
	else
		free_dentry_tree(root, lookup_table);
	return ret;
}

static void
win32_do_capture_warnings(const struct win32_capture_state *state,
			  int add_image_flags)
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
	(add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NO_ACLS) ? L"." :
         L", although you might consider\n"
"          passing the --no-acls flag to `wimlib-imagex capture' or\n"
"          `wimlib-imagex append' to explicitly capture no security\n"
"          descriptors.\n");
}

/* Win32 version of capturing a directory tree */
int
win32_build_dentry_tree(struct wim_dentry **root_ret,
			const wchar_t *root_disk_path,
			struct wim_lookup_table *lookup_table,
			struct wim_inode_table *inode_table,
			struct sd_set *sd_set,
			const struct wimlib_capture_config *config,
			int add_image_flags,
			wimlib_progress_func_t progress_func,
			void *extra_arg)
{
	size_t path_nchars;
	wchar_t *path;
	int ret;
	struct win32_capture_state state;
	unsigned vol_flags;

	path_nchars = wcslen(root_disk_path);
	if (path_nchars > 32767)
		return WIMLIB_ERR_INVALID_PARAM;

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
	ret = win32_build_dentry_tree_recursive(root_ret,
						path,
						path_nchars,
						lookup_table,
						inode_table,
						sd_set,
						config,
						add_image_flags,
						progress_func,
						&state,
						vol_flags);
	FREE(path);
	if (ret == 0)
		win32_do_capture_warnings(&state, add_image_flags);
	return ret;
}

static int
win32_set_reparse_data(HANDLE h,
		       u32 reparse_tag,
		       const struct wim_lookup_table_entry *lte,
		       const wchar_t *path)
{
	int ret;
	u8 *buf;
	size_t len;

	if (!lte) {
		WARNING("\"%ls\" is marked as a reparse point but had no reparse data",
			path);
		return 0;
	}
	len = wim_resource_size(lte);
	if (len > 16 * 1024 - 8) {
		WARNING("\"%ls\": reparse data too long!", path);
		return 0;
	}

	/* The WIM stream omits the ReparseTag and ReparseDataLength fields, so
	 * leave 8 bytes of space for them at the beginning of the buffer, then
	 * set them manually. */
	buf = alloca(len + 8);
	ret = read_full_resource_into_buf(lte, buf + 8, false);
	if (ret)
		return ret;
	*(u32*)(buf + 0) = cpu_to_le32(reparse_tag);
	*(u16*)(buf + 4) = cpu_to_le16(len);
	*(u16*)(buf + 6) = 0;

	/* Set the reparse data on the open file using the
	 * FSCTL_SET_REPARSE_POINT ioctl.
	 *
	 * There are contradictions in Microsoft's documentation for this:
	 *
	 * "If hDevice was opened without specifying FILE_FLAG_OVERLAPPED,
	 * lpOverlapped is ignored."
	 *
	 * --- So setting lpOverlapped to NULL is okay since it's ignored.
	 *
	 * "If lpOverlapped is NULL, lpBytesReturned cannot be NULL. Even when an
	 * operation returns no output data and lpOutBuffer is NULL,
	 * DeviceIoControl makes use of lpBytesReturned. After such an
	 * operation, the value of lpBytesReturned is meaningless."
	 *
	 * --- So lpOverlapped not really ignored, as it affects another
	 *  parameter.  This is the actual behavior: lpBytesReturned must be
	 *  specified, even though lpBytesReturned is documented as:
	 *
	 *  "Not used with this operation; set to NULL."
	 */
	DWORD bytesReturned;
	if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, buf, len + 8,
			     NULL, 0,
			     &bytesReturned /* lpBytesReturned */,
			     NULL /* lpOverlapped */))
	{
		DWORD err = GetLastError();
		ERROR("Failed to set reparse data on \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

static int
win32_set_compressed(HANDLE hFile, const wchar_t *path)
{
	USHORT format = COMPRESSION_FORMAT_DEFAULT;
	DWORD bytesReturned = 0;
	if (!DeviceIoControl(hFile, FSCTL_SET_COMPRESSION,
			     &format, sizeof(USHORT),
			     NULL, 0,
			     &bytesReturned, NULL))
	{
		/* Could be a warning only, but we only call this if the volume
		 * supports compression.  So I'm calling this an error. */
		DWORD err = GetLastError();
		ERROR("Failed to set compression flag on \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

static int
win32_set_sparse(HANDLE hFile, const wchar_t *path)
{
	DWORD bytesReturned = 0;
	if (!DeviceIoControl(hFile, FSCTL_SET_SPARSE,
			     NULL, 0,
			     NULL, 0,
			     &bytesReturned, NULL))
	{
		/* Could be a warning only, but we only call this if the volume
		 * supports sparse files.  So I'm calling this an error. */
		DWORD err = GetLastError();
		WARNING("Failed to set sparse flag on \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/*
 * Sets the security descriptor on an extracted file.
 */
static int
win32_set_security_data(const struct wim_inode *inode,
			const wchar_t *path,
			struct apply_args *args)
{
	PSECURITY_DESCRIPTOR descriptor;
	unsigned long n;
	DWORD err;

	descriptor = wim_const_security_data(args->w)->descriptors[inode->i_security_id];

	SECURITY_INFORMATION securityInformation = DACL_SECURITY_INFORMATION |
					           SACL_SECURITY_INFORMATION |
					           OWNER_SECURITY_INFORMATION |
					           GROUP_SECURITY_INFORMATION;
again:
	if (SetFileSecurityW(path, securityInformation, descriptor))
		return 0;
	err = GetLastError();
	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
		goto fail;
	switch (err) {
	case ERROR_PRIVILEGE_NOT_HELD:
		if (securityInformation & SACL_SECURITY_INFORMATION) {
			n = args->num_set_sacl_priv_notheld++;
			securityInformation &= ~SACL_SECURITY_INFORMATION;
			if (n < MAX_SET_SACL_PRIV_NOTHELD_WARNINGS) {
				WARNING(
"We don't have enough privileges to set the full security\n"
"          descriptor on \"%ls\"!\n", path);
				if (args->num_set_sd_access_denied +
				    args->num_set_sacl_priv_notheld == 1)
				{
					WARNING("%ls", apply_access_denied_msg);
				}
				WARNING("Re-trying with SACL omitted.\n", path);
			} else if (n == MAX_GET_SACL_PRIV_NOTHELD_WARNINGS) {
				WARNING(
"Suppressing further 'privileges not held' error messages when setting\n"
"          security descriptors.");
			}
			goto again;
		}
		/* Fall through */
	case ERROR_INVALID_OWNER:
	case ERROR_ACCESS_DENIED:
		n = args->num_set_sd_access_denied++;
		if (n < MAX_SET_SD_ACCESS_DENIED_WARNINGS) {
			WARNING("Failed to set security descriptor on \"%ls\": "
				"Access denied!\n", path);
			if (args->num_set_sd_access_denied +
			    args->num_set_sacl_priv_notheld == 1)
			{
				WARNING("%ls", apply_access_denied_msg);
			}
		} else if (n == MAX_SET_SD_ACCESS_DENIED_WARNINGS) {
			WARNING(
"Suppressing further access denied error messages when setting\n"
"          security descriptors");
		}
		return 0;
	default:
fail:
		ERROR("Failed to set security descriptor on \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
}


static int
win32_extract_chunk(const void *buf, size_t len, void *arg)
{
	HANDLE hStream = arg;

	DWORD nbytes_written;
	wimlib_assert(len <= 0xffffffff);

	if (!WriteFile(hStream, buf, len, &nbytes_written, NULL) ||
	    nbytes_written != len)
	{
		DWORD err = GetLastError();
		ERROR("WriteFile(): write error");
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

static int
do_win32_extract_stream(HANDLE hStream, struct wim_lookup_table_entry *lte)
{
	return extract_wim_resource(lte, wim_resource_size(lte),
				    win32_extract_chunk, hStream);
}

static int
do_win32_extract_encrypted_stream(const wchar_t *path,
				  const struct wim_lookup_table_entry *lte)
{
	ERROR("Extracting encryted streams not implemented");
	return WIMLIB_ERR_INVALID_PARAM;
}

static bool
path_is_root_of_drive(const wchar_t *path)
{
	if (!*path)
		return false;

	if (*path != L'/' && *path != L'\\') {
		if (*(path + 1) == L':')
			path += 2;
		else
			return false;
	}
	while (*path == L'/' || *path == L'\\')
		path++;
	return (*path == L'\0');
}

static DWORD
win32_get_create_flags_and_attributes(DWORD i_attributes)
{
	DWORD attributes;

	/*
	 * Some attributes cannot be set by passing them to CreateFile().  In
	 * particular:
	 *
	 * FILE_ATTRIBUTE_DIRECTORY:
	 *   CreateDirectory() must be called instead of CreateFile().
	 *
	 * FILE_ATTRIBUTE_SPARSE_FILE:
	 *   Needs an ioctl.
	 *   See: win32_set_sparse().
	 *
	 * FILE_ATTRIBUTE_COMPRESSED:
	 *   Not clear from the documentation, but apparently this needs an
	 *   ioctl as well.
	 *   See: win32_set_compressed().
	 *
	 * FILE_ATTRIBUTE_REPARSE_POINT:
	 *   Needs an ioctl, with the reparse data specified.
	 *   See: win32_set_reparse_data().
	 *
	 * In addition, clear any file flags in the attributes that we don't
	 * want, but also specify FILE_FLAG_OPEN_REPARSE_POINT and
	 * FILE_FLAG_BACKUP_SEMANTICS as we are a backup application.
	 */
	attributes = i_attributes & ~(FILE_ATTRIBUTE_SPARSE_FILE |
				      FILE_ATTRIBUTE_COMPRESSED |
				      FILE_ATTRIBUTE_REPARSE_POINT |
				      FILE_ATTRIBUTE_DIRECTORY |
				      FILE_FLAG_DELETE_ON_CLOSE |
				      FILE_FLAG_NO_BUFFERING |
				      FILE_FLAG_OPEN_NO_RECALL |
				      FILE_FLAG_OVERLAPPED |
				      FILE_FLAG_RANDOM_ACCESS |
				      /*FILE_FLAG_SESSION_AWARE |*/
				      FILE_FLAG_SEQUENTIAL_SCAN |
				      FILE_FLAG_WRITE_THROUGH);
	return attributes |
	       FILE_FLAG_OPEN_REPARSE_POINT |
	       FILE_FLAG_BACKUP_SEMANTICS;
}

static bool
inode_has_special_attributes(const struct wim_inode *inode)
{
	return (inode->i_attributes & (FILE_ATTRIBUTE_COMPRESSED |
				       FILE_ATTRIBUTE_REPARSE_POINT |
				       FILE_ATTRIBUTE_SPARSE_FILE)) != 0;
}

/* Set compression or sparse attributes, and reparse data, if supported by the
 * volume. */
static int
win32_set_special_attributes(HANDLE hFile, const struct wim_inode *inode,
			     struct wim_lookup_table_entry *unnamed_stream_lte,
			     const wchar_t *path, unsigned vol_flags)
{
	int ret;

	if (inode->i_attributes & FILE_ATTRIBUTE_COMPRESSED) {
		if (vol_flags & FILE_FILE_COMPRESSION) {
			DEBUG("Setting compression flag on \"%ls\"", path);
			ret = win32_set_compressed(hFile, path);
			if (ret)
				return ret;
		} else {
			DEBUG("Cannot set compression attribute on \"%ls\": "
			      "volume does not support transparent compression",
			      path);
		}
	}

	if (inode->i_attributes & FILE_ATTRIBUTE_SPARSE_FILE) {
		if (vol_flags & FILE_SUPPORTS_SPARSE_FILES) {
			DEBUG("Setting sparse flag on \"%ls\"", path);
			ret = win32_set_sparse(hFile, path);
			if (ret)
				return ret;
		} else {
			DEBUG("Cannot set sparse attribute on \"%ls\": "
			      "volume does not support sparse files",
			      path);
		}
	}

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		if (vol_flags & FILE_SUPPORTS_REPARSE_POINTS) {
			DEBUG("Setting reparse data on \"%ls\"", path);
			ret = win32_set_reparse_data(hFile, inode->i_reparse_tag,
						     unnamed_stream_lte, path);
			if (ret)
				return ret;
		} else {
			DEBUG("Cannot set reparse data on \"%ls\": volume "
			      "does not support reparse points", path);
		}
	}

	return 0;
}

static int
win32_extract_stream(const struct wim_inode *inode,
		     const wchar_t *path,
		     const wchar_t *stream_name_utf16,
		     struct wim_lookup_table_entry *lte,
		     unsigned vol_flags)
{
	wchar_t *stream_path;
	HANDLE h;
	int ret;
	DWORD err;
	DWORD creationDisposition = CREATE_ALWAYS;

	if (stream_name_utf16) {
		/* Named stream.  Create a buffer that contains the UTF-16LE
		 * string [.\]@path:@stream_name_utf16.  This is needed to
		 * create and open the stream using CreateFileW().  I'm not
		 * aware of any other APIs to do this.  Note: the '$DATA' suffix
		 * seems to be unneeded.  Additional note: a "./" prefix needs
		 * to be added when the path is not absolute to avoid ambiguity
		 * with drive letters. */
		size_t stream_path_nchars;
		size_t path_nchars;
		size_t stream_name_nchars;
		const wchar_t *prefix;

		path_nchars = wcslen(path);
		stream_name_nchars = wcslen(stream_name_utf16);
		stream_path_nchars = path_nchars + 1 + stream_name_nchars;
		if (path[0] != cpu_to_le16(L'\0') &&
		    path[0] != cpu_to_le16(L'/') &&
		    path[0] != cpu_to_le16(L'\\') &&
		    path[1] != cpu_to_le16(L':'))
		{
			prefix = L"./";
			stream_path_nchars += 2;
		} else {
			prefix = L"";
		}
		stream_path = alloca((stream_path_nchars + 1) * sizeof(wchar_t));
		swprintf(stream_path, L"%ls%ls:%ls",
			 prefix, path, stream_name_utf16);
	} else {
		/* Unnamed stream; its path is just the path to the file itself.
		 * */
		stream_path = (wchar_t*)path;

		/* Directories must be created with CreateDirectoryW().  Then
		 * the call to CreateFileW() will merely open the directory that
		 * was already created rather than creating a new file. */
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (!CreateDirectoryW(stream_path, NULL)) {
				err = GetLastError();
				switch (err) {
				case ERROR_ALREADY_EXISTS:
					break;
				case ERROR_ACCESS_DENIED:
					if (path_is_root_of_drive(path))
						break;
					/* Fall through */
				default:
					ERROR("Failed to create directory \"%ls\"",
					      stream_path);
					win32_error(err);
					ret = WIMLIB_ERR_MKDIR;
					goto fail;
				}
			}
			DEBUG("Created directory \"%ls\"", stream_path);
			if (!inode_has_special_attributes(inode)) {
				ret = 0;
				goto out;
			}
			DEBUG("Directory \"%ls\" has special attributes!",
			      stream_path);
			creationDisposition = OPEN_EXISTING;
		}
	}

	DEBUG("Opening \"%ls\"", stream_path);
	h = CreateFileW(stream_path,
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			creationDisposition,
			win32_get_create_flags_and_attributes(inode->i_attributes),
			NULL);
	if (h == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		ERROR("Failed to create \"%ls\"", stream_path);
		win32_error(err);
		ret = WIMLIB_ERR_OPEN;
		goto fail;
	}

	if (stream_name_utf16 == NULL && inode_has_special_attributes(inode)) {
		ret = win32_set_special_attributes(h, inode, lte, path,
						   vol_flags);
		if (ret)
			goto fail_close_handle;
	}

	if (!(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		if (lte) {
			DEBUG("Extracting \"%ls\" (len = %"PRIu64")",
			      stream_path, wim_resource_size(lte));
			if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED
			    && stream_name_utf16 == NULL
			    && (vol_flags & FILE_SUPPORTS_ENCRYPTION))
			{
				ret = do_win32_extract_encrypted_stream(stream_path,
									lte);
			} else {
				ret = do_win32_extract_stream(h, lte);
			}
			if (ret)
				goto fail_close_handle;
		}
	}

	DEBUG("Closing \"%ls\"", stream_path);
	if (!CloseHandle(h)) {
		err = GetLastError();
		ERROR("Failed to close \"%ls\"", stream_path);
		win32_error(err);
		ret = WIMLIB_ERR_WRITE;
		goto fail;
	}
	ret = 0;
	goto out;
fail_close_handle:
	CloseHandle(h);
fail:
	ERROR("Error extracting %ls", stream_path);
out:
	return ret;
}

/*
 * Creates a file, directory, or reparse point and extracts all streams to it
 * (unnamed data stream and/or reparse point stream, plus any alternate data
 * streams).  This in Win32-specific code.
 *
 * @inode:	WIM inode for this file or directory.
 * @path:	UTF-16LE external path to extract the inode to.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_extract_streams(const struct wim_inode *inode,
		      const wchar_t *path, u64 *completed_bytes_p,
		      unsigned vol_flags)
{
	struct wim_lookup_table_entry *unnamed_lte;
	int ret;

	unnamed_lte = inode_unnamed_lte_resolved(inode);
	ret = win32_extract_stream(inode, path, NULL, unnamed_lte,
				   vol_flags);
	if (ret)
		goto out;
	if (unnamed_lte)
		*completed_bytes_p += wim_resource_size(unnamed_lte);

	if (!(vol_flags & FILE_NAMED_STREAMS))
		goto out;
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		const struct wim_ads_entry *ads_entry = &inode->i_ads_entries[i];
		if (ads_entry->stream_name_nbytes != 0) {
			/* Skip special UNIX data entries (see documentation for
			 * WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) */
			if (ads_entry->stream_name_nbytes == WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES
			    && !memcmp(ads_entry->stream_name,
				       WIMLIB_UNIX_DATA_TAG_UTF16LE,
				       WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES))
				continue;
			ret = win32_extract_stream(inode,
						   path,
						   ads_entry->stream_name,
						   ads_entry->lte,
						   vol_flags);
			if (ret)
				break;
			if (ads_entry->lte)
				*completed_bytes_p += wim_resource_size(ads_entry->lte);
		}
	}
out:
	return ret;
}

/* Extract a file, directory, reparse point, or hard link to an
 * already-extracted file using the Win32 API */
int
win32_do_apply_dentry(const wchar_t *output_path,
		      size_t output_path_num_chars,
		      struct wim_dentry *dentry,
		      struct apply_args *args)
{
	int ret;
	struct wim_inode *inode = dentry->d_inode;
	DWORD err;

	if (!args->have_vol_flags) {
		win32_get_vol_flags(output_path, &args->vol_flags);
		args->have_vol_flags = true;
		/* Warn the user about data that may not be extracted. */
		if (!(args->vol_flags & FILE_SUPPORTS_SPARSE_FILES))
			WARNING("Volume does not support sparse files!\n"
				"          Sparse files will be extracted as non-sparse.");
		if (!(args->vol_flags & FILE_SUPPORTS_REPARSE_POINTS))
			WARNING("Volume does not support reparse points!\n"
				"          Reparse point data will not be extracted.");
		if (!(args->vol_flags & FILE_NAMED_STREAMS)) {
			WARNING("Volume does not support named data streams!\n"
				"          Named data streams will not be extracted.");
		}
		if (!(args->vol_flags & FILE_SUPPORTS_ENCRYPTION)) {
			WARNING("Volume does not support encryption!\n"
				"          Encrypted files will be extracted as raw data.");
		}
		if (!(args->vol_flags & FILE_FILE_COMPRESSION)) {
			WARNING("Volume does not support transparent compression!\n"
				"          Compressed files will be extracted as non-compressed.");
		}
		if (!(args->vol_flags & FILE_PERSISTENT_ACLS)) {
			if (args->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS) {
				ERROR("Strict ACLs requested, but the volume does not "
				      "support ACLs!");
				return WIMLIB_ERR_VOLUME_LACKS_FEATURES;
			} else {
				WARNING("Volume does not support persistent ACLS!\n"
					"          File permissions will not be extracted.");
			}
		}
	}

	if (inode->i_nlink > 1 && inode->i_extracted_file != NULL) {
		/* Linked file, with another name already extracted.  Create a
		 * hard link. */

		/* There is a volume flag for this (FILE_SUPPORTS_HARD_LINKS),
		 * but it's only available on Windows 7 and later.  So no use
		 * even checking it, really.  Instead, CreateHardLinkW() will
		 * apparently return ERROR_INVALID_FUNCTION if the volume does
		 * not support hard links. */
		DEBUG("Creating hard link \"%ls => %ls\"",
		      output_path, inode->i_extracted_file);
		if (CreateHardLinkW(output_path, inode->i_extracted_file, NULL))
			return 0;

		err = GetLastError();
		if (err != ERROR_INVALID_FUNCTION) {
			ERROR("Can't create hard link \"%ls => %ls\"",
			      output_path, inode->i_extracted_file);
			win32_error(err);
			return WIMLIB_ERR_LINK;
		} else {
			WARNING("Can't create hard link \"%ls => %ls\":\n"
				"          Volume does not support hard links!\n"
				"          Falling back to extracting a copy of the file.");
		}
	}
	/* Create the file, directory, or reparse point, and extract the
	 * data streams. */
	ret = win32_extract_streams(inode, output_path,
				    &args->progress.extract.completed_bytes,
				    args->vol_flags);
	if (ret)
		return ret;

	if (inode->i_security_id >= 0 &&
	    !(args->extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS)
	    && (args->vol_flags & FILE_PERSISTENT_ACLS))
	{
		ret = win32_set_security_data(inode, output_path, args);
		if (ret)
			return ret;
	}
	if (inode->i_nlink > 1) {
		/* Save extracted path for a later call to
		 * CreateHardLinkW() if this inode has multiple links.
		 * */
		inode->i_extracted_file = WSTRDUP(output_path);
		if (!inode->i_extracted_file)
			ret = WIMLIB_ERR_NOMEM;
	}
	return 0;
}

/* Set timestamps on an extracted file using the Win32 API */
int
win32_do_apply_dentry_timestamps(const wchar_t *path,
				 size_t path_num_chars,
				 const struct wim_dentry *dentry,
				 const struct apply_args *args)
{
	DWORD err;
	HANDLE h;
	const struct wim_inode *inode = dentry->d_inode;

	DEBUG("Opening \"%ls\" to set timestamps", path);
	h = win32_open_existing_file(path, FILE_WRITE_ATTRIBUTES);
	if (h == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		goto fail;
	}

	FILETIME creationTime = {.dwLowDateTime = inode->i_creation_time & 0xffffffff,
				 .dwHighDateTime = inode->i_creation_time >> 32};
	FILETIME lastAccessTime = {.dwLowDateTime = inode->i_last_access_time & 0xffffffff,
				  .dwHighDateTime = inode->i_last_access_time >> 32};
	FILETIME lastWriteTime = {.dwLowDateTime = inode->i_last_write_time & 0xffffffff,
				  .dwHighDateTime = inode->i_last_write_time >> 32};

	DEBUG("Calling SetFileTime() on \"%ls\"", path);
	if (!SetFileTime(h, &creationTime, &lastAccessTime, &lastWriteTime)) {
		err = GetLastError();
		CloseHandle(h);
		goto fail;
	}
	DEBUG("Closing \"%ls\"", path);
	if (!CloseHandle(h)) {
		err = GetLastError();
		goto fail;
	}
	goto out;
fail:
	/* Only warn if setting timestamps failed; still return 0. */
	WARNING("Can't set timestamps on \"%ls\"", path);
	win32_error(err);
out:
	return 0;
}

/* Replacement for POSIX fsync() */
int
fsync(int fd)
{
	DWORD err;
	HANDLE h;

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		ERROR("Could not get Windows handle for file descriptor");
		win32_error(err);
		errno = EBADF;
		return -1;
	}
	if (!FlushFileBuffers(h)) {
		err = GetLastError();
		ERROR("Could not flush file buffers to disk");
		win32_error(err);
		errno = EIO;
		return -1;
	}
	return 0;
}

/* Use the Win32 API to get the number of processors */
unsigned
win32_get_number_of_processors()
{
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
}

/* Replacement for POSIX-2008 realpath().  Warning: partial functionality only
 * (resolved_path must be NULL).   Also I highly doubt that GetFullPathName
 * really does the right thing under all circumstances. */
wchar_t *
realpath(const wchar_t *path, wchar_t *resolved_path)
{
	DWORD ret;
	wimlib_assert(resolved_path == NULL);
	DWORD err;

	ret = GetFullPathNameW(path, 0, NULL, NULL);
	if (!ret) {
		err = GetLastError();
		goto fail_win32;
	}

	resolved_path = TMALLOC(ret);
	if (!resolved_path)
		goto out;
	ret = GetFullPathNameW(path, ret, resolved_path, NULL);
	if (!ret) {
		err = GetLastError();
		free(resolved_path);
		resolved_path = NULL;
		goto fail_win32;
	}
	goto out;
fail_win32:
	win32_error(err);
	errno = -1;
out:
	return resolved_path;
}

/* rename() on Windows fails if the destination file exists.  And we need to
 * make it work on wide characters.  Fix it. */
int
win32_rename_replacement(const wchar_t *oldpath, const wchar_t *newpath)
{
	if (MoveFileExW(oldpath, newpath, MOVEFILE_REPLACE_EXISTING)) {
		return 0;
	} else {
		/* As usual, the possible error values are not documented */
		DWORD err = GetLastError();
		ERROR("MoveFileEx(): Can't rename \"%ls\" to \"%ls\"",
		      oldpath, newpath);
		win32_error(err);
		errno = -1;
		return -1;
	}
}

/* Replacement for POSIX fnmatch() (partial functionality only) */
int
fnmatch(const wchar_t *pattern, const wchar_t *string, int flags)
{
	if (PathMatchSpecW(string, pattern))
		return 0;
	else
		return FNM_NOMATCH;
}

/* truncate() replacement */
int
win32_truncate_replacement(const wchar_t *path, off_t size)
{
	DWORD err = NO_ERROR;
	LARGE_INTEGER liOffset;

	HANDLE h = win32_open_existing_file(path, GENERIC_WRITE);
	if (h == INVALID_HANDLE_VALUE)
		goto fail;

	liOffset.QuadPart = size;
	if (!SetFilePointerEx(h, liOffset, NULL, FILE_BEGIN))
		goto fail_close_handle;

	if (!SetEndOfFile(h))
		goto fail_close_handle;
	CloseHandle(h);
	return 0;

fail_close_handle:
	err = GetLastError();
	CloseHandle(h);
fail:
	if (err == NO_ERROR)
		err = GetLastError();
	ERROR("Can't truncate \"%ls\" to %"PRIu64" bytes", path, size);
	win32_error(err);
	errno = -1;
	return -1;
}


/* This really could be replaced with _wcserror_s, but this doesn't seem to
 * actually be available in MSVCRT.DLL on Windows XP (perhaps it's statically
 * linked in by Visual Studio...?). */
extern int
win32_strerror_r_replacement(int errnum, wchar_t *buf, size_t buflen)
{
	static pthread_mutex_t strerror_lock = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock(&strerror_lock);
	mbstowcs(buf, strerror(errnum), buflen);
	buf[buflen - 1] = '\0';
	pthread_mutex_unlock(&strerror_lock);
	return 0;
}

#endif /* __WIN32__ */
