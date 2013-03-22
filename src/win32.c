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

#ifndef __WIN32__
#  error "This file contains Windows code"
#endif

#include "config.h"
#include <windows.h>
#include <ntdef.h>
#include <wchar.h>
#include <shlwapi.h> /* shlwapi.h for PathMatchSpecA() */
#ifdef ERROR /* windows.h defines this */
#  undef ERROR
#endif

#include "win32.h"
#include "dentry.h"
#include "lookup_table.h"
#include "security.h"
#include "endianness.h"

#include <errno.h>



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

/* Try to dynamically load some functions */
void
win32_global_init()
{
	DWORD err;
	bool warned;

	DEBUG("Loading Kernel32.dll");

	HMODULE lib = LoadLibraryA("Kernel32.dll");
	if (lib == NULL) {
		err = GetLastError();
		WARNING("Can't load Kernel32.dll");
		win32_error(err);
		return;
	}

	DEBUG("Looking for FindFirstStreamW");
	win32func_FindFirstStreamW = (void*)GetProcAddress(lib, "FindFirstStreamW");
	if (!win32func_FindFirstStreamW) {
		WARNING("Could not find function FindFirstStreamW() in Kernel32.dll!");
		WARNING("Capturing alternate data streams will not be supported.");
		goto out_free_lib;
	}

	DEBUG("Looking for FindNextStreamW");
	win32func_FindNextStreamW = (void*)GetProcAddress(lib, "FindNextStreamW");
	if (!win32func_FindNextStreamW) {
		WARNING("Could not find function FindNextStreamW() in Kernel32.dll!");
		WARNING("Capturing alternate data streams will not be supported.");
		win32func_FindFirstStreamW = NULL;
	}
out_free_lib:
	DEBUG("Closing Kernel32.dll");
	FreeLibrary(lib);
}

static const char *access_denied_msg =
"         If you are not running this program as the administrator, you may\n"
"         need to do so, so that all data and metadata can be backed up.\n"
"         Otherwise, there may be no way to access the desired data or\n"
"         metadata without taking ownership of the file or directory.\n";

#ifdef ENABLE_ERROR_MESSAGES
void
win32_error(u32 err_code)
{
	char *buffer;
	DWORD nchars;
	nchars = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
				NULL, err_code, 0,
				(char*)&buffer, 0, NULL);
	if (nchars == 0) {
		ERROR("Error printing error message! "
		      "Computer will self-destruct in 3 seconds.");
	} else {
		ERROR("Win32 error: %s", buffer);
		LocalFree(buffer);
	}
}

void
win32_error_last()
{
	win32_error(GetLastError());
}
#endif

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
win32_read_file(const mbchar *filename,
		void *handle, u64 offset, size_t size, void *buf)
{
	HANDLE h = handle;
	DWORD err;
	DWORD bytesRead;
	LARGE_INTEGER liOffset = {.QuadPart = offset};

	wimlib_assert(size <= 0xffffffff);

	if (SetFilePointerEx(h, liOffset, NULL, FILE_BEGIN))
		if (ReadFile(h, buf, size, &bytesRead, NULL) && bytesRead == size)
			return 0;
	err = GetLastError();
	ERROR("Error reading \"%s\"", filename);
	win32_error(err);
	return WIMLIB_ERR_READ;
}

void
win32_close_file(void *handle)
{
	CloseHandle((HANDLE)handle);
}

static u64
FILETIME_to_u64(const FILETIME *ft)
{
	return ((u64)ft->dwHighDateTime << 32) | (u64)ft->dwLowDateTime;
}

static int
win32_get_short_name(struct wim_dentry *dentry,
		     const wchar_t *path_utf16)
{
	WIN32_FIND_DATAW dat;
	if (FindFirstFileW(path_utf16, &dat) &&
	    dat.cAlternateFileName[0] != L'\0')
	{
		size_t short_name_nbytes = wcslen(dat.cAlternateFileName) * 2;
		size_t n = short_name_nbytes + sizeof(wchar_t);
		dentry->short_name = MALLOC(n);
		if (!dentry->short_name)
			return WIMLIB_ERR_NOMEM;
		memcpy(dentry->short_name, dat.cAlternateFileName, n);
		dentry->short_name_nbytes = short_name_nbytes;
	}
	return 0;
}

static int
win32_get_security_descriptor(struct wim_dentry *dentry,
			      struct sd_set *sd_set,
			      const wchar_t *path_utf16)
{
	SECURITY_INFORMATION requestedInformation;
	DWORD lenNeeded = 0;
	BOOL status;
	DWORD err;

	requestedInformation = DACL_SECURITY_INFORMATION |
			       SACL_SECURITY_INFORMATION |
			       OWNER_SECURITY_INFORMATION |
			       GROUP_SECURITY_INFORMATION;
	/* Request length of security descriptor */
	status = GetFileSecurityW(path_utf16, requestedInformation,
				  NULL, 0, &lenNeeded);
	err = GetLastError();
	if (!status && err == ERROR_INSUFFICIENT_BUFFER) {
		DWORD len = lenNeeded;
		char buf[len];
		if (GetFileSecurityW(path_utf16, requestedInformation,
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

	if (err == ERROR_ACCESS_DENIED) {
		WARNING("Failed to read security descriptor of \"%ls\": "
			"Access denied!\n%s", path_utf16, access_denied_msg);
		return 0;
	} else {
		ERROR("Win32 API: Failed to read security descriptor of \"%ls\"",
		      path_utf16);
		win32_error(err);
		return WIMLIB_ERR_READ;
	}
}

/* Reads the directory entries of directory using a Win32 API and recursively
 * calls win32_build_dentry_tree() on them. */
static int
win32_recurse_directory(struct wim_dentry *root,
			const mbchar *root_disk_path,
			struct wim_lookup_table *lookup_table,
			struct wim_security_data *sd,
			const struct capture_config *config,
			int add_image_flags,
			wimlib_progress_func_t progress_func,
			struct sd_set *sd_set,
			const wchar_t *path_utf16,
			size_t path_utf16_nchars)
{
	WIN32_FIND_DATAW dat;
	HANDLE hFind;
	DWORD err;
	int ret;

	{
		/* Begin reading the directory by calling FindFirstFileW.
		 * Unlike UNIX opendir(), FindFirstFileW has file globbing built
		 * into it.  But this isn't what we actually want, so just add a
		 * dummy glob to get all entries. */
		wchar_t pattern_buf[path_utf16_nchars + 3];
		memcpy(pattern_buf, path_utf16,
		       path_utf16_nchars * sizeof(wchar_t));
		pattern_buf[path_utf16_nchars] = L'/';
		pattern_buf[path_utf16_nchars + 1] = L'*';
		pattern_buf[path_utf16_nchars + 2] = L'\0';
		hFind = FindFirstFileW(pattern_buf, &dat);
	}
	if (hFind == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			return 0;
		} else {
			ERROR("Win32 API: Failed to read directory \"%s\"",
			      root_disk_path);
			win32_error(err);
			return WIMLIB_ERR_READ;
		}
	}
	ret = 0;
	do {
		/* Skip . and .. entries */
		if (!(dat.cFileName[0] == cpu_to_le16(L'.') &&
		      (dat.cFileName[1] == cpu_to_le16(L'\0') ||
		       (dat.cFileName[1] == cpu_to_le16(L'.') &&
			dat.cFileName[2] == cpu_to_le16(L'\0')))))
		{
			struct wim_dentry *child;

			mbchar *mbs_name;
			size_t mbs_name_nbytes;
			ret = utf16le_to_mbs(dat.cFileName,
					     wcslen(dat.cFileName) * sizeof(wchar_t),
					     &mbs_name,
					     &mbs_name_nbytes);
			if (ret)
				goto out_find_close;

			mbchar name[strlen(root_disk_path) + 1 + mbs_name_nbytes + 1];
			sprintf(name, "%s/%s", root_disk_path, mbs_name);
			FREE(mbs_name);
			ret = win32_build_dentry_tree(&child, name, lookup_table,
						      sd, config, add_image_flags,
						      progress_func, sd_set);
			if (ret)
				goto out_find_close;
			if (child)
				dentry_add_child(root, child);
		}
	} while (FindNextFileW(hFind, &dat));
	err = GetLastError();
	if (err != ERROR_NO_MORE_FILES) {
		ERROR("Win32 API: Failed to read directory \"%s\"", root_disk_path);
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
			    const mbchar *path)
{
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
		ERROR("Win32 API: Failed to get reparse data of \"%s\"", path);
		win32_error(err);
		return WIMLIB_ERR_READ;
	}
	if (bytesReturned < 8) {
		ERROR("Reparse data on \"%s\" is invalid", path);
		return WIMLIB_ERR_READ;
	}
	inode->i_reparse_tag = le32_to_cpu(*(u32*)reparse_point_buf);
	return inode_add_ads_with_data(inode, "",
				       reparse_point_buf + 8,
				       bytesReturned - 8, lookup_table);
}

/* Calculate the SHA1 message digest of a Win32 data stream, which may be either
 * an unnamed or named data stream.
 *
 * @path:	Path to the file, with the stream noted at the end for named
 *              streams.  UTF-16LE encoding.
 *
 * @hash:       On success, the SHA1 message digest of the stream is written to
 *              this location.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_sha1sum(const wchar_t *path, u8 hash[SHA1_HASH_SIZE])
{
	HANDLE hFile;
	SHA_CTX ctx;
	u8 buf[32768];
	DWORD bytesRead;
	int ret;

	hFile = win32_open_file_data_only(path);
	if (hFile == INVALID_HANDLE_VALUE)
		return WIMLIB_ERR_OPEN;

	sha1_init(&ctx);
	for (;;) {
		if (!ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL)) {
			ret = WIMLIB_ERR_READ;
			goto out_close_handle;
		}
		if (bytesRead == 0)
			break;
		sha1_update(&ctx, buf, bytesRead);
	}
	ret = 0;
	sha1_final(hash, &ctx);
out_close_handle:
	CloseHandle(hFile);
	return ret;
}

/* Scans an unnamed or named stream of a Win32 file (not a reparse point
 * stream); calculates its SHA1 message digest and either creates a `struct
 * wim_lookup_table_entry' in memory for it, or uses an existing 'struct
 * wim_lookup_table_entry' for an identical stream.
 *
 * @path_utf16:         Path to the file (UTF-16LE).
 *
 * @path_utf16_nchars:  Number of 2-byte characters in @path_utf16.
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
win32_capture_stream(const wchar_t *path_utf16,
		     size_t path_utf16_nchars,
		     struct wim_inode *inode,
		     struct wim_lookup_table *lookup_table,
		     WIN32_FIND_STREAM_DATA *dat)
{
	struct wim_ads_entry *ads_entry;
	u8 hash[SHA1_HASH_SIZE];
	struct wim_lookup_table_entry *lte;
	int ret;
	wchar_t *stream_name, *colon;
	size_t stream_name_nchars;
	bool is_named_stream;
	wchar_t *spath;
	size_t spath_nchars;
	DWORD err;
	size_t spath_buf_nbytes;
	const wchar_t *relpath_prefix;
	const wchar_t *colonchar;

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
						  stream_name_nchars * 2);
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
	spath_nchars = path_utf16_nchars;
	relpath_prefix = L"";
	colonchar = L"";
	if (is_named_stream) {
		spath_nchars += 1 + stream_name_nchars;
		colonchar = L":";
		if (path_utf16_nchars == 1 &&
		    path_utf16[0] != cpu_to_le16('/') &&
		    path_utf16[0] != cpu_to_le16('\\'))
		{
			spath_nchars += 2;
			relpath_prefix = L"./";
		}
	}

	spath_buf_nbytes = (spath_nchars + 1) * sizeof(wchar_t);
	spath = MALLOC(spath_buf_nbytes);

	swprintf(spath, spath_buf_nbytes, L"%ls%ls%ls%ls",
		 relpath_prefix, path_utf16, colonchar, stream_name);

	ret = win32_sha1sum(spath, hash);
	if (ret) {
		err = GetLastError();
		ERROR("Win32 API: Failed to read \"%ls\" to calculate SHA1sum",
		      spath);
		win32_error(err);
		goto out_free_spath;
	}

	lte = __lookup_resource(lookup_table, hash);
	if (lte) {
		/* Use existing wim_lookup_table_entry that has the same SHA1
		 * message digest */
		lte->refcnt++;
	} else {
		/* Make a new wim_lookup_table_entry */
		lte = new_lookup_table_entry();
		if (!lte) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_spath;
		}
		lte->win32_file_on_disk = spath;
		lte->file_on_disk_fp = INVALID_HANDLE_VALUE;
		spath = NULL;
		lte->resource_location = RESOURCE_WIN32;
		lte->resource_entry.original_size = (uint64_t)dat->StreamSize.QuadPart;
		lte->resource_entry.size = (uint64_t)dat->StreamSize.QuadPart;
		copy_hash(lte->hash, hash);
		lookup_table_insert(lookup_table, lte);
	}
	if (is_named_stream)
		ads_entry->lte = lte;
	else
		inode->i_lte = lte;
out_free_spath:
	FREE(spath);
out:
	return ret;
out_invalid_stream_name:
	ERROR("Invalid stream name: \"%ls:%ls\"", path_utf16, dat->cStreamName);
	ret = WIMLIB_ERR_READ;
	goto out;
}

/* Scans a Win32 file for unnamed and named data streams (not reparse point
 * streams).
 *
 * @path_utf16:         Path to the file (UTF-16LE).
 *
 * @path_utf16_nchars:  Number of 2-byte characters in @path_utf16.
 *
 * @inode:              WIM inode to save the stream into.
 *
 * @lookup_table:       Stream lookup table for the WIM.
 *
 * @file_size:		Size of unnamed data stream.  (Used only if alternate
 *                      data streams API appears to be unavailable.)
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_capture_streams(const wchar_t *path_utf16,
		      size_t path_utf16_nchars,
		      struct wim_inode *inode,
		      struct wim_lookup_table *lookup_table,
		      u64 file_size)
{
	WIN32_FIND_STREAM_DATA dat;
	int ret;
	HANDLE hFind;
	DWORD err;

	if (win32func_FindFirstStreamW == NULL)
		goto unnamed_only;

	hFind = win32func_FindFirstStreamW(path_utf16, FindStreamInfoStandard, &dat, 0);
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
			return 0;
		} else {
			if (err == ERROR_ACCESS_DENIED) {
				WARNING("Failed to look up data streams of \"%ls\": "
					"Access denied!\n%s", path_utf16,
					access_denied_msg);
				return 0;
			} else {
				ERROR("Win32 API: Failed to look up data streams of \"%ls\"",
				      path_utf16);
				win32_error(err);
				return WIMLIB_ERR_READ;
			}
		}
	}
	do {
		ret = win32_capture_stream(path_utf16,
					   path_utf16_nchars,
					   inode, lookup_table,
					   &dat);
		if (ret)
			goto out_find_close;
	} while (win32func_FindNextStreamW(hFind, &dat));
	err = GetLastError();
	if (err != ERROR_HANDLE_EOF) {
		ERROR("Win32 API: Error reading data streams from \"%ls\"", path_utf16);
		win32_error(err);
		ret = WIMLIB_ERR_READ;
	}
out_find_close:
	FindClose(hFind);
	return ret;
unnamed_only:
	if (inode->i_attributes &
	     (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
	{
		ret = 0;
	} else {
		wcscpy(dat.cStreamName, L"::$DATA");
		dat.StreamSize.QuadPart = file_size;
		ret = win32_capture_stream(path_utf16,
					   path_utf16_nchars,
					   inode, lookup_table,
					   &dat);
	}
	return ret;
}

/* Win32 version of capturing a directory tree */
int
win32_build_dentry_tree(struct wim_dentry **root_ret,
			const mbchar *root_disk_path,
			struct wim_lookup_table *lookup_table,
			struct wim_security_data *sd,
			const struct capture_config *config,
			int add_image_flags,
			wimlib_progress_func_t progress_func,
			void *extra_arg)
{
	struct wim_dentry *root = NULL;
	int ret = 0;
	struct wim_inode *inode;

	wchar_t *path_utf16;
	size_t path_utf16_nbytes;
	size_t path_utf16_nchars;
	struct sd_set *sd_set;
	DWORD err;
	u64 file_size;

	if (exclude_path(root_disk_path, config, true)) {
		if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) {
			ERROR("Cannot exclude the root directory from capture");
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
			goto out;
		}
		if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
		    && progress_func)
		{
			union wimlib_progress_info info;
			info.scan.cur_path = root_disk_path;
			info.scan.excluded = true;
			progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
		}
		goto out;
	}

	if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
	    && progress_func)
	{
		union wimlib_progress_info info;
		info.scan.cur_path = root_disk_path;
		info.scan.excluded = false;
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
	}

	if (extra_arg == NULL) {
		sd_set = alloca(sizeof(struct sd_set));
		sd_set->rb_root.rb_node = NULL,
		sd_set->sd = sd;
	} else {
		sd_set = extra_arg;
	}

	ret = mbs_to_utf16le(root_disk_path, strlen(root_disk_path),
			     &path_utf16, &path_utf16_nbytes);
	if (ret)
		goto out_destroy_sd_set;
	path_utf16_nchars = path_utf16_nbytes / sizeof(wchar_t);

	HANDLE hFile = win32_open_existing_file(path_utf16,
						FILE_READ_DATA | FILE_READ_ATTRIBUTES);
	if (hFile == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		ERROR("Win32 API: Failed to open \"%s\"", root_disk_path);
		win32_error(err);
		ret = WIMLIB_ERR_OPEN;
		goto out_free_path_utf16;
	}

	BY_HANDLE_FILE_INFORMATION file_info;
	if (!GetFileInformationByHandle(hFile, &file_info)) {
		err = GetLastError();
		ERROR("Win32 API: Failed to get file information for \"%s\"",
		      root_disk_path);
		win32_error(err);
		ret = WIMLIB_ERR_STAT;
		goto out_close_handle;
	}

	/* Create a WIM dentry */
	ret = new_dentry_with_timeless_inode(path_basename(root_disk_path), &root);
	if (ret)
		goto out_close_handle;

	/* Start preparing the associated WIM inode */
	inode = root->d_inode;

	inode->i_attributes = file_info.dwFileAttributes;
	inode->i_creation_time = FILETIME_to_u64(&file_info.ftCreationTime);
	inode->i_last_write_time = FILETIME_to_u64(&file_info.ftLastWriteTime);
	inode->i_last_access_time = FILETIME_to_u64(&file_info.ftLastAccessTime);
	inode->i_ino = ((u64)file_info.nFileIndexHigh << 32) |
			(u64)file_info.nFileIndexLow;

	inode->i_resolved = 1;
	add_image_flags &= ~(WIMLIB_ADD_IMAGE_FLAG_ROOT | WIMLIB_ADD_IMAGE_FLAG_SOURCE);

	/* Get DOS name and security descriptor (if any). */
	ret = win32_get_short_name(root, path_utf16);
	if (ret)
		goto out_close_handle;

	if (!(add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NO_ACLS)) {
		ret = win32_get_security_descriptor(root, sd_set, path_utf16);
		if (ret)
			goto out_close_handle;
	}

	file_size = ((u64)file_info.nFileSizeHigh << 32) |
		     (u64)file_info.nFileSizeLow;

	if (inode_is_directory(inode)) {
		/* Directory (not a reparse point) --- recurse to children */

		/* But first... directories may have alternate data streams that
		 * need to be captured. */
		ret = win32_capture_streams(path_utf16,
					    path_utf16_nchars,
					    inode,
					    lookup_table,
					    file_size);
		if (ret)
			goto out_close_handle;
		ret = win32_recurse_directory(root,
					      root_disk_path,
					      lookup_table,
					      sd,
					      config,
					      add_image_flags,
					      progress_func,
					      sd_set,
					      path_utf16,
					      path_utf16_nchars);
	} else if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		/* Reparse point: save the reparse tag and data */
		ret = win32_capture_reparse_point(hFile,
						  inode,
						  lookup_table,
						  root_disk_path);
	} else {
		/* Not a directory, not a reparse point; capture the default
		 * file contents and any alternate data streams. */
		ret = win32_capture_streams(path_utf16,
					    path_utf16_nchars,
					    inode,
					    lookup_table,
					    file_size);
	}
out_close_handle:
	CloseHandle(hFile);
out_free_path_utf16:
	FREE(path_utf16);
out_destroy_sd_set:
	if (extra_arg == NULL)
		destroy_sd_set(sd_set);
out:
	if (ret == 0)
		*root_ret = root;
	else
		free_dentry_tree(root, lookup_table);
	return ret;
}

/* Replacement for POSIX fnmatch() (partial functionality only) */
int
fnmatch(const char *pattern, const char *string, int flags)
{
	if (PathMatchSpecA(string, pattern))
		return 0;
	else
		return FNM_NOMATCH;
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
	ret = read_full_wim_resource(lte, buf + 8, 0);
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
win32_extract_chunk(const void *buf, size_t len, u64 offset, void *arg)
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
win32_extract_stream(const struct wim_inode *inode,
		     const wchar_t *path,
		     const wchar_t *stream_name_utf16,
		     struct wim_lookup_table_entry *lte,
		     const struct wim_security_data *security_data)
{
	wchar_t *stream_path;
	HANDLE h;
	int ret;
	DWORD err;
	DWORD creationDisposition = CREATE_ALWAYS;

	SECURITY_ATTRIBUTES *secattr;

	if (security_data && inode->i_security_id != -1) {
		secattr = alloca(sizeof(*secattr));
		secattr->nLength = sizeof(*secattr);
		secattr->lpSecurityDescriptor = security_data->descriptors[inode->i_security_id];
		secattr->bInheritHandle = FALSE;
	} else {
		secattr = NULL;
	}

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
		swprintf(stream_path, stream_path_nchars + 1, L"%ls%ls:%ls",
			 prefix, path, stream_name_utf16);
	} else {
		/* Unnamed stream; its path is just the path to the file itself.
		 * */
		stream_path = (wchar_t*)path;

		/* Directories must be created with CreateDirectoryW().  Then
		 * the call to CreateFileW() will merely open the directory that
		 * was already created rather than creating a new file. */
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (!CreateDirectoryW(stream_path, secattr)) {
				err = GetLastError();
				if (err != ERROR_ALREADY_EXISTS) {
					ERROR("Failed to create directory \"%ls\"",
					      stream_path);
					win32_error(err);
					ret = WIMLIB_ERR_MKDIR;
					goto fail;
				}
			}
			DEBUG("Created directory \"%ls\"", stream_path);
			if (!(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
				ret = 0;
				goto out;
			}
			creationDisposition = OPEN_EXISTING;
		}
	}

	DEBUG("Opening \"%ls\"", stream_path);
	h = CreateFileW(stream_path,
			GENERIC_WRITE,
			0,
			secattr,
			creationDisposition,
			FILE_FLAG_OPEN_REPARSE_POINT |
			    FILE_FLAG_BACKUP_SEMANTICS |
			    inode->i_attributes,
			NULL);
	if (h == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		ERROR("Failed to create \"%ls\"", stream_path);
		win32_error(err);
		ret = WIMLIB_ERR_OPEN;
		goto fail;
	}

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT &&
	    stream_name_utf16 == NULL)
	{
		DEBUG("Setting reparse data on \"%ls\"", path);
		ret = win32_set_reparse_data(h, inode->i_reparse_tag, lte, path);
		if (ret)
			goto fail_close_handle;
	} else {
		if (lte) {
			DEBUG("Extracting \"%ls\" (len = %"PRIu64")",
			      stream_path, wim_resource_size(lte));
			ret = do_win32_extract_stream(h, lte);
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
		      const struct wim_security_data *security_data)
{
	struct wim_lookup_table_entry *unnamed_lte;
	int ret;

	unnamed_lte = inode_unnamed_lte_resolved(inode);
	ret = win32_extract_stream(inode, path, NULL, unnamed_lte,
				   security_data);
	if (ret)
		goto out;
	if (unnamed_lte)
		*completed_bytes_p += wim_resource_size(unnamed_lte);
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
						   NULL);
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
int win32_do_apply_dentry(const mbchar *output_path,
			  size_t output_path_nbytes,
			  struct wim_dentry *dentry,
			  struct apply_args *args)
{
	wchar_t *utf16le_path;
	size_t utf16le_path_nbytes;
	DWORD err;
	int ret;
	struct wim_inode *inode = dentry->d_inode;

	ret = mbs_to_utf16le(output_path, output_path_nbytes,
			     &utf16le_path, &utf16le_path_nbytes);
	if (ret)
		return ret;

	if (inode->i_nlink > 1 && inode->i_extracted_file != NULL) {
		/* Linked file, with another name already extracted.  Create a
		 * hard link. */
		DEBUG("Creating hard link \"%ls => %ls\"",
		      utf16le_path, inode->i_extracted_file);
		if (!CreateHardLinkW(utf16le_path, inode->i_extracted_file, NULL))
		{
			err = GetLastError();
			ERROR("Can't create hard link \"%ls => %ls\"",
			      utf16le_path, inode->i_extracted_file);
			ret = WIMLIB_ERR_LINK;
			win32_error(err);
		}
	} else {
		/* Create the file, directory, or reparse point, and extract the
		 * data streams. */
		const struct wim_security_data *security_data;
		if (args->extract_flags & WIMLIB_EXTRACT_FLAG_NOACLS)
			security_data = NULL;
		else
			security_data = wim_const_security_data(args->w);

		ret = win32_extract_streams(inode, utf16le_path,
					    &args->progress.extract.completed_bytes,
					    security_data);
		if (ret)
			goto out_free_utf16_path;

		if (inode->i_nlink > 1) {
			/* Save extracted path for a later call to
			 * CreateHardLinkW() if this inode has multiple links.
			 * */
			inode->i_extracted_file = utf16le_path;
			goto out;
		}
	}
out_free_utf16_path:
	FREE(utf16le_path);
out:
	return ret;
}

/* Set timestamps on an extracted file using the Win32 API */
int
win32_do_apply_dentry_timestamps(const mbchar *output_path,
				 size_t output_path_nbytes,
				 const struct wim_dentry *dentry,
				 const struct apply_args *args)
{
	/* Win32 */
	wchar_t *utf16le_path;
	size_t utf16le_path_nbytes;
	DWORD err;
	HANDLE h;
	int ret;
	const struct wim_inode *inode = dentry->d_inode;

	ret = mbs_to_utf16le(output_path, output_path_nbytes,
			    &utf16le_path, &utf16le_path_nbytes);
	if (ret)
		return ret;

	DEBUG("Opening \"%s\" to set timestamps", output_path);
	h = win32_open_existing_file(utf16le_path, FILE_WRITE_ATTRIBUTES);

	if (h == INVALID_HANDLE_VALUE)
		err = GetLastError();
	FREE(utf16le_path);
	if (h == INVALID_HANDLE_VALUE)
		goto fail;

	FILETIME creationTime = {.dwLowDateTime = inode->i_creation_time & 0xffffffff,
				 .dwHighDateTime = inode->i_creation_time >> 32};
	FILETIME lastAccessTime = {.dwLowDateTime = inode->i_last_access_time & 0xffffffff,
				  .dwHighDateTime = inode->i_last_access_time >> 32};
	FILETIME lastWriteTime = {.dwLowDateTime = inode->i_last_write_time & 0xffffffff,
				  .dwHighDateTime = inode->i_last_write_time >> 32};

	DEBUG("Calling SetFileTime() on \"%s\"", output_path);
	if (!SetFileTime(h, &creationTime, &lastAccessTime, &lastWriteTime)) {
		err = GetLastError();
		CloseHandle(h);
		goto fail;
	}
	DEBUG("Closing \"%s\"", output_path);
	if (!CloseHandle(h)) {
		err = GetLastError();
		goto fail;
	}
	goto out;
fail:
	/* Only warn if setting timestamps failed. */
	WARNING("Can't set timestamps on \"%s\"", output_path);
	win32_error(err);
out:
	return 0;
}

/* Replacement for POSIX fsync() */
int
fsync(int fd)
{
	HANDLE h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE) {
		ERROR("Could not get Windows handle for file descriptor");
		win32_error(GetLastError());
		errno = EBADF;
		return -1;
	}
	if (!FlushFileBuffers(h)) {
		ERROR("Could not flush file buffers to disk");
		win32_error(GetLastError());
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
mbchar *
realpath(const mbchar *path, mbchar *resolved_path)
{
	DWORD ret;
	wimlib_assert(resolved_path == NULL);

	ret = GetFullPathNameA(path, 0, NULL, NULL);
	if (!ret)
		goto fail_win32;

	resolved_path = MALLOC(ret);
	if (!resolved_path)
		goto fail;
	ret = GetFullPathNameA(path, ret, resolved_path, NULL);
	if (!ret) {
		free(resolved_path);
		goto fail_win32;
	}
	return resolved_path;
fail_win32:
	win32_error(GetLastError());
fail:
	return NULL;
}

char *
nl_langinfo(nl_item item)
{
	wimlib_assert(item == CODESET);
	static char buf[64];
	strcpy(buf, "Unknown");
	return buf;
}

/* rename() on Windows fails if the destination file exists.  Fix it. */
int
rename_replacement(const char *oldpath, const char *newpath)
{
	if (MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING)) {
		return 0;
	} else {
		/* As usual, the possible error values are not documented */
		DWORD err = GetLastError();
		ERROR("MoveFileExA(): Can't rename \"%s\" to \"%s\"",
		      oldpath, newpath);
		win32_error(err);
		errno = 0;
		return -1;
	}
}
