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
#include <shlwapi.h> /* for PathMatchSpecW() */
#include <aclapi.h> /* for SetSecurityInfo() */
#ifdef ERROR /* windows.h defines this */
#  undef ERROR
#endif

#include "win32.h"
#include "dentry.h"
#include "lookup_table.h"
#include "security.h"
#include "endianness.h"
#include "buffer_io.h"
#include <pthread.h>

#include <errno.h>

#define MAX_GET_SD_ACCESS_DENIED_WARNINGS 1
#define MAX_GET_SACL_PRIV_NOTHELD_WARNINGS 1
#define MAX_CREATE_HARD_LINK_WARNINGS 5
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
 * Note that this is only executed when WIMLIB_ADD_IMAGE_FLAG_RPFIX has been
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
			u64 capture_root_ino, u64 capture_root_dev)
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
	if (params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_RPFIX &&
	    (reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
	     reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT))
	{
		/* Try doing reparse point fixup */
		ret = win32_capture_try_rpfix(rpbuf,
					      &rpbuflen,
					      params->capture_root_ino,
					      params->capture_root_dev);
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
		if (params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) {
			ERROR("Cannot exclude the root directory from capture");
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
			goto out;
		}
		if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE)
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

	if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
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

	params->add_image_flags &= ~(WIMLIB_ADD_IMAGE_FLAG_ROOT | WIMLIB_ADD_IMAGE_FLAG_SOURCE);

	if (!(params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NO_ACLS)
	    && (vol_flags & FILE_PERSISTENT_ACLS))
	{
		ret = win32_get_security_descriptor(root, params->sd_set,
						    path, state,
						    params->add_image_flags);
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
			struct add_image_params *params)
{
	size_t path_nchars;
	wchar_t *path;
	int ret;
	struct win32_capture_state state;
	unsigned vol_flags;


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
		win32_do_capture_warnings(&state, params->add_image_flags);
	return ret;
}

static int
win32_extract_try_rpfix(u8 *rpbuf,
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

	ret = parse_reparse_data(rpbuf, 8 + le16_to_cpu(*(u16*)(rpbuf + 4)),
				 &rpdata);
	if (ret)
		return ret;

	if (extract_root_realpath[0] == L'\0' ||
	    extract_root_realpath[1] != L':' ||
	    extract_root_realpath[2] != L'\\')
	{
		ERROR("Can't understand full path format \"%ls\".  "
		      "Try turning reparse point fixups off...",
		      extract_root_realpath);
		return WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED;
	}

	ret = parse_substitute_name(rpdata.substitute_name,
				    rpdata.substitute_name_nbytes,
				    rpdata.rptag);
	if (ret < 0)
		return 0;
	stripped_nchars = ret;
	target = rpdata.substitute_name;
	target_nchars = rpdata.substitute_name_nbytes / sizeof(utf16lechar);
	stripped_target = target + 6;
	stripped_target_nchars = target_nchars - stripped_nchars;

	new_target = alloca((6 + extract_root_realpath_nchars +
			     stripped_target_nchars) * sizeof(utf16lechar));

	p = new_target;
	if (stripped_nchars == 6) {
		/* Include \??\ prefix if it was present before */
		wmemcpy(p, L"\\??\\", 4);
		p += 4;
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
	wmemcpy(p, extract_root_realpath + 2, extract_root_realpath_nchars - 2);
	p += extract_root_realpath_nchars - 2;

	/* Append the stripped target */
	wmemcpy(p, stripped_target, stripped_target_nchars);
	p += stripped_target_nchars;
	new_target_nchars = p - new_target;
	new_print_name_nchars = p - new_print_name;

	if (new_target_nchars * sizeof(utf16lechar) >= REPARSE_POINT_MAX_SIZE ||
	    new_print_name_nchars * sizeof(utf16lechar) >= REPARSE_POINT_MAX_SIZE)
	{
		ERROR("Path names too long to do reparse point fixup!");
		return WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED;
	}
	rpdata.substitute_name = new_target;
	rpdata.substitute_name_nbytes = new_target_nchars * sizeof(utf16lechar);
	rpdata.print_name = new_print_name;
	rpdata.print_name_nbytes = new_print_name_nchars * sizeof(utf16lechar);
	return make_reparse_buffer(&rpdata, rpbuf);
}

/* Wrapper around the FSCTL_SET_REPARSE_POINT ioctl to set the reparse data on
 * an extracted reparse point. */
static int
win32_set_reparse_data(HANDLE h,
		       const struct wim_inode *inode,
		       const struct wim_lookup_table_entry *lte,
		       const wchar_t *path,
		       const struct apply_args *args)
{
	int ret;
	u8 rpbuf[REPARSE_POINT_MAX_SIZE];
	DWORD bytesReturned;

	DEBUG("Setting reparse data on \"%ls\"", path);

	ret = wim_inode_get_reparse_data(inode, rpbuf);
	if (ret)
		return ret;

	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX &&
	    (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
	     inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT) &&
	    !inode->i_not_rpfixed)
	{
		ret = win32_extract_try_rpfix(rpbuf,
					      args->target_realpath,
					      args->target_realpath_len);
		if (ret)
			return WIMLIB_ERR_REPARSE_POINT_FIXUP_FAILED;
	}

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
	if (!DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, rpbuf,
			     8 + le16_to_cpu(*(u16*)(rpbuf + 4)),
			     NULL, 0,
			     &bytesReturned /* lpBytesReturned */,
			     NULL /* lpOverlapped */))
	{
		DWORD err = GetLastError();
		ERROR("Failed to set reparse data on \"%ls\"", path);
		win32_error(err);
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD)
			return WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT;
		else if (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
			 inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT)
			return WIMLIB_ERR_LINK;
		else
			return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/* Wrapper around the FSCTL_SET_COMPRESSION ioctl to change the
 * FILE_ATTRIBUTE_COMPRESSED flag of a file or directory. */
static int
win32_set_compression_state(HANDLE hFile, USHORT format, const wchar_t *path)
{
	DWORD bytesReturned;
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
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD)
			return WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT;
		else
			return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/* Wrapper around FSCTL_SET_SPARSE ioctl to set a file as sparse. */
static int
win32_set_sparse(HANDLE hFile, const wchar_t *path)
{
	DWORD bytesReturned;
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
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD)
			return WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT;
		else
			return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/*
 * Sets the security descriptor on an extracted file.
 */
static int
win32_set_security_data(const struct wim_inode *inode,
			HANDLE hFile,
			const wchar_t *path,
			struct apply_args *args)
{
	PSECURITY_DESCRIPTOR descriptor;
	unsigned long n;
	DWORD err;
	const struct wim_security_data *sd;

	SECURITY_INFORMATION securityInformation = 0;

	void *owner = NULL;
	void *group = NULL;
	ACL *dacl = NULL;
	ACL *sacl = NULL;

	BOOL owner_defaulted;
	BOOL group_defaulted;
	BOOL dacl_present;
	BOOL dacl_defaulted;
	BOOL sacl_present;
	BOOL sacl_defaulted;

	sd = wim_const_security_data(args->w);
	descriptor = sd->descriptors[inode->i_security_id];

	GetSecurityDescriptorOwner(descriptor, &owner, &owner_defaulted);
	if (owner)
		securityInformation |= OWNER_SECURITY_INFORMATION;

	GetSecurityDescriptorGroup(descriptor, &group, &group_defaulted);
	if (group)
		securityInformation |= GROUP_SECURITY_INFORMATION;

	GetSecurityDescriptorDacl(descriptor, &dacl_present,
				  &dacl, &dacl_defaulted);
	if (dacl)
		securityInformation |= DACL_SECURITY_INFORMATION;

	GetSecurityDescriptorSacl(descriptor, &sacl_present,
				  &sacl, &sacl_defaulted);
	if (sacl)
		securityInformation |= SACL_SECURITY_INFORMATION;

again:
	if (securityInformation == 0)
		return 0;
	if (SetSecurityInfo(hFile, SE_FILE_OBJECT,
			    securityInformation, owner, group, dacl, sacl))
		return 0;
	err = GetLastError();
	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS)
		goto fail;
	switch (err) {
	case ERROR_PRIVILEGE_NOT_HELD:
		if (securityInformation & SACL_SECURITY_INFORMATION) {
			n = args->num_set_sacl_priv_notheld++;
			securityInformation &= ~SACL_SECURITY_INFORMATION;
			sacl = NULL;
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
		if (err == ERROR_ACCESS_DENIED || err == ERROR_PRIVILEGE_NOT_HELD)
			return WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT;
		else
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
do_win32_extract_stream(HANDLE hStream, const struct wim_lookup_table_entry *lte)
{
	return extract_wim_resource(lte, wim_resource_size(lte),
				    win32_extract_chunk, hStream);
}

struct win32_encrypted_extract_ctx {
	const struct wim_lookup_table_entry *lte;
	u64 offset;
};

static DWORD WINAPI
win32_encrypted_import_cb(unsigned char *data, void *_ctx,
			  unsigned long *len_p)
{
	struct win32_encrypted_extract_ctx *ctx = _ctx;
	unsigned long len = *len_p;
	const struct wim_lookup_table_entry *lte = ctx->lte;

	len = min(len, wim_resource_size(lte) - ctx->offset);

	if (read_partial_wim_resource_into_buf(lte, len, ctx->offset, data, false))
		return ERROR_READ_FAULT;

	ctx->offset += len;
	*len_p = len;
	return ERROR_SUCCESS;
}

/* Create an encrypted file and extract the raw encrypted data to it.
 *
 * @path:  Path to encrypted file to create.
 * @lte:   WIM lookup_table entry for the raw encrypted data.
 *
 * This is separate from do_win32_extract_stream() because the WIM is supposed
 * to contain the *raw* encrypted data, which needs to be extracted ("imported")
 * using the special APIs OpenEncryptedFileRawW(), WriteEncryptedFileRaw(), and
 * CloseEncryptedFileRaw().
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
do_win32_extract_encrypted_stream(const wchar_t *path,
				  const struct wim_lookup_table_entry *lte)
{
	void *file_ctx;
	int ret;

	DEBUG("Opening file \"%ls\" to extract raw encrypted data", path);

	ret = OpenEncryptedFileRawW(path, CREATE_FOR_IMPORT, &file_ctx);
	if (ret) {
		ERROR("Failed to open \"%ls\" to write raw encrypted data", path);
		win32_error(ret);
		return WIMLIB_ERR_OPEN;
	}

	if (lte) {
		struct win32_encrypted_extract_ctx ctx;

		ctx.lte = lte;
		ctx.offset = 0;
		ret = WriteEncryptedFileRaw(win32_encrypted_import_cb, &ctx, file_ctx);
		if (ret == ERROR_SUCCESS) {
			ret = 0;
		} else {
			ret = WIMLIB_ERR_WRITE;
			ERROR("Failed to extract encrypted file \"%ls\"", path);
		}
	}
	CloseEncryptedFileRaw(file_ctx);
	return ret;
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

static inline DWORD
win32_mask_attributes(DWORD i_attributes)
{
	return i_attributes & ~(FILE_ATTRIBUTE_SPARSE_FILE |
				FILE_ATTRIBUTE_COMPRESSED |
				FILE_ATTRIBUTE_REPARSE_POINT |
				FILE_ATTRIBUTE_DIRECTORY |
				FILE_ATTRIBUTE_ENCRYPTED |
				FILE_FLAG_DELETE_ON_CLOSE |
				FILE_FLAG_NO_BUFFERING |
				FILE_FLAG_OPEN_NO_RECALL |
				FILE_FLAG_OVERLAPPED |
				FILE_FLAG_RANDOM_ACCESS |
				/*FILE_FLAG_SESSION_AWARE |*/
				FILE_FLAG_SEQUENTIAL_SCAN |
				FILE_FLAG_WRITE_THROUGH);
}

static inline DWORD
win32_get_create_flags_and_attributes(DWORD i_attributes)
{
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
	return win32_mask_attributes(i_attributes) |
		FILE_FLAG_OPEN_REPARSE_POINT |
		FILE_FLAG_BACKUP_SEMANTICS;
}

/* Set compression and/or sparse attributes on a stream, if supported by the
 * volume. */
static int
win32_set_special_stream_attributes(HANDLE hFile, const struct wim_inode *inode,
				    struct wim_lookup_table_entry *unnamed_stream_lte,
				    const wchar_t *path, unsigned vol_flags)
{
	int ret;

	if (inode->i_attributes & FILE_ATTRIBUTE_COMPRESSED) {
		if (vol_flags & FILE_FILE_COMPRESSION) {
			ret = win32_set_compression_state(hFile,
							  COMPRESSION_FORMAT_DEFAULT,
							  path);
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
	return 0;
}

/* Pre-create directories; extract encrypted streams */
static int
win32_begin_extract_unnamed_stream(const struct wim_inode *inode,
				   const struct wim_lookup_table_entry *lte,
				   const wchar_t *path,
				   DWORD *creationDisposition_ret,
				   unsigned int vol_flags)
{
	DWORD err;
	int ret;

	/* Directories must be created with CreateDirectoryW().  Then the call
	 * to CreateFileW() will merely open the directory that was already
	 * created rather than creating a new file. */
	if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY &&
	    !path_is_root_of_drive(path)) {
		if (!CreateDirectoryW(path, NULL)) {
			err = GetLastError();
			if (err != ERROR_ALREADY_EXISTS) {
				ERROR("Failed to create directory \"%ls\"",
				      path);
				win32_error(err);
				return WIMLIB_ERR_MKDIR;
			}
		}
		DEBUG("Created directory \"%ls\"", path);
		*creationDisposition_ret = OPEN_EXISTING;
	}
	if (inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED &&
	    vol_flags & FILE_SUPPORTS_ENCRYPTION)
	{
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY) {
			unsigned remaining_sharing_violations = 100;
			while (!EncryptFile(path)) {
				if (remaining_sharing_violations &&
				    err == ERROR_SHARING_VIOLATION)
				{
					WARNING("Couldn't encrypt directory \"%ls\" "
						"due to sharing violation; re-trying "
						"after 100 ms", path);
					Sleep(100);
					remaining_sharing_violations--;
				} else {
					err = GetLastError();
					ERROR("Failed to encrypt directory \"%ls\"",
					      path);
					win32_error(err);
					return WIMLIB_ERR_WRITE;
				}
			}
		} else {
			ret = do_win32_extract_encrypted_stream(path, lte);
			if (ret)
				return ret;
			DEBUG("Extracted encrypted file \"%ls\"", path);
		}
		*creationDisposition_ret = OPEN_EXISTING;
	}

	/* Set file attributes if we created the file.  Otherwise, we haven't
	 * created the file set and we will set the attributes in the call to
	 * CreateFileW().
	 *
	 * The FAT filesystem does not let you change the attributes of the root
	 * directory, so treat that as a special case and do not set attributes.
	 * */
	if (*creationDisposition_ret == OPEN_EXISTING &&
	    !path_is_root_of_drive(path))
	{
		if (!SetFileAttributesW(path,
					win32_mask_attributes(inode->i_attributes)))
		{
			err = GetLastError();
			ERROR("Failed to set attributes on \"%ls\"", path);
			win32_error(err);
			return WIMLIB_ERR_WRITE;
		}
	}
	return 0;
}

/* Set security descriptor and extract stream data or reparse data (skip the
 * unnamed data stream of encrypted files, which was already extracted). */
static int
win32_finish_extract_stream(HANDLE h, const struct wim_inode *inode,
			    const struct wim_lookup_table_entry *lte,
			    const wchar_t *stream_path,
			    const wchar_t *stream_name_utf16,
			    struct apply_args *args)
{
	int ret = 0;
	if (stream_name_utf16 == NULL) {
		/* Unnamed stream. */

		/* Set security descriptor, unless the extract_flags indicate
		 * not to or the volume does not supported it.  Note that this
		 * is only done when the unnamed stream is being extracted, as
		 * security descriptors are per-file and not per-stream. */
		if (inode->i_security_id >= 0 &&
		    !(args->extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS)
		    && (args->vol_flags & FILE_PERSISTENT_ACLS))
		{
			ret = win32_set_security_data(inode, h, stream_path, args);
			if (ret)
				return ret;
		}

		/* Handle reparse points.  The data for them needs to be set
		 * using a special ioctl.  Note that the reparse point may have
		 * been created using CreateFileW() in the case of
		 * non-directories or CreateDirectoryW() in the case of
		 * directories; but the ioctl works either way.  Also, it is
		 * only this step that actually sets the
		 * FILE_ATTRIBUTE_REPARSE_POINT, as it is not valid to set it
		 * using SetFileAttributesW() or CreateFileW().
		 *
		 * If the volume does not support reparse points we simply
		 * ignore the reparse data.  (N.B. the code currently doesn't
		 * actually reach this case because reparse points are skipped
		 * entirely on such volumes.) */
		if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
			if (args->vol_flags & FILE_SUPPORTS_REPARSE_POINTS) {
				ret = win32_set_reparse_data(h, inode,
							     lte, stream_path,
							     args);
				if (ret)
					return ret;
			} else {
				DEBUG("Cannot set reparse data on \"%ls\": volume "
				      "does not support reparse points", stream_path);
			}
		} else if (lte != NULL &&
			   !(args->vol_flags & FILE_SUPPORTS_ENCRYPTION &&
			     inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED))
		{
			/* Extract the data of the unnamed stream, unless the
			 * lookup table entry is NULL (indicating an empty
			 * stream for which no data needs to be extracted), or
			 * the stream is encrypted and therefore was already
			 * extracted as a special case. */
			ret = do_win32_extract_stream(h, lte);
		}
	} else {
		/* Extract the data for a named data stream. */
		if (lte != NULL) {
			DEBUG("Extracting named data stream \"%ls\" (len = %"PRIu64")",
			      stream_path, wim_resource_size(lte));
			ret = do_win32_extract_stream(h, lte);
		}
	}
	return ret;
}

static int
win32_decrypt_file(HANDLE open_handle, const wchar_t *path)
{
	DWORD err;
	/* We cannot call DecryptFileW() while there is an open handle to the
	 * file.  So close it first. */
	if (!CloseHandle(open_handle)) {
		err = GetLastError();
		ERROR("Failed to close handle for \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	if (!DecryptFileW(path, 0 /* reserved parameter; set to 0 */)) {
		err = GetLastError();
		ERROR("Failed to decrypt file \"%ls\"", path);
		win32_error(err);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/*
 * Create and extract a stream to a file, or create a directory, using the
 * Windows API.
 *
 * This handles reparse points, directories, alternate data streams, encrypted
 * files, compressed files, etc.
 *
 * @inode: WIM inode containing the stream.
 *
 * @path:  Path to extract the file to.
 *
 * @stream_name_utf16:
 * 	   Name of the stream, or NULL if the stream is unnamed.  This will
 * 	   be called with a NULL stream_name_utf16 before any non-NULL
 * 	   stream_name_utf16's.
 *
 * @lte:   WIM lookup table entry for the stream.  May be NULL to indicate
 *         a stream of length 0.
 *
 * @args:  Additional apply context, including flags indicating supported
 *         volume features.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_extract_stream(const struct wim_inode *inode,
		     const wchar_t *path,
		     const wchar_t *stream_name_utf16,
		     struct wim_lookup_table_entry *lte,
		     struct apply_args *args)
{
	wchar_t *stream_path;
	HANDLE h;
	int ret;
	DWORD err;
	DWORD creationDisposition = CREATE_ALWAYS;
	DWORD requestedAccess;
	BY_HANDLE_FILE_INFORMATION file_info;
	unsigned remaining_sharing_violations = 1000;

	if (stream_name_utf16) {
		/* Named stream.  Create a buffer that contains the UTF-16LE
		 * string [./]path:stream_name_utf16.  This is needed to
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

		ret = win32_begin_extract_unnamed_stream(inode, lte, path,
							 &creationDisposition,
							 args->vol_flags);
		if (ret)
			goto fail;
	}

	DEBUG("Opening \"%ls\"", stream_path);
	requestedAccess = GENERIC_READ | GENERIC_WRITE |
			  ACCESS_SYSTEM_SECURITY;
try_open_again:
	/* Open the stream to be extracted.  Depending on what we have set
	 * creationDisposition to, we may be creating this for the first time,
	 * or we may be opening on existing stream we already created using
	 * CreateDirectoryW() or OpenEncryptedFileRawW(). */
	h = CreateFileW(stream_path,
			requestedAccess,
			FILE_SHARE_READ,
			NULL,
			creationDisposition,
			win32_get_create_flags_and_attributes(inode->i_attributes),
			NULL);
	if (h == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_ACCESS_DENIED &&
		    path_is_root_of_drive(stream_path))
		{
			ret = 0;
			goto out;
		}
		if ((err == ERROR_PRIVILEGE_NOT_HELD ||
		     err == ERROR_ACCESS_DENIED) &&
		    (requestedAccess & ACCESS_SYSTEM_SECURITY))
		{
			/* Try opening the file again without privilege to
			 * modify SACL. */
			requestedAccess &= ~ACCESS_SYSTEM_SECURITY;
			goto try_open_again;
		}
		if (err == ERROR_SHARING_VIOLATION) {
			if (remaining_sharing_violations) {
				--remaining_sharing_violations;
				/* This can happen when restoring encrypted directories
				 * for some reason.  Probably a bug in EncryptFile(). */
				WARNING("Couldn't open \"%ls\" due to sharing violation; "
					"re-trying after 100ms", stream_path);
				Sleep(100);
				goto try_open_again;
			} else {
				ERROR("Too many sharing violations; giving up...");
			}
		} else {
			if (creationDisposition == OPEN_EXISTING)
				ERROR("Failed to open \"%ls\"", stream_path);
			else
				ERROR("Failed to create \"%ls\"", stream_path);
			win32_error(err);
		}
		ret = WIMLIB_ERR_OPEN;
		goto fail;
	}

	/* Check the attributes of the file we just opened, and remove
	 * encryption or compression if either was set by default but is not
	 * supposed to be set based on the WIM inode attributes. */
	if (!GetFileInformationByHandle(h, &file_info)) {
		err = GetLastError();
		ERROR("Failed to get attributes of \"%ls\"", stream_path);
		win32_error(err);
		ret = WIMLIB_ERR_STAT;
		goto fail_close_handle;
	}

	/* Remove encryption? */
	if (file_info.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED &&
	    !(inode->i_attributes & FILE_ATTRIBUTE_ENCRYPTED))
	{
		/* File defaulted to encrypted due to being in an encrypted
		 * directory, but is not actually supposed to be encrypted.
		 *
		 * This is a workaround, because I'm not aware of any way to
		 * directly (e.g. with CreateFileW()) create an unencrypted file
		 * in a directory with FILE_ATTRIBUTE_ENCRYPTED set. */
		ret = win32_decrypt_file(h, stream_path);
		if (ret)
			goto fail; /* win32_decrypt_file() closed the handle. */
		creationDisposition = OPEN_EXISTING;
		goto try_open_again;
	}

	/* Remove compression? */
	if (file_info.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED &&
	    !(inode->i_attributes & FILE_ATTRIBUTE_COMPRESSED))
	{
		/* Similar to the encrypted case, above, if the file defaulted
		 * to compressed due to being in an compressed directory, but is
		 * not actually supposed to be compressed, explicitly set the
		 * compression format to COMPRESSION_FORMAT_NONE. */
		ret = win32_set_compression_state(h, COMPRESSION_FORMAT_NONE,
						  stream_path);
		if (ret)
			goto fail_close_handle;
	}

	/* Set compression and/or sparse attributes if needed */
	ret = win32_set_special_stream_attributes(h, inode, lte, path,
						  args->vol_flags);

	if (ret)
		goto fail_close_handle;

	/* At this point we have at least created the needed stream with the
	 * appropriate attributes.  We have yet to set the appropriate security
	 * descriptor and actually extract the stream data (other than for
	 * extracted files, which were already extracted).
	 * win32_finish_extract_stream() handles these additional steps. */
	ret = win32_finish_extract_stream(h, inode, lte, stream_path,
					  stream_name_utf16, args);
	if (ret)
		goto fail_close_handle;

	/* Done extracting the stream.  Close the handle and return. */
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
	ERROR("Error extracting \"%ls\"", stream_path);
out:
	return ret;
}

/*
 * Creates a file, directory, or reparse point and extracts all streams to it
 * (unnamed data stream and/or reparse point stream, plus any alternate data
 * streams).  Handles sparse, compressed, and/or encrypted files.
 *
 * @inode:	WIM inode for this file or directory.
 * @path:	UTF-16LE external path to extract the inode to.
 * @args:	Additional extraction context.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
win32_extract_streams(const struct wim_inode *inode,
		      const wchar_t *path, struct apply_args *args)
{
	struct wim_lookup_table_entry *unnamed_lte;
	int ret;

	/* First extract the unnamed stream. */

	unnamed_lte = inode_unnamed_lte_resolved(inode);
	ret = win32_extract_stream(inode, path, NULL, unnamed_lte, args);
	if (ret)
		goto out;

	/* Extract any named streams, if supported by the volume. */

	if (!(args->vol_flags & FILE_NAMED_STREAMS))
		goto out;
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		const struct wim_ads_entry *ads_entry = &inode->i_ads_entries[i];

		/* Skip the unnamed stream if it's in the ADS entries (we
		 * already extracted it...) */
		if (ads_entry->stream_name_nbytes == 0)
			continue;

		/* Skip special UNIX data entries (see documentation for
		 * WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) */
		if (ads_entry->stream_name_nbytes == WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES
		    && !memcmp(ads_entry->stream_name,
			       WIMLIB_UNIX_DATA_TAG_UTF16LE,
			       WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES))
			continue;

		/* Extract the named stream */
		ret = win32_extract_stream(inode,
					   path,
					   ads_entry->stream_name,
					   ads_entry->lte,
					   args);
		if (ret)
			break;
	}
out:
	return ret;
}

/* If not done already, load the supported feature flags for the volume onto
 * which the image is being extracted, and warn the user about any missing
 * features that could be important. */
static int
win32_check_vol_flags(const wchar_t *output_path, struct apply_args *args)
{
	if (args->have_vol_flags)
		return 0;

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
	return 0;
}

/*
 * Try extracting a hard link.
 *
 * @output_path:  Path to link to be extracted.
 *
 * @inode:        WIM inode that the link is to; inode->i_extracted_file
 *		  the path to a name of the file that has already been
 *		  extracted (we use this to create the hard link).
 *
 * @args:         Additional apply context, used here to keep track of
 *                the number of times creating a hard link failed due to
 *                ERROR_INVALID_FUNCTION.  This error should indicate that hard
 *                links are not supported by the volume, and we would like to
 *                warn the user a few times, but not too many times.
 *
 * Returns 0 if the hard link was successfully extracted.  Returns
 * WIMLIB_ERR_LINK (> 0) if an error occurred, other than hard links possibly
 * being unsupported by the volume.  Returns a negative value if creating the
 * hard link failed due to ERROR_INVALID_FUNCTION.
 */
static int
win32_try_hard_link(const wchar_t *output_path, const struct wim_inode *inode,
		    struct apply_args *args)
{
	DWORD err;

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
		args->num_hard_links_failed++;
		if (args->num_hard_links_failed < MAX_CREATE_HARD_LINK_WARNINGS) {
			WARNING("Can't create hard link \"%ls => %ls\":\n"
				"          Volume does not support hard links!\n"
				"          Falling back to extracting a copy of the file.",
				output_path, inode->i_extracted_file);
		} else if (args->num_hard_links_failed == MAX_CREATE_HARD_LINK_WARNINGS) {
			WARNING("Suppressing further hard linking warnings...");
		}
		return -1;
	}
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

	ret = win32_check_vol_flags(output_path, args);
	if (ret)
		return ret;
	if (inode->i_nlink > 1 && inode->i_extracted_file != NULL) {
		/* Linked file, with another name already extracted.  Create a
		 * hard link. */
		ret = win32_try_hard_link(output_path, inode, args);
		if (ret >= 0)
			return ret;
		/* Negative return value from win32_try_hard_link() indicates
		 * that hard links are probably not supported by the volume.
		 * Fall back to extracting a copy of the file. */
	}

	/* If this is a reparse point and the volume does not support reparse
	 * points, just skip it completely. */
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT &&
	    !(args->vol_flags & FILE_SUPPORTS_REPARSE_POINTS))
	{
		WARNING("Skipping extraction of reparse point \"%ls\":\n"
			"          Not supported by destination filesystem",
			output_path);
	} else {
		/* Create the file, directory, or reparse point, and extract the
		 * data streams. */
		ret = win32_extract_streams(inode, output_path, args);
		if (ret)
			return ret;
	}
	if (inode->i_extracted_file == NULL) {
		const struct wim_lookup_table_entry *lte;

		/* Tally bytes extracted, including all alternate data streams,
		 * unless we extracted a hard link (or, at least extracted a
		 * name that was supposed to be a hard link) */
		for (unsigned i = 0; i <= inode->i_num_ads; i++) {
			lte = inode_stream_lte_resolved(inode, i);
			if (lte)
				args->progress.extract.completed_bytes +=
							wim_resource_size(lte);
		}
		if (inode->i_nlink > 1) {
			/* Save extracted path for a later call to
			 * CreateHardLinkW() if this inode has multiple links.
			 * */
			inode->i_extracted_file = WSTRDUP(output_path);
			if (!inode->i_extracted_file)
				return WIMLIB_ERR_NOMEM;
		}
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

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT &&
	    !(args->vol_flags & FILE_SUPPORTS_REPARSE_POINTS))
	{
		/* Skip reparse points not extracted */
		return 0;
	}

	/* Windows doesn't let you change the timestamps of the root directory
	 * (at least on FAT, which is dumb but expected since FAT doesn't store
	 * any metadata about the root directory...) */
	if (path_is_root_of_drive(path))
		return 0;

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
