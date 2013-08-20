/*
 * win32_replacements.c - Replacements for various functions not available on
 * Windows, such as fsync().
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

#include <errno.h>
#include <pthread.h>
#include <shlwapi.h> /* for PathMatchSpecW() */
#include "wimlib/win32_common.h"

#include "wimlib/assert.h"
#include "wimlib/file_io.h"
#include "wimlib/glob.h"
#include "wimlib/error.h"
#include "wimlib/util.h"

/* Replacement for POSIX fsync() */
int
fsync(int fd)
{
	HANDLE h;

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE)
		goto err;
	if (!FlushFileBuffers(h))
		goto err_set_errno;
	return 0;
err_set_errno:
	set_errno_from_GetLastError();
err:
	return -1;
}

/* Use the Win32 API to get the number of processors */
unsigned
win32_get_number_of_processors(void)
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
	DWORD err;
	wimlib_assert(resolved_path == NULL);

	ret = GetFullPathNameW(path, 0, NULL, NULL);
	if (!ret) {
		err = GetLastError();
		goto fail_win32;
	}

	resolved_path = MALLOC(ret * sizeof(wchar_t));
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
	set_errno_from_win32_error(err);
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
		set_errno_from_GetLastError();
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
	set_errno_from_win32_error(err);
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

static int
do_pread_or_pwrite(int fd, void *buf, size_t count, off_t offset,
		   bool is_pwrite)
{
	HANDLE h;
	LARGE_INTEGER orig_offset;
	DWORD bytes_read_or_written;
	LARGE_INTEGER relative_offset;
	OVERLAPPED overlapped;
	BOOL bret;

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE)
		goto err;

	if (GetFileType(h) == FILE_TYPE_PIPE) {
		errno = ESPIPE;
		goto err;
	}

	/* Get original position */
	relative_offset.QuadPart = 0;
	if (!SetFilePointerEx(h, relative_offset, &orig_offset, FILE_CURRENT))
		goto err_set_errno;

	memset(&overlapped, 0, sizeof(overlapped));
	overlapped.Offset = offset;
	overlapped.OffsetHigh = offset >> 32;

	/* Do the read or write at the specified offset */
	if (is_pwrite)
		bret = WriteFile(h, buf, count, &bytes_read_or_written, &overlapped);
	else
		bret = ReadFile(h, buf, count, &bytes_read_or_written, &overlapped);
	if (!bret)
		goto err_set_errno;

	/* Restore the original position */
	if (!SetFilePointerEx(h, orig_offset, NULL, FILE_BEGIN))
		goto err_set_errno;

	return bytes_read_or_written;
err_set_errno:
	set_errno_from_GetLastError();
err:
	return -1;
}

/* Dumb Windows implementation of pread().  It temporarily changes the file
 * offset, so it is not safe to use with readers/writers on the same file
 * descriptor.  */
ssize_t
pread(int fd, void *buf, size_t count, off_t offset)
{
	return do_pread_or_pwrite(fd, buf, count, offset, false);
}

/* Dumb Windows implementation of pwrite().  It temporarily changes the file
 * offset, so it is not safe to use with readers/writers on the same file
 * descriptor. */
ssize_t
pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	return do_pread_or_pwrite(fd, (void*)buf, count, offset, true);
}

/* Dumb Windows implementation of writev().  It writes the vectors one at a
 * time. */
ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
	ssize_t total_bytes_written = 0;

	if (iovcnt <= 0) {
		errno = EINVAL;
		return -1;
	}
	for (int i = 0; i < iovcnt; i++) {
		ssize_t bytes_written;

		bytes_written = write(fd, iov[i].iov_base, iov[i].iov_len);
		if (bytes_written >= 0)
			total_bytes_written += bytes_written;
		if (bytes_written != iov[i].iov_len) {
			if (total_bytes_written == 0)
				total_bytes_written = -1;
			break;
		}
	}
	return total_bytes_written;
}

int
win32_get_file_and_vol_ids(const wchar_t *path, u64 *ino_ret, u64 *dev_ret)
{
	HANDLE h;
	BY_HANDLE_FILE_INFORMATION file_info;
	int ret;
	DWORD err;

	h = win32_open_existing_file(path, FILE_READ_ATTRIBUTES);
	if (h == INVALID_HANDLE_VALUE) {
		ret = WIMLIB_ERR_OPEN;
		goto out;
	}

	if (!GetFileInformationByHandle(h, &file_info)) {
		ret = WIMLIB_ERR_STAT;
	} else {
		*ino_ret = ((u64)file_info.nFileIndexHigh << 32) |
			    (u64)file_info.nFileIndexLow;
		*dev_ret = file_info.dwVolumeSerialNumber;
		ret = 0;
	}
	err = GetLastError();
	CloseHandle(h);
	SetLastError(err);
out:
	set_errno_from_GetLastError();
	return ret;
}

/* Replacement for glob() in Windows native builds that operates on wide
 * characters.  */
int
win32_wglob(const wchar_t *pattern, int flags,
	    int (*errfunc)(const wchar_t *epath, int eerrno),
	    glob_t *pglob)
{
	WIN32_FIND_DATAW dat;
	DWORD err;
	HANDLE hFind;
	int ret;
	size_t nspaces;

	const wchar_t *backslash, *end_slash;
	size_t prefix_len;

	backslash = wcsrchr(pattern, L'\\');
	end_slash = wcsrchr(pattern, L'/');

	if (backslash > end_slash)
		end_slash = backslash;

	if (end_slash)
		prefix_len = end_slash - pattern + 1;
	else
		prefix_len = 0;

	/* This function does not support all functionality of the POSIX glob(),
	 * so make sure the parameters are consistent with supported
	 * functionality. */
	wimlib_assert(errfunc == NULL);
	wimlib_assert((flags & GLOB_ERR) == GLOB_ERR);
	wimlib_assert((flags & ~(GLOB_NOSORT | GLOB_ERR)) == 0);

	hFind = FindFirstFileW(pattern, &dat);
	if (hFind == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			errno = 0;
			return GLOB_NOMATCH;
		} else {
			/* The other possible error codes for FindFirstFile()
			 * are undocumented. */
			errno = EIO;
			return GLOB_ABORTED;
		}
	}
	pglob->gl_pathc = 0;
	pglob->gl_pathv = NULL;
	nspaces = 0;
	do {
		wchar_t *path;
		if (pglob->gl_pathc == nspaces) {
			size_t new_nspaces;
			wchar_t **pathv;

			new_nspaces = nspaces * 2 + 1;
			pathv = REALLOC(pglob->gl_pathv,
					new_nspaces * sizeof(pglob->gl_pathv[0]));
			if (!pathv)
				goto oom;
			pglob->gl_pathv = pathv;
			nspaces = new_nspaces;
		}
		size_t filename_len = wcslen(dat.cFileName);
		size_t len_needed = prefix_len + filename_len;

		path = MALLOC((len_needed + 1) * sizeof(wchar_t));
		if (!path)
			goto oom;

		wmemcpy(path, pattern, prefix_len);
		wmemcpy(path + prefix_len, dat.cFileName, filename_len + 1);
		pglob->gl_pathv[pglob->gl_pathc++] = path;
	} while (FindNextFileW(hFind, &dat));
	err = GetLastError();
	CloseHandle(hFind);
	if (err == ERROR_NO_MORE_FILES) {
		errno = 0;
		return 0;
	} else {
		/* Other possible error codes for FindNextFile() are
		 * undocumented */
		errno = EIO;
		ret = GLOB_ABORTED;
		goto fail_globfree;
	}
oom:
	CloseHandle(hFind);
	errno = ENOMEM;
	ret = GLOB_NOSPACE;
fail_globfree:
	globfree(pglob);
	return ret;
}

void
globfree(glob_t *pglob)
{
	size_t i;
	for (i = 0; i < pglob->gl_pathc; i++)
		free(pglob->gl_pathv[i]);
	free(pglob->gl_pathv);
}

#endif /* __WIN32__ */
