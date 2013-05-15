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

#include <pthread.h>
#include <shlwapi.h> /* for PathMatchSpecW() */
#include "wimlib/win32_common.h"

#include "wimlib/assert.h"
#include "wimlib/file_io.h"
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
	errno = win32_error_to_errno(err);
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
	errno = win32_error_to_errno(err);
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

	wimlib_assert(count <= 0xffffffff);

	h = (HANDLE)_get_osfhandle(fd);
	if (h == INVALID_HANDLE_VALUE)
		goto err;

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


#endif /* __WIN32__ */
