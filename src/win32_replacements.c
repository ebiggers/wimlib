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
#include <io.h>	/* for _get_osfhandle()  */

#include "wimlib/win32_common.h"

#include "wimlib/assert.h"
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

/* Use the Win32 API to get the number of processors.  */
unsigned
win32_get_number_of_processors(void)
{
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
}

/* Use the Win32 API to get the amount of available memory.  */
u64
win32_get_avail_memory(void)
{
	MEMORYSTATUSEX status = {
		.dwLength = sizeof(status),
	};
	GlobalMemoryStatusEx(&status);
	return status.ullTotalPhys;
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
		FREE(resolved_path);
		resolved_path = NULL;
		goto fail_win32;
	}
	goto out;
fail_win32:
	set_errno_from_win32_error(err);
out:
	return resolved_path;
}

/* A quick hack to get reasonable rename() semantics on Windows, in particular
 * deleting the destination file instead of failing with ERROR_FILE_EXISTS and
 * working around any processes that may have the destination file open.
 *
 * Note: This is intended to be called when overwriting a regular file with an
 * updated copy and is *not* a fully POSIX compliant rename().  For that you may
 * wish to take a look at Cygwin's implementation, but be prepared...
 *
 * Return 0 on success, -1 on regular error, or 1 if the destination file was
 * deleted but the source could not be renamed and therefore should not be
 * deleted.
 */
int
win32_rename_replacement(const wchar_t *srcpath, const wchar_t *dstpath)
{
	wchar_t *tmpname;

	/* Normally, MoveFileExW() with the MOVEFILE_REPLACE_EXISTING flag does
	 * what we want.  */

	if (MoveFileExW(srcpath, dstpath, MOVEFILE_REPLACE_EXISTING))
		return 0;

	/* MoveFileExW() failed.  One way this can happen is if any process has
	 * the destination file open, in which case ERROR_ACCESS_DENIED is
	 * produced.  This can commonly happen if there is a backup or antivirus
	 * program monitoring or scanning the files.  This behavior is very
	 * different from the behavior of POSIX rename(), which simply unlinks
	 * the destination file and allows other processes to keep it open!  */

	if (GetLastError() != ERROR_ACCESS_DENIED)
		goto err_set_errno;

	/* We can work around the above-mentioned problem by renaming the
	 * destination file to yet another temporary file, then "deleting" it,
	 * which on Windows will in fact not actually delete it immediately but
	 * rather mark it for deletion when the last handle to it is closed.  */
	{
		static const wchar_t orig_suffix[5] = L".orig";
		const size_t num_rand_chars = 9;
		wchar_t *p;

		size_t dstlen = wcslen(dstpath);

		tmpname = alloca(sizeof(wchar_t) *
				 (dstlen + ARRAY_LEN(orig_suffix) + num_rand_chars + 1));
		p = tmpname;
		p = wmempcpy(p, dstpath, dstlen);
		p = wmempcpy(p, orig_suffix, ARRAY_LEN(orig_suffix));
		randomize_char_array_with_alnum(p, num_rand_chars);
		p += num_rand_chars;
		*p = L'\0';
	}

	if (!MoveFile(dstpath, tmpname))
		goto err_set_errno;

	if (!DeleteFile(tmpname)) {
		set_errno_from_GetLastError();
		WARNING_WITH_ERRNO("Failed to delete original file "
				   "(moved to \"%ls\")", tmpname);
	}

	if (!MoveFile(srcpath, dstpath)) {
		set_errno_from_GetLastError();
		WARNING_WITH_ERRNO("Atomic semantics not respected in "
				   "failed rename() (new file is at \"%ls\")",
				   srcpath);
		return 1;
	}

	return 0;

err_set_errno:
	set_errno_from_GetLastError();
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
	int errno_save;

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
			set_errno_from_win32_error(err);
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
	if (err != ERROR_NO_MORE_FILES) {
		set_errno_from_win32_error(err);
		ret = GLOB_ABORTED;
		goto fail_globfree;
	}
	return 0;

oom:
	CloseHandle(hFind);
	errno = ENOMEM;
	ret = GLOB_NOSPACE;
fail_globfree:
	errno_save = errno;
	globfree(pglob);
	errno = errno_save;
	return ret;
}

void
globfree(glob_t *pglob)
{
	size_t i;
	for (i = 0; i < pglob->gl_pathc; i++)
		FREE(pglob->gl_pathv[i]);
	FREE(pglob->gl_pathv);
}

#endif /* __WIN32__ */
