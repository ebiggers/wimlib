/*
 * win32_common.c - Windows code common to applying and capturing images, as
 * well as replacements for various functions not available on Windows, such as
 * fsync().
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

#include <shlwapi.h> /* for PathMatchSpecW() */
#include <errno.h>

#include "win32_common.h"

#ifdef ENABLE_ERROR_MESSAGES
void
win32_error(DWORD err_code)
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
#endif /* ENABLE_ERROR_MESSAGES */

int
win32_error_to_errno(DWORD err_code)
{
	/* This mapping is that used in Cygwin.
	 * Some of these choices are arbitrary. */
	switch (err_code) {
	case ERROR_ACCESS_DENIED:
		return EACCES;
	case ERROR_ACTIVE_CONNECTIONS:
		return EAGAIN;
	case ERROR_ALREADY_EXISTS:
		return EEXIST;
	case ERROR_BAD_DEVICE:
		return ENODEV;
	case ERROR_BAD_EXE_FORMAT:
		return ENOEXEC;
	case ERROR_BAD_NETPATH:
		return ENOENT;
	case ERROR_BAD_NET_NAME:
		return ENOENT;
	case ERROR_BAD_NET_RESP:
		return ENOSYS;
	case ERROR_BAD_PATHNAME:
		return ENOENT;
	case ERROR_BAD_PIPE:
		return EINVAL;
	case ERROR_BAD_UNIT:
		return ENODEV;
	case ERROR_BAD_USERNAME:
		return EINVAL;
	case ERROR_BEGINNING_OF_MEDIA:
		return EIO;
	case ERROR_BROKEN_PIPE:
		return EPIPE;
	case ERROR_BUSY:
		return EBUSY;
	case ERROR_BUS_RESET:
		return EIO;
	case ERROR_CALL_NOT_IMPLEMENTED:
		return ENOSYS;
	case ERROR_CANNOT_MAKE:
		return EPERM;
	case ERROR_CHILD_NOT_COMPLETE:
		return EBUSY;
	case ERROR_COMMITMENT_LIMIT:
		return EAGAIN;
	case ERROR_CRC:
		return EIO;
	case ERROR_DEVICE_DOOR_OPEN:
		return EIO;
	case ERROR_DEVICE_IN_USE:
		return EAGAIN;
	case ERROR_DEVICE_REQUIRES_CLEANING:
		return EIO;
	case ERROR_DIRECTORY:
		return ENOTDIR;
	case ERROR_DIR_NOT_EMPTY:
		return ENOTEMPTY;
	case ERROR_DISK_CORRUPT:
		return EIO;
	case ERROR_DISK_FULL:
		return ENOSPC;
#ifdef ENOTUNIQ
	case ERROR_DUP_NAME:
		return ENOTUNIQ;
#endif
	case ERROR_EAS_DIDNT_FIT:
		return ENOSPC;
#ifdef ENOTSUP
	case ERROR_EAS_NOT_SUPPORTED:
		return ENOTSUP;
#endif
	case ERROR_EA_LIST_INCONSISTENT:
		return EINVAL;
	case ERROR_EA_TABLE_FULL:
		return ENOSPC;
	case ERROR_END_OF_MEDIA:
		return ENOSPC;
	case ERROR_EOM_OVERFLOW:
		return EIO;
	case ERROR_EXE_MACHINE_TYPE_MISMATCH:
		return ENOEXEC;
	case ERROR_EXE_MARKED_INVALID:
		return ENOEXEC;
	case ERROR_FILEMARK_DETECTED:
		return EIO;
	case ERROR_FILENAME_EXCED_RANGE:
		return ENAMETOOLONG;
	case ERROR_FILE_CORRUPT:
		return EEXIST;
	case ERROR_FILE_EXISTS:
		return EEXIST;
	case ERROR_FILE_INVALID:
		return ENXIO;
	case ERROR_FILE_NOT_FOUND:
		return ENOENT;
	case ERROR_HANDLE_DISK_FULL:
		return ENOSPC;
#ifdef ENODATA
	case ERROR_HANDLE_EOF:
		return ENODATA;
#endif
	case ERROR_INVALID_ADDRESS:
		return EINVAL;
	case ERROR_INVALID_AT_INTERRUPT_TIME:
		return EINTR;
	case ERROR_INVALID_BLOCK_LENGTH:
		return EIO;
	case ERROR_INVALID_DATA:
		return EINVAL;
	case ERROR_INVALID_DRIVE:
		return ENODEV;
	case ERROR_INVALID_EA_NAME:
		return EINVAL;
	case ERROR_INVALID_EXE_SIGNATURE:
		return ENOEXEC;
#ifdef EBADRQC
	case ERROR_INVALID_FUNCTION:
		return EBADRQC;
#endif
	case ERROR_INVALID_HANDLE:
		return EBADF;
	case ERROR_INVALID_NAME:
		return ENOENT;
	case ERROR_INVALID_PARAMETER:
		return EINVAL;
	case ERROR_INVALID_SIGNAL_NUMBER:
		return EINVAL;
	case ERROR_IOPL_NOT_ENABLED:
		return ENOEXEC;
	case ERROR_IO_DEVICE:
		return EIO;
	case ERROR_IO_INCOMPLETE:
		return EAGAIN;
	case ERROR_IO_PENDING:
		return EAGAIN;
	case ERROR_LOCK_VIOLATION:
		return EBUSY;
	case ERROR_MAX_THRDS_REACHED:
		return EAGAIN;
	case ERROR_META_EXPANSION_TOO_LONG:
		return EINVAL;
	case ERROR_MOD_NOT_FOUND:
		return ENOENT;
#ifdef EMSGSIZE
	case ERROR_MORE_DATA:
		return EMSGSIZE;
#endif
	case ERROR_NEGATIVE_SEEK:
		return EINVAL;
	case ERROR_NETNAME_DELETED:
		return ENOENT;
	case ERROR_NOACCESS:
		return EFAULT;
	case ERROR_NONE_MAPPED:
		return EINVAL;
	case ERROR_NONPAGED_SYSTEM_RESOURCES:
		return EAGAIN;
#ifdef ENOLINK
	case ERROR_NOT_CONNECTED:
		return ENOLINK;
#endif
	case ERROR_NOT_ENOUGH_MEMORY:
		return ENOMEM;
	case ERROR_NOT_OWNER:
		return EPERM;
#ifdef ENOMEDIUM
	case ERROR_NOT_READY:
		return ENOMEDIUM;
#endif
	case ERROR_NOT_SAME_DEVICE:
		return EXDEV;
	case ERROR_NOT_SUPPORTED:
		return ENOSYS;
	case ERROR_NO_DATA:
		return EPIPE;
	case ERROR_NO_DATA_DETECTED:
		return EIO;
#ifdef ENOMEDIUM
	case ERROR_NO_MEDIA_IN_DRIVE:
		return ENOMEDIUM;
#endif
#ifdef ENMFILE
	case ERROR_NO_MORE_FILES:
		return ENMFILE;
#endif
#ifdef ENMFILE
	case ERROR_NO_MORE_ITEMS:
		return ENMFILE;
#endif
	case ERROR_NO_MORE_SEARCH_HANDLES:
		return ENFILE;
	case ERROR_NO_PROC_SLOTS:
		return EAGAIN;
	case ERROR_NO_SIGNAL_SENT:
		return EIO;
	case ERROR_NO_SYSTEM_RESOURCES:
		return EFBIG;
	case ERROR_NO_TOKEN:
		return EINVAL;
	case ERROR_OPEN_FAILED:
		return EIO;
	case ERROR_OPEN_FILES:
		return EAGAIN;
	case ERROR_OUTOFMEMORY:
		return ENOMEM;
	case ERROR_PAGED_SYSTEM_RESOURCES:
		return EAGAIN;
	case ERROR_PAGEFILE_QUOTA:
		return EAGAIN;
	case ERROR_PATH_NOT_FOUND:
		return ENOENT;
	case ERROR_PIPE_BUSY:
		return EBUSY;
	case ERROR_PIPE_CONNECTED:
		return EBUSY;
#ifdef ECOMM
	case ERROR_PIPE_LISTENING:
		return ECOMM;
	case ERROR_PIPE_NOT_CONNECTED:
		return ECOMM;
#endif
	case ERROR_POSSIBLE_DEADLOCK:
		return EDEADLOCK;
	case ERROR_PRIVILEGE_NOT_HELD:
		return EPERM;
	case ERROR_PROCESS_ABORTED:
		return EFAULT;
	case ERROR_PROC_NOT_FOUND:
		return ESRCH;
#ifdef ENONET
	case ERROR_REM_NOT_LIST:
		return ENONET;
#endif
	case ERROR_SECTOR_NOT_FOUND:
		return EINVAL;
	case ERROR_SEEK:
		return EINVAL;
	case ERROR_SETMARK_DETECTED:
		return EIO;
	case ERROR_SHARING_BUFFER_EXCEEDED:
		return ENOLCK;
	case ERROR_SHARING_VIOLATION:
		return EBUSY;
	case ERROR_SIGNAL_PENDING:
		return EBUSY;
	case ERROR_SIGNAL_REFUSED:
		return EIO;
#ifdef ELIBBAD
	case ERROR_SXS_CANT_GEN_ACTCTX:
		return ELIBBAD;
#endif
	case ERROR_THREAD_1_INACTIVE:
		return EINVAL;
	case ERROR_TOO_MANY_LINKS:
		return EMLINK;
	case ERROR_TOO_MANY_OPEN_FILES:
		return EMFILE;
	case ERROR_WAIT_NO_CHILDREN:
		return ECHILD;
	case ERROR_WORKING_SET_QUOTA:
		return EAGAIN;
	case ERROR_WRITE_PROTECT:
		return EROFS;
	default:
		return -1;
	}
}

void
set_errno_from_GetLastError()
{
	errno = win32_error_to_errno(GetLastError());
}

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
	DWORD err;
	wimlib_assert(resolved_path == NULL);

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
extern ssize_t
win32_pread(int fd, void *buf, size_t count, off_t offset)
{
	return do_pread_or_pwrite(fd, buf, count, offset, false);
}

/* Dumb Windows implementation of pwrite().  It temporarily changes the file
 * offset, so it is not safe to use with readers/writers on the same file
 * descriptor. */
extern ssize_t
win32_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	return do_pread_or_pwrite(fd, (void*)buf, count, offset, true);
}

/* Dumb Windows implementation of writev().  It writes the vectors one at a
 * time. */
extern ssize_t
win32_writev(int fd, const struct iovec *iov, int iovcnt)
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

/* Given a path, which may not yet exist, get a set of flags that describe the
 * features of the volume the path is on. */
int
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

HANDLE
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

/* Pointers to functions that are not available on all targetted versions of
 * Windows (XP and later).  NOTE: The WINAPI annotations seem to be important; I
 * assume it specifies a certain calling convention. */

/* Vista and later */
HANDLE (WINAPI *win32func_FindFirstStreamW)(LPCWSTR lpFileName,
					    STREAM_INFO_LEVELS InfoLevel,
					    LPVOID lpFindStreamData,
					    DWORD dwFlags) = NULL;

/* Vista and later */
BOOL (WINAPI *win32func_FindNextStreamW)(HANDLE hFindStream,
					 LPVOID lpFindStreamData) = NULL;

static OSVERSIONINFO windows_version_info = {
	.dwOSVersionInfoSize = sizeof(OSVERSIONINFO),
};

static HMODULE hKernel32 = NULL;

bool
windows_version_is_at_least(unsigned major, unsigned minor)
{
	return windows_version_info.dwMajorVersion > major ||
		(windows_version_info.dwMajorVersion == major &&
		 windows_version_info.dwMinorVersion >= minor);
}

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
		}
	}

	if (hKernel32) {
		win32func_FindFirstStreamW = (void*)GetProcAddress(hKernel32,
								   "FindFirstStreamW");
		if (win32func_FindFirstStreamW) {
			win32func_FindNextStreamW = (void*)GetProcAddress(hKernel32,
									  "FindNextStreamW");
			if (!win32func_FindNextStreamW)
				win32func_FindFirstStreamW = NULL;
		}
	}

	GetVersionEx(&windows_version_info);
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

#endif /* __WIN32__ */
