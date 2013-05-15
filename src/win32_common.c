/*
 * win32_common.c - Windows code common to applying and capturing images.
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

#include "wimlib/win32_common.h"

#include "wimlib/assert.h"
#include "wimlib/error.h"

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
set_errno_from_GetLastError(void)
{
	errno = win32_error_to_errno(GetLastError());
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
win32_global_init(void)
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
win32_global_cleanup(void)
{
	if (hKernel32 != NULL) {
		DEBUG("Closing Kernel32.dll");
		FreeLibrary(hKernel32);
		hKernel32 = NULL;
	}
}

#endif /* __WIN32__ */
