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

#ifdef WITH_NTDLL
#  include <winternl.h>
#endif

#include "wimlib/win32_common.h"
#include "wimlib/assert.h"
#include "wimlib/error.h"
#include "wimlib/util.h"

static int
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
set_errno_from_win32_error(DWORD err)
{
	errno = win32_error_to_errno(err);
}

void
set_errno_from_GetLastError(void)
{
	set_errno_from_win32_error(GetLastError());
}

#ifdef WITH_NTDLL
void
set_errno_from_nt_status(NTSTATUS status)
{
	set_errno_from_win32_error((*func_RtlNtStatusToDosError)(status));
}
#endif

/* Given a Windows-style path, return the number of characters of the prefix
 * that specify the path to the root directory of a drive, or return 0 if the
 * drive is relative (or at least on the current drive, in the case of
 * absolute-but-not-really-absolute paths like \Windows\System32) */
static size_t
win32_path_drive_spec_len(const wchar_t *path)
{
	size_t n = 0;

	if (!wcsncmp(path, L"\\\\?\\", 4)) {
		/* \\?\-prefixed path.  Check for following drive letter and
		 * path separator. */
		if (path[4] != L'\0' && path[5] == L':' &&
		    is_any_path_separator(path[6]))
			n = 7;
	} else {
		/* Not a \\?\-prefixed path.  Check for an initial drive letter
		 * and path separator. */
		if (path[0] != L'\0' && path[1] == L':' &&
		    is_any_path_separator(path[2]))
			n = 3;
	}
	/* Include any additional path separators.*/
	if (n > 0)
		while (is_any_path_separator(path[n]))
			n++;
	return n;
}

bool
win32_path_is_root_of_drive(const wchar_t *path)
{
	size_t drive_spec_len;
	wchar_t full_path[32768];
	DWORD ret;

	ret = GetFullPathName(path, ARRAY_LEN(full_path), full_path, NULL);
	if (ret > 0 && ret < ARRAY_LEN(full_path))
		path = full_path;

	/* Explicit drive letter and path separator? */
	drive_spec_len = win32_path_drive_spec_len(path);
	if (drive_spec_len > 0 && path[drive_spec_len] == L'\0')
		return true;

	/* All path separators? */
	for (const wchar_t *p = path; *p != L'\0'; p++)
		if (!is_any_path_separator(*p))
			return false;
	return true;
}


/* Given a path, which may not yet exist, get a set of flags that describe the
 * features of the volume the path is on. */
int
win32_get_vol_flags(const wchar_t *path, unsigned *vol_flags_ret,
		    bool *supports_SetFileShortName_ret)
{
	wchar_t *volume;
	BOOL bret;
	DWORD vol_flags;
	size_t drive_spec_len;
	wchar_t filesystem_name[MAX_PATH + 1];

	if (supports_SetFileShortName_ret)
		*supports_SetFileShortName_ret = false;

	drive_spec_len = win32_path_drive_spec_len(path);

	if (drive_spec_len == 0)
		if (path[0] != L'\0' && path[1] == L':') /* Drive-relative path? */
			drive_spec_len = 2;

	if (drive_spec_len == 0) {
		/* Path does not start with a drive letter; use the volume of
		 * the current working directory. */
		volume = NULL;
	} else {
		/* Path starts with a drive letter (or \\?\ followed by a drive
		 * letter); use it. */
		volume = alloca((drive_spec_len + 2) * sizeof(wchar_t));
		wmemcpy(volume, path, drive_spec_len);
		/* Add trailing backslash in case this was a drive-relative
		 * path. */
		volume[drive_spec_len] = L'\\';
		volume[drive_spec_len + 1] = L'\0';
	}
	bret = GetVolumeInformation(
			volume,				/* lpRootPathName */
			NULL,				/* lpVolumeNameBuffer */
			0,				/* nVolumeNameSize */
			NULL,				/* lpVolumeSerialNumber */
			NULL,				/* lpMaximumComponentLength */
			&vol_flags,			/* lpFileSystemFlags */
			filesystem_name,		/* lpFileSystemNameBuffer */
			ARRAY_LEN(filesystem_name));    /* nFileSystemNameSize */
	if (!bret) {
		set_errno_from_GetLastError();
		WARNING_WITH_ERRNO("Failed to get volume information for "
				   "path \"%ls\"", path);
		vol_flags = 0xffffffff;
		goto out;
	}

	if (wcsstr(filesystem_name, L"NTFS")) {
		/* FILE_SUPPORTS_HARD_LINKS is only supported on Windows 7 and later.
		 * Force it on anyway if filesystem is NTFS.  */
		vol_flags |= FILE_SUPPORTS_HARD_LINKS;

		if (supports_SetFileShortName_ret)
			*supports_SetFileShortName_ret = true;
	}

out:
	DEBUG("using vol_flags = %x", vol_flags);
	*vol_flags_ret = vol_flags;
	return 0;
}

static bool
win32_modify_privilege(const wchar_t *privilege, bool enable)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES newState;
	bool ret = FALSE;

	if (!OpenProcessToken(GetCurrentProcess(),
			      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
			      &hToken))
		goto out;

	if (!LookupPrivilegeValue(NULL, privilege, &luid))
		goto out_close_handle;

	newState.PrivilegeCount = 1;
	newState.Privileges[0].Luid = luid;
	newState.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);
	SetLastError(ERROR_SUCCESS);
	ret = AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL);
	if (ret && GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		ret = FALSE;
out_close_handle:
	CloseHandle(hToken);
out:
	return ret;
}

static bool
win32_modify_capture_privileges(bool enable)
{
	return win32_modify_privilege(SE_BACKUP_NAME, enable)
	    && win32_modify_privilege(SE_SECURITY_NAME, enable);
}

static bool
win32_modify_apply_privileges(bool enable)
{
	return win32_modify_privilege(SE_RESTORE_NAME, enable)
	    && win32_modify_privilege(SE_SECURITY_NAME, enable)
	    && win32_modify_privilege(SE_TAKE_OWNERSHIP_NAME, enable);
}

static void
win32_release_capture_and_apply_privileges(void)
{
	win32_modify_capture_privileges(false);
	win32_modify_apply_privileges(false);
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

/* Vista and later */
BOOL (WINAPI *win32func_CreateSymbolicLinkW)(const wchar_t *lpSymlinkFileName,
					     const wchar_t *lpTargetFileName,
					     DWORD dwFlags) = NULL;

#ifdef WITH_NTDLL

DWORD (WINAPI *func_RtlNtStatusToDosError)(NTSTATUS status);

NTSTATUS (WINAPI *func_NtQueryInformationFile)(HANDLE FileHandle,
					       PIO_STATUS_BLOCK IoStatusBlock,
					       PVOID FileInformation,
					       ULONG Length,
					       FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS (WINAPI *func_NtQuerySecurityObject)(HANDLE handle,
					      SECURITY_INFORMATION SecurityInformation,
					      PSECURITY_DESCRIPTOR SecurityDescriptor,
					      ULONG Length,
					      PULONG LengthNeeded);

NTSTATUS (WINAPI *func_NtQueryDirectoryFile) (HANDLE FileHandle,
					      HANDLE Event,
					      PIO_APC_ROUTINE ApcRoutine,
					      PVOID ApcContext,
					      PIO_STATUS_BLOCK IoStatusBlock,
					      PVOID FileInformation,
					      ULONG Length,
					      FILE_INFORMATION_CLASS FileInformationClass,
					      BOOLEAN ReturnSingleEntry,
					      PUNICODE_STRING FileName,
					      BOOLEAN RestartScan);

NTSTATUS (WINAPI *func_NtSetSecurityObject)(HANDLE Handle,
					    SECURITY_INFORMATION SecurityInformation,
					    PSECURITY_DESCRIPTOR SecurityDescriptor);

#endif /* WITH_NTDLL */

static OSVERSIONINFO windows_version_info = {
	.dwOSVersionInfoSize = sizeof(OSVERSIONINFO),
};

static HMODULE hKernel32 = NULL;

#ifdef WITH_NTDLL
static HMODULE hNtdll = NULL;
#endif

static bool acquired_privileges = false;

bool
windows_version_is_at_least(unsigned major, unsigned minor)
{
	return windows_version_info.dwMajorVersion > major ||
		(windows_version_info.dwMajorVersion == major &&
		 windows_version_info.dwMinorVersion >= minor);
}

/* One-time initialization for Windows capture/apply code.  */
int
win32_global_init(int init_flags)
{
	/* Try to acquire useful privileges.  */
	if (!(init_flags & WIMLIB_INIT_FLAG_DONT_ACQUIRE_PRIVILEGES)) {
		if (!win32_modify_capture_privileges(true))
			if (init_flags & WIMLIB_INIT_FLAG_STRICT_CAPTURE_PRIVILEGES)
				goto insufficient_privileges;
		if (!win32_modify_apply_privileges(true))
			if (init_flags & WIMLIB_INIT_FLAG_STRICT_APPLY_PRIVILEGES)
				goto insufficient_privileges;
		acquired_privileges = true;
	}

	/* Get Windows version information.  */
	GetVersionEx(&windows_version_info);

	/* Try to dynamically load some functions.  */
	if (hKernel32 == NULL)
		hKernel32 = LoadLibrary(L"Kernel32.dll");

	if (hKernel32) {
		win32func_FindFirstStreamW = (void*)GetProcAddress(hKernel32,
								   "FindFirstStreamW");
		if (win32func_FindFirstStreamW) {
			win32func_FindNextStreamW = (void*)GetProcAddress(hKernel32,
									  "FindNextStreamW");
			if (!win32func_FindNextStreamW)
				win32func_FindFirstStreamW = NULL;
		}
		win32func_CreateSymbolicLinkW = (void*)GetProcAddress(hKernel32,
								      "CreateSymbolicLinkW");
	}

#ifdef WITH_NTDLL
	if (hNtdll == NULL)
		hNtdll = LoadLibrary(L"ntdll.dll");

	if (hNtdll) {
		func_RtlNtStatusToDosError  =
			(void*)GetProcAddress(hNtdll, "RtlNtStatusToDosError");
		if (func_RtlNtStatusToDosError) {

			func_NtQuerySecurityObject  =
				(void*)GetProcAddress(hNtdll, "NtQuerySecurityObject");

			func_NtQueryDirectoryFile   =
				(void*)GetProcAddress(hNtdll, "NtQueryDirectoryFile");

			func_NtQueryInformationFile =
				(void*)GetProcAddress(hNtdll, "NtQueryInformationFile");

			func_NtSetSecurityObject    =
				(void*)GetProcAddress(hNtdll, "NtSetSecurityObject");
		}
	}

	DEBUG("FindFirstStreamW       @ %p", win32func_FindFirstStreamW);
	DEBUG("FindNextStreamW        @ %p", win32func_FindNextStreamW);
	DEBUG("CreateSymbolicLinkW    @ %p", win32func_CreateSymbolicLinkW);
	DEBUG("RtlNtStatusToDosError  @ %p", func_RtlNtStatusToDosError);
	DEBUG("NtQuerySecurityObject  @ %p", func_NtQuerySecurityObject);
	DEBUG("NtQueryDirectoryFile   @ %p", func_NtQueryDirectoryFile);
	DEBUG("NtQueryInformationFile @ %p", func_NtQueryInformationFile);
	DEBUG("NtSetSecurityObject    @ %p", func_NtSetSecurityObject);
#endif

	return 0;

insufficient_privileges:
	win32_release_capture_and_apply_privileges();
	return WIMLIB_ERR_INSUFFICIENT_PRIVILEGES;
}

void
win32_global_cleanup(void)
{
	if (acquired_privileges)
		win32_release_capture_and_apply_privileges();
	if (hKernel32 != NULL) {
		FreeLibrary(hKernel32);
		hKernel32 = NULL;
	}
#ifdef WITH_NTDLL
	if (hNtdll != NULL) {
		FreeLibrary(hNtdll);
		hNtdll = NULL;
	}
#endif
}

#endif /* __WIN32__ */
