/*
 * win32_common.c - Windows code common to applying and capturing images.
 */

/*
 * Copyright (C) 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef __WIN32__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>

#include "wimlib/win32_common.h"

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

void
set_errno_from_nt_status(NTSTATUS status)
{
	set_errno_from_win32_error((*func_RtlNtStatusToDosError)(status));
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

/* Pointers to dynamically loaded functions  */

/* ntdll.dll  */

NTSTATUS (WINAPI *func_NtCreateFile)(PHANDLE FileHandle,
				     ACCESS_MASK DesiredAccess,
				     POBJECT_ATTRIBUTES ObjectAttributes,
				     PIO_STATUS_BLOCK IoStatusBlock,
				     PLARGE_INTEGER AllocationSize,
				     ULONG FileAttributes,
				     ULONG ShareAccess,
				     ULONG CreateDisposition,
				     ULONG CreateOptions,
				     PVOID EaBuffer,
				     ULONG EaLength);

NTSTATUS (WINAPI *func_NtOpenFile) (PHANDLE FileHandle,
				    ACCESS_MASK DesiredAccess,
				    POBJECT_ATTRIBUTES ObjectAttributes,
				    PIO_STATUS_BLOCK IoStatusBlock,
				    ULONG ShareAccess,
				    ULONG OpenOptions);

NTSTATUS (WINAPI *func_NtReadFile) (HANDLE FileHandle,
				    HANDLE Event,
				    PIO_APC_ROUTINE ApcRoutine,
				    PVOID ApcContext,
				    PIO_STATUS_BLOCK IoStatusBlock,
				    PVOID Buffer,
				    ULONG Length,
				    PLARGE_INTEGER ByteOffset,
				    PULONG Key);

NTSTATUS (WINAPI *func_NtWriteFile) (HANDLE FileHandle,
				     HANDLE Event,
				     PIO_APC_ROUTINE ApcRoutine,
				     PVOID ApcContext,
				     PIO_STATUS_BLOCK IoStatusBlock,
				     PVOID Buffer,
				     ULONG Length,
				     PLARGE_INTEGER ByteOffset,
				     PULONG Key);

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

NTSTATUS (WINAPI *func_NtQueryVolumeInformationFile) (HANDLE FileHandle,
						      PIO_STATUS_BLOCK IoStatusBlock,
						      PVOID FsInformation,
						      ULONG Length,
						      FS_INFORMATION_CLASS FsInformationClass);

NTSTATUS (WINAPI *func_NtSetInformationFile)(HANDLE FileHandle,
					     PIO_STATUS_BLOCK IoStatusBlock,
					     PVOID FileInformation,
					     ULONG Length,
					     FILE_INFORMATION_CLASS FileInformationClass);

NTSTATUS (WINAPI *func_NtSetSecurityObject)(HANDLE Handle,
					    SECURITY_INFORMATION SecurityInformation,
					    PSECURITY_DESCRIPTOR SecurityDescriptor);

NTSTATUS (WINAPI *func_NtFsControlFile) (HANDLE FileHandle,
					 HANDLE Event,
					 PIO_APC_ROUTINE ApcRoutine,
					 PVOID ApcContext,
					 PIO_STATUS_BLOCK IoStatusBlock,
					 ULONG FsControlCode,
					 PVOID InputBuffer,
					 ULONG InputBufferLength,
					 PVOID OutputBuffer,
					 ULONG OutputBufferLength);

NTSTATUS (WINAPI *func_NtClose) (HANDLE Handle);

DWORD (WINAPI *func_RtlNtStatusToDosError)(NTSTATUS status);

BOOLEAN (WINAPI *func_RtlDosPathNameToNtPathName_U)
		  (IN PCWSTR DosName,
		   OUT PUNICODE_STRING NtName,
		   OUT PCWSTR *PartName,
		   OUT PRTL_RELATIVE_NAME_U RelativeName);

NTSTATUS (WINAPI *func_RtlDosPathNameToNtPathName_U_WithStatus)
		(IN PCWSTR DosName,
		 OUT PUNICODE_STRING NtName,
		 OUT PCWSTR *PartName,
		 OUT PRTL_RELATIVE_NAME_U RelativeName);

NTSTATUS (WINAPI *func_RtlCreateSystemVolumeInformationFolder)
		(PCUNICODE_STRING VolumeRootPath);

static bool acquired_privileges = false;

struct dll_sym {
	void **func_ptr;
	const char *name;
	bool required;
};

#define DLL_SYM(name, required) { (void **)&func_##name, #name, required }

#define for_each_sym(sym, spec) \
	for ((sym) = (spec)->syms; (sym)->name; (sym)++)

struct dll_spec {
	const wchar_t *name;
	HMODULE handle;
	const struct dll_sym syms[];
};

struct dll_spec ntdll_spec = {
	.name = L"ntdll.dll",
	.syms = {
		DLL_SYM(NtCreateFile, true),
		DLL_SYM(NtOpenFile, true),
		DLL_SYM(NtReadFile, true),
		DLL_SYM(NtWriteFile, true),
		DLL_SYM(NtQueryInformationFile, true),
		DLL_SYM(NtQuerySecurityObject, true),
		DLL_SYM(NtQueryDirectoryFile, true),
		DLL_SYM(NtQueryVolumeInformationFile, true),
		DLL_SYM(NtSetInformationFile, true),
		DLL_SYM(NtSetSecurityObject, true),
		DLL_SYM(NtFsControlFile, true),
		DLL_SYM(NtClose, true),
		DLL_SYM(RtlNtStatusToDosError, true),
		DLL_SYM(RtlCreateSystemVolumeInformationFolder, false),
		DLL_SYM(RtlDosPathNameToNtPathName_U, true),
		DLL_SYM(RtlDosPathNameToNtPathName_U_WithStatus, false), /* Not present on XP  */
		{NULL, NULL},
	},
};

static int
init_dll(struct dll_spec *spec)
{
	const struct dll_sym *sym;
	void *addr;

	if (!spec->handle)
		spec->handle = LoadLibrary(spec->name);
	if (!spec->handle) {
		for_each_sym(sym, spec) {
			if (sym->required) {
				ERROR("%ls could not be loaded!", spec->name);
				return WIMLIB_ERR_UNSUPPORTED;
			}
		}
		return 0;
	}
	for_each_sym(sym, spec) {
		addr = (void *)GetProcAddress(spec->handle, sym->name);
		if (addr) {
			*(sym->func_ptr) = addr;
		} else if (sym->required) {
			ERROR("Can't find %s in %ls", sym->name, spec->name);
			return WIMLIB_ERR_UNSUPPORTED;
		}
	}
	return 0;
}

static void
cleanup_dll(struct dll_spec *spec)
{
	const struct dll_sym *sym;

	if (spec->handle) {
		FreeLibrary(spec->handle);
		spec->handle = NULL;

		for_each_sym(sym, spec)
			*(sym->func_ptr) = NULL;
	}
}

/* One-time initialization for Windows capture/apply code.  */
int
win32_global_init(int init_flags)
{
	int ret;

	/* Try to acquire useful privileges.  */
	if (!(init_flags & WIMLIB_INIT_FLAG_DONT_ACQUIRE_PRIVILEGES)) {
		ret = WIMLIB_ERR_INSUFFICIENT_PRIVILEGES;
		if (!win32_modify_capture_privileges(true))
			if (init_flags & WIMLIB_INIT_FLAG_STRICT_CAPTURE_PRIVILEGES)
				goto out_drop_privs;
		if (!win32_modify_apply_privileges(true))
			if (init_flags & WIMLIB_INIT_FLAG_STRICT_APPLY_PRIVILEGES)
				goto out_drop_privs;
		acquired_privileges = true;
	}

	ret = init_dll(&ntdll_spec);
	if (ret)
		goto out_drop_privs;

	return 0;

out_drop_privs:
	win32_release_capture_and_apply_privileges();
	return ret;
}

void
win32_global_cleanup(void)
{
	if (acquired_privileges)
		win32_release_capture_and_apply_privileges();

	cleanup_dll(&ntdll_spec);
}

/*
 * Translates a Win32-namespace path into an NT-namespace path.
 *
 * On success, returns 0.  The NT-namespace path will be stored in the
 * UNICODE_STRING structure pointed to by nt_path.  nt_path->Buffer will be set
 * to a new buffer that must later be freed with HeapFree().  (Really
 * RtlHeapFree(), but HeapFree() seems to be the same thing.)
 *
 * On failure, returns WIMLIB_ERR_NOMEM or WIMLIB_ERR_INVALID_PARAM.
 */
int
win32_path_to_nt_path(const wchar_t *win32_path, UNICODE_STRING *nt_path)
{
	NTSTATUS status;

	if (func_RtlDosPathNameToNtPathName_U_WithStatus) {
		status = (*func_RtlDosPathNameToNtPathName_U_WithStatus)(win32_path,
									 nt_path,
									 NULL, NULL);
	} else {
		if ((*func_RtlDosPathNameToNtPathName_U)(win32_path, nt_path,
							 NULL, NULL))
			status = STATUS_SUCCESS;
		else
			status = STATUS_NO_MEMORY;
	}

	if (likely(NT_SUCCESS(status)))
		return 0;

	if (status == STATUS_NO_MEMORY)
		return WIMLIB_ERR_NOMEM;

	ERROR("\"%ls\": invalid path name (status=0x%08"PRIx32")",
	      win32_path, (u32)status);
	return WIMLIB_ERR_INVALID_PARAM;
}

int
win32_get_drive_path(const wchar_t *file_path, wchar_t drive_path[7])
{
	tchar *file_abspath;

	file_abspath = realpath(file_path, NULL);
	if (!file_abspath)
		return WIMLIB_ERR_NOMEM;

	if (file_abspath[0] == L'\0' || file_abspath[1] != L':') {
		ERROR("\"%ls\": Path format not recognized", file_abspath);
		FREE(file_abspath);
		return WIMLIB_ERR_UNSUPPORTED;
	}

	wsprintf(drive_path, L"\\\\.\\%lc:", file_abspath[0]);
	FREE(file_abspath);
	return 0;
}


#endif /* __WIN32__ */
