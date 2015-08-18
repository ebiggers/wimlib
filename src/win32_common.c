/*
 * win32_common.c - Windows code common to applying and capturing images.
 */

/*
 * Copyright (C) 2013, 2014, 2015 Eric Biggers
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

#include "wimlib/win32_common.h"

#include "wimlib/error.h"
#include "wimlib/util.h"

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
	bool ok = true;
	ok &= win32_modify_privilege(SE_BACKUP_NAME, enable);
	ok &= win32_modify_privilege(SE_SECURITY_NAME, enable);
	return ok;
}

static bool
win32_modify_apply_privileges(bool enable)
{
	bool ok = true;
	ok &= win32_modify_privilege(SE_RESTORE_NAME, enable);
	ok &= win32_modify_privilege(SE_SECURITY_NAME, enable);
	ok &= win32_modify_privilege(SE_TAKE_OWNERSHIP_NAME, enable);
	ok &= win32_modify_privilege(SE_MANAGE_VOLUME_NAME, enable);
	return ok;
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

	winnt_error(status, L"\"%ls\": invalid path name", win32_path);
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

static void
windows_msg(u32 code, const wchar_t *format, va_list va,
	    bool is_ntstatus, bool is_error)
{
	wchar_t _buf[STACK_MAX / 8];
	wchar_t *buf = _buf;
	size_t buflen = ARRAY_LEN(_buf);
	size_t ret;
	size_t n;

retry:
	n = vsnwprintf(buf, buflen, format, va);

	if (n >= buflen)
		goto realloc;

	n += snwprintf(&buf[n], buflen - n,
		       (is_ntstatus ?
			L" (status=%08"PRIx32"): " :
			L" (err=%"PRIu32"): "),
		       code);

	if (n >= buflen)
		goto realloc;

	ret = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			    NULL,
			    is_ntstatus ? (*func_RtlNtStatusToDosError)(code) : code,
			    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			    &buf[n],
			    buflen - n,
			    NULL);
	n += ret;

	if (n >= buflen || (ret == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER))
		goto realloc;

        if (buf[n - 1] == L'\n')
		buf[--n] = L'\0';
        if (buf[n - 1] == L'\r')
		buf[--n] = L'\0';
        if (buf[n - 1] == L'.')
		buf[--n] = L'\0';

	if (is_error)
		ERROR("%ls", buf);
	else
		WARNING("%ls", buf);
	if (buf != _buf)
		FREE(buf);
	return;

realloc:
	if (buf != _buf)
		FREE(buf);
	buflen *= 2;
	buf = MALLOC(buflen * sizeof(buf[0]));
	if (buf)
		goto retry;
	ERROR("Ran out of memory while building error message!!!");
}

void
win32_warning(DWORD err, const wchar_t *format, ...)
{
	va_list va;

	va_start(va, format);
	windows_msg(err, format, va, false, false);
	va_end(va);
}

void
win32_error(DWORD err, const wchar_t *format, ...)
{
	va_list va;

	va_start(va, format);
	windows_msg(err, format, va, false, true);
	va_end(va);
}

void
winnt_warning(NTSTATUS status, const wchar_t *format, ...)
{
	va_list va;

	va_start(va, format);
	windows_msg(status, format, va, true, false);
	va_end(va);
}

void
winnt_error(NTSTATUS status, const wchar_t *format, ...)
{
	va_list va;

	va_start(va, format);
	windows_msg(status, format, va, true, true);
	va_end(va);
}

#endif /* __WIN32__ */
