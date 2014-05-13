#ifndef _WIMLIB_WIN32_COMMON_H
#define _WIMLIB_WIN32_COMMON_H

#include <windows.h>
#ifdef ERROR
#  undef ERROR
#endif

#include "wimlib/types.h"
#include "wimlib/win32.h"

#include <ntstatus.h>
#include <winternl.h>

extern void
set_errno_from_GetLastError(void);

extern void
set_errno_from_win32_error(DWORD err);

extern void
set_errno_from_nt_status(NTSTATUS status);

extern bool
win32_path_is_root_of_drive(const wchar_t *path);

extern int
win32_get_vol_flags(const wchar_t *path, unsigned *vol_flags_ret,
		    bool *supports_SetFileShortName_ret);

extern HANDLE
win32_open_existing_file(const wchar_t *path, DWORD dwDesiredAccess);

/* Vista and later */
extern BOOL (WINAPI *func_CreateSymbolicLinkW)(const wchar_t *lpSymlinkFileName,
					       const wchar_t *lpTargetFileName,
					       DWORD dwFlags);

/* ntdll functions  */

extern NTSTATUS (WINAPI *func_NtOpenFile) (PHANDLE FileHandle,
					   ACCESS_MASK DesiredAccess,
					   POBJECT_ATTRIBUTES ObjectAttributes,
					   PIO_STATUS_BLOCK IoStatusBlock,
					   ULONG ShareAccess,
					   ULONG OpenOptions);

extern NTSTATUS (WINAPI *func_NtReadFile) (HANDLE FileHandle,
					   HANDLE Event,
					   PIO_APC_ROUTINE ApcRoutine,
					   PVOID ApcContext,
					   PIO_STATUS_BLOCK IoStatusBlock,
					   PVOID Buffer,
					   ULONG Length,
					   PLARGE_INTEGER ByteOffset,
					   PULONG Key);

extern NTSTATUS (WINAPI *func_NtQueryInformationFile)(HANDLE FileHandle,
						      PIO_STATUS_BLOCK IoStatusBlock,
						      PVOID FileInformation,
						      ULONG Length,
						      FILE_INFORMATION_CLASS FileInformationClass);

extern NTSTATUS (WINAPI *func_NtQuerySecurityObject)(HANDLE handle,
						     SECURITY_INFORMATION SecurityInformation,
						     PSECURITY_DESCRIPTOR SecurityDescriptor,
						     ULONG Length,
						     PULONG LengthNeeded);

extern NTSTATUS (WINAPI *func_NtQueryDirectoryFile) (HANDLE FileHandle,
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

extern NTSTATUS (WINAPI *func_NtQueryVolumeInformationFile) (HANDLE FileHandle,
							     PIO_STATUS_BLOCK IoStatusBlock,
							     PVOID FsInformation,
							     ULONG Length,
							     FS_INFORMATION_CLASS FsInformationClass);


extern NTSTATUS (WINAPI *func_NtSetSecurityObject)(HANDLE Handle,
						   SECURITY_INFORMATION SecurityInformation,
						   PSECURITY_DESCRIPTOR SecurityDescriptor);

extern NTSTATUS (WINAPI *func_NtClose) (HANDLE Handle);

extern DWORD (WINAPI *func_RtlNtStatusToDosError)(NTSTATUS status);

extern NTSTATUS (WINAPI *func_RtlCreateSystemVolumeInformationFolder)
			(PCUNICODE_STRING VolumeRootPath);


extern bool
windows_version_is_at_least(unsigned major, unsigned minor);

#define running_on_windows_xp_or_later() \
			windows_version_is_at_least(5, 1)

#define running_on_windows_vista_or_later() \
			windows_version_is_at_least(6, 0)

#define running_on_windows_7_or_later() \
			windows_version_is_at_least(6, 1)



#endif /* _WIMLIB_WIN32_COMMON_H */
