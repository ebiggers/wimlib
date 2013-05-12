#ifndef _WIMLIB_WIN32_COMMON_H
#define _WIMLIB_WIN32_COMMON_H

#include <windows.h>
#ifdef ERROR
#  undef ERROR
#endif

#include "util.h"
#include "win32.h"


#ifdef ENABLE_ERROR_MESSAGES
extern void
win32_error(DWORD err_code);
#else
static inline void
win32_error(DWORD err_code)
{
}
#endif

extern void
set_errno_from_GetLastError();

extern int
win32_error_to_errno(DWORD err_code);

extern int
win32_get_vol_flags(const wchar_t *path, unsigned *vol_flags_ret);

extern HANDLE
win32_open_existing_file(const wchar_t *path, DWORD dwDesiredAccess);

extern HANDLE
win32_open_file_data_only(const wchar_t *path);

extern HANDLE (WINAPI *win32func_FindFirstStreamW)(LPCWSTR lpFileName,
						   STREAM_INFO_LEVELS InfoLevel,
						   LPVOID lpFindStreamData,
						   DWORD dwFlags);

/* Vista and later */
extern BOOL (WINAPI *win32func_FindNextStreamW)(HANDLE hFindStream,
						LPVOID lpFindStreamData);

#endif /* _WIMLIB_WIN32_COMMON_H */
