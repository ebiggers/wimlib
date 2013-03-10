#include "config.h"

#if defined(__CYGWIN__) || defined(__WIN32__)
#include <windows.h>
#	ifdef ERROR
#		undef ERROR
#	endif

#include "wimlib_internal.h"


#ifdef ENABLE_ERROR_MESSAGES
void win32_error(u32 err_code)
{
	char *buffer;
	DWORD nchars;
	nchars = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
				NULL, err_code, 0,
				(char*)&buffer, 0, NULL);
	if (nchars == 0) {
		ERROR("Error printing error message! "
		      "Computer will self-destruct in 3 seconds.");
	} else {
		ERROR("Win32 error: %s", buffer);
		LocalFree(buffer);
	}
}
#else
#define win32_error(err_code)
#endif

void *win32_open_file(const void *path)
{
	return CreateFileW((const wchar_t*)path,
			   GENERIC_READ | READ_CONTROL,
			   FILE_SHARE_READ,
			   NULL, /* lpSecurityAttributes */
			   OPEN_EXISTING,
			   FILE_FLAG_BACKUP_SEMANTICS |
				   FILE_FLAG_OPEN_REPARSE_POINT,
			   NULL /* hTemplateFile */);
}
		
int win32_read_file(const char *filename,
		    void *handle, u64 offset, size_t size, u8 *buf)
{
	HANDLE h = handle;
	DWORD err;
	DWORD bytesRead;
	LARGE_INTEGER liOffset = {.QuadPart = offset};
	
	wimlib_assert(size <= 0xffffffff);

	if (SetFilePointerEx(h, liOffset, NULL, FILE_BEGIN))
		if (ReadFile(h, buf, size, &bytesRead, NULL) && bytesRead == size)
			return 0;
	err = GetLastError();
	ERROR("Error reading \"%s\"", filename);
	win32_error(err);
	return WIMLIB_ERR_READ;
}

void win32_close_file(void *handle)
{
	CloseHandle((HANDLE)handle);
}

#endif /* __CYGWIN__ || __WIN32__ */
