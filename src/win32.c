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

void *win32_open_file_readonly(const void *path)
{
	return CreateFileW((const wchar_t*)path,
			   FILE_READ_DATA |
			       FILE_READ_ATTRIBUTES |
			       READ_CONTROL |
			       ACCESS_SYSTEM_SECURITY,
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

static bool win32_modify_privilege(const char *privilege, bool enable)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES newState;
	bool ret = false;

	DEBUG("%s privilege %s",
	      enable ? "Enabling" : "Disabling", privilege);

	if (!OpenProcessToken(GetCurrentProcess(),
			      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
			      &hToken))
	{
		DEBUG("OpenProcessToken() failed");
		goto out;
	}

	if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
		DEBUG("LookupPrivilegeValue() failed");
		goto out;
	}

	newState.PrivilegeCount = 1;
	newState.Privileges[0].Luid = luid;
	newState.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);
	ret = AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL);
	if (!ret)
		DEBUG("AdjustTokenPrivileges() failed");
	CloseHandle(hToken);
out:
	if (!ret) {
		DWORD err = GetLastError();
		win32_error(err);
		WARNING("Failed to %s privilege %s",
			enable ? "enable" : "disable", privilege);
		WARNING("The program will continue, but if permission issues are "
			"encountered, you may need to run this program as the administrator");
	}
	return ret;
}

bool win32_acquire_privilege(const char *privilege)
{
	return win32_modify_privilege(privilege, true);
}

bool win32_release_privilege(const char *privilege)
{
	return win32_modify_privilege(privilege, false);
}


#endif /* __CYGWIN__ || __WIN32__ */
