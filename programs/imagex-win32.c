
/* Replacements for functions needed specifically by the 'imagex' program in
 * Windows native builds; also, Windows-specific code to acquire and release
 * privileges needed to backup and restore files */

#ifndef __WIN32__
#  error "This file contains Windows code"
#endif

#include "imagex-win32.h"
#include <windows.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

/* Replacement for glob() in Windows native builds. */
int glob(const char *pattern, int flags,
	 int (*errfunc)(const char *epath, int eerrno),
	 glob_t *pglob)
{
	WIN32_FIND_DATA dat;
	DWORD err;
	HANDLE hFind;
	int ret;
	size_t nspaces;

	const char *backslash, *forward_slash, *end_slash;
	size_t prefix_len;

	backslash = strrchr(pattern, '\\');
	end_slash = strrchr(pattern, '/');

	if (backslash > end_slash)
		end_slash = backslash;

	if (end_slash)
		prefix_len = end_slash - pattern + 1;
	else
		prefix_len = 0;

	/* This function does not support all functionality of the POSIX glob(),
	 * so make sure the parameters are consistent with supported
	 * functionality. */
	assert(errfunc == NULL);
	assert((flags & GLOB_ERR) == GLOB_ERR);
	assert((flags & ~(GLOB_NOSORT | GLOB_ERR)) == 0);

	hFind = FindFirstFileA(pattern, &dat);
	if (hFind == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		if (err == ERROR_FILE_NOT_FOUND) {
			errno = 0;
			return GLOB_NOMATCH;
		} else {
			/* The other possible error codes for FindFirstFile()
			 * are undocumented. */
			errno = EIO;
			return GLOB_ABORTED;
		}
	}
	pglob->gl_pathc = 0;
	pglob->gl_pathv = NULL;
	nspaces = 0;
	do {
		char *path;
		if (pglob->gl_pathc == nspaces) {
			size_t new_nspaces;
			char **pathv;

		 	new_nspaces = nspaces * 2 + 1;	
			pathv = realloc(pglob->gl_pathv,
					new_nspaces * sizeof(pglob->gl_pathv[0]));
			if (!pathv)
				goto oom;
			pglob->gl_pathv = pathv;
			nspaces = new_nspaces;
		}
		size_t filename_len = strlen(dat.cFileName);
		size_t len_needed = prefix_len + filename_len;

		path = malloc(len_needed + 1);
		if (!path)
			goto oom;

		memcpy(path, pattern, prefix_len);
		memcpy(path + prefix_len, dat.cFileName, filename_len + 1);
		pglob->gl_pathv[pglob->gl_pathc++] = path;
	} while (FindNextFileA(hFind, &dat));
	err = GetLastError();
	CloseHandle(hFind);
	if (err == ERROR_NO_MORE_FILES) {
		errno = 0;
		return 0;
	} else {
		/* Other possible error codes for FindNextFile() are
		 * undocumented */
		errno = EIO;
		ret = GLOB_ABORTED;
		goto fail_globfree;
	}
oom:
	CloseHandle(hFind);
	errno = ENOMEM;
	ret = GLOB_NOSPACE;
fail_globfree:
	globfree(pglob);
	return ret;
}

void globfree(glob_t *pglob)
{
	size_t i;
	for (i = 0; i < pglob->gl_pathc; i++)
		free(pglob->gl_pathv[i]);
	free(pglob->gl_pathv);
}

static bool
win32_modify_privilege(const char *privilege, bool enable)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES newState;
	bool ret = false;

	if (!OpenProcessToken(GetCurrentProcess(),
			      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
			      &hToken))
	{
		goto out;
	}

	if (!LookupPrivilegeValue(NULL, privilege, &luid)) {
		goto out;
	}

	newState.PrivilegeCount = 1;
	newState.Privileges[0].Luid = luid;
	newState.Privileges[0].Attributes = (enable ? SE_PRIVILEGE_ENABLED : 0);
	ret = AdjustTokenPrivileges(hToken, FALSE, &newState, 0, NULL, NULL);
	CloseHandle(hToken);
out:
	if (!ret) {
		fprintf(stderr, "WARNING: Failed to %s privilege %s\n",
			enable ? "enable" : "disable", privilege);
		fprintf(stderr,
			"WARNING: The program will continue, "
			"but if permission issues are\n"
			"encountered, you may need to run "
			"this program as the administrator\n");
	}
	return ret;
}

static void
win32_modify_capture_privileges(bool enable)
{
	win32_modify_privilege(SE_BACKUP_NAME, enable);
	win32_modify_privilege(SE_SECURITY_NAME, enable);
}

static void
win32_modify_restore_privileges(bool enable)
{
	win32_modify_privilege(SE_RESTORE_NAME, enable);
	win32_modify_privilege(SE_SECURITY_NAME, enable);
	win32_modify_privilege(SE_TAKE_OWNERSHIP_NAME, enable);
}

void
win32_acquire_capture_privileges()
{
	win32_modify_capture_privileges(true);
}

void
win32_release_capture_privileges()
{
	win32_modify_capture_privileges(false);
}

void
win32_acquire_restore_privileges()
{
	win32_modify_restore_privileges(true);
}

void
win32_release_restore_privileges()
{
	win32_modify_restore_privileges(false);
}
