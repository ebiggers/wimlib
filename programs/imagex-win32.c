
/* Replacements for functions needed specifically by the 'imagex' program in
 * Windows native builds */

#ifndef __WIN32__
#  error "This file contains Windows code"
#endif

#include "imagex-win32.h"
#include <windows.h>
#include <errno.h>
#include <string.h>
#include <assert.h>


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
		char *filename;
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
		filename = strdup(dat.cFileName);
		if (!filename)
			goto oom;
		pglob->gl_pathv[pglob->gl_pathc++] = filename;
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
	free(pglob->gl_pathv[i]);
}
