#ifndef _IMAGEX_WIN32_H
#define _IMAGEX_WIN32_H

#include <stddef.h>
#include <stdbool.h>
#include <wchar.h>

typedef struct {
	size_t    gl_pathc;
	wchar_t **gl_pathv;
	size_t    gl_offs;
} glob_t;

/* WARNING: this is a reduced functionality replacement */
extern int
win32_wglob(const wchar_t *pattern, int flags,
	    int (*errfunc)(const wchar_t *epath, int eerrno),
	    glob_t *pglob);

extern void globfree(glob_t *pglob);

#define	GLOB_ERR	0x1 /* Return on read errors.  */
#define	GLOB_NOSORT	0x2 /* Don't sort the names.  */

/* Error returns from `glob'.  */
#define	GLOB_NOSPACE	1	/* Ran out of memory.  */
#define	GLOB_ABORTED	2	/* Read error.  */
#define	GLOB_NOMATCH	3	/* No matches found.  */

extern void
win32_acquire_capture_privileges();

extern void
win32_release_capture_privileges();

extern void
win32_acquire_restore_privileges();

extern void
win32_release_restore_privileges();

extern wchar_t *
win32_mbs_to_wcs(const char *mbs, size_t mbs_nbytes, size_t *num_wchars_ret);

extern wchar_t *
win32_wbasename(wchar_t *path);

#include "wgetopt.h"

#define optarg			woptarg
#define optind			woptind
#define opterr			wopterr
#define optopt			woptopt
#define option			woption

#define getopt_long_only	wgetopt_long_only
#define getopt_long		wgetopt_long
#define getopt			wgetopt

#endif
