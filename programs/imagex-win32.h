#ifndef _IMAGEX_WIN32_H
#define _IMAGEX_WIN32_H

#include <stddef.h>

typedef struct {
	size_t gl_pathc;
	char **gl_pathv;
	size_t gl_offs;
} glob_t;

/* WARNING: this is a reduced functionality replacement */
extern int glob(const char *pattern, int flags,
		int (*errfunc)(const char *epath, int eerrno),
		glob_t *pglob);

extern void globfree(glob_t *pglob);

#define	GLOB_ERR	0x1 /* Return on read errors.  */
#define	GLOB_NOSORT	0x2 /* Don't sort the names.  */

/* Error returns from `glob'.  */
#define	GLOB_NOSPACE	1	/* Ran out of memory.  */
#define	GLOB_ABORTED	2	/* Read error.  */
#define	GLOB_NOMATCH	3	/* No matches found.  */

#endif
