/*
 * paths.c - Path manipulation routines
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/paths.h"
#include "wimlib/util.h"

#include <string.h>

/* Like the basename() function, but does not modify @path; it just returns a
 * pointer to it. */
const tchar *
path_basename(const tchar *path)
{
	return path_basename_with_len(path, tstrlen(path));
}

/* Like path_basename(), but take an explicit string length. */
const tchar *
path_basename_with_len(const tchar *path, size_t len)
{
	const tchar *p = &path[len] - 1;

	/* Trailing slashes. */
	while (1) {
		if (p == path - 1)
			return T("");
		if (*p != T('/'))
			break;
		p--;
	}

	while ((p != path - 1) && *p != T('/'))
		p--;

	return p + 1;
}


/*
 * Returns a pointer to the part of @path following the first colon in the last
 * path component, or NULL if the last path component does not contain a colon.
 */
const tchar *
path_stream_name(const tchar *path)
{
	const tchar *base = path_basename(path);
	const tchar *stream_name = tstrchr(base, T(':'));
	if (!stream_name)
		return NULL;
	else
		return stream_name + 1;
}


/* Translate backslashes to forward slashes in-place. */
void
zap_backslashes(tchar *s)
{
	if (s) {
		while (*s != T('\0')) {
			if (*s == T('\\'))
				*s = T('/');
			s++;
		}
	}
}

/* Duplicate a path; return empty string for NULL input. */
tchar *
canonicalize_fs_path(const tchar *fs_path)
{
	if (!fs_path)
		fs_path = T("");
	return TSTRDUP(fs_path);
}

/* Duplicate a path, with backslashes translated into forward slashes; return
 * empty string for NULL input;  also strip leading and trailing slashes. */
tchar *
canonicalize_wim_path(const tchar *wim_path)
{
	tchar *p;
	tchar *canonical_path;

	if (wim_path == NULL) {
		wim_path = T("");
	} else {
		while (*wim_path == T('/') || *wim_path == T('\\'))
			wim_path++;
	}
	canonical_path = TSTRDUP(wim_path);
	if (canonical_path) {
		zap_backslashes(canonical_path);
		for (p = tstrchr(canonical_path, T('\0')) - 1;
		     p >= canonical_path && *p == T('/');
		     p--)
		{
			*p = T('\0');
		}
	}
	return canonical_path;
}
