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

#include "wimlib.h"
#include "wimlib/paths.h"
#include "wimlib/util.h"

#include <string.h>

/* Like the basename() function, but does not modify @path; it just returns a
 * pointer to it.  This assumes the path separator is the
 * OS_PREFERRED_PATH_SEPARATOR.  */
const tchar *
path_basename(const tchar *path)
{
	return path_basename_with_len(path, tstrlen(path));
}

/* Like path_basename(), but take an explicit string length.  */
const tchar *
path_basename_with_len(const tchar *path, size_t len)
{
	const tchar *p = &path[len];

	do {
		if (p == path)
			return &path[len];
	} while (*--p == OS_PREFERRED_PATH_SEPARATOR);

	do {
		if (p == path)
			return &path[0];
	} while (*--p != OS_PREFERRED_PATH_SEPARATOR);

	return ++p;
}


/* Returns a pointer to the part of @path following the first colon in the last
 * path component, or NULL if the last path component does not contain a colon
 * or has no characters following the first colon.  */
const tchar *
path_stream_name(const tchar *path)
{
	const tchar *base = path_basename(path);
	const tchar *stream_name = tstrchr(base, T(':'));
	if (stream_name == NULL || *(stream_name + 1) == T('\0'))
		return NULL;
	else
		return stream_name + 1;
}

/* Duplicate a path; return empty string for NULL input.  */
tchar *
canonicalize_fs_path(const tchar *fs_path)
{
	if (fs_path == NULL)
		fs_path = T("");
	return TSTRDUP(fs_path);
}

/*
 * canonicalize_wim_path() - Given a user-provided path to a file within a WIM
 * image, translate it into a "canonical" path.
 *
 * To do this, translate all supported path separators (is_any_path_separator())
 * into the WIM_PATH_SEPARATOR, and strip any leading and trailing slashes.  The
 * returned string is allocated.  Note that there still may be consecutive path
 * separators within the string.  Furthermore, the string may be empty, which
 * indicates the root dentry of the WIM image.
 */
tchar *
canonicalize_wim_path(const tchar *wim_path)
{
	tchar *canonical_path;
	tchar *p;

	if (wim_path == NULL) {
		wim_path = T("");
	} else {
		/* Strip leading path separators.  */
		while (is_any_path_separator(*wim_path))
			wim_path++;
	}

	canonical_path = TSTRDUP(wim_path);
	if (canonical_path == NULL)
		return NULL;

	/* Translate all path separators to WIM_PATH_SEPARATOR.  */
	for (p = canonical_path; *p; p++)
		if (is_any_path_separator(*p))
			*p = WIM_PATH_SEPARATOR;

	/* Strip trailing path separators.  */
	while (p > canonical_path && *--p == WIM_PATH_SEPARATOR)
		*p = T('\0');

	return canonical_path;
}
