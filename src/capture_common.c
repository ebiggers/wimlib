/*
 * Copyright (C) 2013 Eric Biggers
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

#include "wimlib_internal.h"

#include <string.h>

#ifdef __WIN32__
#  include "win32.h"
#else
#  include <fnmatch.h>
#endif

static int
canonicalize_pat(tchar **pat_p)
{
	tchar *pat = *pat_p;

	/* Turn all backslashes in the pattern into forward slashes. */
	zap_backslashes(pat);

	if (*pat != T('/') && *pat != T('\0') && *(pat + 1) == T(':')) {
		/* Pattern begins with drive letter */
		if (*(pat + 2) != T('/')) {
			/* Something like c:file, which is actually a path
			 * relative to the current working directory on the c:
			 * drive.  We require paths with drive letters to be
			 * absolute. */
			ERROR("Invalid path \"%"TS"\"; paths including drive letters "
			      "must be absolute!", pat);
			ERROR("Maybe try \"%"TC":/%"TS"\"?",
			      *pat, pat + 2);
			return WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
		}

		WARNING("Pattern \"%"TS"\" starts with a drive letter, which is "
			"being removed.", pat);
		/* Strip the drive letter */
		pat += 2;
		*pat_p = pat;
	}
	return 0;
}

static int
canonicalize_pat_list(struct wimlib_pattern_list *pat_list)
{
	int ret = 0;
	for (size_t i = 0; i < pat_list->num_pats; i++) {
		ret = canonicalize_pat(&pat_list->pats[i]);
		if (ret)
			break;
	}
	return ret;
}

int
canonicalize_capture_config(struct wimlib_capture_config *config)
{
	int ret = canonicalize_pat_list(&config->exclusion_pats);
	if (ret)
		return ret;
	return canonicalize_pat_list(&config->exclusion_exception_pats);
}

static bool
copy_pattern_list(struct wimlib_pattern_list *copy,
		  const struct wimlib_pattern_list *list)
{
	copy->pats = CALLOC(list->num_pats, sizeof(list->pats[0]));
	if (!copy->pats)
		return false;
	copy->num_pats = list->num_pats;
	for (size_t i = 0; i < list->num_pats; i++) {
		copy->pats[i] = TSTRDUP(list->pats[i]);
		if (!copy->pats[i])
			return false;
	}
	return true;
}

struct wimlib_capture_config *
copy_capture_config(const struct wimlib_capture_config *config)
{
	struct wimlib_capture_config *copy;

	copy = CALLOC(1, sizeof(struct wimlib_capture_config));
	if (!copy)
		goto oom;
	if (!copy_pattern_list(&copy->exclusion_pats, &config->exclusion_pats))
		goto oom;
	if (!copy_pattern_list(&copy->exclusion_exception_pats,
			       &config->exclusion_exception_pats))
		goto oom;
	goto out;
oom:
	free_capture_config(copy);
	copy = NULL;
out:
	return copy;
}

static void
destroy_pattern_list(struct wimlib_pattern_list *list)
{
	for (size_t i = 0; i < list->num_pats; i++)
		FREE(list->pats[i]);
	FREE(list->pats);
}

void
free_capture_config(struct wimlib_capture_config *config)
{
	if (config) {
		destroy_pattern_list(&config->exclusion_pats);
		destroy_pattern_list(&config->exclusion_exception_pats);
		FREE(config);
	}
}

static bool
match_pattern(const tchar *path,
	      const tchar *path_basename,
	      const struct wimlib_pattern_list *list)
{
	for (size_t i = 0; i < list->num_pats; i++) {

		const tchar *pat = list->pats[i];
		const tchar *string;

		if (*pat == T('/')) {
			/* Absolute path from root of capture */
			string = path;
		} else {
			if (tstrchr(pat, T('/')))
				/* Relative path from root of capture */
				string = path + 1;
			else
				/* A file name pattern */
				string = path_basename;
		}

		/* Warning: on Windows native builds, fnmatch() calls the
		 * replacement function in win32.c. */
		if (fnmatch(pat, string, FNM_PATHNAME | FNM_NOESCAPE
				#ifdef FNM_CASEFOLD
			    		| FNM_CASEFOLD
				#endif
			    ) == 0)
		{
			DEBUG("\"%"TS"\" matches the pattern \"%"TS"\"",
			      string, pat);
			return true;
		} else {
			DEBUG2("\"%"TS"\" does not match the pattern \"%"TS"\"",
			       string, pat);
		}
	}
	return false;
}

/* Return true if the image capture configuration file indicates we should
 * exclude the filename @path from capture.
 *
 * If @exclude_prefix is %true, the part of the path up and including the name
 * of the directory being captured is not included in the path for matching
 * purposes.  This allows, for example, a pattern like /hiberfil.sys to match a
 * file /mnt/windows7/hiberfil.sys if we are capturing the /mnt/windows7
 * directory.
 */
bool
exclude_path(const tchar *path, size_t path_len,
	     const struct wimlib_capture_config *config, bool exclude_prefix)
{
	const tchar *basename = path_basename_with_len(path, path_len);
	if (exclude_prefix) {
		wimlib_assert(path_len >= config->_prefix_num_tchars);
		if (!tmemcmp(config->_prefix, path, config->_prefix_num_tchars) &&
		    path[config->_prefix_num_tchars] == T('/'))
		{
			path += config->_prefix_num_tchars;
		}
	}
	return match_pattern(path, basename, &config->exclusion_pats) &&
		!match_pattern(path, basename, &config->exclusion_exception_pats);

}
