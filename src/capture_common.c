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
canonicalize_pattern(const tchar *pat, tchar **canonical_pat_ret)
{
	tchar *canonical_pat;

	if (pat[0] != T('/') && pat[0] != T('\\') &&
	    pat[0] != T('\0') && pat[1] == T(':'))
	{
		/* Pattern begins with drive letter */
		if (pat[2] != T('/') && pat[2] != T('\\')) {
			/* Something like c:file, which is actually a path
			 * relative to the current working directory on the c:
			 * drive.  We require paths with drive letters to be
			 * absolute. */
			ERROR("Invalid path \"%"TS"\"; paths including drive letters "
			      "must be absolute!", pat);
			ERROR("Maybe try \"%"TC":/%"TS"\"?",
			      pat[0], pat + 2);
			return WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
		}

		WARNING("Pattern \"%"TS"\" starts with a drive letter, which is "
			"being removed.", pat);
		/* Strip the drive letter */
		pat += 2;
	}
	canonical_pat = canonicalize_fs_path(pat);
	if (!canonical_pat)
		return WIMLIB_ERR_NOMEM;
	*canonical_pat_ret = canonical_pat;
	return 0;
}

static int
copy_and_canonicalize_pattern_list(const struct wimlib_pattern_list *list,
				   struct wimlib_pattern_list *copy)
{
	int ret = 0;

	copy->pats = CALLOC(list->num_pats, sizeof(list->pats[0]));
	if (!copy->pats)
		return WIMLIB_ERR_NOMEM;
	copy->num_pats = list->num_pats;
	for (size_t i = 0; i < list->num_pats; i++) {
		ret = canonicalize_pattern(list->pats[i], &copy->pats[i]);
		if (ret)
			break;
	}
	return ret;
}

int
copy_and_canonicalize_capture_config(const struct wimlib_capture_config *config,
				     struct wimlib_capture_config **config_copy_ret)
{
	struct wimlib_capture_config *config_copy;
	int ret;

	config_copy = CALLOC(1, sizeof(struct wimlib_capture_config));
	if (!config_copy) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_capture_config;
	}
	ret = copy_and_canonicalize_pattern_list(&config->exclusion_pats,
						 &config_copy->exclusion_pats);
	if (ret)
		goto out_free_capture_config;
	ret = copy_and_canonicalize_pattern_list(&config->exclusion_exception_pats,
						 &config_copy->exclusion_exception_pats);
	if (ret)
		goto out_free_capture_config;
	*config_copy_ret = config_copy;
	goto out;
out_free_capture_config:
	free_capture_config(config_copy);
out:
	return ret;
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
