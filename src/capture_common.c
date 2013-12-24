/*
 * capture_common.c - Mostly code to handle excluding paths from capture.
 */

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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/assert.h"
#include "wimlib/capture.h"
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/paths.h"

#ifdef __WIN32__
#  include "wimlib/win32.h" /* for fnmatch() equivalent */
#else
#  include <fnmatch.h>
#endif
#include <string.h>


static int
canonicalize_pattern(const tchar *pat, tchar **canonical_pat_ret)
{
	tchar *canonical_pat;

	if (!is_any_path_separator(pat[0]) &&
	    pat[0] != T('\0') && pat[1] == T(':'))
	{
		/* Pattern begins with drive letter */
		if (!is_any_path_separator(pat[2])) {
			/* Something like c:file, which is actually a path
			 * relative to the current working directory on the c:
			 * drive.  We require paths with drive letters to be
			 * absolute. */
			ERROR("Invalid path \"%"TS"\"; paths including drive letters "
			      "must be absolute!", pat);
			ERROR("Maybe try \"%"TC":\\%"TS"\"?",
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

	/* Translate all possible path separators into the operating system's
	 * preferred path separator. */
	for (tchar *p = canonical_pat; *p; p++)
		if (is_any_path_separator(*p))
			*p = OS_PREFERRED_PATH_SEPARATOR;
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

		if (*pat == OS_PREFERRED_PATH_SEPARATOR) {
			/* Absolute path from root of capture */
			string = path;
		} else {
			if (tstrchr(pat, OS_PREFERRED_PATH_SEPARATOR))
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

void
do_capture_progress(struct add_image_params *params, int status,
		    const struct wim_inode *inode)
{
	switch (status) {
	case WIMLIB_SCAN_DENTRY_OK:
		if (!(params->add_flags & WIMLIB_ADD_FLAG_VERBOSE))
			return;
	case WIMLIB_SCAN_DENTRY_UNSUPPORTED:
	case WIMLIB_SCAN_DENTRY_EXCLUDED:
		if (!(params->add_flags & WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE))
			return;
	}
	params->progress.scan.status = status;
	if (status == WIMLIB_SCAN_DENTRY_OK && inode->i_nlink == 1) {
		const struct wim_lookup_table_entry *lte;
		for (unsigned i = 0; i <= inode->i_num_ads; i++) {
			lte = inode_stream_lte_resolved(inode, i);
			if (lte != NULL)
				params->progress.scan.num_bytes_scanned += lte->size;
		}
		if (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
			params->progress.scan.num_dirs_scanned++;
		else
			params->progress.scan.num_nondirs_scanned++;
	}
	if (params->progress_func) {
		params->progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY,
				      &params->progress);
	}
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
	if (!config)
		return false;
	const tchar *basename = path_basename_with_len(path, path_len);
	if (exclude_prefix) {
		wimlib_assert(path_len >= config->_prefix_num_tchars);
		if (!tmemcmp(config->_prefix, path, config->_prefix_num_tchars) &&
		    path[config->_prefix_num_tchars] == OS_PREFERRED_PATH_SEPARATOR)
		{
			path += config->_prefix_num_tchars;
		}
	}
	return match_pattern(path, basename, &config->exclusion_pats) &&
		!match_pattern(path, basename, &config->exclusion_exception_pats);

}
