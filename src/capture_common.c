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
#include "wimlib/textfile.h"
#include "wimlib/wildcard.h"

#include <string.h>

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
	case WIMLIB_SCAN_DENTRY_EXCLUDED_SYMLINK:
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

int
mangle_pat(tchar *pat, const tchar *path, unsigned long line_no)
{
	if (!is_any_path_separator(pat[0]) &&
	    pat[0] != T('\0') && pat[1] == T(':'))
	{
		/* Pattern begins with drive letter */
		if (!is_any_path_separator(pat[2])) {
			/* Something like c:file, which is actually a path
			 * relative to the current working directory on the c:
			 * drive.  We require paths with drive letters to be
			 * absolute. */
			ERROR("%"TS":%lu: Invalid pattern \"%"TS"\":\n"
			      "        Patterns including drive letters must be absolute!\n"
			      "        Maybe try \"%"TC":%"TC"%"TS"\"?\n",
			      path, line_no, pat,
			      pat[0], OS_PREFERRED_PATH_SEPARATOR, &pat[2]);
			return WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
		}

		WARNING("%"TS":%lu: Pattern \"%"TS"\" starts with a drive "
			"letter, which is being removed.",
			path, line_no, pat);

		/* Strip the drive letter.  */
		tmemmove(pat, pat + 2, tstrlen(pat + 2) + 1);
	}

	/* Collapse and translate path separators.
	 *
	 * Note: we require that this works for filesystem paths and WIM paths,
	 * so the desired path separators must be the same.  */
	BUILD_BUG_ON(OS_PREFERRED_PATH_SEPARATOR != WIM_PATH_SEPARATOR);
	do_canonicalize_path(pat, pat);

	/* Relative patterns can only match file names.  */
	if (pat[0] != OS_PREFERRED_PATH_SEPARATOR &&
	    tstrchr(pat, OS_PREFERRED_PATH_SEPARATOR))
	{
		ERROR("%"TS":%lu: Invalid path \"%"TS"\":\n"
		      "        Relative patterns can only include one path component!\n"
		      "        Maybe try \"%"TC"%"TS"\"?",
		      path, line_no, pat, OS_PREFERRED_PATH_SEPARATOR, pat);
		return WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
	}

	return 0;
}

int
do_read_capture_config_file(const tchar *config_file, const void *buf,
			    size_t bufsize, struct capture_config *config)
{
	int ret;

	/* [PrepopulateList] is used for apply, not capture.  But since we do
	 * understand it, recognize it (avoiding unrecognized section warning)
	 * and discard the strings.  */
	STRING_SET(prepopulate_pats);

	struct text_file_section sections[] = {
		{T("ExclusionList"),
			&config->exclusion_pats},
		{T("ExclusionException"),
			&config->exclusion_exception_pats},
		{T("PrepopulateList"),
			&prepopulate_pats},
	};
	void *mem;

	ret = do_load_text_file(config_file, buf, bufsize, &mem,
				sections, ARRAY_LEN(sections),
				LOAD_TEXT_FILE_REMOVE_QUOTES, mangle_pat);
	if (ret)
		return ret;

	FREE(prepopulate_pats.strings);

	config->buf = mem;
	return 0;
}

void
destroy_capture_config(struct capture_config *config)
{
	FREE(config->exclusion_pats.strings);
	FREE(config->exclusion_exception_pats.strings);
	FREE(config->buf);
}

bool
match_pattern_list(const tchar *path, size_t path_len,
		   const struct string_set *list)
{
	for (size_t i = 0; i < list->num_strings; i++)
		if (match_path(path, path_len, list->strings[i],
			       OS_PREFERRED_PATH_SEPARATOR, true))
			return true;
	return false;
}

/*
 * Return true if the image capture configuration file indicates we should
 * exclude the filename @path from capture.
 *
 * The passed in @path must be given relative to the root of the capture, but
 * with a leading path separator.  For example, if the file "in/file" is being
 * tested and the library user ran wimlib_add_image(wim, "in", ...), then the
 * directory "in" is the root of the capture and the path should be specified as
 * "/file".
 *
 * Also, all path separators in @path must be OS_PREFERRED_PATH_SEPARATOR, and
 * there cannot be trailing slashes.
 *
 * As a special case, the empty string will be interpreted as a single path
 * separator.
 */
bool
exclude_path(const tchar *path, size_t path_nchars,
	     const struct capture_config *config)
{
	tchar dummy[2];

	if (!config)
		return false;

	if (!*path) {
		dummy[0] = OS_PREFERRED_PATH_SEPARATOR;
		dummy[1] = T('\0');
		path = dummy;
	}

	return match_pattern_list(path, path_nchars, &config->exclusion_pats) &&
	      !match_pattern_list(path, path_nchars, &config->exclusion_exception_pats);

}
