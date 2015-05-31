/*
 * wildcard.c
 *
 * Wildcard matching functions.
 */

/*
 * Copyright (C) 2013 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <ctype.h>

#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/wildcard.h"

struct match_dentry_ctx {
	int (*consume_dentry)(struct wim_dentry *, void *);
	void *consume_dentry_ctx;
	size_t consume_dentry_count;
	tchar *wildcard_path;
	size_t cur_component_offset;
	size_t cur_component_len;
	bool case_insensitive;
};

static bool
do_match_wildcard(const tchar *string, size_t string_len,
		  const tchar *wildcard, size_t wildcard_len,
		  bool ignore_case)
{
	for (;;) {
		if (string_len == 0) {
			while (wildcard_len != 0 && *wildcard == T('*')) {
				wildcard++;
				wildcard_len--;
			}
			return (wildcard_len == 0);
		} else if (wildcard_len == 0) {
			return false;
		} else if (*string == *wildcard || *wildcard == T('?') ||
			   (ignore_case && totlower(*string) == totlower(*wildcard)))
		{
			string++;
			string_len--;
			wildcard_len--;
			wildcard++;
			continue;
		} else if (*wildcard == T('*')) {
			return do_match_wildcard(string, string_len,
						 wildcard + 1, wildcard_len - 1,
						 ignore_case) ||
			       do_match_wildcard(string + 1, string_len - 1,
						 wildcard, wildcard_len,
						 ignore_case);
		} else {
			return false;
		}
	}
}

static bool
match_wildcard(const tchar *string, const tchar *wildcard,
	       size_t wildcard_len, bool ignore_case)
{
	return do_match_wildcard(string, tstrlen(string),
				 wildcard, wildcard_len, ignore_case);
}

/*
 * Determines whether a path matches a wildcard pattern.
 *
 * @path
 *	The path to match.  Assumptions:  All path separators must be @path_sep,
 *	there cannot be consecutive path separators, there cannot be a trailing
 *	path separator, and there must be exactly one leading path separator.
 *
 * @path_nchars
 *	Number of characters in @path.
 *
 * @wildcard
 *	The wildcard pattern to match.  It can contain the wildcard characters
 *	'*' and '?'.  The former matches zero or more characters except
 *	@path_sep, and the latter matches any character except @path_sep.  All
 *	path separators in the pattern must be @path_sep, and there cannot be
 *	consecutive path separators, and there cannot be a trailing path
 *	separator.  If there is a leading path separator, the match is attempted
 *	with the filename only; otherwise, the match is attempted with the whole
 *	path.
 *
 * @path_sep
 *	Path separator character used in @path and @wildcard.
 *
 * @prefix_ok
 *	If %true, allow a prefix of @path, terminated by a path separator, to
 *	match the pattern, in addition to @path itself.  In other words, return
 *	%true if the pattern actually matches one of the ancestor directories of
 *	@path.
 *
 * Returns %true if there was a match; %false if there was not.
 */
bool
match_path(const tchar *path, size_t path_nchars,
	   const tchar *wildcard, tchar path_sep, bool prefix_ok)
{
	if (*wildcard != path_sep) {
		/* Pattern doesn't begin with path separator.  Try to match the
		 * file name only.  */
		return match_wildcard(path_basename_with_len(path, path_nchars),
				      wildcard, tstrlen(wildcard),
				      default_ignore_case);
	} else {
		/* Pattern begins with path separator.  Try to match the whole
		 * path.  */
		do {
			if (!*wildcard) {
				/* Path has more components than pattern  */
				return prefix_ok;
			}

			size_t path_component_len = 0;
			size_t wildcard_component_len = 0;

			do {
				path_component_len++;
			} while (path[path_component_len] != path_sep &&
				 path[path_component_len] != T('\0'));
			do {
				wildcard_component_len++;
			} while (wildcard[wildcard_component_len] != path_sep &&
				 wildcard[wildcard_component_len] != T('\0'));
			if (!do_match_wildcard(path, path_component_len,
					       wildcard, wildcard_component_len,
					       default_ignore_case))
				return false;
			path += path_component_len;
			wildcard += wildcard_component_len;
		} while (*path);

		return (*wildcard == '\0');
	}
}

static int
expand_wildcard_recursive(struct wim_dentry *cur_dentry,
			  struct match_dentry_ctx *ctx);

enum {
	WILDCARD_STATUS_DONE_FULLY,
	WILDCARD_STATUS_DONE_TRAILING_SLASHES,
	WILDCARD_STATUS_NOT_DONE,
};

static int
wildcard_status(const tchar *wildcard)
{
	if (*wildcard == T('\0'))
		return WILDCARD_STATUS_DONE_FULLY;
	while (*wildcard == WIM_PATH_SEPARATOR)
		wildcard++;
	if (*wildcard == T('\0'))
		return WILDCARD_STATUS_DONE_TRAILING_SLASHES;

	return WILDCARD_STATUS_NOT_DONE;
}

static int
match_dentry(struct wim_dentry *cur_dentry, struct match_dentry_ctx *ctx)
{
	const tchar *name;
	size_t name_nchars;
	int ret;

	if (cur_dentry->d_name_nbytes == 0)
		return 0;

	ret = utf16le_get_tstr(cur_dentry->d_name,
			       cur_dentry->d_name_nbytes,
			       &name, &name_nchars);
	if (ret)
		return ret;
	name_nchars /= sizeof(tchar);

	if (do_match_wildcard(name,
			      name_nchars,
			      &ctx->wildcard_path[ctx->cur_component_offset],
			      ctx->cur_component_len,
			      ctx->case_insensitive))
	{
		switch (wildcard_status(&ctx->wildcard_path[
				ctx->cur_component_offset +
				ctx->cur_component_len]))
		{
		case WILDCARD_STATUS_DONE_TRAILING_SLASHES:
			if (!dentry_is_directory(cur_dentry)) {
				ret = 0;
				break;
			}
			/* Fall through  */
		case WILDCARD_STATUS_DONE_FULLY:
			ret = (*ctx->consume_dentry)(cur_dentry,
						     ctx->consume_dentry_ctx);
			ctx->consume_dentry_count++;
			break;
		case WILDCARD_STATUS_NOT_DONE:
			ret = expand_wildcard_recursive(cur_dentry, ctx);
			break;
		}
	} else {
		ret = 0;
	}

	utf16le_put_tstr(name);

	return ret;
}

static int
expand_wildcard_recursive(struct wim_dentry *cur_dentry,
			  struct match_dentry_ctx *ctx)
{
	tchar *w;
	size_t begin;
	size_t end;
	size_t len;
	size_t offset_save;
	size_t len_save;
	int ret;
	struct wim_dentry *child;

	w = ctx->wildcard_path;

	begin = ctx->cur_component_offset + ctx->cur_component_len;
	while (w[begin] == WIM_PATH_SEPARATOR)
		begin++;

	end = begin;

	while (w[end] != T('\0') && w[end] != WIM_PATH_SEPARATOR)
		end++;

	len = end - begin;

	if (len == 0)
		return 0;

	offset_save = ctx->cur_component_offset;
	len_save = ctx->cur_component_len;

	ctx->cur_component_offset = begin;
	ctx->cur_component_len = len;

	ret = 0;
	for_dentry_child(child, cur_dentry) {
		ret = match_dentry(child, ctx);
		if (ret)
			break;
	}

	ctx->cur_component_len = len_save;
	ctx->cur_component_offset = offset_save;

	return ret;
}

/* Expand a wildcard relative to the current WIM image.
 *
 * @wim
 *	WIMStruct whose currently selected image is searched to expand the
 *	wildcard.
 * @wildcard_path
 *	Wildcard path to expand, which may contain the '?' and '*' characters.
 *	Path separators must be WIM_PATH_SEPARATOR.  Leading path separators are
 *	ignored, whereas one or more trailing path separators indicate that the
 *	wildcard path can only match directories (and not reparse points).
 * @consume_dentry
 *	Callback function which will receive each directory entry matched by the
 *	wildcard.
 * @consume_dentry_ctx
 *	Argument to pass to @consume_dentry.
 * @flags
 *	Zero or more of the following flags:
 *
 *	WILDCARD_FLAG_WARN_IF_NO_MATCH:
 *		Issue a warning if the wildcard does not match any dentries.
 *
 *	WILDCARD_FLAG_ERROR_IF_NO_MATCH:
 *		Issue an error and return WIMLIB_ERR_PATH_DOES_NOT_EXIST if the
 *		wildcard does not match any dentries.
 *
 *	WILDCARD_FLAG_CASE_INSENSITIVE:
 *		Perform the matching case insensitively.  Note that this may
 *		cause @wildcard to match multiple dentries, even if it does not
 *		contain wildcard characters.
 *
 * @return 0 on success; a positive error code on error; or the first nonzero
 * value returned by @consume_dentry.
 */
int
expand_wildcard(WIMStruct *wim,
		const tchar *wildcard_path,
		int (*consume_dentry)(struct wim_dentry *, void *),
		void *consume_dentry_ctx,
		u32 flags)
{
	struct wim_dentry *root;
	int ret;

	root = wim_get_current_root_dentry(wim);
	if (root == NULL)
		goto no_match;

	struct match_dentry_ctx ctx = {
		.consume_dentry = consume_dentry,
		.consume_dentry_ctx = consume_dentry_ctx,
		.consume_dentry_count = 0,
		.wildcard_path = TSTRDUP(wildcard_path),
		.cur_component_offset = 0,
		.cur_component_len = 0,
		.case_insensitive = ((flags & WILDCARD_FLAG_CASE_INSENSITIVE) != 0),
	};

	if (ctx.wildcard_path == NULL)
		return WIMLIB_ERR_NOMEM;

	ret = expand_wildcard_recursive(root, &ctx);
	FREE(ctx.wildcard_path);
	if (ret == 0 && ctx.consume_dentry_count == 0)
		goto no_match;
	return ret;

no_match:
	ret = 0;
	if (flags & WILDCARD_FLAG_WARN_IF_NO_MATCH)
		WARNING("No matches for wildcard path \"%"TS"\"", wildcard_path);

	if (flags & WILDCARD_FLAG_ERROR_IF_NO_MATCH) {
		ERROR("No matches for wildcard path \"%"TS"\"", wildcard_path);
		ret = WIMLIB_ERR_PATH_DOES_NOT_EXIST;
	}
	return ret;
}
