/*
 * wildcard.c
 *
 * Wildcard matching functions.
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

#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/metadata.h"
#include "wimlib/wildcard.h"

struct match_dentry_ctx {
	int (*consume_path)(const tchar *, void *, bool);
	void *consume_path_ctx;
	size_t consume_path_count;
	tchar *expanded_path;
	size_t expanded_path_len;
	size_t expanded_path_alloc_len;
	tchar *wildcard_path;
	size_t cur_component_offset;
	size_t cur_component_len;
	bool case_insensitive;
};

static bool
match_wildcard(const tchar *string, tchar *wildcard,
	       size_t wildcard_len, bool case_insensitive)
{
	char orig;
	int flags;
	int ret;

	orig = wildcard[wildcard_len];
	wildcard[wildcard_len] = T('\0');

	/* Warning: in Windows builds fnmatch() calls a replacement function.
	 * Also, FNM_CASEFOLD is a GNU extension and it is defined to 0 if not
	 * available.  */
	flags = FNM_NOESCAPE;
	if (case_insensitive)
		flags |= FNM_CASEFOLD;
	ret = fnmatch(wildcard, string, flags);

	wildcard[wildcard_len] = orig;
	return (ret == 0);
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
	while (is_any_path_separator(*wildcard))
		wildcard++;
	if (*wildcard == T('\0'))
		return WILDCARD_STATUS_DONE_TRAILING_SLASHES;

	return WILDCARD_STATUS_NOT_DONE;
}

static int
match_dentry(struct wim_dentry *cur_dentry, void *_ctx)
{
	struct match_dentry_ctx *ctx = _ctx;
	tchar *name;
	size_t name_len;
	int ret;

	if (cur_dentry->file_name_nbytes == 0)
		return 0;

#if TCHAR_IS_UTF16LE
	name = cur_dentry->file_name;
	name_len = cur_dentry->file_name_nbytes;
#else
	ret = utf16le_to_tstr(cur_dentry->file_name,
			      cur_dentry->file_name_nbytes,
			      &name, &name_len);
	if (ret)
		return ret;
#endif
	name_len /= sizeof(tchar);

	if (match_wildcard(name,
			   &ctx->wildcard_path[ctx->cur_component_offset],
			   ctx->cur_component_len,
			   ctx->case_insensitive))
	{
		size_t len_needed = ctx->expanded_path_len + 1 + name_len + 1;
		size_t expanded_path_len_save;

		if (len_needed > ctx->expanded_path_alloc_len) {
			tchar *expanded_path;

			expanded_path = REALLOC(ctx->expanded_path,
						len_needed * sizeof(ctx->expanded_path[0]));
			if (expanded_path == NULL) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_name;
			}
			ctx->expanded_path = expanded_path;
			ctx->expanded_path_alloc_len = len_needed;
		}
		expanded_path_len_save = ctx->expanded_path_len;

		ctx->expanded_path[ctx->expanded_path_len++] = WIM_PATH_SEPARATOR;
		tmemcpy(&ctx->expanded_path[ctx->expanded_path_len],
			name, name_len);
		ctx->expanded_path_len += name_len;
		ctx->expanded_path[ctx->expanded_path_len] = T('\0');

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
			ret = (*ctx->consume_path)(ctx->expanded_path,
						   ctx->consume_path_ctx,
						   false);
			ctx->consume_path_count++;
			break;
		case WILDCARD_STATUS_NOT_DONE:
			ret = expand_wildcard_recursive(cur_dentry, ctx);
			break;
		}
		ctx->expanded_path_len = expanded_path_len_save;
		ctx->expanded_path[expanded_path_len_save] = T('\0');
	} else {
		ret = 0;
	}

out_free_name:
#if !TCHAR_IS_UTF16LE
	FREE(name);
#endif
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

	w = ctx->wildcard_path;

	begin = ctx->cur_component_offset + ctx->cur_component_len;
	while (is_any_path_separator(w[begin]))
		begin++;

	end = begin;

	while (w[end] != T('\0') && !is_any_path_separator(w[end]))
		end++;

	len = end - begin;

	if (len == 0)
		return 0;

	offset_save = ctx->cur_component_offset;
	len_save = ctx->cur_component_len;

	ctx->cur_component_offset = begin;
	ctx->cur_component_len = len;

	ret = for_dentry_child(cur_dentry, match_dentry, ctx);

	ctx->cur_component_len = len_save;
	ctx->cur_component_offset = offset_save;

	return ret;
}

static int
expand_wildcard(WIMStruct *wim,
		const tchar *wildcard_path,
		int (*consume_path)(const tchar *, void *, bool),
		void *consume_path_ctx,
		u32 flags)
{
	struct wim_dentry *root;
	int ret;

	root = wim_root_dentry(wim);
	if (root == NULL)
		goto no_match;

	struct match_dentry_ctx ctx = {
		.consume_path = consume_path,
		.consume_path_ctx = consume_path_ctx,
		.consume_path_count = 0,
		.expanded_path = MALLOC(256 * sizeof(ctx.expanded_path[0])),
		.expanded_path_len = 0,
		.expanded_path_alloc_len = 256,
		.wildcard_path = TSTRDUP(wildcard_path),
		.cur_component_offset = 0,
		.cur_component_len = 0,
		.case_insensitive = ((flags & WILDCARD_FLAG_CASE_INSENSITIVE) != 0),
	};

	if (ctx.expanded_path == NULL || ctx.wildcard_path == NULL) {
		FREE(ctx.expanded_path);
		FREE(ctx.wildcard_path);
		return WIMLIB_ERR_NOMEM;
	}

	ret = expand_wildcard_recursive(root, &ctx);
	FREE(ctx.expanded_path);
	FREE(ctx.wildcard_path);
	if (ret == 0 && ctx.consume_path_count == 0)
		goto no_match;
	return ret;

no_match:
	ret = 0;
	if (flags & WILDCARD_FLAG_USE_LITERAL_IF_NO_MATCHES)
		ret = (*consume_path)(wildcard_path, consume_path_ctx, true);

	if (flags & WILDCARD_FLAG_WARN_IF_NO_MATCH)
		WARNING("No matches for wildcard path \"%"TS"\"", wildcard_path);

	if (flags & WILDCARD_FLAG_ERROR_IF_NO_MATCH) {
		ERROR("No matches for wildcard path \"%"TS"\"", wildcard_path);
		ret = WIMLIB_ERR_PATH_DOES_NOT_EXIST;
	}
	return ret;
}

struct expanded_paths_ctx {
	tchar **expanded_paths;
	size_t num_expanded_paths;
	size_t alloc_length;
};

static int
append_path_cb(const tchar *path, void *_ctx, bool may_need_trans)
{
	struct expanded_paths_ctx *ctx = _ctx;
	tchar *path_dup;

	if (ctx->num_expanded_paths == ctx->alloc_length) {
		tchar **new_paths;
		size_t new_alloc_length = max(ctx->alloc_length + 8,
					      ctx->alloc_length * 3 / 2);

		new_paths = REALLOC(ctx->expanded_paths,
				    new_alloc_length * sizeof(new_paths[0]));
		if (new_paths == NULL)
			return WIMLIB_ERR_NOMEM;
		ctx->expanded_paths = new_paths;
		ctx->alloc_length = new_alloc_length;
	}
	path_dup = TSTRDUP(path);
	if (path_dup == NULL)
		return WIMLIB_ERR_NOMEM;
	if (may_need_trans) {
		for (tchar *p = path_dup; *p; p++)
			if (is_any_path_separator(*p))
				*p = WIM_PATH_SEPARATOR;
	}
	ctx->expanded_paths[ctx->num_expanded_paths++] = path_dup;
	return 0;
}

int
expand_wildcard_wim_paths(WIMStruct *wim,
			  const char * const *wildcards,
			  size_t num_wildcards,
			  tchar ***expanded_paths_ret,
			  size_t *num_expanded_paths_ret,
			  u32 flags)
{
	int ret;
	struct expanded_paths_ctx ctx = {
		.expanded_paths = NULL,
		.num_expanded_paths = 0,
		.alloc_length = 0,
	};
	for (size_t i = 0; i < num_wildcards; i++) {
		ret = expand_wildcard(wim, wildcards[i], append_path_cb, &ctx,
				      flags);
		if (ret)
			goto out_free;
	}
	*expanded_paths_ret = ctx.expanded_paths;
	*num_expanded_paths_ret = ctx.num_expanded_paths;
	return 0;

out_free:
	for (size_t i = 0; i < ctx.num_expanded_paths; i++)
		FREE(ctx.expanded_paths[i]);
	FREE(ctx.expanded_paths);
	return ret;
}
