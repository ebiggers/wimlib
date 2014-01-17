/*
 * reference.c
 *
 * Reference resources from external WIM file(s).
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

#include "wimlib.h"
#include "wimlib/error.h"
#include "wimlib/glob.h"
#include "wimlib/lookup_table.h"
#include "wimlib/wim.h"

#define WIMLIB_REF_MASK_PUBLIC (WIMLIB_REF_FLAG_GLOB_ENABLE | \
				WIMLIB_REF_FLAG_GLOB_ERR_ON_NOMATCH)

static int
lte_clone_if_new(struct wim_lookup_table_entry *lte, void *_lookup_table)
{
	struct wim_lookup_table *lookup_table = _lookup_table;

	if (lookup_stream(lookup_table, lte->hash))
		return 0;  /*  Resource already present.  */

	lte = clone_lookup_table_entry(lte);
	if (lte == NULL)
		return WIMLIB_ERR_NOMEM;
	lte->out_refcnt = 1;
	lookup_table_insert(lookup_table, lte);
	return 0;
}

static int
lte_delete_if_new(struct wim_lookup_table_entry *lte, void *_lookup_table)
{
	struct wim_lookup_table *lookup_table = _lookup_table;

	if (lte->out_refcnt) {
		lookup_table_unlink(lookup_table, lte);
		free_lookup_table_entry(lte);
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_reference_resources(WIMStruct *wim,
			   WIMStruct **resource_wims, unsigned num_resource_wims,
			   int ref_flags)
{
	int ret;
	unsigned i;

	if (wim == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	if (num_resource_wims != 0 && resource_wims == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	if (ref_flags & ~WIMLIB_REF_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;

	for (i = 0; i < num_resource_wims; i++)
		if (resource_wims[i] == NULL)
			return WIMLIB_ERR_INVALID_PARAM;

	for_lookup_table_entry(wim->lookup_table, lte_zero_out_refcnt, NULL);

	for (i = 0; i < num_resource_wims; i++) {
		ret = for_lookup_table_entry(resource_wims[i]->lookup_table,
					     lte_clone_if_new,
					     wim->lookup_table);
		if (ret)
			goto out_rollback;
	}
	return 0;

out_rollback:
	for_lookup_table_entry(wim->lookup_table, lte_delete_if_new,
			       wim->lookup_table);
	return ret;
}

static int
reference_resource_paths(WIMStruct *wim,
			 const tchar * const *resource_wimfiles,
			 unsigned num_resource_wimfiles,
			 int ref_flags,
			 int open_flags,
			 wimlib_progress_func_t progress_func)
{
	WIMStruct **resource_wims;
	unsigned i;
	int ret;

	resource_wims = CALLOC(num_resource_wimfiles, sizeof(resource_wims[0]));
	if (!resource_wims)
		return WIMLIB_ERR_NOMEM;

	for (i = 0; i < num_resource_wimfiles; i++) {
		DEBUG("Referencing resources from path \"%"TS"\"",
		      resource_wimfiles[i]);
		ret = wimlib_open_wim(resource_wimfiles[i], open_flags,
				      &resource_wims[i], progress_func);
		if (ret)
			goto out_free_resource_wims;
	}

	ret = wimlib_reference_resources(wim, resource_wims,
					 num_resource_wimfiles, ref_flags);
	if (ret)
		goto out_free_resource_wims;

	for (i = 0; i < num_resource_wimfiles; i++)
		list_add_tail(&resource_wims[i]->subwim_node, &wim->subwims);

	ret = 0;
	goto out_free_array;

out_free_resource_wims:
	for (i = 0; i < num_resource_wimfiles; i++)
		wimlib_free(resource_wims[i]);
out_free_array:
	FREE(resource_wims);
	return ret;
}

static int
reference_resource_glob(WIMStruct *wim, const tchar *refglob,
			int ref_flags, int open_flags,
			wimlib_progress_func_t progress_func)
{
	glob_t globbuf;
	int ret;

	/* Note: glob() is replaced in Windows native builds.  */
	ret = tglob(refglob, GLOB_ERR | GLOB_NOSORT, NULL, &globbuf);
	if (ret) {
		if (ret == GLOB_NOMATCH) {
			if (ref_flags & WIMLIB_REF_FLAG_GLOB_ERR_ON_NOMATCH) {
				ERROR("Found no files for glob \"%"TS"\"", refglob);
				return WIMLIB_ERR_GLOB_HAD_NO_MATCHES;
			} else {
				return reference_resource_paths(wim,
								&refglob,
								1,
								ref_flags,
								open_flags,
								progress_func);
			}
		} else {
			ERROR_WITH_ERRNO("Failed to process glob \"%"TS"\"", refglob);
			if (ret == GLOB_NOSPACE)
				return WIMLIB_ERR_NOMEM;
			else
				return WIMLIB_ERR_READ;
		}
	}

	ret = reference_resource_paths(wim,
				       (const tchar * const *)globbuf.gl_pathv,
				       globbuf.gl_pathc,
				       ref_flags,
				       open_flags,
				       progress_func);
	globfree(&globbuf);
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_reference_resource_files(WIMStruct *wim,
				const tchar * const * resource_wimfiles_or_globs,
				unsigned count,
				int ref_flags,
				int open_flags,
				wimlib_progress_func_t progress_func)
{
	unsigned i;
	int ret;

	if (ref_flags & ~WIMLIB_REF_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;

	if (ref_flags & WIMLIB_REF_FLAG_GLOB_ENABLE) {
		for (i = 0; i < count; i++) {
			ret = reference_resource_glob(wim,
						      resource_wimfiles_or_globs[i],
						      ref_flags,
						      open_flags,
						      progress_func);
			if (ret)
				return ret;
		}
		return 0;
	} else {
		return reference_resource_paths(wim, resource_wimfiles_or_globs,
						count, ref_flags,
						open_flags, progress_func);
	}
}
