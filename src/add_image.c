/*
 * add_image.c - Add an image to a WIM file.
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
#include "wimlib/capture.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/xml.h"

/*
 * Adds the dentry tree and security data for a new image to the image metadata
 * array of the WIMStruct.
 */
static int
add_new_dentry_tree(WIMStruct *wim, struct wim_dentry *root_dentry,
		    struct wim_security_data *sd)
{
	struct wim_image_metadata *new_imd;
	struct wim_lookup_table_entry *metadata_lte;
	int ret;

	metadata_lte = new_lookup_table_entry();
	if (!metadata_lte)
		return WIMLIB_ERR_NOMEM;

	metadata_lte->resource_entry.flags = WIM_RESHDR_FLAG_METADATA;
	metadata_lte->unhashed = 1;

	new_imd = new_image_metadata();
	if (!new_imd) {
		free_lookup_table_entry(metadata_lte);
		return WIMLIB_ERR_NOMEM;
	}

	new_imd->root_dentry	= root_dentry;
	new_imd->metadata_lte	= metadata_lte;
	new_imd->security_data  = sd;
	new_imd->modified	= 1;

	ret = append_image_metadata(wim, new_imd);
	if (ret)
		put_image_metadata(new_imd, NULL);
	return ret;
}

/* Append an empty image to the WIMStruct. */
WIMLIBAPI int
wimlib_add_empty_image(WIMStruct *wim, const tchar *name, int *new_idx_ret)
{
	int ret;
	struct wim_security_data *sd;

	DEBUG("Adding empty image \"%"TS"\"", name);

	if (name == NULL)
		name = T("");

	ret = can_modify_wim(wim);
	if (ret)
		goto out;

	if (wimlib_image_name_in_use(wim, name)) {
		ERROR("There is already an image named \"%"TS"\" in the WIM!",
		      name);
		ret = WIMLIB_ERR_IMAGE_NAME_COLLISION;
		goto out;
	}

	sd = new_wim_security_data();
	if (!sd) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	ret = add_new_dentry_tree(wim, NULL, sd);
	if (ret)
		goto out_free_security_data;

	ret = xml_add_image(wim, name);
	if (ret)
		goto out_put_image_metadata;

	if (new_idx_ret)
		*new_idx_ret = wim->hdr.image_count;
	DEBUG("Successfully added new image (index %d)",
	      wim->hdr.image_count);
	goto out;
out_put_image_metadata:
	put_image_metadata(wim->image_metadata[--wim->hdr.image_count],
			   wim->lookup_table);
	goto out;
out_free_security_data:
	free_wim_security_data(sd);
out:
	return ret;
}

static struct wimlib_update_command *
capture_sources_to_add_cmds(const struct wimlib_capture_source *sources,
			    size_t num_sources,
			    int add_flags,
			    const struct wimlib_capture_config *config)
{
	struct wimlib_update_command *add_cmds;

	DEBUG("Translating %zu capture sources to `struct wimlib_update_command's",
	      num_sources);
	add_cmds = CALLOC(num_sources, sizeof(add_cmds[0]));
	if (add_cmds) {
		for (size_t i = 0; i < num_sources; i++) {
			DEBUG("Source %zu of %zu: fs_source_path=\"%"TS"\", "
			      "wim_target_path=\"%"TS"\"",
			      i + 1, num_sources,
			      sources[i].fs_source_path,
			      sources[i].wim_target_path);
			add_cmds[i].op = WIMLIB_UPDATE_OP_ADD;
			add_cmds[i].add.add_flags = add_flags;
			add_cmds[i].add.config = (struct wimlib_capture_config*)config;
			add_cmds[i].add.fs_source_path = sources[i].fs_source_path;
			add_cmds[i].add.wim_target_path = sources[i].wim_target_path;
		}
	}
	return add_cmds;
}

/* Adds an image to the WIMStruct from multiple on-disk directory trees, or a
 * NTFS volume. */
WIMLIBAPI int
wimlib_add_image_multisource(WIMStruct *wim,
			     const struct wimlib_capture_source *sources,
			     size_t num_sources,
			     const tchar *name,
			     const struct wimlib_capture_config *config,
			     int add_flags,
			     wimlib_progress_func_t progress_func)
{
	int ret;
	struct wimlib_update_command *add_cmds;

	DEBUG("Adding image \"%"TS"\" from %zu sources (add_flags=%#x)",
	      name, num_sources, add_flags);

	/* Add the new image (initially empty) */
	ret = wimlib_add_empty_image(wim, name, NULL);
	if (ret)
		goto out;

	/* Translate the "capture sources" into generic update commands. */
	add_cmds = capture_sources_to_add_cmds(sources, num_sources,
					       add_flags, config);
	if (!add_cmds) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_delete_image;
	}

	/* Delegate the work to wimlib_update_image(). */
	ret = wimlib_update_image(wim, wim->hdr.image_count, add_cmds,
				  num_sources, 0, progress_func);
	FREE(add_cmds);
	if (ret)
		goto out_delete_image;

	/* Success; set boot index if requested. */
	if (add_flags & WIMLIB_ADD_FLAG_BOOT)
		wim->hdr.boot_idx = wim->hdr.image_count;
	ret = 0;
	goto out;
out_delete_image:
	/* Roll back the image we added */
	put_image_metadata(wim->image_metadata[wim->hdr.image_count - 1],
			   wim->lookup_table);
	xml_delete_image(&wim->wim_info, wim->hdr.image_count);
	wim->hdr.image_count--;
out:
	return ret;
}

/* Adds an image to the WIMStruct from an on-disk directory tree or NTFS volume. */
WIMLIBAPI int
wimlib_add_image(WIMStruct *wim,
		 const tchar *source,
		 const tchar *name,
		 const struct wimlib_capture_config *config,
		 int add_flags,
		 wimlib_progress_func_t progress_func)
{
	/* Delegate the work to the more general wimlib_add_image_multisource().
	 * */
	const struct wimlib_capture_source capture_src = {
		.fs_source_path = (tchar*)source,
		.wim_target_path = T(""),
		.reserved = 0,
	};
	return wimlib_add_image_multisource(wim, &capture_src, 1, name,
					    config, add_flags,
					    progress_func);
}
