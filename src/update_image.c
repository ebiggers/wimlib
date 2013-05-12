/*
 * update_image.c - Update a WIM image.
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

#include "wimlib_internal.h"
#include "dentry.h"
#include "lookup_table.h"
#include "security.h"
#include "xml.h"
#include <errno.h>

/* Overlays @branch onto @target, both of which must be directories. */
static int
do_overlay(struct wim_dentry *target, struct wim_dentry *branch)
{
	struct rb_root *rb_root;

	DEBUG("Doing overlay \"%"WS"\" => \"%"WS"\"",
	      branch->file_name, target->file_name);

	if (!dentry_is_directory(branch) || !dentry_is_directory(target)) {
		ERROR("Cannot overlay \"%"WS"\" onto existing dentry: "
		      "is not directory-on-directory!", branch->file_name);
		return WIMLIB_ERR_INVALID_OVERLAY;
	}

	rb_root = &branch->d_inode->i_children;
	while (rb_root->rb_node) { /* While @branch has children... */
		struct wim_dentry *child = rbnode_dentry(rb_root->rb_node);
		struct wim_dentry *existing;

		/* Move @child to the directory @target */
		unlink_dentry(child);
		existing = dentry_add_child(target, child);

		/* File or directory with same name already exists */
		if (existing) {
			int ret;
			ret = do_overlay(existing, child);
			if (ret) {
				/* Overlay failed.  Revert the change to avoid
				 * leaking the directory tree rooted at @child.
				 * */
				dentry_add_child(branch, child);
				return ret;
			}
		}
	}
	free_dentry(branch);
	return 0;
}

/* Attach or overlay a branch onto the WIM image.
 *
 * @root_p:
 * 	Pointer to the root of the WIM image, or pointer to NULL if it has not
 * 	been created yet.
 * @branch
 * 	Branch to add.
 * @target_path:
 * 	Path in the WIM image to add the branch, with leading and trailing
 * 	slashes stripped.
 */
static int
attach_branch(struct wim_dentry **root_p, struct wim_dentry *branch,
	      tchar *target_path)
{
	tchar *slash;
	struct wim_dentry *dentry, *parent, *target;
	int ret;

	DEBUG("Attaching branch \"%"WS"\" => \"%"TS"\"",
	      branch->file_name, target_path);

	if (*target_path == T('\0')) {
		/* Target: root directory */
		if (*root_p) {
			/* Overlay on existing root */
			return do_overlay(*root_p, branch);
		} else {
			if (!dentry_is_directory(branch)) {
				ERROR("Cannot set non-directory as root of WIM image");
				return WIMLIB_ERR_NOTDIR;
			}
			/* Set as root */
			*root_p = branch;
			return 0;
		}
	}

	/* Adding a non-root branch.  Create root if it hasn't been created
	 * already. */
	if (!*root_p) {
		ret  = new_filler_directory(T(""), root_p);
		if (ret)
			return ret;
	}

	/* Walk the path to the branch, creating filler directories as needed.
	 * */
	parent = *root_p;
	while ((slash = tstrchr(target_path, T('/')))) {
		*slash = T('\0');
		dentry = get_dentry_child_with_name(parent, target_path);
		if (!dentry) {
			ret = new_filler_directory(target_path, &dentry);
			if (ret)
				return ret;
			dentry_add_child(parent, dentry);
		}
		parent = dentry;
		target_path = slash;
		/* Skip over slashes.  Note: this cannot overrun the length of
		 * the string because the last character cannot be a slash, as
		 * trailing slashes were tripped.  */
		do {
			++target_path;
		} while (*target_path == T('/'));
	}

	/* If the target path already existed, overlay the branch onto it.
	 * Otherwise, set the branch as the target path. */
	target = get_dentry_child_with_utf16le_name(parent, branch->file_name,
						    branch->file_name_nbytes);
	if (target) {
		return do_overlay(target, branch);
	} else {
		dentry_add_child(parent, branch);
		return 0;
	}
}

static int
execute_add_command(WIMStruct *wim,
		    const struct wimlib_update_command *add_cmd,
		    wimlib_progress_func_t progress_func)
{
	int ret;
	int add_flags;
	tchar *fs_source_path;
	tchar *wim_target_path;
	struct wim_inode_table inode_table;
	struct sd_set sd_set;
	struct wim_image_metadata *imd;
	struct list_head unhashed_streams;
	struct add_image_params params;
	int (*capture_tree)(struct wim_dentry **,
			    const tchar *,
			    struct add_image_params *);
	union wimlib_progress_info progress;
	struct wimlib_capture_config *config;
#ifdef WITH_NTFS_3G
	struct _ntfs_volume *ntfs_vol = NULL;
#endif
	void *extra_arg;
	struct wim_dentry *branch;
	bool rollback_sd = true;

	wimlib_assert(add_cmd->op == WIMLIB_UPDATE_OP_ADD);
	add_flags = add_cmd->add.add_flags;
	fs_source_path = add_cmd->add.fs_source_path;
	wim_target_path = add_cmd->add.wim_target_path;
	config = add_cmd->add.config;
	DEBUG("fs_source_path=\"%"TS"\", wim_target_path=\"%"TS"\", add_flags=%#x",
	      fs_source_path, wim_target_path, add_flags);

	imd = wim->image_metadata[wim->current_image - 1];

	if (add_flags & WIMLIB_ADD_FLAG_NTFS) {
	#ifdef WITH_NTFS_3G
		capture_tree = build_dentry_tree_ntfs;
		extra_arg = &ntfs_vol;
		if (imd->ntfs_vol != NULL) {
			ERROR("NTFS volume already set");
			ret = WIMLIB_ERR_INVALID_PARAM;
			goto out;
		}
	#else
		ret = WIMLIB_ERR_INVALID_PARAM;
		goto out;
	#endif
	} else {
	#ifdef __WIN32__
		capture_tree = win32_build_dentry_tree;
	#else
		capture_tree = unix_build_dentry_tree;
	#endif
		extra_arg = NULL;
	}

	ret = init_inode_table(&inode_table, 9001);
	if (ret)
		goto out;

	ret = init_sd_set(&sd_set, imd->security_data);
	if (ret)
		goto out_destroy_inode_table;

	INIT_LIST_HEAD(&unhashed_streams);
	wim->lookup_table->unhashed_streams = &unhashed_streams;
	params.lookup_table = wim->lookup_table;
	params.inode_table = &inode_table;
	params.sd_set = &sd_set;
	params.config = config;
	params.add_flags = add_flags;
	params.progress_func = progress_func;
	params.extra_arg = extra_arg;

	if (progress_func) {
		memset(&progress, 0, sizeof(progress));
		progress.scan.source = fs_source_path;
		progress.scan.wim_target_path = wim_target_path;
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_BEGIN, &progress);
	}
	config->_prefix = fs_source_path;
	config->_prefix_num_tchars = tstrlen(fs_source_path);

	if (wim_target_path[0] == T('\0'))
		add_flags |= WIMLIB_ADD_FLAG_ROOT;
	ret = (*capture_tree)(&branch, fs_source_path, &params);
	if (ret) {
		ERROR("Failed to build dentry tree for \"%"TS"\"",
		      fs_source_path);
		goto out_destroy_sd_set;
	}
	if (branch) {
		/* Use the target name, not the source name, for
		 * the root of each branch from a capture
		 * source.  (This will also set the root dentry
		 * of the entire image to be unnamed.) */
		ret = set_dentry_name(branch,
				      path_basename(wim_target_path));
		if (ret)
			goto out_ntfs_umount;

		ret = attach_branch(&imd->root_dentry, branch, wim_target_path);
		if (ret)
			goto out_ntfs_umount;
	}
	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_END, &progress);
	list_splice_tail(&unhashed_streams, &imd->unhashed_streams);
#ifdef WITH_NTFS_3G
	imd->ntfs_vol = ntfs_vol;
#endif
	inode_table_prepare_inode_list(&inode_table, &imd->inode_list);
	ret = 0;
	rollback_sd = false;
	if (add_flags & WIMLIB_ADD_FLAG_RPFIX)
		wim->hdr.flags |= WIM_HDR_FLAG_RP_FIX;
	goto out_destroy_sd_set;
out_ntfs_umount:
#ifdef WITH_NTFS_3G
	if (ntfs_vol)
		do_ntfs_umount(ntfs_vol);
#endif
	free_dentry_tree(branch, wim->lookup_table);
out_destroy_sd_set:
	destroy_sd_set(&sd_set, rollback_sd);
out_destroy_inode_table:
	destroy_inode_table(&inode_table);
out:
	return ret;
}

static int
execute_delete_command(WIMStruct *wim,
		       const struct wimlib_update_command *delete_cmd)
{
	int flags;
	const tchar *wim_path;
	struct wim_dentry *tree;
	bool is_root;

	wimlib_assert(delete_cmd->op == WIMLIB_UPDATE_OP_DELETE);
	flags = delete_cmd->delete.delete_flags;
	wim_path = delete_cmd->delete.wim_path;

	tree = get_dentry(wim, wim_path);
	if (!tree) {
		/* Path to delete does not exist in the WIM. */
		if (flags & WIMLIB_DELETE_FLAG_FORCE) {
			return 0;
		} else {
			ERROR("Path \"%"TS"\" does not exist in WIM image %d",
			      wim_path, wim->current_image);
			return WIMLIB_ERR_PATH_DOES_NOT_EXIST;
		}
	}

	if (dentry_is_directory(tree) && !(flags & WIMLIB_DELETE_FLAG_RECURSIVE)) {
		ERROR("Path \"%"TS"\" in WIM image %d is a directory "
		      "but a recursive delete was not requested",
		      wim_path, wim->current_image);
		return WIMLIB_ERR_IS_DIRECTORY;
	}

	is_root = dentry_is_root(tree);
	unlink_dentry(tree);
	free_dentry_tree(tree, wim->lookup_table);
	if (is_root)
		wim->image_metadata[wim->current_image - 1]->root_dentry = NULL;
	return 0;
}

/* 
 * Rename a file or directory in the WIM.
 *
 * This is also called from wimfs_rename() in the FUSE mount code.
 */
int
rename_wim_path(WIMStruct *wim, const tchar *from, const tchar *to)
{
	struct wim_dentry *src;
	struct wim_dentry *dst;
	struct wim_dentry *parent_of_dst;
	int ret;

	/* This rename() implementation currently only supports actual files
	 * (not alternate data streams) */

	src = get_dentry(wim, from);
	if (!src)
		return -errno;

	dst = get_dentry(wim, to);

	if (dst) {
		/* Destination file exists */

		if (src == dst) /* Same file */
			return 0;

		if (!dentry_is_directory(src)) {
			/* Cannot rename non-directory to directory. */
			if (dentry_is_directory(dst))
				return -EISDIR;
		} else {
			/* Cannot rename directory to a non-directory or a non-empty
			 * directory */
			if (!dentry_is_directory(dst))
				return -ENOTDIR;
			if (inode_has_children(dst->d_inode))
				return -ENOTEMPTY;
		}
		parent_of_dst = dst->parent;
	} else {
		/* Destination does not exist */
		parent_of_dst = get_parent_dentry(wim, to);
		if (!parent_of_dst)
			return -errno;

		if (!dentry_is_directory(parent_of_dst))
			return -ENOTDIR;
	}

	ret = set_dentry_name(src, path_basename(to));
	if (ret)
		return -ENOMEM;
	if (dst) {
		unlink_dentry(dst);
		free_dentry_tree(dst, wim->lookup_table);
	}
	unlink_dentry(src);
	dentry_add_child(parent_of_dst, src);
	return 0;
}


static int
execute_rename_command(WIMStruct *wim,
		       const struct wimlib_update_command *rename_cmd)
{
	int ret;

	wimlib_assert(rename_cmd->op == WIMLIB_UPDATE_OP_RENAME);

	ret = rename_wim_path(wim, rename_cmd->rename.wim_source_path,
			      rename_cmd->rename.wim_target_path);
	if (ret) {
		switch (ret) {
		case -ENOMEM:
			ret = WIMLIB_ERR_NOMEM;
			break;
		case -ENOTDIR:
			ret = WIMLIB_ERR_NOTDIR;
			break;
		case -ENOTEMPTY:
			ret = WIMLIB_ERR_NOTEMPTY;
			break;
		case -EISDIR:
			ret = WIMLIB_ERR_IS_DIRECTORY;
			break;
		case -ENOENT:
		default:
			ret = WIMLIB_ERR_PATH_DOES_NOT_EXIST;
			break;
		}
	}
	return ret;
}

static inline const tchar *
update_op_to_str(int op)
{
	switch (op) {
	case WIMLIB_UPDATE_OP_ADD:
		return T("add");
	case WIMLIB_UPDATE_OP_DELETE:
		return T("delete");
	case WIMLIB_UPDATE_OP_RENAME:
		return T("rename");
	default:
		return T("???");
	}
}

static int
execute_update_commands(WIMStruct *wim,
			const struct wimlib_update_command *cmds,
			size_t num_cmds,
			wimlib_progress_func_t progress_func)
{
	int ret = 0;
	for (size_t i = 0; i < num_cmds; i++) {
		DEBUG("Executing update command %zu of %zu (op=%"TS")",
		      i + 1, num_cmds, update_op_to_str(cmds[i].op));
		switch (cmds[i].op) {
		case WIMLIB_UPDATE_OP_ADD:
			ret = execute_add_command(wim, &cmds[i], progress_func);
			break;
		case WIMLIB_UPDATE_OP_DELETE:
			ret = execute_delete_command(wim, &cmds[i]);
			if (ret == 0)
				wim->deletion_occurred = 1;
			break;
		case WIMLIB_UPDATE_OP_RENAME:
			ret = execute_rename_command(wim, &cmds[i]);
			break;
		default:
			wimlib_assert(0);
			break;
		}
		if (ret)
			break;
	}
	return ret;
}

static int
check_add_command(struct wimlib_update_command *cmd,
		  const struct wim_header *hdr)
{
	int add_flags = cmd->add.add_flags;

	/* Are we adding the entire image or not?  An empty wim_target_path
	 * indicates that the tree we're adding is to be placed in the root of
	 * the image.  We consider this to be capturing the entire image,
	 * although it could potentially be an overlay on an existing root as
	 * well. */
	bool is_entire_image = cmd->add.wim_target_path[0] == T('\0');

#ifdef __WIN32__
	/* Check for flags not supported on Windows */
	if (add_flags & WIMLIB_ADD_FLAG_NTFS) {
		ERROR("wimlib was compiled without support for NTFS-3g, so");
		ERROR("we cannot capture a WIM image directly from a NTFS volume");
		return WIMLIB_ERR_UNSUPPORTED;
	}
	if (add_flags & WIMLIB_ADD_FLAG_UNIX_DATA) {
		ERROR("Capturing UNIX-specific data is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (add_flags & WIMLIB_ADD_FLAG_DEREFERENCE) {
		ERROR("Dereferencing symbolic links is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
#endif

	/* VERBOSE implies EXCLUDE_VERBOSE */
	if (add_flags & WIMLIB_ADD_FLAG_VERBOSE)
		add_flags |= WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE;

	/* Check for contradictory reparse point fixup flags */
	if ((add_flags & (WIMLIB_ADD_FLAG_RPFIX |
			  WIMLIB_ADD_FLAG_NORPFIX)) ==
		(WIMLIB_ADD_FLAG_RPFIX |
		 WIMLIB_ADD_FLAG_NORPFIX))
	{
		ERROR("Cannot specify RPFIX and NORPFIX flags "
		      "at the same time!");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	/* Set default behavior on reparse point fixups if requested */
	if ((add_flags & (WIMLIB_ADD_FLAG_RPFIX |
			  WIMLIB_ADD_FLAG_NORPFIX)) == 0)
	{
		/* Do reparse-point fixups by default if we are capturing an
		 * entire image and either the header flag is set from previous
		 * images, or if this is the first image being added. */
		if (is_entire_image &&
		    ((hdr->flags & WIM_HDR_FLAG_RP_FIX) || hdr->image_count == 1))
			add_flags |= WIMLIB_ADD_FLAG_RPFIX;
	}

	if (!is_entire_image) {
		if (add_flags & WIMLIB_ADD_FLAG_NTFS) {
			ERROR("Cannot add directly from a NTFS volume "
			      "when not capturing a full image!");
			return WIMLIB_ERR_INVALID_PARAM;
		}

		if (add_flags & WIMLIB_ADD_FLAG_RPFIX) {
			ERROR("Cannot do reparse point fixups when "
			      "not capturing a full image!");
			return WIMLIB_ERR_INVALID_PARAM;
		}
	}
	/* We may have modified the add flags. */
	cmd->add.add_flags = add_flags;
	return 0;
}

static int
check_update_command(struct wimlib_update_command *cmd,
		     const struct wim_header *hdr)
{
	switch (cmd->op) {
	case WIMLIB_UPDATE_OP_ADD:
		return check_add_command(cmd, hdr);
	case WIMLIB_UPDATE_OP_DELETE:
	case WIMLIB_UPDATE_OP_RENAME:
		break;
	}
	return 0;
}

static int
check_update_commands(struct wimlib_update_command *cmds, size_t num_cmds,
		      const struct wim_header *hdr)
{
	int ret = 0;
	for (size_t i = 0; i < num_cmds; i++) {
		ret = check_update_command(&cmds[i], hdr);
		if (ret)
			break;
	}
	return ret;
}


extern void
free_update_commands(struct wimlib_update_command *cmds, size_t num_cmds)
{
	if (cmds) {
		for (size_t i = 0; i < num_cmds; i++) {
			switch (cmds->op) {
			case WIMLIB_UPDATE_OP_ADD:
				FREE(cmds[i].add.fs_source_path);
				FREE(cmds[i].add.wim_target_path);
				free_capture_config(cmds[i].add.config);
				break;
			case WIMLIB_UPDATE_OP_DELETE:
				FREE(cmds[i].delete.wim_path);
				break;
			case WIMLIB_UPDATE_OP_RENAME:
				FREE(cmds[i].rename.wim_source_path);
				FREE(cmds[i].rename.wim_target_path);
				break;
			}
		}
		FREE(cmds);
	}
}

static int
copy_update_commands(const struct wimlib_update_command *cmds,
		     size_t num_cmds,
		     struct wimlib_update_command **cmds_copy_ret)
{
	int ret;
	struct wimlib_update_command *cmds_copy;

	cmds_copy = CALLOC(num_cmds, sizeof(cmds[0]));
	if (!cmds_copy)
		goto oom;

	for (size_t i = 0; i < num_cmds; i++) {
		cmds_copy[i].op = cmds[i].op;
		switch (cmds[i].op) {
		case WIMLIB_UPDATE_OP_ADD:
			cmds_copy[i].add.fs_source_path =
				canonicalize_fs_path(cmds[i].add.fs_source_path);
			cmds_copy[i].add.wim_target_path =
				canonicalize_wim_path(cmds[i].add.wim_target_path);
			if (!cmds_copy[i].add.fs_source_path ||
			    !cmds_copy[i].add.wim_target_path)
				goto oom;
			if (cmds[i].add.config) {
				ret = copy_and_canonicalize_capture_config(cmds[i].add.config,
									   &cmds_copy[i].add.config);
				if (ret)
					goto err;
			}
			cmds_copy[i].add.add_flags = cmds[i].add.add_flags;
			break;
		case WIMLIB_UPDATE_OP_DELETE:
			cmds_copy[i].delete.wim_path =
				canonicalize_wim_path(cmds[i].delete.wim_path);
			if (!cmds_copy[i].delete.wim_path)
				goto oom;
			cmds_copy[i].delete.delete_flags = cmds[i].delete.delete_flags;
			break;
		case WIMLIB_UPDATE_OP_RENAME:
			cmds_copy[i].rename.wim_source_path =
				canonicalize_wim_path(cmds[i].rename.wim_source_path);
			cmds_copy[i].rename.wim_target_path =
				canonicalize_wim_path(cmds[i].rename.wim_target_path);
			if (!cmds_copy[i].rename.wim_source_path ||
			    !cmds_copy[i].rename.wim_target_path)
				goto oom;
			break;
		default:
			ERROR("Unknown update operation %u", cmds[i].op);
			ret = WIMLIB_ERR_INVALID_PARAM;
			goto err;
		}
	}
	*cmds_copy_ret = cmds_copy;
	ret = 0;
out:
	return ret;
oom:
	ret = WIMLIB_ERR_NOMEM;
err:
	free_update_commands(cmds_copy, num_cmds);
	goto out;
}

/*
 * Entry point for making a series of updates to a WIM image.
 */
WIMLIBAPI int
wimlib_update_image(WIMStruct *wim,
		    int image,
		    const struct wimlib_update_command *cmds,
		    size_t num_cmds,
		    int update_flags,
		    wimlib_progress_func_t progress_func)
{
	int ret;
	struct wimlib_update_command *cmds_copy;

	DEBUG("Updating image %d with %zu commands", image, num_cmds);

	/* Refuse to update a split WIM. */
	if (wim->hdr.total_parts != 1) {
		ERROR("Cannot update a split WIM!");
		ret = WIMLIB_ERR_SPLIT_UNSUPPORTED;
		goto out;
	}

	/* Load the metadata for the image to modify (if not loaded already) */
	ret = select_wim_image(wim, image);
	if (ret)
		goto out;

	/* Short circuit a successful return if no commands were specified.
	 * Avoids problems with trying to allocate 0 bytes of memory. */
	if (num_cmds == 0)
		goto out;

	DEBUG("Preparing %zu update commands", num_cmds);

	/* Make a copy of the update commands, in the process doing certain
	 * canonicalizations on paths (e.g. translating backslashes to forward
	 * slashes).  This is done to avoid modifying the caller's copy of the
	 * commands. */
	ret = copy_update_commands(cmds, num_cmds, &cmds_copy);
	if (ret)
		goto out;

	/* Perform additional checks on the update commands before we execute
	 * them. */
	ret = check_update_commands(cmds_copy, num_cmds, &wim->hdr);
	if (ret)
		goto out_free_cmds_copy;

	/* Actually execute the update commands. */
	DEBUG("Executing %zu update commands", num_cmds);
	ret = execute_update_commands(wim, cmds_copy, num_cmds, progress_func);
	if (ret)
		goto out_free_cmds_copy;

	wim->image_metadata[image - 1]->modified = 1;

	/* Statistics about the WIM image, such as the numbers of files and
	 * directories, may have changed.  Call xml_update_image_info() to
	 * recalculate these statistics. */
	xml_update_image_info(wim, image);
out_free_cmds_copy:
	free_update_commands(cmds_copy, num_cmds);
out:
	return ret;
}
