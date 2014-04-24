/*
 * update_image.c - Update a WIM image.
 */

/*
 * Copyright (C) 2013, 2014 Eric Biggers
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

#include "wimlib/capture.h"
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#ifdef WITH_NTFS_3G
#  include "wimlib/ntfs_3g.h" /* for do_ntfs_umount() */
#endif
#include "wimlib/paths.h"
#include "wimlib/xml.h"

#include <errno.h>
#include <sys/stat.h>

/* Overlays @branch onto @target, both of which must be directories. */
static int
do_overlay(struct wim_dentry *target, struct wim_dentry *branch)
{
	DEBUG("Doing overlay \"%"WS"\" => \"%"WS"\"",
	      branch->file_name, target->file_name);

	if (!dentry_is_directory(branch) || !dentry_is_directory(target)) {
		ERROR("Cannot overlay \"%"WS"\" onto existing dentry: "
		      "is not directory-on-directory!", branch->file_name);
		return WIMLIB_ERR_INVALID_OVERLAY;
	}

	LIST_HEAD(moved_children);
	while (dentry_has_children(branch)) {
		struct wim_dentry *child = dentry_any_child(branch);
		struct wim_dentry *existing;

		/* Move @child to the directory @target */
		unlink_dentry(child);
		existing = dentry_add_child(target, child);

		/* File or directory with same name already exists */
		if (existing) {
			int ret;
			ret = do_overlay(existing, child);
			if (ret) {
				/* Overlay failed.  Revert the changes. */
				dentry_add_child(branch, child);
				list_for_each_entry(child, &moved_children, tmp_list)
				{
					unlink_dentry(child);
					dentry_add_child(branch, child);
				}
				return ret;
			}
		} else {
			list_add(&child->tmp_list, &moved_children);
		}
	}
	free_dentry(branch);
	return 0;
}

/* Attach or overlay a branch onto the WIM image.
 *
 * @root_p:
 *	Pointer to the root of the WIM image, or pointer to NULL if it has not
 *	been created yet.
 * @branch
 *	Branch to add.
 * @target_path:
 *	Path in the WIM image to add the branch, with leading and trailing
 *	slashes stripped.
 */
static int
attach_branch(struct wim_dentry **root_p, struct wim_dentry *branch,
	      tchar *target_path, CASE_SENSITIVITY_TYPE case_type)
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
	while ((slash = tstrchr(target_path, WIM_PATH_SEPARATOR))) {
		*slash = T('\0');
		dentry = get_dentry_child_with_name(parent, target_path,
						    case_type);
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
		} while (*target_path == WIM_PATH_SEPARATOR);
	}

	/* If the target path already existed, overlay the branch onto it.
	 * Otherwise, set the branch as the target path. */
	target = get_dentry_child_with_utf16le_name(parent, branch->file_name,
						    branch->file_name_nbytes,
						    case_type);
	if (target) {
		return do_overlay(target, branch);
	} else {
		dentry_add_child(parent, branch);
		return 0;
	}
}

const tchar wincfg[] =
T(
"[ExclusionList]\n"
"/$ntfs.log\n"
"/hiberfil.sys\n"
"/pagefile.sys\n"
"/System Volume Information\n"
"/RECYCLER\n"
"/Windows/CSC\n"
);

static int
get_capture_config(const tchar *config_file, struct capture_config *config,
		   int add_flags, const tchar *fs_source_path)
{
	int ret;
	tchar *tmp_config_file = NULL;

	memset(config, 0, sizeof(*config));

	/* For WIMBoot capture, check for default capture configuration file
	 * unless one was explicitly specified.  */
	if (!config_file && (add_flags & WIMLIB_ADD_FLAG_WIMBOOT)) {

		/* XXX: Handle loading file correctly when in NTFS volume.  */

		const tchar *wimboot_cfgfile =
			T("/Windows/System32/WimBootCompress.ini");
		size_t len = tstrlen(fs_source_path) +
			     tstrlen(wimboot_cfgfile);
		tmp_config_file = MALLOC((len + 1) * sizeof(tchar));
		struct stat st;

		tsprintf(tmp_config_file, T("%"TS"%"TS),
			 fs_source_path, wimboot_cfgfile);
		if (!tstat(tmp_config_file, &st)) {
			config_file = tmp_config_file;
			add_flags &= ~WIMLIB_ADD_FLAG_WINCONFIG;
		} else {
			WARNING("\"%"TS"\" does not exist.\n"
				"          Using default capture configuration!",
				tmp_config_file);
		}
	}

	if (add_flags & WIMLIB_ADD_FLAG_WINCONFIG) {

		/* Use Windows default.  */

		tchar *wincfg_copy;
		const size_t wincfg_len = ARRAY_LEN(wincfg) - 1;

		if (config_file)
			return WIMLIB_ERR_INVALID_PARAM;

		wincfg_copy = memdup(wincfg, wincfg_len * sizeof(wincfg[0]));
		if (!wincfg_copy)
			return WIMLIB_ERR_NOMEM;

		ret = do_read_capture_config_file(T("wincfg"), wincfg_copy,
						  wincfg_len, config);
		if (ret)
			FREE(wincfg_copy);
	} else if (config_file) {
		/* Use the specified configuration file.  */
		ret = do_read_capture_config_file(config_file, NULL, 0, config);
	} else {
		/* ... Or don't use any configuration file at all.  No files
		 * will be excluded from capture, all files will be compressed,
		 * etc.  */
		ret = 0;
	}
	FREE(tmp_config_file);
	return ret;
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
	struct wim_image_metadata *imd;
	struct list_head unhashed_streams;
	struct add_image_params params;
	int (*capture_tree)(struct wim_dentry **,
			    const tchar *,
			    struct add_image_params *);
	const tchar *config_file;
	struct capture_config config;
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
	config_file = add_cmd->add.config_file;

	DEBUG("fs_source_path=\"%"TS"\", wim_target_path=\"%"TS"\", add_flags=%#x",
	      fs_source_path, wim_target_path, add_flags);

	memset(&params, 0, sizeof(params));

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

	ret = get_capture_config(config_file, &config,
				 add_flags, fs_source_path);
	if (ret)
		goto out;

	ret = init_inode_table(&params.inode_table, 9001);
	if (ret)
		goto out_destroy_config;

	ret = init_sd_set(&params.sd_set, imd->security_data);
	if (ret)
		goto out_destroy_inode_table;

	INIT_LIST_HEAD(&unhashed_streams);
	params.lookup_table = wim->lookup_table;
	params.unhashed_streams = &unhashed_streams;
	params.config = &config;
	params.add_flags = add_flags;
	params.extra_arg = extra_arg;

	params.progress_func = progress_func;
	params.progress.scan.source = fs_source_path;
	params.progress.scan.wim_target_path = wim_target_path;
	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_BEGIN, &params.progress);

	config.prefix = fs_source_path;
	config.prefix_num_tchars = tstrlen(fs_source_path);

	if (wim_target_path[0] == T('\0'))
		params.add_flags |= WIMLIB_ADD_FLAG_ROOT;
	ret = (*capture_tree)(&branch, fs_source_path, &params);
	if (ret)
		goto out_destroy_sd_set;

	if (branch) {
		/* Use the target name, not the source name, for
		 * the root of each branch from a capture
		 * source.  (This will also set the root dentry
		 * of the entire image to be unnamed.) */
		ret = dentry_set_name(branch,
				      path_basename(wim_target_path));
		if (ret)
			goto out_ntfs_umount;

		ret = attach_branch(&imd->root_dentry, branch, wim_target_path,
				    WIMLIB_CASE_PLATFORM_DEFAULT);
		if (ret)
			goto out_ntfs_umount;
	}
	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_END, &params.progress);
	list_splice_tail(&unhashed_streams, &imd->unhashed_streams);
#ifdef WITH_NTFS_3G
	imd->ntfs_vol = ntfs_vol;
#endif
	inode_table_prepare_inode_list(&params.inode_table, &imd->inode_list);
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
	destroy_sd_set(&params.sd_set, rollback_sd);
out_destroy_inode_table:
	destroy_inode_table(&params.inode_table);
out_destroy_config:
	destroy_capture_config(&config);
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
	flags = delete_cmd->delete_.delete_flags;
	wim_path = delete_cmd->delete_.wim_path;

	DEBUG("Deleting WIM path \"%"TS"\" (flags=%#x)", wim_path, flags);

	tree = get_dentry(wim, wim_path, WIMLIB_CASE_PLATFORM_DEFAULT);
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

static int
execute_rename_command(WIMStruct *wim,
		       const struct wimlib_update_command *rename_cmd)
{
	int ret;

	wimlib_assert(rename_cmd->op == WIMLIB_UPDATE_OP_RENAME);

	ret = rename_wim_path(wim, rename_cmd->rename.wim_source_path,
			      rename_cmd->rename.wim_target_path,
			      WIMLIB_CASE_PLATFORM_DEFAULT);
	if (ret) {
		ret = -ret;
		errno = ret;
		ERROR_WITH_ERRNO("Can't rename \"%"TS"\" to \"%"TS"\"",
				 rename_cmd->rename.wim_source_path,
				 rename_cmd->rename.wim_target_path);
		switch (ret) {
		case ENOMEM:
			ret = WIMLIB_ERR_NOMEM;
			break;
		case ENOTDIR:
			ret = WIMLIB_ERR_NOTDIR;
			break;
		case ENOTEMPTY:
			ret = WIMLIB_ERR_NOTEMPTY;
			break;
		case EISDIR:
			ret = WIMLIB_ERR_IS_DIRECTORY;
			break;
		case ENOENT:
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
		wimlib_assert(0);
		return NULL;
	}
}

static int
execute_update_commands(WIMStruct *wim,
			const struct wimlib_update_command *cmds,
			size_t num_cmds,
			int update_flags,
			wimlib_progress_func_t progress_func)
{
	int ret = 0;
	union wimlib_progress_info info;
	info.update.completed_commands = 0;
	info.update.total_commands = num_cmds;
	for (size_t i = 0; i < num_cmds; i++) {
		DEBUG("Executing update command %zu of %zu (op=%"TS")",
		      i + 1, num_cmds, update_op_to_str(cmds[i].op));
		if (update_flags & WIMLIB_UPDATE_FLAG_SEND_PROGRESS &&
		    progress_func)
		{
			info.update.command = &cmds[i];
			(*progress_func)(WIMLIB_PROGRESS_MSG_UPDATE_BEGIN_COMMAND,
					 &info);
		}
		switch (cmds[i].op) {
		case WIMLIB_UPDATE_OP_ADD:
			ret = execute_add_command(wim, &cmds[i], progress_func);
			break;
		case WIMLIB_UPDATE_OP_DELETE:
			ret = execute_delete_command(wim, &cmds[i]);
			break;
		case WIMLIB_UPDATE_OP_RENAME:
			ret = execute_rename_command(wim, &cmds[i]);
			break;
		default:
			wimlib_assert(0);
		}
		if (ret)
			break;
		info.update.completed_commands++;
		if (update_flags & WIMLIB_UPDATE_FLAG_SEND_PROGRESS &&
		    progress_func)
		{
			(*progress_func)(WIMLIB_PROGRESS_MSG_UPDATE_END_COMMAND,
					 &info);
		}
	}
	return ret;
}


static int
check_add_command(struct wimlib_update_command *cmd,
		  const struct wim_header *hdr)
{
	int add_flags = cmd->add.add_flags;

	if (add_flags & ~(WIMLIB_ADD_FLAG_NTFS |
			  WIMLIB_ADD_FLAG_DEREFERENCE |
			  WIMLIB_ADD_FLAG_VERBOSE |
			  /* BOOT doesn't make sense for wimlib_update_image().  */
			  /*WIMLIB_ADD_FLAG_BOOT |*/
			  WIMLIB_ADD_FLAG_WIMBOOT |
			  WIMLIB_ADD_FLAG_UNIX_DATA |
			  WIMLIB_ADD_FLAG_NO_ACLS |
			  WIMLIB_ADD_FLAG_STRICT_ACLS |
			  WIMLIB_ADD_FLAG_EXCLUDE_VERBOSE |
			  WIMLIB_ADD_FLAG_RPFIX |
			  WIMLIB_ADD_FLAG_NORPFIX |
			  WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE |
			  WIMLIB_ADD_FLAG_WINCONFIG))
		return WIMLIB_ERR_INVALID_PARAM;

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
		return WIMLIB_ERR_UNSUPPORTED;
	}
	if (add_flags & WIMLIB_ADD_FLAG_DEREFERENCE) {
		ERROR("Dereferencing symbolic links is not supported on Windows");
		return WIMLIB_ERR_UNSUPPORTED;
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
check_delete_command(const struct wimlib_update_command *cmd)
{
	if (cmd->delete_.delete_flags & ~(WIMLIB_DELETE_FLAG_FORCE |
					  WIMLIB_DELETE_FLAG_RECURSIVE))
		return WIMLIB_ERR_INVALID_PARAM;
	return 0;
}

static int
check_rename_command(const struct wimlib_update_command *cmd)
{
	if (cmd->rename.rename_flags != 0)
		return WIMLIB_ERR_INVALID_PARAM;
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
		return check_delete_command(cmd);
	case WIMLIB_UPDATE_OP_RENAME:
		return check_rename_command(cmd);
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


static void
free_update_commands(struct wimlib_update_command *cmds, size_t num_cmds)
{
	if (cmds) {
		for (size_t i = 0; i < num_cmds; i++) {
			switch (cmds[i].op) {
			case WIMLIB_UPDATE_OP_ADD:
				FREE(cmds[i].add.fs_source_path);
				FREE(cmds[i].add.wim_target_path);
				FREE(cmds[i].add.config_file);
				break;
			case WIMLIB_UPDATE_OP_DELETE:
				FREE(cmds[i].delete_.wim_path);
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
			if (cmds[i].add.config_file) {
				cmds_copy[i].add.config_file = TSTRDUP(cmds[i].add.config_file);
				if (!cmds_copy[i].add.config_file)
					goto oom;
			}
			cmds_copy[i].add.add_flags = cmds[i].add.add_flags;
			break;
		case WIMLIB_UPDATE_OP_DELETE:
			cmds_copy[i].delete_.wim_path =
				canonicalize_wim_path(cmds[i].delete_.wim_path);
			if (!cmds_copy[i].delete_.wim_path)
				goto oom;
			cmds_copy[i].delete_.delete_flags = cmds[i].delete_.delete_flags;
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

/* API function documented in wimlib.h  */
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
	bool deletion_requested = false;

	if (update_flags & ~WIMLIB_UPDATE_FLAG_SEND_PROGRESS)
		return WIMLIB_ERR_INVALID_PARAM;

	DEBUG("Updating image %d with %zu commands", image, num_cmds);

	for (size_t i = 0; i < num_cmds; i++)
		if (cmds[i].op == WIMLIB_UPDATE_OP_DELETE)
			deletion_requested = true;

	if (deletion_requested)
		ret = can_delete_from_wim(wim);
	else
		ret = can_modify_wim(wim);

	if (ret)
		goto out;

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
	ret = execute_update_commands(wim, cmds_copy, num_cmds, update_flags,
				      progress_func);
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
