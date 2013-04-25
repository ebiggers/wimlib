/*
 * add_image.c
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

#include "config.h"

#ifdef __WIN32__
#  include "win32.h"
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <fnmatch.h>
#  include "timestamp.h"
#endif

#include "wimlib_internal.h"
#include "dentry.h"
#include "lookup_table.h"
#include "xml.h"
#include "security.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include <unistd.h>

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif

/*
 * Adds the dentry tree and security data for a new image to the image metadata
 * array of the WIMStruct.
 */
static int
add_new_dentry_tree(WIMStruct *w, struct wim_dentry *root_dentry,
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

	ret = append_image_metadata(w, new_imd);
	if (ret)
		put_image_metadata(new_imd, NULL);
	return ret;

}

#ifndef __WIN32__

static int
unix_capture_regular_file(const char *path,
			  u64 size,
			  struct wim_inode *inode,
			  struct wim_lookup_table *lookup_table)
{
	inode->i_attributes = FILE_ATTRIBUTE_NORMAL;

	/* Empty files do not have to have a lookup table entry. */
	if (size != 0) {
		struct wim_lookup_table_entry *lte;
		char *file_on_disk;

		file_on_disk = STRDUP(path);
		if (!file_on_disk)
			return WIMLIB_ERR_NOMEM;
		lte = new_lookup_table_entry();
		if (!lte) {
			FREE(file_on_disk);
			return WIMLIB_ERR_NOMEM;
		}
		lte->file_on_disk = file_on_disk;
		lte->resource_location = RESOURCE_IN_FILE_ON_DISK;
		lte->resource_entry.original_size = size;
		lookup_table_insert_unhashed(lookup_table, lte, inode, 0);
		inode->i_lte = lte;
	}
	return 0;
}

static int
unix_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				 char *path,
				 size_t path_len,
				 struct add_image_params *params);

static int
unix_capture_directory(struct wim_dentry *dir_dentry,
		       char *path,
		       size_t path_len,
		       struct add_image_params *params)
{

	DIR *dir;
	struct dirent *entry;
	struct wim_dentry *child;
	int ret;

	dir_dentry->d_inode->i_attributes = FILE_ATTRIBUTE_DIRECTORY;
	dir = opendir(path);
	if (!dir) {
		ERROR_WITH_ERRNO("Failed to open the directory `%s'",
				 path);
		return WIMLIB_ERR_OPEN;
	}

	/* Recurse on directory contents */
	ret = 0;
	for (;;) {
		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			if (errno) {
				ret = WIMLIB_ERR_READ;
				ERROR_WITH_ERRNO("Error reading the "
						 "directory `%s'", path);
			}
			break;
		}

		if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0'
		      || (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
				continue;

		size_t name_len = strlen(entry->d_name);

		path[path_len] = '/';
		memcpy(&path[path_len + 1], entry->d_name, name_len + 1);
		ret = unix_build_dentry_tree_recursive(&child,
						       path,
						       path_len + 1 + name_len,
						       params);
		if (ret)
			break;
		if (child)
			dentry_add_child(dir_dentry, child);
	}
	closedir(dir);
	return ret;
}

static int
unix_capture_symlink(struct wim_dentry **root_p,
		     const char *path,
		     struct wim_inode *inode,
		     struct add_image_params *params)
{
	char deref_name_buf[4096];
	ssize_t deref_name_len;
	int ret;

	inode->i_attributes = FILE_ATTRIBUTE_REPARSE_POINT;
	inode->i_reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;

	/* The idea here is to call readlink() to get the UNIX target of
	 * the symbolic link, then turn the target into a reparse point
	 * data buffer that contains a relative or absolute symbolic
	 * link (NOT a junction point or *full* path symbolic link with
	 * drive letter).
	 */
	deref_name_len = readlink(path, deref_name_buf,
				  sizeof(deref_name_buf) - 1);
	if (deref_name_len >= 0) {
		char *dest = deref_name_buf;

		dest[deref_name_len] = '\0';
		DEBUG("Read symlink `%s'", dest);

		if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_RPFIX) &&
		     dest[0] == '/')
		{
			dest = fixup_symlink(dest,
					     params->capture_root_ino,
					     params->capture_root_dev);
			if (!dest) {
				WARNING("Ignoring out of tree absolute symlink "
					"\"%s\" -> \"%s\"\n"
					"          (Use --norpfix to capture "
					"absolute symlinks as-is)",
					path, deref_name_buf);
				free_dentry(*root_p);
				*root_p = NULL;
				return 0;
			}
			inode->i_not_rpfixed = 0;
		}
		ret = inode_set_symlink(inode, dest,
					params->lookup_table, NULL);
		if (ret == 0) {
			/* Unfortunately, Windows seems to have the concept of
			 * "file" symbolic links as being different from
			 * "directory" symbolic links...  so
			 * FILE_ATTRIBUTE_DIRECTORY needs to be set on the
			 * symbolic link if the *target* of the symbolic link is
			 * a directory.  */
			struct stat stbuf;
			if (stat(path, &stbuf) == 0 && S_ISDIR(stbuf.st_mode))
				inode->i_attributes |= FILE_ATTRIBUTE_DIRECTORY;
		}
	} else {
		ERROR_WITH_ERRNO("Failed to read target of "
				 "symbolic link `%s'", path);
		ret = WIMLIB_ERR_READLINK;
	}
	return ret;
}

static int
unix_build_dentry_tree_recursive(struct wim_dentry **root_ret,
				 char *path,
				 size_t path_len,
				 struct add_image_params *params)
{
	struct wim_dentry *root = NULL;
	int ret = 0;
	struct wim_inode *inode;

	if (exclude_path(path, path_len, params->config, true)) {
		if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE)
		    && params->progress_func)
		{
			union wimlib_progress_info info;
			info.scan.cur_path = path;
			info.scan.excluded = true;
			params->progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
		}
		goto out;
	}

	if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
	    && params->progress_func)
	{
		union wimlib_progress_info info;
		info.scan.cur_path = path;
		info.scan.excluded = false;
		params->progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
	}

	struct stat stbuf;
	int (*stat_fn)(const char *restrict, struct stat *restrict);
	if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE) ||
	    (params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT))
		stat_fn = stat;
	else
		stat_fn = lstat;

	ret = (*stat_fn)(path, &stbuf);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to stat `%s'", path);
		goto out;
	}
	if (!S_ISREG(stbuf.st_mode) && !S_ISDIR(stbuf.st_mode)
	    && !S_ISLNK(stbuf.st_mode)) {
		ERROR("`%s' is not a regular file, directory, or symbolic link.",
		      path);
		ret = WIMLIB_ERR_SPECIAL_FILE;
		goto out;
	}

	ret = inode_table_new_dentry(params->inode_table,
				     path_basename_with_len(path, path_len),
				     stbuf.st_ino,
				     stbuf.st_dev,
				     &root);
	if (ret)
		goto out;

	inode = root->d_inode;

	if (inode->i_nlink > 1) /* Already captured this inode? */
		goto out;

#ifdef HAVE_STAT_NANOSECOND_PRECISION
	inode->i_creation_time = timespec_to_wim_timestamp(stbuf.st_mtim);
	inode->i_last_write_time = timespec_to_wim_timestamp(stbuf.st_mtim);
	inode->i_last_access_time = timespec_to_wim_timestamp(stbuf.st_atim);
#else
	inode->i_creation_time = unix_timestamp_to_wim(stbuf.st_mtime);
	inode->i_last_write_time = unix_timestamp_to_wim(stbuf.st_mtime);
	inode->i_last_access_time = unix_timestamp_to_wim(stbuf.st_atime);
#endif
	inode->i_resolved = 1;
	if (params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) {
		ret = inode_set_unix_data(inode, stbuf.st_uid,
					  stbuf.st_gid,
					  stbuf.st_mode,
					  params->lookup_table,
					  UNIX_DATA_ALL | UNIX_DATA_CREATE);
		if (ret)
			goto out;
	}
	params->add_image_flags &=
		~(WIMLIB_ADD_IMAGE_FLAG_ROOT | WIMLIB_ADD_IMAGE_FLAG_SOURCE);
	if (S_ISREG(stbuf.st_mode))
		ret = unix_capture_regular_file(path, stbuf.st_size,
						inode, params->lookup_table);
	else if (S_ISDIR(stbuf.st_mode))
		ret = unix_capture_directory(root, path, path_len, params);
	else
		ret = unix_capture_symlink(&root, path, inode, params);
out:
	if (ret == 0)
		*root_ret = root;
	else
		free_dentry_tree(root, params->lookup_table);
	return ret;
}

/*
 * unix_build_dentry_tree():
 * 	Builds a tree of WIM dentries from an on-disk directory tree (UNIX
 * 	version; no NTFS-specific data is captured).
 *
 * @root_ret:   Place to return a pointer to the root of the dentry tree.  Only
 *		modified if successful.  Set to NULL if the file or directory was
 *		excluded from capture.
 *
 * @root_disk_path:  The path to the root of the directory tree on disk.
 *
 * @params:     See doc for `struct add_image_params'.
 *
 * @return:	0 on success, nonzero on failure.  It is a failure if any of
 *		the files cannot be `stat'ed, or if any of the needed
 *		directories cannot be opened or read.  Failure to add the files
 *		to the WIM may still occur later when trying to actually read
 *		the on-disk files during a call to wimlib_write() or
 *		wimlib_overwrite().
 */
static int
unix_build_dentry_tree(struct wim_dentry **root_ret,
		       const char *root_disk_path,
		       struct add_image_params *params)
{
	char *path_buf;
	int ret;
	size_t path_len;
	size_t path_bufsz;

	{
		struct stat root_stbuf;
		if (stat(root_disk_path, &root_stbuf)) {
			ERROR_WITH_ERRNO("Failed to stat \"%s\"", root_disk_path);
			return WIMLIB_ERR_STAT;
		}

		if ((params->add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) &&
		    !S_ISDIR(root_stbuf.st_mode))
		{
			ERROR("Root of capture \"%s\" is not a directory",
			      root_disk_path);
			return WIMLIB_ERR_NOTDIR;
		}
		params->capture_root_ino = root_stbuf.st_ino;
		params->capture_root_dev = root_stbuf.st_dev;
	}

	path_bufsz = min(32790, PATH_MAX + 1);
	path_len = strlen(root_disk_path);

	if (path_len >= path_bufsz)
		return WIMLIB_ERR_INVALID_PARAM;

 	path_buf = MALLOC(path_bufsz);
	if (!path_buf)
		return WIMLIB_ERR_NOMEM;
	memcpy(path_buf, root_disk_path, path_len + 1);

	ret = unix_build_dentry_tree_recursive(root_ret, path_buf,
					       path_len, params);
	FREE(path_buf);
	return ret;
}
#endif /* !__WIN32__ */

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

/* Strip leading and trailing forward slashes from a string.  Modifies it in
 * place and returns the stripped string. */
static const tchar *
canonicalize_target_path(tchar *target_path)
{
	tchar *p;
	if (target_path == NULL)
		return T("");
	for (;;) {
		if (*target_path == T('\0'))
			return target_path;
		else if (*target_path == T('/'))
			target_path++;
		else
			break;
	}

	p = tstrchr(target_path, T('\0')) - 1;
	while (*p == T('/'))
		*p-- = T('\0');
	return target_path;
}

/* Strip leading and trailing slashes from the target paths, and translate all
 * backslashes in the source and target paths into forward slashes. */
static void
canonicalize_sources_and_targets(struct wimlib_capture_source *sources,
				 size_t num_sources)
{
	while (num_sources--) {
		DEBUG("Canonicalizing { source: \"%"TS"\", target=\"%"TS"\"}",
		      sources->fs_source_path,
		      sources->wim_target_path);

		/* The Windows API can handle forward slashes.  Just get rid of
		 * backslashes to avoid confusing other parts of the library
		 * code. */
		zap_backslashes(sources->fs_source_path);
		if (sources->wim_target_path)
			zap_backslashes(sources->wim_target_path);

		sources->wim_target_path =
			(tchar*)canonicalize_target_path(sources->wim_target_path);
		DEBUG("Canonical target: \"%"TS"\"", sources->wim_target_path);
		sources++;
	}
}

static int
capture_source_cmp(const void *p1, const void *p2)
{
	const struct wimlib_capture_source *s1 = p1, *s2 = p2;
	return tstrcmp(s1->wim_target_path, s2->wim_target_path);
}

/* Sorts the capture sources lexicographically by target path.  This occurs
 * after leading and trailing forward slashes are stripped.
 *
 * One purpose of this is to make sure that target paths that are inside other
 * target paths are added after the containing target paths. */
static void
sort_sources(struct wimlib_capture_source *sources, size_t num_sources)
{
	qsort(sources, num_sources, sizeof(sources[0]), capture_source_cmp);
}

static int
check_sorted_sources(struct wimlib_capture_source *sources, size_t num_sources,
		     int add_image_flags)
{
	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NTFS) {
		if (num_sources != 1) {
			ERROR("Must specify exactly 1 capture source "
			      "(the NTFS volume) in NTFS mode!");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (sources[0].wim_target_path[0] != T('\0')) {
			ERROR("In NTFS capture mode the target path inside "
			      "the image must be the root directory!");
			return WIMLIB_ERR_INVALID_PARAM;
		}
	} else if (num_sources != 0) {
		/* This code is disabled because the current code
		 * unconditionally attempts to do overlays.  So, duplicate
		 * target paths are OK. */
	#if 0
		if (num_sources > 1 && sources[0].wim_target_path[0] == '\0') {
			ERROR("Cannot specify root target when using multiple "
			      "capture sources!");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		for (size_t i = 0; i < num_sources - 1; i++) {
			size_t len = strlen(sources[i].wim_target_path);
			size_t j = i + 1;
			const char *target1 = sources[i].wim_target_path;
			do {
				const char *target2 = sources[j].wim_target_path;
				DEBUG("target1=%s, target2=%s",
				      target1,target2);
				if (strncmp(target1, target2, len) ||
				    target2[len] > '/')
					break;
				if (target2[len] == '/') {
					ERROR("Invalid target `%s': is a prefix of `%s'",
					      target1, target2);
					return WIMLIB_ERR_INVALID_PARAM;
				}
				if (target2[len] == '\0') {
					ERROR("Invalid target `%s': is a duplicate of `%s'",
					      target1, target2);
					return WIMLIB_ERR_INVALID_PARAM;
				}
			} while (++j != num_sources);
		}
	#endif
	}
	return 0;

}

/* Creates a new directory to place in the WIM image.  This is to create parent
 * directories that are not part of any target as needed.  */
static int
new_filler_directory(const tchar *name, struct wim_dentry **dentry_ret)
{
	int ret;
	struct wim_dentry *dentry;

	DEBUG("Creating filler directory \"%"TS"\"", name);
	ret = new_dentry_with_inode(name, &dentry);
	if (ret == 0) {
		/* Leave the inode number as 0; this is allowed for non
		 * hard-linked files. */
		dentry->d_inode->i_resolved = 1;
		dentry->d_inode->i_attributes = FILE_ATTRIBUTE_DIRECTORY;
		*dentry_ret = dentry;
	}
	return ret;
}

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
		} else  {
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

static int
canonicalize_capture_config(struct wimlib_capture_config *config)
{
	int ret = canonicalize_pat_list(&config->exclusion_pats);
	if (ret)
		return ret;
	return canonicalize_pat_list(&config->exclusion_exception_pats);
}

WIMLIBAPI int
wimlib_add_image_multisource(WIMStruct *w,
			     struct wimlib_capture_source *sources,
			     size_t num_sources,
			     const tchar *name,
			     struct wimlib_capture_config *config,
			     int add_image_flags,
			     wimlib_progress_func_t progress_func)
{
	int (*capture_tree)(struct wim_dentry **,
			    const tchar *,
			    struct add_image_params *);
	void *extra_arg;
	struct wim_dentry *root_dentry;
	struct wim_dentry *branch;
	struct wim_security_data *sd;
	struct wim_image_metadata *imd;
	struct wim_inode_table inode_table;
	struct list_head unhashed_streams;
	struct add_image_params params;
	int ret;
	struct sd_set sd_set;
#ifdef WITH_NTFS_3G
	struct _ntfs_volume *ntfs_vol = NULL;
#endif

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NTFS) {
#ifdef WITH_NTFS_3G
		if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE) {
			ERROR("Cannot dereference files when capturing directly from NTFS");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) {
			ERROR("Capturing UNIX owner and mode not supported "
			      "when capturing directly from NTFS");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		capture_tree = build_dentry_tree_ntfs;
		extra_arg = &ntfs_vol;
#else
		ERROR("wimlib was compiled without support for NTFS-3g, so\n"
		      "        cannot capture a WIM image directly from a NTFS volume!");
		return WIMLIB_ERR_UNSUPPORTED;
#endif
	} else {
	#ifdef __WIN32__
		capture_tree = win32_build_dentry_tree;
	#else
		capture_tree = unix_build_dentry_tree;
	#endif
		extra_arg = NULL;
	}

#ifdef __WIN32__
	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) {
		ERROR("Capturing UNIX-specific data is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE) {
		ERROR("Dereferencing symbolic links is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
#endif

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
		add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_EXCLUDE_VERBOSE;

	if ((add_image_flags & (WIMLIB_ADD_IMAGE_FLAG_RPFIX |
				WIMLIB_ADD_IMAGE_FLAG_RPFIX)) ==
		(WIMLIB_ADD_IMAGE_FLAG_RPFIX | WIMLIB_ADD_IMAGE_FLAG_NORPFIX))
	{
		ERROR("Cannot specify RPFIX and NORPFIX flags at the same time!");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if ((add_image_flags & (WIMLIB_ADD_IMAGE_FLAG_RPFIX |
				WIMLIB_ADD_IMAGE_FLAG_NORPFIX)) == 0)
	{
		/* Do reparse-point fixups by default if the header flag is set
		 * from previous images, or if this is the first image being
		 * added. */
		if ((w->hdr.flags & WIM_HDR_FLAG_RP_FIX) || w->hdr.image_count == 0)
			add_image_flags |= WIMLIB_ADD_IMAGE_FLAG_RPFIX;
	}

	if (!name || !*name) {
		ERROR("Must specify a non-empty string for the image name");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (w->hdr.total_parts != 1) {
		ERROR("Cannot add an image to a split WIM");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	if (wimlib_image_name_in_use(w, name)) {
		ERROR("There is already an image named \"%"TS"\" in the WIM!",
		      name);
		return WIMLIB_ERR_IMAGE_NAME_COLLISION;
	}

	if (!config) {
		DEBUG("Capture config not provided; using empty config");
		config = alloca(sizeof(*config));
		memset(config, 0, sizeof(*config));
	}

	ret = canonicalize_capture_config(config);
	if (ret)
		goto out;

	ret = init_inode_table(&inode_table, 9001);
	if (ret)
		goto out;

	DEBUG("Allocating security data");
	sd = CALLOC(1, sizeof(struct wim_security_data));
	if (!sd) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_destroy_inode_table;
	}
	sd->total_length = 8;

	sd_set.sd = sd;
	sd_set.rb_root.rb_node = NULL;


	DEBUG("Using %zu capture sources", num_sources);
	canonicalize_sources_and_targets(sources, num_sources);
	sort_sources(sources, num_sources);
	ret = check_sorted_sources(sources, num_sources, add_image_flags);
	if (ret) {
		ret = WIMLIB_ERR_INVALID_PARAM;
		goto out_free_security_data;
	}

	INIT_LIST_HEAD(&unhashed_streams);
	w->lookup_table->unhashed_streams = &unhashed_streams;
	root_dentry = NULL;

	params.lookup_table = w->lookup_table;
	params.inode_table = &inode_table;
	params.sd_set = &sd_set;
	params.config = config;
	params.add_image_flags = add_image_flags;
	params.progress_func = progress_func;
	params.extra_arg = extra_arg;
	for (size_t i = 0; i < num_sources; i++) {
		int flags;
		union wimlib_progress_info progress;

		DEBUG("Building dentry tree for source %zu of %zu "
		      "(\"%"TS"\" => \"%"TS"\")", i + 1, num_sources,
		      sources[i].fs_source_path,
		      sources[i].wim_target_path);
		if (progress_func) {
			memset(&progress, 0, sizeof(progress));
			progress.scan.source = sources[i].fs_source_path;
			progress.scan.wim_target_path = sources[i].wim_target_path;
			progress_func(WIMLIB_PROGRESS_MSG_SCAN_BEGIN, &progress);
		}
		config->_prefix = sources[i].fs_source_path;
		config->_prefix_num_tchars = tstrlen(sources[i].fs_source_path);
		flags = add_image_flags | WIMLIB_ADD_IMAGE_FLAG_SOURCE;
		if (!*sources[i].wim_target_path)
			flags |= WIMLIB_ADD_IMAGE_FLAG_ROOT;
		ret = (*capture_tree)(&branch, sources[i].fs_source_path,
				      &params);
		if (ret) {
			ERROR("Failed to build dentry tree for `%"TS"'",
			      sources[i].fs_source_path);
			goto out_free_dentry_tree;
		}
		if (branch) {
			/* Use the target name, not the source name, for
			 * the root of each branch from a capture
			 * source.  (This will also set the root dentry
			 * of the entire image to be unnamed.) */
			ret = set_dentry_name(branch,
					      path_basename(sources[i].wim_target_path));
			if (ret)
				goto out_free_branch;

			ret = attach_branch(&root_dentry, branch,
					    sources[i].wim_target_path);
			if (ret)
				goto out_free_branch;
		}
		if (progress_func)
			progress_func(WIMLIB_PROGRESS_MSG_SCAN_END, &progress);
	}

	if (root_dentry == NULL) {
		ret = new_filler_directory(T(""), &root_dentry);
		if (ret)
			goto out_free_dentry_tree;
	}

	ret = add_new_dentry_tree(w, root_dentry, sd);

	if (ret) {
#ifdef WITH_NTFS_3G
		if (ntfs_vol)
			do_ntfs_umount(ntfs_vol);
#endif
		goto out_free_dentry_tree;
	}

	imd = w->image_metadata[w->hdr.image_count - 1];
	list_transfer(&unhashed_streams, &imd->unhashed_streams);

#ifdef WITH_NTFS_3G
	imd->ntfs_vol = ntfs_vol;
#endif

	DEBUG("Assigning hard link group IDs");
	inode_table_prepare_inode_list(&inode_table, &imd->inode_list);

	ret = xml_add_image(w, name);
	if (ret)
		goto out_put_imd;

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_BOOT)
		wimlib_set_boot_idx(w, w->hdr.image_count);

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_RPFIX)
		w->hdr.flags |= WIM_HDR_FLAG_RP_FIX;

	ret = 0;
	goto out_destroy_inode_table;
out_put_imd:
	put_image_metadata(w->image_metadata[--w->hdr.image_count],
			   w->lookup_table);
	goto out_destroy_inode_table;
out_free_branch:
	free_dentry_tree(branch, w->lookup_table);
out_free_dentry_tree:
	free_dentry_tree(root_dentry, w->lookup_table);
out_free_security_data:
	free_security_data(sd);
out_destroy_inode_table:
	destroy_inode_table(&inode_table);
	destroy_sd_set(&sd_set);
out:
	return ret;
}

WIMLIBAPI int
wimlib_add_image(WIMStruct *w,
		 const tchar *source,
		 const tchar *name,
		 struct wimlib_capture_config *config,
		 int add_image_flags,
		 wimlib_progress_func_t progress_func)
{
	if (!source || !*source)
		return WIMLIB_ERR_INVALID_PARAM;

	tchar *fs_source_path = TSTRDUP(source);
	int ret;
	struct wimlib_capture_source capture_src = {
		.fs_source_path = fs_source_path,
		.wim_target_path = NULL,
		.reserved = 0,
	};
	ret = wimlib_add_image_multisource(w, &capture_src, 1, name,
					   config, add_image_flags,
					   progress_func);
	FREE(fs_source_path);
	return ret;
}
