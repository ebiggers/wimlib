/*
 * unix_capture.c:  Capture a directory tree on UNIX.
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

#ifndef __WIN32__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "wimlib/capture.h"
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/paths.h"
#include "wimlib/reparse.h"
#include "wimlib/timestamp.h"

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
		return WIMLIB_ERR_OPENDIR;
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

	/* The idea here is to call readlink() to get the UNIX target of the
	 * symbolic link, then turn the target into a reparse point data buffer
	 * that contains a relative or absolute symbolic link. */
	deref_name_len = readlink(path, deref_name_buf,
				  sizeof(deref_name_buf) - 1);
	if (deref_name_len >= 0) {
		char *dest = deref_name_buf;

		dest[deref_name_len] = '\0';
		DEBUG("Read symlink `%s'", dest);

		if ((params->add_flags & WIMLIB_ADD_FLAG_RPFIX) &&
		     dest[0] == '/')
		{
			dest = capture_fixup_absolute_symlink(dest,
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
		ret = wim_inode_set_symlink(inode, dest, params->lookup_table);
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
	int ret;
	struct wim_inode *inode;

	params->progress.scan.cur_path = path;

	if (exclude_path(path, path_len, params->config, true)) {
		do_capture_progress(params, WIMLIB_SCAN_DENTRY_EXCLUDED);
		ret = 0;
		goto out;
	}

	struct stat stbuf;
	int (*stat_fn)(const char *restrict, struct stat *restrict);
	if ((params->add_flags & WIMLIB_ADD_FLAG_DEREFERENCE) ||
	    (params->add_flags & WIMLIB_ADD_FLAG_ROOT))
		stat_fn = stat;
	else
		stat_fn = lstat;

	ret = (*stat_fn)(path, &stbuf);
	if (ret) {
		ERROR_WITH_ERRNO("Failed to stat `%s'", path);
		ret = WIMLIB_ERR_STAT;
		goto out;
	}
	if (!S_ISREG(stbuf.st_mode) && !S_ISDIR(stbuf.st_mode)
	    && !S_ISLNK(stbuf.st_mode)) {
		if (params->add_flags & WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE)
		{
			ERROR("Can't archive unsupported file \"%s\"", path);
			ret = WIMLIB_ERR_UNSUPPORTED_FILE;
			goto out;
		}
		do_capture_progress(params, WIMLIB_SCAN_DENTRY_UNSUPPORTED);
		ret = 0;
		goto out;
	}

	do_capture_progress(params, WIMLIB_SCAN_DENTRY_OK);

	ret = inode_table_new_dentry(&params->inode_table,
				     path_basename_with_len(path, path_len),
				     stbuf.st_ino, stbuf.st_dev, false, &root);
	if (ret)
		goto out;

	inode = root->d_inode;

	if (inode->i_nlink > 1) {
		/* Already captured this inode? */
		ret = 0;
		goto out;
	}

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
	if (params->add_flags & WIMLIB_ADD_FLAG_UNIX_DATA) {
		ret = inode_set_unix_data(inode, stbuf.st_uid,
					  stbuf.st_gid,
					  stbuf.st_mode,
					  params->lookup_table,
					  UNIX_DATA_ALL | UNIX_DATA_CREATE);
		if (ret)
			goto out;
	}
	params->add_flags &= ~WIMLIB_ADD_FLAG_ROOT;
	if (S_ISREG(stbuf.st_mode))
		ret = unix_capture_regular_file(path, stbuf.st_size,
						inode, params->lookup_table);
	else if (S_ISDIR(stbuf.st_mode))
		ret = unix_capture_directory(root, path, path_len, params);
	else
		ret = unix_capture_symlink(&root, path, inode, params);

	if (ret)
		goto out;

out:
	if (ret)
		free_dentry_tree(root, params->lookup_table);
	else
		*root_ret = root;
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
int
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

		if ((params->add_flags & WIMLIB_ADD_FLAG_ROOT) &&
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
