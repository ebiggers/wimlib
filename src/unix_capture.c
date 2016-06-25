/*
 * unix_capture.c:  Capture a directory tree on UNIX.
 */

/*
 * Copyright (C) 2012-2016 Eric Biggers
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

#ifndef __WIN32__

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h> /* for PATH_MAX */
#include <sys/stat.h>
#include <unistd.h>

#include "wimlib/blob_table.h"
#include "wimlib/dentry.h"
#include "wimlib/error.h"
#include "wimlib/reparse.h"
#include "wimlib/scan.h"
#include "wimlib/timestamp.h"
#include "wimlib/unix_data.h"

#ifdef HAVE_FDOPENDIR
#  define my_fdopendir(dirfd_p) fdopendir(*(dirfd_p))
#else
static DIR *
my_fdopendir(int *dirfd_p)
{
	DIR *dir = NULL;
	int old_pwd;

	old_pwd = open(".", O_RDONLY);
	if (old_pwd >= 0) {
		if (!fchdir(*dirfd_p)) {
			dir = opendir(".");
			if (dir) {
				close(*dirfd_p);
				*dirfd_p = dirfd(dir);
			}
			fchdir(old_pwd);
		}
		close(old_pwd);
	}
	return dir;
}
#endif

#ifdef HAVE_OPENAT
#  define my_openat(full_path, dirfd, relpath, flags) \
		openat((dirfd), (relpath), (flags))
#else
#  define my_openat(full_path, dirfd, relpath, flags) \
		open((full_path), (flags))
#endif

#ifdef HAVE_READLINKAT
#  define my_readlinkat(full_path, dirfd, relpath, buf, bufsize) \
		readlinkat((dirfd), (relpath), (buf), (bufsize))
#else
#  define my_readlinkat(full_path, dirfd, relpath, buf, bufsize) \
		readlink((full_path), (buf), (bufsize))
#endif

#ifdef HAVE_FSTATAT
#  define my_fstatat(full_path, dirfd, relpath, stbuf, flags)	\
	fstatat((dirfd), (relpath), (stbuf), (flags))
#else
#  define my_fstatat(full_path, dirfd, relpath, stbuf, flags)	\
	((flags) & AT_SYMLINK_NOFOLLOW) ? \
		lstat((full_path), (stbuf)) : \
		stat((full_path), (stbuf))
#endif

#ifndef AT_FDCWD
#  define AT_FDCWD	-100
#endif

#ifndef AT_SYMLINK_NOFOLLOW
#  define AT_SYMLINK_NOFOLLOW	0x100
#endif

static int
unix_scan_regular_file(const char *path, u64 size, struct wim_inode *inode,
		       struct list_head *unhashed_blobs)
{
	struct blob_descriptor *blob = NULL;
	struct wim_inode_stream *strm;

	inode->i_attributes = FILE_ATTRIBUTE_NORMAL;

	if (size) {
		blob = new_blob_descriptor();
		if (unlikely(!blob))
			goto err_nomem;
		blob->file_on_disk = STRDUP(path);
		if (unlikely(!blob->file_on_disk))
			goto err_nomem;
		blob->blob_location = BLOB_IN_FILE_ON_DISK;
		blob->size = size;
		blob->file_inode = inode;
	}

	strm = inode_add_stream(inode, STREAM_TYPE_DATA, NO_STREAM_NAME, blob);
	if (unlikely(!strm))
		goto err_nomem;

	prepare_unhashed_blob(blob, inode, strm->stream_id, unhashed_blobs);
	return 0;

err_nomem:
	free_blob_descriptor(blob);
	return WIMLIB_ERR_NOMEM;
}

static int
unix_build_dentry_tree_recursive(struct wim_dentry **tree_ret,
				 char *path, size_t path_len,
				 int dirfd, const char *relpath,
				 struct scan_params *params);

static int
unix_scan_directory(struct wim_dentry *dir_dentry,
		    char *full_path, size_t full_path_len,
		    int parent_dirfd, const char *dir_relpath,
		    struct scan_params *params)
{

	int dirfd;
	DIR *dir;
	int ret;

	dirfd = my_openat(full_path, parent_dirfd, dir_relpath, O_RDONLY);
	if (dirfd < 0) {
		ERROR_WITH_ERRNO("\"%s\": Can't open directory", full_path);
		return WIMLIB_ERR_OPENDIR;
	}

	dir_dentry->d_inode->i_attributes = FILE_ATTRIBUTE_DIRECTORY;
	dir = my_fdopendir(&dirfd);
	if (!dir) {
		ERROR_WITH_ERRNO("\"%s\": Can't open directory", full_path);
		close(dirfd);
		return WIMLIB_ERR_OPENDIR;
	}

	ret = 0;
	for (;;) {
		struct dirent *entry;
		struct wim_dentry *child;
		size_t name_len;

		errno = 0;
		entry = readdir(dir);
		if (!entry) {
			if (errno) {
				ret = WIMLIB_ERR_READ;
				ERROR_WITH_ERRNO("\"%s\": Error reading directory",
						 full_path);
			}
			break;
		}

		name_len = strlen(entry->d_name);

		if (should_ignore_filename(entry->d_name, name_len))
			continue;

		full_path[full_path_len] = '/';
		memcpy(&full_path[full_path_len + 1], entry->d_name, name_len + 1);
		ret = unix_build_dentry_tree_recursive(&child,
						       full_path,
						       full_path_len + 1 + name_len,
						       dirfd,
						       &full_path[full_path_len + 1],
						       params);
		full_path[full_path_len] = '\0';
		if (ret)
			break;
		attach_scanned_tree(dir_dentry, child, params->blob_table);
	}
	closedir(dir);
	return ret;
}

/*
 * Given an absolute symbolic link target (UNIX-style, beginning with '/'),
 * determine whether it points into the directory identified by @ino and @dev.
 * If yes, return the suffix of @target which is relative to this directory, but
 * retaining leading slashes.  If no, return @target.
 *
 * Here are some examples, assuming that the @ino/@dev directory is "/home/e":
 *
 *	Original target		New target
 *	---------------		----------
 *	/home/e/test		/test
 *	/home/e/test/		/test/
 *	//home//e//test//	//test//
 *	/home/e						(empty string)
 *	/home/e/		/
 *	/usr/lib		/usr/lib		(external link)
 *
 * Because of the possibility of other links into the @ino/@dev directory and/or
 * multiple path separators, we can't simply do a string comparison; instead we
 * need to stat() each ancestor directory.
 *
 * If the link points directly to the @ino/@dev directory with no trailing
 * slashes, then the new target will be an empty string.  This is not a valid
 * UNIX symlink target, but we store this in the archive anyway since the target
 * is intended to be de-relativized when the link is extracted.
 */
static char *
unix_relativize_link_target(char *target, u64 ino, u64 dev)
{
	char *p = target;

	do {
		char save;
		struct stat stbuf;
		int ret;

		/* Skip slashes (guaranteed to be at least one here)  */
		do {
			p++;
		} while (*p == '/');

		/* End of string?  */
		if (!*p)
			break;

		/* Skip non-slashes (guaranteed to be at least one here)  */
		do {
			p++;
		} while (*p && *p != '/');

		/* Get the inode and device numbers for this prefix.  */
		save = *p;
		*p = '\0';
		ret = stat(target, &stbuf);
		*p = save;

		if (ret) {
			/* stat() failed.  Assume the link points outside the
			 * directory tree being captured.  */
			break;
		}

		if (stbuf.st_ino == ino && stbuf.st_dev == dev) {
			/* Link points inside directory tree being captured.
			 * Return abbreviated path.  */
			return p;
		}
	} while (*p);

	/* Link does not point inside directory tree being captured.  */
	return target;
}

static noinline_for_stack int
unix_scan_symlink(const char *full_path, int dirfd, const char *relpath,
		  struct wim_inode *inode, struct scan_params *params)
{
	char orig_target[REPARSE_POINT_MAX_SIZE];
	char *target = orig_target;
	int ret;

	/* Read the UNIX symbolic link target.  */
	ret = my_readlinkat(full_path, dirfd, relpath, target,
			    sizeof(orig_target));
	if (unlikely(ret < 0)) {
		ERROR_WITH_ERRNO("\"%s\": Can't read target of symbolic link",
				 full_path);
		return WIMLIB_ERR_READLINK;
	}
	if (unlikely(ret >= sizeof(orig_target))) {
		ERROR("\"%s\": target of symbolic link is too long", full_path);
		return WIMLIB_ERR_READLINK;
	}
	target[ret] = '\0';

	/* If the link is absolute and reparse point fixups are enabled, then
	 * change it to be "absolute" relative to the tree being captured.  */
	if (target[0] == '/' && (params->add_flags & WIMLIB_ADD_FLAG_RPFIX)) {
		int status = WIMLIB_SCAN_DENTRY_NOT_FIXED_SYMLINK;

		params->progress.scan.cur_path = full_path;
		params->progress.scan.symlink_target = target;

		target = unix_relativize_link_target(target,
						     params->capture_root_ino,
						     params->capture_root_dev);
		if (target != orig_target) {
			/* Link target was fixed.  */
			inode->i_rp_flags &= ~WIM_RP_FLAG_NOT_FIXED;
			status = WIMLIB_SCAN_DENTRY_FIXED_SYMLINK;
		}
		ret = do_scan_progress(params, status, NULL);
		if (ret)
			return ret;
	}

	/* Translate the UNIX symlink target into a Windows reparse point.  */
	ret = wim_inode_set_symlink(inode, target, params->blob_table);
	if (unlikely(ret)) {
		if (ret == WIMLIB_ERR_INVALID_UTF8_STRING) {
			ERROR("\"%s\": target of symbolic link is not valid "
			      "UTF-8.  This is not supported.", full_path);
		}
		return ret;
	}

	/* On Windows, a reparse point can be set on both directory and
	 * non-directory files.  Usually, a link that is intended to point to a
	 * (non-)directory is stored as a reparse point on a (non-)directory
	 * file.  Replicate this behavior by examining the target file.  */
	struct stat stbuf;
	if (my_fstatat(full_path, dirfd, relpath, &stbuf, 0) == 0 &&
	    S_ISDIR(stbuf.st_mode))
		inode->i_attributes |= FILE_ATTRIBUTE_DIRECTORY;
	return 0;
}

static int
unix_build_dentry_tree_recursive(struct wim_dentry **tree_ret,
				 char *full_path, size_t full_path_len,
				 int dirfd, const char *relpath,
				 struct scan_params *params)
{
	struct wim_dentry *tree = NULL;
	struct wim_inode *inode = NULL;
	int ret;
	struct stat stbuf;
	int stat_flags;

	ret = try_exclude(full_path, params);
	if (unlikely(ret < 0)) /* Excluded? */
		goto out_progress;
	if (unlikely(ret > 0)) /* Error? */
		goto out;

	if (params->add_flags & (WIMLIB_ADD_FLAG_DEREFERENCE |
				 WIMLIB_ADD_FLAG_ROOT))
		stat_flags = 0;
	else
		stat_flags = AT_SYMLINK_NOFOLLOW;

	ret = my_fstatat(full_path, dirfd, relpath, &stbuf, stat_flags);

	if (ret) {
		ERROR_WITH_ERRNO("\"%s\": Can't read metadata", full_path);
		ret = WIMLIB_ERR_STAT;
		goto out;
	}

	if (!(params->add_flags & WIMLIB_ADD_FLAG_UNIX_DATA)) {
		if (unlikely(!S_ISREG(stbuf.st_mode) &&
			     !S_ISDIR(stbuf.st_mode) &&
			     !S_ISLNK(stbuf.st_mode)))
		{
			if (params->add_flags &
			    WIMLIB_ADD_FLAG_NO_UNSUPPORTED_EXCLUDE)
			{
				ERROR("\"%s\": File type is unsupported",
				      full_path);
				ret = WIMLIB_ERR_UNSUPPORTED_FILE;
				goto out;
			}
			params->progress.scan.cur_path = full_path;
			ret = do_scan_progress(params,
					       WIMLIB_SCAN_DENTRY_UNSUPPORTED,
					       NULL);
			goto out;
		}
	}

	ret = inode_table_new_dentry(params->inode_table, relpath,
				     stbuf.st_ino, stbuf.st_dev, false, &tree);
	if (unlikely(ret)) {
		if (ret == WIMLIB_ERR_INVALID_UTF8_STRING) {
			ERROR("\"%s\": filename is not valid UTF-8.  "
			      "This is not supported.", full_path);
		}
		goto out;
	}

	inode = tree->d_inode;

	/* Already seen this inode?  */
	if (inode->i_nlink > 1)
		goto out_progress;

#ifdef HAVE_STAT_NANOSECOND_PRECISION
	inode->i_creation_time = timespec_to_wim_timestamp(&stbuf.st_mtim);
	inode->i_last_write_time = timespec_to_wim_timestamp(&stbuf.st_mtim);
	inode->i_last_access_time = timespec_to_wim_timestamp(&stbuf.st_atim);
#else
	inode->i_creation_time = time_t_to_wim_timestamp(stbuf.st_mtime);
	inode->i_last_write_time = time_t_to_wim_timestamp(stbuf.st_mtime);
	inode->i_last_access_time = time_t_to_wim_timestamp(stbuf.st_atime);
#endif
	if (params->add_flags & WIMLIB_ADD_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;

		unix_data.uid = stbuf.st_uid;
		unix_data.gid = stbuf.st_gid;
		unix_data.mode = stbuf.st_mode;
		unix_data.rdev = stbuf.st_rdev;
		if (!inode_set_unix_data(inode, &unix_data, UNIX_DATA_ALL)) {
			ret = WIMLIB_ERR_NOMEM;
			goto out;
		}
	}

	if (params->add_flags & WIMLIB_ADD_FLAG_ROOT) {
		params->capture_root_ino = stbuf.st_ino;
		params->capture_root_dev = stbuf.st_dev;
		params->add_flags &= ~WIMLIB_ADD_FLAG_ROOT;
	}

	if (S_ISREG(stbuf.st_mode)) {
		ret = unix_scan_regular_file(full_path, stbuf.st_size,
					     inode, params->unhashed_blobs);
	} else if (S_ISDIR(stbuf.st_mode)) {
		ret = unix_scan_directory(tree, full_path, full_path_len,
					  dirfd, relpath, params);
	} else if (S_ISLNK(stbuf.st_mode)) {
		ret = unix_scan_symlink(full_path, dirfd, relpath,
					inode, params);
	}

	if (ret)
		goto out;

out_progress:
	params->progress.scan.cur_path = full_path;
	if (likely(tree))
		ret = do_scan_progress(params, WIMLIB_SCAN_DENTRY_OK, inode);
	else
		ret = do_scan_progress(params, WIMLIB_SCAN_DENTRY_EXCLUDED, NULL);
out:
	if (unlikely(ret)) {
		free_dentry_tree(tree, params->blob_table);
		tree = NULL;
		ret = report_scan_error(params, ret, full_path);
	}
	*tree_ret = tree;
	return ret;
}

/*
 * unix_build_dentry_tree():
 *	Builds a tree of WIM dentries from an on-disk directory tree (UNIX
 *	version; no NTFS-specific data is captured).
 *
 * @root_ret:   Place to return a pointer to the root of the dentry tree.  Set
 *		to NULL if the file or directory was excluded from capture.
 *
 * @root_disk_path:  The path to the root of the directory tree on disk.
 *
 * @params:     See doc for `struct scan_params'.
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
		       const char *root_disk_path, struct scan_params *params)
{
	size_t path_len;
	size_t path_bufsz;
	char *path_buf;
	int ret;

	path_len = strlen(root_disk_path);
	path_bufsz = min(32790, PATH_MAX + 1);

	if (path_len >= path_bufsz)
		return WIMLIB_ERR_INVALID_PARAM;

	path_buf = MALLOC(path_bufsz);
	if (!path_buf)
		return WIMLIB_ERR_NOMEM;
	memcpy(path_buf, root_disk_path, path_len + 1);

	params->capture_root_nchars = path_len;

	ret = unix_build_dentry_tree_recursive(root_ret, path_buf, path_len,
					       AT_FDCWD, path_buf, params);
	FREE(path_buf);
	return ret;
}

#endif /* !__WIN32__ */
