/*
 * unix_apply.c - Code to apply files from a WIM image on UNIX.
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
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef HAVE_UTIME_H
#  include <utime.h>
#endif

#include "wimlib/apply.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/reparse.h"
#include "wimlib/timestamp.h"

/* Returns the number of components of @path.  */
static unsigned
get_num_path_components(const char *path)
{
	unsigned num_components = 0;
	while (*path) {
		while (*path == '/')
			path++;
		if (*path)
			num_components++;
		while (*path && *path != '/')
			path++;
	}
	return num_components;
}

static const char *
path_next_part(const char *path)
{
	while (*path && *path != '/')
		path++;
	while (*path && *path == '/')
		path++;
	return path;
}

static int
unix_extract_regular_file_linked(struct wim_dentry *dentry,
				 const char *output_path,
				 struct apply_args *args,
				 struct wim_lookup_table_entry *lte)
{
	/* This mode overrides the normal hard-link extraction and
	 * instead either symlinks or hardlinks *all* identical files in
	 * the WIM, even if they are in a different image (in the case
	 * of a multi-image extraction) */

	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_HARDLINK) {
		if (link(lte->extracted_file, output_path) != 0) {
			ERROR_WITH_ERRNO("Failed to hard link "
					 "`%s' to `%s'",
					 output_path, lte->extracted_file);
			return WIMLIB_ERR_LINK;
		}
	} else {
		int num_path_components;
		int num_output_dir_path_components;
		size_t extracted_file_len;
		char *p;
		const char *p2;
		size_t i;

		num_path_components = get_num_path_components(dentry->_full_path) - 1;
		num_output_dir_path_components = get_num_path_components(args->target);

		if (args->extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE) {
			num_path_components++;
			num_output_dir_path_components--;
		}
		extracted_file_len = strlen(lte->extracted_file);

		char buf[extracted_file_len + 3 * num_path_components + 1];
		p = &buf[0];

		for (i = 0; i < num_path_components; i++) {
			*p++ = '.';
			*p++ = '.';
			*p++ = '/';
		}
		p2 = lte->extracted_file;
		while (*p2 == '/')
			p2++;
		while (num_output_dir_path_components > 0) {
			p2 = path_next_part(p2);
			num_output_dir_path_components--;
		}
		strcpy(p, p2);
		if (symlink(buf, output_path) != 0) {
			ERROR_WITH_ERRNO("Failed to symlink `%s' to `%s'",
					 buf, lte->extracted_file);
			return WIMLIB_ERR_LINK;
		}
	}
	return 0;
}

static int
symlink_apply_unix_data(const char *link,
			const struct wimlib_unix_data *unix_data)
{
	if (lchown(link, unix_data->uid, unix_data->gid)) {
		if (errno == EPERM) {
			/* Ignore */
			WARNING_WITH_ERRNO("failed to set symlink UNIX "
					   "owner/group on \"%s\"", link);
		} else {
			ERROR_WITH_ERRNO("failed to set symlink UNIX "
					 "owner/group on \"%s\"", link);
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	}
	return 0;
}

static int
fd_apply_unix_data(int fd, const char *path,
		   const struct wimlib_unix_data *unix_data,
		   int extract_flags)
{
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NO_ACLS)
		return 0;

	if (fchown(fd, unix_data->uid, unix_data->gid)) {
		if (errno == EPERM &&
		    !(extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS))
		{
			WARNING_WITH_ERRNO("failed to set file UNIX "
					   "owner/group on \"%s\"", path);
		} else {
			ERROR_WITH_ERRNO("failed to set file UNIX "
					 "owner/group on \"%s\"", path);
			return (errno == EPERM) ? WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT :
				WIMLIB_ERR_WRITE;
		}
	}

	if (fchmod(fd, unix_data->mode)) {
		if (errno == EPERM &&
		    !(extract_flags & WIMLIB_EXTRACT_FLAG_STRICT_ACLS))
		{
			WARNING_WITH_ERRNO("failed to set UNIX file mode "
					   "on \"%s\"", path);
		} else {
			ERROR_WITH_ERRNO("failed to set UNIX file mode "
					 "on \"%s\"", path);
			return (errno == EPERM) ? WIMLIB_ERR_INSUFFICIENT_PRIVILEGES_TO_EXTRACT :
				WIMLIB_ERR_WRITE;
		}
	}
	return 0;
}

static int
dir_apply_unix_data(const char *dir, const struct wimlib_unix_data *unix_data,
		    int extract_flags)
{
	int dfd = open(dir, O_RDONLY);
	int ret;
	if (dfd >= 0) {
		ret = fd_apply_unix_data(dfd, dir, unix_data, extract_flags);
		if (close(dfd) && ret == 0) {
			ERROR_WITH_ERRNO("can't close directory `%s'", dir);
			ret = WIMLIB_ERR_WRITE;
		}
	} else {
		ERROR_WITH_ERRNO("can't open directory `%s'", dir);
		ret = WIMLIB_ERR_OPENDIR;
	}
	return ret;
}

static int
unix_extract_regular_file_unlinked(struct wim_dentry *dentry,
				   struct apply_args *args,
				   const char *output_path,
				   struct wim_lookup_table_entry *lte)
{
	/* Normal mode of extraction.  Regular files and hard links are
	 * extracted in the way that they appear in the WIM. */

	int out_fd;
	int ret;
	struct wim_inode *inode = dentry->d_inode;

	if (!((args->extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE)
		&& (args->extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
				     WIMLIB_EXTRACT_FLAG_HARDLINK))))
	{
		/* If the dentry is part of a hard link set of at least 2
		 * dentries and one of the other dentries has already been
		 * extracted, make a hard link to the file corresponding to this
		 * already-extracted directory.  Otherwise, extract the file and
		 * set the inode->i_extracted_file field so that other dentries
		 * in the hard link group can link to it. */
		if (inode->i_nlink > 1) {
			if (inode->i_extracted_file) {
				DEBUG("Extracting hard link `%s' => `%s'",
				      output_path, inode->i_extracted_file);
				if (link(inode->i_extracted_file, output_path) != 0) {
					ERROR_WITH_ERRNO("Failed to hard link "
							 "`%s' to `%s'",
							 output_path,
							 inode->i_extracted_file);
					return WIMLIB_ERR_LINK;
				}
				return 0;
			}
			FREE(inode->i_extracted_file);
			inode->i_extracted_file = STRDUP(output_path);
			if (!inode->i_extracted_file) {
				ERROR("Failed to allocate memory for filename");
				return WIMLIB_ERR_NOMEM;
			}
		}
	}

	/* Extract the contents of the file to @output_path. */

	out_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out_fd == -1) {
		ERROR_WITH_ERRNO("Failed to open the file `%s' for writing",
				 output_path);
		return WIMLIB_ERR_OPEN;
	}

	if (!lte) {
		/* Empty file with no lookup table entry */
		DEBUG("Empty file `%s'.", output_path);
		ret = 0;
		goto out_extract_unix_data;
	}

	ret = extract_wim_resource_to_fd(lte, out_fd, wim_resource_size(lte));
	if (ret) {
		ERROR("Failed to extract resource to `%s'", output_path);
		goto out;
	}

out_extract_unix_data:
	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;
		ret = inode_get_unix_data(inode, &unix_data, NULL);
		if (ret > 0)
			;
		else if (ret < 0)
			ret = 0;
		else
			ret = fd_apply_unix_data(out_fd, output_path, &unix_data,
						 args->extract_flags);
		if (ret)
			goto out;
	}
	if (lte)
		args->progress.extract.completed_bytes += wim_resource_size(lte);
out:
	if (close(out_fd) != 0) {
		ERROR_WITH_ERRNO("Failed to close file `%s'", output_path);
		if (ret == 0)
			ret = WIMLIB_ERR_WRITE;
	}
	return ret;
}

static int
unix_extract_regular_file(struct wim_dentry *dentry,
			  struct apply_args *args,
			  const char *output_path)
{
	struct wim_lookup_table_entry *lte;
	const struct wim_inode *inode = dentry->d_inode;

	lte = inode_unnamed_lte_resolved(inode);

	if (lte && (args->extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
					   WIMLIB_EXTRACT_FLAG_HARDLINK)))
	{
		if (lte->extracted_file) {
			return unix_extract_regular_file_linked(dentry,
								output_path,
								args, lte);
		} else {
			lte->extracted_file = STRDUP(output_path);
			if (!lte->extracted_file)
				return WIMLIB_ERR_NOMEM;
		}
	}
	return unix_extract_regular_file_unlinked(dentry, args, output_path, lte);
}

static int
unix_extract_symlink(struct wim_dentry *dentry,
		     struct apply_args *args,
		     const char *output_path)
{
	char target[4096 + args->target_realpath_len];
	char *fixed_target;
	const struct wim_inode *inode = dentry->d_inode;

	ssize_t ret = wim_inode_readlink(inode,
					 target + args->target_realpath_len,
					 sizeof(target) - args->target_realpath_len - 1);
	struct wim_lookup_table_entry *lte;

	if (ret <= 0) {
		ERROR("Could not read the symbolic link from dentry `%s'",
		      dentry->_full_path);
		return WIMLIB_ERR_INVALID_DENTRY;
	}
	target[args->target_realpath_len + ret] = '\0';
	if (target[args->target_realpath_len] == '/' &&
	    args->extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX)
	{
		/* Fix absolute symbolic link target to point into the actual
		 * extraction destination */
		memcpy(target, args->target_realpath,
		       args->target_realpath_len);
		fixed_target = target;
	} else {
		/* Keep same link target */
		fixed_target = target + args->target_realpath_len;
	}
	ret = symlink(fixed_target, output_path);
	if (ret) {
		ERROR_WITH_ERRNO("Failed to symlink `%s' to `%s'",
				 output_path, fixed_target);
		return WIMLIB_ERR_LINK;
	}
	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;
		ret = inode_get_unix_data(inode, &unix_data, NULL);
		if (ret > 0)
			;
		else if (ret < 0)
			ret = 0;
		else
			ret = symlink_apply_unix_data(output_path, &unix_data);
		if (ret)
			return ret;
	}
	lte = inode_unnamed_lte_resolved(inode);
	wimlib_assert(lte != NULL);
	args->progress.extract.completed_bytes += wim_resource_size(lte);
	return 0;
}

static int
unix_extract_directory(struct wim_dentry *dentry, const tchar *output_path,
		       int extract_flags)
{
	int ret;
	struct stat stbuf;

	ret = tstat(output_path, &stbuf);
	if (ret == 0) {
		if (S_ISDIR(stbuf.st_mode)) {
			goto dir_exists;
		} else {
			ERROR("`%"TS"' is not a directory", output_path);
			return WIMLIB_ERR_MKDIR;
		}
	} else {
		if (errno != ENOENT) {
			ERROR_WITH_ERRNO("Failed to stat `%"TS"'", output_path);
			return WIMLIB_ERR_STAT;
		}
	}

	if (tmkdir(output_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH))
	{
		ERROR_WITH_ERRNO("Cannot create directory `%"TS"'", output_path);
		return WIMLIB_ERR_MKDIR;
	}
dir_exists:
	ret = 0;
#ifndef __WIN32__
	if (extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		struct wimlib_unix_data unix_data;
		ret = inode_get_unix_data(dentry->d_inode, &unix_data, NULL);
		if (ret > 0)
			;
		else if (ret < 0)
			ret = 0;
		else
			ret = dir_apply_unix_data(output_path, &unix_data,
						  extract_flags);
	}
#endif
	return ret;
}

int
unix_do_apply_dentry(const char *output_path, size_t output_path_len,
		     struct wim_dentry *dentry, struct apply_args *args)
{
	const struct wim_inode *inode = dentry->d_inode;

	if (inode_is_symlink(inode))
		return unix_extract_symlink(dentry, args, output_path);
	else if (inode_is_directory(inode))
		return unix_extract_directory(dentry, output_path, args->extract_flags);
	else
		return unix_extract_regular_file(dentry, args, output_path);
}

int
unix_do_apply_dentry_timestamps(const char *output_path,
				size_t output_path_len,
				struct wim_dentry *dentry,
				struct apply_args *args)
{
	int ret;
	const struct wim_inode *inode = dentry->d_inode;

#ifdef HAVE_UTIMENSAT
	/* Convert the WIM timestamps, which are accurate to 100 nanoseconds,
	 * into `struct timespec's for passing to utimensat(), which is accurate
	 * to 1 nanosecond. */

	struct timespec ts[2];
	ts[0] = wim_timestamp_to_timespec(inode->i_last_access_time);
	ts[1] = wim_timestamp_to_timespec(inode->i_last_write_time);
	ret = utimensat(AT_FDCWD, output_path, ts, AT_SYMLINK_NOFOLLOW);
	if (ret)
		ret = errno;
#else
	ret = ENOSYS;
#endif

	if (ret == ENOSYS) {
		/* utimensat() not implemented or not available */
	#ifdef HAVE_LUTIMES
		/* Convert the WIM timestamps, which are accurate to 100
		 * nanoseconds, into `struct timeval's for passing to lutimes(),
		 * which is accurate to 1 microsecond. */
		struct timeval tv[2];
		tv[0] = wim_timestamp_to_timeval(inode->i_last_access_time);
		tv[1] = wim_timestamp_to_timeval(inode->i_last_write_time);
		ret = lutimes(output_path, tv);
		if (ret)
			ret = errno;
	#endif
	}

	if (ret == ENOSYS) {
		/* utimensat() and lutimes() both not implemented or not
		 * available */
	#ifdef HAVE_UTIME
		/* Convert the WIM timestamps, which are accurate to 100
		 * nanoseconds, into a `struct utimbuf's for passing to
		 * utime(), which is accurate to 1 second. */
		struct utimbuf buf;
		buf.actime = wim_timestamp_to_unix(inode->i_last_access_time);
		buf.modtime = wim_timestamp_to_unix(inode->i_last_write_time);
		ret = utime(output_path, &buf);
	#endif
	}
	if (ret && args->num_utime_warnings < 10) {
		WARNING_WITH_ERRNO("Failed to set timestamp on file `%s'",
				    output_path);
		args->num_utime_warnings++;
	}
	return 0;
}

#endif /* !__WIN32__ */
