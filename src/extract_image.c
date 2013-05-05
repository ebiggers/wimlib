/*
 * extract_image.c
 *
 * Support for extracting WIM files.
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

#include <dirent.h>

#ifdef __WIN32__
#  include "win32.h"
#else
#  ifdef HAVE_UTIME_H
#    include <utime.h>
#  endif
#  include "timestamp.h"
#  include <sys/time.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dentry.h"
#include "lookup_table.h"
#include "wimlib_internal.h"
#include "xml.h"

#ifdef WITH_NTFS_3G
#  include <ntfs-3g/volume.h>
#endif

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif


#ifndef __WIN32__

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
extract_regular_file_linked(struct wim_dentry *dentry,
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
		   const struct wimlib_unix_data *unix_data)
{
	if (fchown(fd, unix_data->uid, unix_data->gid)) {
		if (errno == EPERM) {
			WARNING_WITH_ERRNO("failed to set file UNIX "
					   "owner/group on \"%s\"", path);
			/* Ignore? */
		} else {
			ERROR_WITH_ERRNO("failed to set file UNIX "
					 "owner/group on \"%s\"", path);
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	}

	if (fchmod(fd, unix_data->mode)) {
		if (errno == EPERM) {
			WARNING_WITH_ERRNO("failed to set UNIX file mode "
					   "on \"%s\"", path);
			/* Ignore? */
		} else {
			ERROR_WITH_ERRNO("failed to set UNIX file mode "
					 "on \"%s\"", path);
			return WIMLIB_ERR_INVALID_DENTRY;
		}
	}
	return 0;
}

static int
dir_apply_unix_data(const char *dir, const struct wimlib_unix_data *unix_data)
{
	int dfd = open(dir, O_RDONLY);
	int ret;
	if (dfd >= 0) {
		ret = fd_apply_unix_data(dfd, dir, unix_data);
		if (close(dfd)) {
			ERROR_WITH_ERRNO("can't close directory `%s'", dir);
			ret = WIMLIB_ERR_MKDIR;
		}
	} else {
		ERROR_WITH_ERRNO("can't open directory `%s'", dir);
		ret = WIMLIB_ERR_MKDIR;
	}
	return ret;
}

static int
extract_regular_file_unlinked(struct wim_dentry *dentry,
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
			ret = fd_apply_unix_data(out_fd, output_path, &unix_data);
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
extract_regular_file(struct wim_dentry *dentry,
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
			return extract_regular_file_linked(dentry, output_path, args, lte);
		} else {
			lte->extracted_file = STRDUP(output_path);
			if (!lte->extracted_file)
				return WIMLIB_ERR_NOMEM;
		}
	}
	return extract_regular_file_unlinked(dentry, args, output_path, lte);
}

static int
extract_symlink(struct wim_dentry *dentry,
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

#endif /* !__WIN32__ */

static int
extract_directory(struct wim_dentry *dentry,
		  const tchar *output_path, bool is_root)
{
	int ret;
	struct stat stbuf;

	ret = tstat(output_path, &stbuf);
	if (ret == 0) {
		if (S_ISDIR(stbuf.st_mode)) {
			/*if (!is_root)*/
				/*WARNING("`%s' already exists", output_path);*/
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
	if (dentry) {
		struct wimlib_unix_data unix_data;
		ret = inode_get_unix_data(dentry->d_inode, &unix_data, NULL);
		if (ret > 0)
			;
		else if (ret < 0)
			ret = 0;
		else
			ret = dir_apply_unix_data(output_path, &unix_data);
	}
#endif
	return ret;
}

#ifndef __WIN32__
static int
unix_do_apply_dentry(const char *output_path, size_t output_path_len,
		     struct wim_dentry *dentry, struct apply_args *args)
{
	const struct wim_inode *inode = dentry->d_inode;

	if (inode_is_symlink(inode))
		return extract_symlink(dentry, args, output_path);
	else if (inode_is_directory(inode))
		return extract_directory((args->extract_flags &
					   WIMLIB_EXTRACT_FLAG_UNIX_DATA) ? dentry : NULL,
					 output_path, false);
	else
		return extract_regular_file(dentry, args, output_path);
}

static int
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

static int
do_apply_op(struct wim_dentry *dentry, struct apply_args *args,
	    int (*apply_dentry_func)(const tchar *, size_t,
				     struct wim_dentry *, struct apply_args *))
{
	tchar *p;
	const tchar *full_path;
	size_t full_path_nchars;

	wimlib_assert(dentry->_full_path != NULL);
 	full_path = dentry->_full_path + 1;
 	full_path_nchars = dentry->full_path_nbytes / sizeof(tchar) - 1;
	tchar output_path[args->target_nchars + 1 +
			 (full_path_nchars - args->wim_source_path_nchars) + 1];
	p = output_path;

	/*print_dentry(dentry, NULL);*/
	/*ERROR("%"TS" %"TS, args->target, dentry->_full_path);*/
	/*ERROR("");*/

	tmemcpy(p, args->target, args->target_nchars);
	p += args->target_nchars;

	if (dentry != args->extract_root) {
		*p++ = T('/');
		tmemcpy(p, full_path + args->wim_source_path_nchars,
			full_path_nchars - args->wim_source_path_nchars);
		p += full_path_nchars - args->wim_source_path_nchars;
	}
	*p = T('\0');
	return (*apply_dentry_func)(output_path, p - output_path,
				    dentry, args);
}


/* Extracts a file, directory, or symbolic link from the WIM archive. */
static int
apply_dentry_normal(struct wim_dentry *dentry, void *arg)
{
#ifdef __WIN32__
	return do_apply_op(dentry, arg, win32_do_apply_dentry);
#else
	return do_apply_op(dentry, arg, unix_do_apply_dentry);
#endif
}


/* Apply timestamps to an extracted file or directory */
static int
apply_dentry_timestamps_normal(struct wim_dentry *dentry, void *arg)
{
#ifdef __WIN32__
	return do_apply_op(dentry, arg, win32_do_apply_dentry_timestamps);
#else
	return do_apply_op(dentry, arg, unix_do_apply_dentry_timestamps);
#endif
}

static bool
dentry_is_descendent(const struct wim_dentry *dentry,
		     const struct wim_dentry *ancestor)
{
	for (;;) {
		if (dentry == ancestor)
			return true;
		if (dentry_is_root(dentry))
			return false;
		dentry = dentry->parent;
	}
}

/* Extract a dentry if it hasn't already been extracted and either
 * WIMLIB_EXTRACT_FLAG_NO_STREAMS is not specified, or the dentry is a directory
 * and/or has no unnamed stream. */
static int
maybe_apply_dentry(struct wim_dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	int ret;

	if (dentry->is_extracted)
		return 0;

	if (!dentry_is_descendent(dentry, args->extract_root))
		return 0;

	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_NO_STREAMS &&
	    !dentry_is_directory(dentry) &&
	    inode_unnamed_lte_resolved(dentry->d_inode) != NULL)
		return 0;

	if ((args->extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE) &&
	     args->progress_func) {
		args->progress.extract.cur_path = dentry->_full_path;
		args->progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY,
				    &args->progress);
	}
	ret = args->apply_dentry(dentry, args);
	if (ret == 0)
		dentry->is_extracted = 1;
	return ret;
}

static void
calculate_bytes_to_extract(struct list_head *stream_list,
			   int extract_flags,
			   union wimlib_progress_info *progress)
{
	struct wim_lookup_table_entry *lte;
	u64 total_bytes = 0;
	u64 num_streams = 0;

	/* For each stream to be extracted... */
	list_for_each_entry(lte, stream_list, extraction_list) {
		if (extract_flags &
		    (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
		{
			/* In the symlink or hard link extraction mode, each
			 * stream will be extracted one time regardless of how
			 * many dentries share the stream. */
			wimlib_assert(!(extract_flags & WIMLIB_EXTRACT_FLAG_NTFS));
			if (!lte->extracted_file) {
				num_streams++;
				total_bytes += wim_resource_size(lte);
			}
		} else {
			num_streams += lte->out_refcnt;
			total_bytes += lte->out_refcnt * wim_resource_size(lte);
		}
	}
	progress->extract.num_streams = num_streams;
	progress->extract.total_bytes = total_bytes;
	progress->extract.completed_bytes = 0;
}

static void
maybe_add_stream_for_extraction(struct wim_lookup_table_entry *lte,
				struct list_head *stream_list)
{
	if (++lte->out_refcnt == 1) {
		INIT_LIST_HEAD(&lte->inode_list);
		list_add_tail(&lte->extraction_list, stream_list);
	}
}

static void
inode_find_streams_for_extraction(struct wim_inode *inode,
				  struct list_head *stream_list,
				  int extract_flags)
{
	struct wim_lookup_table_entry *lte;
	bool inode_added = false;

	lte = inode_unnamed_lte_resolved(inode);
	if (lte) {
		maybe_add_stream_for_extraction(lte, stream_list);
		list_add_tail(&inode->i_lte_inode_list, &lte->inode_list);
		inode_added = true;
	}

	/* Determine whether to include alternate data stream entries or not.
	 *
	 * UNIX:  Include them if extracting using NTFS-3g.
	 *
	 * Windows: Include them undconditionally, although if the filesystem is
	 * not NTFS we won't actually be able to extract them. */
#if defined(WITH_NTFS_3G)
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS)
#elif defined(__WIN32__)
	if (1)
#else
	if (0)
#endif
	{
		for (unsigned i = 0; i < inode->i_num_ads; i++) {
			if (inode->i_ads_entries[i].stream_name_nbytes != 0) {
				lte = inode->i_ads_entries[i].lte;
				if (lte) {
					maybe_add_stream_for_extraction(lte,
									stream_list);
					if (!inode_added) {
						list_add_tail(&inode->i_lte_inode_list,
							      &lte->inode_list);
						inode_added = true;
					}
				}
			}
		}
	}
}

struct find_streams_ctx {
	struct list_head stream_list;
	int extract_flags;
};

static int
dentry_find_streams_to_extract(struct wim_dentry *dentry, void *_ctx)
{
	struct find_streams_ctx *ctx = _ctx;
	struct wim_inode *inode = dentry->d_inode;

	dentry->is_extracted = 0;
	if (!inode->i_visited) {
		inode_find_streams_for_extraction(inode, &ctx->stream_list,
						  ctx->extract_flags);
		inode->i_visited = 1;
	}
	return 0;
}

static int
dentry_resolve_and_zero_lte_refcnt(struct wim_dentry *dentry, void *_lookup_table)
{
	struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table *lookup_table = _lookup_table;
	struct wim_lookup_table_entry *lte;

	inode_resolve_ltes(inode, lookup_table);
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		lte = inode_stream_lte_resolved(inode, i);
		if (lte)
			lte->out_refcnt = 0;
	}
	return 0;
}

static void
find_streams_for_extraction(struct wim_dentry *root,
			    struct list_head *stream_list,
			    struct wim_lookup_table *lookup_table,
			    int extract_flags)
{
	struct find_streams_ctx ctx;

	INIT_LIST_HEAD(&ctx.stream_list);
	ctx.extract_flags = extract_flags;
	for_dentry_in_tree(root, dentry_resolve_and_zero_lte_refcnt, lookup_table);
	for_dentry_in_tree(root, dentry_find_streams_to_extract, &ctx);
	list_transfer(&ctx.stream_list, stream_list);
}

static int
dentry_mark_inode_unvisited(struct wim_dentry *dentry, void *_ignore)
{
	dentry->d_inode->i_visited = 0;
	return 0;
}

struct apply_operations {
	int (*apply_dentry)(struct wim_dentry *dentry, void *arg);
	int (*apply_dentry_timestamps)(struct wim_dentry *dentry, void *arg);
};

static const struct apply_operations normal_apply_operations = {
	.apply_dentry = apply_dentry_normal,
	.apply_dentry_timestamps = apply_dentry_timestamps_normal,
};

#ifdef WITH_NTFS_3G
static const struct apply_operations ntfs_apply_operations = {
	.apply_dentry = apply_dentry_ntfs,
	.apply_dentry_timestamps = apply_dentry_timestamps_ntfs,
};
#endif

static int
apply_stream_list(struct list_head *stream_list,
		  struct apply_args *args,
		  const struct apply_operations *ops,
		  wimlib_progress_func_t progress_func)
{
	uint64_t bytes_per_progress = args->progress.extract.total_bytes / 100;
	uint64_t next_progress = bytes_per_progress;
	struct wim_lookup_table_entry *lte;
	struct wim_inode *inode;
	struct wim_dentry *dentry;
	int ret;

	/* This complicated loop is essentially looping through the dentries,
	 * although dentries may be visited more than once (if a dentry contains
	 * two different nonempty streams) or not at all (if a dentry contains
	 * no non-empty streams).
	 *
	 * The outer loop is over the distinct streams to be extracted so that
	 * sequential reading of the WIM can be implemented. */

	/* For each distinct stream to be extracted */
	list_for_each_entry(lte, stream_list, extraction_list) {
		/* For each inode that contains the stream */
		list_for_each_entry(inode, &lte->inode_list, i_lte_inode_list) {
			/* For each dentry that points to the inode */
			inode_for_each_dentry(dentry, inode) {
				/* Extract the dentry if it was not already
				 * extracted */
				ret = maybe_apply_dentry(dentry, args);
				if (ret)
					return ret;
				if (progress_func &&
				    args->progress.extract.completed_bytes >= next_progress)
				{
					progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS,
						      &args->progress);
					if (args->progress.extract.completed_bytes >=
					    args->progress.extract.total_bytes)
					{
						next_progress = ~0ULL;
					} else {
						next_progress =
							min (args->progress.extract.completed_bytes +
							     bytes_per_progress,
							     args->progress.extract.total_bytes);
					}
				}
			}
		}
	}
	return 0;
}

static int
sort_stream_list_by_wim_position(struct list_head *stream_list)
{
	struct list_head *cur;
	size_t num_streams;
	struct wim_lookup_table_entry **array;
	size_t i;
	size_t array_size;

	num_streams = 0;
	list_for_each(cur, stream_list)
		num_streams++;
	array_size = num_streams * sizeof(array[0]);
	array = MALLOC(array_size);
	if (!array) {
		ERROR("Failed to allocate %zu bytes to sort stream entries",
		      array_size);
		return WIMLIB_ERR_NOMEM;
	}
	cur = stream_list->next;
	for (i = 0; i < num_streams; i++) {
		array[i] = container_of(cur, struct wim_lookup_table_entry, extraction_list);
		cur = cur->next;
	}

	qsort(array, num_streams, sizeof(array[0]), cmp_streams_by_wim_position);

	INIT_LIST_HEAD(stream_list);
	for (i = 0; i < num_streams; i++)
		list_add_tail(&array[i]->extraction_list, stream_list);
	FREE(array);
	return 0;
}

/*
 * Extract a dentry to standard output.
 *
 * This obviously doesn't make sense in all cases.  We return an error if the
 * dentry does not correspond to a regular file.  Otherwise we extract the
 * unnamed data stream only.
 */
static int
extract_dentry_to_stdout(struct wim_dentry *dentry)
{
	int ret = 0;
	if (!dentry_is_regular_file(dentry)) {
		ERROR("\"%"TS"\" is not a regular file and therefore cannot be "
		      "extracted to standard output", dentry->_full_path);
		ret = WIMLIB_ERR_NOT_A_REGULAR_FILE;
	} else {
		struct wim_lookup_table_entry *lte;

		lte = inode_unnamed_lte_resolved(dentry->d_inode);
		if (lte) {
			ret = extract_wim_resource_to_fd(lte, STDOUT_FILENO,
							 wim_resource_size(lte));
		}
	}
	return ret;
}

/*
 * extract_tree - Extract a file or directory tree from the currently selected
 *		  WIM image.
 *
 * @wim:	WIMStruct for the WIM file, with the desired image selected
 *		(as wim->current_image).
 * @wim_source_path:
 *		"Canonical" (i.e. no leading or trailing slashes, path
 *		separators forwald slashes) path inside the WIM image to
 *		extract.  An empty string means the full image.
 * @target:
 *		Filesystem path to extract the file or directory tree to.
 *
 * @extract_flags:
 *		WIMLIB_EXTRACT_FLAG_*.  Also, the private flag
 *		WIMLIB_EXTRACT_FLAG_MULTI_IMAGE will be set if this is being
 *		called through wimlib_extract_image() with WIMLIB_ALL_IMAGES as
 *		the image.
 *
 * @progress_func:
 *		If non-NULL, progress function for the extraction.  The messages
 *		we may in this function are:
 *
 *		WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN or
 *			WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS;
 *		WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS;
 *		WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END or
 *			WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
extract_tree(WIMStruct *wim, const tchar *wim_source_path, const tchar *target,
	     int extract_flags, wimlib_progress_func_t progress_func)
{
	int ret;
	struct list_head stream_list;
	struct apply_args args;
	const struct apply_operations *ops;
	struct wim_dentry *root;

	memset(&args, 0, sizeof(args));

	args.w                      = wim;
	args.target                 = target;
	args.extract_flags          = extract_flags;
	args.progress_func          = progress_func;
	args.target_nchars          = tstrlen(target);
	args.wim_source_path_nchars = tstrlen(wim_source_path);

	if (progress_func) {
		args.progress.extract.wimfile_name = wim->filename;
		args.progress.extract.image = wim->current_image;
		args.progress.extract.extract_flags = (extract_flags &
						       WIMLIB_EXTRACT_MASK_PUBLIC);
		args.progress.extract.image_name = wimlib_get_image_name(wim,
									 wim->current_image);
		args.progress.extract.extract_root_wim_source_path = wim_source_path;
		args.progress.extract.target = target;
	}

#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		args.vol = ntfs_mount(target, 0);
		if (!args.vol) {
			ERROR_WITH_ERRNO("Failed to mount NTFS volume `%"TS"'",
					 target);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out;
		}
		ops = &ntfs_apply_operations;
	} else
#endif
		ops = &normal_apply_operations;

	root = get_dentry(wim, wim_source_path);
	if (!root) {
		ERROR("Path \"%"TS"\" does not exist in WIM image %d",
		      wim_source_path, wim->current_image);
		ret = WIMLIB_ERR_PATH_DOES_NOT_EXIST;
		goto out_ntfs_umount;
	}
	args.extract_root = root;

	ret = calculate_dentry_tree_full_paths(root);
	if (ret)
		goto out_ntfs_umount;


	/* Build a list of the streams that need to be extracted */
	find_streams_for_extraction(root,
				    &stream_list,
				    wim->lookup_table, extract_flags);

	/* Calculate the number of bytes of data that will be extracted */
	calculate_bytes_to_extract(&stream_list, extract_flags,
				   &args.progress);

	if (extract_flags & WIMLIB_EXTRACT_FLAG_TO_STDOUT) {
		ret = extract_dentry_to_stdout(root);
		goto out_mark_inodes_unvisited;
	}

	if (progress_func) {
		progress_func(*wim_source_path ? WIMLIB_PROGRESS_MSG_EXTRACT_TREE_BEGIN :
			      WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN,
			      &args.progress);
	}

	/* If a sequential extraction was specified, sort the streams to be
	 * extracted by their position in the WIM file, so that the WIM file can
	 * be read sequentially. */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL) {
		ret = sort_stream_list_by_wim_position(&stream_list);
		if (ret != 0) {
			WARNING("Falling back to non-sequential extraction");
			extract_flags &= ~WIMLIB_EXTRACT_FLAG_SEQUENTIAL;
		}
	}

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,
			      &args.progress);
	}

	/* Make the directory structure and extract empty files */
	args.extract_flags |= WIMLIB_EXTRACT_FLAG_NO_STREAMS;
	args.apply_dentry = ops->apply_dentry;
	ret = for_dentry_in_tree(root, maybe_apply_dentry, &args);
	args.extract_flags &= ~WIMLIB_EXTRACT_FLAG_NO_STREAMS;
	if (ret)
		goto out_mark_inodes_unvisited;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,
			      &args.progress);
	}

	if (extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX) {
		args.target_realpath = realpath(target, NULL);
		if (!args.target_realpath) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_mark_inodes_unvisited;
		}
		args.target_realpath_len = tstrlen(args.target_realpath);
	}

	/* Extract non-empty files */
	ret = apply_stream_list(&stream_list, &args, ops, progress_func);
	if (ret)
		goto out_free_target_realpath;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS,
			      &args.progress);
	}

	/* Apply timestamps */
	ret = for_dentry_in_tree_depth(root,
				       ops->apply_dentry_timestamps, &args);
	if (ret)
		goto out_free_target_realpath;

	if (progress_func) {
		progress_func(*wim_source_path ? WIMLIB_PROGRESS_MSG_EXTRACT_TREE_END :
			      WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END,
			      &args.progress);
	}
out_free_target_realpath:
	FREE(args.target_realpath);
out_mark_inodes_unvisited:
	for_dentry_in_tree(root, dentry_mark_inode_unvisited, NULL);
out_ntfs_umount:
#ifdef WITH_NTFS_3G
	/* Unmount the NTFS volume */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		if (ntfs_umount(args.vol, FALSE) != 0) {
			ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%"TS"'",
					 args.target);
			if (ret == 0)
				ret = WIMLIB_ERR_NTFS_3G;
		}
	}
#endif
out:
	return ret;
}

/* Validates a single wimlib_extract_command, mostly checking to make sure the
 * extract flags make sense. */
static int
check_extract_command(struct wimlib_extract_command *cmd, int wim_header_flags)
{
	int extract_flags;
	bool is_entire_image = (cmd->wim_source_path[0] == T('\0'));

	/* Empty destination path? */
	if (cmd->fs_dest_path[0] == T('\0'))
		return WIMLIB_ERR_INVALID_PARAM;

	extract_flags = cmd->extract_flags;

	/* Specified both symlink and hardlink modes? */
	if ((extract_flags &
	     (WIMLIB_EXTRACT_FLAG_SYMLINK |
	      WIMLIB_EXTRACT_FLAG_HARDLINK)) == (WIMLIB_EXTRACT_FLAG_SYMLINK |
						 WIMLIB_EXTRACT_FLAG_HARDLINK))
		return WIMLIB_ERR_INVALID_PARAM;

#ifdef __WIN32__
	/* Wanted UNIX data on Win32? */
	if (extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
		ERROR("Extracting UNIX data is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	/* Wanted linked extraction on Windows?  (XXX This is possible, just not
	 * implemented yet.) */
	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		ERROR("Linked extraction modes are not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
#endif

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		/* NTFS-3g extraction mode requested */
#ifdef WITH_NTFS_3G
		if ((extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
				      WIMLIB_EXTRACT_FLAG_HARDLINK))) {
			ERROR("Cannot specify symlink or hardlink flags when applying\n"
			      "        directly to a NTFS volume");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (!is_entire_image &&
		    (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS))
		{
			ERROR("When applying directly to a NTFS volume you can "
			      "only extract a full image, not part of one");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (extract_flags & WIMLIB_EXTRACT_FLAG_UNIX_DATA) {
			ERROR("Cannot restore UNIX-specific data in "
			      "the NTFS extraction mode");
			return WIMLIB_ERR_INVALID_PARAM;
		}
#else
		ERROR("wimlib was compiled without support for NTFS-3g, so");
		ERROR("we cannot apply a WIM image directly to a NTFS volume");
		return WIMLIB_ERR_UNSUPPORTED;
#endif
	}

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_RPFIX |
			      WIMLIB_EXTRACT_FLAG_NORPFIX)) ==
		(WIMLIB_EXTRACT_FLAG_RPFIX | WIMLIB_EXTRACT_FLAG_NORPFIX))
	{
		ERROR("Cannot specify RPFIX and NORPFIX flags at the same time!");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_RPFIX |
			      WIMLIB_EXTRACT_FLAG_NORPFIX)) == 0)
	{
		/* Do reparse point fixups by default if the WIM header says
		 * they are enabled and we are extracting a full image. */
		if ((wim_header_flags & WIM_HDR_FLAG_RP_FIX) && is_entire_image)
			extract_flags |= WIMLIB_EXTRACT_FLAG_RPFIX;
	}

	if (!is_entire_image && (extract_flags & WIMLIB_EXTRACT_FLAG_RPFIX)) {
		ERROR("Cannot specify --rpfix when not extracting entire image");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	cmd->extract_flags = extract_flags;
	return 0;
}


/* Internal function to execute extraction commands for a WIM image. */
static int
do_wimlib_extract_files(WIMStruct *wim,
			int image,
			struct wimlib_extract_command *cmds,
			size_t num_cmds,
			wimlib_progress_func_t progress_func)
{
	int ret;
	bool found_link_cmd = false;
	bool found_nolink_cmd = false;

	/* Select the image from which we are extracting files */
	ret = select_wim_image(wim, image);
	if (ret)
		return ret;

	/* Make sure there are no streams in the WIM that have not been
	 * checksummed yet. */
	ret = wim_checksum_unhashed_streams(wim);
	if (ret)
		return ret;

	/* Check for problems with the extraction commands */
	for (size_t i = 0; i < num_cmds; i++) {
		ret = check_extract_command(&cmds[i], wim->hdr.flags);
		if (ret)
			return ret;
		if (cmds[i].extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
					     WIMLIB_EXTRACT_FLAG_HARDLINK)) {
			found_link_cmd = true;
		} else {
			found_nolink_cmd = true;
		}
		if (found_link_cmd && found_nolink_cmd) {
			ERROR("Symlink or hardlink extraction mode must "
			      "be set on all extraction commands");
			return WIMLIB_ERR_INVALID_PARAM;
		}
	}

	/* Execute the extraction commands */
	for (size_t i = 0; i < num_cmds; i++) {
		ret = extract_tree(wim,
				   cmds[i].wim_source_path,
				   cmds[i].fs_dest_path,
				   cmds[i].extract_flags,
				   progress_func);
		if (ret)
			return ret;
	}
	return 0;
}

/* Extract files or directories from a WIM image. */
WIMLIBAPI int
wimlib_extract_files(WIMStruct *wim,
		     int image,
		     int default_extract_flags,
		     const struct wimlib_extract_command *cmds,
		     size_t num_cmds,
		     WIMStruct **additional_swms,
		     unsigned num_additional_swms,
		     wimlib_progress_func_t progress_func)
{
	int ret;
	struct wimlib_extract_command *cmds_copy;
	struct wim_lookup_table *wim_tab_save, *joined_tab;
	int all_flags = 0;

	default_extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	ret = verify_swm_set(wim, additional_swms, num_additional_swms);
	if (ret)
		goto out;

	if (num_additional_swms) {
		ret = new_joined_lookup_table(wim, additional_swms,
					      num_additional_swms,
					      &joined_tab);
		if (ret)
			goto out;
		wim_tab_save = wim->lookup_table;
		wim->lookup_table = joined_tab;
	}

	cmds_copy = CALLOC(num_cmds, sizeof(cmds[0]));
	if (!cmds_copy) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_restore_lookup_table;
	}

	for (size_t i = 0; i < num_cmds; i++) {
		cmds_copy[i].extract_flags = (default_extract_flags |
						 cmds[i].extract_flags)
						& WIMLIB_EXTRACT_MASK_PUBLIC;
		all_flags |= cmds_copy[i].extract_flags;

		cmds_copy[i].wim_source_path = canonicalize_wim_path(cmds[i].wim_source_path);
		if (!cmds_copy[i].wim_source_path) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_cmds_copy;
		}

		cmds_copy[i].fs_dest_path = canonicalize_fs_path(cmds[i].fs_dest_path);
		if (!cmds_copy[i].fs_dest_path) {
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_cmds_copy;
		}

	}
	ret = do_wimlib_extract_files(wim, image,
				      cmds_copy, num_cmds,
				      progress_func);

	if (all_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			 WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(wim->lookup_table,
				       lte_free_extracted_file, NULL);
	}
out_free_cmds_copy:
	for (size_t i = 0; i < num_cmds; i++) {
		FREE(cmds_copy[i].wim_source_path);
		FREE(cmds_copy[i].fs_dest_path);
	}
	FREE(cmds_copy);
out_restore_lookup_table:
	if (num_additional_swms) {
		free_lookup_table(wim->lookup_table);
		wim->lookup_table = wim_tab_save;
	}
out:
	return ret;
}

/*
 * Extracts an image from a WIM file.
 *
 * @wim:		WIMStruct for the WIM file.
 *
 * @image:		Number of the single image to extract.
 *
 * @target:		Directory or NTFS volume to extract the image to.
 *
 * @extract_flags:	Bitwise or of WIMLIB_EXTRACT_FLAG_*.
 *
 * @progress_func:	If non-NULL, a progress function to be called
 *			periodically.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
extract_single_image(WIMStruct *wim, int image,
		     const tchar *target, int extract_flags,
		     wimlib_progress_func_t progress_func)
{
	int ret;
	tchar *target_copy = canonicalize_fs_path(target);
	if (!target_copy)
		return WIMLIB_ERR_NOMEM;
	struct wimlib_extract_command cmd = {
		.wim_source_path = T(""),
		.fs_dest_path = target_copy,
		.extract_flags = extract_flags,
	};
	ret = do_wimlib_extract_files(wim, image, &cmd, 1, progress_func);
	FREE(target_copy);
	return ret;
}

static const tchar * const filename_forbidden_chars =
T(
#ifdef __WIN32__
"<>:\"/\\|?*"
#else
"/"
#endif
);

/* This function checks if it is okay to use a WIM image's name as a directory
 * name.  */
static bool
image_name_ok_as_dir(const tchar *image_name)
{
	return image_name && *image_name &&
		!tstrpbrk(image_name, filename_forbidden_chars);
}

/* Extracts all images from the WIM to the directory @target, with the images
 * placed in subdirectories named by their image names. */
static int
extract_all_images(WIMStruct *wim,
		   const tchar *target,
		   int extract_flags,
		   wimlib_progress_func_t progress_func)
{
	size_t image_name_max_len = max(xml_get_max_image_name_len(wim), 20);
	size_t output_path_len = tstrlen(target);
	tchar buf[output_path_len + 1 + image_name_max_len + 1];
	int ret;
	int image;
	const tchar *image_name;

	ret = extract_directory(NULL, target, true);
	if (ret)
		return ret;

	tmemcpy(buf, target, output_path_len);
	buf[output_path_len] = T('/');
	for (image = 1; image <= wim->hdr.image_count; image++) {
		image_name = wimlib_get_image_name(wim, image);
		if (image_name_ok_as_dir(image_name)) {
			tstrcpy(buf + output_path_len + 1, image_name);
		} else {
			/* Image name is empty or contains forbidden characters.
			 * Use image number instead. */
			tsprintf(buf + output_path_len + 1, T("%d"), image);
		}
		ret = extract_single_image(wim, image, buf, extract_flags,
					   progress_func);
		if (ret)
			return ret;
	}
	return 0;
}

/* Extracts a single image or all images from a WIM file to a directory or NTFS
 * volume. */
WIMLIBAPI int
wimlib_extract_image(WIMStruct *wim,
		     int image,
		     const tchar *target,
		     int extract_flags,
		     WIMStruct **additional_swms,
		     unsigned num_additional_swms,
		     wimlib_progress_func_t progress_func)
{
	struct wim_lookup_table *joined_tab, *wim_tab_save;
	int ret;

	extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	ret = verify_swm_set(wim, additional_swms, num_additional_swms);
	if (ret)
		return ret;

	if (num_additional_swms) {
		ret = new_joined_lookup_table(wim, additional_swms,
					      num_additional_swms, &joined_tab);
		if (ret)
			return ret;
		wim_tab_save = wim->lookup_table;
		wim->lookup_table = joined_tab;
	}

	if (image == WIMLIB_ALL_IMAGES) {
		extract_flags |= WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;
		ret = extract_all_images(wim, target, extract_flags,
					 progress_func);
	} else {
		extract_flags &= ~WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;
		ret = extract_single_image(wim, image, target, extract_flags,
					   progress_func);
	}

	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(wim->lookup_table,
				       lte_free_extracted_file,
				       NULL);
	}
	if (num_additional_swms) {
		free_lookup_table(wim->lookup_table);
		wim->lookup_table = wim_tab_save;
	}
	return ret;
}
