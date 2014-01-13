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

#include "wimlib/apply.h"
#include "wimlib/error.h"
#include "wimlib/resource.h"
#include "wimlib/timestamp.h"
#include "wimlib/unix_data.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef HAVE_UTIME_H
#  include <utime.h>
#endif

static int
unix_start_extract(const char *target, struct apply_ctx *ctx)
{
	ctx->supported_features.hard_links = 1;
	ctx->supported_features.symlink_reparse_points = 1;
	ctx->supported_features.unix_data = 1;
	return 0;
}

static int
unix_create_file(const char *path, struct apply_ctx *ctx, u64 *cookie_ret)
{
	int fd = open(path, O_TRUNC | O_CREAT | O_WRONLY, 0644);
	if (fd < 0)
		return WIMLIB_ERR_OPEN;
	close(fd);
	return 0;
}

static int
unix_create_directory(const tchar *path, struct apply_ctx *ctx, u64 *cookie_ret)
{
	struct stat stbuf;

	if (mkdir(path, 0755)) {
		if (errno != EEXIST)
			return WIMLIB_ERR_MKDIR;
		if (lstat(path, &stbuf))
			return WIMLIB_ERR_MKDIR;
		errno = EEXIST;
		if (!S_ISDIR(stbuf.st_mode))
			return WIMLIB_ERR_MKDIR;
	}
	return 0;
}

static int
unix_makelink(const tchar *oldpath, const tchar *newpath,
	      int (*makelink)(const tchar *oldpath, const tchar *newpath))
{
	if ((*makelink)(oldpath, newpath)) {
		if (errno != EEXIST)
			return WIMLIB_ERR_LINK;
		if (unlink(newpath))
			return WIMLIB_ERR_LINK;
		if ((*makelink)(oldpath, newpath))
			return WIMLIB_ERR_LINK;
	}
	return 0;
}
static int
unix_create_hardlink(const tchar *oldpath, const tchar *newpath,
		     struct apply_ctx *ctx)
{
	return unix_makelink(oldpath, newpath, link);
}

static int
unix_create_symlink(const tchar *oldpath, const tchar *newpath,
		    struct apply_ctx *ctx)
{
	return unix_makelink(oldpath, newpath, symlink);
}

static int
unix_extract_unnamed_stream(file_spec_t file,
			    struct wim_lookup_table_entry *lte,
			    struct apply_ctx *ctx)
{
	const char *path = file.path;
	struct filedes fd;
	int raw_fd;
	int ret;

	raw_fd = open(path, O_WRONLY | O_TRUNC);
	if (raw_fd < 0)
		return WIMLIB_ERR_OPEN;
	filedes_init(&fd, raw_fd);
	ret = extract_full_stream_to_fd(lte, &fd);
	if (filedes_close(&fd) && !ret)
		ret = WIMLIB_ERR_WRITE;
	return ret;
}

static int
unix_set_unix_data(const tchar *path, const struct wimlib_unix_data *data,
		   struct apply_ctx *ctx)
{
	struct stat stbuf;

	if (lstat(path, &stbuf))
		return WIMLIB_ERR_SET_SECURITY;
	if (!S_ISLNK(stbuf.st_mode))
		if (chmod(path, data->mode))
			return WIMLIB_ERR_SET_SECURITY;
	if (lchown(path, data->uid, data->gid))
		return WIMLIB_ERR_SET_SECURITY;
	return 0;
}

static int
unix_set_timestamps(const tchar *path, u64 creation_time, u64 last_write_time,
		    u64 last_access_time, struct apply_ctx *ctx)
{
	int ret;

#ifdef HAVE_UTIMENSAT
	/* Convert the WIM timestamps, which are accurate to 100 nanoseconds,
	 * into `struct timespec's for passing to utimensat(), which is accurate
	 * to 1 nanosecond. */

	struct timespec ts[2];
	ts[0] = wim_timestamp_to_timespec(last_access_time);
	ts[1] = wim_timestamp_to_timespec(last_write_time);
	ret = utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
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
		tv[0] = wim_timestamp_to_timeval(last_access_time);
		tv[1] = wim_timestamp_to_timeval(last_write_time);
		ret = lutimes(path, tv);
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
		buf.actime = wim_timestamp_to_unix(last_access_time);
		buf.modtime = wim_timestamp_to_unix(last_write_time);
		ret = utime(path, &buf);
	#endif
	}
	if (ret)
		return WIMLIB_ERR_SET_TIMESTAMPS;
	return 0;
}

const struct apply_operations unix_apply_ops = {
	.name = "UNIX",

	.start_extract          = unix_start_extract,
	.create_file            = unix_create_file,
	.create_directory       = unix_create_directory,
	.create_hardlink        = unix_create_hardlink,
	.create_symlink         = unix_create_symlink,
	.extract_unnamed_stream = unix_extract_unnamed_stream,
	.set_unix_data          = unix_set_unix_data,
	.set_timestamps         = unix_set_timestamps,

	.path_separator = '/',
	.path_max = PATH_MAX,

	.requires_target_in_paths = 1,
	.supports_case_sensitive_filenames = 1,
};

#endif /* !__WIN32__ */
