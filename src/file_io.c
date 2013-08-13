/*
 * file_io.c - Helper functions for reading and writing to file descriptors.
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

#include "wimlib/assert.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/util.h"
#ifdef __WIN32__
#  include "wimlib/win32.h" /* For pread(), pwrite() replacements */
#else
#  include <sys/uio.h> /* for writev() and `struct iovec' */
#endif

#include <errno.h>
#include <unistd.h>


/* Wrapper around read() that keeps retrying until all requested bytes have been
 * read or until end-of file has occurred.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS			(0)
 *	WIMLIB_ERR_READ				(errno set)
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE	(errno set to 0)
 */
int
full_read(struct filedes *fd, void *buf, size_t count)
{
	ssize_t bytes_read;
	size_t bytes_remaining;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_read, buf += bytes_read)
	{
		bytes_read = read(fd->fd, buf, bytes_remaining);
		if (unlikely(bytes_read <= 0)) {
			if (bytes_read == 0) {
				errno = 0;
				return WIMLIB_ERR_UNEXPECTED_END_OF_FILE;
			} else if (errno == EINTR) {
				continue;
			} else {
				return WIMLIB_ERR_READ;
			}
		}
	}
	count -= bytes_remaining;
	fd->offset += count;
	return 0;
}

static int
pipe_read(struct filedes *fd, void *buf, size_t count, off_t offset)
{
	int ret;

	if (offset < fd->offset) {
		ERROR("Can't seek backwards in pipe "
		      "(offset %"PRIu64" => %"PRIu64").\n"
		      "      Make sure the WIM was captured as "
		      "pipable.",
			fd->offset, offset);
		errno = ESPIPE;
		return WIMLIB_ERR_RESOURCE_ORDER;
	}
	while (fd->offset != offset) {
		size_t bytes_to_read = min(offset - fd->offset, BUFFER_SIZE);
		u8 dummy[bytes_to_read];

		ret = full_read(fd, dummy, bytes_to_read);
		if (ret)
			return ret;
	}
	return full_read(fd, buf, count);
}

/* Wrapper around pread() that keep retrying until all requested bytes have been
 * read or until end-of file has occurred.  This also transparently handle
 * reading from pipe files, but the caller needs to be sure the requested offset
 * is greater than or equal to the current offset, or else
 * WIMLIB_ERR_RESOURCE_ORDER will be returned.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS			(0)
 *	WIMLIB_ERR_READ				(errno set)
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE	(errno set to 0)
 *	WIMLIB_ERR_RESOURCE_ORDER		(errno set to ESPIPE)
 * */
int
full_pread(struct filedes *fd, void *buf, size_t count, off_t offset)
{
	ssize_t bytes_read;
	size_t bytes_remaining;

	if (fd->is_pipe)
		goto is_pipe;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_read, buf += bytes_read,
	     	offset += bytes_read)
	{
		bytes_read = pread(fd->fd, buf, bytes_remaining, offset);
		if (unlikely(bytes_read <= 0)) {
			if (bytes_read == 0) {
				errno = 0;
				return WIMLIB_ERR_UNEXPECTED_END_OF_FILE;
			} else if (errno == EINTR) {
				continue;
			} else if (errno == ESPIPE) {
				wimlib_assert(count == bytes_remaining);
				fd->is_pipe = 1;
				goto is_pipe;
			} else {
				return WIMLIB_ERR_READ;
			}
		}
	}
	return 0;

is_pipe:
	return pipe_read(fd, buf, count, offset);
}

/* Wrapper around write() that keeps retrying until all requested bytes have
 * been written.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS			(0)
 *	WIMLIB_ERR_WRITE			(errno set)
 */
int
full_write(struct filedes *fd, const void *buf, size_t count)
{
	ssize_t bytes_written;
	size_t bytes_remaining;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_written, buf += bytes_written)
	{
		bytes_written = write(fd->fd, buf, bytes_remaining);
		if (unlikely(bytes_written < 0)) {
			if (errno == EINTR)
				continue;
			return WIMLIB_ERR_WRITE;
		}
	}
	fd->offset += count;
	return 0;
}


/* Wrapper around pwrite() that keep retrying until all requested bytes have been
 * written.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS	(0)
 *	WIMLIB_ERR_WRITE	(errno set)
 * */
int
full_pwrite(struct filedes *fd, const void *buf, size_t count, off_t offset)
{
	ssize_t bytes_written;
	size_t bytes_remaining;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_written, buf += bytes_written,
	     	offset += bytes_written)
	{
		bytes_written = pwrite(fd->fd, buf, bytes_remaining, offset);
		if (unlikely(bytes_written < 0)) {
			if (errno == EINTR)
				continue;
			return WIMLIB_ERR_WRITE;
		}
	}
	return 0;
}

/* Wrapper around writev() that keep retrying until all requested bytes have been
 * written.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS	(0)
 *	WIMLIB_ERR_WRITE	(errno set)
 * */
int
full_writev(struct filedes *fd, struct iovec *iov, int iovcnt)
{
	size_t total_bytes_written = 0;
	while (iovcnt > 0) {
		ssize_t bytes_written;

		bytes_written = writev(fd->fd, iov, iovcnt);
		if (bytes_written < 0) {
			if (errno == EINTR)
				continue;
			return WIMLIB_ERR_WRITE;
		}
		total_bytes_written += bytes_written;
		while (bytes_written) {
			if (bytes_written >= iov[0].iov_len) {
				bytes_written -= iov[0].iov_len;
				iov++;
				iovcnt--;
			} else {
				iov[0].iov_base += bytes_written;
				iov[0].iov_len -= bytes_written;
				bytes_written = 0;
			}
		}
	}
	fd->offset += total_bytes_written;
	return 0;
}

ssize_t
raw_pread(struct filedes *fd, void *buf, size_t count, off_t offset)
{
	return pread(fd->fd, buf, count, offset);
}

ssize_t
raw_pwrite(struct filedes *fd, const void *buf, size_t count, off_t offset)
{
	return pwrite(fd->fd, buf, count, offset);
}

off_t filedes_seek(struct filedes *fd, off_t offset)
{
	if (fd->is_pipe) {
		errno = ESPIPE;
		return -1;
	}
	if (fd->offset != offset) {
		if (lseek(fd->fd, offset, SEEK_SET) == -1)
			return -1;
		fd->offset = offset;
	}
	return offset;
}

bool filedes_is_seekable(struct filedes *fd)
{
	return !fd->is_pipe && lseek(fd->fd, 0, SEEK_CUR) != -1;
}
