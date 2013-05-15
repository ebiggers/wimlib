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

#include "wimlib/file_io.h"
#ifdef __WIN32__
#  include "wimlib/win32.h" /* For pread(), pwrite() replacements */
#else
#  include <sys/uio.h> /* for writev() and `struct iovec' */
#endif

#include <errno.h>
#include <unistd.h>


/* Like read(), but keep trying until everything has been written or we know for
 * sure that there was an error (or end-of-file). */
size_t
full_read(int fd, void *buf, size_t count)
{
	ssize_t bytes_read;
	size_t bytes_remaining;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_read, buf += bytes_read)
	{
		bytes_read = read(fd, buf, bytes_remaining);
		if (bytes_read <= 0) {
			if (bytes_read == 0)
				errno = EIO;
			else if (errno == EINTR)
				continue;
			break;
		}
	}
	return count - bytes_remaining;
}

/* Like write(), but keep trying until everything has been written or we know
 * for sure that there was an error. */
size_t
full_write(int fd, const void *buf, size_t count)
{
	ssize_t bytes_written;
	size_t bytes_remaining;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_written, buf += bytes_written)
	{
		bytes_written = write(fd, buf, bytes_remaining);
		if (bytes_written < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
	}
	return count - bytes_remaining;
}

/* Like pread(), but keep trying until everything has been read or we know for
 * sure that there was an error (or end-of-file) */
size_t
full_pread(int fd, void *buf, size_t count, off_t offset)
{
	ssize_t bytes_read;
	size_t bytes_remaining;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_read, buf += bytes_read,
	     	offset += bytes_read)
	{
		bytes_read = pread(fd, buf, bytes_remaining, offset);
		if (bytes_read <= 0) {
			if (bytes_read == 0)
				errno = EIO;
			else if (errno == EINTR)
				continue;
			break;
		}
	}
	return count - bytes_remaining;
}

/* Like pwrite(), but keep trying until everything has been written or we know
 * for sure that there was an error. */
size_t
full_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	ssize_t bytes_written;
	size_t bytes_remaining;

	for (bytes_remaining = count;
	     bytes_remaining != 0;
	     bytes_remaining -= bytes_written, buf += bytes_written,
	     	offset += bytes_written)
	{
		bytes_written = pwrite(fd, buf, bytes_remaining, offset);
		if (bytes_written < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
	}
	return count - bytes_remaining;
}

/* Like writev(), but keep trying until everything has been written or we know
 * for sure that there was an error. */
size_t
full_writev(int fd, struct iovec *iov, int iovcnt)
{
	size_t total_bytes_written = 0;
	while (iovcnt > 0) {
		ssize_t bytes_written;

		bytes_written = writev(fd, iov, iovcnt);
		if (bytes_written < 0) {
			if (errno == EINTR)
				continue;
			break;
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
	return total_bytes_written;
}

off_t
filedes_offset(int fd)
{
	return lseek(fd, 0, SEEK_CUR);
}
