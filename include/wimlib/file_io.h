#ifndef _WIMLIB_FILE_IO_H
#define _WIMLIB_FILE_IO_H

#include <stddef.h>
#include <sys/types.h>

extern size_t
full_read(int fd, void *buf, size_t n);

extern size_t
full_write(int fd, const void *buf, size_t n);

extern size_t
full_pread(int fd, void *buf, size_t nbyte, off_t offset);

extern size_t
full_pwrite(int fd, const void *buf, size_t count, off_t offset);


#ifdef __WIN32__
struct iovec {
	void *iov_base;
	size_t iov_len;
};
#else
struct iovec;
#endif

extern size_t
full_writev(int fd, struct iovec *iov, int iovcnt);

extern off_t
filedes_offset(int fd);

#ifndef __WIN32__
#  define O_BINARY 0
#endif

#endif /* _WIMLIB_FILE_IO_H */
