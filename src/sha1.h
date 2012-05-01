#ifndef _WIMLIB_SHA1_H
#define _WIMLIB_SHA1_H

#include "config.h"
#include <stdio.h>
#include <stddef.h>

/* Compute SHA1 message digest for bytes read from STREAM.  The
   resulting message digest number will be written into the 20 bytes
   beginning at RESBLOCK.  */
extern int sha1_stream(FILE * stream, void *resblock);

#ifdef WITH_LIBCRYPTO
#include <openssl/sha.h>
static inline void *sha1_buffer(const char *buffer, size_t len, void *resblock)
{
	return SHA1(buffer, len, resblock);
}
#else
/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
extern void *sha1_buffer(const char *buffer, size_t len, void *resblock);
#endif


#endif /* _WIMLIB_SHA1_H */
