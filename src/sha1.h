#ifndef _WIMLIB_SHA1_H
#define _WIMLIB_SHA1_H

#include "config.h"
#include <stdio.h>
#include <stddef.h>
#include "string.h"

#define SHA1_HASH_SIZE 20

extern const u8 empty_file_sha1sum[SHA1_HASH_SIZE];

static inline bool is_empty_file_hash(const u8 hash[SHA1_HASH_SIZE])
{
	return memcmp(hash, empty_file_sha1sum, SHA1_HASH_SIZE) == 0;
}


extern int sha1sum(const char *filename, void *md);

#ifdef WITH_LIBCRYPTO
#include <openssl/sha.h>
static inline void sha1_buffer(const void *buffer, size_t len, void *md)
{
	SHA1(buffer, len, md);
}
#else
extern void sha1_buffer(const void *buffer, size_t len, void *md);
#endif

#endif /* _WIMLIB_SHA1_H */
