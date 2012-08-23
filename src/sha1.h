#ifndef _WIMLIB_SHA1_H
#define _WIMLIB_SHA1_H

#include "config.h"
#include <stdio.h>
#include <stddef.h>
#include "string.h"
#include "util.h"

#define SHA1_HASH_SIZE 20

static inline void copy_hash(u8 dest[SHA1_HASH_SIZE],
			     const u8 src[SHA1_HASH_SIZE])
{
	memcpy(dest, src, SHA1_HASH_SIZE);
}

static inline void random_hash(u8 hash[SHA1_HASH_SIZE])
{
	randomize_byte_array(hash, SHA1_HASH_SIZE);
}

static inline bool hashes_equal(const u8 h1[SHA1_HASH_SIZE],
				const u8 h2[SHA1_HASH_SIZE])
{
	return memcmp(h1, h2, SHA1_HASH_SIZE) == 0;
}

/* Prints a hash code field. */
static inline void print_hash(const u8 hash[])
{
	print_byte_field(hash, SHA1_HASH_SIZE);
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
