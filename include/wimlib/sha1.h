/*
 * sha1.h
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_SHA1_H
#define _WIMLIB_SHA1_H

#include <string.h>

#include "wimlib/types.h"
#include "wimlib/util.h"

#define SHA1_HASH_SIZE 20

extern const u8 zero_hash[SHA1_HASH_SIZE];

extern void
sprint_hash(const u8 hash[SHA1_HASH_SIZE], tchar strbuf[SHA1_HASH_SIZE * 2 + 1]);

static inline void
copy_hash(u8 dest[SHA1_HASH_SIZE], const u8 src[SHA1_HASH_SIZE])
{
	memcpy(dest, src, SHA1_HASH_SIZE);
}

static inline int
hashes_cmp(const u8 h1[SHA1_HASH_SIZE], const u8 h2[SHA1_HASH_SIZE])
{
	return memcmp(h1, h2, SHA1_HASH_SIZE);
}

static inline bool
hashes_equal(const u8 h1[SHA1_HASH_SIZE], const u8 h2[SHA1_HASH_SIZE])
{
	return !hashes_cmp(h1, h2);
}

static inline bool
is_zero_hash(const u8 *hash)
{
	return (hash == zero_hash || hashes_equal(hash, zero_hash));
}

#ifdef WITH_LIBCRYPTO

#include <openssl/sha.h>

#define sha1_init     SHA1_Init
#define sha1_update   SHA1_Update
#define sha1_final    SHA1_Final

static inline void
sha1_buffer(const void *buffer, size_t len, u8 hash[SHA1_HASH_SIZE])
{
	SHA1(buffer, len, hash);
}

#else /* WITH_LIBCRYPTO */

typedef struct {
	u64 bytecount;
	u32 state[5];
	u8 buffer[64];
} SHA_CTX;

extern void
sha1_init(SHA_CTX *ctx);

extern void
sha1_update(SHA_CTX *ctx, const void *data, size_t len);

extern void
sha1_final(u8 hash[SHA1_HASH_SIZE], SHA_CTX *ctx);

extern void
sha1_buffer(const void *buffer, size_t len, u8 hash[SHA1_HASH_SIZE]);

#endif /* !WITH_LIBCRYPTO */

#endif /* _WIMLIB_SHA1_H */
