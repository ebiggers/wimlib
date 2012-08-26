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
static inline int hashes_cmp(const u8 h1[SHA1_HASH_SIZE],
			     const u8 h2[SHA1_HASH_SIZE])
{
	return memcmp(h1, h2, SHA1_HASH_SIZE);
}

/* Prints a hash code field. */
static inline void print_hash(const u8 hash[SHA1_HASH_SIZE])
{
	print_byte_field(hash, SHA1_HASH_SIZE);
}

static inline bool is_zero_hash(const u8 hash[SHA1_HASH_SIZE])
{
	for (u8 i = 0; i < SHA1_HASH_SIZE / 4; i++)
		if (((u32*)hash)[i])
			return false;
	return true;
}

static void zero_hash(u8 hash[SHA1_HASH_SIZE])
{
	memset(hash, 0, SHA1_HASH_SIZE);
}


#ifdef WITH_LIBCRYPTO

#include <openssl/sha.h>
#define sha1_buffer   SHA1
#define sha1_init     SHA1_Init
#define sha1_update   SHA1_Update
#define sha1_final    SHA1_Final

#else /* WITH_LIBCRYPTO */

typedef struct {
    u32 state[5];
    u32 count[2];
    u8  buffer[64];
} SHA_CTX;

extern void sha1_buffer(const u8 buffer[], size_t len, u8 hash[SHA1_HASH_SIZE]);
extern void sha1_init(SHA_CTX *ctx);
extern void sha1_update(SHA_CTX *ctx, const u8 data[], size_t len);
extern void sha1_final(u8 hash[SHA1_HASH_SIZE], SHA_CTX *ctx);

#endif /* !WITH_LIBCRYPTO */

extern int sha1sum(const char *filename, u8 hash[SHA1_HASH_SIZE]);



#endif /* _WIMLIB_SHA1_H */
