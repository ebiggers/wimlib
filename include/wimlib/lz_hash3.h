/*
 * lz_hash3.h
 *
 * 3-byte hashing for Lempel-Ziv matchfinding.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_LZ_HASH3_H
#define _WIMLIB_LZ_HASH3_H

#include "wimlib/types.h"

/* Constant for the multiplicative hash function.  */
#define LZ_HASH_MULTIPLIER 0x1E35A7BD

/* Hash the next 3-byte sequence in the window, producing a hash of length
 * 'num_bits' bits.  4 bytes must be available, since 32-bit unaligned load is
 * faster on some architectures.  */
static inline u32
lz_hash(const u8 *p, unsigned int num_bits)
{
	u32 str;
	u32 hash;

#if defined(__i386__) || defined(__x86_64__)
	/* Unaligned access allowed, and little endian CPU.
	 * Callers ensure that at least 4 (not 3) bytes are remaining.  */
	str = *(const u32 *)p & 0xFFFFFF;
#else
	str = ((u32)p[0] << 0) | ((u32)p[1] << 8) | ((u32)p[2] << 16);
#endif

	hash = str * LZ_HASH_MULTIPLIER;

	/* High bits are more random than the low bits.  */
	return hash >> (32 - num_bits);
}

/* The number of bytes being hashed.  */
#define LZ_HASH_NBYTES 3

/* Number of bytes the hash function actually requires be available, due to the
 * possibility of an unaligned load.  */
#define LZ_HASH_REQUIRED_NBYTES 4

#endif /* _WIMLIB_LZ_HASH3_H */
