/*
 * lz_hash.h
 *
 * Hashing for Lempel-Ziv matchfinding.
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _LZ_HASH_H
#define _LZ_HASH_H

#include "wimlib/types.h"

/*
 * The hash function: given a sequence prefix held in the low-order bits of a
 * 32-bit value, multiply by a carefully-chosen large constant.  Discard any
 * bits of the product that don't fit in a 32-bit value, but take the
 * next-highest @num_bits bits of the product as the hash value, as those have
 * the most randomness.
 */
static inline u32
lz_hash(u32 seq, unsigned num_bits)
{
	return (u32)(seq * 0x1E35A7BD) >> (32 - num_bits);
}

#endif /* _LZ_HASH_H */
