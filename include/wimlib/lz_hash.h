/*
 * lz_hash.h - hashing for Lempel-Ziv matchfinding
 *
 * The following copying information applies to this specific source code file:
 *
 * Written in 2014-2015 by Eric Biggers <ebiggers3@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide via the Creative Commons Zero 1.0 Universal Public Domain
 * Dedication (the "CC0").
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the CC0 for more details.
 *
 * You should have received a copy of the CC0 along with this software; if not
 * see <http://creativecommons.org/publicdomain/zero/1.0/>.
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
static forceinline u32
lz_hash(u32 seq, unsigned num_bits)
{
	return (u32)(seq * 0x1E35A7BD) >> (32 - num_bits);
}

#endif /* _LZ_HASH_H */
