/*
 * bitops.h - inline functions for bit manipulation
 *
 * The following copying information applies to this specific source code file:
 *
 * Written in 2014-2016 by Eric Biggers <ebiggers3@gmail.com>
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

#ifndef _WIMLIB_BITOPS_H
#define _WIMLIB_BITOPS_H

#include "wimlib/compiler.h"
#include "wimlib/types.h"

/* Find Last Set bit   */

static inline unsigned
fls32(u32 v)
{
#ifdef compiler_fls32
	return compiler_fls32(v);
#else
	unsigned bit = 0;
	while ((v >>= 1) != 0)
		bit++;
	return bit;
#endif
}

static inline unsigned
fls64(u64 v)
{
#ifdef compiler_fls64
	return compiler_fls64(v);
#else
	unsigned bit = 0;
	while ((v >>= 1) != 0)
		bit++;
	return bit;
#endif
}

static inline unsigned
flsw(machine_word_t v)
{
	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
	if (WORDBITS == 32)
		return fls32(v);
	else
		return fls64(v);
}

/* Find First Set bit   */

static inline unsigned
ffs32(u32 v)
{
#ifdef compiler_ffs32
	return compiler_ffs32(v);
#else
	unsigned bit;
	for (bit = 0; !(v & 1); bit++, v >>= 1)
		;
	return bit;
#endif
}

static inline unsigned
ffs64(u64 v)
{
#ifdef compiler_ffs64
	return compiler_ffs64(v);
#else
	unsigned bit;
	for (bit = 0; !(v & 1); bit++, v >>= 1)
		;
	return bit;
#endif
}

static inline unsigned
ffsw(machine_word_t v)
{
	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);
	if (WORDBITS == 32)
		return ffs32(v);
	else
		return ffs64(v);
}

/* Return the log base 2 of 'n', rounded up to the nearest integer. */
static inline unsigned
ilog2_ceil(size_t n)
{
        if (n <= 1)
                return 0;
        return 1 + flsw(n - 1);
}

/* Round 'n' up to the nearest power of 2 */
static inline size_t
roundup_pow_of_2(size_t n)
{
	return (size_t)1 << ilog2_ceil(n);
}

#endif /* _WIMLIB_BITOPS_H */
