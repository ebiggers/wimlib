/*
 * matchfinder_common.h
 *
 * Common code for Lempel-Ziv matchfinding.
 *
 * Copyright (c) 2014 Eric Biggers.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _MATCHFINDER_COMMON_H
#define _MATCHFINDER_COMMON_H

#include "wimlib/types.h"

#include <string.h>

#ifndef MATCHFINDER_WINDOW_ORDER
#  error "MATCHFINDER_WINDOW_ORDER must be defined!"
#endif

#ifndef MATCHFINDER_IS_SLIDING
#  error "MATCHFINDER_IS_SLIDING must be defined!"
#endif

#define MATCHFINDER_WINDOW_SIZE ((size_t)1 << MATCHFINDER_WINDOW_ORDER)

#if MATCHFINDER_IS_SLIDING
#  include "matchfinder_sliding.h"
#else
#  include "matchfinder_nonsliding.h"
#endif

#define MATCHFINDER_ALIGNMENT 8

#ifdef __AVX2__
#  include "matchfinder_avx2.h"
#  if MATCHFINDER_ALIGNMENT < 32
#    undef MATCHFINDER_ALIGNMENT
#    define MATCHFINDER_ALIGNMENT 32
#  endif
#endif

#ifdef __SSE2__
#  include "matchfinder_sse2.h"
#  if MATCHFINDER_ALIGNMENT < 16
#    undef MATCHFINDER_ALIGNMENT
#    define MATCHFINDER_ALIGNMENT 16
#  endif
#endif

/*
 * Representation of a match.
 */
struct lz_match {

	/* The number of bytes matched.  */
	pos_t length;

	/* The offset back from the current position that was matched.  */
	pos_t offset;
};

static inline bool
matchfinder_memset_init_okay(void)
{
	/* All bytes must match in order to use memset.  */
	const pos_t v = MATCHFINDER_INITVAL;
	if (sizeof(pos_t) == 2)
		return (u8)v == (u8)(v >> 8);
	if (sizeof(pos_t) == 4)
		return (u8)v == (u8)(v >> 8) &&
		       (u8)v == (u8)(v >> 16) &&
		       (u8)v == (u8)(v >> 24);
	return false;
}

/*
 * Initialize the hash table portion of the matchfinder.
 *
 * Essentially, this is an optimized memset().
 *
 * 'data' must be aligned to a MATCHFINDER_ALIGNMENT boundary.
 */
static inline void
matchfinder_init(pos_t *data, size_t num_entries)
{
	const size_t size = num_entries * sizeof(data[0]);

#ifdef __AVX2__
	if (matchfinder_init_avx2(data, size))
		return;
#endif

#ifdef __SSE2__
	if (matchfinder_init_sse2(data, size))
		return;
#endif

	if (matchfinder_memset_init_okay()) {
		memset(data, (u8)MATCHFINDER_INITVAL, size);
		return;
	}

	for (size_t i = 0; i < num_entries; i++)
		data[i] = MATCHFINDER_INITVAL;
}

#if MATCHFINDER_IS_SLIDING
/*
 * Slide the matchfinder by WINDOW_SIZE bytes.
 *
 * This must be called just after each WINDOW_SIZE bytes have been run through
 * the matchfinder.
 *
 * This will subtract WINDOW_SIZE bytes from each entry in the array specified.
 * The effect is that all entries are updated to be relative to the current
 * position, rather than the position WINDOW_SIZE bytes prior.
 *
 * Underflow is detected and replaced with signed saturation.  This ensures that
 * once the sliding window has passed over a position, that position forever
 * remains out of bounds.
 *
 * The array passed in must contain all matchfinder data that is
 * position-relative.  Concretely, this will include the hash table as well as
 * the table of positions that is used to link together the sequences in each
 * hash bucket.  Note that in the latter table, the links are 1-ary in the case
 * of "hash chains", and 2-ary in the case of "binary trees".  In either case,
 * the links need to be rebased in the same way.
 */
static inline void
matchfinder_rebase(pos_t *data, size_t num_entries)
{
	const size_t size = num_entries * sizeof(data[0]);

#ifdef __AVX2__
	if (matchfinder_rebase_avx2(data, size))
		return;
#endif

#ifdef __SSE2__
	if (matchfinder_rebase_sse2(data, size))
		return;
#endif

	if (MATCHFINDER_WINDOW_SIZE == 32768) {
		/* Branchless version for 32768 byte windows.  If the value was
		 * already negative, clear all bits except the sign bit; this
		 * changes the value to -32768.  Otherwise, set the sign bit;
		 * this is equivalent to subtracting 32768.  */
		for (size_t i = 0; i < num_entries; i++) {
			u16 v = data[i];
			u16 sign_bit = v & 0x8000;
			v &= sign_bit - ((sign_bit >> 15) ^ 1);
			v |= 0x8000;
			data[i] = v;
		}
		return;
	}

	for (size_t i = 0; i < num_entries; i++) {
		if (data[i] >= 0)
			data[i] -= (pos_t)-MATCHFINDER_WINDOW_SIZE;
		else
			data[i] = (pos_t)-MATCHFINDER_WINDOW_SIZE;
	}
}
#endif /* MATCHFINDER_IS_SLIDING */

#endif /* _MATCHFINDER_COMMON_H */
