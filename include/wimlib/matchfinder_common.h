/*
 * matchfinder_common.h
 *
 * Common code for Lempel-Ziv matchfinding.
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _MATCHFINDER_COMMON_H
#define _MATCHFINDER_COMMON_H

#include "wimlib/types.h"

#include <string.h>

#ifndef MATCHFINDER_MAX_WINDOW_ORDER
#  error "MATCHFINDER_MAX_WINDOW_ORDER must be defined!"
#endif

#if MATCHFINDER_MAX_WINDOW_ORDER <= 16
typedef u16 pos_t;
#else
typedef u32 pos_t;
#endif

#if MATCHFINDER_MAX_WINDOW_ORDER != 16 && MATCHFINDER_MAX_WINDOW_ORDER != 32

/* Not all the bits of the position type are needed, so the sign bit can be
 * reserved to mean "out of bounds".  */
#define MATCHFINDER_NULL ((pos_t)-1)

static inline bool
matchfinder_node_valid(pos_t node)
{
	return !(node & ((pos_t)1 << (sizeof(pos_t) * 8 - 1)));
}

#else

/* All bits of the position type are needed, so use 0 to mean "out of bounds".
 * This prevents the beginning of the buffer from matching anything; however,
 * this doesn't matter much.  */

#define MATCHFINDER_NULL ((pos_t)0)

static inline bool
matchfinder_node_valid(pos_t node)
{
	return node != 0;
}

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
	const pos_t v = MATCHFINDER_NULL;
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
		memset(data, (u8)MATCHFINDER_NULL, size);
		return;
	}

	for (size_t i = 0; i < num_entries; i++)
		data[i] = MATCHFINDER_NULL;
}

#endif /* _MATCHFINDER_COMMON_H */
