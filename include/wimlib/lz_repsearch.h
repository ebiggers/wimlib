/*
 * lz_repsearch.h
 *
 * Fast searching for repeat offset matches.
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _LZ_REPSEARCH_H
#define _LZ_REPSEARCH_H

#include "wimlib/lz_extend.h"
#include "wimlib/unaligned.h"

extern u32
lz_extend_repmatch(const u8 *strptr, const u8 *matchptr, u32 max_len);

/*
 * Given a pointer to the current string and a queue of 3 recent match offsets,
 * find the longest repeat offset match.
 *
 * If no match of at least 2 bytes is found, then return 0.
 *
 * If a match of at least 2 bytes is found, then return its length and set
 * *rep_max_idx_ret to the index of its offset in @recent_offsets.
*/
static inline u32
lz_repsearch3(const u8 * const strptr, const u32 max_len,
	      const u32 recent_offsets[3], unsigned *rep_max_idx_ret)
{
	unsigned rep_max_idx;
	u32 rep_len;
	u32 rep_max_len;
	const u16 str = load_u16_unaligned(strptr);
	const u8 *matchptr;

	matchptr = strptr - recent_offsets[0];
	if (load_u16_unaligned(matchptr) == str)
		rep_max_len = lz_extend_repmatch(strptr, matchptr, max_len);
	else
		rep_max_len = 0;
	rep_max_idx = 0;

	matchptr = strptr - recent_offsets[1];
	if (load_u16_unaligned(matchptr) == str) {
		rep_len = lz_extend_repmatch(strptr, matchptr, max_len);
		if (rep_len > rep_max_len) {
			rep_max_len = rep_len;
			rep_max_idx = 1;
		}
	}

	matchptr = strptr - recent_offsets[2];
	if (load_u16_unaligned(matchptr) == str) {
		rep_len = lz_extend_repmatch(strptr, matchptr, max_len);
		if (rep_len > rep_max_len) {
			rep_max_len = rep_len;
			rep_max_idx = 2;
		}
	}

	*rep_max_idx_ret = rep_max_idx;
	return rep_max_len;
}

#endif /* _LZ_REPSEARCH_H */
