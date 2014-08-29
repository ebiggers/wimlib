/*
 * lz_repsearch.h
 *
 * Fast searching for repeat offset matches.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _LZ_REPSEARCH_H
#define _LZ_REPSEARCH_H

#include "wimlib/lz_extend.h"
#include "wimlib/util.h"

extern u32
lz_extend_repmatch(const u8 *strptr, const u8 *matchptr, u32 max_len);

/*
 * Find the longest repeat offset match.
 *
 * If no match of at least 2 bytes is found, then return 0.
 *
 * If a match of at least 2 bytes is found, then return its length and set
 * *slot_ret to the index of its offset in @queue.
 */
static inline u32
lz_repsearch(const u8 * const strptr, const u32 bytes_remaining,
	     const u32 max_match_len, const u32 repeat_offsets[],
	     const unsigned num_repeat_offsets, unsigned *slot_ret)
{
	u32 best_len = 0;

	if (likely(bytes_remaining >= 2)) {
		const u32 max_len = min(max_match_len, bytes_remaining);
		const u16 str = *(const u16 *)strptr;

		for (unsigned i = 0; i < num_repeat_offsets; i++) {
			const u8 * const matchptr = strptr - repeat_offsets[i];

			/* Check the first two bytes.  If they match, then
			 * extend the match to its full length.  */
			if (*(const u16 *)matchptr == str) {
				const u32 len = lz_extend_repmatch(strptr, matchptr, max_len);
				if (len > best_len) {
					best_len = len;
					*slot_ret = i;
				}
			}
		}
	}
	return best_len;
}

#endif /* _LZ_REPSEARCH_H */
