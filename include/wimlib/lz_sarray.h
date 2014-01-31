/*
 * lz_sarray.h
 *
 * Suffix array match-finder for Lempel-Ziv compression.
 */

/*
 * Copyright (c) 2013, 2014 Eric Biggers.  All rights reserved.
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

#ifndef _WIMLIB_LZ_SARRAY_H
#define _WIMLIB_LZ_SARRAY_H

#include "wimlib/compiler.h" /* must define '_always_inline_attribute',
				'likely()', and 'prefetch()'.  */
#include "wimlib/lz.h"       /* must define 'struct raw_match' and LZ_ASSERT()  */
#include "wimlib/types.h"    /* must define 'bool', 'u8', 'u16, and 'u32'  */

struct salink;

/* Position type --- must be an unsigned type large enough to hold the length of
 * longest window for which the suffix array match-finder will be used.  */
typedef u32 lz_sarray_pos_t;

/* Length type --- must be an unsigned type large enough to hold the maximum
 * match length.  */
typedef u16 lz_sarray_len_t;

/* Cost type, for the user-provided match cost evaluation function.  */
typedef lz_sarray_pos_t lz_sarray_cost_t;

/* Type of distances in suffix array links.  A larger type would allow skipping
 * irrelevant suffixes more quickly, which is especially helpful towards the
 * start of the window.  However, even a single byte allows skipping 255 at a
 * time, which where it matters is already a big improvement over the
 * alternative of searching the suffixes consecutively.  */
typedef u8 lz_sarray_delta_t;

#define LZ_SARRAY_LEN_MAX	((lz_sarray_len_t)~0UL)
#define LZ_SARRAY_POS_MAX	((lz_sarray_pos_t)~0UL)
#define LZ_SARRAY_DELTA_MAX	((lz_sarray_delta_t)~0UL)
#define LZ_SARRAY_INFINITE_COST	((lz_sarray_cost_t)~0UL)

/* State of the suffix array LZ (Lempel-Ziv) match-finder.
 *
 * This is defined here for benefit of the inlined code.  It's not intended for
 * code outside the match-finder itself to read or write members from this
 * structure.  */
struct lz_sarray {
	/* Allocated window size for the match-finder.
	 *
	 * Note: this match-finder does not store the window itself, as the
	 * suffix array (@SA) and associated arrays (@ISA, @LCP, @salink) are
	 * sufficient to find matches.  This number is the maximum length of
	 * those arrays, or also the maximum window (block) size that can be
	 * passed to lz_sarray_load_window().  */
	lz_sarray_pos_t max_window_size;

	/* Minimum length of matches to return.  */
	lz_sarray_len_t min_match_len;

	/* Maximum length of matches to return.  */
	lz_sarray_len_t max_match_len;

	/* Maximum matches to consider at each position (max search depth).  */
	u32 max_matches_to_consider;

	/* Maximum number of matches to return at each position.  */
	u32 max_matches_to_return;

	/* Current position in the window.  */
	lz_sarray_pos_t cur_pos;

	/* Current window size.  */
	lz_sarray_pos_t window_size;

	/* Suffix array for the current window.
	 * This is a mapping from suffix rank to suffix position.  */
	lz_sarray_pos_t *SA;

	/* Inverse suffix array for the current window.
	 * This is a mapping from suffix position to suffix rank.
	 * If 0 <= r < window_size, then ISA[SA[r]] == r.  */
	lz_sarray_pos_t *ISA;

	/* Suffix array links.
	 *
	 * During a linear scan of the input string to find matches, this array
	 * used to keep track of which rank suffixes in the suffix array appear
	 * before the current position.  Instead of searching in the original
	 * suffix array, scans for matches at a given position traverse a linked
	 * list containing (usually) only suffixes that appear before that
	 * position.  */
	struct salink *salink;
};

/* Suffix array link.  An array of these structures, one per suffix rank, is
 * used as a replacement for the raw LCP (Longest Common Prefix) array to allow
 * skipping over suffixes that appear later in the window and hence cannot be
 * used as LZ77 matches.  */
struct salink {
	union {
		/* Temporary fields used while this structure is being
		 * initialized.
		 *
		 * Note: we want the entire `struct salink' to be only 6 bytes,
		 * even though this makes "next_initial" unaligned.  */
		struct {
			lz_sarray_pos_t next_initial;
			lz_sarray_len_t lcpnext_initial;
		} _packed_attribute;

		struct {
			/* Intially, the length, in bytes, of the longest common
			 * prefix (LCP) between the suffix having this rank and
			 * the suffix with the the smallest larger rank that
			 * starts earlier in the window than the suffix having
			 * this rank.  If no such suffix exists, this will be 0.
			 *
			 * Later, during match-finding, after the corresponding
			 * suffix has entered the LZ77 dictionary, this value
			 * may be updated by lz_sarray_update_salink() to refer
			 * instead to a lexicographically closer (but still
			 * larger) suffix that begins at a later position that
			 * has entered the LZ77 dictionary.  */
			lz_sarray_len_t   lcpnext;

			/* Initially, the length, in bytes, of the longest
			 * common prefix (LCP) between the suffix having this
			 * rank and the suffix with the the largest smaller rank
			 * that starts earlier in the window than the suffix
			 * having this rank.  If no such suffix exists, this
			 * will be 0.
			 *
			 * Later, during match-finding, after the corresponding
			 * suffix has entered the LZ77 dictionary, this value
			 * may be updated by lz_sarray_update_salink() to refer
			 * instead to a lexicographically closer (but still
			 * smaller) suffix that begins at a later position that
			 * has entered the LZ77 dictionary.  */
			lz_sarray_len_t   lcpprev;

			/* Distance to the suffix referred to in the description
			 * of "lcpnext" above, but capped to a maximum value to
			 * save memory; or, 0 if no such suffix exists.  If the
			 * true distance was truncated, this will give the
			 * distance to the rank of a suffix that is
			 * lexicographically closer to the current suffix than
			 * the desired suffix, but appears *later* in the window
			 * and hence cannot be used as the basis for a LZ77
			 * match.  */
			lz_sarray_delta_t dist_to_next;

			/* Distance to the suffix referred to in the description
			 * of "lcpprev" above, but capped to a maximum value to
			 * save memory; or, 0 if no such suffix exists.  If the
			 * true distance was truncated, this will give the
			 * distance to the rank of a suffix that is
			 * lexicographically closer to the current suffix than
			 * the desired suffix, but appears *later* in the window
			 * and hence cannot be used as the basis for a LZ77
			 * match.  */
			lz_sarray_delta_t dist_to_prev;
		};
	};
};


/*-----------------------------------*/
/* Functions defined in lz_sarray.c  */
/*-----------------------------------*/

extern bool
lz_sarray_init(struct lz_sarray *mf,
	       lz_sarray_pos_t max_window_size,
	       lz_sarray_len_t min_match_len,
	       lz_sarray_len_t max_match_len,
	       u32 max_matches_to_consider,
	       u32 max_matches_to_return);

extern u64
lz_sarray_get_needed_memory(lz_sarray_pos_t max_window_size);

extern void
lz_sarray_destroy(struct lz_sarray *mf);

extern void
lz_sarray_load_window(struct lz_sarray *mf, const u8 T[], lz_sarray_pos_t n);

/*-------------------*/
/* Inline functions  */
/*-------------------*/

static _always_inline_attribute lz_sarray_pos_t
lz_sarray_get_pos(const struct lz_sarray *mf)
{
	return mf->cur_pos;
}

/* Advance the suffix array match-finder to the next position.  */
static _always_inline_attribute void
lz_sarray_update_salink(const lz_sarray_pos_t r, struct salink link[])
{
	const lz_sarray_pos_t next = r + link[r].dist_to_next;
	const lz_sarray_pos_t prev = r - link[r].dist_to_prev;

	if (next != r && link[r].dist_to_next < link[next].dist_to_prev) {
		link[next].dist_to_prev = link[r].dist_to_next;
		link[next].lcpprev = link[r].lcpnext;
	}

	if (prev != r && link[r].dist_to_prev < link[prev].dist_to_next) {
		link[prev].dist_to_next = link[r].dist_to_prev;
		link[prev].lcpnext = link[r].lcpprev;
	}
}

/* Skip the current position in the suffix array match-finder.  */
static _always_inline_attribute void
lz_sarray_skip_position(struct lz_sarray *mf)
{
	LZ_ASSERT(mf->cur_pos < mf->window_size);
	lz_sarray_update_salink(mf->ISA[mf->cur_pos++], mf->salink);
}

/*
 * Use the suffix array match-finder to retrieve a list of matches at the
 * current position.
 *
 * Returns the number of matches written into @matches.  The matches are
 * returned in decreasing order by length, and each will be of unique length
 * between the minimum and maximum match lengths (inclusively) passed to
 * lz_sarray_init().  Up to @max_matches_to_return (passed to lz_sarray_init())
 * matches will be returned.
 *
 * @eval_match_cost is a function for evaluating the cost of a match when
 * deciding which ones to return.  It needs to be fast, and need not be exact;
 * an implementation might simply rank matches by their offset, for example,
 * although implementations may choose to take into account additional
 * information such as repeat offsets.
 */
static _always_inline_attribute u32
lz_sarray_get_matches(struct lz_sarray *mf,
		      struct raw_match matches[],
		      lz_sarray_cost_t (*eval_match_cost)
				(lz_sarray_pos_t length,
				 lz_sarray_pos_t offset,
				 const void *ctx),
		      const void *eval_match_cost_ctx)
{
	LZ_ASSERT(mf->cur_pos < mf->window_size);
	const lz_sarray_pos_t i = mf->cur_pos++;

	const lz_sarray_pos_t * const restrict SA = mf->SA;
	const lz_sarray_pos_t * const restrict ISA = mf->ISA;
	struct salink * const restrict link = mf->salink;
	const u32 max_matches_to_consider = mf->max_matches_to_consider;
	const u32 max_matches_to_return = mf->max_matches_to_return;

	/* r = Rank of the suffix at the current position.  */
	const lz_sarray_pos_t r = ISA[i];

	/* Prepare for searching the current position.  */
	lz_sarray_update_salink(r, link);

#if 1
	/* Prefetch next position in SA and link.
	 *
	 * This can improve performance on large windows since the locations in
	 * SA and link at which each successive search begins are in general
	 * randomly distributed.  */
	if (likely(i + 1 < mf->window_size)) {
		const lz_sarray_pos_t next_r = ISA[i + 1];
		prefetch(&SA[next_r]);
		prefetch(&link[next_r]);
	}
#endif

	/* L = rank of next suffix to the left;
	 * R = rank of next suffix to the right;
	 * lenL = length of match between current position and the suffix with rank L;
	 * lenR = length of match between current position and the suffix with rank R.
	 *
	 * This is left and right relative to the rank of the current suffix.
	 * Since the suffixes in the suffix array are sorted, the longest
	 * matches are immediately to the left and right (using the linked list
	 * to ignore all suffixes that occur later in the window).  The match
	 * length decreases the farther left and right we go.  We shall keep the
	 * length on both sides in sync in order to choose the lowest-cost match
	 * of each length.
	 */
	lz_sarray_pos_t L = r - link[r].dist_to_prev;
	lz_sarray_pos_t R = r + link[r].dist_to_next;
	lz_sarray_pos_t lenL = link[r].lcpprev;
	lz_sarray_pos_t lenR = link[r].lcpnext;

	/* nmatches = number of matches found so far.  */
	u32 nmatches = 0;

	/* best_cost = cost of lowest-cost match found so far.
	 *
	 * Shorter matches that do not have a lower cost than this are
	 * discarded, since presumably it would be cheaper to output the bytes
	 * from the longer match instead.  */
	lz_sarray_cost_t best_cost = LZ_SARRAY_INFINITE_COST;

	/* count_remaining = maximum number of possible matches remaining to be
	 * considered.  */
	u32 count_remaining = max_matches_to_consider;

	/* pending_offset = offset of lowest-cost match found for the current
	 * length, or 0 if none found yet.  */
	lz_sarray_pos_t pending_offset = 0;

	/* Note: some 'goto' statements are used in the remainder of this
	 * function to remove unnecessary checks and create branches that the
	 * CPU may predict better.  (This function is performance critical.)  */

	if (lenL != 0 && lenL >= lenR)
		goto extend_left;
	else if (lenR != 0)
		goto extend_right;
	else
		return 0;

extend_left:
	/* Search suffixes on the left until the match length has decreased
	 * below the next match length on the right or to below the minimum
	 * match length.  */
	for (;;) {
		lz_sarray_pos_t offset;
		lz_sarray_cost_t cost;
		lz_sarray_pos_t old_L;
		lz_sarray_pos_t old_lenL;

		/* Check for hard cutoff on amount of work done.  */
		if (count_remaining-- == 0) {
			if (pending_offset != 0) {
				/* Save pending match.  */
				matches[nmatches++] = (struct raw_match){
					.len = lenL,
					.offset = pending_offset,
				};
			}
			return nmatches;
		}

		if (SA[L] < i) {
			/* Suffix is in LZ77 dictionary.  (Check was needed
			 * because the salink array caps distances to save
			 * memory.)  */

			offset = i - SA[L];

			/* Save match offset if it results in lower cost.  */
			cost = (*eval_match_cost)(lenL, offset,
						  eval_match_cost_ctx);
			if (cost < best_cost) {
				best_cost = cost;
				pending_offset = offset;
			}
		}

		/* Advance left to previous suffix.  */

		old_L = L;
		old_lenL = lenL;

		L -= link[L].dist_to_prev;

		if (link[old_L].lcpprev < old_lenL) {
			/* Match length decreased.  */

			lenL = link[old_L].lcpprev;

			if (old_lenL > lenR) {
				/* Neither the right side nor the left size has
				 * any more matches of length @old_lenL.  If a
				 * pending match exists, save it.  */
				if (pending_offset != 0) {
					matches[nmatches++] = (struct raw_match){
						.len = old_lenL,
						.offset = pending_offset,
					};
					if (nmatches == max_matches_to_return)
						return nmatches;

					pending_offset = 0;
				}

				if (lenL >= lenR) {
					/* New match length on left is still at
					 * least as large as the next match
					 * length on the right:  Keep extending
					 * left, unless the minimum match length
					 * would be underrun.  */
					if (lenL == 0)
						return nmatches;
					goto extend_left;
				}
			}

			/* Here we have lenL < lenR.  Extend right.
			 * (No check for whether the minimum match length has
			 * been underrun is needed, provided that such lengths
			 * are marked as 0.)  */
			goto extend_right;
		}
	}

extend_right:
	/* Search suffixes on the right until the match length has decreased to
	 * the next match length on the left or to below the minimum match
	 * length.  */
	for (;;) {
		lz_sarray_pos_t offset;
		lz_sarray_cost_t cost;
		lz_sarray_pos_t old_R;
		lz_sarray_pos_t old_lenR;

		/* Check for hard cutoff on amount of work done.  */
		if (count_remaining-- == 0) {
			if (pending_offset != 0) {
				/* Save pending match.  */
				matches[nmatches++] = (struct raw_match){
					.len = lenR,
					.offset = pending_offset,
				};
			}
			return nmatches;
		}

		if (SA[R] < i) {
			/* Suffix is in LZ77 dictionary.  (Check was needed
			 * because the salink array caps distances to save
			 * memory.)  */

			offset = i - SA[R];

			/* Save match offset if it results in lower cost.  */
			cost = (*eval_match_cost)(lenR,
						  offset,
						  eval_match_cost_ctx);
			if (cost < best_cost) {
				best_cost = cost;
				pending_offset = offset;
			}
		}

		/* Advance right to next suffix.  */

		old_R = R;
		old_lenR = lenR;

		R += link[R].dist_to_next;

		if (link[old_R].lcpnext < lenR) {
			/* Match length decreased.  */

			lenR = link[old_R].lcpnext;

			/* Neither the right side nor the left size has any more
			 * matches of length @old_lenR.  If a pending match
			 * exists, save it.  */
			if (pending_offset != 0) {
				matches[nmatches++] = (struct raw_match){
					.len = old_lenR,
					.offset = pending_offset,
				};
				if (nmatches == max_matches_to_return)
					return nmatches;

				pending_offset = 0;
			}

			if (lenL >= lenR) {
				/* lenL >= lenR:  Extend left, unless the
				 * minimum match length would be underrun, in
				 * which case we are done.  */
				if (lenL == 0)
					return nmatches;

				goto extend_left;
			}
			/* lenR > lenL:  Keep extending right.
			 * (No check for whether the minimum match length has
			 * been underrun is needed, provided that such lengths
			 * are marked as 0.)  */
		}
	}
}

#endif /* _WIMLIB_LZ_SARRAY_H */
