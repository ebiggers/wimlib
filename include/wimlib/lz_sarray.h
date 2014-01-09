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

#include "wimlib/compiler.h" /* must define '_always_inline_attribute'  */
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

#define LZ_SARRAY_LEN_MAX	((lz_sarray_len_t)~0UL)
#define LZ_SARRAY_POS_MAX	((lz_sarray_pos_t)~0UL)
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
	 * list containing only suffixes that appear before that position.  */
	struct salink *salink;
};

/* Suffix array link; one of these exists for each position in the suffix array.
 */
struct salink {
	/* Rank of highest ranked suffix that has rank lower than the suffix
	 * corresponding to this structure and either has a lower position
	 * (initially) or has a position lower than the highest position at
	 * which matches have been searched for so far, or LZ_SARRAY_POS_MAX if
	 * there is no such suffix.
	 *
	 * Think of this as a pointer to the closest position in the suffix
	 * array to the left that corresponds to a suffix that begins at a
	 * position in the current dictionary (i.e. before the current position
	 * in the window).  */
	lz_sarray_pos_t prev;

	/* Rank of lowest ranked suffix that has rank greater than the suffix
	 * corresponding to this structure and either has a lower position
	 * (intially) or has a position lower than the highest position at which
	 * matches have been searched for so far, or LZ_SARRAY_POS_MAX if there
	 * is no such suffix.

	 * Think of this as a pointer to the closest position in the suffix
	 * array to the right that corresponds to a suffix that begins at a
	 * position in the current dictionary (i.e. before the current position
	 * in the window).  */
	lz_sarray_pos_t next;

	/* Length of longest common prefix between the suffix corresponding to
	 * this structure and the suffix with rank @prev, or 0 if @prev is
	 * LZ_SARRAY_POS_MAX.  Capped to the maximum match length.  */
	lz_sarray_len_t lcpprev;

	/* Length of longest common prefix between the suffix corresponding to
	 * this structure and the suffix with rank @next, or 0 if @next is
	 * LZ_SARRAY_POS_MAX.  Capped to the maximum match length.  */
	lz_sarray_len_t lcpnext;
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
	/* next = rank of LOWEST ranked suffix that is ranked HIGHER than the
	 * current suffix AND has a LOWER position, or LZ_SARRAY_POS_MAX if none
	 * exists.  */
	const lz_sarray_pos_t next = link[r].next;

	/* prev = rank of HIGHEST ranked suffix that is ranked LOWER than the
	 * current suffix AND has a LOWER position, or LZ_SARRAY_POS_MAX if none
	 * exists.  */
	const lz_sarray_pos_t prev = link[r].prev;

	/* Link the suffix at the current position into the linked list that
	 * contains all suffixes referenced by the suffix array that appear at
	 * or before the current position, sorted by rank.  */
	if (next != LZ_SARRAY_POS_MAX) {
		link[next].prev = r;
		link[next].lcpprev = link[r].lcpnext;
	}

	if (prev != LZ_SARRAY_POS_MAX) {
		link[prev].next = r;
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
	const lz_sarray_pos_t min_match_len = mf->min_match_len;
	const u32 max_matches_to_consider = mf->max_matches_to_consider;
	const u32 max_matches_to_return = mf->max_matches_to_return;

	/* r = Rank of the suffix at the current position.  */
	const lz_sarray_pos_t r = ISA[i];

	/* Prepare for searching the current position.  */
	lz_sarray_update_salink(r, link);

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
	lz_sarray_pos_t L = link[r].prev;
	lz_sarray_pos_t R = link[r].next;
	lz_sarray_pos_t lenL = link[r].lcpprev;
	lz_sarray_pos_t lenR = link[r].lcpnext;

	/* nmatches = number of matches found so far.  */
	u32 nmatches = 0;

	/* best_cost = cost of lowest-cost match found so far.
	 *
	 * We keep track of this so that we can ignore shorter matches that do
	 * not have lower costs than longer matches already found.  */
	lz_sarray_cost_t best_cost = LZ_SARRAY_INFINITE_COST;

	/* count_remaining = maximum number of possible matches remaining to be
	 * considered.  */
	u32 count_remaining = max_matches_to_consider;

	/* pending = match currently being considered for a specific length.  */
	struct raw_match pending;
	lz_sarray_cost_t pending_cost;

	while (lenL >= min_match_len || lenR >= min_match_len)
	{
		pending.len = lenL;
		pending_cost = LZ_SARRAY_INFINITE_COST;
		lz_sarray_cost_t cost;

		/* Extend left.  */
		if (lenL >= min_match_len && lenL >= lenR) {
			for (;;) {

				if (--count_remaining == 0)
					goto out_save_pending;

				lz_sarray_pos_t offset = i - SA[L];

				/* Save match if it has smaller cost.  */
				cost = (*eval_match_cost)(lenL, offset,
							  eval_match_cost_ctx);
				if (cost < pending_cost) {
					pending.offset = offset;
					pending_cost = cost;
				}

				if (link[L].lcpprev < lenL) {
					/* Match length decreased.  */

					lenL = link[L].lcpprev;

					/* Save the pending match unless the
					 * right side still may have matches of
					 * this length to be scanned, or if a
					 * previous (longer) match had lower
					 * cost.  */
					if (pending.len > lenR) {
						if (pending_cost < best_cost) {
							best_cost = pending_cost;
							matches[nmatches++] = pending;
							if (nmatches == max_matches_to_return)
								return nmatches;
						}
						pending.len = lenL;
						pending_cost = LZ_SARRAY_INFINITE_COST;
					}
					if (lenL < min_match_len || lenL < lenR)
						break;
				}
				L = link[L].prev;
			}
		}

		pending.len = lenR;

		/* Extend right.  */
		if (lenR >= min_match_len && lenR > lenL) {
			for (;;) {

				if (--count_remaining == 0)
					goto out_save_pending;

				lz_sarray_pos_t offset = i - SA[R];

				/* Save match if it has smaller cost.  */
				cost = (*eval_match_cost)(lenR,
							  offset,
							  eval_match_cost_ctx);
				if (cost < pending_cost) {
					pending.offset = offset;
					pending_cost = cost;
				}

				if (link[R].lcpnext < lenR) {
					/* Match length decreased.  */

					lenR = link[R].lcpnext;

					/* Save the pending match unless a
					 * previous (longer) match had lower
					 * cost.  */
					if (pending_cost < best_cost) {
						matches[nmatches++] = pending;
						best_cost = pending_cost;
						if (nmatches == max_matches_to_return)
							return nmatches;
					}

					if (lenR < min_match_len || lenR <= lenL)
						break;

					pending.len = lenR;
					pending_cost = LZ_SARRAY_INFINITE_COST;
				}
				R = link[R].next;
			}
		}
	}
	goto out;

out_save_pending:
	if (pending_cost != LZ_SARRAY_INFINITE_COST)
		matches[nmatches++] = pending;

out:
	return nmatches;
}

#endif /* _WIMLIB_LZ_SARRAY_H */
