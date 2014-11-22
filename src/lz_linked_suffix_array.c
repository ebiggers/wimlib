/*
 * lz_linked_suffix_array.c
 *
 * Linked suffix array match-finder for Lempel-Ziv compression.
 *
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lz_mf.h"
#include "wimlib/lz_suffix_array_utils.h"
#include "wimlib/util.h"

struct salink;

/* Length type --- must be an unsigned type large enough to hold the maximum
 * match length.  */
typedef u16 lz_lsa_len_t;

/* Type of distances in suffix array links.  A larger type would allow skipping
 * irrelevant suffixes more quickly, which is especially helpful towards the
 * start of the window.  However, even a single byte allows skipping 255 at a
 * time, which where it matters is already a big improvement over the
 * alternative of searching the suffixes consecutively.  */
typedef u8 lz_lsa_delta_t;

#define LZ_LSA_LEN_MAX		((lz_lsa_len_t)~0UL)
#define LZ_LSA_POS_MAX		((u32)~0UL)
#define LZ_LSA_DELTA_MAX	((lz_lsa_delta_t)~0UL)

/* State of the linked suffix array match-finder.  */
struct lz_lsa {

	struct lz_mf base;

	/* Suffix array for the current window.
	 * This is a mapping from suffix rank to suffix position.  */
	u32 *SA;

	/* Inverse suffix array for the current window.
	 * This is a mapping from suffix position to suffix rank.
	 * If 0 <= r < window_size, then ISA[SA[r]] == r.  */
	u32 *ISA;

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
			u32 next_initial;
			lz_lsa_len_t lcpnext_initial;
		} _packed_attribute;

		struct {
			/* Intially, the length, in bytes, of the longest common
			 * prefix (LCP) between the suffix having this rank and
			 * the suffix with the smallest larger rank that
			 * starts earlier in the window than the suffix having
			 * this rank.  If no such suffix exists, this will be 0.
			 *
			 * Later, during match-finding, after the corresponding
			 * suffix has entered the LZ77 dictionary, this value
			 * may be updated by lz_lsa_update_salink() to refer
			 * instead to a lexicographically closer (but still
			 * larger) suffix that begins at a later position that
			 * has entered the LZ77 dictionary.  */
			lz_lsa_len_t   lcpnext;

			/* Initially, the length, in bytes, of the longest
			 * common prefix (LCP) between the suffix having this
			 * rank and the suffix with the largest smaller rank
			 * that starts earlier in the window than the suffix
			 * having this rank.  If no such suffix exists, this
			 * will be 0.
			 *
			 * Later, during match-finding, after the corresponding
			 * suffix has entered the LZ77 dictionary, this value
			 * may be updated by lz_lsa_update_salink() to refer
			 * instead to a lexicographically closer (but still
			 * smaller) suffix that begins at a later position that
			 * has entered the LZ77 dictionary.  */
			lz_lsa_len_t   lcpprev;

			/* Distance to the suffix referred to in the description
			 * of "lcpnext" above, but capped to a maximum value to
			 * save memory; or, 0 if no such suffix exists.  If the
			 * true distance was truncated, this will give the
			 * distance to the rank of a suffix that is
			 * lexicographically closer to the current suffix than
			 * the desired suffix, but appears *later* in the window
			 * and hence cannot be used as the basis for an LZ77
			 * match.  */
			lz_lsa_delta_t dist_to_next;

			/* Distance to the suffix referred to in the description
			 * of "lcpprev" above, but capped to a maximum value to
			 * save memory; or, 0 if no such suffix exists.  If the
			 * true distance was truncated, this will give the
			 * distance to the rank of a suffix that is
			 * lexicographically closer to the current suffix than
			 * the desired suffix, but appears *later* in the window
			 * and hence cannot be used as the basis for an LZ77
			 * match.  */
			lz_lsa_delta_t dist_to_prev;
		};
	};
};

/* Initialize the SA link array in linear time.
 *
 * This is similar to computing the LPF (Longest Previous Factor) array, which
 * is addressed in several papers.  In particular the algorithms below are based
 * on Crochemore et al. 2009: "LPF computation revisited".  However, this
 * match-finder does not actually compute or use the LPF array per se.  Rather,
 * this function sets up some information necessary to compute the LPF array,
 * but later lz_lsa_get_matches() actually uses this information to search
 * the suffix array directly and can keep searching beyond the first (longest)
 * match whose length would be placed in the LPF array.  This difference from
 * the theoretical work is necessary because in many real compression formats
 * matches take variable numbers of bits to encode, so a decent parser needs to
 * consider more than just the longest match with unspecified offset.
 *
 * Note: We cap the lcpprev and lcpnext values to the maximum match length so
 * that the match-finder need not worry about it later, in the inner loop.
 *
 * Note: the LCP array is one of the inputs to this function, but it is used as
 * temporary space and therefore will be invalidated.
 */
static void
init_salink(struct salink link[restrict], u32 LCP[restrict],
	    const u32 SA[restrict], const u8 T[restrict], u32 n,
	    lz_lsa_len_t min_match_len, lz_lsa_len_t max_match_len)
{
	/* Calculate salink.dist_to_next and salink.lcpnext.
	 *
	 * Pass 1 calculates, for each suffix rank, the corresponding
	 * "next_initial" value which is the smallest larger rank that
	 * corresponds to a suffix starting earlier in the string.  It also
	 * calculates "lcpnext_initial", which is the longest common prefix with
	 * that suffix, although to eliminate checks in lz_lsa_get_matches(),
	 * "lcpnext_initial" is set to 0 if it's less than the minimum match
	 * length or set to the maximum match length if it's greater than the
	 * maximum match length.
	 *
	 * Pass 2 translates each absolute "next_initial", a 4-byte value, into
	 * a relative "dist_to_next", a 1-byte value.  This is done to save
	 * memory.  In the case that the exact relative distance cannot be
	 * encoded in 1 byte, it is capped to 255.  This is valid as long as
	 * lz_lsa_get_matches() validates each position before using it.
	 * Note that "lcpnext" need not be updated in this case because it will
	 * not be used until the actual next rank has been found anyway.
	 */
	link[n - 1].next_initial = LZ_LSA_POS_MAX;
	link[n - 1].lcpnext_initial = 0;
	for (u32 r = n - 2; r != LZ_LSA_POS_MAX; r--) {
		u32 t = r + 1;
		u32 l = LCP[t];
		while (t != LZ_LSA_POS_MAX && SA[t] > SA[r]) {
			l = min(l, link[t].lcpnext_initial);
			t = link[t].next_initial;
		}
		link[r].next_initial = t;

		if (l < min_match_len)
			l = 0;
		else if (l > max_match_len)
			l = max_match_len;
		link[r].lcpnext_initial = l;
	}
	for (u32 r = 0; r < n; r++) {
		u32 next;
		lz_lsa_len_t l;
		lz_lsa_delta_t dist_to_next;

		next = link[r].next_initial;
		l = link[r].lcpnext_initial;

		if (next == LZ_LSA_POS_MAX)
			dist_to_next = 0;
		else if (next - r <= LZ_LSA_DELTA_MAX)
			dist_to_next = next - r;
		else
			dist_to_next = LZ_LSA_DELTA_MAX;

		link[r].lcpnext = l;
		link[r].dist_to_next = dist_to_next;
	}

	/* Calculate salink.dist_to_prev and salink.lcpprev.
	 *
	 * This is analgous to dist_to_next and lcpnext as described above, but
	 * in the other direction.  That is, here we're interested in, for each
	 * rank, the largest smaller rank that corresponds to a suffix starting
	 * earlier in the string.
	 *
	 * To save memory we don't have a "prev_initial" field, but rather store
	 * those values in the LCP array.  */
	LCP[0] = LZ_LSA_POS_MAX;
	link[0].lcpprev = 0;
	for (u32 r = 1; r < n; r++) {
		u32 t = r - 1;
		u32 l = LCP[r];
		while (t != LZ_LSA_POS_MAX && SA[t] > SA[r]) {
			l = min(l, link[t].lcpprev);
			t = LCP[t];
		}
		LCP[r] = t;

		if (l < min_match_len)
			l = 0;
		else if (l > max_match_len)
			l = max_match_len;

		link[r].lcpprev = l;
	}
	for (u32 r = 0; r < n; r++) {

		u32 prev = LCP[r];

		if (prev == LZ_LSA_POS_MAX)
			link[r].dist_to_prev = 0;
		else if (r - prev <= LZ_LSA_DELTA_MAX)
			link[r].dist_to_prev = r - prev;
		else
			link[r].dist_to_prev = LZ_LSA_DELTA_MAX;
	}
}

/* If ENABLE_LZ_DEBUG is defined, verify the values computed by init_salink().
 *
 * WARNING: this is for debug use only as it does not necessarily run in linear
 * time!!!  */
static void
verify_salink(const struct salink link[], const u32 SA[], const u8 T[], u32 n,
	      lz_lsa_len_t min_match_len, lz_lsa_len_t max_match_len)
{
#ifdef ENABLE_LZ_DEBUG
	for (u32 r = 0; r < n; r++) {
		for (u32 prev = r; ; ) {
			if (prev == 0) {
				LZ_ASSERT(link[r].dist_to_prev == 0);
				LZ_ASSERT(link[r].lcpprev == 0);
				break;
			}

			prev--;

			if (SA[prev] < SA[r]) {
				LZ_ASSERT(link[r].dist_to_prev == min(r - prev, LZ_LSA_DELTA_MAX));

				u32 lcpprev;
				for (lcpprev = 0;
				     lcpprev < min(n - SA[prev], n - SA[r]) &&
					     T[SA[prev] + lcpprev] == T[SA[r] + lcpprev];
				     lcpprev++)
					;
				if (lcpprev < min_match_len)
					lcpprev = 0;
				else if (lcpprev > max_match_len)
					lcpprev = max_match_len;

				LZ_ASSERT(lcpprev == link[r].lcpprev);
				break;
			}
		}

		for (u32 next = r; ; ) {
			if (next == n - 1) {
				LZ_ASSERT(link[r].dist_to_next == 0);
				LZ_ASSERT(link[r].lcpnext == 0);
				break;
			}

			next++;

			if (SA[next] < SA[r]) {
				LZ_ASSERT(link[r].dist_to_next == min(next - r, LZ_LSA_DELTA_MAX));

				u32 lcpnext;
				for (lcpnext = 0;
				     lcpnext < min(n - SA[next], n - SA[r]) &&
					     T[SA[next] + lcpnext] == T[SA[r] + lcpnext];
				     lcpnext++)
					;
				if (lcpnext < min_match_len)
					lcpnext = 0;
				else if (lcpnext > max_match_len)
					lcpnext = max_match_len;

				LZ_ASSERT(lcpnext == link[r].lcpnext);
				break;
			}
		}
	}
#endif
}

static inline void
lz_lsa_update_salink(const u32 r, struct salink link[])
{
	const u32 next = r + link[r].dist_to_next;
	const u32 prev = r - link[r].dist_to_prev;

	if (next != r && link[r].dist_to_next < link[next].dist_to_prev) {
		link[next].dist_to_prev = link[r].dist_to_next;
		link[next].lcpprev = link[r].lcpnext;
	}

	if (prev != r && link[r].dist_to_prev < link[prev].dist_to_next) {
		link[prev].dist_to_next = link[r].dist_to_prev;
		link[prev].lcpnext = link[r].lcpprev;
	}
}

static void
lz_lsa_set_default_params(struct lz_mf_params *params)
{
	if (params->min_match_len == 0)
		params->min_match_len = 2;

	if (params->max_match_len == 0)
		params->max_match_len = UINT32_MAX;

	if (params->max_match_len > LZ_LSA_LEN_MAX)
		params->max_match_len = LZ_LSA_LEN_MAX;

	if (params->max_search_depth == 0)
		params->max_search_depth = 32;

	/* Scale max_search_depth down since this algorithm finds the longest
	 * matches first.  */
	params->max_search_depth = DIV_ROUND_UP(params->max_search_depth, 5);
}

static u64
lz_lsa_get_needed_memory(u32 max_window_size)
{
	u64 size = 0;

	/* SA */
	size += (u64)max_window_size * sizeof(u32);

	/* ISA */
	size += (u64)max_window_size * sizeof(u32);

	/* salink and minimum temporary space for divsufsort  */
	size += max(BUILD_SA_MIN_TMP_LEN * sizeof(u32),
		    (u64)max_window_size * sizeof(struct salink));

	return size;
}

static bool
lz_lsa_params_valid(const struct lz_mf_params *params)
{
	return true;
}

static bool
lz_lsa_init(struct lz_mf *_mf)
{
	struct lz_lsa *mf = (struct lz_lsa *)_mf;
	const u32 max_window_size = mf->base.params.max_window_size;

	lz_lsa_set_default_params(&mf->base.params);

	/* SA and ISA will share the same allocation.  */
	mf->SA = MALLOC(max_window_size * 2 * sizeof(u32));
	if (!mf->SA)
		return false;

	mf->salink = MALLOC(max(BUILD_SA_MIN_TMP_LEN * sizeof(u32),
				max_window_size * sizeof(struct salink)));
	if (!mf->salink) {
		FREE(mf->SA);
		return false;
	}

	return true;
}

static void
lz_lsa_load_window(struct lz_mf *_mf, const u8 T[], u32 n)
{
	struct lz_lsa *mf = (struct lz_lsa *)_mf;
	u32 *ISA, *LCP;

	build_SA(mf->SA, T, n, (u32 *)mf->salink);

	/* Compute ISA (Inverse Suffix Array) in a preliminary position.
	 *
	 * This is just a trick to save memory.  Since LCP is unneeded after
	 * this function, it can be computed in any available space.  The
	 * storage for the ISA is the best choice because the ISA can be built
	 * quickly in salink for now, then re-built in its real location at the
	 * end.  This is probably worth it because computing the ISA from the SA
	 * is very fast, and since this match-finder is memory-hungry we'd like
	 * to save as much memory as possible.  */
	BUILD_BUG_ON(sizeof(mf->salink[0]) < sizeof(mf->ISA[0]));
	ISA = (u32 *)mf->salink;
	build_ISA(ISA, mf->SA, n);

	/* Compute LCP (Longest Common Prefix) array.  */
	LCP = mf->SA + n;
	build_LCP(LCP, mf->SA, ISA, T, n);

	/* Initialize suffix array links.  */
	init_salink(mf->salink, LCP, mf->SA, T, n,
		    mf->base.params.min_match_len,
		    mf->base.params.max_match_len);
	verify_salink(mf->salink, mf->SA, T, n,
		      mf->base.params.min_match_len,
		      mf->base.params.max_match_len);

	/* Compute ISA (Inverse Suffix Array) in its final position.  */
	ISA = mf->SA + n;
	build_ISA(ISA, mf->SA, n);

	/* Save new variables and return.  */
	mf->ISA = ISA;
}

static u32
lz_lsa_get_matches(struct lz_mf *_mf, struct lz_match matches[])
{
	struct lz_lsa *mf = (struct lz_lsa *)_mf;
	const u32 i = mf->base.cur_window_pos++;

	const u32 * const restrict SA = mf->SA;
	const u32 * const restrict ISA = mf->ISA;
	struct salink * const restrict link = mf->salink;

	/* r = Rank of the suffix at the current position.  */
	const u32 r = ISA[i];

	/* Prepare for searching the current position.  */
	lz_lsa_update_salink(r, link);

	/* Prefetch next position in SA and link.
	 *
	 * This can improve performance on large windows since the locations in
	 * SA and link at which each successive search begins are in general
	 * randomly distributed.  */
	if (likely(i + 1 < mf->base.cur_window_size)) {
		const u32 next_r = ISA[i + 1];
		prefetch(&SA[next_r]);
		prefetch(&link[next_r]);
	}

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
	u32 L = r - link[r].dist_to_prev;
	u32 R = r + link[r].dist_to_next;
	u32 lenL = link[r].lcpprev;
	u32 lenR = link[r].lcpnext;

	/* num_matches = number of matches found so far.  */
	u32 num_matches = 0;

	/* best_offset = offset of lowest-cost match found so far.
	 *
	 * Shorter matches that do not have a lower offset than this are
	 * discarded, since presumably it would be cheaper to output the bytes
	 * from the longer match instead.  */
	u32 best_offset = LZ_LSA_POS_MAX;

	/* count_remaining = maximum number of possible matches remaining to be
	 * considered.  */
	u32 count_remaining = mf->base.params.max_search_depth;

	/* pending_offset = offset of lowest-cost match found for the current
	 * length, or 0 if none found yet.  */
	u32 pending_offset = 0;

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
		u32 offset;
		u32 old_L;
		u32 old_lenL;

		/* Check for hard cutoff on amount of work done.  */
		if (count_remaining-- == 0) {
			if (pending_offset != 0) {
				/* Save pending match.  */
				matches[num_matches++] = (struct lz_match) {
					.len = lenL,
					.offset = pending_offset,
				};
			}
			goto out;
		}

		if (SA[L] < i) {
			/* Suffix is in LZ77 dictionary.  (Check was needed
			 * because the salink array caps distances to save
			 * memory.)  */

			offset = i - SA[L];

			/* Save match offset if it results in lower cost.  */
			if (offset < best_offset) {
				best_offset = offset;
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
					matches[num_matches++] = (struct lz_match) {
						.len = old_lenL,
						.offset = pending_offset,
					};
					pending_offset = 0;
				}

				if (lenL >= lenR) {
					/* New match length on left is still at
					 * least as large as the next match
					 * length on the right:  Keep extending
					 * left, unless the minimum match length
					 * would be underrun.  */
					if (lenL == 0)
						goto out;
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
		u32 offset;
		u32 old_R;
		u32 old_lenR;

		/* Check for hard cutoff on amount of work done.  */
		if (count_remaining-- == 0) {
			if (pending_offset != 0) {
				/* Save pending match.  */
				matches[num_matches++] = (struct lz_match) {
					.len = lenR,
					.offset = pending_offset,
				};
			}
			goto out;
		}

		if (SA[R] < i) {
			/* Suffix is in LZ77 dictionary.  (Check was needed
			 * because the salink array caps distances to save
			 * memory.)  */

			offset = i - SA[R];

			if (offset < best_offset) {
				best_offset = offset;
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
				matches[num_matches++] = (struct lz_match) {
					.len = old_lenR,
					.offset = pending_offset,
				};
				pending_offset = 0;
			}

			if (lenL >= lenR) {
				/* lenL >= lenR:  Extend left, unless the
				 * minimum match length would be underrun, in
				 * which case we are done.  */
				if (lenL == 0)
					goto out;

				goto extend_left;
			}
			/* lenR > lenL:  Keep extending right.
			 * (No check for whether the minimum match length has
			 * been underrun is needed, provided that such lengths
			 * are marked as 0.)  */
		}
	}

out:
	for (u32 i = 0; i < num_matches / 2; i++)
		swap(matches[i], matches[num_matches - 1 - i]);
	return num_matches;
}

static void
lz_lsa_skip_positions(struct lz_mf *_mf, u32 n)
{
	struct lz_lsa *mf = (struct lz_lsa *)_mf;
	do {
		lz_lsa_update_salink(mf->ISA[mf->base.cur_window_pos++], mf->salink);
	} while (--n);
}

static void
lz_lsa_destroy(struct lz_mf *_mf)
{
	struct lz_lsa *mf = (struct lz_lsa *)_mf;

	FREE(mf->SA);
	FREE(mf->salink);
}

const struct lz_mf_ops lz_linked_suffix_array_ops = {
	.params_valid      = lz_lsa_params_valid,
	.get_needed_memory = lz_lsa_get_needed_memory,
	.init		   = lz_lsa_init,
	.load_window       = lz_lsa_load_window,
	.get_matches       = lz_lsa_get_matches,
	.skip_positions    = lz_lsa_skip_positions,
	.destroy           = lz_lsa_destroy,
	.struct_size	   = sizeof(struct lz_lsa),
};
