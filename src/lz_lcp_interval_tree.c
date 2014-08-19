/*
 * lz_lcp_interval_tree.c
 *
 * A match-finder for Lempel-Ziv compression based on bottom-up construction and
 * traversal of the Longest Common Prefix (LCP) interval tree.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lz_mf.h"
#include "wimlib/lz_suffix_array_utils.h"
#include "wimlib/util.h"

/*
 * To save space, we pack lcp (longest common prefix) and position values into
 * 32-bit integers.  Therefore, we must divide the 32 bits into lcp and position
 * bits.  6 lcp bits seems to be a good value, since matches of length 64 are
 * sufficiently long so that the compression ratio isn't hurt much by choosing
 * one such match over another.  We also use 1 bit to mark intervals as "not yet
 * visited".  This leaves 25 bits, which when used for position results in a
 * maximum window size of 33554432 bytes.
 */
#define LZ_LCPIT_LCP_BITS		6
#define LZ_LCPIT_LCP_MASK		((1 << LZ_LCPIT_LCP_BITS) - 1)
#define LZ_LCPIT_LCP_MAX		LZ_LCPIT_LCP_MASK
#define LZ_LCPIT_POS_BITS		(32 - 1 - LZ_LCPIT_LCP_BITS)
#define LZ_LCPIT_MAX_WINDOW_SIZE	(1UL << LZ_LCPIT_POS_BITS)

struct lz_lcpit {
	struct lz_mf base;

	/* Each of the arrays has length equal to the window size.  This
	 * therefore results in an additional memory usage of 12 bytes per
	 * position.  (That's compared to about 8 for binary trees or 4 for hash
	 * chains, for example.)
	 *
	 * We allocate these arrays in one contiguous block.  'SA' is first,
	 * 'intervals' is second, and 'pos_data' is third.  */

	/* Pointer to the suffix array  */
	u32 *SA;

	/* Mapping: lcp-interval index => lcp-interval data
	 *
	 * Initially, the lcp-interval data for an lcp-interval contains that
	 * interval's lcp and superinterval index.
	 *
	 * After a lcp-interval is visited during match-finding, its
	 * lcp-interval data contains that interval's lcp and the position of
	 * the next suffix to consider as a match when matching against that
	 * lcp-interval.  */
	u32 *intervals;

	/* Mapping: suffix index ("window position") => lcp-interval index  */
	u32 *pos_data;
};

/*
 * Use the suffix array accompanied with the longest-common-prefix array --- in
 * other words, the "enhanced suffix array" --- to simulate a bottom-up
 * traversal of the corresponding suffix tree, or equivalently the "lcp-interval
 * tree", as described in Abouelhoda et al. (2004).
 *
 * While doing the traversal, create a table 'intervals' that contains data for
 * each lcp-interval, specifically the lcp value of that interval, and the index
 * of the superinterval.
 *
 * Also while doing the traversal, create a table 'pos_data' that contains a
 * mapping from suffix index to the deepest lcp-interval containing it.
 *
 * The result is that we will later be able to do match-finding at a given
 * position by looking up that position in 'pos_data' to get the deepest
 * lcp-interval containing the corresponding suffix, then proceeding to the
 * superintervals.  See lz_lcpit_get_matches() for more details.
 *
 * Note: We limit the depth of the lcp-interval tree by capping the lcp at
 * LZ_LCPIT_LCP_MAX.  This can cause a sub-tree of intervals with lcp greater
 * than LZ_LCPIT_LCP_MAX to be collapsed into a single interval with lcp
 * LZ_LCPIT_LCP_MAX.  This avoids degenerate cases and does not hurt
 * match-finding very much, since if we find a match of length LZ_LCPIT_LCP_MAX
 * and extend it as far as possible, that's usually good enough because that
 * region of the input must already be highly compressible.
 *
 * References:
 *
 *	M.I. Abouelhoda, S. Kurtz, E. Ohlebusch.  2004.  Replacing Suffix Trees
 *	With Enhanced Suffix Arrays.  Journal of Discrete Algorithms Volume 2
 *	Issue 1, March 2004, pp. 53-86.
 *
 *	G. Chen, S.J. Puglisi, W.F. Smyth.  2008.  Lempel-Ziv Factorization
 *	Using Less Time & Space.  Mathematics in Computer Science June 2008,
 *	Volume 1, Issue 4, pp. 605-623.
 *
 *	Kasai et al. Linear-Time Longest-Common-Prefix Computation in Suffix
 *	Arrays and Its Applications.  2001.  CPM '01 Proceedings of the 12th
 *	Annual Symposium on Combinatorial Pattern Matching pp. 181-192.
 */
static void
build_LCPIT(const u32 SA[restrict], u32 LCP[restrict],
	    u32 pos_data[restrict], const u32 lcp_limit, const u32 n)
{
	u32 *intervals = LCP;
	u32 next_interval;
	u32 incomplete_intervals[lcp_limit + 1];
	u32 *cur_interval;
	u32 prev_pos;

	/* As we determine lcp-intervals, we assign each one an entry in
	 * 'intervals', overwriting LCP in the process.  Each such entry will
	 * contain the index in 'intervals' of the superinterval, along with the
	 * longest common prefix length that the suffixes in that interval
	 * share.
	 *
	 * Note: since we don't need its memory for anything, we don't overwrite
	 * the suffix array, even though this could potentially be done since
	 * it's not actually used during match-finding.  */

	/* Process rank 0 as special case.  This creates the lcp-interval
	 * containing every suffix in the window.  */
	prev_pos = SA[0];
	intervals[0] = 0;
	pos_data[prev_pos] = 0;
	cur_interval = incomplete_intervals;
	*cur_interval = 0;
	next_interval = 1;

	/* Iterate through each suffix array rank.  */
	for (u32 r = 1; r < n; r++) {

		/* Get the longest common prefix (lcp) between the suffixes with
		 * ranks r and r - 1.  But cap it to the lcp limit.  */
		const u32 lcp = min(LCP[r], lcp_limit);

		/* Convert rank => position using the suffix array.  */
		const u32 pos = SA[r];

		/* cur_interval points to the index of the deepest (highest lcp
		 * value) incomplete lcp-interval.  */

		/*
		 * There are three cases:
		 *
		 * (1) The lcp stayed the same as the previous value.  Place the
		 * current suffix in cur_interval.  (This placement is
		 * tentative, because if LCP increases at the next rank, this
		 * suffix could still be placed in the resulting new LCP
		 * interval instead.)  cur_interval remains unchanged.
		 *
		 * (2) The lcp increased from the previous value.  This signals
		 * the beginning of a new lcp-interval.  Create it and push it
		 * onto the stack of incomplete intervals.  But since lcp is
		 * defined in terms of the longest prefix between this suffix
		 * and the *previous* ranked suffix, the new lcp-interval
		 * actually should have begun at the *previous* ranked suffix.
		 * Therefore, we need to set both pos_data[pos] and
		 * pos_data[prev_pos] to refer to the new interval.
		 *
		 * (3) The lcp decreased from the previous value.  This signals
		 * the termination of at least one lcp-interval.  Pop the stack,
		 * finalizing the lcp-intervals, until the current lcp is at
		 * least as large as the lcp associated with cur_interval.
		 * Then, if the current lcp is equal to the lcp associated with
		 * cur_interval, place the current suffix in cur_interval,
		 * similar to case (1).  Else, create a new lcp-interval,
		 * similar to case (2).
		 */

		if (lcp == (intervals[*cur_interval] & LZ_LCPIT_LCP_MASK)) {

			/* Case (1) */

			pos_data[pos] = *cur_interval;

		} else if (lcp > (intervals[*cur_interval] & LZ_LCPIT_LCP_MASK)) {

			/* Case (2) */

			intervals[next_interval] = lcp | 0x80000000;
			pos_data[prev_pos] = next_interval;
			pos_data[pos] = next_interval;
			*++cur_interval = next_interval++;

		} else {

			/* Case (3) */

			u32 interval;
			u32 superinterval;

			for (;;) {
				/* Examine the deepest incomplete lcp-interval
				 * and its superinterval.  */

				interval = *cur_interval;
				superinterval = *--cur_interval;

				if (lcp >= (intervals[superinterval] &
					    LZ_LCPIT_LCP_MASK))
					break;

				/* The current suffix can't go in either of
				 * them.  Therefore we're visiting 'interval'
				 * for the last time and finalizing its
				 * membership in 'superinterval'.  */

				intervals[interval] |=
					(superinterval << LZ_LCPIT_LCP_BITS);
			}

			/* The current suffix can't go in 'interval', but it can
			 * go in 'superinterval'.  */

			if (lcp > (intervals[superinterval] & LZ_LCPIT_LCP_MASK)) {
				/* Creating a new lcp-interval that is a
				 * superinterval of 'interval' but a subinterval
				 * of 'superinterval'.
				 *
				 * Example: with the LCP arrayl
				 *
				 *            2  2  2  4  4  3
				 *
				 * then we will execute this case when
				 * processing the LCP value 3.  The LCP
				 * intervals will be:
				 *
				 *            2  2  2  4  4  3
				 * (lcp=0):  |                |
				 * (lcp=2):  |                |
				 * (lcp=3):        |          |
				 * (lcp=4):        |       |
				 *
				 * Note that the 3-interval (the one being
				 * created by this code) is a superinterval of
				 * the 4-interval (which already existed)!  But
				 * we don't need to re-assign pos_data values in
				 * the 4-interval because they point to the
				 * deepest interval which contains them, which
				 * is the 4-interval.  */

				intervals[next_interval] = lcp | 0x80000000;
				intervals[interval] |=
					(next_interval << LZ_LCPIT_LCP_BITS);
				pos_data[pos] = next_interval;
				*++cur_interval = next_interval++;
			} else {
				/* Finishing 'interval', continuing with
				 * 'superinterval'.  */

				intervals[interval] |=
					(superinterval << LZ_LCPIT_LCP_BITS);
				pos_data[pos] = superinterval;
			}
		}

		/* Remember this suffix index when processing the next-ranked
		 * suffix.  */
		prev_pos = pos;
	}

	/* Finalize any still-incomplete lcp-intervals.  */
	while (intervals[*cur_interval] & LZ_LCPIT_LCP_MASK) {
		intervals[*cur_interval] |=
			(*(cur_interval - 1) << LZ_LCPIT_LCP_BITS);
		cur_interval--;
	}
}

static void
lz_lcpit_set_default_params(struct lz_mf_params *params)
{
	if (params->min_match_len == 0)
		params->min_match_len = 2;

	if (params->max_match_len == 0)
		params->max_match_len = UINT32_MAX;

	if (params->max_search_depth == 0)
		params->max_search_depth = 32;

	params->max_search_depth = DIV_ROUND_UP(params->max_search_depth, 8);

	if (params->nice_match_len == 0)
		params->nice_match_len = LZ_LCPIT_LCP_MAX;

	if (params->nice_match_len < params->min_match_len)
		params->nice_match_len = params->min_match_len;

	if (params->nice_match_len > params->max_match_len)
		params->nice_match_len = params->max_match_len;

	if (params->nice_match_len > LZ_LCPIT_LCP_MAX)
		params->nice_match_len = LZ_LCPIT_LCP_MAX;
}

static bool
lz_lcpit_params_valid(const struct lz_mf_params *params)
{
	return params->max_window_size <= LZ_LCPIT_MAX_WINDOW_SIZE;
}

static u64
lz_lcpit_get_needed_memory(u32 max_window_size)
{
	return sizeof(u32) * (max_window_size +
			      max(BUILD_SA_MIN_TMP_LEN,
				  2 * (u64)max_window_size));
}

static bool
lz_lcpit_init(struct lz_mf *_mf)
{
	struct lz_lcpit *mf = (struct lz_lcpit *)_mf;

	lz_lcpit_set_default_params(&mf->base.params);

	mf->SA = MALLOC(lz_lcpit_get_needed_memory(mf->base.params.max_window_size));
	if (!mf->SA)
		return false;

	return true;
}

static void
lz_lcpit_load_window(struct lz_mf *_mf, const u8 T[], u32 n)
{
	struct lz_lcpit *mf = (struct lz_lcpit *)_mf;
	u32 *mem = mf->SA;

	build_SA(&mem[0 * n], T, n, &mem[1 * n]);
	build_ISA(&mem[2 * n], &mem[0 * n], n);
	build_LCP(&mem[1 * n], &mem[0 * n], &mem[2 * n], T, n);
	build_LCPIT(&mem[0 * n], &mem[1 * n], &mem[2 * n],
		    mf->base.params.nice_match_len, n);
	mf->SA = &mem[0 * n];
	mf->intervals = &mem[1 * n];
	mf->pos_data = &mem[2 * n];
}

static u32
lz_lcpit_get_matches(struct lz_mf *_mf, struct lz_match matches[])
{
	struct lz_lcpit *mf = (struct lz_lcpit *)_mf;
	const u32 min_match_len = mf->base.params.min_match_len;
	const u32 cur_pos = mf->base.cur_window_pos;
	u32 * const pos_data = mf->pos_data;
	u32 * const intervals = mf->intervals;
	u32 num_matches = 0;
	u32 lcp, next_lcp;
	u32 interval, next_interval;
	u32 cur_match, next_match;

	/* Look up the deepest lcp-interval containing the current suffix.  */
	interval = pos_data[cur_pos];

	/* Since the current position is greater than any position previously
	 * searched, set the "lcp interval of the next match" for this suffix to
	 * 0.  This is the index of the root interval, and this indicates that
	 * there is no next match.  */
	pos_data[cur_pos] = 0;

	/* Ascend the lcp-interval tree until we reach an lcp-interval that has
	 * already been visited.  */

	while (intervals[interval] & 0x80000000) {

		/* Visiting this lcp-interval for the first time.  Therefore,
		 * there are no Lempel-Ziv matches with length equal to the lcp
		 * of this lcp-interval.  */

		/* Extract the LCP and superinterval reference.  */

		lcp = intervals[interval] & LZ_LCPIT_LCP_MASK;

		next_interval = (intervals[interval] & ~0x80000000)
					>> LZ_LCPIT_LCP_BITS;

		/* If the LCP is shorter than the minimum length of matches to
		 * be produced, we're done, since the LCP will only ever get
		 * shorter from here.  This also prevents ascending above the
		 * root of the lcp-interval tree, since the root is guaranteed
		 * to be a 0-interval, and min_match_len is guaranteed to be at
		 * least 2.  */
		if (lcp < min_match_len)
			goto out;

		/* Set the position of the most-recently-seen suffix within this
		 * lcp-interval.  Since this is the first visitation of this
		 * lcp-interval, this is simply the current suffix.
		 *
		 * Note that this overwrites the superinterval reference which
		 * was previously included in this lcp-interval data slot.
		 * Further visitations of this lcp-interval will detect that it
		 * is already visited and will follow the chain of
		 * most-recently-seen suffixes rather than ascend the tree
		 * directly.  */
		intervals[interval] = (cur_pos << LZ_LCPIT_LCP_BITS) | lcp;

		/* Ascend to the superinterval of this lcp-interval.  */
		interval = next_interval;
	}

	/* We've already visited the current lcp-interval.  */

	/* Extract the LCP of this lcp-interval.  */
	lcp = intervals[interval] & LZ_LCPIT_LCP_MASK;

	/* Extract the current match for this lcp-interval.  This usually is the
	 * most-recently-seen suffix within this lcp-interval, but it may be
	 * outdated.  */
	cur_match = intervals[interval] >> LZ_LCPIT_LCP_BITS;

	for (;;) {
		/* If the LCP is shorter than the minimum length of matches to
		 * be produced, we're done, since the LCP will only ever get
		 * shorter from here.  This also prevents ascending above the
		 * root of the lcp-interval tree, since the root is guaranteed
		 * to be a 0-interval, and min_match_len is guaranteed to be at
		 * least 2.  */
		if (lcp < min_match_len)
			break;

		/* Advance the current match until the lcp of the *next* match
		 * is lower than the current lcp.  When this is true we know
		 * that the current match is up to date (lowest offset /
		 * greatest position for that lcp).  */

		next_match = cur_match;
		do {
			next_interval = pos_data[next_match];
			next_lcp = intervals[next_interval] & LZ_LCPIT_LCP_MASK;
			cur_match = next_match;
			next_match = intervals[next_interval] >> LZ_LCPIT_LCP_BITS;
		} while (next_lcp >= lcp);

		/* Link the current position into the match chain, discarding
		 * any skipped matches.  */
		intervals[interval] = (cur_pos << LZ_LCPIT_LCP_BITS) | lcp;
		pos_data[cur_match] = interval;

		/* Record the match.  */
		matches[num_matches++] = (struct lz_match) {
			.len = lcp,
			.offset = cur_pos - cur_match,
		};

		/* Bound the number of matches per position.  */
		if (num_matches >= mf->base.params.max_search_depth)
			break;

		/* Advance to the next match.  */
		interval = next_interval;
		lcp = next_lcp;
		cur_match = next_match;
	}

	/* If the length of the longest match is equal to the lcp limit, it may
	 * have been truncated.  Try extending it up to the maximum match
	 * length.  */
	if (num_matches && matches[0].len == mf->base.params.nice_match_len) {
		const u8 * const strptr = lz_mf_get_window_ptr(&mf->base);
		const u8 * const matchptr = strptr - matches[0].offset;
		const u32 len_limit = min(lz_mf_get_bytes_remaining(&mf->base),
					  mf->base.params.max_match_len);
		u32 len;

		len = matches[0].len;
		while (len < len_limit && strptr[len] == matchptr[len])
			len++;
		matches[0].len = len;
	}

	for (u32 i = 0; i < num_matches / 2; i++)
		swap(matches[i], matches[num_matches - 1 - i]);
out:
	mf->base.cur_window_pos++;
	return num_matches;
}

/* Slightly simplified version of lz_lcpit_get_matches() for updating the data
 * structures when we don't actually need matches at the current position.  See
 * lz_lcpit_get_matches() for explanatory comments.  */
static void
lz_lcpit_skip_position(struct lz_lcpit *mf)
{
	const u32 min_match_len = mf->base.params.min_match_len;
	const u32 cur_pos = mf->base.cur_window_pos++;
	u32 * const pos_data = mf->pos_data;
	u32 * const intervals = mf->intervals;
	u32 lcp, next_lcp;
	u32 interval, next_interval;
	u32 cur_match, next_match;

	interval = pos_data[cur_pos];
	pos_data[cur_pos] = 0;
	while (intervals[interval] & 0x80000000) {
		lcp = intervals[interval] & LZ_LCPIT_LCP_MASK;
		next_interval = (intervals[interval] & ~0x80000000)
					>> LZ_LCPIT_LCP_BITS;
		if (lcp < min_match_len)
			return;
		intervals[interval] = (cur_pos << LZ_LCPIT_LCP_BITS) | lcp;
		interval = next_interval;
	}
	lcp = intervals[interval] & LZ_LCPIT_LCP_MASK;
	cur_match = intervals[interval] >> LZ_LCPIT_LCP_BITS;
	while (lcp >= min_match_len) {
		next_match = cur_match;
		do {
			next_interval = pos_data[next_match];
			next_lcp = intervals[next_interval] & LZ_LCPIT_LCP_MASK;
			cur_match = next_match;
			next_match = intervals[next_interval] >> LZ_LCPIT_LCP_BITS;
		} while (next_lcp >= lcp);
		intervals[interval] = (cur_pos << LZ_LCPIT_LCP_BITS) | lcp;
		pos_data[cur_match] = interval;
		interval = next_interval;
		lcp = next_lcp;
		cur_match = next_match;
	}
}

static void
lz_lcpit_skip_positions(struct lz_mf *_mf, u32 n)
{
	struct lz_lcpit *mf = (struct lz_lcpit *)_mf;

	do {
		lz_lcpit_skip_position(mf);
	} while (--n);
}

static void
lz_lcpit_destroy(struct lz_mf *_mf)
{
	struct lz_lcpit *mf = (struct lz_lcpit *)_mf;

	FREE(mf->SA);
}

const struct lz_mf_ops lz_lcp_interval_tree_ops = {
	.params_valid      = lz_lcpit_params_valid,
	.get_needed_memory = lz_lcpit_get_needed_memory,
	.init		   = lz_lcpit_init,
	.load_window       = lz_lcpit_load_window,
	.get_matches       = lz_lcpit_get_matches,
	.skip_positions    = lz_lcpit_skip_positions,
	.destroy           = lz_lcpit_destroy,
	.struct_size	   = sizeof(struct lz_lcpit),
};
