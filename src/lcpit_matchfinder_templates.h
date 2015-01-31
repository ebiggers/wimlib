/*
 * lcpit_matchfinder_templates.h
 *
 * This file is included by lcpit_matchfinder.c.
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

/*
 * In normal mode, we can pack a buffer position and a LCP value into a 32-bit
 * number.  In huge mode, we can't.
 */
#if HUGE_MODE
#  define GET_SA_ENTRY(r)	(SA[r])
#  define GET_LCP_ENTRY(r)	(LCP[r])
#  define SET_LCP_ENTRY(r, val)	(LCP[r] = (val))
#  define UNVISITED_TAG		HUGE_UNVISITED_TAG
#else
#  define GET_SA_ENTRY(r)	(SA_and_LCP[r] & SA_and_LCP_POS_MASK)
#  define GET_LCP_ENTRY(r)	(SA_and_LCP[r] >> SA_and_LCP_LCP_SHIFT)
#  define SET_LCP_ENTRY(r, val)	(SA_and_LCP[r] |= (val) << SA_and_LCP_LCP_SHIFT)
#  define UNVISITED_TAG		NORMAL_UNVISITED_TAG
#endif

/*
 * Build the LCP (Longest Common Prefix) array in linear time.
 *
 * LCP[r] will be the length of the longest common prefix between the suffixes
 * with positions SA[r - 1] and  SA[r].  LCP[0] will be undefined.
 *
 * Algorithm taken from Kasai et al. (2001), but modified slightly:
 *
 *  - For decreased memory usage and improved memory locality, pack the two
 *    logically distinct SA and LCP arrays into a single array SA_and_LCP.
 *
 *  - With bytes there is no realistic way to reserve a unique symbol for
 *    end-of-buffer, so use explicit checks for end-of-buffer.
 *
 *  - If a LCP value is less than the minimum match length, then store 0.  This
 *    avoids having to do comparisons against the minimum match length later.
 *
 *  - If a LCP value is greater than the "nice match length", then store the
 *    "nice match length".  This caps the number of bits needed to store each
 *    LCP value, and this caps the depth of the LCP-interval tree, without
 *    usually hurting the compression ratio too much.
 *
 * References:
 *
 *	Kasai et al.  2001.  Linear-Time Longest-Common-Prefix Computation in
 *	Suffix Arrays and Its Applications.  CPM '01 Proceedings of the 12th
 *	Annual Symposium on Combinatorial Pattern Matching pp. 181-192.
 */
#if HUGE_MODE
static void
build_LCP_huge(u32 LCP[restrict], const u32 SA[restrict], const u32 ISA[restrict],
	       const u8 T[restrict], u32 n, u32 min_lcp, u32 max_lcp)
#else
static void
build_LCP_normal(u32 SA_and_LCP[restrict], const u32 ISA[restrict],
		 const u8 T[restrict], u32 n, u32 min_lcp, u32 max_lcp)
#endif
{
	u32 h = 0;
	for (u32 i = 0; i < n; i++) {
		u32 r = ISA[i];
		if (r > 0) {
			u32 j = GET_SA_ENTRY(r - 1);
			u32 lim = min(n - i, n - j);
			while (h < lim && T[i + h] == T[j + h])
				h++;
			u32 stored_lcp = h;
			if (stored_lcp < min_lcp)
				stored_lcp = 0;
			else if (stored_lcp > max_lcp)
				stored_lcp = max_lcp;
			SET_LCP_ENTRY(r, stored_lcp);
			if (h > 0)
				h--;
		}
	}
}

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
 * superintervals.  See lcpit_advance_one_byte() for more details.
 *
 * Note: We limit the depth of the lcp-interval tree by capping the lcp at
 * LCP_MAX.  This can cause a sub-tree of intervals with lcp greater than
 * LCP_MAX to be collapsed into a single interval with lcp LCP_MAX.  This avoids
 * degenerate cases and does not hurt match-finding very much, since if we find
 * a match of length LCP_MAX and extend it as far as possible, that's usually
 * good enough because that region of the input must already be highly
 * compressible.
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
#if HUGE_MODE
static void
build_LCPIT_huge(const u32 SA[restrict], u32 LCP[], u64 intervals[],
		 u32 pos_data[restrict], u32 n)
#else
static void
build_LCPIT_normal(const u32 SA_and_LCP[restrict], u32 intervals[restrict],
		   u32 pos_data[restrict], u32 n)
#endif
{
	u32 next_interval_idx = 0;
	u32 open_intervals[LCP_MAX + 1];
	u32 *top = open_intervals;
	u32 prev_pos = GET_SA_ENTRY(0);

	/* The interval with lcp=0 covers the entire array.  It remains open
	 * until the end.  */
	*top = next_interval_idx;
	intervals[next_interval_idx] = 0;
	next_interval_idx++;

	for (u32 r = 1; r < n; r++) {
		u32 next_pos = GET_SA_ENTRY(r);
		u32 next_lcp = GET_LCP_ENTRY(r);
		u32 top_lcp = intervals[*top];

		if (next_lcp == top_lcp) {
			/* continuing the deepest open interval  */
			pos_data[prev_pos] = *top;
		} else if (next_lcp > top_lcp) {
			/* opening a new interval  */
			intervals[next_interval_idx] = next_lcp;
			*++top = next_interval_idx;
			pos_data[prev_pos] = next_interval_idx;
			next_interval_idx++;
		} else {
			/* closing the deepest open interval  */
			pos_data[prev_pos] = *top;
			for (;;) {
				u32 closed_interval_idx = *top;
				u32 superinterval_idx = *--top;
				u32 superinterval_lcp = intervals[superinterval_idx];

				if (next_lcp == superinterval_lcp) {
					/* continuing the superinterval */
					intervals[closed_interval_idx] |=
						(superinterval_idx << LCP_BITS) |
							UNVISITED_TAG;
					break;
				} else if (next_lcp > superinterval_lcp) {
					/* creating a new interval that is a
					 * superinterval of the one being
					 * closed, but still a subinterval of
					 * its superinterval  */
					intervals[next_interval_idx] = next_lcp;
					*++top = next_interval_idx;
					intervals[closed_interval_idx] |=
						(next_interval_idx << LCP_BITS) |
							UNVISITED_TAG;
					next_interval_idx++;
					break;
				} else {
					/* also closing the superinterval  */
					intervals[closed_interval_idx] |=
						(superinterval_idx << LCP_BITS) |
							UNVISITED_TAG;
				}
			}
		}
		prev_pos = next_pos;
	}

	/* close any still-open intervals  */
	pos_data[prev_pos] = *top;
	while (top > open_intervals) {
		u32 closed_interval_idx = *top;
		u32 superinterval_idx = *--top;
		intervals[closed_interval_idx] |=
			(superinterval_idx << LCP_BITS) | UNVISITED_TAG;
	}
}

/*
 * Advance the LCP-interval tree matchfinder by one byte.
 *
 * If @record_matches is true, then matches are recorded in the @matches array,
 * and the return value is the number of matches found.  Otherwise, @matches is
 * ignored and the return value is always 0.
 */
static inline u32
#if HUGE_MODE
lcpit_advance_one_byte_huge
#else
lcpit_advance_one_byte_normal
#endif
(struct lcpit_matchfinder *mf, struct lz_match * restrict matches,
 bool record_matches)
{
	const u32 cur_pos = mf->cur_pos++;
	u32 * const pos_data = mf->pos_data;
#if HUGE_MODE
	u64 * const intervals = mf->intervals64;
#else
	u32 * const intervals = mf->intervals;
#endif
	u32 num_matches = 0;
	u32 lcp, next_lcp;
	u32 interval, next_interval;
	u32 cur_match, next_match;

	/* Look up the deepest lcp-interval containing the current suffix.  */
	interval = pos_data[cur_pos];

	/* Prefetch the deepest lcp-interval containing the next suffix.  */
	prefetch(&intervals[pos_data[cur_pos + 1]]);

	/* Since the current position is greater than any position previously
	 * searched, set the "lcp interval of the next match" for this suffix to
	 * 0.  This is the index of the root interval, and this indicates that
	 * there is no next match.  */
	pos_data[cur_pos] = 0;

	/* Ascend the lcp-interval tree until we reach an lcp-interval that has
	 * already been visited.  */

	while (intervals[interval] & UNVISITED_TAG) {

		/* Visiting this lcp-interval for the first time.  Therefore,
		 * there are no matches with length equal to the lcp of this
		 * lcp-interval.  */

		/* Extract the LCP and superinterval reference.  */

		lcp = intervals[interval] & LCP_MASK;

		/* If the LCP is shorter than the minimum length of matches to
		 * be produced, we're done, since the LCP will only ever get
		 * shorter from here.  This also prevents ascending above the
		 * root of the lcp-interval tree, since the root is guaranteed
		 * to be a 0-interval.  */
		if (lcp == 0)
			return 0;

		next_interval = (intervals[interval] & ~UNVISITED_TAG) >> LCP_BITS;

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
		intervals[interval] = (cur_pos << LCP_BITS) | lcp;

		/* Ascend to the superinterval of this lcp-interval.  */
		interval = next_interval;
	}

	/* We've already visited the current lcp-interval.  */

	/* Extract the LCP of this lcp-interval.  */
	lcp = intervals[interval] & LCP_MASK;

	/* Extract the current match for this lcp-interval.  This usually is the
	 * most-recently-seen suffix within this lcp-interval, but it may be
	 * outdated.  */
	cur_match = intervals[interval] >> LCP_BITS;

	for (;;) {
		/* If the LCP is shorter than the minimum length of matches to
		 * be produced, we're done, since the LCP will only ever get
		 * shorter from here.  This also prevents ascending above the
		 * root of the lcp-interval tree, since the root is guaranteed
		 * to be a 0-interval.  */
		if (lcp == 0)
			break;

		/* Advance the current match until the lcp of the *next* match
		 * is lower than the current lcp.  When this is true we know
		 * that the current match is up to date (lowest offset /
		 * greatest position for that lcp).  */

		next_match = cur_match;
		do {
			next_interval = pos_data[next_match];
			next_lcp = intervals[next_interval] & LCP_MASK;
			cur_match = next_match;
			next_match = intervals[next_interval] >> LCP_BITS;
		} while (next_lcp >= lcp);

		/* Link the current position into the match chain, discarding
		 * any skipped matches.  */
		intervals[interval] = (cur_pos << LCP_BITS) | lcp;
		pos_data[cur_match] = interval;

		if (record_matches) {
			/* Record the match.  */
			matches[num_matches].length = lcp;
			matches[num_matches].offset = cur_pos - cur_match;
			num_matches++;
		}

		/* Advance to the next match.  */
		interval = next_interval;
		lcp = next_lcp;
		cur_match = next_match;
	}
	return num_matches;
}

#undef GET_SA_ENTRY
#undef GET_LCP_ENTRY
#undef SET_LCP_ENTRY
#undef UNVISITED_TAG
