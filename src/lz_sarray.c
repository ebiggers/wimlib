/*
 * lz_sarray.c
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lz_sarray.h"
#include "wimlib/util.h"
#include "divsufsort/divsufsort.h"
#include <string.h>

#define DIVSUFSORT_TMP1_SIZE (256 * sizeof(saidx_t))	   /* bucket_A  */
#define DIVSUFSORT_TMP2_SIZE (256 * 256 * sizeof(saidx_t)) /* bucket_B  */

/* If ENABLE_LZ_DEBUG is defined, verify that the suffix array satisfies its
 * definition.
 *
 * @SA		The constructed suffix array.
 * @T		The original data.
 * @found	Temporary 'bool' array of length @n.
 * @n		Length of the data (length of @SA, @T, and @found arrays).
 *
 * WARNING: this is for debug use only as it does not necessarily run in linear
 * time!!!  */
static void
verify_suffix_array(const lz_sarray_pos_t SA[restrict],
		    const u8 T[restrict],
		    bool found[restrict],
		    lz_sarray_pos_t n)
{
#ifdef ENABLE_LZ_DEBUG
	/* Ensure the SA contains exactly one of each i in [0, n - 1].  */
	for (lz_sarray_pos_t i = 0; i < n; i++)
		found[i] = false;
	for (lz_sarray_pos_t r = 0; r < n; r++) {
		lz_sarray_pos_t i = SA[r];
		LZ_ASSERT(i < n);
		LZ_ASSERT(!found[i]);
		found[i] = true;
	}

	/* Ensure the suffix with rank r is lexicographically lesser than the
	 * suffix with rank (r + 1) for all r in [0, n - 2].  */
	for (lz_sarray_pos_t r = 0; r < n - 1; r++) {

		lz_sarray_pos_t i1 = SA[r];
		lz_sarray_pos_t i2 = SA[r + 1];

		lz_sarray_pos_t n1 = n - i1;
		lz_sarray_pos_t n2 = n - i2;

		int res = memcmp(&T[i1], &T[i2], min(n1, n2));
		LZ_ASSERT(res < 0 || (res == 0 && n1 < n2));
	}
#endif /* ENABLE_LZ_DEBUG  */
}

/* Compute the inverse suffix array @ISA from the suffix array @SA in linear
 * time.
 *
 * Whereas the suffix array is a mapping from suffix rank to suffix position,
 * the inverse suffix array is a mapping from suffix position to suffix rank.
 */
static void
compute_inverse_suffix_array(lz_sarray_pos_t ISA[restrict],
			     const lz_sarray_pos_t SA[restrict],
			     lz_sarray_pos_t n)
{
	lz_sarray_pos_t r;

	for (r = 0; r < n; r++)
		ISA[SA[r]] = r;
}


/* Compute the LCP (Longest Common Prefix) array in linear time.
 *
 * LCP[r] will be the length of the longest common prefix between the suffixes
 * with positions SA[r - 1] and  SA[r].  LCP[0] will be undefined.
 *
 * Algorithm adapted from Kasai et al. 2001: "Linear-Time Longest-Common-Prefix
 * Computation in Suffix Arrays and Its Applications".  Modified slightly to
 * take into account that with bytes in the real world, there is no unique
 * symbol at the end of the string.  */
static void
compute_lcp_array(lz_sarray_pos_t LCP[restrict],
		  const lz_sarray_pos_t SA[restrict],
		  const lz_sarray_pos_t ISA[restrict],
		  const u8 T[restrict],
		  lz_sarray_pos_t n)
{
	lz_sarray_pos_t h, i, r, j, lim;

	h = 0;
	for (i = 0; i < n; i++) {
		r = ISA[i];
		if (r > 0) {
			j = SA[r - 1];
			lim = min(n - i, n - j);

			while (h < lim && T[i + h] == T[j + h])
				h++;
			LCP[r] = h;
			if (h > 0)
				h--;
		}
	}
}

/* If ENABLE_LZ_DEBUG is defined, verify that the LCP (Longest Common Prefix)
 * array satisfies its definition.
 *
 * WARNING: this is for debug use only as it does not necessarily run in linear
 * time!!!  */
static void
verify_lcp_array(lz_sarray_pos_t LCP[restrict],
		 const lz_sarray_pos_t SA[restrict],
		 const u8 T[restrict],
		 lz_sarray_pos_t n)
{
#ifdef ENABLE_LZ_DEBUG
	for (lz_sarray_pos_t r = 0; r < n - 1; r++) {
		lz_sarray_pos_t i1 = SA[r];
		lz_sarray_pos_t i2 = SA[r + 1];
		lz_sarray_pos_t lcp = LCP[r + 1];

		lz_sarray_pos_t n1 = n - i1;
		lz_sarray_pos_t n2 = n - i2;

		LZ_ASSERT(lcp <= min(n1, n2));

		LZ_ASSERT(memcmp(&T[i1], &T[i2], lcp) == 0);
		if (lcp < min(n1, n2))
			LZ_ASSERT(T[i1 + lcp] != T[i2 + lcp]);
	}
#endif /* ENABLE_LZ_DEBUG */
}

/* Initialize the SA link array in linear time.
 *
 * This is similar to computing the LPF (Longest Previous Factor) array, which
 * is addressed in several papers.  In particular the algorithms below are based
 * on Crochemore et al. 2009: "LPF computation revisited".  However, this
 * match-finder does not actually compute or use the LPF array per se.  Rather,
 * this function sets up some information necessary to compute the LPF array,
 * but later lz_sarray_get_matches() actually uses this information to search
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
init_salink(struct salink link[restrict],
	    lz_sarray_pos_t LCP[restrict],
	    const lz_sarray_pos_t SA[restrict],
	    const u8 T[restrict],
	    lz_sarray_pos_t n,
	    lz_sarray_len_t min_match_len,
	    lz_sarray_len_t max_match_len)
{
	/* Calculate salink.dist_to_next and salink.lcpnext.
	 *
	 * Pass 1 calculates, for each suffix rank, the corresponding
	 * "next_initial" value which is the smallest larger rank that
	 * corresponds to a suffix starting earlier in the string.  It also
	 * calculates "lcpnext_initial", which is the longest common prefix with
	 * that suffix, although to eliminate checks in lz_sarray_get_matches(),
	 * "lcpnext_initial" is set to 0 if it's less than the minimum match
	 * length or set to the maximum match length if it's greater than the
	 * maximum match length.
	 *
	 * Pass 2 translates each absolute "next_initial", a 4-byte value, into
	 * a relative "dist_to_next", a 1-byte value.  This is done to save
	 * memory.  In the case that the exact relative distance cannot be
	 * encoded in 1 byte, it is capped to 255.  This is valid as long as
	 * lz_sarray_get_matches() validates each position before using it.
	 * Note that "lcpnext" need not be updated in this case because it will
	 * not be used until the actual next rank has been found anyway.
	 */
	link[n - 1].next_initial = LZ_SARRAY_POS_MAX;
	link[n - 1].lcpnext_initial = 0;
	for (lz_sarray_pos_t r = n - 2; r != LZ_SARRAY_POS_MAX; r--) {
		lz_sarray_pos_t t = r + 1;
		lz_sarray_pos_t l = LCP[t];
		while (t != LZ_SARRAY_POS_MAX && SA[t] > SA[r]) {
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
	for (lz_sarray_pos_t r = 0; r < n; r++) {
		lz_sarray_pos_t next;
		lz_sarray_len_t l;
		lz_sarray_delta_t dist_to_next;

		next = link[r].next_initial;
		l = link[r].lcpnext_initial;

		if (next == LZ_SARRAY_POS_MAX)
			dist_to_next = 0;
		else if (next - r <= LZ_SARRAY_DELTA_MAX)
			dist_to_next = next - r;
		else
			dist_to_next = LZ_SARRAY_DELTA_MAX;

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
	LCP[0] = LZ_SARRAY_POS_MAX;
	link[0].lcpprev = 0;
	for (lz_sarray_pos_t r = 1; r < n; r++) {
		lz_sarray_pos_t t = r - 1;
		lz_sarray_pos_t l = LCP[r];
		while (t != LZ_SARRAY_POS_MAX && SA[t] > SA[r]) {
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
	for (lz_sarray_pos_t r = 0; r < n; r++) {

		lz_sarray_pos_t prev = LCP[r];

		if (prev == LZ_SARRAY_POS_MAX)
			link[r].dist_to_prev = 0;
		else if (r - prev <= LZ_SARRAY_DELTA_MAX)
			link[r].dist_to_prev = r - prev;
		else
			link[r].dist_to_prev = LZ_SARRAY_DELTA_MAX;
	}
}

/* If ENABLE_LZ_DEBUG is defined, verify the values computed by init_salink().
 *
 * WARNING: this is for debug use only as it does not necessarily run in linear
 * time!!!  */
static void
verify_salink(const struct salink link[],
	      const lz_sarray_pos_t SA[],
	      const u8 T[],
	      lz_sarray_pos_t n,
	      lz_sarray_len_t min_match_len,
	      lz_sarray_len_t max_match_len)
{
#ifdef ENABLE_LZ_DEBUG
	for (lz_sarray_pos_t r = 0; r < n; r++) {
		for (lz_sarray_pos_t prev = r; ; ) {
			if (prev == 0) {
				LZ_ASSERT(link[r].dist_to_prev == 0);
				LZ_ASSERT(link[r].lcpprev == 0);
				break;
			}

			prev--;

			if (SA[prev] < SA[r]) {
				LZ_ASSERT(link[r].dist_to_prev == min(r - prev, LZ_SARRAY_DELTA_MAX));

				lz_sarray_pos_t lcpprev;
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

		for (lz_sarray_pos_t next = r; ; ) {
			if (next == n - 1) {
				LZ_ASSERT(link[r].dist_to_next == 0);
				LZ_ASSERT(link[r].lcpnext == 0);
				break;
			}

			next++;

			if (SA[next] < SA[r]) {
				LZ_ASSERT(link[r].dist_to_next == min(next - r, LZ_SARRAY_DELTA_MAX));

				lz_sarray_pos_t lcpnext;
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

/*
 * Initialize the suffix array match-finder.
 *
 * @mf
 *	The suffix array match-finder structure to initialize.  This structure
 *	is expected to be zeroed before this function is called.  In the case
 *	that this function fails, lz_sarray_destroy() should be called to free
 *	any memory that may have been allocated.
 *
 * @max_window_size
 *	The maximum window size to support.  This must be greater than 0.
 *
 *	The amount of needed memory will depend on this value; see
 *	lz_sarray_get_needed_memory() for details.
 *
 * @min_match_len
 *	The minimum length of each match to be found.  Must be greater than 0.
 *
 * @max_match_len
 *	The maximum length of each match to be found.  Must be greater than or
 *	equal to @min_match_len.
 *
 * @max_matches_to_consider
 *	The maximum number of matches to consider at each position.  This should
 *	be greater than @max_matches_to_return because @max_matches_to_consider
 *	counts all the returned matches as well as matches of equal length to
 *	returned matches that were not returned.  This parameter bounds the
 *	amount of work the match-finder does at any one position.  This could be
 *	anywhere from 1 to 100+ depending on the compression ratio and
 *	performance desired.
 *
 * @max_matches_to_return
 *	Maximum number of matches to return at each position.  Because of the
 *	suffix array search algorithm, the order in which matches are returned
 *	will be from longest to shortest, so cut-offs due to this parameter will
 *	only result in shorter matches being discarded.  This parameter could be
 *	anywhere from 1 to (@max_match_len - @min_match_len + 1) depending on
 *	the compression performance desired.  However, making it even moderately
 *	large (say, greater than 3) may not be very helpful due to the property
 *	that the matches are returned from longest to shortest.  But the main
 *	thing to keep in mind is that if the compressor decides to output a
 *	shorter-than-possible match, ideally it would be best to choose the best
 *	match of the desired length rather than truncate a longer match to that
 *	length.
 *
 * After initialization, the suffix-array match-finder can be used for any
 * number of input strings (windows) of length less than or equal to
 * @max_window_size by successive calls to lz_sarray_load_window().
 *
 * Returns %true on success, or %false if sufficient memory could not be
 * allocated.  See the note for @max_window_size above regarding the needed
 * memory size.
 */
bool
lz_sarray_init(struct lz_sarray *mf,
	       lz_sarray_pos_t max_window_size,
	       lz_sarray_len_t min_match_len,
	       lz_sarray_len_t max_match_len,
	       u32 max_matches_to_consider,
	       u32 max_matches_to_return)
{
	LZ_ASSERT(min_match_len > 0);
	LZ_ASSERT(max_window_size > 0);
	LZ_ASSERT(max_match_len >= min_match_len);

	mf->max_window_size = max_window_size;
	mf->min_match_len = min_match_len;
	mf->max_match_len = max_match_len;
	mf->max_matches_to_consider = max_matches_to_consider;
	mf->max_matches_to_return = max_matches_to_return;

	/* SA and ISA will share the same storage block.  */
	if ((u64)2 * max_window_size * sizeof(mf->SA[0]) !=
		 2 * max_window_size * sizeof(mf->SA[0]))
		return false;
	mf->SA = MALLOC(max_window_size * sizeof(mf->SA[0]) +
			max(DIVSUFSORT_TMP1_SIZE,
			    max_window_size * sizeof(mf->SA[0])));
	if (mf->SA == NULL)
		return false;

	if ((u64)max_window_size * sizeof(mf->salink[0]) !=
		 max_window_size * sizeof(mf->salink[0]))
		return false;
	mf->salink = MALLOC(max(DIVSUFSORT_TMP2_SIZE,
				max_window_size * sizeof(mf->salink[0])));
	if (mf->salink == NULL)
		return false;

	return true;
}

/*
 * Return the number of bytes of memory that lz_sarray_init() would allocate for
 * the specified maximum window size.
 *
 * This should be (14 * @max_window_size) unless the type definitions have been
 * changed.
 */
u64
lz_sarray_get_needed_memory(lz_sarray_pos_t max_window_size)
{
	u64 size = 0;

	/* SA and ISA: 8 bytes per position  */
	size += (u64)max_window_size * sizeof(((struct lz_sarray*)0)->SA[0]) +
		max(DIVSUFSORT_TMP1_SIZE,
		    (u64)max_window_size * sizeof(((struct lz_sarray*)0)->SA[0]));

	/* salink: 6 bytes per position  */
	size += max(DIVSUFSORT_TMP2_SIZE,
		    (u64)max_window_size * sizeof(((struct lz_sarray*)0)->salink[0]));

	return size;
}

/*
 * Prepare the suffix array match-finder to scan the specified window for
 * matches.
 *
 * @mf	Suffix array match-finder previously initialized with lz_sarray_init().
 *
 * @T	Window, or "block", in which to find matches.
 *
 * @n	Size of window in bytes.  This must be positive and less than or equal
 *	to the @max_window_size passed to lz_sarray_init().
 *
 * This function runs in linear time (relative to @n).
 */
void
lz_sarray_load_window(struct lz_sarray *mf, const u8 T[], lz_sarray_pos_t n)
{
	lz_sarray_pos_t *ISA, *LCP;

	LZ_ASSERT(n > 0 && n <= mf->max_window_size);

	/* Compute SA (Suffix Array).
	 *
	 * divsufsort() needs temporary space --- one array with 256 spaces and
	 * one array with 65536 spaces.  The implementation of divsufsort() has
	 * been modified from the original to use the provided temporary space
	 * instead of allocating its own.
	 *
	 * We also check at build-time that divsufsort() uses the same integer
	 * size expected by this code.  Unfortunately, divsufsort breaks if
	 * 'sa_idx_t' is defined to be a 16-bit integer; however, that would
	 * limit blocks to only 65536 bytes anyway.  */
	BUILD_BUG_ON(sizeof(lz_sarray_pos_t) != sizeof(saidx_t));

	divsufsort(T, mf->SA, n, (saidx_t*)&mf->SA[n], (saidx_t*)mf->salink);

	BUILD_BUG_ON(sizeof(bool) > sizeof(mf->salink[0]));
	verify_suffix_array(mf->SA, T, (bool*)mf->salink, n);

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
	ISA = (lz_sarray_pos_t*)mf->salink;
	compute_inverse_suffix_array(ISA, mf->SA, n);

	/* Compute LCP (Longest Common Prefix) array.  */
	LCP = mf->SA + n;
	compute_lcp_array(LCP, mf->SA, ISA, T, n);
	verify_lcp_array(LCP, mf->SA, T, n);

	/* Initialize suffix array links.  */
	init_salink(mf->salink, LCP, mf->SA, T, n,
		    mf->min_match_len, mf->max_match_len);
	verify_salink(mf->salink, mf->SA, T, n,
		      mf->min_match_len, mf->max_match_len);

	/* Compute ISA (Inverse Suffix Array) in its final position.  */
	ISA = mf->SA + n;
	compute_inverse_suffix_array(ISA, mf->SA, n);

	/* Save new variables and return.  */
	mf->ISA = ISA;
	mf->cur_pos = 0;
	mf->window_size = n;
}

/* Free memory allocated for the suffix array match-finder.  */
void
lz_sarray_destroy(struct lz_sarray *mf)
{
	FREE(mf->SA);
	FREE(mf->salink);
}
