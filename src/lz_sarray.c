/*
 * lz_sarray.c
 *
 * Suffix array match-finder for Lempel-Ziv compression.
 */

/*
 * Copyright (c) 2013 Eric Biggers.  All rights reserved.
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
verify_suffix_array(const input_idx_t SA[restrict],
		    const u8 T[restrict],
		    bool found[restrict],
		    input_idx_t n)
{
#ifdef ENABLE_LZ_DEBUG
	/* Ensure the SA contains exactly one of each i in [0, n - 1].  */
	for (input_idx_t i = 0; i < n; i++)
		found[i] = false;
	for (input_idx_t r = 0; r < n; r++) {
		input_idx_t i = SA[r];
		LZ_ASSERT(i < n);
		LZ_ASSERT(!found[i]);
		found[i] = true;
	}

	/* Ensure the suffix with rank r is lexicographically lesser than the
	 * suffix with rank (r + 1) for all r in [0, n - 2].  */
	for (input_idx_t r = 0; r < n - 1; r++) {

		input_idx_t i1 = SA[r];
		input_idx_t i2 = SA[r + 1];

		input_idx_t n1 = n - i1;
		input_idx_t n2 = n - i2;

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
compute_inverse_suffix_array(input_idx_t ISA[restrict],
			     const input_idx_t SA[restrict],
			     input_idx_t n)
{
	input_idx_t i;

	for (i = 0; i < n; i++)
		ISA[SA[i]] = i;
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
compute_lcp_array(input_idx_t LCP[restrict],
		  const input_idx_t SA[restrict],
		  const input_idx_t ISA[restrict],
		  const u8 T[restrict],
		  input_idx_t n)
{
	input_idx_t h, i, r, j, lim;

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
verify_lcp_array(input_idx_t LCP[restrict],
		 const input_idx_t SA[restrict],
		 const u8 T[restrict],
		 input_idx_t n)
{
#ifdef ENABLE_LZ_DEBUG
	for (input_idx_t r = 0; r < n - 1; r++) {
		input_idx_t i1 = SA[r];
		input_idx_t i2 = SA[r + 1];
		input_idx_t lcp = LCP[r + 1];

		input_idx_t n1 = n - i1;
		input_idx_t n2 = n - i2;

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
 */
static void
init_salink(struct salink link[restrict],
	    const input_idx_t LCP[restrict],
	    const input_idx_t SA[restrict],
	    const u8 T[restrict],
	    input_idx_t n,
	    input_idx_t max_match_len)
{
	/* Compute salink.next and salink.lcpnext.  */
	link[n - 1].next = ~(input_idx_t)0;
	link[n - 1].lcpnext = 0;
	for (input_idx_t r = n - 2; r != ~(input_idx_t)0; r--) {
		input_idx_t t = r + 1;
		input_idx_t l = LCP[t];
		while (t != ~(input_idx_t)0 && SA[t] > SA[r]) {
			l = min(l, link[t].lcpnext);
			t = link[t].next;
		}
		link[r].next = t;
		link[r].lcpnext = min(l, max_match_len);
	}

	/* Compute salink.prev and salink.lcpprev.  */
	link[0].prev = ~(input_idx_t)0;
	link[0].lcpprev = 0;
	for (input_idx_t r = 1; r < n; r++) {
		input_idx_t t = r - 1;
		input_idx_t l = LCP[r];
		while (t != ~(input_idx_t)0 && SA[t] > SA[r]) {
			l = min(l, link[t].lcpprev);
			t = link[t].prev;
		}
		link[r].prev = t;
		link[r].lcpprev = min(l, max_match_len);
	}
}

/* If ENABLE_LZ_DEBUG is defined, verify the values computed by init_salink().
 *
 * WARNING: this is for debug use only as it does not necessarily run in linear
 * time!!!  */
static void
verify_salink(const struct salink link[],
	      const input_idx_t SA[],
	      const u8 T[],
	      input_idx_t n,
	      input_idx_t max_match_len)
{
#ifdef ENABLE_LZ_DEBUG
	for (input_idx_t r = 0; r < n; r++) {
		for (input_idx_t prev = r; ; ) {
			if (prev == 0) {
				LZ_ASSERT(link[r].prev == ~(input_idx_t)0);
				LZ_ASSERT(link[r].lcpprev == 0);
				break;
			}

			prev--;

			if (SA[prev] < SA[r]) {
				LZ_ASSERT(link[r].prev == prev);
				LZ_ASSERT(link[r].lcpprev <= n - SA[prev]);
				LZ_ASSERT(link[r].lcpprev <= n - SA[r]);
				LZ_ASSERT(link[r].lcpprev <= max_match_len);
				LZ_ASSERT(0 == memcmp(&T[SA[prev]],
						      &T[SA[r]],
						      link[r].lcpprev));
				if (link[r].lcpprev < n - SA[prev] &&
				    link[r].lcpprev < n - SA[r] &&
				    link[r].lcpprev < max_match_len)
				{
					LZ_ASSERT(T[SA[prev] + link[r].lcpprev] !=
						  T[SA[r] + link[r].lcpprev]);
				}
				break;
			}
		}

		for (input_idx_t next = r; ; ) {
			if (next == n - 1) {
				LZ_ASSERT(link[r].next == ~(input_idx_t)0);
				LZ_ASSERT(link[r].lcpnext == 0);
				break;
			}

			next++;

			if (SA[next] < SA[r]) {
				LZ_ASSERT(link[r].next == next);
				LZ_ASSERT(link[r].lcpnext <= n - SA[next]);
				LZ_ASSERT(link[r].lcpnext <= n - SA[r]);
				LZ_ASSERT(link[r].lcpnext <= max_match_len);
				LZ_ASSERT(0 == memcmp(&T[SA[next]],
						      &T[SA[r]],
						      link[r].lcpnext));
				if (link[r].lcpnext < n - SA[next] &&
				    link[r].lcpnext < n - SA[r] &&
				    link[r].lcpnext < max_match_len)
				{
					LZ_ASSERT(T[SA[next] + link[r].lcpnext] !=
						  T[SA[r] + link[r].lcpnext]);

				}
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
 *	The maximum window size to support.
 *
 *	In the current implementation, the memory needed will be
 *	(6 * sizeof(input_idx_t) * @max_window_size) bytes.
 *	For (sizeof(input_idx_t) == 4) that's 24 times the window size.
 *
 *	Memory is saved by saving neither the original window nor the LCP
 *	(Longest Common Prefix) array; otherwise 29 times the window size would
 *	be required.  (In practice the compressor will likely keep the original
 *	window around anyway, although based on this property of the
 *	match-finder it theoretically it could overwrite it with the compressed
 *	data.)
 *
 * @min_match_len
 *	The minimum length of each match to be found.
 *
 * @max_match_len
 *	The maximum length of each match to be found.
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
	       input_idx_t max_window_size,
	       input_idx_t min_match_len,
	       input_idx_t max_match_len,
	       u32 max_matches_to_consider,
	       u32 max_matches_to_return)
{
	mf->max_window_size = max_window_size;
	mf->min_match_len = min_match_len;
	mf->max_match_len = max_match_len;
	mf->max_matches_to_consider = max_matches_to_consider;
	mf->max_matches_to_return = max_matches_to_return;

	/* SA and ISA will share the same storage block.  */
	mf->SA = MALLOC(2 * max_window_size * sizeof(mf->SA[0]));
	if (mf->SA == NULL)
		return false;

	mf->salink = MALLOC(max_window_size * sizeof(mf->salink[0]));
	if (mf->salink == NULL)
		return false;

	return true;
}

u64
lz_sarray_get_needed_memory(input_idx_t max_window_size)
{
	return (u64)6 * sizeof(input_idx_t) * max_window_size;
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
lz_sarray_load_window(struct lz_sarray *mf, const u8 T[], input_idx_t n)
{
	input_idx_t *ISA, *LCP;

	LZ_ASSERT(n > 0 && n <= mf->max_window_size);

	/* Compute SA (Suffix Array).
	 *
	 * divsufsort() needs temporary space --- one array with 256 spaces and
	 * one array with 65536 spaces.  The implementation has been modified
	 * from the original to use the provided temporary space instead of
	 * allocating its own.
	 *
	 * We also check at build-time that divsufsort() uses the same integer
	 * size expected by this code.  Unfortunately, divsufsort breaks if
	 * 'sa_idx_t' is defined to be a 16-bit integer; however, that would
	 * limit blocks to only 65536 bytes anyway.  */
	LZ_ASSERT(mf->max_window_size * sizeof(mf->SA[0])
		  >= 256 * sizeof(saidx_t));
	LZ_ASSERT(mf->max_window_size * sizeof(mf->salink[0])
		  >= 256 * 256 * sizeof(saidx_t));
	BUILD_BUG_ON(sizeof(input_idx_t) != sizeof(saidx_t));

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
	ISA = (input_idx_t*)mf->salink;
	compute_inverse_suffix_array(ISA, mf->SA, n);

	/* Compute LCP (Longest Common Prefix) array.  */
	LCP = mf->SA + n;
	compute_lcp_array(LCP, mf->SA, ISA, T, n);
	verify_lcp_array(LCP, mf->SA, T, n);

	/* Initialize suffix array links.  */
	init_salink(mf->salink, LCP, mf->SA, T, n, mf->max_match_len);
	verify_salink(mf->salink, mf->SA, T, n, mf->max_match_len);

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
