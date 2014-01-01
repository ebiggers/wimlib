/*
 * lz_sarray.c
 *
 * Suffix array match-finder for LZ (Lempel-Ziv) compression.
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

/* Initialize the suffix array match-finder with the specified parameters.
 *
 * After initialization, it can be used for any number of input strings of
 * length less than or equal to @max_window_size.  */
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

	mf->SA = MALLOC(3U * max_window_size * sizeof(mf->SA[0]));
	if (mf->SA == NULL)
		return false;

	mf->salink = MALLOC(max_window_size * sizeof(mf->salink[0]));
	if (mf->salink == NULL)
		return false;

	return true;
}

/* Free memory allocated for the suffix array match-finder.  */
void
lz_sarray_destroy(struct lz_sarray *mf)
{
	FREE(mf->SA);
	FREE(mf->salink);
}

/* Initialize the suffix array match-finder for the specified input.  */
void
lz_sarray_load_window(struct lz_sarray *mf, const u8 window[],
		      input_idx_t window_size)
{
	/* Load variables  */
	const u8 * const restrict T = window;
	const input_idx_t n = window_size;
	const input_idx_t max_match_len = mf->max_match_len;
	input_idx_t * const restrict SA = mf->SA;
	input_idx_t * const restrict ISA = mf->ISA = SA + window_size;
	input_idx_t * const restrict LCP = mf->LCP = ISA + window_size;
	struct salink * const restrict link = mf->salink;

	/* Compute SA (Suffix Array).  */
	{
		/* ISA and link are used as temporary space.  */
		LZ_ASSERT(mf->max_window_size * sizeof(ISA[0]) >= 256 * sizeof(saidx_t));
		LZ_ASSERT(mf->max_window_size * 2 * sizeof(link[0]) >= 256 * 256 * sizeof(saidx_t));

		if (sizeof(input_idx_t) == sizeof(saidx_t)) {
			divsufsort(T, SA, n, (saidx_t*)ISA, (saidx_t*)link);
		} else {
			saidx_t sa[n];
			divsufsort(T, sa, n, (saidx_t*)ISA, (saidx_t*)link);
			for (input_idx_t i = 0; i < n; i++)
				SA[i] = sa[i];
		}
	}

#ifdef ENABLE_LZ_DEBUG

	LZ_ASSERT(n > 0);

	/* Verify suffix array.  */
	{
		bool found[n];
		ZERO_ARRAY(found);
		for (input_idx_t r = 0; r < n; r++) {
			input_idx_t i = SA[r];
			LZ_ASSERT(i < n);
			LZ_ASSERT(!found[i]);
			found[i] = true;
		}
	}

	for (input_idx_t r = 0; r < n - 1; r++) {

		input_idx_t i1 = SA[r];
		input_idx_t i2 = SA[r + 1];

		input_idx_t n1 = n - i1;
		input_idx_t n2 = n - i2;

		LZ_ASSERT(memcmp(&T[i1], &T[i2], min(n1, n2)) <= 0);
	}
	LZ_DEBUG("Verified SA (len %u)", n);
#endif /* ENABLE_LZ_DEBUG */

	/* Compute ISA (Inverse Suffix Array)  */
	for (input_idx_t r = 0; r < n; r++)
		ISA[SA[r]] = r;

	/* Compute LCP (longest common prefix) array.
	 *
	 * Algorithm adapted from Kasai et al. 2001: "Linear-Time
	 * Longest-Common-Prefix Computation in Suffix Arrays and Its
	 * Applications".  */
	{
		input_idx_t h = 0;
		for (input_idx_t i = 0; i < n; i++) {
			input_idx_t r = ISA[i];
			if (r > 0) {
				input_idx_t j = SA[r - 1];

				input_idx_t lim = min(n - i, n - j);

				while (h < lim && T[i + h] == T[j + h])
					h++;
				LCP[r] = h;
				if (h > 0)
					h--;
			}
		}
	}

#ifdef ENABLE_LZ_DEBUG
	/* Verify LCP array.  */
	for (input_idx_t r = 0; r < n - 1; r++) {
		LZ_ASSERT(ISA[SA[r]] == r);
		LZ_ASSERT(ISA[SA[r + 1]] == r + 1);

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

	/* Compute salink.next and salink.lcpnext.
	 *
	 * Algorithm adapted from Crochemore et al. 2009:
	 * "LPF computation revisited".
	 *
	 * Note: we cap lcpnext to the maximum match length so that the
	 * match-finder need not worry about it later.  */
	link[n - 1].next = ~(input_idx_t)0;
	link[n - 1].prev = ~(input_idx_t)0;
	link[n - 1].lcpnext = 0;
	link[n - 1].lcpprev = 0;
	for (input_idx_t r = n - 2; r != ~(input_idx_t)0; r--) {
		input_idx_t t = r + 1;
		input_idx_t l = LCP[t];
		while (t != ~(input_idx_t)0 && SA[t] > SA[r]) {
			l = min(l, link[t].lcpnext);
			t = link[t].next;
		}
		link[r].next = t;
		link[r].lcpnext = min(l, max_match_len);
		LZ_ASSERT(t == ~(input_idx_t)0 || l <= n - SA[t]);
		LZ_ASSERT(l <= n - SA[r]);
		if (t == ~(input_idx_t)0)
			LZ_ASSERT(l == 0);
		else
			LZ_ASSERT(memcmp(&T[SA[r]], &T[SA[t]], l) == 0);
	}

	/* Compute salink.prev and salink.lcpprev.
	 *
	 * Algorithm adapted from Crochemore et al. 2009:
	 * "LPF computation revisited".
	 *
	 * Note: we cap lcpprev to the maximum match length so that the
	 * match-finder need not worry about it later.  */
	link[0].prev = ~(input_idx_t)0;
	link[0].next = ~(input_idx_t)0;
	link[0].lcpprev = 0;
	link[0].lcpnext = 0;
	for (input_idx_t r = 1; r < n; r++) {
		input_idx_t t = r - 1;
		input_idx_t l = LCP[r];
		while (t != ~(input_idx_t)0 && SA[t] > SA[r]) {
			l = min(l, link[t].lcpprev);
			t = link[t].prev;
		}
		link[r].prev = t;
		link[r].lcpprev = min(l, max_match_len);
		LZ_ASSERT(t == ~(input_idx_t)0 || l <= n - SA[t]);
		LZ_ASSERT(l <= n - SA[r]);
		if (t == ~(input_idx_t)0)
			LZ_ASSERT(l == 0);
		else
			LZ_ASSERT(memcmp(&T[SA[r]], &T[SA[t]], l) == 0);
	}

	mf->cur_pos = 0;
	mf->window_size = n;
}
