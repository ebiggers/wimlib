/*
 * lz_suffix_array_utils.c
 *
 * Common utilities for suffix-array based Lempel-Ziv match-finding algorithms.
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

#include "wimlib/divsufsort.h"
#include "wimlib/lz_mf.h"
#include "wimlib/lz_suffix_array_utils.h"
#include "wimlib/util.h"

/* If ENABLE_LZ_DEBUG is defined, verify that the suffix array satisfies its
 * definition.
 *
 * WARNING: this is for debug use only as it does not necessarily run in linear
 * time!!!  */
static void
verify_SA(const u32 *SA, const u8 *T, u32 n, u32 *tmp)
{
#ifdef ENABLE_LZ_DEBUG
	/* Ensure the SA contains exactly one of each i in [0, n - 1].  */
	for (u32 i = 0; i < n; i++)
		tmp[i] = 0;
	for (u32 r = 0; r < n; r++) {
		u32 i = SA[r];
		LZ_ASSERT(i < n);
		LZ_ASSERT(!tmp[i]);
		tmp[i] = 1;
	}

	/* Ensure the suffix with rank r is lexicographically less than the
	 * suffix with rank (r + 1) for all r in [0, n - 2].  */
	for (u32 r = 0; r < n - 1; r++) {

		u32 i1 = SA[r];
		u32 i2 = SA[r + 1];

		u32 n1 = n - i1;
		u32 n2 = n - i2;

		int res = memcmp(&T[i1], &T[i2], min(n1, n2));
		LZ_ASSERT(res < 0 || (res == 0 && n1 < n2));
	}
#endif /* ENABLE_LZ_DEBUG  */
}

/*
 * Build the suffix array (SA) for the specified "text".
 *
 * The SA is a sorted array of the text's suffixes, represented by indices into
 * the text.  It can equivalently be viewed as a mapping from suffix rank to
 * suffix position.
 *
 * To build the SA, we currently rely on libdivsufsort, which uses an
 * induced-sorting-based algorithm.  In practice, this seems to be the fastest
 * suffix array construction algorithm currently available.
 *
 * References:
 *
 *	Y. Mori.  libdivsufsort, a lightweight suffix-sorting library.
 *	https://code.google.com/p/libdivsufsort/.
 *
 *	G. Nong, S. Zhang, and W.H. Chan.  2009.  Linear Suffix Array
 *	Construction by Almost Pure Induced-Sorting.  Data Compression
 *	Conference, 2009.  DCC '09.  pp. 193 - 202.
 *
 *	S.J. Puglisi, W.F. Smyth, and A. Turpin.  2007.  A Taxonomy of Suffix
 *	Array Construction Algorithms.  ACM Computing Surveys (CSUR) Volume 39
 *	Issue 2, 2007 Article No. 4.
 */
void
build_SA(u32 *SA, const u8 *T, u32 n, u32 *tmp)
{
	BUILD_BUG_ON(BUILD_SA_MIN_TMP_LEN !=
		     DIVSUFSORT_TMP1_LEN + DIVSUFSORT_TMP2_LEN);

	/* Note: divsufsort() needs temporary space --- one array with 256
	 * spaces and one array with 65536 spaces.  The implementation of
	 * divsufsort() has been modified from the original to use the provided
	 * temporary space instead of allocating its own, since we don't want to
	 * have to deal with malloc() failures here.  */
	divsufsort(T, SA, n, tmp, tmp + DIVSUFSORT_TMP1_LEN);

	verify_SA(SA, T, n, tmp);
}


/* Build the inverse suffix array @ISA from the suffix array @SA in linear time.
 *
 * Whereas the suffix array is a mapping from suffix rank to suffix position,
 * the inverse suffix array is a mapping from suffix position to suffix rank.
 */
void
build_ISA(u32 * restrict ISA, const u32 * restrict SA, u32 n)
{
	for (u32 r = 0; r < n; r++)
		ISA[SA[r]] = r;
}

/* If ENABLE_LZ_DEBUG is defined, verify that the LCP (Longest Common Prefix)
 * array satisfies its definition.
 *
 * WARNING: this is for debug use only as it does not necessarily run in linear
 * time!!!  */
static void
verify_LCP(const u32 *LCP, const u32 *SA, const u8 *T, u32 n)
{
#ifdef ENABLE_LZ_DEBUG
	for (u32 r = 0; r < n - 1; r++) {
		u32 i1 = SA[r];
		u32 i2 = SA[r + 1];
		u32 lcp = LCP[r + 1];

		u32 n1 = n - i1;
		u32 n2 = n - i2;

		LZ_ASSERT(lcp <= min(n1, n2));

		LZ_ASSERT(memcmp(&T[i1], &T[i2], lcp) == 0);
		if (lcp < min(n1, n2))
			LZ_ASSERT(T[i1 + lcp] != T[i2 + lcp]);
	}
#endif /* ENABLE_LZ_DEBUG */
}

/*
 * Build the LCP (Longest Common Prefix) array in linear time.
 *
 * LCP[r] will be the length of the longest common prefix between the suffixes
 * with positions SA[r - 1] and  SA[r].  LCP[0] will be undefined.
 *
 * Algorithm taken from Kasai et al. (2001), but modified slightly to take into
 * account that with bytes in the real world, there is no unique symbol at the
 * end of the string.
 *
 * References:
 *
 *	Kasai et al.  2001.  Linear-Time Longest-Common-Prefix Computation in
 *	Suffix Arrays and Its Applications.  CPM '01 Proceedings of the 12th
 *	Annual Symposium on Combinatorial Pattern Matching pp. 181-192.
 */
void
build_LCP(u32 * restrict LCP, const u32 * restrict SA,
	  const u32 * restrict ISA, const u8 * restrict T, u32 n)
{
	u32 h, i, r, j, lim;

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

	verify_LCP(LCP, SA, T, n);
}
