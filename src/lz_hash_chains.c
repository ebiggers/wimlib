/*
 * lz_hash_chains.c
 *
 * Hash chain match-finder for Lempel-Ziv compression.
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

#include "wimlib/lz_extend.h"
#include "wimlib/lz_hash3.h"
#include "wimlib/lz_mf.h"
#include "wimlib/util.h"

#include <string.h>

/* log2 of the number of buckets in the hash table.  This can be changed.  */
#define LZ_HC_HASH_ORDER 15

#define LZ_HC_HASH_LEN   (1 << LZ_HC_HASH_ORDER)

struct lz_hc {
	struct lz_mf base;
	u32 *hash_tab; /* followed by 'prev_tab' in memory */
	u32 next_hash;
};

static inline u32
lz_hc_hash(const u8 *p)
{
	return lz_hash(p, LZ_HC_HASH_ORDER);
}

static void
lz_hc_set_default_params(struct lz_mf_params *params)
{
	if (params->min_match_len < LZ_HASH_NBYTES)
		params->min_match_len = LZ_HASH_NBYTES;

	if (params->max_match_len == 0)
		params->max_match_len = UINT32_MAX;

	if (params->max_search_depth == 0)
		params->max_search_depth = 50;

	if (params->nice_match_len == 0)
		params->nice_match_len = 24;

	if (params->nice_match_len < params->min_match_len)
		params->nice_match_len = params->min_match_len;

	if (params->nice_match_len > params->max_match_len)
		params->nice_match_len = params->max_match_len;
}

static bool
lz_hc_params_valid(const struct lz_mf_params *_params)
{
	struct lz_mf_params params = *_params;

	lz_hc_set_default_params(&params);

	return (params.min_match_len <= params.max_match_len);
}

static u64
lz_hc_get_needed_memory(u32 max_window_size)
{
	u64 len = 0;

	len += LZ_HC_HASH_LEN;
	len += max_window_size;

	return len * sizeof(u32);
}

static bool
lz_hc_init(struct lz_mf *_mf)
{
	struct lz_hc *mf = (struct lz_hc *)_mf;

	lz_hc_set_default_params(&mf->base.params);

	mf->hash_tab = MALLOC(lz_hc_get_needed_memory(mf->base.params.max_window_size));
	if (!mf->hash_tab)
		return false;

	return true;
}

static void
lz_hc_load_window(struct lz_mf *_mf, const u8 window[], u32 size)
{
	struct lz_hc *mf = (struct lz_hc *)_mf;

	memset(mf->hash_tab, 0, LZ_HC_HASH_LEN * sizeof(u32));
}

static u32
lz_hc_get_matches(struct lz_mf *_mf, struct lz_match matches[])
{
	struct lz_hc *mf = (struct lz_hc *)_mf;
	const u8 * const window = mf->base.cur_window;
	const u32 cur_pos = mf->base.cur_window_pos++;
	const u8 * const strptr = &window[cur_pos];
	const u32 bytes_remaining = mf->base.cur_window_size - cur_pos;
	u32 * const prev_tab = mf->hash_tab + LZ_HC_HASH_LEN;
	const u32 max_len = min(bytes_remaining, mf->base.params.max_match_len);
	const u32 nice_len = min(max_len, mf->base.params.nice_match_len);
	u32 best_len = mf->base.params.min_match_len - 1;
	u32 depth_remaining = mf->base.params.max_search_depth;
	struct lz_match *lz_matchptr = matches;
	u32 hash;
	u32 cur_match;

	if (unlikely(bytes_remaining < LZ_HASH_REQUIRED_NBYTES + 1))
		return 0;

	/* Insert the current position into the appropriate hash chain and set
	 * 'cur_match' to the previous head.
	 *
	 * For a slight performance improvement, we do each hash calculation one
	 * position in advance and prefetch the necessary hash table entry.  */

	hash = mf->next_hash;
	mf->next_hash = lz_hc_hash(strptr + 1);
	prefetch(&mf->hash_tab[mf->next_hash]);
	cur_match = mf->hash_tab[hash];
	mf->hash_tab[hash] = cur_pos;
	prev_tab[cur_pos] = cur_match;

	/* Ensure we can find a match of at least the requested length.  */
	if (unlikely(best_len >= max_len))
		return 0;

	/* Search the appropriate hash chain for matches.  */
	for (; cur_match && depth_remaining--; cur_match = prev_tab[cur_match]) {

		const u8 * const matchptr = &window[cur_match];
		u32 len;

		/* Considering the potential match at 'matchptr':  is it longer
		 * than 'best_len'?
		 *
		 * The bytes at index 'best_len' are the most likely to differ,
		 * so check them first.  */
		if (matchptr[best_len] != strptr[best_len])
			goto next_match;

	#if HAVE_FAST_LZ_EXTEND
		if ((*(const u32 *)strptr & 0xFFFFFF) !=
		    (*(const u32 *)matchptr & 0xFFFFFF))
			goto next_match;

		len = lz_extend(strptr, matchptr, 3, max_len);

		if (len > best_len) {
			best_len = len;

			*lz_matchptr++ = (struct lz_match) {
				.len = best_len,
				.offset = strptr - matchptr,
			};

			if (best_len >= nice_len)
				break;
		}

	#else /* HAVE_FAST_LZ_EXTEND */

		/* The bytes at indices 'best_len - 1' and '0' are less
		 * important to check separately.  But doing so still gives a
		 * slight performance improvement, at least on x86_64, probably
		 * because they create separate branches for the CPU to predict
		 * independently of the branches in the main comparison loops.
		 */
		 if (matchptr[best_len - 1] != strptr[best_len - 1] ||
		     matchptr[0] != strptr[0])
			goto next_match;

		for (len = 1; len < best_len - 1; len++)
			if (matchptr[len] != strptr[len])
				goto next_match;

		/* The match is the longest found so far ---
		 * at least 'best_len' + 1 bytes.  Continue extending it.  */

		if (++best_len != max_len && strptr[best_len] == matchptr[best_len])
			while (++best_len != max_len)
				if (strptr[best_len] != matchptr[best_len])
					break;

		/* Record the match.  */
		*lz_matchptr++ = (struct lz_match) {
			.len = best_len,
			.offset = strptr - matchptr,
		};

		/* Terminate the search if 'nice_len' was reached.  */
		if (best_len >= nice_len)
			break;
	#endif /* !HAVE_FAST_LZ_EXTEND */

	next_match:
		/* Continue to next match in the chain.  */
		;
	}

	return lz_matchptr - matches;
}

static void
lz_hc_skip_positions(struct lz_mf *_mf, u32 n)
{
	struct lz_hc *mf = (struct lz_hc *)_mf;
	u32 * const hash_tab = mf->hash_tab;
	u32 * const prev_tab = hash_tab + LZ_HC_HASH_LEN;
	const u8 * const window = mf->base.cur_window;
	u32 cur_pos = mf->base.cur_window_pos;
	u32 end_pos = cur_pos + n;
	const u32 bytes_remaining = mf->base.cur_window_size - cur_pos;
	u32 hash;
	u32 next_hash;

	mf->base.cur_window_pos = end_pos;

	if (unlikely(bytes_remaining < n + (LZ_HASH_REQUIRED_NBYTES + 1) - 1)) {
	        /* Nearing end of window.  */
	        if (unlikely(bytes_remaining < (LZ_HASH_REQUIRED_NBYTES + 1)))
	                return;

	        end_pos = cur_pos + bytes_remaining - (LZ_HASH_REQUIRED_NBYTES + 1) + 1;
	}

	next_hash = mf->next_hash;
	do {
		hash = next_hash;
		next_hash = lz_hc_hash(&window[cur_pos + 1]);
		prev_tab[cur_pos] = hash_tab[hash];
		hash_tab[hash] = cur_pos;
	} while (++cur_pos != end_pos);

	prefetch(&hash_tab[next_hash]);
	mf->next_hash = next_hash;
}

static void
lz_hc_destroy(struct lz_mf *_mf)
{
	struct lz_hc *mf = (struct lz_hc *)_mf;

	FREE(mf->hash_tab);
}

const struct lz_mf_ops lz_hash_chains_ops = {
	.params_valid      = lz_hc_params_valid,
	.get_needed_memory = lz_hc_get_needed_memory,
	.init		   = lz_hc_init,
	.load_window       = lz_hc_load_window,
	.get_matches       = lz_hc_get_matches,
	.skip_positions    = lz_hc_skip_positions,
	.destroy           = lz_hc_destroy,
	.struct_size	   = sizeof(struct lz_hc),
};
