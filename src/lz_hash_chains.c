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

#include "wimlib/lz_mf.h"
#include "wimlib/util.h"
#include <pthread.h>
#include <string.h>

/* Number of hash buckets.  This can be changed, but should be a power of 2 so
 * that the correct hash bucket can be selected using a fast bitwise AND.  */
#define LZ_HC_HASH_LEN     (1 << 15)

/* Number of bytes from which the hash code is computed at each position.  This
 * can be changed, provided that lz_hc_hash() is updated as well.  */
#define LZ_HC_HASH_BYTES   3

struct lz_hc {
	struct lz_mf base;
	u32 *hash_tab;
	u32 *prev_tab;
	u32 next_hash;
};

static u32 crc32_table[256];
static pthread_once_t crc32_table_filled = PTHREAD_ONCE_INIT;

static void
crc32_init(void)
{
        for (u32 b = 0; b < 256; b++) {
                u32 r = b;
                for (int i = 0; i < 8; i++) {
                        if (r & 1)
                                r = (r >> 1) ^ 0xEDB88320;
                        else
                                r >>= 1;
                }
                crc32_table[b] = r;
        }
}

/* This hash function is taken from the LZMA SDK.  It seems to work well.
 *
 * TODO: Maybe use the SSE4.2 CRC32 instruction when available?  */
static inline u32
lz_hc_hash(const u8 *p)
{
	u32 hash = 0;

	hash ^= crc32_table[p[0]];
	hash ^= p[1];
	hash ^= (u32)p[2] << 8;

	return hash % LZ_HC_HASH_LEN;
}

static void
lz_hc_set_default_params(struct lz_mf_params *params)
{
	if (params->min_match_len < LZ_HC_HASH_BYTES)
		params->min_match_len = LZ_HC_HASH_BYTES;

	if (params->max_match_len == 0)
		params->max_match_len = params->max_window_size;

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

	/* Avoid edge case where min_match_len = 3, max_match_len = 2 */
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

	/* Allocate space for 'hash_tab' and 'prev_tab'.  */

	mf->hash_tab = MALLOC(lz_hc_get_needed_memory(mf->base.params.max_window_size));
	if (!mf->hash_tab)
		return false;

	mf->prev_tab = mf->hash_tab + LZ_HC_HASH_LEN;

	/* Fill in the CRC32 table if not done already.  */
	pthread_once(&crc32_table_filled, crc32_init);

	return true;
}

static void
lz_hc_load_window(struct lz_mf *_mf, const u8 window[], u32 size)
{
	struct lz_hc *mf = (struct lz_hc *)_mf;

	memset(mf->hash_tab, 0, LZ_HC_HASH_LEN * sizeof(u32));

	if (size >= LZ_HC_HASH_BYTES)
		mf->next_hash = lz_hc_hash(window);
}

static u32
lz_hc_get_matches(struct lz_mf *_mf, struct lz_match matches[])
{
	struct lz_hc *mf = (struct lz_hc *)_mf;
	const u8 * const window = mf->base.cur_window;
	const u32 cur_pos = mf->base.cur_window_pos;
	const u8 * const strptr = &window[cur_pos];
	const u32 bytes_remaining = mf->base.cur_window_size - cur_pos;
	u32 * const prev_tab = mf->prev_tab;
	const u32 nice_len = min(bytes_remaining, mf->base.params.nice_match_len);
	u32 best_len = mf->base.params.min_match_len - 1;
	u32 depth_remaining = mf->base.params.max_search_depth;
	u32 num_matches = 0;
	u32 hash;
	u32 cur_match;

	if (unlikely(bytes_remaining <= LZ_HC_HASH_BYTES))
		goto out;

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

	for (; cur_match && depth_remaining--; cur_match = prev_tab[cur_match]) {

		const u8 * const matchptr = &window[cur_match];
		u32 len;

		/* Considering a match at 'matchptr'.  */

		/* The bytes at index 'best_len' are the most likely to differ,
		 * so check them first.
		 *
		 * The bytes at indices 'best_len - 1' and '0' are less
		 * important to check separately.  But doing so still gives a
		 * slight performance improvement, probably because they create
		 * separate branches for the CPU to predict independently of the
		 * branches in the main comparison loops.  */
		if (matchptr[best_len] != strptr[best_len] ||
		    matchptr[best_len - 1] != strptr[best_len - 1] ||
		    matchptr[0] != strptr[0])
			goto next_match;

		for (len = 1; len < best_len - 1; len++)
			if (matchptr[len] != strptr[len])
				goto next_match;

		/* We now know the match length is at least 'best_len + 1'.  */

		len = best_len;

		do {
			if (++len == nice_len) {
				/* 'nice_len' reached; don't waste time
				 * searching for longer matches.  Extend the
				 * match as far as possible, record it, and
				 * return.  */
				const u32 max_len = min(bytes_remaining,
							mf->base.params.max_match_len);
				while (len < max_len && strptr[len] == matchptr[len])
					len++;
				matches[num_matches++] = (struct lz_match) {
					.len = len,
					.offset = strptr - matchptr,
				};
				goto out;
			}
		} while (matchptr[len] == strptr[len]);

		/* Found a longer match, but 'nice_len' not yet reached.  */
		best_len = len;
		matches[num_matches++] = (struct lz_match) {
			.len = len,
			.offset = strptr - matchptr,
		};

	next_match:
		/* Continue to next match in the chain.  */
		;
	}

out:
	mf->base.cur_window_pos++;
	return num_matches;
}

static void
lz_hc_skip_position(struct lz_hc *mf)
{
	const u32 bytes_remaining = lz_mf_get_bytes_remaining(&mf->base);
	u32 hash;

	if (bytes_remaining <= LZ_HC_HASH_BYTES)
		goto out;

	hash = mf->next_hash;
	mf->next_hash = lz_hc_hash(lz_mf_get_window_ptr(&mf->base) + 1);
	prefetch(&mf->hash_tab[mf->next_hash]);
	mf->prev_tab[mf->base.cur_window_pos] = mf->hash_tab[hash];
	mf->hash_tab[hash] = mf->base.cur_window_pos;

out:
	mf->base.cur_window_pos++;
}

static void
lz_hc_skip_positions(struct lz_mf *_mf, u32 n)
{
	struct lz_hc *mf = (struct lz_hc *)_mf;

	do {
		lz_hc_skip_position(mf);
	} while (--n);
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
