/*
 * lz_brute_force.c
 *
 * Brute force match-finder for Lempel-Ziv compression.
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

static bool
lz_bf_params_valid(const struct lz_mf_params *params)
{
	return true;
}

static u64
lz_bf_get_needed_memory(u32 max_window_size)
{
	return 0;
}

static bool
lz_bf_init(struct lz_mf *mf)
{
	if (mf->params.min_match_len == 0)
		mf->params.min_match_len = 2;

	if (mf->params.max_match_len == 0)
		mf->params.max_match_len = mf->params.max_window_size;

	if (mf->params.max_search_depth == 0)
		mf->params.max_search_depth = 32;

	mf->params.max_search_depth = DIV_ROUND_UP(mf->params.max_search_depth, 8);

	if (mf->params.nice_match_len == 0)
		mf->params.nice_match_len = 24;

	if (mf->params.nice_match_len < mf->params.min_match_len)
		mf->params.nice_match_len = mf->params.min_match_len;

	if (mf->params.nice_match_len > mf->params.max_match_len)
		mf->params.nice_match_len = mf->params.max_match_len;

	return true;
}

static void
lz_bf_load_window(struct lz_mf *mf, const u8 window[], u32 size)
{
}

static u32
lz_bf_get_matches(struct lz_mf *mf, struct lz_match matches[])
{
	const u8 * const strptr = lz_mf_get_window_ptr(mf);
	const u32 max_len = min(lz_mf_get_bytes_remaining(mf),
				mf->params.nice_match_len);
	u32 best_len = mf->params.min_match_len - 1;
	u32 num_matches = 0;
	const u8 *matchptr = strptr;

	if (best_len >= max_len)
		goto out;

	while (matchptr-- > mf->cur_window) {
		if (matchptr[best_len] == strptr[best_len] &&
		    matchptr[best_len - 1] == strptr[best_len - 1] &&
		    matchptr[0] == strptr[0])
		{
			u32 len = 0;

			while (++len != max_len)
				if (matchptr[len] != strptr[len])
					break;

			if (len > best_len) {
				matches[num_matches++] = (struct lz_match) {
					.len = len,
					.offset = strptr - matchptr,
				};
				best_len = len;
				if (best_len == max_len)
					break;
				if (num_matches == mf->params.max_search_depth)
					break;
			}
		}
	}

	/* If the longest match is @nice_match_len in length, it may have been
	 * truncated.  Try extending it up to the maximum match length.  */
	if (num_matches != 0 &&
	    matches[num_matches - 1].len == mf->params.nice_match_len)
	{
		const u8 * const matchptr = strptr - matches[num_matches - 1].offset;
		const u32 len_limit = min(lz_mf_get_bytes_remaining(mf),
					  mf->params.max_match_len);
		u32 len;

		len = matches[num_matches - 1].len;
		while (len < len_limit && strptr[len] == matchptr[len])
			len++;
		matches[num_matches - 1].len = len;
	}

out:
	mf->cur_window_pos++;
	return num_matches;
}

static void
lz_bf_skip_positions(struct lz_mf *mf, u32 n)
{
	mf->cur_window_pos += n;
}

static void
lz_bf_destroy(struct lz_mf *mf)
{
}

const struct lz_mf_ops lz_brute_force_ops = {
	.params_valid      = lz_bf_params_valid,
	.get_needed_memory = lz_bf_get_needed_memory,
	.init		   = lz_bf_init,
	.load_window       = lz_bf_load_window,
	.get_matches       = lz_bf_get_matches,
	.skip_positions    = lz_bf_skip_positions,
	.destroy           = lz_bf_destroy,
	.struct_size	   = sizeof(struct lz_mf),
};
