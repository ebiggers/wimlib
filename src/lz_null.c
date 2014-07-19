/*
 * lz_null.c
 *
 * Dummy "match-finder" for Lempel-Ziv compression.
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

static bool
lz_null_params_valid(const struct lz_mf_params *_params)
{
	return true;
}

static u64
lz_null_get_needed_memory(u32 max_window_size)
{
	return 0;
}

static bool
lz_null_init(struct lz_mf *mf)
{
	if (mf->params.min_match_len == 0)
		mf->params.min_match_len = 2;

	if (mf->params.max_match_len == 0)
		mf->params.max_match_len = mf->params.max_window_size;

	return true;
}

static void
lz_null_load_window(struct lz_mf *mf, const u8 window[], u32 size)
{
}

static u32
lz_null_get_matches(struct lz_mf *mf, struct lz_match matches[])
{
	mf->cur_window_pos++;
	return 0;
}

static void
lz_null_skip_positions(struct lz_mf *mf, u32 n)
{
	mf->cur_window_pos += n;
}

static void
lz_null_destroy(struct lz_mf *mf)
{
}

const struct lz_mf_ops lz_null_ops = {
	.params_valid      = lz_null_params_valid,
	.get_needed_memory = lz_null_get_needed_memory,
	.init		   = lz_null_init,
	.load_window       = lz_null_load_window,
	.get_matches       = lz_null_get_matches,
	.skip_positions    = lz_null_skip_positions,
	.destroy           = lz_null_destroy,
	.struct_size	   = sizeof(struct lz_mf),
};
