/*
 * lzms-compress.c
 *
 * A compressor for the LZMS compression format.
 */

/*
 * Copyright (C) 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

/* This a compressor for the LZMS compression format.  More details about this
 * format can be found in lzms-decompress.c.  */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/assert.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/compress_common.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lzms.h"
#include "wimlib/util.h"

#include <string.h>

struct lzms_compressor {
	u8 *window;
	u32 window_size;
	u32 max_block_size;
	s32 *last_target_usages;
};

static size_t
lzms_compress(const void *uncompressed_data, size_t uncompressed_size,
	      void *compressed_data, size_t compressed_size_avail, void *_ctx)
{
	struct lzms_compressor *ctx = _ctx;

	if (uncompressed_size > ctx->max_block_size) {
		LZMS_DEBUG("Can't compress %su bytes: LZMS context "
			   "only supports %u bytes",
			   uncompressed_size, ctx->max_block_size);
		return 0;
	}

	memcpy(ctx->window, uncompressed_data, uncompressed_size);
	ctx->window_size = uncompressed_size;

	lzms_x86_filter(ctx->window, ctx->window_size,
			ctx->last_target_usages, false);

	return 0;
}

static void
lzms_free_compressor(void *_ctx)
{
	struct lzms_compressor *ctx = _ctx;

	if (ctx) {
		FREE(ctx->window);
		FREE(ctx->last_target_usages);
		FREE(ctx);
	}
}

static int
lzms_create_compressor(size_t max_block_size,
		       const struct wimlib_compressor_params_header *params,
		       void **ctx_ret)
{
	struct lzms_compressor *ctx;

	if (max_block_size == 0 || max_block_size > 1U << 26) {
		LZMS_DEBUG("Invalid max_block_size (%u)", max_block_size);
		return WIMLIB_ERR_INVALID_PARAM;
	}

	ctx = CALLOC(1, sizeof(struct lzms_compressor));
	if (ctx == NULL)
		goto oom;

	ctx->window = MALLOC(max_block_size);
	if (ctx->window == NULL)
		goto oom;
	ctx->max_block_size = max_block_size;

	ctx->last_target_usages = MALLOC(65536 * sizeof(ctx->last_target_usages[0]));
	if (ctx->last_target_usages == NULL)
		goto oom;

	*ctx_ret = ctx;
	return 0;

oom:
	lzms_free_compressor(ctx);
	return WIMLIB_ERR_NOMEM;
}

const struct compressor_ops lzms_compressor_ops = {
	.create_compressor  = lzms_create_compressor,
	.compress	    = lzms_compress,
	.free_compressor    = lzms_free_compressor,
};
