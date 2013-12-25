/*
 * decompress.c
 *
 * Generic functions for decompression, wrapping around actual decompression
 * implementations.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/decompressor_ops.h"
#include "wimlib/util.h"

struct wimlib_decompressor {
	const struct decompressor_ops *ops;
	void *private;
};

static const struct decompressor_ops *decompressor_ops[] = {
	[WIMLIB_COMPRESSION_TYPE_LZX]    = &lzx_decompressor_ops,
	[WIMLIB_COMPRESSION_TYPE_XPRESS] = &xpress_decompressor_ops,
	[WIMLIB_COMPRESSION_TYPE_LZMS]   = &lzms_decompressor_ops,
};

static struct wimlib_decompressor_params_header *
decompressor_default_params[ARRAY_LEN(decompressor_ops)] = {
};

static bool
decompressor_ctype_valid(int ctype)
{
	return (ctype >= 0 &&
		ctype < ARRAY_LEN(decompressor_ops) &&
		decompressor_ops[ctype] != NULL);
}

WIMLIBAPI int
wimlib_set_default_decompressor_params(enum wimlib_compression_type ctype,
				       const struct wimlib_decompressor_params_header *params)
{
	struct wimlib_decompressor_params_header *dup;

	if (!decompressor_ctype_valid(ctype))
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;

	dup = NULL;
	if (params) {
		dup = memdup(params, params->size);
		if (dup == NULL)
			return WIMLIB_ERR_NOMEM;
	}

	FREE(decompressor_default_params[ctype]);
	decompressor_default_params[ctype] = dup;
	return 0;
}

void
cleanup_decompressor_params(void)
{
	for (size_t i = 0; i < ARRAY_LEN(decompressor_default_params); i++) {
		FREE(decompressor_default_params[i]);
		decompressor_default_params[i] = NULL;
	}
}

WIMLIBAPI int
wimlib_create_decompressor(enum wimlib_compression_type ctype,
			   size_t max_block_size,
			   const struct wimlib_decompressor_params_header *extra_params,
			   struct wimlib_decompressor **dec_ret)
{
	struct wimlib_decompressor *dec;

	if (dec_ret == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	if (!decompressor_ctype_valid(ctype))
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;

	dec = MALLOC(sizeof(*dec));
	if (dec == NULL)
		return WIMLIB_ERR_NOMEM;
	dec->ops = decompressor_ops[ctype];
	dec->private = NULL;
	if (dec->ops->create_decompressor) {
		const struct wimlib_decompressor_params_header *params;
		int ret;

		if (extra_params)
			params = extra_params;
		else
			params = decompressor_default_params[ctype];
		ret = dec->ops->create_decompressor(max_block_size,
						    params,
						    &dec->private);
		if (ret) {
			FREE(dec);
			return ret;
		}
	}
	*dec_ret = dec;
	return 0;
}

WIMLIBAPI int
wimlib_decompress(const void *compressed_data, size_t compressed_size,
		  void *uncompressed_data, size_t uncompressed_size,
		  struct wimlib_decompressor *dec)
{
	return dec->ops->decompress(compressed_data, compressed_size,
				    uncompressed_data, uncompressed_size,
				    dec->private);
}

WIMLIBAPI void
wimlib_free_decompressor(struct wimlib_decompressor *dec)
{
	if (dec) {
		if (dec->ops->free_decompressor)
			dec->ops->free_decompressor(dec->private);
		FREE(dec);
	}
}
