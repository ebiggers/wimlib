/*
 * compress.c
 *
 * Generic functions for compression, wrapping around actual compression
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
#include "wimlib/compressor_ops.h"
#include "wimlib/util.h"

struct wimlib_compressor {
	const struct compressor_ops *ops;
	void *private;
};

static const struct compressor_ops *compressor_ops[] = {
	[WIMLIB_COMPRESSION_TYPE_LZX]    = &lzx_compressor_ops,
	[WIMLIB_COMPRESSION_TYPE_XPRESS] = &xpress_compressor_ops,
	[WIMLIB_COMPRESSION_TYPE_LZMS]   = &lzms_compressor_ops,
};

static struct wimlib_compressor_params_header *
compressor_default_params[ARRAY_LEN(compressor_ops)] = {
};

static bool
compressor_ctype_valid(int ctype)
{
	return (ctype >= 0 &&
		ctype < ARRAY_LEN(compressor_ops) &&
		compressor_ops[ctype] != NULL);
}

WIMLIBAPI int
wimlib_set_default_compressor_params(enum wimlib_compression_type ctype,
				     const struct wimlib_compressor_params_header *params)
{
	struct wimlib_compressor_params_header *dup;

	if (!compressor_ctype_valid(ctype))
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;

	if (params != NULL &&
	    compressor_ops[ctype]->params_valid != NULL &&
	    !compressor_ops[ctype]->params_valid(params))
		return WIMLIB_ERR_INVALID_PARAM;

	dup = NULL;
	if (params) {
		dup = memdup(params, params->size);
		if (dup == NULL)
			return WIMLIB_ERR_NOMEM;
	}

	FREE(compressor_default_params[ctype]);
	compressor_default_params[ctype] = dup;
	return 0;
}

void
cleanup_compressor_params(void)
{
	for (size_t i = 0; i < ARRAY_LEN(compressor_default_params); i++) {
		FREE(compressor_default_params[i]);
		compressor_default_params[i] = NULL;
	}
}

WIMLIBAPI u64
wimlib_get_compressor_needed_memory(enum wimlib_compression_type ctype,
				    size_t max_block_size,
				    const struct wimlib_compressor_params_header *extra_params)
{
	const struct compressor_ops *ops;
	const struct wimlib_compressor_params_header *params;

	if (!compressor_ctype_valid(ctype))
		return 0;

	ops = compressor_ops[ctype];
	if (ops->get_needed_memory == NULL)
		return 0;

	if (extra_params) {
		params = extra_params;
		if (ops->params_valid && !ops->params_valid(params))
			return 0;
	} else {
		params = compressor_default_params[ctype];
	}

	return sizeof(struct wimlib_compressor) +
		ops->get_needed_memory(max_block_size, params);
}


WIMLIBAPI int
wimlib_create_compressor(enum wimlib_compression_type ctype,
			 size_t max_block_size,
			 const struct wimlib_compressor_params_header *extra_params,
			 struct wimlib_compressor **c_ret)
{
	struct wimlib_compressor *c;

	if (c_ret == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	if (!compressor_ctype_valid(ctype))
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;

	c = MALLOC(sizeof(*c));
	if (c == NULL)
		return WIMLIB_ERR_NOMEM;
	c->ops = compressor_ops[ctype];
	c->private = NULL;
	if (c->ops->create_compressor) {
		const struct wimlib_compressor_params_header *params;
		int ret;

		if (extra_params) {
			params = extra_params;
			if (c->ops->params_valid && !c->ops->params_valid(params)) {
				FREE(c);
				return WIMLIB_ERR_INVALID_PARAM;
			}
		} else {
			params = compressor_default_params[ctype];
		}
		ret = c->ops->create_compressor(max_block_size,
						params, &c->private);
		if (ret) {
			FREE(c);
			return ret;
		}
	}
	*c_ret = c;
	return 0;
}

WIMLIBAPI size_t
wimlib_compress(const void *uncompressed_data, size_t uncompressed_size,
		void *compressed_data, size_t compressed_size_avail,
		struct wimlib_compressor *c)
{
	return c->ops->compress(uncompressed_data, uncompressed_size,
				compressed_data, compressed_size_avail,
				c->private);
}

WIMLIBAPI void
wimlib_free_compressor(struct wimlib_compressor *c)
{
	if (c) {
		if (c->ops->free_compressor)
			c->ops->free_compressor(c->private);
		FREE(c);
	}
}
