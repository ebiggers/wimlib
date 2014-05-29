/*
 * xpress-compress.c
 *
 * XPRESS compression routines.
 *
 * See the comments in xpress-decompress.c about the XPRESS format.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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
#include "wimlib/assert.h"
#include "wimlib/compressor_ops.h"
#include "wimlib/compress_common.h"
#include "wimlib/error.h"
#include "wimlib/lz_hash.h"
#include "wimlib/util.h"
#include "wimlib/xpress.h"

#include <string.h>

struct xpress_record_ctx {
	input_idx_t freqs[XPRESS_NUM_SYMBOLS];
	struct xpress_match *matches;
};

struct xpress_compressor {
	u8 *window;
	u32 max_window_size;
	struct xpress_match *matches;
	input_idx_t *prev_tab;
	u32 codewords[XPRESS_NUM_SYMBOLS];
	u8 lens[XPRESS_NUM_SYMBOLS];
	struct xpress_record_ctx record_ctx;
};

/* Intermediate XPRESS match/literal representation.  */
struct xpress_match {
	u16 adjusted_len;  /* Match length minus XPRESS_MIN_MATCH_LEN */
	u16 offset;        /* Match offset */
	/* For literals, offset == 0 and adjusted_len is the literal.  */
};

/*
 * Writes @match, which is a match given in the intermediate representation for
 * XPRESS matches, to the output stream @ostream.
 *
 * @codewords and @lens provide the Huffman code that is being used.
 */
static void
xpress_write_match(struct xpress_match match,
		   struct output_bitstream *restrict ostream,
		   const u32 codewords[restrict],
		   const u8 lens[restrict])
{
	u8 len_hdr = min(match.adjusted_len, 0xf);
	u8 offset_bsr = bsr32(match.offset);
	unsigned sym = XPRESS_NUM_CHARS + ((offset_bsr << 4) | len_hdr);

	bitstream_put_bits(ostream, codewords[sym], lens[sym]);

	if (match.adjusted_len >= 0xf) {
		u8 byte1 = min(match.adjusted_len - 0xf, 0xff);
		bitstream_put_byte(ostream, byte1);
		if (byte1 == 0xff) {
			bitstream_put_byte(ostream, match.adjusted_len & 0xff);
			bitstream_put_byte(ostream, match.adjusted_len >> 8);
		}
	}
	bitstream_put_bits(ostream, match.offset ^ (1U << offset_bsr), offset_bsr);
}

static void
xpress_write_matches_and_literals(struct output_bitstream *ostream,
				  const struct xpress_match matches[restrict],
				  input_idx_t num_matches,
				  const u32 codewords[restrict],
				  const u8 lens[restrict])
{
	for (input_idx_t i = 0; i < num_matches; i++) {
		if (matches[i].offset) {
			/* Real match  */
			xpress_write_match(matches[i], ostream, codewords, lens);
		} else {
			/* Literal byte  */
			u8 lit = matches[i].adjusted_len;
			bitstream_put_bits(ostream, codewords[lit], lens[lit]);
		}
	}
	bitstream_put_bits(ostream, codewords[XPRESS_END_OF_DATA], lens[XPRESS_END_OF_DATA]);
}

static void
xpress_record_literal(u8 lit, void *_ctx)
{
	struct xpress_record_ctx *ctx = _ctx;
	ctx->freqs[lit]++;
	*(ctx->matches++) = (struct xpress_match) { .offset = 0, .adjusted_len = lit };
}

static void
xpress_record_match(unsigned len, unsigned offset, void *_ctx)
{
	struct xpress_record_ctx *ctx = _ctx;

	XPRESS_ASSERT(len >= XPRESS_MIN_MATCH_LEN);
	XPRESS_ASSERT(len <= XPRESS_MAX_MATCH_LEN);
	XPRESS_ASSERT(offset >= XPRESS_MIN_OFFSET);
	XPRESS_ASSERT(offset <= XPRESS_MAX_OFFSET);

	unsigned adjusted_len = len - XPRESS_MIN_MATCH_LEN;
	unsigned len_hdr = min(adjusted_len, 0xf);
	unsigned sym = XPRESS_NUM_CHARS + ((bsr32(offset) << 4) | len_hdr);

	XPRESS_ASSERT(sym >= XPRESS_NUM_CHARS);
	XPRESS_ASSERT(sym < XPRESS_NUM_SYMBOLS);

	ctx->freqs[sym]++;
	*(ctx->matches++) = (struct xpress_match) { .offset = offset,
						    .adjusted_len = adjusted_len };
}

static const struct lz_params xpress_lz_params = {
	.min_match      = XPRESS_MIN_MATCH_LEN,
	.max_match      = XPRESS_MAX_MATCH_LEN,
	.max_offset	= XPRESS_MAX_OFFSET,
	.good_match	= 16,
	.nice_match     = 32,
	.max_chain_len  = 16,
	.max_lazy_match = 16,
	.too_far        = 4096,
};

static size_t
xpress_compress(const void *uncompressed_data, size_t uncompressed_size,
		void *compressed_data, size_t compressed_size_avail, void *_c)
{
	struct xpress_compressor *c = _c;
	u8 *cptr = compressed_data;
	struct output_bitstream ostream;
	input_idx_t num_matches;
	input_idx_t i;
	size_t compressed_size;

	/* XPRESS requires 256 bytes of overhead for the Huffman code, so it's
	 * impossible to compress 256 bytes or less of data to less than the
	 * input size.
	 *
	 * +1 to take into account that the buffer for compressed data is 1 byte
	 * smaller than the buffer for uncompressed data.
	 *
	 * +4 to take into account that init_output_bitstream() requires at
	 * least 4 bytes of data.  */
	if (compressed_size_avail < XPRESS_NUM_SYMBOLS / 2 + 1 + 4)
		return 0;

	/* Copy the data to a temporary buffer, but only to avoid
	 * inconsequential accesses of uninitialized memory in
	 * lz_analyze_block().  */
	memcpy(c->window, uncompressed_data, uncompressed_size);
	memset(c->window + uncompressed_size, 0, 8);

	/* Determine match/literal sequence to divide the data into.  */
	memset(c->record_ctx.freqs, 0, sizeof(c->record_ctx.freqs));
	c->record_ctx.matches = c->matches;
	lz_analyze_block(c->window,
			 uncompressed_size,
			 xpress_record_match,
			 xpress_record_literal,
			 &c->record_ctx,
			 &xpress_lz_params,
			 c->prev_tab);

	num_matches = (c->record_ctx.matches - c->matches);

	/* Account for end of data symbol.  */
	c->record_ctx.freqs[XPRESS_END_OF_DATA]++;

	/* Build the Huffman code.  */
	make_canonical_huffman_code(XPRESS_NUM_SYMBOLS, XPRESS_MAX_CODEWORD_LEN,
				    c->record_ctx.freqs, c->lens, c->codewords);

	/* Output the Huffman code as a series of 512 4-bit lengths.  */
	for (i = 0; i < XPRESS_NUM_SYMBOLS; i += 2)
		*cptr++ = (c->lens[i] & 0xf) | (c->lens[i + 1] << 4);

	/* Output the encoded matches/literals.  */
	init_output_bitstream(&ostream, cptr,
			      compressed_size_avail - XPRESS_NUM_SYMBOLS / 2 - 1);

	xpress_write_matches_and_literals(&ostream, c->matches,
					  num_matches, c->codewords, c->lens);

	/* Flush any pending data and get the length of the compressed data.  */
	compressed_size = flush_output_bitstream(&ostream);
	if (compressed_size == ~(input_idx_t)0)
		return 0;

	compressed_size += XPRESS_NUM_SYMBOLS / 2;

#if defined(ENABLE_XPRESS_DEBUG) || defined(ENABLE_VERIFY_COMPRESSION)
	/* Verify that we really get the same thing back when decompressing.  */
	{
		struct wimlib_decompressor *decompressor;

		if (0 == wimlib_create_decompressor(WIMLIB_COMPRESSION_TYPE_XPRESS,
						    c->max_window_size,
						    NULL,
						    &decompressor))
		{
			int ret;
			ret = wimlib_decompress(compressed_data,
						compressed_size,
						c->window,
						uncompressed_size,
						decompressor);
			wimlib_free_decompressor(decompressor);

			if (ret) {
				ERROR("Failed to decompress data we "
				      "compressed using XPRESS algorithm");
				wimlib_assert(0);
				return 0;
			}
			if (memcmp(uncompressed_data, c->window,
				   uncompressed_size))
			{
				ERROR("Data we compressed using XPRESS algorithm "
				      "didn't decompress to original");
				wimlib_assert(0);
				return 0;
			}
		} else {
			WARNING("Failed to create decompressor for "
				"data verification!");
		}
	}
#endif

	return compressed_size;
}

static void
xpress_free_compressor(void *_c)
{
	struct xpress_compressor *c = _c;

	if (c) {
		FREE(c->window);
		FREE(c->matches);
		FREE(c->prev_tab);
		FREE(c);
	}
}

static int
xpress_create_compressor(size_t max_window_size,
			 const struct wimlib_compressor_params_header *params,
			 void **c_ret)
{
	struct xpress_compressor *c;

	if (max_window_size == 0 || max_window_size > (1U << 26))
		return WIMLIB_ERR_INVALID_PARAM;

	c = CALLOC(1, sizeof(struct xpress_compressor));
	if (c == NULL)
		goto oom;

	c->window = MALLOC(max_window_size + 8);
	if (c->window == NULL)
		goto oom;

	c->max_window_size = max_window_size;

	c->matches = MALLOC(max_window_size * sizeof(c->matches[0]));
	if (c->matches == NULL)
		goto oom;

	c->prev_tab = MALLOC(max_window_size * sizeof(c->prev_tab[0]));
	if (c->prev_tab == NULL)
		goto oom;

	*c_ret = c;
	return 0;

oom:
	xpress_free_compressor(c);
	return WIMLIB_ERR_NOMEM;
}

static u64
xpress_get_needed_memory(size_t max_window_size,
			 const struct wimlib_compressor_params_header *params)
{
	u64 size = 0;

	size += sizeof(struct xpress_compressor);
	size += max_window_size + 8;
	size += max_window_size * sizeof(((struct xpress_compressor*)0)->matches[0]);
	size += max_window_size * sizeof(((struct xpress_compressor*)0)->prev_tab[0]);

	return size;
}

const struct compressor_ops xpress_compressor_ops = {
	.get_needed_memory  = xpress_get_needed_memory,
	.create_compressor  = xpress_create_compressor,
	.compress	    = xpress_compress,
	.free_compressor    = xpress_free_compressor,
};
