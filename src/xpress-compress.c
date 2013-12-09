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
#include "wimlib/compress.h"
#include "wimlib/error.h"
#include "wimlib/util.h"
#include "wimlib/xpress.h"

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif

#include <string.h>

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
		   const u16 codewords[restrict],
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
				  const u16 codewords[restrict],
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

struct xpress_record_ctx {
	freq_t freqs[XPRESS_NUM_SYMBOLS];
	struct xpress_match *matches;
};

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

/* API function documented in wimlib.h  */
WIMLIBAPI unsigned
wimlib_xpress_compress(const void * restrict uncompressed_data,
		       unsigned uncompressed_len,
		       void * restrict compressed_data)
{
	u8 *cptr = compressed_data;
	struct output_bitstream ostream;

	struct xpress_record_ctx record_ctx;

	struct xpress_match *matches;
	input_idx_t *prev_tab;
	u8 *udata;

	u16 codewords[XPRESS_NUM_SYMBOLS];
	u8 lens[XPRESS_NUM_SYMBOLS];
	input_idx_t num_matches;
	input_idx_t compressed_len;
	input_idx_t i;
	const size_t stack_max = 65536;

	/* XPRESS requires 256 bytes of overhead for the Huffman code, so it's
	 * impossible to compress 256 bytes or less of data to less than the
	 * input size.
	 *
	 * +1 to take into account that the buffer for compressed data is 1 byte
	 * smaller than the buffer for uncompressed data.
	 *
	 * +4 to take into account that init_output_bitstream() requires at
	 * least 4 bytes of data.  */
	if (uncompressed_len < XPRESS_NUM_SYMBOLS / 2 + 1 + 4)
		return 0;

	if (uncompressed_len <= stack_max) {
		matches = alloca(uncompressed_len * sizeof(matches[0]));
		udata = alloca(uncompressed_len + 8);
		prev_tab = alloca(uncompressed_len * sizeof(prev_tab[0]));
	} else {
		matches = MALLOC(uncompressed_len * sizeof(matches[0]));
		udata = MALLOC(uncompressed_len + 8);
		prev_tab = MALLOC(uncompressed_len * sizeof(prev_tab[0]));
		if (matches == NULL || udata == NULL || prev_tab == NULL) {
			WARNING("Failed to allocate memory for compression...");
			compressed_len = 0;
			goto out_free;
		}
	}

	/* Copy the data to a temporary buffer, but only to avoid
	 * inconsequential accesses of uninitialized memory in
	 * lz_analyze_block().  */
	memcpy(udata, uncompressed_data, uncompressed_len);
	memset(udata + uncompressed_len, 0, 8);

	/* Determine match/literal sequence to divide the data into.  */
	ZERO_ARRAY(record_ctx.freqs);
	record_ctx.matches = matches;
	lz_analyze_block(udata,
			 uncompressed_len,
			 xpress_record_match,
			 xpress_record_literal,
			 &record_ctx,
			 &xpress_lz_params,
			 prev_tab);

	num_matches = (record_ctx.matches - matches);

	/* Account for end of data symbol.  */
	record_ctx.freqs[XPRESS_END_OF_DATA]++;

	/* Build the Huffman code.  */
	make_canonical_huffman_code(XPRESS_NUM_SYMBOLS, XPRESS_MAX_CODEWORD_LEN,
				    record_ctx.freqs, lens, codewords);

	/* Output the Huffman code as a series of 512 4-bit lengths.  */
	for (i = 0; i < XPRESS_NUM_SYMBOLS; i += 2)
		*cptr++ = (lens[i] & 0xf) | (lens[i + 1] << 4);

	/* Output the encoded matches/literals.  */
	init_output_bitstream(&ostream, cptr,
			      uncompressed_len - XPRESS_NUM_SYMBOLS / 2 - 1);
	xpress_write_matches_and_literals(&ostream, matches,
					  num_matches, codewords, lens);

	/* Flush any pending data and get the length of the compressed data.  */
	compressed_len = flush_output_bitstream(&ostream);
	if (compressed_len == ~(input_idx_t)0) {
		compressed_len = 0;
		goto out_free;
	}
	compressed_len += XPRESS_NUM_SYMBOLS / 2;

#if defined(ENABLE_XPRESS_DEBUG) || defined(ENABLE_VERIFY_COMPRESSION) || 1
	/* Verify that we really get the same thing back when decompressing.  */
	if (wimlib_xpress_decompress(compressed_data, compressed_len,
				     udata, uncompressed_len))
	{
		ERROR("Failed to decompress data we "
		      "compressed using XPRESS algorithm");
		wimlib_assert(0);
		compressed_len = 0;
		goto out_free;
	}

	if (memcmp(uncompressed_data, udata, uncompressed_len)) {
		ERROR("Data we compressed using XPRESS algorithm "
		      "didn't decompress to original");
		wimlib_assert(0);
		compressed_len = 0;
		goto out_free;
	}
#endif

out_free:
	if (uncompressed_len > stack_max) {
		FREE(matches);
		FREE(udata);
		FREE(prev_tab);
	}
	return compressed_len;
}
