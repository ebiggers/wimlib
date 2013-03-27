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

#include "xpress.h"
#include "compress.h"
#include <stdlib.h>
#include <string.h>

/*
 * Writes @match, which is a match given in the intermediate representation for
 * XPRESS matches, to the output stream @ostream.
 *
 * @codewords and @lens provide the Huffman code that is being used.
 */
static int
xpress_write_match(struct output_bitstream *ostream, u32 match,
		   const u16 codewords[], const u8 lens[])
{
	u32 adjusted_match_len = match & 0xffff;
	u32 match_offset = match >> 16;
	u32 len_hdr = min(adjusted_match_len, 0xf);
	u32 offset_bsr = bsr32(match_offset);
	u32 sym = len_hdr | (offset_bsr << 4) | XPRESS_NUM_CHARS;
	int ret;

	ret = bitstream_put_bits(ostream, codewords[sym], lens[sym]);
	if (ret != 0)
		return ret;

	if (adjusted_match_len >= 0xf) {
		u8 byte1 = min(adjusted_match_len - 0xf, 0xff);
		ret = bitstream_put_byte(ostream, byte1);
		if (ret != 0)
			return ret;
		if (byte1 == 0xff) {
			ret = bitstream_put_two_bytes(ostream, adjusted_match_len);
			if (ret != 0)
				return ret;
		}
	}
	return bitstream_put_bits(ostream,
				  match_offset ^ (1 << offset_bsr), offset_bsr);
}

static int
xpress_write_compressed_literals(struct output_bitstream *ostream,
				 const u32 match_tab[],
				 unsigned num_matches,
				 const u16 codewords[],
				 const u8 lens[])
{
	for (unsigned i = 0; i < num_matches; i++) {
		int ret;
		u32 match = match_tab[i];

		if (match >= XPRESS_NUM_CHARS) /* match */
			ret = xpress_write_match(ostream, match, codewords,
						 lens);
		else /* literal byte */
			ret = bitstream_put_bits(ostream, codewords[match],
						 lens[match]);
		if (ret != 0)
			return ret;
	}
	return bitstream_put_bits(ostream, codewords[XPRESS_END_OF_DATA],
				  lens[XPRESS_END_OF_DATA]);
}

static u32
xpress_record_literal(u8 literal, void *__freq_tab)
{
	freq_t *freq_tab = __freq_tab;
	freq_tab[literal]++;
	return literal;
}

static u32
xpress_record_match(unsigned match_offset, unsigned match_len,
		    void *freq_tab, void *ignore)
{
	wimlib_assert(match_len >= XPRESS_MIN_MATCH &&
		      match_len <= XPRESS_MAX_MATCH);
	wimlib_assert(match_offset >= XPRESS_MIN_OFFSET &&
		      match_offset <= XPRESS_MAX_OFFSET);

	/*
	 * The intermediate representation of XPRESS matches is as follows:
	 *
	 * bits    description
	 * ----    -----------------------------------------------------------
	 *
	 * 16-31   match offset (XPRESS_MIN_OFFSET < x < XPRESS_MAX_OFFSET)
	 *
	 * 0-15    adjusted match length (0 <= x <= XPRESS_MAX_MATCH - XPRESS_MIN_MATCH)
	 *
	 * Literals are simply represented as themselves and can be
	 * distinguished from matches by the fact that only literals will have
	 * the upper three bytes completely clear. */

	u32 adjusted_match_len = match_len - XPRESS_MIN_MATCH;
	u32 len_hdr = min(adjusted_match_len, 0xf);
	u32 offset_bsr = bsr32(match_offset);
	u32 sym = len_hdr | (offset_bsr << 4) | XPRESS_NUM_CHARS;
	((freq_t*)freq_tab)[sym]++;
	return adjusted_match_len | (match_offset << 16);
}

static const struct lz_params xpress_lz_params = {
	.min_match      = XPRESS_MIN_MATCH,
	.max_match      = XPRESS_MAX_MATCH,
	.good_match	= 16,
	.nice_match     = 32,
	.max_chain_len  = 16,
	.max_lazy_match = 16,
	.too_far        = 4096,
};

/*
 * Performs XPRESS compression on a block of data.
 *
 * Please see the documentation for the 'compress_func_t' type in write.c for
 * the exact behavior of this function and how to call it.
 */
#ifdef EXPORT_COMPRESSION_FUNCTIONS
WIMLIBAPI
#endif
unsigned
xpress_compress(const void *__uncompressed_data, unsigned uncompressed_len,
		void *__compressed_data)
{
	const u8 *uncompressed_data = __uncompressed_data;
	u8 *compressed_data = __compressed_data;
	struct output_bitstream ostream;
	u32 match_tab[uncompressed_len];
	freq_t freq_tab[XPRESS_NUM_SYMBOLS];
	u16 codewords[XPRESS_NUM_SYMBOLS];
	u8 lens[XPRESS_NUM_SYMBOLS];
	unsigned num_matches;
	unsigned compressed_len;
	unsigned i;
	int ret;

	wimlib_assert(uncompressed_len <= 32768);

	/* XPRESS requires 256 bytes of overhead for the Huffman tables, so it's
	 * impossible cannot compress 256 bytes or less of data to less than the
	 * input size.
	 *
	 * +1 to take into account that the buffer for compressed data is 1 byte
	 * smaller than the buffer for uncompressed data.
	 *
	 * +4 to take into account that init_output_bitstream() requires at
	 * least 4 bytes of data. */
	if (uncompressed_len < XPRESS_NUM_SYMBOLS / 2 + 1 + 4)
		return 0;

	ZERO_ARRAY(freq_tab);
	num_matches = lz_analyze_block(uncompressed_data, uncompressed_len,
				       match_tab, xpress_record_match,
				       xpress_record_literal, freq_tab,
				       NULL, freq_tab,
				       &xpress_lz_params);

	freq_tab[XPRESS_END_OF_DATA]++;

	make_canonical_huffman_code(XPRESS_NUM_SYMBOLS, XPRESS_MAX_CODEWORD_LEN,
				    freq_tab, lens, codewords);

	/* IMPORTANT NOTE:
	 *
	 * It's tempting to output the 512 Huffman codeword lengths using the
	 * bitstream_put_bits() function.  However, this is NOT correct because
	 * bitstream_put_bits() will output 2 bytes at a time in little-endian
	 * order, which is the order that is needed for the compressed literals.
	 * However, the bytes in the lengths table are in order, so they need to
	 * be written one at a time without using bitstream_put_bits().
	 *
	 * Because of this, init_output_bitstream() is not called until after
	 * the lengths table is output.
	 */
	for (i = 0; i < XPRESS_NUM_SYMBOLS; i += 2)
		*compressed_data++ = (lens[i] & 0xf) | (lens[i + 1] << 4);

	init_output_bitstream(&ostream, compressed_data,
			      uncompressed_len - XPRESS_NUM_SYMBOLS / 2 - 1);

	ret = xpress_write_compressed_literals(&ostream, match_tab,
					       num_matches, codewords, lens);
	if (ret)
		return 0;

	/* Flush any bits that are buffered. */
	ret = flush_output_bitstream(&ostream);
	if (ret)
		return 0;

	/* Assert that there are no output bytes between the ostream.output
	 * pointer and the ostream.next_bit_output pointer.  This can only
	 * happen if bytes had been written at the ostream.output pointer before
	 * the last bit word was written to the stream.  But, this does not
	 * occur since xpress_write_match() always finishes by writing some bits
	 * (a Huffman symbol), and the bitstream was just flushed. */
	wimlib_assert(ostream.output - ostream.next_bit_output == 2);

	/* The length of the compressed data is supposed to be the value of the
	 * ostream.output pointer before flushing, which is now the
	 * output.next_bit_output pointer after flushing.
	 *
	 * There will be an extra 2 bytes at the ostream.bit_output pointer,
	 * which is zeroed out.  (These 2 bytes may be either the last bytes in
	 * the compressed data, in which case they are actually unnecessary, or
	 * they may precede a number of bytes embedded into the bitstream.) */
	if (ostream.bit_output >
	    (const u8*)__compressed_data + uncompressed_len - 3)
		return 0;
	*(u16*)ostream.bit_output = cpu_to_le16(0);
	compressed_len = ostream.next_bit_output - (const u8*)__compressed_data;

	wimlib_assert(compressed_len <= uncompressed_len - 1);

#ifdef ENABLE_VERIFY_COMPRESSION
	/* Verify that we really get the same thing back when decompressing. */
	u8 buf[uncompressed_len];
	ret = xpress_decompress(__compressed_data, compressed_len, buf,
				uncompressed_len);
	if (ret) {
		ERROR("xpress_compress(): Failed to decompress data we "
		      "compressed");
		abort();
	}
	for (i = 0; i < uncompressed_len; i++) {
		if (buf[i] != uncompressed_data[i]) {
			ERROR("xpress_compress(): Data we compressed didn't "
			      "decompress to the original data (difference at "
			      "byte %u of %u)", i + 1, uncompressed_len);
			abort();
		}
	}
#endif
	return compressed_len;
}
