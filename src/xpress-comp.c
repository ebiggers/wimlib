/*
 * xpress-comp.c
 *
 * XPRESS compression routines.
 *
 * See the comments in xpress-decomp.c about the XPRESS format.
 */

/*
 * Copyright (C) 2012 Eric Biggers
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
#include "comp.h"
#include <stdlib.h>
#include <string.h>

static inline u32 bsr32(u32 n)
{
#if defined(__x86__) || defined(__x86_64__)
	asm("bsrl %0, %0;"
			: "=r"(n)
			: "0" (n));
	return n;
#else
	u32 pow = 0;
	while ((n >>= 1) != 0)
		pow++;
	return pow;
#endif
}


/*
 * Writes @match, which is a match given in the intermediate representation for
 * XPRESS matches, to the output stream @ostream.
 *
 * @codewords and @lens provide the Huffman code that is being used.
 */
static int xpress_write_match(struct output_bitstream *ostream, u32 match,
			      const u16 codewords[], const u8 lens[])
{
	uint main_sym;
	uint huff_sym;
	uint offset_bsr;
	uint match_len;
	uint match_offset;
	int ret;
	u8 byte1;

	main_sym = (match & 0xff);
	huff_sym = main_sym + XPRESS_NUM_CHARS;
	ret = bitstream_put_bits(ostream, codewords[huff_sym], lens[huff_sym]);
	if (ret != 0)
		return ret;

	offset_bsr = main_sym >> 4;

	match_len = (match >> 8) & 0xff;
	match_offset = (match >> 16);


	match_len -= XPRESS_MIN_MATCH;
	if (match_len >= 0xf) {
		byte1 = (u8)(match_len - 0xf);
		ret = bitstream_put_byte(ostream, byte1);
		if (ret != 0)
			return ret;
		if (byte1 == 0xff) {
			ret = bitstream_put_two_bytes(ostream, match_len);
			if (ret != 0)
				return ret;
		}
	}
	return bitstream_put_bits(ostream, match_offset ^ (1 << offset_bsr),
							offset_bsr);
}

static int xpress_write_compressed_literals(struct output_bitstream *ostream,
					    const u32 match_tab[],
					    uint num_matches,
					    const u16 codewords[],
					    const u8 lens[])
{
	uint i;
	u32 match;
	int ret;

	for (i = 0; i < num_matches; i++) {
		match = match_tab[i];
		if (match >= XPRESS_NUM_CHARS) /* match */
			ret = xpress_write_match(ostream, match, codewords,
						 lens);
		else /* literal byte */
			ret = bitstream_put_bits(ostream, codewords[match],
						 lens[match]);
		if (ret != 0)
			return ret;
	}
	return bitstream_put_bits(ostream, codewords[256], lens[256]);
}

static u32 xpress_record_literal(u8 literal, void *__freq_tab)
{
	u32 *freq_tab = __freq_tab;
	freq_tab[literal]++;
	return literal;
}

static u32 xpress_record_match(uint match_offset, uint match_len,
			       void *__freq_tab, void *ignore)
{
	u32 *freq_tab = __freq_tab;
	u32 len_hdr;
	u32 offset_bsr;
	u32 match;

	wimlib_assert(match_len >= XPRESS_MIN_MATCH &&
		      match_len <= XPRESS_MAX_MATCH);
	wimlib_assert(match_offset > 0);

	len_hdr = min(match_len - XPRESS_MIN_MATCH, 15);
	offset_bsr = bsr32(match_offset);
	match = (offset_bsr << 4) | len_hdr;
	freq_tab[match + XPRESS_NUM_CHARS]++;
	match |= match_len << 8;
	match |= match_offset << 16;
	return match;
}

static const struct lz_params xpress_lz_params = {
	.min_match      = 3,
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
 * @__uncompressed_data:  Pointer to the data to be compressed.
 * @uncompressed_len:	Length, in bytes, of the data to be compressed.
 * @__compressed_data:	Pointer to a location at least (@uncompressed_len - 1)
 * 				bytes long into which the compressed data may be
 * 				written.
 * @compressed_len_ret:	A pointer to an unsigned int into which the length of
 * 				the compressed data may be returned.
 *
 * Returns zero if compression was successfully performed.  In that case
 * @compressed_data and @compressed_len_ret will contain the compressed data and
 * its length.  A return value of nonzero means that compressing the data did
 * not reduce its size, and @compressed_data will not contain the full
 * compressed data.
 */
int xpress_compress(const void *__uncompressed_data, uint uncompressed_len,
		    void *__compressed_data, uint *compressed_len_ret)
{
	const u8 *uncompressed_data = __uncompressed_data;
	u8 *compressed_data = __compressed_data;
	struct output_bitstream ostream;
	u32 match_tab[uncompressed_len];
	u32 freq_tab[XPRESS_NUM_SYMBOLS];
	u16 codewords[XPRESS_NUM_SYMBOLS];
	u8  lens[XPRESS_NUM_SYMBOLS];
	uint num_matches;
	uint compressed_len;
	uint i;
	int ret;

	XPRESS_DEBUG("uncompressed_len = %u", uncompressed_len);

	if (uncompressed_len < 300)
		return 1;

	ZERO_ARRAY(freq_tab);

	num_matches = lz_analyze_block(uncompressed_data, uncompressed_len,
				       match_tab, xpress_record_match,
				       xpress_record_literal, freq_tab,
				       NULL, freq_tab,
				       &xpress_lz_params);

	XPRESS_DEBUG("using %u matches", num_matches);

	freq_tab[256]++;

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
	if (ret != 0)
		return ret;

	/* Flush any bits that are buffered. */
	ret = flush_output_bitstream(&ostream);
	if (ret != 0)
		return ret;

	/* Assert that there are no output bytes between the ostream.output
	 * pointer and the ostream.next_bit_output pointer.  This can only
	 * happen if bytes had been written at the ostream.output pointer before
	 * the last bit word was written to the stream.  But, this does not
	 * occur since xpress_write_match() always finishes by writing some bits
	 * (a Huffman symbol), and the bitstream was just flushed. */
	wimlib_assert(ostream.output - ostream.next_bit_output == 2);

	/*
	 * The length of the compressed data is supposed to be the value of the
	 * ostream.output pointer before flushing, which is now the
	 * output.next_bit_output pointer after flushing.
	 *
	 * There will be an extra 2 bytes at the ostream.bit_output pointer,
	 * which is zeroed out.  (These 2 bytes may be either the last bytes in
	 * the compressed data, in which case they are actually unnecessary, or
	 * they may precede a number of bytes embedded into the bitstream.)
	 */
	if (ostream.bit_output >
	    (const u8*)__compressed_data + uncompressed_len - 3)
		return 1;
	*(u16*)ostream.bit_output = cpu_to_le16(0);
	compressed_len = ostream.next_bit_output - (const u8*)__compressed_data;

	wimlib_assert(compressed_len <= uncompressed_len - 1);

	XPRESS_DEBUG("Compressed %u => %u bytes",
		     uncompressed_len, compressed_len);

	*compressed_len_ret = compressed_len;

#ifdef ENABLE_VERIFY_COMPRESSION
	/* Verify that we really get the same thing back when decompressing. */
	XPRESS_DEBUG("Verifying the compressed data.");
	u8 buf[uncompressed_len];
	ret = xpress_decompress(__compressed_data, compressed_len, buf,
				uncompressed_len);
	if (ret != 0) {
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
	XPRESS_DEBUG("Compression verified to be correct.");
#endif

	return 0;

}
