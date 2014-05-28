/*
 * xpress-decompress.c
 *
 * XPRESS decompression routines.
 */

/*
 *
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


/*
 * The XPRESS compression format is an LZ77 and Huffman-code based algorithm.
 * That means it is fairly similar to LZX compression, but XPRESS is simpler, so
 * it is a little faster to compress and decompress.
 *
 * The XPRESS compression format is mostly documented in a file called "[MS-XCA]
 * Xpress Compression Algorithm".  In the MSDN library, it can currently be
 * found under Open Specifications => Protocols => Windows Protocols => Windows
 * Server Protocols => [MS-XCA] Xpress Compression Algorithm".  The format in
 * WIMs is specifically the algorithm labeled as the "LZ77+Huffman Algorithm"
 * (there apparently are some other versions of XPRESS as well).
 *
 * If you are already familiar with the LZ77 algorithm and Huffman coding, the
 * XPRESS format is fairly simple.  The compressed data begins with 256 bytes
 * that contain 512 4-bit integers that are the lengths of the symbols in the
 * Huffman code used for match/literal headers.  In contrast with more
 * complicated formats such as DEFLATE and LZX, this is the only Huffman code
 * that is used for the entirety of the XPRESS compressed data, and the codeword
 * lengths are not encoded with a pretree.
 *
 * The rest of the compressed data is Huffman-encoded symbols.  Values 0 through
 * 255 represent the corresponding literal bytes.  Values 256 through 511
 * represent matches and may require extra bits or bytes to be read to get the
 * match offset and match length.
 *
 * The trickiest part is probably the way in which literal bytes for match
 * lengths are interleaved in the bitstream.
 *
 * Also, a caveat--- according to Microsoft's documentation for XPRESS,
 *
 *	"Some implementation of the decompression algorithm expect an extra
 *	symbol to mark the end of the data.  Specifically, some implementations
 *	fail during decompression if the Huffman symbol 256 is not found after
 *	the actual data."
 *
 * This is the case for the implementation in WIMGAPI.  However, wimlib's
 * decompressor in this file currently does not care if this extra symbol is
 * there or not.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/decompressor_ops.h"
#include "wimlib/decompress_common.h"
#include "wimlib/xpress.h"

/*
 * Decodes a symbol @sym that begins an XPRESS match.
 *
 * The low 8 bits of the symbol are divided into:
 *
 * bits 0-3:  length header
 * bits 4-7:  index of high-order bit of match offset
 *
 * Returns the match length, or -1 if the data is invalid.
 */
static int
xpress_decode_match(unsigned sym, input_idx_t window_pos,
		    input_idx_t window_len, u8 window[restrict],
		    struct input_bitstream * restrict istream)
{

	u8 len_hdr;
	u8 offset_bsr;
	u8 *match_dest;
	u8 *match_src;
	unsigned i;
	unsigned match_len;
	unsigned match_offset;

	sym -= XPRESS_NUM_CHARS;
	len_hdr = sym & 0xf;
	offset_bsr = sym >> 4;

	bitstream_ensure_bits(istream, 16);

	match_offset = (1U << offset_bsr) | bitstream_pop_bits(istream, offset_bsr);

	if (len_hdr == 0xf) {
		match_len = bitstream_read_byte(istream);
		if (unlikely(match_len == 0xff)) {
			match_len = bitstream_read_byte(istream);
			match_len |= (unsigned)bitstream_read_byte(istream) << 8;
		} else {
			match_len += 0xf;
		}
	} else {
		match_len = len_hdr;
	}
	match_len += XPRESS_MIN_MATCH_LEN;


	/* Verify the match is in bounds, then copy its data to the current
	 * position.  */

	if (window_pos + match_len > window_len)
		return -1;

	if (match_offset > window_pos)
		return -1;

	match_dest = window + window_pos;
	match_src = match_dest - match_offset;

	for (i = 0; i < match_len; i++)
		match_dest[i] = match_src[i];

	return match_len;
}

/* Decodes the Huffman-encoded matches and literal bytes in a region of
 * XPRESS-encoded data.  */
static int
xpress_lz_decode(struct input_bitstream * restrict istream,
		 u8 uncompressed_data[restrict],
		 unsigned uncompressed_len,
		 const u8 lens[restrict],
		 const u16 decode_table[restrict])
{
	input_idx_t curpos;
	unsigned match_len;

	for (curpos = 0; curpos < uncompressed_len; curpos += match_len) {
		unsigned sym;
		int ret;

		bitstream_ensure_bits(istream, 16);

		sym = read_huffsym(istream, decode_table,
				   XPRESS_TABLEBITS, XPRESS_MAX_CODEWORD_LEN);
		if (sym < XPRESS_NUM_CHARS) {
			/* Literal  */
			uncompressed_data[curpos] = sym;
			match_len = 1;
		} else {
			/* Match  */
			ret = xpress_decode_match(sym,
						  curpos,
						  uncompressed_len,
						  uncompressed_data,
						  istream);
			if (unlikely(ret < 0))
				return -1;
			match_len = ret;
		}
	}
	return 0;
}


static int
xpress_decompress(const void *compressed_data, size_t compressed_size,
		  void *uncompressed_data, size_t uncompressed_size, void *_ctx)
{
	const u8 *cdata = compressed_data;
	u8 lens[XPRESS_NUM_SYMBOLS];
	u8 *lens_p;
	u16 decode_table[(1 << XPRESS_TABLEBITS) + 2 * XPRESS_NUM_SYMBOLS]
			_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	struct input_bitstream istream;

	/* XPRESS uses only one Huffman code.  It contains 512 symbols, and the
	 * code lengths of these symbols are given literally as 4-bit integers
	 * in the first 256 bytes of the compressed data.  */
	if (compressed_size < XPRESS_NUM_SYMBOLS / 2)
		return -1;

	lens_p = lens;
	for (unsigned i = 0; i < XPRESS_NUM_SYMBOLS / 2; i++) {
		*lens_p++ = cdata[i] & 0xf;
		*lens_p++ = cdata[i] >> 4;
	}

	if (make_huffman_decode_table(decode_table, XPRESS_NUM_SYMBOLS,
				      XPRESS_TABLEBITS, lens,
				      XPRESS_MAX_CODEWORD_LEN))
		return -1;

	init_input_bitstream(&istream, cdata + XPRESS_NUM_SYMBOLS / 2,
			     compressed_size - XPRESS_NUM_SYMBOLS / 2);

	return xpress_lz_decode(&istream, uncompressed_data,
				uncompressed_size, lens, decode_table);
}

const struct decompressor_ops xpress_decompressor_ops = {
	.decompress = xpress_decompress,
};
