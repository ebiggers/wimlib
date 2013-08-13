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
 * The XPRESS compression format is a LZ77 and Huffman-code based algorithm.
 * That means it is quite similar to LZX compression, but XPRESS is slightly
 * simpler, so it is a little faster to compress and decompress.
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
 * Huffman tree used for decoding compressed literals.  This is the only Huffman
 * tree that is used for the entirety of the compressed data, and the codeword
 * lengths are not encoded with a pretree.
 *
 * The rest of the compressed data is Huffman-encoded symbols.  Values 0 through
 * 255 are literal bytes.  Values 256 through 511 are matches and may require
 * extra bits or bytes to be read to get the match offset and match length.
 *
 * There is no notion of a "compressed block" in the XPRESS format, so in the
 * XPRESS format, each WIM chunk (32768 bytes) will always use only one Huffman
 * tree.
 *
 * The trickiest part is probably the fact that literal bytes for match lengths
 * are encoded "separately" from the bitstream.
 *
 * Also, a caveat--- according to Microsoft's documentation for XPRESS,
 *
 * 	"Some implementation of the decompression algorithm expect an extra
 * 	symbol to mark the end of the data.  Specifically, some implementations
 * 	fail during decompression if the Huffman symbol 256 is not found after
 * 	the actual data."
 *
 * This is the case for WIM files--- in we must write this extra symbol "256" at
 * the end.  Otherwise Microsoft's software will fail to decompress the
 * XPRESS-compressed data.
 *
 * However, wimlib's decompressor in this file currently does not care if this
 * extra symbol is there or not.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/assert.h"
#define XPRESS_DECOMP
#include "wimlib/decompress.h"
#include "wimlib/util.h"
#include "wimlib/xpress.h"

/*
 * Decodes a symbol @huffsym that begins an XPRESS match.
 *
 * The low 8 bits of the symbol are divided into:
 *
 * bits 0-3:  length header
 * bits 4-7:  index of high-order bit of match offset
 *
 * Note: taking the low 8 bits of the symbol is the same as subtracting 256, the
 * number of symbols reserved for literals.
 *
 * Returns the match length, or -1 on error.
 */
static int
xpress_decode_match(unsigned huffsym, unsigned window_pos,
		    unsigned window_len, u8 window[restrict],
		    struct input_bitstream * restrict istream)
{
	unsigned match_len;
	unsigned match_offset;
	u8 match_sym = (u8)huffsym;
	u8 len_hdr = match_sym & 0xf;
	u8 offset_bsr = match_sym >> 4;
	int ret;
	u8 *match_dest;
	u8 *match_src;
	unsigned i;

	ret = bitstream_read_bits(istream, offset_bsr, &match_offset);
	if (ret)
		return ret;
	match_offset |= (1 << offset_bsr);

	if (len_hdr == 0xf) {
		ret = bitstream_read_byte(istream);
		if (ret < 0)
			return ret;
		match_len = ret;
		if (match_len == 0xff) {
			ret = bitstream_read_byte(istream);
			if (ret < 0)
				return ret;
			match_len = ret;

			ret = bitstream_read_byte(istream);
			if (ret < 0)
				return ret;

			match_len |= (ret << 8);
		} else {
			match_len += 0xf;
		}
	} else {
		match_len = len_hdr;
	}
	match_len += XPRESS_MIN_MATCH;

	/* Verify that the match is in the bounds of the part of the window
	 * currently in use, then copy the source of the match to the current
	 * position. */

	match_dest = window + window_pos;
	match_src = match_dest - match_offset;

	if (window_pos + match_len > window_len) {
		DEBUG("XPRESS decompression error: match of length %u "
		      "bytes overflows window", match_len);
		return -1;
	}

	if (match_src < window) {
		DEBUG("XPRESS decompression error: match of length %u bytes "
		      "references data before window (match_offset = %u, "
		      "window_pos = %u)", match_len, match_offset, window_pos);
		return -1;
	}

	for (i = 0; i < match_len; i++)
		match_dest[i] = match_src[i];

	return match_len;
}

/* Decodes the Huffman-encoded matches and literal bytes in a block of
 * XPRESS-encoded data. */
static int
xpress_decompress_block(struct input_bitstream * restrict istream,
			u8 uncompressed_data[restrict],
			unsigned uncompressed_len,
			const u8 lens[restrict],
			const u16 decode_table[restrict])
{
	unsigned curpos;
	unsigned huffsym;
	int ret;
	int match_len;

	curpos = 0;
	while (curpos < uncompressed_len) {
		ret = read_huffsym(istream, decode_table, lens,
				   XPRESS_NUM_SYMBOLS, XPRESS_TABLEBITS,
				   &huffsym, XPRESS_MAX_CODEWORD_LEN);
		if (ret)
			return ret;

		if (huffsym < XPRESS_NUM_CHARS) {
			uncompressed_data[curpos++] = huffsym;
		} else {
			match_len = xpress_decode_match(huffsym,
							curpos,
							uncompressed_len,
							uncompressed_data,
							istream);
			if (match_len < 0)
				return match_len;
			curpos += match_len;
		}
	}
	return 0;
}


/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_xpress_decompress(const void * restrict _compressed_data, unsigned compressed_len,
			 void * restrict uncompressed_data, unsigned uncompressed_len)
{
	u8 lens[XPRESS_NUM_SYMBOLS];
	u16 decode_table[(1 << XPRESS_TABLEBITS) + 2 * XPRESS_NUM_SYMBOLS]
			_aligned_attribute(DECODE_TABLE_ALIGNMENT);
	struct input_bitstream istream;
	u8 *lens_p;
	const u8 *compressed_data;
	unsigned i;
	int ret;

	compressed_data = _compressed_data;
	lens_p = lens;

	DEBUG2("compressed_len = %d, uncompressed_len = %d",
	       compressed_len, uncompressed_len);

	/* XPRESS uses only one Huffman tree.  It contains 512 symbols, and the
	 * code lengths of these symbols are given literally as 4-bit integers
	 * in the first 256 bytes of the compressed data.
	 */
	if (compressed_len < XPRESS_NUM_SYMBOLS / 2) {
		DEBUG("xpress_decompress(): Compressed length too short!");
		return -1;
	}

	for (i = 0; i < XPRESS_NUM_SYMBOLS / 2; i++) {
		*lens_p++ = compressed_data[i] & 0xf;
		*lens_p++ = compressed_data[i] >> 4;
	}

	ret = make_huffman_decode_table(decode_table, XPRESS_NUM_SYMBOLS,
					XPRESS_TABLEBITS, lens,
					XPRESS_MAX_CODEWORD_LEN);
	if (ret)
		return ret;

	init_input_bitstream(&istream, compressed_data + XPRESS_NUM_SYMBOLS / 2,
			     compressed_len - XPRESS_NUM_SYMBOLS / 2);

	return xpress_decompress_block(&istream, uncompressed_data,
				       uncompressed_len, lens,
				       decode_table);
}
