/*
 * xpress-decomp.c
 *
 * XPRESS decompression routines.
 */

/*
 *
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



/*
 * The XPRESS compression format is a LZ77-based algorithm.  That means it is
 * quite similar to LZX compression, but XPRESS is slightly simpler, so it is a
 * little faster to compress and decompress.
 *
 * The XPRESS compression format is mostly documented in a file called "[MS-XCA]
 * Xpress Compression Algorithm".  In the MSDN library, it can currently be
 * found under Open Specifications => Protocols => Windows Protocols => Windows
 * Server Protocols => [MS-XCA] Xpress Compression Algorithm".  Note that
 * Microsoft apparently also has either a slightly different format or an
 * entirely different format that is also called XPRESS.  The other one is
 * supposedly used in Windows' hibernation file or something, but the one used
 * in WIM files is the one described in the above document.
 *
 * If you are already familiar with the LZ77 algorithm and Huffman coding, the
 * XPRESS format is pretty simple.  The compressed data begins with 256 bytes
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
 * Also, a caveat--- according to M$'s documentation for XPRESS,
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
 * Howeve, wimlib's decompressor in xpress-decomp.c currently does not care if
 * this extra symbol is there or not.
 */

#include "util.h"
#include "xpress.h"
#include "wimlib.h"

#define XPRESS_DECOMP
#include "decomp.h"


/* Decodes @huffsym, a value >= XPRESS_NUM_CHARS, that is the header of a match.
 * */
static int xpress_decode_match(int huffsym, uint window_pos, uint window_len,
				u8 window[], struct input_bitstream *istream)
{
	uint match_len;
	uint match_offset;
	u8 match_sym = (u8)huffsym;
	u8 len_hdr = match_sym & 0xf;
	u8 offset_bsr = match_sym >> 4;
	int ret;
	u8 *match_dest;
	u8 *match_src;
	uint i;

	ret = bitstream_read_bits(istream, offset_bsr, &match_offset);
	if (ret != 0)
		return -1;
	match_offset |= (1 << offset_bsr);

	if (len_hdr == 0xf) {
		ret = bitstream_read_byte(istream);
		if (ret == -1)
			return -1;
		match_len = ret;
		if (match_len == 0xff) {

			ret = bitstream_read_byte(istream);
			if (ret == -1)
				return -1;
			match_len = ret;

			ret = bitstream_read_byte(istream);
			if (ret == -1)
				return -1;

			match_len |= (ret << 8);
			if (match_len < 0xf)
				return -1;
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
		ERROR("XPRESS dedecompression error: match of length %d "
		      "bytes overflows window", match_len);
		return -1;
	}

	if (match_src < window) {
		ERROR("XPRESS decompression error: match of length %d bytes "
		      "references data before window (match_offset = %d, "
		      "window_pos = %d)", match_len, match_offset, window_pos);
		return -1;
	}

	for (i = 0; i < match_len; i++)
		match_dest[i] = match_src[i];

	return match_len;
}

/* Decodes the Huffman-encoded matches and literal bytes in a block of
 * XPRESS-encoded data. */
static int xpress_decompress_literals(struct input_bitstream *istream,
				      u8 uncompressed_data[],
				      uint uncompressed_len,
				      const u8 lens[],
				      const u16 decode_table[])
{
	uint curpos = 0;
	uint huffsym;
	int match_len;
	int ret = 0;

	while (curpos < uncompressed_len) {
		ret = read_huffsym(istream, decode_table, lens,
				   XPRESS_NUM_SYMBOLS, XPRESS_TABLEBITS,
				   &huffsym, XPRESS_MAX_CODEWORD_LEN);
		if (ret != 0)
			break;

		if (huffsym < XPRESS_NUM_CHARS) {
			uncompressed_data[curpos++] = huffsym;
		} else {
			match_len = xpress_decode_match(huffsym,
							curpos,
							uncompressed_len,
							uncompressed_data,
							istream);
			if (match_len == -1) {
				ret = 1;
				break;
			}
			curpos += match_len;
		}
	}
	return ret;
}


int xpress_decompress(const void *__compressed_data, uint compressed_len,
		      void *uncompressed_data, uint uncompressed_len)
{
	u8 lens[XPRESS_NUM_SYMBOLS];
	u16 decode_table[(1 << XPRESS_TABLEBITS) + 2 * XPRESS_NUM_SYMBOLS];
	struct input_bitstream istream;
	u8 *lens_p;
	const u8 *compressed_data;
	uint i;
	int ret;

	compressed_data = __compressed_data;
	lens_p = lens;

	DEBUG2("compressed_len = %d, uncompressed_len = %d",
	       compressed_len, uncompressed_len);

	/* XPRESS uses only one Huffman tree.  It contains 512 symbols, and the
	 * code lengths of these symbols are given literally as 4-bit integers
	 * in the first 256 bytes of the compressed data.
	 */
	if (compressed_len < XPRESS_NUM_SYMBOLS / 2)
		return WIMLIB_ERR_DECOMPRESSION;

	for (i = 0; i < XPRESS_NUM_SYMBOLS / 2; i++) {
		*lens_p++ = compressed_data[i] & 0xf;
		*lens_p++ = compressed_data[i] >> 4;
	}

	ret = make_huffman_decode_table(decode_table, XPRESS_NUM_SYMBOLS,
					XPRESS_TABLEBITS, lens,
					XPRESS_MAX_CODEWORD_LEN);
	if (ret != 0)
		return ret;

	init_input_bitstream(&istream, compressed_data + XPRESS_NUM_SYMBOLS / 2,
			     compressed_len - XPRESS_NUM_SYMBOLS / 2);

	return xpress_decompress_literals(&istream, uncompressed_data,
					  uncompressed_len, lens,
					  decode_table);
}
