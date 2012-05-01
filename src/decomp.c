/*
 * decomp.c
 *
 * Functions too long to declare as inline in decomp.h.
 *
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "decomp.h"
#include <string.h>

/* Reads @n bytes from the bitstream @stream into the location pointed to by @dest.
 * The bitstream must be 16-bit aligned. */
int bitstream_read_bytes(struct input_bitstream *stream, size_t n, void *dest)
{
	/* Precondition:  The bitstream is 16-byte aligned. */
	wimlib_assert(stream->bitsleft % 16 == 0);

	u8 *p = dest;

	/* Get the bytes currently in the buffer variable. */
	while (stream->bitsleft != 0) {
		if (n-- == 0)
			return 0;
		*p++ = bitstream_peek_bits(stream, 8);
		bitstream_remove_bits(stream, 8);
	}

	/* Get the rest directly from the pointer to the data.  Of course, it's
	 * necessary to check there are really n bytes available. */
	if (n > stream->data_bytes_left) {
		ERROR("Unexpected end of input when "
				"reading %zu bytes from bitstream "
				"(only have %u bytes left)\n", n,
				stream->data_bytes_left);
		return 1;
	}
	memcpy(p, stream->data, n);
	stream->data += n;
	stream->data_bytes_left -= n;

	/* It's possible to copy an odd number of bytes and leave the stream in
	 * an inconsistent state. Fix it by reading the next byte, if it is
	 * there. */
	if ((n & 1) && stream->data_bytes_left != 0) {
		stream->bitsleft = 8;
		stream->data_bytes_left--;
		stream->bitbuf |= (input_bitbuf_t)(*stream->data) << 
					(sizeof(input_bitbuf_t) * 8 - 8);
		stream->data++;
	}
	return 0;
}

/* Aligns the bitstream on a 16-bit boundary.
 *
 * Note: M$'s idea of "alignment" means that for some reason, a 16-bit word
 * should be skipped over if the buffer happens to already be aligned on such a
 * boundary.  This only applies for realigning the stream after the blocktype
 * and length fields of an uncompressed block, however; it does not apply when
 * realigning the stream after the end of the uncompressed block.
 */
int align_input_bitstream(struct input_bitstream *stream, 
			  bool skip_word_if_aligned)
{
	int ret;
	if (stream->bitsleft % 16 != 0) {
		bitstream_remove_bits(stream, stream->bitsleft % 16);
	} else if (skip_word_if_aligned) {
		if (stream->bitsleft == 0) {
			ret = bitstream_ensure_bits(stream, 16);
			if (ret != 0) {
				ERROR("Unexpected end of input when "
						"aligning bitstream!\n");
				return ret;
			}
		}
		bitstream_remove_bits(stream, 16);
	}
	return 0;
}
