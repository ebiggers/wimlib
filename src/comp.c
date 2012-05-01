/*
 * comp.c
 *
 * Functions too long to declare as inline in comp.h.
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

#include "comp.h"

static inline void flush_bits(struct output_bitstream *ostream)
{
	*(u16*)ostream->bit_output = to_le16(ostream->bitbuf);
	ostream->bit_output = ostream->next_bit_output;
	ostream->next_bit_output = ostream->output;
	ostream->output += 2;
	ostream->num_bytes_remaining -= 2;
}

/* Writes @num_bits bits, given by the @num_bits least significant bits of
 * @bits, to the output @ostream. */
int bitstream_put_bits(struct output_bitstream *ostream, output_bitbuf_t bits, 
		       uint num_bits)
{
	uint rem_bits;

	wimlib_assert(num_bits <= 16);
	if (num_bits <= ostream->free_bits) {
		ostream->bitbuf = (ostream->bitbuf << num_bits) | bits;
		ostream->free_bits -= num_bits;
	} else {

		if (ostream->num_bytes_remaining + (ostream->output - 
						ostream->bit_output) < 2)
			return 1;

		/* It is tricky to output the bits correctly.  The correct way
		 * is to output little-endian 2-byte words, such that the bits
		 * in the SECOND byte logically precede those in the FIRST byte.
		 * While the byte order is little-endian, the bit order is
		 * big-endian; the first bit in a byte is the high-order one.
		 * Any multi-bit numbers are in bit-big-endian form, so the
		 * low-order bit of a multi-bit number is the LAST bit to be
		 * output. */
		rem_bits = num_bits - ostream->free_bits;
		ostream->bitbuf <<= ostream->free_bits;
		ostream->bitbuf |= bits >> rem_bits;
		flush_bits(ostream);
		ostream->free_bits = 16 - rem_bits;
		ostream->bitbuf = bits;

	}
	return 0;
}

/* Flushes any remaining bits in the output buffer to the output byte stream. */
int flush_output_bitstream(struct output_bitstream *ostream)
{
	if (ostream->num_bytes_remaining + (ostream->output - 
					ostream->bit_output) < 2)
		return 1;
	if (ostream->free_bits != 16) {
		ostream->bitbuf <<= ostream->free_bits;
		flush_bits(ostream);
	}
	return 0;
}

/* Initializes an output bit buffer to write its output to the memory location
 * pointer to by @data. */
void init_output_bitstream(struct output_bitstream *ostream, void *data, 
			   uint num_bytes)
{
	ostream->bitbuf              = 0;
	ostream->free_bits           = 16;
	ostream->bit_output          = (u8*)data;
	ostream->next_bit_output     = (u8*)data + 2;
	ostream->output              = (u8*)data + 4;
	ostream->num_bytes_remaining = num_bytes - 4;
}
