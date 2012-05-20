/*
 * comp.h
 *
 * Functions useful for compression, mainly bitstreams.
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

#ifndef _WIMLIB_COMP_H
#define _WIMLIB_COMP_H

#include "util.h"
#include "endianness.h"

typedef u16 output_bitbuf_t;

/* Structure to keep track of the current position in the compressed output. */
struct output_bitstream {

	/* A variable to buffer writing bits to the output and is flushed to the
	 * compressed output when full. */
	output_bitbuf_t bitbuf;

	/* Number of free bits in @bitbuf */
	uint free_bits;

	u8 *bit_output;
	u8 *next_bit_output;

	/* Pointer to the next byte in the compressed output. */
	u8 *output;


	/* Number of bytes left in the memory pointed to by @output. */
	int num_bytes_remaining;
};


static inline int bitstream_put_byte(struct output_bitstream *ostream,
				      u8 n)
{
	if (ostream->num_bytes_remaining == 0)
		return 1;
	*ostream->output = n;
	ostream->output++;
	ostream->num_bytes_remaining--;
	return 0;
}

static inline int bitstream_put_two_bytes(struct output_bitstream *ostream,
					   u16 n)
{
	if (ostream->num_bytes_remaining < 2)
		return 1;
	*(u16*)ostream->output = to_le16(n);
	ostream->output += 2;
	ostream->num_bytes_remaining -= 2;
	return 0;
}


struct lz_params {
	uint min_match;
	uint max_match;
	uint nice_match;
	uint good_match;
	uint max_chain_len;
	uint max_lazy_match;
	uint too_far;
};
						
typedef uint (*lz_record_match_t)(uint, uint, void *, void *);
typedef uint (*lz_record_literal_t)(u8, void *);

extern uint lz_analyze_block(const u8 uncompressed_data[], 
			     uint uncompressed_len,
			     u32 match_tab[], 
			     lz_record_match_t record_match,
			     lz_record_literal_t record_literal, 
			     void *record_match_arg1,
			     void *record_match_arg2, 
			     void *record_literal_arg,
			     const struct lz_params *params);

extern int bitstream_put_bits(struct output_bitstream *ostream, 
			      output_bitbuf_t bits, unsigned num_bits);

extern void init_output_bitstream(struct output_bitstream *ostream,
						void *data, unsigned num_bytes);

extern int flush_output_bitstream(struct output_bitstream *ostream);

extern void make_canonical_huffman_code(uint num_syms, uint max_codeword_len, 
					const u32 freq_tab[], u8 lens[], 
					u16 codewords[]);

#endif /* _WIMLIB_COMP_H */
