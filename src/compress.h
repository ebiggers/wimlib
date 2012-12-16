/*
 * compress.h
 *
 * Functions useful for compression, mainly bitstreams.
 */

#ifndef _WIMLIB_COMPRESS_H
#define _WIMLIB_COMPRESS_H

#include "util.h"
#include "endianness.h"

typedef u16 output_bitbuf_t;

/* Structure to keep track of the current position in the compressed output. */
struct output_bitstream {

	/* A variable to buffer writing bits to the output and is flushed to the
	 * compressed output when full. */
	output_bitbuf_t bitbuf;

	/* Number of free bits in @bitbuf */
	unsigned free_bits;

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
	if (ostream->num_bytes_remaining < 1)
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
	*(u16*)ostream->output = cpu_to_le16(n);
	ostream->output += 2;
	ostream->num_bytes_remaining -= 2;
	return 0;
}

struct lz_params {
	unsigned min_match;
	unsigned max_match;
	unsigned nice_match;
	unsigned good_match;
	unsigned max_chain_len;
	unsigned max_lazy_match;
	unsigned too_far;
};

typedef unsigned (*lz_record_match_t)(unsigned, unsigned, void *, void *);
typedef unsigned (*lz_record_literal_t)(u8, void *);

extern unsigned lz_analyze_block(const u8 uncompressed_data[],
				 unsigned uncompressed_len,
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

extern void make_canonical_huffman_code(unsigned num_syms,
					unsigned max_codeword_len,
					const u32 freq_tab[],
					u8 lens[],
					u16 codewords[]);

#endif /* _WIMLIB_COMPRESS_H */
