/*
 * compress_common.h
 *
 * Header for compression code shared by multiple compression formats.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_COMPRESS_COMMON_H
#define _WIMLIB_COMPRESS_COMMON_H

#include "wimlib/types.h"

/* Variable type that can represent all possible window positions.  */
#ifndef INPUT_IDX_T_DEFINED
#define INPUT_IDX_T_DEFINED
typedef u32 input_idx_t;
#endif

/* Structure to keep track of the current state sending bits and bytes to the
 * compressed output buffer.  */
struct output_bitstream {

	/* Variable that holds up to 16 bits that haven't yet been flushed to
	 * the output.  */
	u16 bitbuf;

	/* Number of free bits in @bitbuf; that is, 16 minus the number of valid
	 * bits in @bitbuf.  */
	unsigned free_bits;

	/* Pointer to the start of the output buffer.  */
	u8 *output_start;

	/* Position at which to write the next 16 bits.  */
	u8 *bit_output;

	/* Next position to write 16 bits, after they are written to bit_output.
	 * This is after @next_bit_output and may be separated from @bit_output
	 * by literal bytes.  */
	u8 *next_bit_output;

	/* Next position to write literal bytes.  This is after @bit_output and
	 * @next_bit_output, and may be separated from them by literal bytes.
	 */
	u8 *output;

	/* Number of bytes remaining in the @output buffer.  */
	input_idx_t bytes_remaining;

	/* Set to true if the buffer has been exhausted.  */
	bool overrun;
};

extern void
init_output_bitstream(struct output_bitstream *ostream,
		      void *data, unsigned num_bytes);

extern input_idx_t
flush_output_bitstream(struct output_bitstream *ostream);

extern void
bitstream_put_bits(struct output_bitstream *ostream,
		   u32 bits, unsigned num_bits);

extern void
bitstream_put_byte(struct output_bitstream *ostream, u8 n);

extern void
make_canonical_huffman_code(unsigned num_syms,
			    unsigned max_codeword_len,
			    const input_idx_t freq_tab[restrict],
			    u8 lens[restrict],
			    u32 codewords[restrict]);

#endif /* _WIMLIB_COMPRESS_COMMON_H */
