/*
 * compress.h
 *
 * Header for compression code shared by multiple compression formats.
 */

#ifndef _WIMLIB_COMPRESS_H
#define _WIMLIB_COMPRESS_H

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

struct lz_params {
	unsigned min_match;
	unsigned max_match;
	unsigned max_offset;
	unsigned nice_match;
	unsigned good_match;
	unsigned max_chain_len;
	unsigned max_lazy_match;
	unsigned too_far;
};

typedef void (*lz_record_match_t)(unsigned len, unsigned offset, void *ctx);
typedef void (*lz_record_literal_t)(u8 lit, void *ctx);

extern void
lz_analyze_block(const u8 window[restrict],
		 input_idx_t window_size,
		 lz_record_match_t record_match,
		 lz_record_literal_t record_literal,
		 void *record_ctx,
		 const struct lz_params *params,
		 input_idx_t prev_tab[restrict]);

extern void
make_canonical_huffman_code(unsigned num_syms,
			    unsigned max_codeword_len,
			    const input_idx_t freq_tab[restrict],
			    u8 lens[restrict],
			    u16 codewords[restrict]);

#endif /* _WIMLIB_COMPRESS_H */
