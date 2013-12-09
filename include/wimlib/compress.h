/*
 * compress.h
 *
 * Header for compression code shared by multiple compression formats.
 */

#ifndef _WIMLIB_COMPRESS_H
#define _WIMLIB_COMPRESS_H

#include "wimlib/endianness.h"
#include "wimlib/types.h"

typedef u16 output_bitbuf_t;

/* Variable type that can represent all possible window positions.  */
typedef u32 freq_t;
#ifndef INPUT_IDX_T_DEFINED
#define INPUT_IDX_T_DEFINED
typedef u32 input_idx_t;
#endif

/* Structure to keep track of the current position in the compressed output. */
struct output_bitstream {

	/* A variable to buffer writing bits to the output and is flushed to the
	 * compressed output when full. */
	output_bitbuf_t bitbuf;

	/* Number of free bits in @bitbuf */
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

	/* Bytes remaining in @output buffer.  */
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
		   output_bitbuf_t bits, unsigned num_bits);

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
lz_analyze_block(const u8 window[],
		 input_idx_t window_size,
		 lz_record_match_t record_match,
		 lz_record_literal_t record_literal,
		 void *record_ctx,
		 const struct lz_params *params,
		 input_idx_t prev_tab[]);

extern void
make_canonical_huffman_code(unsigned num_syms,
			    unsigned max_codeword_len,
			    const freq_t freq_tab[restrict],
			    u8 lens[restrict],
			    u16 codewords[restrict]);

#endif /* _WIMLIB_COMPRESS_H */
