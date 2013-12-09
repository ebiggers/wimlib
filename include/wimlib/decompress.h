/*
 * decompress.h
 *
 * Header for decompression code shared by multiple compression formats.
 */

#ifndef _WIMLIB_DECOMPRESS_H
#define _WIMLIB_DECOMPRESS_H

#include "wimlib/assert.h"
#include "wimlib/compiler.h"
#include "wimlib/error.h"
#include "wimlib/endianness.h"
#include "wimlib/types.h"

/* Must be at least 32 bits. */
typedef u32 input_bitbuf_t;
#define INPUT_BITBUF_BITS (sizeof(input_bitbuf_t) * 8)

#ifndef INPUT_IDX_T_DEFINED
#define INPUT_IDX_T_DEFINED
typedef u32 input_idx_t;
#endif

/* Structure to encapsulate a block of in-memory data that is being interpreted
 * as a stream of bits.
 *
 * This is geared specifically towards the XPRESS and LZX compression formats
 * with regards to the actual ordering the bits within the byte sequence.  */
struct input_bitstream {

	/* A variable of length at least 32 bits that is used to hold bits that
	 * have been read from the stream.  The bits are ordered from high-order
	 * to low-order, and the next bit is always the high-order bit.  */
	input_bitbuf_t  bitbuf;

	/* Pointer to the next byte to be retrieved from the input. */
	const u8 *data;

	/* Number of bits in @bitbuf that are valid. */
	unsigned bitsleft;

	/* Number of words of data that are left.  */
	input_idx_t data_bytes_left;
};

/* Initializes a bitstream to receive its input from @data. */
static inline void
init_input_bitstream(struct input_bitstream *istream,
		     const void *data, input_idx_t num_data_bytes)
{
	istream->bitbuf          = 0;
	istream->bitsleft        = 0;
	istream->data            = data;
	istream->data_bytes_left = num_data_bytes;
}

/* Ensures that the bit buffer variable for the bitstream contains @num_bits
 * bits, which must be 16 or fewer.
 *
 * If there are at least @num_bits bits remaining in the bitstream, 0 is
 * returned.  Otherwise, -1 is returned.  */
static inline int
bitstream_ensure_bits(struct input_bitstream *istream, unsigned num_bits)
{
	wimlib_assert2(num_bits <= 16);

	if (istream->bitsleft >= num_bits)
		return 0;

	if (unlikely(istream->data_bytes_left < 2))
		return -1;

	istream->bitbuf |= le16_to_cpu(*(le16*)istream->data) <<
			   (INPUT_BITBUF_BITS - 16 - istream->bitsleft);
	istream->data += 2;
	istream->bitsleft += 16;
	istream->data_bytes_left -= 2;
	return 0;
}

/* Returns the next @num_bits bits in the buffer variable, which must contain at
 * least @num_bits bits, for the bitstream.  */
static inline unsigned
bitstream_peek_bits(const struct input_bitstream *istream, unsigned num_bits)
{
	wimlib_assert2(istream->bitsleft >= num_bits);

	if (unlikely(num_bits == 0))
		return 0;

	return istream->bitbuf >> (INPUT_BITBUF_BITS - num_bits);
}

/* Removes @num_bits bits from the buffer variable, which must contain at least
 * @num_bits bits, for the bitstream.  */
static inline void
bitstream_remove_bits(struct input_bitstream *istream, unsigned num_bits)
{
	wimlib_assert2(istream->bitsleft >= num_bits);

	istream->bitbuf <<= num_bits;
	istream->bitsleft -= num_bits;
}

/* Gets and removes @num_bits bits from the buffer variable, which must contain
 * at least @num_bits bits, for the bitstream.  */
static inline unsigned
bitstream_pop_bits(struct input_bitstream *istream,
		   unsigned num_bits)
{
	unsigned n = bitstream_peek_bits(istream, num_bits);
	bitstream_remove_bits(istream, num_bits);
	return n;
}

/* Reads @num_bits bits from the input bitstream.  @num_bits must be 16 or
 * fewer.  On success, returns 0 and returns the requested bits in @n.  If there
 * are fewer than @num_bits remaining in the bitstream, -1 is returned. */
static inline int
bitstream_read_bits(struct input_bitstream *istream,
		    unsigned num_bits, unsigned *n)
{
	if (unlikely(bitstream_ensure_bits(istream, num_bits)))
		return -1;

	*n = bitstream_pop_bits(istream, num_bits);
	return 0;
}

/* Return the next literal byte embedded in the bitstream, or -1 if the input
 * was exhausted.  */
static inline int
bitstream_read_byte(struct input_bitstream *istream)
{
	if (unlikely(istream->data_bytes_left < 1))
		return -1;

	istream->data_bytes_left--;
	return *istream->data++;
}

/* Reads @num_bits bits from the buffer variable for a bistream without checking
 * to see if that many bits are in the buffer or not.  */
static inline unsigned
bitstream_read_bits_nocheck(struct input_bitstream *istream, unsigned num_bits)
{
	unsigned n = bitstream_peek_bits(istream, num_bits);
	bitstream_remove_bits(istream, num_bits);
	return n;
}

extern int
read_huffsym_near_end_of_input(struct input_bitstream *istream,
			       const u16 decode_table[],
			       const u8 lens[],
			       unsigned num_syms,
			       unsigned table_bits,
			       unsigned *n);

/* Read a Huffman-encoded symbol from a bitstream.  */
static inline int
read_huffsym(struct input_bitstream * restrict istream,
	     const u16 decode_table[restrict],
	     const u8 lens[restrict],
	     unsigned num_syms,
	     unsigned table_bits,
	     unsigned *restrict n,
	     unsigned max_codeword_len)
{
	/* If there are fewer bits remaining in the input than the maximum
	 * codeword length, use the slow path that has extra checks.  */
	if (unlikely(bitstream_ensure_bits(istream, max_codeword_len))) {
		return read_huffsym_near_end_of_input(istream, decode_table,
						      lens, num_syms,
						      table_bits, n);
	}

	/* Use the next table_bits of the input as an index into the
	 * decode_table.  */
	u16 key_bits = bitstream_peek_bits(istream, table_bits);

	u16 sym = decode_table[key_bits];

	if (likely(sym < num_syms)) {
		/* Fast case: The decode table directly provided the symbol.  */
		bitstream_remove_bits(istream, lens[sym]);
	} else {
		/* Slow case: The symbol took too many bits to include directly
		 * in the decode table, so search for it in a binary tree at the
		 * end of the decode table.  */
		bitstream_remove_bits(istream, table_bits);
		do {
			key_bits = sym + bitstream_peek_bits(istream, 1);
			bitstream_remove_bits(istream, 1);
		} while ((sym = decode_table[key_bits]) >= num_syms);
	}
	*n = sym;
	return 0;
}

extern int
make_huffman_decode_table(u16 decode_table[], unsigned num_syms,
			  unsigned num_bits, const u8 lengths[],
			  unsigned max_codeword_len);

/* Minimum alignment for the decode_table parameter to
 * make_huffman_decode_table().  */
#define DECODE_TABLE_ALIGNMENT 16

#endif /* _WIMLIB_DECOMPRESS_H */
