/*
 * decompress_common.h
 *
 * Header for decompression code shared by multiple compression formats.
 */

#ifndef _WIMLIB_DECOMPRESS_COMMON_H
#define _WIMLIB_DECOMPRESS_COMMON_H

#include "wimlib/assert.h"
#include "wimlib/compiler.h"
#include "wimlib/error.h"
#include "wimlib/endianness.h"
#include "wimlib/types.h"

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
	u32 bitbuf;

	/* Number of bits in @bitbuf that are valid.  */
	unsigned bitsleft;

	/* Pointer to the next byte to be retrieved from the input.  */
	const u8 *data;

	/* Number of bytes of data that are left.  */
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

/* Ensures the bit buffer variable for the bitstream contains at least @num_bits
 * bits.  Following this, bitstream_peek_bits() and/or bitstream_remove_bits()
 * may be called on the bitstream to peek or remove up to @num_bits bits.
 *
 * If the input data is exhausted, any further bits are assumed to be 0.  */
static inline void
bitstream_ensure_bits(struct input_bitstream *istream, unsigned num_bits)
{
	for (int nbits = num_bits; (int)istream->bitsleft < nbits; nbits -= 16) {
		u16 nextword;
		unsigned shift;

		if (unlikely(istream->data_bytes_left < 2)) {
			istream->bitsleft = num_bits;
			return;
		}

		nextword = le16_to_cpu(*(const le16*)istream->data);
		shift = sizeof(istream->bitbuf) * 8 - 16 - istream->bitsleft;
		istream->bitbuf |= (u32)nextword << shift;
		istream->data += 2;
		istream->bitsleft += 16;
		istream->data_bytes_left -= 2;
	}
}

/* Returns the next @num_bits bits from the bitstream, without removing them.
 * There must be at least @num_bits remaining in the buffer variable, from a
 * previous call to bitstream_ensure_bits().  */
static inline u32
bitstream_peek_bits(const struct input_bitstream *istream, unsigned num_bits)
{
	if (unlikely(num_bits == 0))
		return 0;
	return istream->bitbuf >> (sizeof(istream->bitbuf) * 8 - num_bits);
}

/* Removes @num_bits from the bitstream.  There must be at least @num_bits
 * remaining in the buffer variable, from a previous call to
 * bitstream_ensure_bits().  */
static inline void
bitstream_remove_bits(struct input_bitstream *istream, unsigned num_bits)
{
	istream->bitbuf <<= num_bits;
	istream->bitsleft -= num_bits;
}

/* Removes and returns @num_bits bits from the bitstream.  There must be at
 * least @num_bits remaining in the buffer variable, from a previous call to
 * bitstream_ensure_bits().  */
static inline u32
bitstream_pop_bits(struct input_bitstream *istream, unsigned num_bits)
{
	u32 n = bitstream_peek_bits(istream, num_bits);
	bitstream_remove_bits(istream, num_bits);
	return n;
}

/* Reads and returns the next @num_bits bits from the bitstream.
 * If the input data is exhausted, the bits are assumed to be 0.  */
static inline u32
bitstream_read_bits(struct input_bitstream *istream, unsigned num_bits)
{
	bitstream_ensure_bits(istream, num_bits);
	return bitstream_pop_bits(istream, num_bits);
}

/* Reads and returns the next literal byte embedded in the bitstream.
 * If the input data is exhausted, the byte is assumed to be 0.  */
static inline u8
bitstream_read_byte(struct input_bitstream *istream)
{
	if (unlikely(istream->data_bytes_left == 0))
		return 0;
	istream->data_bytes_left--;
	return *istream->data++;
}

/* Reads and returns the next Huffman-encoded symbol from a bitstream.  If the
 * input data is exhausted, the Huffman symbol is decoded as if the missing bits
 * are all zeroes.  */
static inline u16
read_huffsym(struct input_bitstream * restrict istream,
	     const u16 decode_table[restrict],
	     const u8 lens[restrict],
	     unsigned num_syms,
	     unsigned table_bits,
	     unsigned max_codeword_len)
{

	bitstream_ensure_bits(istream, max_codeword_len);

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
			key_bits = sym + bitstream_pop_bits(istream, 1);
		} while ((sym = decode_table[key_bits]) >= num_syms);
	}
	return sym;
}

extern int
make_huffman_decode_table(u16 decode_table[], unsigned num_syms,
			  unsigned num_bits, const u8 lengths[],
			  unsigned max_codeword_len);

/* Minimum alignment for the decode_table parameter to
 * make_huffman_decode_table().  */
#define DECODE_TABLE_ALIGNMENT 16

#endif /* _WIMLIB_DECOMPRESS_H */
