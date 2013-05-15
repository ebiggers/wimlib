/*
 * decompress.h
 *
 * Functions useful for decompression, mainly bitstreams.
 */

#ifndef _WIMLIB_DECOMPRESS_H
#define _WIMLIB_DECOMPRESS_H

#include "wimlib/assert.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/types.h"

/* Must be at least 32 bits. */
typedef unsigned long input_bitbuf_t;

/* Structure to encapsulate a block of in-memory data that is being interpreted
 * as a stream of bits.
 *
 * This is geared specifically towards the XPRESS and LZX compression formats
 * with regards to the actual ordering the bits within the byte sequence. */
struct input_bitstream {

	/* A variable of length at least 32 bits that is used to hold bits that
	 * have been read from the stream.  The bits are ordered from high-order
	 * to low-order, and the next bit is always the high-order bit. */
	input_bitbuf_t  bitbuf;

	/* Pointer to the next byte to be retrieved from the input. */
	const u8 *data;

	/* Number of bits in @bitbuf that are valid. */
	unsigned bitsleft;

	/* Number of words of data that are left. */
	unsigned data_bytes_left;
};

/* Initializes a bitstream to receive its input from @data. */
static inline void
init_input_bitstream(struct input_bitstream *istream,
		     const void *data, unsigned num_data_bytes)
{
	istream->bitbuf          = 0;
	istream->bitsleft        = 0;
	istream->data            = data;
	istream->data_bytes_left = num_data_bytes;
}

/* Ensures that the bit buffer variable for the bitstream contains @num_bits
 * bits.
 *
 * If there are at least @num_bits bits remaining in the bitstream, 0 is
 * returned.  Otherwise, -1 is returned.  */
static inline int
bitstream_ensure_bits(struct input_bitstream *istream, unsigned num_bits)
{
	wimlib_assert2(num_bits <= 16);

	int ret = 0;

	/* Unfortunately this needs to be different for the different
	 * compression types.  LZX requires reading no more than the number of
	 * bits needed, otherwise the end of the compressed data may be overrun.
	 * XPRESS, on the other hand, requires that we always return with at
	 * least 16 bits in the buffer, even if fewer are requested.  This is
	 * important because this may change the location of a literal byte
	 * read with bitstream_read_byte(). */
#ifdef XPRESS_DECOMP
	if (istream->bitsleft < 16) {
#else
	if (istream->bitsleft < num_bits) {
#endif
		if (istream->data_bytes_left >= 2) {
			unsigned shift = sizeof(input_bitbuf_t) * 8 - 16 -
					 istream->bitsleft;
			istream->bitbuf |= (input_bitbuf_t)le16_to_cpu(
						*(u16*)istream->data) << shift;
			istream->data += 2;
			istream->bitsleft += 16;
			istream->data_bytes_left -= 2;
		} else {
			ret = -1;
		}
	}
	wimlib_assert2(ret != 0 || istream->bitsleft >= num_bits);
	return ret;
}

/* Returns the next @num_bits bits in the buffer variable, which must contain at
 * least @num_bits bits, for the bitstream. */
static inline unsigned
bitstream_peek_bits(const struct input_bitstream *istream, unsigned num_bits)
{
	wimlib_assert2(istream->bitsleft >= num_bits);
	int ret;
	if (num_bits == 0)
		ret = 0;
	else
		ret = istream->bitbuf >> (sizeof(input_bitbuf_t) * 8 - num_bits);
	return ret;
}

/* Removes @num_bits bits from the buffer variable, which must contain at least
 * @num_bits bits, for the bitstream. */
static inline void
bitstream_remove_bits(struct input_bitstream *istream, unsigned num_bits)
{
	wimlib_assert2(istream->bitsleft >= num_bits);
	istream->bitbuf <<= num_bits;
	istream->bitsleft -= num_bits;
}

/* Reads @num_bits bits from the input bitstream.  @num_bits must be 16 or fewer.
 * On success, returns 0 and returns the requested bits in @n.  If there are
 * fewer than @num_bits remaining in the bitstream, -1 is returned. */
static inline int
bitstream_read_bits(struct input_bitstream *istream,
		    unsigned num_bits, unsigned *n)
{
	wimlib_assert2(num_bits <= 16);
	int ret = bitstream_ensure_bits(istream, num_bits);
	if (ret == 0) {
		*n = bitstream_peek_bits(istream, num_bits);
		bitstream_remove_bits(istream, num_bits);
	} else {
		ERROR("bitstream_read_bits(): Input buffer exhausted");
	}
	return ret;
}

/* In the XPRESS format there can be literal bytes embedded in the bitstream.
 * These bytes are basically separate from the bitstream, as they come AFTER the
 * bits that are currently in the buffer variable (based on reading 16 bits at a
 * time), even though the buffer variable may not be empty.
 *
 * This function returns the next such literal byte, or -1 if there are no more.
 */
static inline int
bitstream_read_byte(struct input_bitstream *istream)
{
	wimlib_assert2(istream->bitsleft < 32);
	int ret;

	if (istream->data_bytes_left == 0) {
		ERROR("bitstream_read_byte(): Input buffer exhausted");
		ret = -1;
	} else {
		istream->data_bytes_left--;
		ret = *istream->data++;
	}
	return ret;
}

/* Reads @num_bits bits from the buffer variable for a bistream without checking
 * to see if that many bits are in the buffer or not. */
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

/*
 * Reads a Huffman-encoded symbol from a bitstream.
 *
 * This function may be called hundreds of millions of times when extracting a
 * large WIM file.  I'm not sure it could be made much faster that it is,
 * especially since there isn't enough time to make a big table that allows
 * decoding multiple symbols per lookup.  But if extracting files to a hard
 * disk, the I/O will be the bottleneck anyway.
 *
 * @buf:	The input buffer from which the symbol will be read.
 * @decode_table:	The fast Huffman decoding table for the Huffman tree.
 * @lengths:		The table that gives the length of the code for each
 * 				symbol.
 * @num_symbols:	The number of symbols in the Huffman code.
 * @table_bits:		Huffman codes this length or less can be looked up
 * 				directory in the decode_table, as the
 * 				decode_table contains 2**table_bits entries.
 */
static inline int
read_huffsym(struct input_bitstream *istream,
	     const u16 decode_table[],
	     const u8 lens[],
	     unsigned num_syms,
	     unsigned table_bits,
	     unsigned *n,
	     unsigned max_codeword_len)
{
	int ret;

	/* In the most common case, there are at least max_codeword_len bits
	 * remaining in the stream. */
	if (bitstream_ensure_bits(istream, max_codeword_len) == 0) {

		/* Use the next table_bits of the input as an index into the
		 * decode_table. */
		u16 key_bits = bitstream_peek_bits(istream, table_bits);

		u16 sym = decode_table[key_bits];

		/* If the entry in the decode table is not a valid symbol, it is
		 * the offset of the root of its Huffman subtree. */
		if (sym >= num_syms) {
			bitstream_remove_bits(istream, table_bits);
			do {
				key_bits = sym + bitstream_peek_bits(istream, 1);
				bitstream_remove_bits(istream, 1);

				wimlib_assert2(key_bits < num_syms * 2 +
					       (1 << table_bits));
			} while ((sym = decode_table[key_bits]) >= num_syms);
		} else {
			wimlib_assert2(lens[sym] <= table_bits);
			bitstream_remove_bits(istream, lens[sym]);
		}
		*n = sym;
		ret = 0;
	} else {
		/* Otherwise, we must be careful to use only the bits that are
		 * actually remaining.  */
		ret = read_huffsym_near_end_of_input(istream, decode_table,
						     lens, num_syms,
						     table_bits, n);
	}
	return ret;
}

extern int make_huffman_decode_table(u16 decode_table[], unsigned num_syms,
				     unsigned num_bits, const u8 lengths[],
				     unsigned max_codeword_len);

#endif /* _WIMLIB_DECOMPRESS_H */
