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


/* Needed alignment of decode_table parameter to make_huffman_decode_table().
 *
 * Reason: We may fill the entries with SSE instructions without worrying
 * about dealing with the unaligned case.  */
#define DECODE_TABLE_ALIGNMENT 16

/* Maximum supported symbol count for make_huffman_decode_table().
 *
 * Reason: In direct mapping entries, we store the symbol in 11 bits.  */
#define DECODE_TABLE_MAX_SYMBOLS 2048

/* Maximum supported table bits for make_huffman_decode_table().
 *
 * Reason: In internal binary tree nodes, offsets are encoded in 14 bits.
 * But the real limit is 13, because we allocate entries past the end of
 * the direct lookup part of the table for binary tree nodes.  (Note: if
 * needed this limit could be removed by encoding the offsets relative to
 * &decode_table[1 << table_bits].)  */
#define DECODE_TABLE_MAX_TABLE_BITS 13

/* Maximum supported codeword length for make_huffman_decode_table().
 *
 * Reason: In direct mapping entries, we encode the codeword length in 5
 * bits, and the top 2 bits can't both be set because that has special
 * meaning.  */
#define DECODE_TABLE_MAX_CODEWORD_LEN 23

/* Reads and returns the next Huffman-encoded symbol from a bitstream.  If the
 * input data is exhausted, the Huffman symbol is decoded as if the missing bits
 * are all zeroes.
 *
 * XXX: This is mostly duplicated in lzms_huffman_decode_symbol() in
 * lzms-decompress.c.  */
static inline u16
read_huffsym(struct input_bitstream *istream, const u16 decode_table[],
	     unsigned table_bits, unsigned max_codeword_len)
{
	u16 entry;
	u16 key_bits;

	bitstream_ensure_bits(istream, max_codeword_len);

	/* Index the decode table by the next table_bits bits of the input.  */
	key_bits = bitstream_peek_bits(istream, table_bits);
	entry = decode_table[key_bits];
	if (likely(entry < 0xC000)) {
		/* Fast case: The decode table directly provided the
		 * symbol and codeword length.  The low 11 bits are the
		 * symbol, and the high 5 bits are the codeword length.  */
		bitstream_remove_bits(istream, entry >> 11);
		return entry & 0x7FF;
	} else {
		/* Slow case: The codeword for the symbol is longer than
		 * table_bits, so the symbol does not have an entry
		 * directly in the first (1 << table_bits) entries of the
		 * decode table.  Traverse the appropriate binary tree
		 * bit-by-bit to decode the symbol.  */
		bitstream_remove_bits(istream, table_bits);
		do {
			key_bits = (entry & 0x3FFF) + bitstream_pop_bits(istream, 1);
		} while ((entry = decode_table[key_bits]) >= 0xC000);
		return entry;
	}
}

extern int
make_huffman_decode_table(u16 decode_table[], unsigned num_syms,
			  unsigned num_bits, const u8 lens[],
			  unsigned max_codeword_len);

#endif /* _WIMLIB_DECOMPRESS_H */
