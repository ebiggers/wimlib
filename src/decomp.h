/*
 * decomp.h
 *
 * Functions useful for decompression, mainly bitstreams.
 */

#ifndef _WIMLIB_DECOMP_H
#define _WIMLIB_DECOMP_H

#include "util.h"
#include "endianness.h"

/* Must be at least 32 bits. */
typedef unsigned long input_bitbuf_t;

/* Structure to provide a bitstream. */
struct input_bitstream {

	/* A variable of length at least 32 bits that is used to hold bits that
	 * have been read from the stream.  The bits are ordered from high-order
	 * to low-order; the next bit is always the high-order bit. */
	input_bitbuf_t   bitbuf;

	/* Pointer to the next byte to be retrieved from the input. */
	const u8  *data;

	/* Number of bits in @bitbuf that are valid. */
	uint        bitsleft;

	/* Number of words of data that are left. */
	uint        data_bytes_left;
};

/* Initializes a bitstream to receive its input from @data. */
static inline void init_input_bitstream(struct input_bitstream *istream, 
					const void *data, uint num_data_bytes)
{
	istream->bitbuf          = 0;
	istream->bitsleft        = 0;
	istream->data            = data;
	istream->data_bytes_left = num_data_bytes;
}

/* Ensures that the bit buffer contains @num_bits bits. */
static inline int bitstream_ensure_bits(struct input_bitstream *istream, 
					 uint num_bits)
{
	wimlib_assert(num_bits <= 16);

	/* Unfortunately this needs to be different for the different
	 * compression types.  LZX requires reading no more than the number of
	 * bits needed, otherwise the end of the compressed data may be overrun.
	 * XPRESS, on the other hand, requires that we always return with at
	 * least 16 bits in the buffer, even if fewer are requested.  This is
	 * important because this may change the location of a literal byte
	 * read with bitstream_read_byte(). */
#ifdef XPRESS_DECOMP
	while (istream->bitsleft < 16) {
#else
	while (istream->bitsleft < num_bits) {
#endif
		if (istream->data_bytes_left < 2)
			return 1;

		uint shift = sizeof(input_bitbuf_t) * 8 - 16 - 
			     istream->bitsleft;
		istream->bitbuf |= (input_bitbuf_t)to_le16(
					*(u16*)istream->data) << shift;
		istream->data += 2;
		istream->bitsleft += 16;
		istream->data_bytes_left -= 2;
	}
	return 0;
}

/* Returns the next @num_bits bits in the bit buffer.  It must contain at least
 * @num_bits bits to call this function. */
static inline uint bitstream_peek_bits(const struct input_bitstream *istream, 
				       uint num_bits)
{
	if (num_bits == 0)
		return 0;
	return istream->bitbuf >> (sizeof(input_bitbuf_t) * 8 - num_bits);
}

/* Removes @num_bits bits from the bit buffer.  It must contain at least
 * @num_bits bits to call this function. */
static inline void bitstream_remove_bits(struct input_bitstream *istream, 
					 uint num_bits)
{
	istream->bitbuf <<= num_bits;
	istream->bitsleft -= num_bits;
}

/* Reads and returns @num_bits bits from the input bitstream. */
static inline int bitstream_read_bits(struct input_bitstream *istream, 
				       uint num_bits, uint *n)
{
	int ret;
	ret = bitstream_ensure_bits(istream, num_bits);
	if (ret != 0) {
		ERROR("bitstream_read_bits(): Input buffer exhausted\n");
		return ret;
	}
	*n = bitstream_peek_bits(istream, num_bits);
	bitstream_remove_bits(istream, num_bits);
	return 0;
}

/* In the XPRESS format there can be literal length bytes embedded in the
 * compressed bitstream.  These bytes are basically separate from the bitstream,
 * as they come AFTER the bits that are currently in the buffer variable (based
 * on reading 16 bits at a time), even though the buffer variable may not be
 * empty. 
 *
 * This function returns the next such literal length byte in the input
 * bitstream.  Returns -1 if we are at the end of the bitstream. */
static inline int bitstream_read_byte(struct input_bitstream *istream)
{
	wimlib_assert(istream->bitsleft < 32);

	if (istream->data_bytes_left == 0) {
		ERROR("bitstream_read_byte(): Input buffer exhausted\n");
		return -1;
	}
	istream->data_bytes_left--;
	return *istream->data++;
}

/* Reads @num_bits bits from the bit buffer without checking to see if that many
 * bits are in the buffer or not. */
static inline uint bitstream_read_bits_nocheck(struct input_bitstream *istream, 
					       uint num_bits)
{
	uint n = bitstream_peek_bits(istream, num_bits);
	bitstream_remove_bits(istream, num_bits);
	return n;
}

/* Removes the bits that have been read into the bit buffer variable. */
static inline void flush_input_bitstream(struct input_bitstream *istream)
{
	bitstream_remove_bits(istream, istream->bitsleft);
	istream->bitsleft = 0;
	istream->bitbuf   = 0;
}

extern int bitstream_read_bytes(struct input_bitstream *istream, size_t n, 
				void *dest);

extern int align_input_bitstream(struct input_bitstream *istream, 
				 bool skip_word_if_aligned);

extern int read_huffsym(struct input_bitstream *stream, 
			const u16 decode_table[],
			const u8 lengths[],
			unsigned num_symbols,
			unsigned table_bits,
			uint *n,
			unsigned max_codeword_len);

extern int make_huffman_decode_table(u16 decode_table[], uint num_syms, 
				     uint num_bits, const u8 lengths[],
				     uint max_codeword_len);

#endif /* _WIMLIB_DECOMP_H */
