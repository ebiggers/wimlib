/*
 * decompress_common.h
 *
 * Header for decompression code shared by multiple compression formats.
 *
 * The following copying information applies to this specific source code file:
 *
 * Written in 2012-2016 by Eric Biggers <ebiggers3@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide via the Creative Commons Zero 1.0 Universal Public Domain
 * Dedication (the "CC0").
 *
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the CC0 for more details.
 *
 * You should have received a copy of the CC0 along with this software; if not
 * see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef _WIMLIB_DECOMPRESS_COMMON_H
#define _WIMLIB_DECOMPRESS_COMMON_H

#include <string.h>

#include "wimlib/compiler.h"
#include "wimlib/types.h"
#include "wimlib/unaligned.h"

/* Structure that encapsulates a block of in-memory data being interpreted as a
 * stream of bits, optionally with interwoven literal bytes.  Bits are assumed
 * to be stored in little endian 16-bit coding units, with the bits ordered high
 * to low.  */
struct input_bitstream {

	/* Bits that have been read from the input buffer.  The bits are
	 * left-justified; the next bit is always bit 31.  */
	u32 bitbuf;

	/* Number of bits currently held in @bitbuf.  */
	u32 bitsleft;

	/* Pointer to the next byte to be retrieved from the input buffer.  */
	const u8 *next;

	/* Pointer past the end of the input buffer.  */
	const u8 *end;
};

/* Initialize a bitstream to read from the specified input buffer.  */
static inline void
init_input_bitstream(struct input_bitstream *is, const void *buffer, u32 size)
{
	is->bitbuf = 0;
	is->bitsleft = 0;
	is->next = buffer;
	is->end = is->next + size;
}

/* Note: for performance reasons, the following methods don't return error codes
 * to the caller if the input buffer is overrun.  Instead, they just assume that
 * all overrun data is zeroes.  This has no effect on well-formed compressed
 * data.  The only disadvantage is that bad compressed data may go undetected,
 * but even this is irrelevant if higher level code checksums the uncompressed
 * data anyway.  */

/* Ensure the bit buffer variable for the bitstream contains at least @num_bits
 * bits.  Following this, bitstream_peek_bits() and/or bitstream_remove_bits()
 * may be called on the bitstream to peek or remove up to @num_bits bits.  */
static inline void
bitstream_ensure_bits(struct input_bitstream *is, const unsigned num_bits)
{
	/* This currently works for at most 17 bits.  */

	if (is->bitsleft >= num_bits)
		return;

	if (unlikely(is->end - is->next < 2))
		goto overflow;

	is->bitbuf |= (u32)get_unaligned_le16(is->next) << (16 - is->bitsleft);
	is->next += 2;
	is->bitsleft += 16;

	if (unlikely(num_bits == 17 && is->bitsleft == 16)) {
		if (unlikely(is->end - is->next < 2))
			goto overflow;

		is->bitbuf |= (u32)get_unaligned_le16(is->next);
		is->next += 2;
		is->bitsleft = 32;
	}

	return;

overflow:
	is->bitsleft = 32;
}

/* Return the next @num_bits bits from the bitstream, without removing them.
 * There must be at least @num_bits remaining in the buffer variable, from a
 * previous call to bitstream_ensure_bits().  */
static inline u32
bitstream_peek_bits(const struct input_bitstream *is, const unsigned num_bits)
{
	return (is->bitbuf >> 1) >> (sizeof(is->bitbuf) * 8 - num_bits - 1);
}

/* Remove @num_bits from the bitstream.  There must be at least @num_bits
 * remaining in the buffer variable, from a previous call to
 * bitstream_ensure_bits().  */
static inline void
bitstream_remove_bits(struct input_bitstream *is, unsigned num_bits)
{
	is->bitbuf <<= num_bits;
	is->bitsleft -= num_bits;
}

/* Remove and return @num_bits bits from the bitstream.  There must be at least
 * @num_bits remaining in the buffer variable, from a previous call to
 * bitstream_ensure_bits().  */
static inline u32
bitstream_pop_bits(struct input_bitstream *is, unsigned num_bits)
{
	u32 bits = bitstream_peek_bits(is, num_bits);
	bitstream_remove_bits(is, num_bits);
	return bits;
}

/* Read and return the next @num_bits bits from the bitstream.  */
static inline u32
bitstream_read_bits(struct input_bitstream *is, unsigned num_bits)
{
	bitstream_ensure_bits(is, num_bits);
	return bitstream_pop_bits(is, num_bits);
}

/* Read and return the next literal byte embedded in the bitstream.  */
static inline u8
bitstream_read_byte(struct input_bitstream *is)
{
	if (unlikely(is->end == is->next))
		return 0;
	return *is->next++;
}

/* Read and return the next 16-bit integer embedded in the bitstream.  */
static inline u16
bitstream_read_u16(struct input_bitstream *is)
{
	u16 v;

	if (unlikely(is->end - is->next < 2))
		return 0;
	v = get_unaligned_le16(is->next);
	is->next += 2;
	return v;
}

/* Read and return the next 32-bit integer embedded in the bitstream.  */
static inline u32
bitstream_read_u32(struct input_bitstream *is)
{
	u32 v;

	if (unlikely(is->end - is->next < 4))
		return 0;
	v = get_unaligned_le32(is->next);
	is->next += 4;
	return v;
}

/* Read into @dst_buffer an array of literal bytes embedded in the bitstream.
 * Return either a pointer to the byte past the last written, or NULL if the
 * read overflows the input buffer.  */
static inline void *
bitstream_read_bytes(struct input_bitstream *is, void *dst_buffer, size_t count)
{
	if (unlikely(is->end - is->next < count))
		return NULL;
	memcpy(dst_buffer, is->next, count);
	is->next += count;
	return (u8 *)dst_buffer + count;
}

/* Align the input bitstream on a coding-unit boundary.  */
static inline void
bitstream_align(struct input_bitstream *is)
{
	is->bitsleft = 0;
	is->bitbuf = 0;
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
 * XXX: This is mostly duplicated in lzms_decode_huffman_symbol() in
 * lzms_decompress.c.  */
static inline unsigned
read_huffsym(struct input_bitstream *istream, const u16 decode_table[],
	     unsigned table_bits, unsigned max_codeword_len)
{
	unsigned entry;
	unsigned key_bits;

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

static inline void
copy_word_unaligned(const void *src, void *dst)
{
	store_word_unaligned(load_word_unaligned(src), dst);
}

static inline machine_word_t
repeat_byte(u8 b)
{
	machine_word_t v;

	STATIC_ASSERT(WORDBITS == 32 || WORDBITS == 64);

	v = b;
	v |= v << 8;
	v |= v << 16;
	v |= v << ((WORDBITS == 64) ? 32 : 0);
	return v;
}

/*
 * Copy an LZ77 match at (dst - offset) to dst.
 *
 * The length and offset must be already validated --- that is, (dst - offset)
 * can't underrun the output buffer, and (dst + length) can't overrun the output
 * buffer.  Also, the length cannot be 0.
 *
 * @winend points to the byte past the end of the output buffer.
 * This function won't write any data beyond this position.
 */
static inline void
lz_copy(u8 *dst, u32 length, u32 offset, const u8 *winend, u32 min_length)
{
	const u8 *src = dst - offset;
	const u8 * const end = dst + length;

	/*
	 * Try to copy one machine word at a time.  On i386 and x86_64 this is
	 * faster than copying one byte at a time, unless the data is
	 * near-random and all the matches have very short lengths.  Note that
	 * since this requires unaligned memory accesses, it won't necessarily
	 * be faster on every architecture.
	 *
	 * Also note that we might copy more than the length of the match.  For
	 * example, if a word is 8 bytes and the match is of length 5, then
	 * we'll simply copy 8 bytes.  This is okay as long as we don't write
	 * beyond the end of the output buffer, hence the check for (winend -
	 * end >= WORDBYTES - 1).
	 */
	if (UNALIGNED_ACCESS_IS_FAST && likely(winend - end >= WORDBYTES - 1)) {

		if (offset >= WORDBYTES) {
			/* The source and destination words don't overlap.  */

			/* To improve branch prediction, one iteration of this
			 * loop is unrolled.  Most matches are short and will
			 * fail the first check.  But if that check passes, then
			 * it becomes increasing likely that the match is long
			 * and we'll need to continue copying.  */

			copy_word_unaligned(src, dst);
			src += WORDBYTES;
			dst += WORDBYTES;

			if (dst < end) {
				do {
					copy_word_unaligned(src, dst);
					src += WORDBYTES;
					dst += WORDBYTES;
				} while (dst < end);
			}
			return;
		} else if (offset == 1) {

			/* Offset 1 matches are equivalent to run-length
			 * encoding of the previous byte.  This case is common
			 * if the data contains many repeated bytes.  */

			machine_word_t v = repeat_byte(*(dst - 1));
			do {
				store_word_unaligned(v, dst);
				src += WORDBYTES;
				dst += WORDBYTES;
			} while (dst < end);
			return;
		}
		/*
		 * We don't bother with special cases for other 'offset <
		 * WORDBYTES', which are usually rarer than 'offset == 1'.
		 * Extra checks will just slow things down.  Actually, it's
		 * possible to handle all the 'offset < WORDBYTES' cases using
		 * the same code, but it still becomes more complicated doesn't
		 * seem any faster overall; it definitely slows down the more
		 * common 'offset == 1' case.
		 */
	}

	/* Fall back to a bytewise copy.  */

	if (min_length >= 2) {
		*dst++ = *src++;
		length--;
	}
	if (min_length >= 3) {
		*dst++ = *src++;
		length--;
	}
	if (min_length >= 4) {
		*dst++ = *src++;
		length--;
	}
	do {
		*dst++ = *src++;
	} while (--length);
}

#endif /* _WIMLIB_DECOMPRESS_COMMON_H */
