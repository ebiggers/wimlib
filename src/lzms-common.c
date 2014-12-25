/*
 * lzms-common.c - Common code for LZMS compression and decompression
 */

/*
 * Copyright (C) 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/bitops.h"
#include "wimlib/endianness.h"
#include "wimlib/lzms.h"
#include "wimlib/unaligned.h"
#include "wimlib/util.h"

#include <pthread.h>

/***************************************************************
 * Constant tables initialized by lzms_compute_slots():        *
 ***************************************************************/

/* Table: offset slot => offset slot base value  */
u32 lzms_offset_slot_base[LZMS_MAX_NUM_OFFSET_SYMS + 1];

/* Table: offset slot => number of extra offset bits  */
u8 lzms_extra_offset_bits[LZMS_MAX_NUM_OFFSET_SYMS];

/* Table: length slot => length slot base value  */
u32 lzms_length_slot_base[LZMS_NUM_LEN_SYMS + 1];

/* Table: length slot => number of extra length bits  */
u8 lzms_extra_length_bits[LZMS_NUM_LEN_SYMS];

unsigned
lzms_get_slot(u32 value, const u32 slot_base_tab[], unsigned num_slots)
{
	unsigned l = 0;
	unsigned r = num_slots - 1;
	for (;;) {
		LZMS_ASSERT(r >= l);
		unsigned slot = (l + r) / 2;
		if (value >= slot_base_tab[slot]) {
			if (value < slot_base_tab[slot + 1])
				return slot;
			else
				l = slot + 1;
		} else {
			r = slot - 1;
		}
	}
}

static void
lzms_decode_delta_rle_slot_bases(u32 slot_bases[],
				 u8 extra_bits[],
				 const u8 delta_run_lens[],
				 unsigned num_run_lens,
				 u32 final,
				 unsigned expected_num_slots)
{
	unsigned order = 0;
	u32 delta = 1;
	u32 base = 0;
	unsigned slot = 0;
	for (unsigned i = 0; i < num_run_lens; i++) {
		unsigned run_len = delta_run_lens[i];
		while (run_len--) {
			base += delta;
			if (slot > 0)
				extra_bits[slot - 1] = order;
			slot_bases[slot] = base;
			slot++;
		}
		delta <<= 1;
		order++;
	}
	LZMS_ASSERT(slot == expected_num_slots);

	slot_bases[slot] = final;
	extra_bits[slot - 1] = fls32(slot_bases[slot] - slot_bases[slot - 1]);
}

/* Initialize the global offset and length slot tables.  */
static void
lzms_compute_slots(void)
{
	/* If an explicit formula that maps LZMS offset and length slots to slot
	 * bases exists, then it could be used here.  But until one is found,
	 * the following code fills in the slots using the observation that the
	 * increase from one slot base to the next is an increasing power of 2.
	 * Therefore, run-length encoding of the delta of adjacent entries can
	 * be used.  */
	static const u8 offset_slot_delta_run_lens[] = {
		9,   0,   9,   7,   10,  15,  15,  20,
		20,  30,  33,  40,  42,  45,  60,  73,
		80,  85,  95,  105, 6,
	};

	static const u8 length_slot_delta_run_lens[] = {
		27,  4,   6,   4,   5,   2,   1,   1,
		1,   1,   1,   0,   0,   0,   0,   0,
		1,
	};

	/* Offset slots  */
	lzms_decode_delta_rle_slot_bases(lzms_offset_slot_base,
					 lzms_extra_offset_bits,
					 offset_slot_delta_run_lens,
					 ARRAY_LEN(offset_slot_delta_run_lens),
					 0x7fffffff,
					 LZMS_MAX_NUM_OFFSET_SYMS);

	/* Length slots  */
	lzms_decode_delta_rle_slot_bases(lzms_length_slot_base,
					 lzms_extra_length_bits,
					 length_slot_delta_run_lens,
					 ARRAY_LEN(length_slot_delta_run_lens),
					 0x400108ab,
					 LZMS_NUM_LEN_SYMS);
}

/* Initialize the global offset and length slot tables if not already done.  */
void
lzms_init_slots(void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once(&once, lzms_compute_slots);
}

/*
 * Translate relative addresses embedded in x86 instructions into absolute
 * addresses (@undo == %false), or undo this translation (@undo == %true).
 *
 * Absolute addresses are usually more compressible by LZ factorization.
 *
 * @last_target_usages must be a temporary array of length >= 65536.
 */
void
lzms_x86_filter(u8 data[restrict], s32 size,
		s32 last_target_usages[restrict], bool undo)
{
	/*
	 * Note: this filter runs unconditionally and uses a custom algorithm to
	 * detect data regions that probably contain x86 code.
	 *
	 * 'last_x86_pos' tracks the most recent position that has a good chance
	 * of being the start of an x86 instruction.  When the filter detects a
	 * likely x86 instruction, it updates this variable and considers the
	 * next LZMS_X86_MAX_TRANSLATION_OFFSET bytes of data as valid for x86
	 * translations.
	 *
	 * If part of the data does not, in fact, contain x86 machine code, then
	 * 'last_x86_pos' will, very likely, eventually fall more than
	 * LZMS_X86_MAX_TRANSLATION_OFFSET bytes behind the current position.
	 * This results in x86 translations being disabled until the next likely
	 * x86 instruction is detected.
	 *
	 * To identify "likely x86 instructions", the algorithm attempts to
	 * track the position of the most recent potential relative-addressing
	 * instruction that referenced each possible memory address.  If it
	 * finds two references to the same memory address within an
	 * LZMS_X86_ID_WINDOW_SIZE-byte sized window, then the second reference
	 * is flagged as a likely x86 instruction.  Since the instructions
	 * considered for translation necessarily use relative addressing, the
	 * algorithm does a tentative translation into absolute addresses.  In
	 * addition, so that memory addresses can be looked up in an array of
	 * reasonable size (in this code, 'last_target_usages'), only the
	 * low-order 2 bytes of each address are considered significant.
	 */

	s32 i;
	s32 tail_idx;
	u8 saved_byte;
	s32 last_x86_pos;

	if (size <= 17)
		return;

	for (i = 0; i < 65536; i++)
		last_target_usages[i] = -(s32)LZMS_X86_ID_WINDOW_SIZE - 1;

	/*
	 * Optimization: only check for end-of-buffer when we already have a
	 * byte that is a potential opcode for x86 translation.  To do this,
	 * overwrite one of the bytes near the end of the buffer, and restore it
	 * later.  The correctness of this optimization relies on two
	 * characteristics of compressed format:
	 *
	 *  1. No translation can follow an opcode beginning in the last 16
	 *     bytes.
	 *  2. A translation following an opcode starting at the last possible
	 *     position (17 bytes from the end) never extends more than 7 bytes.
	 *     Consequently, we can overwrite any of the bytes starting at
	 *     data[(size - 16) + 7] and have no effect on the result, as long
	 *     as we restore those bytes later.
	 */
	tail_idx = size - 16;
	saved_byte = data[tail_idx + 8];
	data[tail_idx + 8] = 0xE8;
	last_x86_pos = -LZMS_X86_MAX_TRANSLATION_OFFSET - 1;

	/* Note: the very first byte must be ignored completely!  */
	i = 0;
	for (;;) {
		s32 max_trans_offset;
		s32 opcode_nbytes;
		u16 target16;

		/*
		 * The following table is used to accelerate the common case
		 * where the byte has nothing to do with x86 translation and
		 * must simply be skipped.  This is the fastest (at least on
		 * x86_64) of the implementations I tested.  The other
		 * implementations I tested were:
		 *	- Jump table with 256 entries
		 *	- Switch statement with default
		 */
		static const u8 is_potential_opcode[256] = {
			[0x48] = 1, [0x4C] = 1, [0xE8] = 1,
			[0xE9] = 1, [0xF0] = 1, [0xFF] = 1,
		};

		for (;;) {
			if (is_potential_opcode[data[++i]])
				break;
			if (is_potential_opcode[data[++i]])
				break;
			if (is_potential_opcode[data[++i]])
				break;
			if (is_potential_opcode[data[++i]])
				break;
		}

		if (i >= tail_idx)
			break;

		max_trans_offset = LZMS_X86_MAX_TRANSLATION_OFFSET;
		switch (data[i]) {
		case 0x48:
			if (data[i + 1] == 0x8B) {
				if (data[i + 2] == 0x5 || data[i + 2] == 0xD) {
					/* Load relative (x86_64)  */
					opcode_nbytes = 3;
					goto have_opcode;
				}
			} else if (data[i + 1] == 0x8D) {
				if ((data[i + 2] & 0x7) == 0x5) {
					/* Load effective address relative (x86_64)  */
					opcode_nbytes = 3;
					goto have_opcode;
				}
			}
			break;
		case 0x4C:
			if (data[i + 1] == 0x8D) {
				if ((data[i + 2] & 0x7) == 0x5) {
					/* Load effective address relative (x86_64)  */
					opcode_nbytes = 3;
					goto have_opcode;
				}
			}
			break;
		case 0xE8:
			/* Call relative.  Note: 'max_trans_offset' must be
			 * halved for this instruction.  This means that we must
			 * be more confident that we are in a region of x86
			 * machine code before we will do a translation for this
			 * particular instruction.  */
			opcode_nbytes = 1;
			max_trans_offset /= 2;
			goto have_opcode;
		case 0xE9:
			/* Jump relative  */
			i += 4;
			break;
		case 0xF0:
			if (data[i + 1] == 0x83 && data[i + 2] == 0x05) {
				/* Lock add relative  */
				opcode_nbytes = 3;
				goto have_opcode;
			}
			break;
		case 0xFF:
			if (data[i + 1] == 0x15) {
				/* Call indirect  */
				opcode_nbytes = 2;
				goto have_opcode;
			}
			break;
		}

		continue;

	have_opcode:
		if (undo) {
			if (i - last_x86_pos <= max_trans_offset) {
				LZMS_DEBUG("Undid x86 translation at position %d "
					   "(opcode 0x%02x)", i, data[i]);
				void *p32 = &data[i + opcode_nbytes];
				u32 n = get_unaligned_u32_le(p32);
				put_unaligned_u32_le(n - i, p32);
			}
			target16 = i + get_unaligned_u16_le(&data[i + opcode_nbytes]);
		} else {
			target16 = i + get_unaligned_u16_le(&data[i + opcode_nbytes]);
			if (i - last_x86_pos <= max_trans_offset) {
				LZMS_DEBUG("Did x86 translation at position %d "
					   "(opcode 0x%02x)", i, data[i]);
				void *p32 = &data[i + opcode_nbytes];
				u32 n = get_unaligned_u32_le(p32);
				put_unaligned_u32_le(n + i, p32);
			}
		}

		i += opcode_nbytes + sizeof(le32) - 1;

		if (i - last_target_usages[target16] <= LZMS_X86_ID_WINDOW_SIZE)
			last_x86_pos = i;

		last_target_usages[target16] = i;

		continue;
	}

	data[tail_idx + 8] = saved_byte;
}

void
lzms_init_lz_lru_queues(struct lzms_lz_lru_queues *lz)
{
	/* Recent offsets for LZ matches  */
	for (u32 i = 0; i < LZMS_NUM_RECENT_OFFSETS + 1; i++)
		lz->recent_offsets[i] = i + 1;

	lz->prev_offset = 0;
	lz->upcoming_offset = 0;
}

void
lzms_init_delta_lru_queues(struct lzms_delta_lru_queues *delta)
{
	/* Recent offsets and powers for LZ matches  */
	for (u32 i = 0; i < LZMS_NUM_RECENT_OFFSETS + 1; i++) {
		delta->recent_offsets[i] = i + 1;
		delta->recent_powers[i] = 0;
	}
	delta->prev_offset = 0;
	delta->prev_power = 0;
	delta->upcoming_offset = 0;
	delta->upcoming_power = 0;
}


void
lzms_init_lru_queues(struct lzms_lru_queues *lru)
{
	lzms_init_lz_lru_queues(&lru->lz);
	lzms_init_delta_lru_queues(&lru->delta);
}

void
lzms_update_lz_lru_queue(struct lzms_lz_lru_queues *lz)
{
	if (lz->prev_offset != 0) {
		for (int i = LZMS_NUM_RECENT_OFFSETS - 1; i >= 0; i--)
			lz->recent_offsets[i + 1] = lz->recent_offsets[i];
		lz->recent_offsets[0] = lz->prev_offset;
	}
	lz->prev_offset = lz->upcoming_offset;
}

void
lzms_update_delta_lru_queues(struct lzms_delta_lru_queues *delta)
{
	if (delta->prev_offset != 0) {
		for (int i = LZMS_NUM_RECENT_OFFSETS - 1; i >= 0; i--) {
			delta->recent_offsets[i + 1] = delta->recent_offsets[i];
			delta->recent_powers[i + 1] = delta->recent_powers[i];
		}
		delta->recent_offsets[0] = delta->prev_offset;
		delta->recent_powers[0] = delta->prev_power;
	}

	delta->prev_offset = delta->upcoming_offset;
	delta->prev_power = delta->upcoming_power;
}

void
lzms_update_lru_queues(struct lzms_lru_queues *lru)
{
	lzms_update_lz_lru_queue(&lru->lz);
	lzms_update_delta_lru_queues(&lru->delta);
}
