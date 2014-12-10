/*
 * lzms-common.c
 *
 * Code shared between the compressor and decompressor for the LZMS compression
 * format.
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

static s32
lzms_maybe_do_x86_translation(u8 data[restrict], s32 i, s32 num_op_bytes,
			      s32 * restrict closest_target_usage_p,
			      s32 last_target_usages[restrict],
			      s32 max_trans_offset, bool undo)
{
	u16 pos;

	if (undo) {
		if (i - *closest_target_usage_p <= max_trans_offset) {
			LZMS_DEBUG("Undid x86 translation at position %d "
				   "(opcode 0x%02x)", i, data[i]);
			void *p32 = &data[i + num_op_bytes];
			u32 n = get_unaligned_u32_le(p32);
			put_unaligned_u32_le(n - i, p32);
		}
		pos = i + get_unaligned_u16_le(&data[i + num_op_bytes]);
	} else {
		pos = i + get_unaligned_u16_le(&data[i + num_op_bytes]);

		if (i - *closest_target_usage_p <= max_trans_offset) {
			LZMS_DEBUG("Did x86 translation at position %d "
				   "(opcode 0x%02x)", i, data[i]);
			void *p32 = &data[i + num_op_bytes];
			u32 n = get_unaligned_u32_le(p32);
			put_unaligned_u32_le(n + i, p32);
		}
	}

	i += num_op_bytes + sizeof(le32) - 1;

	if (i - last_target_usages[pos] <= LZMS_X86_MAX_GOOD_TARGET_OFFSET)
		*closest_target_usage_p = i;

	last_target_usages[pos] = i;

	return i + 1;
}

static inline s32
lzms_may_x86_translate(const u8 p[restrict], s32 *restrict max_offset_ret)
{
	/* Switch on first byte of the opcode, assuming it is really an x86
	 * instruction.  */
	*max_offset_ret = LZMS_X86_MAX_TRANSLATION_OFFSET;
	switch (p[0]) {
	case 0x48:
		if (p[1] == 0x8b) {
			if (p[2] == 0x5 || p[2] == 0xd) {
				/* Load relative (x86_64)  */
				return 3;
			}
		} else if (p[1] == 0x8d) {
			if ((p[2] & 0x7) == 0x5) {
				/* Load effective address relative (x86_64)  */
				return 3;
			}
		}
		break;

	case 0x4c:
		if (p[1] == 0x8d) {
			if ((p[2] & 0x7) == 0x5) {
				/* Load effective address relative (x86_64)  */
				return 3;
			}
		}
		break;

	case 0xe8:
		/* Call relative  */
		*max_offset_ret = LZMS_X86_MAX_TRANSLATION_OFFSET / 2;
		return 1;

	case 0xe9:
		/* Jump relative  */
		*max_offset_ret = 0;
		return 5;

	case 0xf0:
		if (p[1] == 0x83 && p[2] == 0x05) {
			/* Lock add relative  */
			return 3;
		}
		break;

	case 0xff:
		if (p[1] == 0x15) {
			/* Call indirect  */
			return 2;
		}
		break;
	}
	*max_offset_ret = 0;
	return 1;
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
	 * 'closest_target_usage' tracks the most recent position that has a
	 * good chance of being an x86 instruction.  When the filter detects a
	 * likely x86 instruction, it updates this variable and considers the
	 * next 1023 bytes of data as valid for x86 translations.
	 *
	 * If part of the data does not, in fact, contain x86 machine code, then
	 * 'closest_target_usage' will, very likely, eventually fall more than
	 * 1023 bytes behind the current position.  This results in x86
	 * translations being disabled until the next likely x86 instruction is
	 * detected.
	 *
	 * Translations on relative call (e8 opcode) instructions are slightly
	 * more restricted.  They require that the most recent likely x86
	 * instruction was in the last 511 bytes, rather than the last 1023
	 * bytes.
	 *
	 * To identify "likely x86 instructions", the algorithm attempts to
	 * track the position of the most recent potential relative-addressing
	 * instruction that referenced each possible memory address.  If it
	 * finds two references to the same memory address within a 65535 byte
	 * window, the second reference is flagged as a likely x86 instruction.
	 * Since the instructions considered for translation necessarily use
	 * relative addressing, the algorithm does a tentative translation into
	 * absolute addresses.  In addition, so that memory addresses can be
	 * looked up in an array of reasonable size (in this code,
	 * 'last_target_usages'), only the low-order 2 bytes of each address are
	 * considered significant.
	 */

	s32 closest_target_usage = -LZMS_X86_MAX_TRANSLATION_OFFSET - 1;

	for (s32 i = 0; i < 65536; i++)
		last_target_usages[i] = -LZMS_X86_MAX_GOOD_TARGET_OFFSET - 1;

	for (s32 i = 1; i < size - 16; ) {
		s32 max_trans_offset;
		s32 n;

		n = lzms_may_x86_translate(data + i, &max_trans_offset);

		if (max_trans_offset) {
			/* Recognized opcode.  */
			i = lzms_maybe_do_x86_translation(data, i, n,
							  &closest_target_usage,
							  last_target_usages,
							  max_trans_offset,
							  undo);
		} else {
			/* Not a recognized opcode.  */
			i += n;
		}
	}
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
