/*
 * lzms-common.c
 *
 * Code shared between the compressor and decompressor for the LZMS compression
 * format.
 */

/*
 * Copyright (C) 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lzms.h"
#include "wimlib/endianness.h"

static s32
lzms_maybe_do_x86_translation(u8 data[], s32 i, s32 num_op_bytes,
			      s32 *closest_target_usage_p,
			      s32 last_target_usages[], s32 max_trans_offset,
			      bool undo)
{
	u16 pos;

	if (undo) {
		if (i - *closest_target_usage_p <= max_trans_offset) {
			LZMS_DEBUG("Undid x86 translation at position %d "
				   "(opcode 0x%02x)", i, data[i]);
			le32 *p32 = (le32*)&data[i + num_op_bytes];
			u32 n = le32_to_cpu(*p32);
			*p32 = cpu_to_le32(n - i);
		}
		pos = i + le16_to_cpu(*(const le16*)&data[i + num_op_bytes]);
	} else {
		pos = i + le16_to_cpu(*(const le16*)&data[i + num_op_bytes]);

		if (i - *closest_target_usage_p <= max_trans_offset) {
			LZMS_DEBUG("Did x86 translation at position %d "
				   "(opcode 0x%02x)", i, data[i]);
			le32 *p32 = (le32*)&data[i + num_op_bytes];
			u32 n = le32_to_cpu(*p32);
			*p32 = cpu_to_le32(n + i);
		}
	}

	i += num_op_bytes + sizeof(le32) - 1;

	if (i - last_target_usages[pos] <= LZMS_X86_MAX_GOOD_TARGET_OFFSET)
		*closest_target_usage_p = i;

	last_target_usages[pos] = i;

	return i + 1;
}

static s32
lzms_may_x86_translate(const u8 p[], s32 *max_offset_ret)
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
 * @last_target_usages is a temporary array of length >= 65536.
 */
void
lzms_x86_filter(u8 data[], s32 size, s32 last_target_usages[], bool undo)
{
	s32 closest_target_usage = -LZMS_X86_MAX_TRANSLATION_OFFSET - 1;

	for (s32 i = 0; i < 65536; i++)
		last_target_usages[i] = -LZMS_X86_MAX_GOOD_TARGET_OFFSET - 1;

	for (s32 i = 0; i < size - 11; ) {
		s32 max_trans_offset;
		s32 n;

		n = lzms_may_x86_translate(data + i, &max_trans_offset);
		if (max_trans_offset) {
			i = lzms_maybe_do_x86_translation(data, i, n,
							  &closest_target_usage,
							  last_target_usages,
							  max_trans_offset,
							  undo);
		} else {
			i += n;
		}
	}
}
