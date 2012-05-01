/*
 * io.h
 *
 * A few endianness-aware macros for reading and writing data from in-memory
 * buffers.
 *
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef _WIMLIB_IO_H
#define _WIMLIB_IO_H

#include "util.h"
#include "endianness.h"
#include <string.h>

/* Note that in the WIM format, integers are always in little-endian format. */

/* The get_u8, get_u16, get_u32, get_u56, and get_u64 functions take in a
 * pointer to an input location as the first argument and a pointer to an output
 * location as the second argument.  The data in the input location is copied to
 * the output location, with the size indicated in the function name, in little
 * endian format.  A pointer to the input location directly following the bytes
 * read is returned. */
static inline const u8 *get_u8(const u8 *p, u8 *res)
{
	*res = *p;
	return p + 1;
}


static inline const u8 *get_u16(const u8 *p, u16 *res)
{
	*res = to_le16(*(u16*)p);
	return p + 2;
}



static inline const u8 *get_u32(const u8 *p, u32 *res)
{
	*res = to_le32(*(u32*)p);
	return p + 4;
}


static inline const u8 *get_u56(const u8 *p, u64 *res)
{
	*res = to_le64(*(u64*)p) & 0x00ffffffffffffff;
	return p + 7;
}


static inline const u8 *get_u64(const u8 *p, u64 *res)
{
	*res = to_le64(*(u64*)p);
	return p + 8;
}

/* The put_u8, put_u16, put_u32, put_u56, and put_u64 functions take in a
 * pointer to an output location as the first argument and a value for the
 * second argument.  The value of the second argument is written to the output
 * location in little-endian format as the data type indicated in the function
 * name, and a pointer to the output location directory following the bytes
 * written is returned. */
static inline u8 *put_u8(u8 *res, u8 val)
{
	*res = val;
	return res + 1;
}

static inline u8 *put_u16(u8 *res, u16 val)
{
	*(uint16_t*)res = to_le16(val);
	return res + 2;
}

static inline u8 *put_u32(u8 *res, u32 val)
{
	*(uint32_t*)res = to_le32(val);
	return res + 4;
}

static inline u8 *put_u56(u8 *res, u64 val)
{
	const u8 *__p = (const u8*)&val;
#ifdef WORDS_BIGENDIAN
	res[0] = __p[6];
	res[1] = __p[5];
	res[2] = __p[4];
	res[3] = __p[3];
	res[4] = __p[2];
	res[5] = __p[1];
	res[6] = __p[0];
#else
	memcpy(res, __p, 7);
#endif
	return res + 7;
}

static inline u8 *put_u64(u8 *res, u64 val)
{
	*(u64*)res = to_le64(val);
	return res + 8;
}

static inline const u8 *get_bytes(const u8 *p, size_t num_bytes, void *res)
{
	memcpy(res, p, num_bytes);
	return p + num_bytes;
}

static inline u8 *put_bytes(u8 *p, size_t num_bytes, const u8 *input)
{
	memcpy(p, input, num_bytes);
	return p + num_bytes;
}
#endif /* _WIMLIB_IO_H */
