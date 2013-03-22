/*
 * buffer_io.h
 *
 * A few endianness-aware macros for reading and writing data from in-memory
 * buffers.
 */

#ifndef _WIMLIB_BUFFER_IO_H
#define _WIMLIB_BUFFER_IO_H

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
static inline const void *
get_u8(const void *p, u8 *res)
{
	*res = *(const u8*)p;
	return p + 1;
}

static inline const void *
get_u16(const void *p, u16 *res)
{
	*res = le16_to_cpu(*(const u16*)p);
	return p + 2;
}



static inline const void *
get_u32(const void *p, u32 *res)
{
	*res = le32_to_cpu(*(const u32*)p);
	return p + 4;
}


static inline const void *
get_u56(const void *p, u64 *res)
{
	*res = le64_to_cpu(*(const u64*)p) & 0x00ffffffffffffff;
	return p + 7;
}


static inline const void *
get_u64(const void *p, u64 *res)
{
	*res = le64_to_cpu(*(const u64*)p);
	return p + 8;
}

/* The put_u8, put_u16, put_u32, put_u56, and put_u64 functions take in a
 * pointer to an output location as the first argument and a value for the
 * second argument.  The value of the second argument is written to the output
 * location in little-endian format as the data type indicated in the function
 * name, and a pointer to the output location directory following the bytes
 * written is returned. */
static inline void *
put_u8(void *res, u8 val)
{
	*(u8*)res = val;
	return res + 1;
}

static inline void *
put_u16(void *res, u16 val)
{
	*(uint16_t*)res = cpu_to_le16(val);
	return res + 2;
}

static inline void *
put_u32(void *res, u32 val)
{
	*(uint32_t*)res = cpu_to_le32(val);
	return res + 4;
}

static inline void *
put_u56(void *res, u64 val)
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

static inline void *
put_u64(void *res, u64 val)
{
	*(u64*)res = cpu_to_le64(val);
	return res + 8;
}

static inline const void *
get_bytes(const void *p, size_t num_bytes, void *res)
{
	memcpy(res, p, num_bytes);
	return p + num_bytes;
}

static inline void *
put_zeroes(void *p, size_t num_bytes)
{
	return memset(p, 0, num_bytes) + num_bytes;
}

static inline void *
put_bytes(void *p, size_t num_bytes, const void *input)
{
	return memcpy(p, input, num_bytes) + num_bytes;
}
#endif /* _WIMLIB_BUFFER_IO_H */
