/*
 * unaligned.h
 *
 * Inline functions for unaligned memory accesses.
 *
 * Author:	Eric Biggers
 * Year:	2014, 2015
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#ifndef _WIMLIB_UNALIGNED_H
#define _WIMLIB_UNALIGNED_H

#include "wimlib/compiler.h"
#include "wimlib/endianness.h"
#include "wimlib/types.h"

#define DEFINE_UNALIGNED_TYPE(type)				\
struct type##_unaligned {					\
	type v;							\
} _packed_attribute;						\
								\
static inline type						\
load_##type##_unaligned(const void *p)				\
{								\
	return ((const struct type##_unaligned *)p)->v;		\
}								\
								\
static inline void						\
store_##type##_unaligned(type val, void *p)			\
{								\
	((struct type##_unaligned *)p)->v = val;		\
}

DEFINE_UNALIGNED_TYPE(u16);
DEFINE_UNALIGNED_TYPE(u32);
DEFINE_UNALIGNED_TYPE(u64);
DEFINE_UNALIGNED_TYPE(le16);
DEFINE_UNALIGNED_TYPE(le32);
DEFINE_UNALIGNED_TYPE(le64);
DEFINE_UNALIGNED_TYPE(be16);
DEFINE_UNALIGNED_TYPE(be32);
DEFINE_UNALIGNED_TYPE(be64);
DEFINE_UNALIGNED_TYPE(size_t);
DEFINE_UNALIGNED_TYPE(machine_word_t);

#define load_word_unaligned	load_machine_word_t_unaligned
#define store_word_unaligned	store_machine_word_t_unaligned

static inline u16
get_unaligned_u16_le(const void *p)
{
	u16 v;

	if (UNALIGNED_ACCESS_IS_FAST) {
		v = le16_to_cpu(load_le16_unaligned(p));
	} else {
		const u8 *p8 = p;
		v = 0;
		v |= (u16)p8[0] << 0;
		v |= (u16)p8[1] << 8;
	}
	return v;
}

static inline u32
get_unaligned_u32_le(const void *p)
{
	u32 v;

	if (UNALIGNED_ACCESS_IS_FAST) {
		v = le32_to_cpu(load_le32_unaligned(p));
	} else {
		const u8 *p8 = p;
		v = 0;
		v |= (u32)p8[0] << 0;
		v |= (u32)p8[1] << 8;
		v |= (u32)p8[2] << 16;
		v |= (u32)p8[3] << 24;
	}
	return v;
}

static inline void
put_unaligned_u16_le(u16 v, void *p)
{
	if (UNALIGNED_ACCESS_IS_FAST) {
		store_le16_unaligned(cpu_to_le16(v), p);
	} else {
		u8 *p8 = p;
		p8[0] = (v >> 0) & 0xFF;
		p8[1] = (v >> 8) & 0xFF;
	}
}

static inline void
put_unaligned_u32_le(u32 v, void *p)
{
	if (UNALIGNED_ACCESS_IS_FAST) {
		store_le32_unaligned(cpu_to_le32(v), p);
	} else {
		u8 *p8 = p;
		p8[0] = (v >> 0) & 0xFF;
		p8[1] = (v >> 8) & 0xFF;
		p8[2] = (v >> 16) & 0xFF;
		p8[3] = (v >> 24) & 0xFF;
	}
}

/*
 * Given a 32-bit value that was loaded with the platform's native endianness,
 * return a 32-bit value whose high-order 8 bits are 0 and whose low-order 24
 * bits contain the first 3 bytes, arranged in octets in a platform-dependent
 * order, at the memory location from which the input 32-bit value was loaded.
 */
static inline u32
loaded_u32_to_u24(u32 v)
{
	if (CPU_IS_LITTLE_ENDIAN)
		return v & 0xFFFFFF;
	else
		return v >> 8;
}

/*
 * Load the next 3 bytes from the memory location @p into the 24 low-order bits
 * of a 32-bit value.  The order in which the 3 bytes will be arranged as octets
 * in the 24 bits is platform-dependent.  At least LOAD_U24_REQUIRED_NBYTES
 * bytes must be available at @p; note that this may be more than 3.
 */
static inline u32
load_u24_unaligned(const u8 *p)
{
#if UNALIGNED_ACCESS_IS_FAST
#  define LOAD_U24_REQUIRED_NBYTES 4
	return loaded_u32_to_u24(load_u32_unaligned(p));
#else
#  define LOAD_U24_REQUIRED_NBYTES 3
	return ((u32)p[0] << 0) | ((u32)p[1] << 8) | ((u32)p[2] << 16);
#endif
}


#endif /* _WIMLIB_UNALIGNED_H */
