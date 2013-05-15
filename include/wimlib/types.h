#ifndef _WIMLIB_TYPES_H
#define _WIMLIB_TYPES_H

#include "wimlib_tchar.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef _NTFS_TYPES_H
/* Unsigned integer types of exact size in bits */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Signed integer types of exact size in bits */
typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
#endif

/* A pointer to 'utf16lechar' indicates a UTF-16LE encoded string */
typedef u16 utf16lechar;

#ifndef WIMLIB_WIMSTRUCT_DECLARED
typedef struct WIMStruct WIMStruct;
#  define WIMLIB_WIMSTRUCT_DECLARED
#endif

#endif
