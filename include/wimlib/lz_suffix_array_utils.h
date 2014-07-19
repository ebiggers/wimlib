#ifndef _WIMLIB_LZ_SUFFIX_ARRAY_UTILS_H
#define _WIMLIB_LZ_SUFFIX_ARRAY_UTILS_H

#include "wimlib/types.h"

#define BUILD_SA_MIN_TMP_LEN (65536 + 256)

extern void
build_SA(u32 *SA, const u8 *T, u32 n, u32 *tmp);

extern void
build_ISA(u32 *ISA, const u32 *SA, u32 n);

extern void
build_LCP(u32 *LCP, const u32 *SA, const u32 *ISA, const u8 *T, u32 n);

#endif /* _WIMLIB_LZ_SUFFIX_ARRAY_UTILS_H */
