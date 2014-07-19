#ifndef _WIMLIB_DIVSUFSORT_H
#define _WIMLIB_DIVSUFSORT_H

#include "wimlib/types.h"

extern void
divsufsort(const u8 *T, u32 *SA, u32 n, u32 *bucket_A, u32 *bucket_B);

#define DIVSUFSORT_TMP1_LEN (256)	   	/* bucket_A  */
#define DIVSUFSORT_TMP2_LEN (256 * 256)		/* bucket_B  */

#endif /* _WIMLIB_DIVSUFSORT_H */
