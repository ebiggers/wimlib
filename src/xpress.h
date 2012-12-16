#ifndef _WIMLIB_XPRESS_H
#define _WIMLIB_XPRESS_H

#include "util.h"

/* See the comments in xpress-decompress.c about the XPRESS format. */

//#define ENABLE_XPRESS_DEBUG
#ifdef ENABLE_XPRESS_DEBUG
#	define XPRESS_DEBUG DEBUG
#else
#	define XPRESS_DEBUG(format, ...)
#endif

#define XPRESS_NUM_CHARS	256
#define XPRESS_NUM_SYMBOLS	512
#define XPRESS_MAX_CODEWORD_LEN	15
#define XPRESS_TABLEBITS	12

#define XPRESS_END_OF_DATA	256

#define XPRESS_MIN_OFFSET	1
#define XPRESS_MAX_OFFSET	65535

#define XPRESS_MIN_MATCH	3
#define XPRESS_MAX_MATCH    	65538

extern int xpress_decompress(const void *__compressed_data, uint compressed_len,
			     void *__uncompressed_data, uint uncompressed_len);

extern int xpress_compress(const void *uncompressed_data, uint uncompressed_len,
			   void *compressed_data, uint *compressed_len_ret);

#endif /* _WIMLIB_XPRESS_H */
