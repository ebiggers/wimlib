/*
 * xpress.h
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

#ifndef _WIMLIB_XPRESS_H
#define _WIMLIB_XPRESS_H

#include "util.h"

/* See the comments in xpress-decomp.c about the XPRESS format. */

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

#define XPRESS_MIN_MATCH	3
#define XPRESS_MAX_MATCH    	255

extern int xpress_decompress(const void *__compressed_data, uint compressed_len, 
			     void *__uncompressed_data, uint uncompressed_len);

extern int xpress_compress(const void *uncompressed_data, uint uncompressed_len,
			   void *compressed_data, uint *compressed_len_ret);

#endif /* _WIMLIB_XPRESS_H */
