#ifndef _WIMLIB_XPRESS_H
#define _WIMLIB_XPRESS_H

/* Constants for the XPRESS data compression format.  See the comments in
 * xpress-decompress.c for more information about this format.  */

#define XPRESS_NUM_CHARS	256
#define XPRESS_NUM_SYMBOLS	512
#define XPRESS_MAX_CODEWORD_LEN	15

#define XPRESS_END_OF_DATA	256

#define XPRESS_MIN_OFFSET	1
#define XPRESS_MAX_OFFSET	65535

#define XPRESS_MIN_MATCH_LEN	3
#define XPRESS_MAX_MATCH_LEN	65538

#endif /* _WIMLIB_XPRESS_H */
