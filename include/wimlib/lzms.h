#ifndef _WIMLIB_LZMS_H
#define _WIMLIB_LZMS_H

int
lzms_decompress(const void *cdata, unsigned clen, void *udata, unsigned unlen,
		unsigned window_size);

#endif
