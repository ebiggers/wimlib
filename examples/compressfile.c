/*
 * compressfile.c - compression API example
 *
 * Copyright 2022 Eric Biggers
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * This an example of using wimlib's compression API to compress a file.
 *
 * This program does *not* have anything to do with WIM files other than the
 * fact that this makes use of compression formats that are used in WIM files.
 * This is purely an example of using the compression API.
 *
 * Compile with:
 *
 *    $ gcc compressfile.c -o compressfile -lwim
 *
 * Run with:
 *
 *    $ ./compressfile INFILE OUTFILE [LZX | XPRESS | LZMS] [chunk size]
 *
 *
 * Use the decompressfile.c program to decompress the file.
 *
 * For example:
 *
 *    $ ./compressfile book.txt book.txt.lzms LZMS 1048576
 *    $ rm -f book.txt
 *    $ ./decompressfile book.txt.lzms book.txt
 *
 * The compressed file format created here is simply a series of compressed
 * chunks.  A real format would need to have checksums and other metadata.
 */

#define _FILE_OFFSET_BITS 64

#if defined(_MSC_VER) && _MSC_VER < 1800 /* VS pre-2013? */
#  define PRIu64 "I64u"
#  define PRIu32 "u"
#else
#  define __STDC_FORMAT_MACROS 1
#  include <inttypes.h>
#endif

#include <wimlib.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#  include <io.h>
#else
#  include <unistd.h>
#endif

/*
 * Windows compatibility defines for string encoding.  Applications using wimlib
 * that need to run on both UNIX and Windows will need to do something similar
 * to this, whereas applications that only need to run on one or the other can
 * just use their platform's convention directly.
 */
#ifdef _WIN32
#  define main		wmain
   typedef wchar_t	tchar;
#  define _T(text)	L##text
#  define T(text)	_T(text)
#  define TS		"ls"
#  define topen		_wopen
#  define tstrcmp	wcscmp
#  define tstrtol	wcstol
#else
   typedef char		tchar;
#  define T(text)	text
#  define TS		"s"
#  define topen		open
#  define O_BINARY	0
#  define tstrcmp	strcmp
#  define tstrtol	strtol
#endif

static void
fatal_error(int err, const char *format, ...)
{
	va_list va;

	va_start(va, format);
	vfprintf(stderr, format, va);
	if (err != 0)
		fprintf(stderr, ": %s\n", strerror(err));
	else
		fputc('\n', stderr);
	va_end(va);
	exit(1);
}

static void
do_compress(int in_fd, const tchar *in_filename,
	    int out_fd, const tchar *out_filename,
	    uint32_t chunk_size, struct wimlib_compressor *compressor)
{
	char *ubuf = (char *)malloc(chunk_size);
	char *cbuf = (char *)malloc(chunk_size - 1);
	uint64_t chunk_num;

	for (chunk_num = 1; ; chunk_num++) {
		int32_t bytes_read;
		size_t csize;
		char *out_buf;
		uint32_t out_size;
		uint32_t usize;

		/* Read next chunk of data to compress.  */
		bytes_read = read(in_fd, ubuf, chunk_size);
		if (bytes_read <= 0) {
			if (bytes_read == 0)
				break;
			fatal_error(errno, "Error reading \"%" TS"\"",
				    in_filename);
		}

		/* Compress the chunk.  */
		usize = bytes_read;

		csize = wimlib_compress(ubuf, usize, cbuf, usize - 1, compressor);
		if (csize != 0) {
			/* Chunk was compressed; use the compressed data.  */
			out_buf = cbuf;
			out_size = csize;
		} else {
			/* Chunk did not compress to less than original size;
			 * use the uncompressed data.  */
			out_buf = ubuf;
			out_size = usize;
		}

		printf("Chunk %" PRIu64": %" PRIu32" => %" PRIu32" bytes\n",
		       chunk_num, usize, out_size);

		/* Output the uncompressed chunk size, the compressed chunk
		 * size, then the chunk data.  Note: a real program would need
		 * to output the chunk sizes in consistent endianness.  */
		if (write(out_fd, &usize, sizeof(uint32_t)) != sizeof(uint32_t) ||
		    write(out_fd, &out_size, sizeof(uint32_t)) != sizeof(uint32_t) ||
		    write(out_fd, out_buf, out_size) != (int32_t)out_size)
		{
			fatal_error(errno, "Error writing to \"%" TS"\"",
				    out_filename);
		}
	}
	free(ubuf);
	free(cbuf);
}

int main(int argc, tchar **argv)
{
	const tchar *in_filename;
	const tchar *out_filename;
	int in_fd;
	int out_fd;
	struct wimlib_compressor *compressor;
	enum wimlib_compression_type ctype = WIMLIB_COMPRESSION_TYPE_LZX;
	uint32_t ctype32;
	uint32_t chunk_size = 32768;
	int ret;

	if (argc < 3 || argc > 5) {
		fprintf(stderr, "Usage: %" TS" INFILE OUTFILE "
			"[LZX | XPRESS | LZMS] [chunk size]\n", argv[0]);
		return 2;
	}

	in_filename = argv[1];
	out_filename = argv[2];

	/* Parse compression type (optional)  */
	if (argc >= 4) {
		if (!tstrcmp(argv[3], T("LZX")))
			ctype = WIMLIB_COMPRESSION_TYPE_LZX;
		else if (!tstrcmp(argv[3], T("XPRESS")))
			ctype = WIMLIB_COMPRESSION_TYPE_XPRESS;
		else if (!tstrcmp(argv[3], T("LZMS")))
			ctype = WIMLIB_COMPRESSION_TYPE_LZMS;
		else
			fatal_error(0,
				    "Unrecognized compression type \"%" TS"\"",
				    argv[3]);
	}
	/* Parse chunk size (optional).  */
	if (argc >= 5)
		chunk_size = tstrtol(argv[4], NULL, 10);

	/* Open input file and output file.  */
	in_fd = topen(in_filename, O_RDONLY | O_BINARY);
	if (in_fd < 0)
		fatal_error(errno, "Failed to open \"%" TS"\"", in_filename);
	out_fd = topen(out_filename, O_WRONLY | O_TRUNC | O_CREAT | O_BINARY,
		       0644);
	if (out_fd < 0)
		fatal_error(errno, "Failed to open \"%" TS"s\"", out_filename);

	/* Create a compressor for the compression type and chunk size with the
	 * default parameters.  */
	ret = wimlib_create_compressor(ctype, chunk_size, 0, &compressor);
	if (ret != 0)
		fatal_error(0, "Failed to create compressor: %" TS,
			    wimlib_get_error_string((enum wimlib_error_code)ret));

	ctype32 = (uint32_t)ctype;
	/* Write compression type and chunk size to the file.  */
	if (write(out_fd, &ctype32, sizeof(uint32_t)) != sizeof(uint32_t) ||
	    write(out_fd, &chunk_size, sizeof(uint32_t)) != sizeof(uint32_t))
	{
		fatal_error(errno, "Error writing to \"%" TS"\"", out_filename);
	}

	/* Compress and write the data.  */
	do_compress(in_fd, in_filename,
		    out_fd, out_filename,
		    chunk_size, compressor);

	/* Cleanup and return.  */
	if (close(out_fd))
		fatal_error(errno, "Error closing \"%" TS"\"", out_filename);
	wimlib_free_compressor(compressor);
	return 0;
}
