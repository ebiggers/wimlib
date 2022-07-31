/*
 * decompressfile.c - decompression API example
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
 * This an example of using wimlib's compression API to decompress a file
 * compressed with the compressfile.c program.
 *
 * This program does *not* have anything to do with WIM files other than the
 * fact that this makes use of compression formats that are used in WIM files.
 * This is purely an example of using the compression API.
 *
 * Compile with:
 *
 *    $ gcc decompressfile.c -o decompressfile -lwim
 *
 * Run with:
 *
 *    $ ./decompressfile INFILE OUTFILE
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
#  define TS		"ls"
#  define topen		_wopen
#else
   typedef char		tchar;
#  define TS		"s"
#  define topen		open
#  define O_BINARY	0
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
do_decompress(int in_fd, const tchar *in_filename,
	      int out_fd, const tchar *out_filename,
	      uint32_t chunk_size, struct wimlib_decompressor *decompressor)
{
	uint64_t chunk_num;

	char *ubuf = (char *)malloc(chunk_size);
	char *cbuf = (char *)malloc(chunk_size - 1);

	for (chunk_num = 1; ; chunk_num++) {
		int32_t bytes_read;
		uint32_t usize;
		uint32_t csize;

		/* Read chunk uncompressed and compressed sizes.  */
		bytes_read = read(in_fd, &usize, sizeof(uint32_t));
		if (bytes_read == 0)
			break;

		if (bytes_read != sizeof(uint32_t) ||
		    read(in_fd, &csize, sizeof(uint32_t)) != sizeof(uint32_t))
		{
			fatal_error(errno, "Error reading \"%" TS"\"",
				    in_filename);
		}

		if (csize > usize || usize > chunk_size)
			fatal_error(0, "The data is invalid!");

		if (usize == csize) {
			if (read(in_fd, ubuf, usize) != (int32_t)usize) {
				fatal_error(errno, "Error reading \"%" TS"\"",
					    in_filename);
			}
		} else {
			if (read(in_fd, cbuf, csize) != (int32_t)csize) {
				fatal_error(errno, "Error reading \"%" TS"\"",
					    in_filename);
			}

			if (wimlib_decompress(cbuf, csize, ubuf, usize,
					      decompressor))
			{
				fatal_error(0,
					    "The compressed data is invalid!");
			}
		}

		printf("Chunk %" PRIu64": %" PRIu32" => %" PRIu32" bytes\n",
		       chunk_num, csize, usize);

		/* Output the uncompressed chunk size, the compressed chunk
		 * size, then the chunk data.  Note: a real program would need
		 * to output the chunk sizes in consistent endianness.  */
		if (write(out_fd, ubuf, usize) != (int32_t)usize) {
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
	uint32_t ctype32;
	enum wimlib_compression_type ctype;
	uint32_t chunk_size;
	int ret;
	struct wimlib_decompressor *decompressor;

	if (argc != 3) {
		fprintf(stderr, "Usage: %" TS" INFILE OUTFILE\n", argv[0]);
		return 2;
	}

	in_filename = argv[1];
	out_filename = argv[2];

	/* Open input file and output file.  */
	in_fd = topen(in_filename, O_RDONLY | O_BINARY);
	if (in_fd < 0)
		fatal_error(errno, "Failed to open \"%" TS"\"", in_filename);
	out_fd = topen(out_filename, O_WRONLY | O_TRUNC | O_CREAT | O_BINARY,
		       0644);
	if (out_fd < 0)
		fatal_error(errno, "Failed to open \"%" TS"\"", out_filename);

	/* Get compression type and chunk size.  */
	if (read(in_fd, &ctype32, sizeof(uint32_t)) != sizeof(uint32_t) ||
	    read(in_fd, &chunk_size, sizeof(uint32_t)) != sizeof(uint32_t))
		fatal_error(errno, "Error reading from \"%" TS"\"", in_filename);
	ctype = (enum wimlib_compression_type)ctype32;

	/* Create a decompressor for the compression type and chunk size with
	 * the default parameters.  */
	ret = wimlib_create_decompressor(ctype, chunk_size, &decompressor);
	if (ret != 0)
		fatal_error(0, "Failed to create decompressor: %" TS,
			    wimlib_get_error_string((enum wimlib_error_code)ret));

	/* Decompress and write the data.  */
	do_decompress(in_fd, in_filename,
		      out_fd, out_filename,
		      chunk_size, decompressor);

	/* Cleanup and return.  */
	if (close(out_fd))
		fatal_error(errno, "Error closing \"%" TS"\"", out_filename);
	wimlib_free_decompressor(decompressor);
	return 0;
}
