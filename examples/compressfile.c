/*
 * compressfile.c
 *
 * An example of using wimlib's compression API to compress a file.
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
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <wimlib.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
do_compress(int in_fd, const char *in_filename,
	    int out_fd, const char *out_filename,
	    uint32_t chunk_size, struct wimlib_compressor *compressor)
{
	char *ubuf = malloc(chunk_size);
	char *cbuf = malloc(chunk_size - 1);
	uint64_t chunk_num;

	for (chunk_num = 1; ; chunk_num++) {
		ssize_t bytes_read;
		size_t csize;
		char *out_buf;
		uint32_t out_size;
		uint32_t usize;

		/* Read next chunk of data to compress.  */
		bytes_read = read(in_fd, ubuf, chunk_size);
		if (bytes_read <= 0) {
			if (bytes_read == 0)
				break;
			error(1, errno, "Error reading \"%s\"", in_filename);
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

		printf("Chunk %"PRIu64": %"PRIu32" => %"PRIu32" bytes\n",
		       chunk_num, usize, out_size);

		/* Output the uncompressed chunk size, the compressed chunk
		 * size, then the chunk data.  Note: a real program would need
		 * to output the chunk sizes in consistent endianness.  */
		if (write(out_fd, &usize, sizeof(uint32_t)) != sizeof(uint32_t) ||
		    write(out_fd, &out_size, sizeof(uint32_t)) != sizeof(uint32_t) ||
		    write(out_fd, out_buf, out_size) != out_size)
		{
			error(1, errno, "Error writing to \"%s\"",
			      out_filename);
		}
	}
	free(ubuf);
	free(cbuf);
}

int main(int argc, char **argv)
{
	const char *in_filename;
	const char *out_filename;
	int in_fd;
	int out_fd;
	struct wimlib_compressor *compressor;
	int ctype = WIMLIB_COMPRESSION_TYPE_LZX;
	uint32_t chunk_size = 32768;
	int ret;

	if (argc < 3 || argc > 5) {
		fprintf(stderr, "Usage: %s INFILE OUTFILE "
			"[LZX | XPRESS | LZMS] [chunk size]\n", argv[0]);
		return 2;
	}

	in_filename = argv[1];
	out_filename = argv[2];

	/* Parse compression type (optional)  */
	if (argc >= 4) {
		if (!strcmp(argv[3], "LZX"))
			ctype = WIMLIB_COMPRESSION_TYPE_LZX;
		else if (!strcmp(argv[3], "XPRESS"))
			ctype = WIMLIB_COMPRESSION_TYPE_XPRESS;
		else if (!strcmp(argv[3], "LZMS"))
			ctype = WIMLIB_COMPRESSION_TYPE_LZMS;
		else
			error(1, 0, "Unrecognized compression type \"%s\"", argv[3]);
	}
	/* Parse chunk size (optional).  */
	if (argc >= 5)
		chunk_size = atoi(argv[4]);

	/* Open input file and output file.  */
	in_fd = open(in_filename, O_RDONLY);
	if (in_fd < 0)
		error(1, errno, "Failed to open \"%s\"", in_filename);
	out_fd = open(out_filename, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (out_fd < 0)
		error(1, errno, "Failed to open \"%s\"", out_filename);

	/* Create a compressor for the compression type and chunk size with the
	 * default parameters.  */
	ret = wimlib_create_compressor(ctype, chunk_size, 0, &compressor);
	if (ret != 0)
		error(1, 0, "Failed to create compressor: %s",
		      wimlib_get_error_string(ret));

	uint32_t ctype32 = ctype;
	/* Write compression type and chunk size to the file.  */
	if (write(out_fd, &ctype32, sizeof(uint32_t)) != sizeof(uint32_t) ||
	    write(out_fd, &chunk_size, sizeof(uint32_t)) != sizeof(uint32_t))
	{
		error(1, errno, "Error writing to \"%s\"",
		      out_filename);
	}

	/* Compress and write the data.  */
	do_compress(in_fd, in_filename,
		    out_fd, out_filename,
		    chunk_size, compressor);

	/* Cleanup and return.  */
	if (close(out_fd))
		error(1, errno, "Error closing \"%s\"", out_filename);
	wimlib_free_compressor(compressor);
	return 0;
}
