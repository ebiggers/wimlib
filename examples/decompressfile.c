/*
 * decompressfile.c
 *
 * An example of using wimlib's compression API to decompress a file compressed
 * with the compressfile.c program.
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
do_decompress(int in_fd, const char *in_filename,
	      int out_fd, const char *out_filename,
	      uint32_t chunk_size, struct wimlib_decompressor *decompressor)
{
	uint64_t chunk_num;

	char *ubuf = malloc(chunk_size);
	char *cbuf = malloc(chunk_size - 1);

	for (chunk_num = 1; ; chunk_num++) {
		ssize_t bytes_read;
		uint32_t usize;
		uint32_t csize;

		/* Read chunk uncompressed and compressed sizes.  */
		bytes_read = read(in_fd, &usize, sizeof(uint32_t));
		if (bytes_read == 0)
			break;

		if (bytes_read != sizeof(uint32_t) ||
		    read(in_fd, &csize, sizeof(uint32_t)) != sizeof(uint32_t))
		{
			error(1, errno, "Error reading \"%s\"", in_filename);
		}

		if (csize > usize || usize > chunk_size)
			error(1, 0, "The data is invalid!");

		if (usize == csize) {
			if (read(in_fd, ubuf, usize) != usize) {
				error(1, errno, "Error reading \"%s\"",
				      in_filename);
			}
		} else {
			if (read(in_fd, cbuf, csize) != csize) {
				error(1, errno, "Error reading \"%s\"",
				      in_filename);
			}

			if (wimlib_decompress(cbuf, csize, ubuf, usize,
					      decompressor))
			{
				error(1, 0, "The compressed data is invalid!");
			}
		}

		printf("Chunk %"PRIu64": %"PRIu32" => %"PRIu32" bytes\n",
		       chunk_num, csize, usize);

		/* Output the uncompressed chunk size, the compressed chunk
		 * size, then the chunk data.  Note: a real program would need
		 * to output the chunk sizes in consistent endianness.  */
		if (write(out_fd, ubuf, usize) != usize)
			error(1, errno, "Error writing to \"%s\"", out_filename);
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
	uint32_t ctype;
	uint32_t chunk_size;
	int ret;
	struct wimlib_decompressor *decompressor;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s INFILE OUTFILE\n", argv[0]);
		return 2;
	}

	in_filename = argv[1];
	out_filename = argv[2];

	/* Open input file and output file.  */
	in_fd = open(in_filename, O_RDONLY);
	if (in_fd < 0)
		error(1, errno, "Failed to open \"%s\"", in_filename);
	out_fd = open(out_filename, O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (out_fd < 0)
		error(1, errno, "Failed to open \"%s\"", out_filename);

	/* Get compression type and chunk size.  */
	if (read(in_fd, &ctype, sizeof(uint32_t)) != sizeof(uint32_t) ||
	    read(in_fd, &chunk_size, sizeof(uint32_t)) != sizeof(uint32_t))
		error(1, errno, "Error reading from \"%s\"", in_filename);

	/* Create a decompressor for the compression type and chunk size with
	 * the default parameters.  */
	ret = wimlib_create_decompressor(ctype, chunk_size, &decompressor);
	if (ret != 0)
		error(1, 0, "Failed to create decompressor: %s",
		      wimlib_get_error_string(ret));

	/* Decompress and write the data.  */
	do_decompress(in_fd, in_filename,
		      out_fd, out_filename,
		      chunk_size, decompressor);

	/* Cleanup and return.  */
	if (close(out_fd))
		error(1, errno, "Error closing \"%s\"", out_filename);
	wimlib_free_decompressor(decompressor);
	return 0;
}
