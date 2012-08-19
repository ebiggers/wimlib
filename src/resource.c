/*
 * resource.c
 *
 * Read uncompressed and compressed metadata and file resources.
 */

/*
 * Copyright (C) 2010 Carl Thijssen
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "wimlib_internal.h"
#include "lookup_table.h"
#include "io.h"
#include "lzx.h"
#include "xpress.h"
#include "sha1.h"
#include "dentry.h"
#include "config.h"
#include <unistd.h>
#include <errno.h>


/* 
 * Reads all or part of a compressed resource into an in-memory buffer.
 *
 * @fp:      		The FILE* for the WIM file.
 * @resource_compressed_size:  	 The compressed size of the resource.  
 * @resource_uncompressed_size:  The uncompressed size of the resource.
 * @resource_offset:		 The offset of the start of the resource from
 * 					the start of the stream @fp.
 * @resource_ctype:	The compression type of the resource. 
 * @len:		The number of bytes of uncompressed data to read from
 * 				the resource.
 * @offset:		The offset of the bytes to read within the uncompressed
 * 				resource.
 * @contents_len:	An array into which the uncompressed data is written.
 * 				It must be at least @len bytes long.
 *
 * Returns zero on success, nonzero on failure.
 */
static int read_compressed_resource(FILE *fp, u64 resource_compressed_size, 
				    u64 resource_uncompressed_size, 
				    u64 resource_offset, int resource_ctype, 
				    u64 len, u64 offset, u8  contents_ret[])
{

	DEBUG2("comp size = %"PRIu64", uncomp size = %"PRIu64", "
	       "res offset = %"PRIu64"",
	       resource_compressed_size,
	       resource_uncompressed_size,
	       resource_offset);
	DEBUG2("resource_ctype = %s, len = %"PRIu64", offset = %"PRIu64"",
	       wimlib_get_compression_type_string(resource_ctype), len, offset);
	/* Trivial case */
	if (len == 0)
		return 0;

	int (*decompress)(const void *, uint, void *, uint);
	/* Set the appropriate decompress function. */
	if (resource_ctype == WIM_COMPRESSION_TYPE_LZX)
		decompress = lzx_decompress;
	else
		decompress = xpress_decompress;

	/* The structure of a compressed resource consists of a table of chunk
	 * offsets followed by the chunks themselves.  Each chunk consists of
	 * compressed data, and there is one chunk for each WIM_CHUNK_SIZE =
	 * 32768 bytes of the uncompressed file, with the last chunk having any
	 * remaining bytes.
	 *
	 * The chunk offsets are measured relative to the end of the chunk
	 * table.  The first chunk is omitted from the table in the WIM file
	 * because its offset is implicitly given by the fact that it directly
	 * follows the chunk table and therefore must have an offset of 0. 
	 */

	/* Calculate how many chunks the resource conists of in its entirety. */
	u64 num_chunks = (resource_uncompressed_size + WIM_CHUNK_SIZE - 1) /
								WIM_CHUNK_SIZE;
	/* As mentioned, the first chunk has no entry in the chunk table. */
	u64 num_chunk_entries = num_chunks - 1;


	/* The index of the chunk that the read starts at. */
	u64 start_chunk = offset / WIM_CHUNK_SIZE;
	/* The byte offset at which the read starts, within the start chunk. */
	u64 start_chunk_offset = offset % WIM_CHUNK_SIZE;

	/* The index of the chunk that contains the last byte of the read. */
	u64 end_chunk   = (offset + len - 1) / WIM_CHUNK_SIZE;
	/* The byte offset of the last byte of the read, within the end chunk */
	u64 end_chunk_offset = (offset + len - 1) % WIM_CHUNK_SIZE;

	/* Number of chunks that are actually needed to read the requested part
	 * of the file. */
	u64 num_needed_chunks = end_chunk - start_chunk + 1;

	/* If the end chunk is not the last chunk, an extra chunk entry is
	 * needed because we need to know the offset of the chunk after the last
	 * chunk read to figure out the size of the last read chunk. */
	if (end_chunk != num_chunks - 1)
		num_needed_chunks++;

	/* Declare the chunk table.  It will only contain offsets for the chunks
	 * that are actually needed for this read. */
	u64 chunk_offsets[num_needed_chunks];

	/* Set the implicit offset of the first chunk if it is included in the
	 * needed chunks.
	 *
	 * Note: M$'s documentation includes a picture that shows the first
	 * chunk starting right after the chunk entry table, labeled as offset
	 * 0x10.  However, in the actual file format, the offset is measured
	 * from the end of the chunk entry table, so the first chunk has an
	 * offset of 0. */
	if (start_chunk == 0)
		chunk_offsets[0] = 0;

	/* According to M$'s documentation, if the uncompressed size of
	 * the file is greater than 4 GB, the chunk entries are 8-byte
	 * integers.  Otherwise, they are 4-byte integers. */
	u64 chunk_entry_size = (resource_uncompressed_size >= (u64)1 << 32) ? 
									8 : 4;

	/* Size of the full chunk table in the WIM file. */
	u64 chunk_table_size = chunk_entry_size * num_chunk_entries;

	/* Read the needed chunk offsets from the table in the WIM file. */

	/* Index, in the WIM file, of the first needed entry in the
	 * chunk table. */
	u64 start_table_idx = (start_chunk == 0) ? 0 : start_chunk - 1;

	/* Number of entries we need to actually read from the chunk
	 * table (excludes the implicit first chunk). */
	u64 num_needed_chunk_entries = (start_chunk == 0) ? 
				num_needed_chunks - 1 : num_needed_chunks;

	/* Skip over unneeded chunk table entries. */
	u64 file_offset_of_needed_chunk_entries = resource_offset + 
				start_table_idx * chunk_entry_size;
	if (fseeko(fp, file_offset_of_needed_chunk_entries, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" to read "
				 "chunk table of compressed resource",
				 file_offset_of_needed_chunk_entries);
		return WIMLIB_ERR_READ;
	}

	/* Number of bytes we need to read from the chunk table. */
	size_t size = num_needed_chunk_entries * chunk_entry_size;

	u8 chunk_tab_buf[size];

	if (fread(chunk_tab_buf, 1, size, fp) != size)
		goto err;

	/* Now fill in chunk_offsets from the entries we have read in
	 * chunk_tab_buf. */

	u64 *chunk_tab_p = chunk_offsets;
	if (start_chunk == 0)
		chunk_tab_p++;

	if (chunk_entry_size == 4) {
		u32 *entries = (u32*)chunk_tab_buf;
		while (num_needed_chunk_entries--)
			*chunk_tab_p++ = to_le32(*entries++);
	} else {
		u64 *entries = (u64*)chunk_tab_buf;
		while (num_needed_chunk_entries--)
			*chunk_tab_p++ = to_le64(*entries++);
	}

	/* Done with the chunk table now.  We must now seek to the first chunk
	 * that is needed for the read. */

	u64 file_offset_of_first_needed_chunk = resource_offset + 
				chunk_table_size + chunk_offsets[0];
	if (fseeko(fp, file_offset_of_first_needed_chunk, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" to read "
				 "first chunk of compressed resource",
				 file_offset_of_first_needed_chunk);
		return WIMLIB_ERR_READ;
	}

	/* Pointer to current position in the output buffer for uncompressed
	 * data. */
	u8 *out_p = (u8*)contents_ret;

	/* Buffer for compressed data.  While most compressed chunks will have a
	 * size much less than WIM_CHUNK_SIZE, WIM_CHUNK_SIZE - 1 is the maximum
	 * size in the worst-case.  This assumption is valid only if chunks that
	 * happen to compress to more than the uncompressed size (i.e. a
	 * sequence of random bytes) are always stored uncompressed. But this seems
	 * to be the case in M$'s WIM files, even though it is undocumented. */
	u8 compressed_buf[WIM_CHUNK_SIZE - 1];


	/* Decompress all the chunks. */
	for (u64 i = start_chunk; i <= end_chunk; i++) {

		DEBUG2("Chunk %"PRIu64" (start %"PRIu64", end %"PRIu64").",
		       i, start_chunk, end_chunk);

		/* Calculate the sizes of the compressed chunk and of the
		 * uncompressed chunk. */
		uint compressed_chunk_size, uncompressed_chunk_size;
		if (i != num_chunks - 1) {
			/* All the chunks except the last one in the resource
			 * expand to WIM_CHUNK_SIZE uncompressed, and the amount
			 * of compressed data for the chunk is given by the
			 * difference of offsets in the chunk offset table. */
			compressed_chunk_size = chunk_offsets[i + 1 - start_chunk] - 
						chunk_offsets[i - start_chunk];
			uncompressed_chunk_size = WIM_CHUNK_SIZE;
		} else {
			/* The last compressed chunk consists of the remaining
			 * bytes in the file resource, and the last uncompressed
			 * chunk has size equal to however many bytes are left-
			 * that is, the remainder of the uncompressed size when
			 * divided by WIM_CHUNK_SIZE. 
			 *
			 * Note that the resource_compressed_size includes the
			 * chunk table, so the size of it must be subtracted. */
			compressed_chunk_size = resource_compressed_size - 
						chunk_table_size -
						chunk_offsets[i - start_chunk];

			uncompressed_chunk_size = resource_uncompressed_size % 
								WIM_CHUNK_SIZE;

			/* If the remainder is 0, the last chunk actually
			 * uncompresses to a full WIM_CHUNK_SIZE bytes. */
			if (uncompressed_chunk_size == 0)
				uncompressed_chunk_size = WIM_CHUNK_SIZE;
		}

		DEBUG2("compressed_chunk_size = %u, "
		       "uncompressed_chunk_size = %u",
		       compressed_chunk_size, uncompressed_chunk_size);


		/* Figure out how much of this chunk we actually need to read */
		u64 start_offset;
		if (i == start_chunk)
			start_offset = start_chunk_offset;
		else
			start_offset = 0;
		u64 end_offset;
		if (i == end_chunk)
			end_offset = end_chunk_offset;
		else
			end_offset = WIM_CHUNK_SIZE - 1;

		u64 partial_chunk_size = end_offset + 1 - start_offset;
		bool is_partial_chunk = (partial_chunk_size != 
						uncompressed_chunk_size);

		DEBUG2("start_offset = %u, end_offset = %u", start_offset,
					end_offset);
		DEBUG2("partial_chunk_size = %u", partial_chunk_size);

		/* This is undocumented, but chunks can be uncompressed.  This
		 * appears to always be the case when the compressed chunk size
		 * is equal to the uncompressed chunk size. */
		if (compressed_chunk_size == uncompressed_chunk_size) {
			/* Probably an uncompressed chunk */

			if (start_offset != 0) {
				if (fseeko(fp, start_offset, SEEK_CUR) != 0) {
					ERROR_WITH_ERRNO("Uncompressed partial "
							 "chunk fseek() error");
					return WIMLIB_ERR_READ;
				}
			}
			if (fread(out_p, 1, partial_chunk_size, fp) != 
					partial_chunk_size)
				goto err;
		} else {
			/* Compressed chunk */
			int ret;

			/* Read the compressed data into compressed_buf. */
			if (fread(compressed_buf, 1, compressed_chunk_size, 
						fp) != compressed_chunk_size)
				goto err;

			/* For partial chunks we must buffer the uncompressed
			 * data because we don't need all of it. */
			if (is_partial_chunk) {
				u8 uncompressed_buf[uncompressed_chunk_size];

				ret = decompress(compressed_buf,
						compressed_chunk_size,
						uncompressed_buf, 
						uncompressed_chunk_size);
				if (ret != 0)
					return WIMLIB_ERR_DECOMPRESSION;
				memcpy(out_p, uncompressed_buf + start_offset,
						partial_chunk_size);
			} else {
				ret = decompress(compressed_buf,
						compressed_chunk_size,
						out_p,
						uncompressed_chunk_size);
				if (ret != 0)
					return WIMLIB_ERR_DECOMPRESSION;
			}
		}

		/* Advance the pointer into the uncompressed output data by the
		 * number of uncompressed bytes that were written.  */
		out_p += partial_chunk_size;
	}

	return 0;

err:
	if (feof(fp))
		ERROR("Unexpected EOF in compressed file resource");
	else
		ERROR_WITH_ERRNO("Error reading compressed file resource");
	return WIMLIB_ERR_READ;
}

/* 
 * Reads uncompressed data from an open file stream.
 */
int read_uncompressed_resource(FILE *fp, u64 offset, u64 len, 
					u8 contents_ret[])
{
	if (fseeko(fp, offset, SEEK_SET) != 0) {
		ERROR("Failed to seek to byte %"PRIu64" of input file "
		      "to read uncompressed resource (len = %"PRIu64")",
		      offset, len);
		return WIMLIB_ERR_READ;
	}
	if (fread(contents_ret, 1, len, fp) != len) {
		if (feof(fp)) {
			ERROR("Unexpected EOF in uncompressed file resource");
		} else {
			ERROR("Failed to read %"PRIu64" bytes from "
			      "uncompressed resource at offset %"PRIu64,
			      len, offset);
		}
		return WIMLIB_ERR_READ;
	}
	return 0;
}


/* 
 * Reads a WIM resource.
 *
 * @fp:  		The FILE* for the WIM file.
 * @resource_size:		The compressed size of the resource.
 * @resource_original_size:	The uncompressed size of the resource.
 * @resource_offset:		The offset of the resource in the stream @fp.
 * @resource_ctype:		The compression type of the resource.
 * 				(WIM_COMPRESSION_TYPE_*)
 * @len:		How many bytes of the resource should be read.
 * @offset:        	The offset within the resource at which the read
 * 				will occur.
 *
 * 			To read the whole file resource, specify offset =
 * 			0 and len = resource_original_size, or call
 * 			read_full_resource().
 *
 * @contents_ret:  	An array, that must have length at least @len,
 * 				into which the uncompressed contents of
 * 				the file resource starting at @offset and 
 * 				continuing for @len bytes will be written.
 *
 * @return:  		Zero on success, nonzero on failure. Failure may be due to
 * 			being unable to read the data from the WIM file at the
 * 			specified length and offset, or it may be due to the
 * 			compressed data (if the data is compressed) being
 * 			invalid.
 */
int read_resource(FILE *fp, u64 resource_size, u64 resource_original_size,
		  u64 resource_offset, int resource_ctype, u64 len, 
		  u64 offset, void *contents_ret)
{
	if (resource_ctype == WIM_COMPRESSION_TYPE_NONE) {
		if (resource_size != resource_original_size) {
			ERROR("Resource with original size %"PRIu64" bytes is "
			      "marked as uncompressed, but its actual size is "
			      "%"PRIu64" bytes", 
			      resource_original_size, resource_size);
			return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
		}
		return read_uncompressed_resource(fp, 
				resource_offset + offset, 
				len, contents_ret);
	} else {
		return read_compressed_resource(fp, resource_size,
				resource_original_size, resource_offset,
				resource_ctype, len, offset, contents_ret);
	}
}


/* 
 * Extracts the first @size bytes file resource specified by @entry to the open
 * file @fd.  Returns nonzero on error.
 *
 * XXX
 * This function is somewhat redundant with uncompress_resource(). The
 * main difference is that this function writes to a file descriptor using
 * low-level calls to write() rather than to a FILE* with fwrite(); also this
 * function allows only up to @size bytes to be extracted.
 */
int extract_resource_to_fd(WIMStruct *w, const struct resource_entry *entry, 
			   int fd, u64 size)
{
	u64 num_chunks;
	u64 n;
	u8 buf[min(size, WIM_CHUNK_SIZE)];
	int res_ctype;
	u64 offset;
	u64 i;
	int ret;

	errno = 0;

	num_chunks = (size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;
	n = WIM_CHUNK_SIZE;
	res_ctype = wim_resource_compression_type(w, entry);
	offset = 0;
	for (i = 0; i < num_chunks; i++) {
		if (i == num_chunks - 1) {
			n = size % WIM_CHUNK_SIZE;
			if (n == 0) {
				n = WIM_CHUNK_SIZE;
			}
		}

		ret = read_resource(w->fp, entry->size, entry->original_size,
				    entry->offset, res_ctype, n, offset, buf);
		if (ret != 0)
			return ret;

		if (full_write(fd, buf, n) != n)
			return WIMLIB_ERR_WRITE;
		offset += n;
	}
	return ret;
}

/* 
 * Copies the file resource specified by the lookup table entry @lte from the
 * input WIM, pointed to by the fp field of the WIMStruct, to the output WIM,
 * pointed to by the out_fp field of the WIMStruct.
 *
 * The output_resource_entry, out_refcnt, and part_number fields of @lte are
 * updated.
 *
 * Metadata resources are not copied (they are handled elsewhere for joining and
 * splitting).
 */
int copy_resource(struct lookup_table_entry *lte, void *w)
{
	if ((lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA) &&
	    !((WIMStruct*)w)->write_metadata) {
		return 0;
	}

	FILE *in_fp = ((WIMStruct*)w)->fp;
	FILE *out_fp = ((WIMStruct*)w)->out_fp;
	int ret;
	u64 size = lte->resource_entry.size;
	u64 offset = lte->resource_entry.offset;
	off_t new_offset = ftello(out_fp);

	if (new_offset == -1)
		return WIMLIB_ERR_WRITE;

	ret = copy_between_files(in_fp, offset, out_fp, size);
	if (ret != 0)
		return ret;

	memcpy(&lte->output_resource_entry, &lte->resource_entry, 
			sizeof(struct resource_entry));

	lte->output_resource_entry.offset = new_offset;
	lte->out_refcnt = lte->refcnt;
	lte->part_number = ((WIMStruct*)w)->hdr.part_number;
	return 0;
}

/* Reads the contents of a struct resource_entry, as represented in the on-disk
 * format, from the memory pointed to by @p, and fills in the fields of @entry.
 * A pointer to the byte after the memory read at @p is returned. */
const u8 *get_resource_entry(const u8 *p, struct resource_entry *entry)
{
	u64 size;
	u8 flags;

	p = get_u56(p, &size);
	p = get_u8(p, &flags);
	entry->size = size;
	entry->flags = flags;
	p = get_u64(p, &entry->offset);
	p = get_u64(p, &entry->original_size);
	return p;
}

/* Copies the struct resource_entry @entry to the memory pointed to by @p in the
 * on-disk format.  A pointer to the byte after the memory written at @p is
 * returned. */
u8 *put_resource_entry(u8 *p, const struct resource_entry *entry)
{
	p = put_u56(p, entry->size);
	p = put_u8(p, entry->flags);
	p = put_u64(p, entry->offset);
	p = put_u64(p, entry->original_size);
	return p;
}

/* Given the compression type for the WIM file as a whole as the flags field of
 * a resource entry, returns the compression type for that resource entry. */
int resource_compression_type(int wim_ctype, int reshdr_flags)
{
	if (wim_ctype != WIM_COMPRESSION_TYPE_NONE &&
	     (reshdr_flags & WIM_RESHDR_FLAG_COMPRESSED))
		return wim_ctype;
	else
		return WIM_COMPRESSION_TYPE_NONE;
}



/*
 * Copies bytes between two file streams.
 *
 * Copies @len bytes from @in_fp to @out_fp, at the current position in @out_fp,
 * and at an offset of @in_offset in @in_fp.
 */
int copy_between_files(FILE *in_fp, off_t in_offset, FILE *out_fp, size_t len)
{
	u8 buf[BUFFER_SIZE];
	size_t n;

	if (fseeko(in_fp, in_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" of "
				 "input file", in_offset);
		return WIMLIB_ERR_READ;
	}
	/* To reduce memory usage and improve speed, read and write BUFFER_SIZE
	 * bytes at a time. */
	while (len != 0) {
		n = min(len, BUFFER_SIZE);
		if (fread(buf, 1, n, in_fp) != n) {
			if (feof(in_fp)) {
				ERROR("Unexpected EOF when copying data "
				      "between files");
			} else {
				ERROR_WITH_ERRNO("Error copying data between "
						 "files");
			}
			return WIMLIB_ERR_READ;
		}

		if (fwrite(buf, 1, n, out_fp) != n) {
			ERROR_WITH_ERRNO("Error copying data between files");
			return WIMLIB_ERR_WRITE;
		}
		len -= n;
	}
	return 0;
}


/* 
 * Uncompresses a WIM file resource and writes it uncompressed to a file stream.
 *
 * @in_fp:          The file stream that contains the file resource.
 * @size:           The size of the resource in the input file.
 * @original_size:  The original (uncompressed) size of the resource. 
 * @offset:	    The offset of the start of the resource in @in.
 * @input_ctype:    The compression type of the resource in @in.
 * @out_fp:	    The file stream to write the file resource to.
 */
static int uncompress_resource(FILE *in_fp, u64 size, u64 original_size,
			       off_t offset, int input_ctype, FILE *out_fp)
{
	int ret;
	u8 buf[WIM_CHUNK_SIZE];
	/* Determine how many compressed chunks the file is divided into. */
	u64 num_chunks;
	u64 i;
	u64 uncompressed_offset;
	u64 uncompressed_chunk_size;
	
	num_chunks = (original_size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;

	for (i = 0; i < num_chunks; i++) {

		uncompressed_offset = i * WIM_CHUNK_SIZE;
		uncompressed_chunk_size = min(WIM_CHUNK_SIZE, original_size -
					      uncompressed_offset);

		ret = read_resource(in_fp, size, original_size, offset,
				    input_ctype, uncompressed_chunk_size, 
				    uncompressed_offset, buf);
		if (ret != 0)
			return ret;

		if (fwrite(buf, 1, uncompressed_chunk_size, out_fp) != 
		      uncompressed_chunk_size) 
		{
			ERROR_WITH_ERRNO("Failed to write file resource");
			return WIMLIB_ERR_WRITE;
		}
	}
	return 0;
}

/* 
 * Transfers a file resource between two files, writing it compressed.  The file
 * resource in the input file may be either compressed or uncompressed.
 * Alternatively, the input resource may be in-memory, but it must be
 * uncompressed.
 *
 * @in_fp:	            The file stream that contains the file resource.  Ignored
 * 			if uncompressed_resource != NULL.
 * @uncompressed_resource:	If this pointer is not NULL, it points to an
 * 					array of @original_size bytes that are
 * 					the uncompressed input resource.
 * @size:           The size of the resource in the input file.
 * @original_size:  The original (uncompressed) size of the resource. 
 * @offset:	    The offset of the start of the resource in @in.  Ignored
 * 			if uncompressed_resource != NULL.
 * @input_ctype:    The compression type of the resource in @in.  Ignored if
 * 			uncompressed_resource != NULL.
 * @out_fp:	    The file stream to write the file resource to.
 * @output_type:    The compression type to use when writing the resource to
 * 			@out.
 * @new_size_ret:   A location into which the new compressed size of the file
 * 			resource in returned.
 */
static int recompress_resource(FILE *in_fp, const u8 *uncompressed_resource, 
			       u64 size, u64 original_size,
			       off_t offset, int input_ctype, FILE *out_fp,
			       int output_ctype, u64 *new_size_ret)
{
	int ret;
	int (*compress)(const void *, uint, void *, uint *);
	if (output_ctype == WIM_COMPRESSION_TYPE_LZX)
		compress = lzx_compress;
	else
		compress = xpress_compress;

	u8 uncompressed_buf[WIM_CHUNK_SIZE];
	u8 compressed_buf[WIM_CHUNK_SIZE - 1];

	/* Determine how many compressed chunks the file needs to be divided
	 * into. */
	u64 num_chunks = (original_size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;

	u64 num_chunk_entries = num_chunks - 1;

	/* Size of the chunk entries--- 8 bytes for files over 4GB, otherwise 4
	 * bytes */
	uint chunk_entry_size = (original_size >= (u64)1 << 32) ? 8 : 4;

	/* Array in which to construct the chunk offset table. */
	u64 chunk_offsets[num_chunk_entries];

	/* Offset of the start of the chunk table in the output file. */
	off_t chunk_tab_offset = ftello(out_fp);

	if (chunk_tab_offset == -1) {
		ERROR_WITH_ERRNO("Failed to get offset of output file");
		return WIMLIB_ERR_WRITE;
	}

	/* Total size of the chunk table (as written to the file) */
	u64 chunk_tab_size = chunk_entry_size * num_chunk_entries;

	/* Reserve space for the chunk table. */
	if (fwrite(chunk_offsets, 1, chunk_tab_size, out_fp) !=
	      chunk_tab_size)
	{
		ERROR_WITH_ERRNO("Failed to write chunk offset table");
		return WIMLIB_ERR_WRITE;
	}

	/* Read each chunk of the file, compress it, write it to the output
	 * file, and update th chunk offset table. */
	u64 cur_chunk_offset = 0;
	for (u64 i = 0; i < num_chunks; i++) {

		u64 uncompressed_offset = i * WIM_CHUNK_SIZE;
		u64 uncompressed_chunk_size = min(WIM_CHUNK_SIZE, 
					original_size - uncompressed_offset);

		const u8 *uncompressed_p;
		if (uncompressed_resource != NULL) {
			uncompressed_p = uncompressed_resource + 
					 uncompressed_offset;

		} else {
			/* Read chunk i of the file into uncompressed_buf. */
			ret = read_resource(in_fp, size, original_size, offset,
					    input_ctype,
					    uncompressed_chunk_size, 
					    uncompressed_offset, 
					    uncompressed_buf);
			if (ret != 0)
				return ret;
			uncompressed_p = uncompressed_buf;
		}

		if (i != 0)
			chunk_offsets[i - 1] = cur_chunk_offset;

		uint compressed_len;

		ret = compress(uncompressed_p, uncompressed_chunk_size, 
			       compressed_buf, &compressed_len);

		/* if compress() returned nonzero, the compressed chunk would
		 * have been at least as large as the uncompressed chunk.  In
		 * this situation, the WIM format requires that the uncompressed
		 * chunk be written instead. */
		const u8 *buf_to_write;
		uint len_to_write;
		if (ret == 0) {
			buf_to_write = compressed_buf;
			len_to_write = compressed_len;
		} else {
			buf_to_write = uncompressed_p;
			len_to_write = uncompressed_chunk_size;
		}

		if (fwrite(buf_to_write, 1, len_to_write, out_fp) !=
		      len_to_write)
		{
			ERROR_WITH_ERRNO("Failed to write compressed "
					 "file resource");
			return WIMLIB_ERR_WRITE;
		}
		cur_chunk_offset += len_to_write;
	}

	/* The chunk offset after the last chunk, plus the size of the chunk
	 * table, gives the total compressed size of the resource. */
	*new_size_ret = cur_chunk_offset + chunk_tab_size;

	/* Now that all entries of the chunk table are determined, rewind the
	 * stream to where the chunk table was, and write it back out. */

	if (fseeko(out_fp, chunk_tab_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to beginning of chunk table");
		return WIMLIB_ERR_READ;
	}

	if (chunk_entry_size == 8) {
		array_to_le64(chunk_offsets, num_chunk_entries);
	} else {
		for (u64 i = 0; i < num_chunk_entries; i++)
			((u32*)chunk_offsets)[i] = to_le32(chunk_offsets[i]);
	}
	if (fwrite(chunk_offsets, 1, chunk_tab_size, out_fp) != chunk_tab_size)
	{
		ERROR_WITH_ERRNO("Failed to write chunk table");
		return WIMLIB_ERR_WRITE;
	}

	if (fseeko(out_fp, 0, SEEK_END) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to end of output file");
		return WIMLIB_ERR_WRITE;
	}

	return 0;
}

int write_resource_from_memory(const u8 resource[], int out_ctype,
			       u64 resource_original_size, FILE *out_fp,
			       u64 *resource_size_ret)
{
	if (out_ctype == WIM_COMPRESSION_TYPE_NONE) {
		if (fwrite(resource, 1, resource_original_size, out_fp) != 
		      resource_original_size)
		{
			ERROR_WITH_ERRNO("Failed to write resource of length "
					 "%"PRIu64, resource_original_size);
			return WIMLIB_ERR_WRITE;
		}
		*resource_size_ret = resource_original_size;
		return 0;
	} else {
		return recompress_resource(NULL, resource,
					   resource_original_size,
					   resource_original_size, 0, 0, out_fp,
					   out_ctype, resource_size_ret);
	}
}


/* 
 * Transfers a file resource from a FILE* opened for reading to a FILE* opened
 * for writing, possibly changing the compression type. 
 *
 * @in_fp:		The FILE* that contains the file resource.
 * @size:		The (compressed) size of the file resource.
 * @original_size:	The uncompressed size of the file resource.
 * @offset:		The offset of the file resource in the input file.
 * @input_ctype:	The compression type of the file resource in the input
 * 				file.
 * @out_fp:		The FILE* for the output file.  The file resource is 
 * 				written at the current position of @out.
 * @output_ctype:	The compression type to which the file resource will be
 * 				converted.
 * @output_res_entry:	A pointer to a resource entry that, upon successful
 * 				return of this function,  will have the size,
 * 				original size, offset, and flags fields filled
 * 				in for the file resource written to the output
 * 				file.
 */
static int transfer_file_resource(FILE *in_fp, u64 size, u64 original_size,
				  off_t offset, int input_ctype, FILE *out_fp,
				  int output_ctype,
				  struct resource_entry *output_res_entry)
{
	int ret;

	/* Handle zero-length files */
	if (original_size == 0) {
		memset(output_res_entry, 0, sizeof(*output_res_entry));
		return 0;
	}

	/* Get current offset in the output file. */
	off_t out_offset = ftello(out_fp);
	if (out_offset == -1) {
		ERROR_WITH_ERRNO("Failed to get output position");
		return WIMLIB_ERR_WRITE;
	}
	output_res_entry->offset = (u64)out_offset;

	if (output_ctype == input_ctype) {
		/* The same compression types; simply copy the resource. */

		ret = copy_between_files(in_fp, offset, out_fp, size);
		if (ret != 0)
			return ret;
		output_res_entry->size = size;
	} else {
		/* Different compression types. */

		if (output_ctype == WIM_COMPRESSION_TYPE_NONE) {
			/* Uncompress a compressed file resource */
			ret = uncompress_resource(in_fp, size,
						  original_size, offset, 
						  input_ctype, out_fp);
			if (ret != 0)
				return ret;
			output_res_entry->size = original_size;
		} else {
			u64 new_size;
			/* Compress an uncompressed file resource, or compress a
			 * compressed file resource using a different
			 * compression type */
			ret = recompress_resource(in_fp, NULL, size,
						  original_size,
						  offset, input_ctype, out_fp,
						  output_ctype, &new_size);
			if (ret != 0)
				return ret;
			output_res_entry->size = new_size;
		}

	}

	output_res_entry->original_size = original_size;
	if (output_ctype == WIM_COMPRESSION_TYPE_NONE)
		output_res_entry->flags = 0;
	else
		output_res_entry->flags = WIM_RESHDR_FLAG_COMPRESSED;
	return 0;
}

/* 
 * Reads the metadata metadata resource from the WIM file.  The metadata
 * resource consists of the security data, followed by the directory entry for
 * the root directory, followed by all the other directory entries in the
 * filesystem.  The subdir_offset field of each directory entry gives the start
 * of its child entries from the beginning of the metadata resource.  An
 * end-of-directory is signaled by a directory entry of length '0', really of
 * length 8, because that's how long the 'length' field is.
 *
 * @fp:		The FILE* for the input WIM file.
 * @wim_ctype:	The compression type of the WIM file.
 * @imd:	Pointer to the image metadata structure.  Its
 *		`lookup_table_entry' member specifies the lookup table entry for
 *		the metadata resource.  The rest of the image metadata entry
 *		will be filled in by this function.
 *
 * @return:	Zero on success, nonzero on failure.
 */
int read_metadata_resource(FILE *fp, int wim_ctype, struct image_metadata *imd)
{
	u8 *buf;
	int ctype;
	u32 dentry_offset;
	int ret;
	const struct resource_entry *res_entry;
	struct dentry *dentry;
	struct wim_security_data *sd;
	struct link_group_table *lgt;

	res_entry = &imd->metadata_lte->resource_entry;

	DEBUG("Reading metadata resource: length = %"PRIu64", "
	      "offset = %"PRIu64"",
	      res_entry->original_size, res_entry->offset);

	if (res_entry->original_size < 8) {
		ERROR("Expected at least 8 bytes for the metadata resource");
		return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
	}

	/* Allocate memory for the uncompressed metadata resource. */
	buf = MALLOC(res_entry->original_size);

	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for uncompressed "
		      "metadata resource", res_entry->original_size);
		return WIMLIB_ERR_NOMEM;
	}

	/* Determine the compression type of the metadata resource. */
	ctype = resource_compression_type(wim_ctype, res_entry->flags);

	/* Read the metadata resource into memory.  (It may be compressed.) */
	ret = read_full_resource(fp, res_entry->size, 
				 res_entry->original_size, res_entry->offset, 
				 ctype, buf);
	if (ret != 0)
		goto out_free_buf;

	DEBUG("Finished reading metadata resource into memory.");

	/* The root directory entry starts after security data, on an 8-byte
	 * aligned address. 
	 *
	 * The security data starts with a 4-byte integer giving its total
	 * length. */

	/* Read the security data into a wim_security_data structure. */
	ret = read_security_data(buf, res_entry->original_size, &sd);
	if (ret != 0)
		goto out_free_buf;

	dentry = MALLOC(sizeof(struct dentry));
	if (!dentry) {
		ERROR("Failed to allocate %zu bytes for root dentry",
		      sizeof(struct dentry));
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_security_data;
	}

	get_u32(buf, &dentry_offset);
	if (dentry_offset == 0)
		dentry_offset = 8;
	dentry_offset = (dentry_offset + 7) & ~7;
		
	ret = read_dentry(buf, res_entry->original_size, dentry_offset, dentry);
	/* This is the root dentry, so set its pointers correctly. */
	dentry->parent = dentry;
	dentry->next   = dentry;
	dentry->prev   = dentry;
	if (ret != 0)
		goto out_free_dentry_tree;

	/* Now read the entire directory entry tree. */
	ret = read_dentry_tree(buf, res_entry->original_size, dentry);
	if (ret != 0)
		goto out_free_dentry_tree;

	/* Calculate the full paths in the dentry tree. */
	ret = for_dentry_in_tree(dentry, calculate_dentry_full_path, NULL);
	if (ret != 0)
		goto out_free_dentry_tree;

	lgt = new_link_group_table(9001);
	if (!lgt)
		goto out_free_dentry_tree;
	ret = for_dentry_in_tree(dentry, link_group_table_insert, lgt);
	if (ret != 0)
		goto out_free_lgt;

	ret = link_groups_free_duplicate_data(lgt);
	if (ret != 0)
		goto out_free_lgt;

	imd->lgt           = lgt;
	imd->security_data = sd;
	imd->root_dentry   = dentry;
	goto out_free_buf;
out_free_lgt:
	free_link_group_table(lgt);
out_free_dentry_tree:
	free_dentry_tree(dentry, NULL, false);
out_free_security_data:
	free_security_data(sd);
out_free_buf:
	FREE(buf);
	return ret;
}

/* Write the metadata resource for the current image. */
int write_metadata_resource(WIMStruct *w)
{
	FILE *out;
	u8 *buf;
	u8 *p;
	int ret;
	u64 subdir_offset;
	struct dentry *root;
	struct lookup_table_entry *lte;
	struct resource_entry *res_entry;
	off_t metadata_offset;
	u64 metadata_original_size;
	u64 metadata_compressed_size;
	int metadata_ctype;
	u8  hash[WIM_HASH_SIZE];

	DEBUG("Writing metadata resource for image %d", w->current_image);

	out = w->out_fp;
	root = wim_root_dentry(w);
	metadata_ctype = wimlib_get_compression_type(w);
	metadata_offset = ftello(out);
	if (metadata_offset == -1)
		return WIMLIB_ERR_WRITE;

	struct wim_security_data *sd = wim_security_data(w);
	if (sd)
		subdir_offset = sd->total_length + root->length + 8;
	else
		subdir_offset = 8 + root->length + 8;
	calculate_subdir_offsets(root, &subdir_offset);
	metadata_original_size = subdir_offset;
	buf = MALLOC(metadata_original_size);
	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for "
		      "metadata resource", metadata_original_size);
		return WIMLIB_ERR_NOMEM;
	}

	p = write_security_data(sd, buf);

	DEBUG("Writing dentry tree.");
	p = write_dentry_tree(root, p);

	/* Like file resources, the lookup table entry for a metadata resource
	 * uses for the hash code a SHA1 message digest of its uncompressed
	 * contents. */
	sha1_buffer(buf, metadata_original_size, hash);

	ret = write_resource_from_memory(buf, 
					 metadata_ctype,
					 metadata_original_size, 
					 out,
					 &metadata_compressed_size);
	FREE(buf);
	if (ret != 0)
		return ret;

	/* Update the lookup table entry, including the hash and output resource
	 * entry fields, for this image's metadata resource.  */
	lte = wim_metadata_lookup_table_entry(w);
	res_entry = &lte->output_resource_entry;
	lte->out_refcnt++;
	if (memcmp(hash, lte->hash, WIM_HASH_SIZE) != 0) {
		lookup_table_unlink(w->lookup_table, lte);
		memcpy(lte->hash, hash, WIM_HASH_SIZE);
		lookup_table_insert(w->lookup_table, lte);
	}
	res_entry->original_size = metadata_original_size;
	res_entry->offset        = metadata_offset;
	res_entry->size          = metadata_compressed_size;
	res_entry->flags         = WIM_RESHDR_FLAG_METADATA;
	if (metadata_ctype != WIM_COMPRESSION_TYPE_NONE)
		res_entry->flags |= WIM_RESHDR_FLAG_COMPRESSED;
	return 0;
}

static int write_file_resource(WIMStruct *w, const u8 hash[])
{
	/* Get the lookup entry for the file resource. */
	struct lookup_table_entry *lte;
	
	lte = __lookup_resource(w->lookup_table, hash);
	if (!lte)
		return 0;

	/* No need to write file resources twice. */
	if (++lte->out_refcnt != 1)
		return 0;

	/* do not write empty resources */
	if (lte->resource_entry.original_size == 0)
		return 0;

	int out_wim_ctype = wimlib_get_compression_type(w);
	struct resource_entry *output_res_entry = &lte->output_resource_entry;
	u64 len;
	FILE *in_fp;
	FILE *out_fp = w->out_fp;
	int ret = 0;

	/* Figure out if we can read the resource from the WIM file, or
	 * if we have to read it from the filesystem outside, or if it's a
	 * symbolic link with the data already in memory pointed to by a field
	 * of the lookup table entry. */
	if (lte->is_symlink) {
		off_t offset = ftello(w->out_fp);
		u64 new_size;

		if (offset == -1) {
			ERROR_WITH_ERRNO("Could not get position in output "
					 "file");
			return WIMLIB_ERR_WRITE;
		}

		wimlib_assert(lte->symlink_buf);

		len = lte->resource_entry.original_size;

		ret = recompress_resource(NULL, lte->symlink_buf, len, len, 0,
					  0, out_fp, out_wim_ctype, &new_size);
		output_res_entry->size = new_size;
		output_res_entry->original_size = len;
		output_res_entry->offset = offset;
		output_res_entry->flags = (out_wim_ctype == WIM_COMPRESSION_TYPE_NONE)
						? 0 : WIM_RESHDR_FLAG_COMPRESSED;
	} else if (lte->file_on_disk) {

		/* Read from disk (uncompressed) */

		len = lte->resource_entry.original_size;

		in_fp = fopen(lte->file_on_disk, "rb");
		if (!in_fp) {
			ERROR_WITH_ERRNO("Failed to open the file `%s'",
					 lte->file_on_disk);
			return WIMLIB_ERR_OPEN;
		}

		ret = transfer_file_resource(in_fp, len, len, 0,
					     WIM_COMPRESSION_TYPE_NONE, out_fp,
					     out_wim_ctype, output_res_entry);
		fclose(in_fp);
	} else {
		int in_wim_ctype;

		/* Read from input WIM (possibly compressed) */

		/* It may be a different WIM file, in the case of
		 * exporting images from one WIM file to another */
		if (lte->other_wim_fp) {
			/* Different WIM file. */
			in_fp = lte->other_wim_fp;
			in_wim_ctype = lte->other_wim_ctype;
		} else {
			/* Same WIM file. */
			in_fp = w->fp;
			in_wim_ctype = out_wim_ctype;
		}
		int input_res_ctype = resource_compression_type(
						in_wim_ctype, 
						lte->resource_entry.flags);

		ret = transfer_file_resource(in_fp,
					     lte->resource_entry.size,
					     lte->resource_entry.original_size, 
					     lte->resource_entry.offset,
					     input_res_ctype, 
					     out_fp,
					     out_wim_ctype,
					     output_res_entry);
	}
	return ret;
}

/* 
 * Writes a dentry's resources to the output file. 
 *
 * @dentry:  The dentry for the file resource.
 * @wim_p:   A pointer to the WIMStruct.  The fields of interest to this
 * 	     function are the input and output file streams and the lookup
 * 	     table, and the alternate data streams.
 *
 * @return zero on success, nonzero on failure. 
 */
int write_dentry_resources(struct dentry *dentry, void *wim_p)
{
	WIMStruct *w = wim_p;
	int ret;

	/* Directories don't need file resources. */
	if (dentry_is_directory(dentry))
		return 0;

	ret = write_file_resource(w, dentry->hash);
	if (ret != 0)
		return ret;
	for (u16 i = 0; i < dentry->num_ads; i++) {
		ret = write_file_resource(w, dentry->ads_entries[i].hash);
		if (ret != 0)
			return ret;
	}
	return 0;
}

