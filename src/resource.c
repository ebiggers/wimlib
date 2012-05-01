/*
 * resource.c
 *
 * Read uncompressed and compressed metadata and file resources.
 *
 * Copyright (C) 2010 Carl Thijssen
 * Copyright (C) 2012 Eric Biggers
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

#include "wimlib_internal.h"
#include "io.h"
#include "lzx.h"
#include "xpress.h"
#include "dentry.h"
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

	DEBUG2("comp size = %"PRIu64", "
			"uncomp size = %"PRIu64", "
			"res offset = %"PRIu64"\n",
			resource_compressed_size,
			resource_uncompressed_size,
			resource_offset);
	DEBUG2("resource_ctype = %s, len = %"PRIu64", offset = %"PRIu64"\n",
				wimlib_get_compression_type_string(resource_ctype), 
								len, offset);
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
		ERROR("Failed to seek to byte %"PRIu64" "
				"to read chunk table of compressed "
				"resource: %m\n", 
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
		ERROR("Failed to seek to byte %"PRIu64" "
				"to read first chunk of compressed "
				"resource: %m\n", 
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

		DEBUG2("Chunk %"PRIu64" (start %"PRIu64", end %"PRIu64")\n",
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

		DEBUG2("compressed_chunk_size = %u, uncompressed_chunk_size = %u\n",
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

		DEBUG2("start_offset = %u, end_offset = %u\n", start_offset,
					end_offset);
		DEBUG2("partial_chunk_size = %u\n", partial_chunk_size);

		/* This is undocumented, but chunks can be uncompressed.  This
		 * appears to always be the case when the compressed chunk size
		 * is equal to the uncompressed chunk size. */
		if (compressed_chunk_size == uncompressed_chunk_size) {
			/* Probably an uncompressed chunk */

			if (start_offset != 0) {
				if (fseeko(fp, start_offset, SEEK_CUR) != 0) {
					ERROR("Uncompressed partial chunk "
							"fseek() error: %m\n");
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
				DEBUG2("out_p = %p\n");
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
		ERROR("Unexpected EOF in compressed file resource\n");
	else
		ERROR("Error reading compressed file resource: %m\n");
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
				"to read uncompressed resource "
				"(len = %"PRIu64")!\n", offset, len);
		return WIMLIB_ERR_READ;
	}
	if (fread(contents_ret, 1, len, fp) != len) {
		if (feof(fp)) {
			ERROR("Unexpected EOF in uncompressed file resource!\n");
		} else {
			ERROR("Failed to read %"PRIu64" bytes from "
					"uncompressed resource at offset "
					"%"PRIu64"\n", len, offset);
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
			ERROR("Resource with original size %"PRIu64" "
					"bytes is marked as uncompressed, \n",
					resource_original_size);
			ERROR("    but its actual size is %"PRIu64" "
								"bytes!\n",
					resource_size);
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
	if (wim_ctype == WIM_COMPRESSION_TYPE_NONE) {
		return WIM_COMPRESSION_TYPE_NONE;
	} else {
		if (reshdr_flags & WIM_RESHDR_FLAG_COMPRESSED)
			return wim_ctype;
		else
			return WIM_COMPRESSION_TYPE_NONE;
	}
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
 * @res_entry:	The resource entry for the metadata resource (a.k.a the metadata
 * 			for the metadata)
 * @wim_ctype:	The compression type of the WIM file.
 * @root_dentry_p:	A pointer to a pointer to a struct dentry structure into which the 
 * 		root dentry is allocated and returned.
 *
 * @return:	True on success, false on failure.
 */
int read_metadata_resource(FILE *fp, const struct resource_entry *res_entry,
			   int wim_ctype, struct dentry **root_dentry_p)
{
	u8 *buf;
	int ctype;
	u32 dentry_offset;
	int ret;
	struct dentry *dentry;

	DEBUG("Reading metadata resource: length = %lu, offset = %lu\n",
			res_entry->original_size, res_entry->offset);

	if (res_entry->original_size < 8) {
		ERROR("Expected at least 8 bytes for the metadata "
				"resource!\n");
		return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
	}

	/* Allocate memory for the uncompressed metadata resource. */
	buf = MALLOC(res_entry->original_size);

	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for uncompressed "
				"metadata resource!\n",
				res_entry->original_size);
		return WIMLIB_ERR_NOMEM;
	}

	/* Determine the compression type of the metadata resource. */
	ctype = resource_compression_type(wim_ctype, res_entry->flags);

	/* Read the metadata resource into memory.  (It may be compressed.) */
	ret = read_full_resource(fp, res_entry->size, 
				 res_entry->original_size, res_entry->offset, 
				 ctype, buf);
	if (ret != 0)
		goto err1;

	DEBUG("Finished reading metadata resource into memory.\n");

#if 0
	/* Read the security data into a WIMSecurityData structure. */
	if (!read_security_data(buf, res_entry->original_size, sd))
		goto err1;
#endif

	dentry = MALLOC(sizeof(struct dentry));
	if (!dentry) {
		ERROR("Failed to allocate %zu bytes for root dentry!\n",
				sizeof(struct dentry));
		ret = WIMLIB_ERR_NOMEM;
		goto err1;
	}

	/* Read the root directory entry starts after security data, on an
	 * 8-byte aligned address. 
	 *
	 * The security data starts with a 4-byte integer giving its total
	 * length. */
	get_u32(buf, &dentry_offset);
	dentry_offset += (8 - dentry_offset % 8) % 8;
		
	ret = read_dentry(buf, res_entry->original_size, dentry_offset, dentry);
	if (ret != 0)
		goto err1;

	/* This is the root dentry, so set its pointers correctly. */
	dentry->parent = dentry;
	dentry->next   = dentry;
	dentry->prev   = dentry;

	/* Now read the entire directory entry tree. */
	ret = read_dentry_tree(buf, res_entry->original_size, dentry);
	if (ret != 0)
		goto err2;

	/* Calculate the full paths in the dentry tree. */
	ret = for_dentry_in_tree(dentry, calculate_dentry_full_path, NULL);
	if (ret != 0)
		goto err2;

	*root_dentry_p = dentry;
	FREE(buf);
	return ret;
err2:
	free_dentry_tree(dentry, NULL, false);
err1:
	FREE(buf);
	return ret;
}


