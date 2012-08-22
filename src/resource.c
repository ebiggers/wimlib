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
#include <alloca.h>


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

static int __read_wim_resource(const struct lookup_table_entry *lte,
		      	       u8 buf[], size_t size, u64 offset, bool raw)
{
	wimlib_assert(offset + size <= wim_resource_size(lte));
	int ctype;
	int ret;
	FILE *fp;
	switch (lte->resource_location) {
	case RESOURCE_IN_WIM:
		wimlib_assert(lte->wim);
		wimlib_assert(lte->wim->fp);
		ctype = wim_resource_compression_type(lte);
		if (ctype == WIM_COMPRESSION_TYPE_NONE &&
		     lte->resource_entry.original_size !=
		      lte->resource_entry.size) {
			ERROR("WIM resource at offset %"PRIu64", size %"PRIu64
			      "has an original size of %"PRIu64", but is "
			      "uncompressed",
			      lte->resource_entry.offset,
			      lte->resource_entry.size,
			      lte->resource_entry.original_size);
			return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
		}
		if (raw || ctype == WIM_COMPRESSION_TYPE_NONE)
			return read_uncompressed_resource(lte->wim->fp,
							  offset, size, buf);
		else
			return read_compressed_resource(lte->wim->fp,
							lte->resource_entry.size,
							lte->resource_entry.original_size,
							lte->resource_entry.offset,
							ctype, size, offset, buf);
		break;
	case RESOURCE_IN_STAGING_FILE:
		wimlib_assert(lte->staging_file_name);
		wimlib_assert(0);
		break;
	case RESOURCE_IN_FILE_ON_DISK:
		wimlib_assert(lte->file_on_disk);
		if (lte->file_on_disk_fp) {
			fp = lte->file_on_disk_fp;
		} else {
			fp = fopen(lte->file_on_disk, "rb");
			if (!fp) {
				ERROR_WITH_ERRNO("Failed to open the file "
						 "`%s'", lte->file_on_disk);
			}
		}
		ret = read_uncompressed_resource(lte->file_on_disk_fp,
						 offset, size, buf);
		if (fp != lte->file_on_disk_fp)
			fclose(fp);
		return ret;
		break;
	case RESOURCE_IN_ATTACHED_BUFFER:
		wimlib_assert(lte->attached_buffer);
		memcpy(buf, lte->attached_buffer + offset, size);
		return 0;
		break;
	default:
		assert(0);
	}
}

int read_wim_resource(const struct lookup_table_entry *lte, u8 buf[],
		      size_t size, u64 offset)
{
	return __read_wim_resource(lte, buf, size, offset, false);
}

int read_full_wim_resource(const struct lookup_table_entry *lte, u8 buf[])
{
	return __read_wim_resource(lte, buf, lte->resource_entry.original_size,
				   0, false);
}

struct chunk_table {
	off_t file_offset;
	u64 num_chunks;
	u64 original_resource_size;
	u64 bytes_per_chunk_entry;
	u64 table_disk_size;
	u64 cur_offset;
	u64 *cur_offset_p;
	u64 offsets[0];
};

static int
begin_wim_resource_chunk_tab(const struct lookup_table_entry *lte,
			     FILE *out_fp,
			     struct chunk_table **chunk_tab_ret)
{
	u64 size = wim_resource_size(lte);
	u64 num_chunks = (size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;
	struct chunk_table *chunk_tab = MALLOC(sizeof(struct chunk_table) +
					       num_chunks * sizeof(u64));
	int ret = 0;

	if (!chunk_tab) {
		ERROR("Failed to allocate chunk table for %"PRIu64" byte "
		      "resource", size);
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}
	chunk_tab->file_offset = ftello(out_fp);
	if (chunk_tab->file_offset == -1) {
		ERROR_WITH_ERRNO("Failed to get file offset in output WIM");
		ret = WIMLIB_ERR_WRITE;
		goto out;
	}
	chunk_tab->num_chunks = num_chunks;
	chunk_tab->cur_offset_p = chunk_tab->offsets;
	chunk_tab->original_resource_size = lte->resource_entry.original_size;
	chunk_tab->bytes_per_chunk_entry =
			(lte->resource_entry.original_size >= (1ULL << 32))
				 ? 8 : 4;
	chunk_tab->table_disk_size = chunk_tab->bytes_per_chunk_entry *
				     (num_chunks - 1);

	if (fwrite(chunk_tab, 1, chunk_tab->table_disk_size, out_fp) !=
		   chunk_tab->table_disk_size)
	{
		ERROR_WITH_ERRNO("Failed to write chunk table in compressed "
				 "file resource");
		ret = WIMLIB_ERR_WRITE;
		goto out;
	}

	*chunk_tab_ret = chunk_tab;
out:
	return ret;
}

static int compress_chunk(const u8 chunk[], unsigned chunk_sz,
			  u8 compressed_chunk[],
			  unsigned *compressed_chunk_len_ret,
			  int ctype)
{
	unsigned compressed_chunk_sz;
	int (*compress)(const void *, unsigned, void *, unsigned *);
	if (ctype == WIM_COMPRESSION_TYPE_LZX)
		compress = lzx_compress;
	else
		compress = xpress_compress;
	return (*compress)(chunk, chunk_sz, compressed_chunk,
			   compressed_chunk_len_ret);
}

static int write_wim_resource_chunk(const u8 chunk[], unsigned chunk_size,
				    FILE *out_fp, int out_ctype,
				    struct chunk_table *chunk_tab)
{
	const u8 *out_chunk;
	unsigned out_chunk_size;

	if (out_ctype == WIM_COMPRESSION_TYPE_NONE) {
		out_chunk = chunk;
		out_chunk_size = chunk_size;
	} else {
		u8 *compressed_chunk = alloca(chunk_size);
		int ret;
		unsigned compressed_chunk_len;

		wimlib_assert(chunk_tab != NULL);

		ret = compress_chunk(chunk, chunk_size, compressed_chunk,
				     &out_chunk_size, out_ctype);
		if (ret > 0)
			return ret;
		else if (ret < 0) {
			out_chunk = chunk;
			out_chunk_size = chunk_size;
		} else {
			out_chunk = compressed_chunk;
		}
		*chunk_tab->cur_offset_p++ = chunk_tab->cur_offset;
		chunk_tab->cur_offset += out_chunk_size;
	}
	
	if (fwrite(out_chunk, 1, out_chunk_size, out_fp) != out_chunk_size) {
		ERROR_WITH_ERRNO("Failed to write WIM resource chunk");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

static int
finish_wim_resource_chunk_tab(const struct chunk_table *chunk_tab,
			      FILE *out_fp)
{
	if (fseeko(out_fp, chunk_tab->file_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seet to byte "PRIu64" of output "
				 "WIM file", chunk_tab->file_offset);
		return WIMLIB_ERR_WRITE;
	}

	if (chunk_tab->bytes_per_chunk_entry == 8) {
		array_to_le64(chunk_tab->offsets, chunk_tab->num_chunks - 1);
	} else {
		for (u64 i = 0; i < chunk_tab->num_chunks - 1; i++)
			((u32*)chunk_tab->offsets)[i] =
				to_le32(chunk_tab->offsets[i]);
	}
	if (fwrite(chunk_tab->offsets, 1, chunk_tab->table_disk_size, out_fp) !=
		   chunk_tab->table_disk_size)
	{
		ERROR_WITH_ERRNO("Failed to write chunk table in compressed "
				 "file resource");
		return WIMLIB_ERR_WRITE;
	}
	if (fseeko(out_fp, chunk_tab->file_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seet to byte "PRIu64" of output "
				 "WIM file", chunk_tab->file_offset);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

static int write_wim_resource(const struct lookup_table_entry *lte,
			      FILE *out_fp, int out_ctype)
{
	u64 bytes_remaining = wim_resource_size(lte);
	char buf[min(WIM_CHUNK_SIZE, bytes_remaining)];
	u64 offset = 0;
	int ret = 0;
	bool raw = wim_resource_compression_type(lte) == out_ctype;
	struct chunk_table *chunk_tab = NULL;

	if (raw)
		out_ctype = WIM_COMPRESSION_TYPE_NONE;

	if (out_ctype != WIM_COMPRESSION_TYPE_NONE) {
		ret = begin_wim_resource_chunk_tab(lte, out_fp,
						   &chunk_tab);
		if (ret != 0)
			return 0;
	}

	while (bytes_remaining) {
		u64 to_read = min(bytes_remaining, WIM_CHUNK_SIZE);
		ret = __read_wim_resource(lte, buf, to_read, offset, raw);
		if (ret != 0)
			break;
		ret = write_wim_resource_chunk(buf, to_read, out_fp,
					       out_ctype, chunk_tab);
		if (ret != 0)
			break;
		bytes_remaining -= to_read;
		offset += to_read;
	}
	if (out_ctype != WIM_COMPRESSION_TYPE_NONE)
		ret = finish_wim_resource_chunk_tab(chunk_tab, out_fp);
	return ret;
}

static int write_wim_resource_from_buffer(const u8 *buf, u64 buf_size,
					  FILE *out_fp, int out_ctype)
{
	struct lookup_table_entry lte;
	lte.resource_entry.flags = 0;
	lte.resource_entry.original_size = buf_size;
	lte.resource_entry.size = buf_size;
	lte.resource_entry.offset = 0;
	lte.resource_location = RESOURCE_IN_ATTACHED_BUFFER;
	lte.attached_buffer = (u8*)buf;
	return write_wim_resource(&lte, out_fp, out_ctype);
}

/* 
 * Extracts the first @size bytes of the resource specified by @lte to the open
 * file @fd.  Returns nonzero on error.
 */
int extract_wim_resource_to_fd(const struct lookup_table_entry *lte, int fd,
			       u64 size)
{
	u64 bytes_remaining = size;
	char buf[min(WIM_CHUNK_SIZE, bytes_remaining)];
	u64 offset = 0;
	int ret = 0;

	while (bytes_remaining) {
		u64 to_read = min(bytes_remaining, WIM_CHUNK_SIZE);
		ret = read_wim_resource(lte, buf, to_read, offset);
		if (ret != 0)
			break;
		if (full_write(fd, buf, to_read) < 0) {
			ERROR_WITH_ERRNO("Error extracting WIM resource");
			return WIMLIB_ERR_WRITE;
		}
		bytes_remaining -= to_read;
		offset += to_read;
	}
	return 0;
}

int extract_full_wim_resource_to_fd(const struct lookup_table_entry *lte, int fd)
{
	return extract_wim_resource_to_fd(lte, fd,
					  lte->resource_entry.original_size);
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
int copy_resource(struct lookup_table_entry *lte, void *wim)
{
	WIMStruct *w = wim;
	int ret;
	off_t new_offset;

	if ((lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA) &&
	    !w->write_metadata)
		return 0;

	new_offset = ftello(w->out_fp);
	if (new_offset == -1) {
		ERROR_WITH_ERRNO("Could not get offset in output WIM");
		return WIMLIB_ERR_WRITE;
	}


	ret = write_wim_resource(lte, w->out_fp,
				 wimlib_get_compression_type((WIMStruct*)w));
	if (ret != 0)
		return ret;

	memcpy(&lte->output_resource_entry, &lte->resource_entry, 
	       sizeof(struct resource_entry));

	lte->output_resource_entry.offset = new_offset;
	lte->out_refcnt = lte->refcnt;
	lte->part_number = w->hdr.part_number;
	return 0;
}

/* 
 * Writes a dentry's resources, including the main file resource as well as all
 * alternate data streams, to the output file. 
 *
 * @dentry:  The dentry for the file.
 * @wim_p:   A pointer to the WIMStruct.  The fields of interest to this
 * 	     function are the input and output file streams and the lookup
 * 	     table.
 *
 * @return zero on success, nonzero on failure. 
 */
int write_dentry_resources(struct dentry *dentry, void *wim_p)
{
	WIMStruct *w = wim_p;
	int ret = 0;
	struct lookup_table_entry *lte;
	int ctype = wimlib_get_compression_type(w);

	for (unsigned i = 0; i <= dentry->num_ads; i++) {
		lte = dentry_stream_lte(dentry, i, w->lookup_table);
		if (lte && ++lte->out_refcnt == 1) {
			ret = write_wim_resource(lte, w->out_fp, ctype);
			if (ret != 0)
				break;
		}
	}
	return ret;
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
	struct dentry *dentry;
	struct wim_security_data *sd;
	struct link_group_table *lgt;
	const struct lookup_table_entry *metadata_lte;
	const struct resource_entry *res_entry;

	metadata_lte = imd->metadata_lte;
	res_entry = &metadata_lte->resource_entry;

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

	/* Read the metadata resource into memory.  (It may be compressed.) */
	ret = read_full_wim_resource(metadata_lte, buf);
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

	DEBUG("Reading dentry tree");
	/* Now read the entire directory entry tree. */
	ret = read_dentry_tree(buf, res_entry->original_size, dentry);
	if (ret != 0)
		goto out_free_dentry_tree;

	DEBUG("Calculating dentry full paths");
	/* Calculate the full paths in the dentry tree. */
	ret = for_dentry_in_tree(dentry, calculate_dentry_full_path, NULL);
	if (ret != 0)
		goto out_free_dentry_tree;

	DEBUG("Building link group table");
	/* Build hash table that maps hard link group IDs to dentry sets */
	lgt = new_link_group_table(9001);
	if (!lgt)
		goto out_free_dentry_tree;
	ret = for_dentry_in_tree(dentry, link_group_table_insert, lgt);
	if (ret != 0)
		goto out_free_lgt;

	DEBUG("Freeing duplicate ADS entries in link group table");
	ret = link_groups_free_duplicate_data(lgt);
	if (ret != 0)
		goto out_free_lgt;
	DEBUG("Done reading image metadata");

	imd->lgt           = lgt;
	imd->security_data = sd;
	imd->root_dentry   = dentry;
	goto out_free_buf;
out_free_lgt:
	free_link_group_table(lgt);
out_free_dentry_tree:
	free_dentry_tree(dentry, NULL);
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
	off_t metadata_offset;
	u64 metadata_original_size;
	u64 metadata_compressed_size;
	int metadata_ctype;
	u8  hash[SHA1_HASH_SIZE];

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


	ret = write_wim_resource_from_buffer(buf, metadata_original_size,
					     out, metadata_ctype);
	FREE(buf);
	if (ret != 0)
		return ret;

	DEBUG("Updating metadata lookup table entry (size %zu)",
	      metadata_original_size);

	/* Update the lookup table entry, including the hash and output resource
	 * entry fields, for this image's metadata resource.  */
	lte = wim_metadata_lookup_table_entry(w);
	lte->out_refcnt++;
	if (!hashes_equal(hash, lte->hash)) {
		lookup_table_unlink(w->lookup_table, lte);
		copy_hash(lte->hash, hash);
		lookup_table_insert(w->lookup_table, lte);
	}
	lte->output_resource_entry.original_size = metadata_original_size;
	lte->output_resource_entry.offset        = metadata_offset;
	lte->output_resource_entry.size          = metadata_compressed_size;
	lte->output_resource_entry.flags         = WIM_RESHDR_FLAG_METADATA;
	if (metadata_ctype != WIM_COMPRESSION_TYPE_NONE)
		lte->output_resource_entry.flags |= WIM_RESHDR_FLAG_COMPRESSED;
	return 0;
}
