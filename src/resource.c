/*
 * resource.c
 *
 * Read uncompressed and compressed metadata and file resources.
 */

/*
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "config.h"

#include <stdlib.h>
#include <stdarg.h>

#ifdef WITH_NTFS_3G
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/dir.h>
#endif

#include "wimlib_internal.h"
#include "lookup_table.h"
#include "io.h"
#include "lzx.h"
#include "xpress.h"
#include "sha1.h"
#include "dentry.h"
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif


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

/*
 * Reads some data from the resource corresponding to a WIM lookup table entry.
 *
 * @lte:	The WIM lookup table entry for the resource.
 * @buf:	Buffer into which to write the data.
 * @size:	Number of bytes to read.
 * @offset:	Offset at which to start reading the resource.
 * @raw:	If %true, compressed data is read literally rather than being
 * 			decompressed first.
 *
 * Returns zero on success, nonzero on failure.
 */
int read_wim_resource(const struct lookup_table_entry *lte, u8 buf[],
		      size_t size, u64 offset, bool raw)
{
	/* We shouldn't be allowing read over-runs in any part of the library.
	 * */
	if (raw)
		wimlib_assert(offset + size <= lte->resource_entry.size);
	else
		wimlib_assert(offset + size <= lte->resource_entry.original_size);

	int ctype;
	int ret;
	FILE *fp;
	switch (lte->resource_location) {
	case RESOURCE_IN_WIM:
		/* The resource is in a WIM file, and its WIMStruct is given by
		 * the lte->wim member.  The resource may be either compressed
		 * or uncompressed. */
		wimlib_assert(lte->wim);
		wimlib_assert(lte->wim->fp);
		ctype = wim_resource_compression_type(lte);

		wimlib_assert(ctype != WIM_COMPRESSION_TYPE_NONE ||
			      (lte->resource_entry.original_size ==
			       lte->resource_entry.size));

		if (raw || ctype == WIM_COMPRESSION_TYPE_NONE)
			return read_uncompressed_resource(lte->wim->fp,
							  lte->resource_entry.offset + offset,
							  size, buf);
		else
			return read_compressed_resource(lte->wim->fp,
							lte->resource_entry.size,
							lte->resource_entry.original_size,
							lte->resource_entry.offset,
							ctype, size, offset, buf);
		break;
	case RESOURCE_IN_STAGING_FILE:
	case RESOURCE_IN_FILE_ON_DISK:
		/* The resource is in some file on the external filesystem and
		 * needs to be read uncompressed */
		wimlib_assert(lte->file_on_disk);
		wimlib_assert(&lte->file_on_disk == &lte->staging_file_name);
		/* Use existing file pointer if available; otherwise open one
		 * temporarily */
		if (lte->file_on_disk_fp) {
			fp = lte->file_on_disk_fp;
		} else {
			fp = fopen(lte->file_on_disk, "rb");
			if (!fp) {
				ERROR_WITH_ERRNO("Failed to open the file "
						 "`%s'", lte->file_on_disk);
				return WIMLIB_ERR_OPEN;
			}
		}
		ret = read_uncompressed_resource(fp, offset, size, buf);
		if (fp != lte->file_on_disk_fp)
			fclose(fp);
		return ret;
		break;
	case RESOURCE_IN_ATTACHED_BUFFER:
		/* The resource is directly attached uncompressed in an
		 * in-memory buffer. */
		wimlib_assert(lte->attached_buffer);
		memcpy(buf, lte->attached_buffer + offset, size);
		return 0;
		break;
#ifdef WITH_NTFS_3G
	case RESOURCE_IN_NTFS_VOLUME:
		wimlib_assert(lte->ntfs_loc);
		if (lte->attr) {
			u64 adjusted_offset;
			if (lte->ntfs_loc->is_reparse_point)
				adjusted_offset = offset + 8;
			else
				adjusted_offset = offset;
			if (ntfs_attr_pread(lte->attr, offset, size, buf) == size) {
				return 0;
			} else {
				ERROR_WITH_ERRNO("Error reading NTFS attribute "
						 "at `%s'",
						 lte->ntfs_loc->path_utf8);
				return WIMLIB_ERR_NTFS_3G;
			}
		} else {
			wimlib_assert(0);
		}
		break;
#endif
	default:
		assert(0);
	}
}

/* 
 * Reads all the data from the resource corresponding to a WIM lookup table
 * entry.
 *
 * @lte:	The WIM lookup table entry for the resource.
 * @buf:	Buffer into which to write the data.  It must be at least
 * 		wim_resource_size(lte) bytes long.
 *
 * Returns 0 on success; nonzero on failure.
 */
int read_full_wim_resource(const struct lookup_table_entry *lte, u8 buf[])
{
	return read_wim_resource(lte, buf, wim_resource_size(lte), 0, false);
}

/* Chunk table that's located at the beginning of each compressed resource in
 * the WIM.  (This is not the on-disk format; the on-disk format just has an
 * array of offsets.) */
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

/* 
 * Allocates and initializes a chunk table, and reserves space for it in the
 * output file.
 */
static int
begin_wim_resource_chunk_tab(const struct lookup_table_entry *lte,
			     FILE *out_fp,
			     off_t file_offset,
			     struct chunk_table **chunk_tab_ret)
{
	u64 size = wim_resource_size(lte);
	u64 num_chunks = (size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;
	struct chunk_table *chunk_tab = MALLOC(sizeof(struct chunk_table) +
					       num_chunks * sizeof(u64));
	int ret = 0;

	wimlib_assert(size != 0);

	if (!chunk_tab) {
		ERROR("Failed to allocate chunk table for %"PRIu64" byte "
		      "resource", size);
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}
	chunk_tab->file_offset = file_offset;
	chunk_tab->num_chunks = num_chunks;
	chunk_tab->original_resource_size = size;
	chunk_tab->bytes_per_chunk_entry = (size >= (1ULL << 32)) ? 8 : 4;
	chunk_tab->table_disk_size = chunk_tab->bytes_per_chunk_entry *
				     (num_chunks - 1);
	chunk_tab->cur_offset = 0;
	chunk_tab->cur_offset_p = chunk_tab->offsets;

	if (fwrite(chunk_tab, 1, chunk_tab->table_disk_size, out_fp) !=
		   chunk_tab->table_disk_size) {
		ERROR_WITH_ERRNO("Failed to write chunk table in compressed "
				 "file resource");
		ret = WIMLIB_ERR_WRITE;
		goto out;
	}

	*chunk_tab_ret = chunk_tab;
out:
	return ret;
}

/* 
 * Compresses a chunk of a WIM resource.
 *
 * @chunk:		Uncompressed data of the chunk.
 * @chunk_size:		Size of the uncompressed chunk in bytes.
 * @compressed_chunk:	Pointer to output buffer of size at least
 * 				(@chunk_size - 1) bytes.
 * @compressed_chunk_len_ret:	Pointer to an unsigned int into which the size
 * 					of the compressed chunk will be
 * 					returned.
 * @ctype:	Type of compression to use.  Must be WIM_COMPRESSION_TYPE_LZX
 * 		or WIM_COMPRESSION_TYPE_XPRESS.
 *
 * Returns zero if compressed succeeded, and nonzero if the chunk could not be
 * compressed to any smaller than @chunk_size.  This function cannot fail for
 * any other reasons.
 */
static int compress_chunk(const u8 chunk[], unsigned chunk_size,
			  u8 compressed_chunk[],
			  unsigned *compressed_chunk_len_ret,
			  int ctype)
{
	int (*compress)(const void *, unsigned, void *, unsigned *);
	switch (ctype) {
	case WIM_COMPRESSION_TYPE_LZX:
		compress = lzx_compress;
		break;
	case WIM_COMPRESSION_TYPE_XPRESS:
		compress = xpress_compress;
		break;
	default:
		wimlib_assert(0);
		break;
	}
	return (*compress)(chunk, chunk_size, compressed_chunk,
			   compressed_chunk_len_ret);
}

/*
 * Writes a chunk of a WIM resource to an output file.
 *
 * @chunk:	  Uncompressed data of the chunk.
 * @chunk_size:	  Size of the chunk (<= WIM_CHUNK_SIZE)
 * @out_fp:	  FILE * to write tho chunk to.
 * @out_ctype:	  Compression type to use when writing the chunk (ignored if no 
 * 			chunk table provided)
 * @chunk_tab:	  Pointer to chunk table being created.  It is updated with the
 * 			offset of the chunk we write.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int write_wim_resource_chunk(const u8 chunk[], unsigned chunk_size,
				    FILE *out_fp, int out_ctype,
				    struct chunk_table *chunk_tab)
{
	const u8 *out_chunk;
	unsigned out_chunk_size;

	wimlib_assert(chunk_size <= WIM_CHUNK_SIZE);

	if (!chunk_tab) {
		out_chunk = chunk;
		out_chunk_size = chunk_size;
	} else {
		u8 *compressed_chunk = alloca(chunk_size);
		int ret;

		ret = compress_chunk(chunk, chunk_size, compressed_chunk,
				     &out_chunk_size, out_ctype);
		if (ret == 0) {
			out_chunk = compressed_chunk;
		} else {
			out_chunk = chunk;
			out_chunk_size = chunk_size;
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

/* 
 * Finishes a WIM chunk tale and writes it to the output file at the correct
 * offset.
 *
 * The final size of the full compressed resource is returned in the
 * @compressed_size_p.
 */
static int
finish_wim_resource_chunk_tab(struct chunk_table *chunk_tab,
			      FILE *out_fp, u64 *compressed_size_p)
{
	size_t bytes_written;
	if (fseeko(out_fp, chunk_tab->file_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" of output "
				 "WIM file", chunk_tab->file_offset);
		return WIMLIB_ERR_WRITE;
	}

	if (chunk_tab->bytes_per_chunk_entry == 8) {
		array_to_le64(chunk_tab->offsets, chunk_tab->num_chunks);
	} else {
		for (u64 i = 0; i < chunk_tab->num_chunks; i++)
			((u32*)chunk_tab->offsets)[i] =
				to_le32(chunk_tab->offsets[i]);
	}
	bytes_written = fwrite((u8*)chunk_tab->offsets +
					chunk_tab->bytes_per_chunk_entry,
			       1, chunk_tab->table_disk_size, out_fp);
	if (bytes_written != chunk_tab->table_disk_size) {
		ERROR_WITH_ERRNO("Failed to write chunk table in compressed "
				 "file resource");
		return WIMLIB_ERR_WRITE;
	}
	if (fseeko(out_fp, 0, SEEK_END) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to end of output WIM file");
		return WIMLIB_ERR_WRITE;
	}
	*compressed_size_p = chunk_tab->cur_offset + chunk_tab->table_disk_size;
	return 0;
}

/*
 * Writes a WIM resource to a FILE * opened for writing.  The resource may be
 * written uncompressed or compressed depending on the @out_ctype parameter.
 *
 * If by chance the resource compresses to more than the original size (this may
 * happen with random data or files than are pre-compressed), the resource is
 * instead written uncompressed (and this is reflected in the @out_res_entry by
 * removing the WIM_RESHDR_FLAG_COMPRESSED flag).
 *
 * @lte:	The lookup table entry for the WIM resource.
 * @out_fp:	The FILE * to write the resource to.
 * @out_ctype:  The compression type of the resource to write.  Note: if this is
 * 			the same as the compression type of the WIM resource we
 * 			need to read, we simply copy the data (i.e. we do not
 * 			uncompress it, then compress it again).
 * @out_res_entry:  If non-NULL, a resource entry that is filled in with the 
 * 		    offset, original size, compressed size, and compression flag
 * 		    of the output resource.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int write_wim_resource(struct lookup_table_entry *lte,
			      FILE *out_fp, int out_ctype,
			      struct resource_entry *out_res_entry)
{
	u64 bytes_remaining;
	u64 original_size;
	u64 old_compressed_size;
	u64 new_compressed_size;
	u64 offset = 0;
	int ret = 0;
	struct chunk_table *chunk_tab = NULL;
	bool raw;
	off_t file_offset;
#ifdef WITH_NTFS_3G
	ntfs_inode *ni = NULL;
#endif

	wimlib_assert(lte);

	/* Original size of the resource */
 	original_size = wim_resource_size(lte);

	/* Compressed size of the resource (as it exists now) */
	old_compressed_size = wim_resource_compressed_size(lte);

	/* Current offset in output file */
	file_offset = ftello(out_fp);
	if (file_offset == -1) {
		ERROR_WITH_ERRNO("Failed to get offset in output "
				 "stream");
		return WIMLIB_ERR_WRITE;
	}
	
	/* Are the compression types the same?  If so, do a raw copy (copy
	 * without decompressing and recompressing the data). */
	raw = (wim_resource_compression_type(lte) == out_ctype
	       && out_ctype != WIM_COMPRESSION_TYPE_NONE);
	if (raw)
		bytes_remaining = old_compressed_size;
	else
		bytes_remaining = original_size;

	/* Empty resource; nothing needs to be done, so just return success. */
	if (bytes_remaining == 0)
		return 0;

	/* Buffer for reading chunks for the resource */
	u8 buf[min(WIM_CHUNK_SIZE, bytes_remaining)];

	/* If we are writing a compressed resource and not doing a raw copy, we
	 * need to initialize the chunk table */
	if (out_ctype != WIM_COMPRESSION_TYPE_NONE && !raw) {
		ret = begin_wim_resource_chunk_tab(lte, out_fp, file_offset,
						   &chunk_tab);
		if (ret != 0)
			goto out;
	}

	/* If the WIM resource is in an external file, open a FILE * to it so we
	 * don't have to open a temporary one in read_wim_resource() for each
	 * chunk. */
	if (lte->resource_location == RESOURCE_IN_FILE_ON_DISK
	     && !lte->file_on_disk_fp)
	{
		wimlib_assert(lte->file_on_disk);
		lte->file_on_disk_fp = fopen(lte->file_on_disk, "rb");
		if (!lte->file_on_disk_fp) {
			ERROR_WITH_ERRNO("Failed to open the file `%s' for "
					 "reading", lte->file_on_disk);
			ret = WIMLIB_ERR_OPEN;
			goto out;
		}
	}
#ifdef WITH_NTFS_3G
	else if (lte->resource_location == RESOURCE_IN_NTFS_VOLUME
		  && !lte->attr)
	{
		struct ntfs_location *loc = lte->ntfs_loc;
		wimlib_assert(loc);
		ni = ntfs_pathname_to_inode(*loc->ntfs_vol_p, NULL, loc->path_utf8);
		if (!ni) {
			ERROR_WITH_ERRNO("Failed to open inode `%s' in NTFS "
					 "volume", loc->path_utf8);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out;
		}
		lte->attr = ntfs_attr_open(ni,
					   loc->is_reparse_point ? AT_REPARSE_POINT : AT_DATA,
					   (ntfschar*)loc->stream_name_utf16,
					   loc->stream_name_utf16_num_chars);
		if (!lte->attr) {
			ERROR_WITH_ERRNO("Failed to open attribute of `%s' in "
					 "NTFS volume", loc->path_utf8);
			ret = WIMLIB_ERR_NTFS_3G;
			goto out_fclose;
		}
	}
#endif

	/* If we aren't doing a raw copy, we will compute the SHA1 message
	 * digest of the resource as we read it, and verify it's the same as the
	 * hash given in the lookup table entry once we've finished reading the
	 * resource. */
	SHA_CTX ctx;
	if (!raw)
		sha1_init(&ctx);

	/* While there are still bytes remaining in the WIM resource, read a
	 * chunk of the resource, update SHA1, then write that chunk using the
	 * desired compression type. */
	do {
		u64 to_read = min(bytes_remaining, WIM_CHUNK_SIZE);
		ret = read_wim_resource(lte, buf, to_read, offset, raw);
		if (ret != 0)
			goto out_fclose;
		if (!raw)
			sha1_update(&ctx, buf, to_read);
		ret = write_wim_resource_chunk(buf, to_read, out_fp,
					       out_ctype, chunk_tab);
		if (ret != 0)
			goto out_fclose;
		bytes_remaining -= to_read;
		offset += to_read;
	} while (bytes_remaining);

	/* Raw copy:  The new compressed size is the same as the old compressed
	 * size
	 * 
	 * Using WIM_COMPRESSION_TYPE_NONE:  The new compressed size is the
	 * original size
	 *
	 * Using a different compression type:  Call
	 * finish_wim_resource_chunk_tab() and it will provide the new
	 * compressed size.
	 */
	if (raw) {
		new_compressed_size = old_compressed_size;
	} else {
		if (out_ctype == WIM_COMPRESSION_TYPE_NONE)
			new_compressed_size = original_size;
		else {
			ret = finish_wim_resource_chunk_tab(chunk_tab, out_fp,
							    &new_compressed_size);
			if (ret != 0)
				goto out_fclose;
		}
	}

	/* Verify SHA1 message digest of the resource, unless we are doing a raw
	 * write (in which case we never even saw the uncompressed data).  Or,
	 * if the hash we had before is all 0's, just re-set it to be the new
	 * hash. */
	if (!raw) {
		u8 md[SHA1_HASH_SIZE];
		sha1_final(md, &ctx);
		if (is_zero_hash(lte->hash)) {
			copy_hash(lte->hash, md);
		} else if (!hashes_equal(md, lte->hash)) {
			ERROR("WIM resource has incorrect hash!");
			if (lte->resource_location == RESOURCE_IN_FILE_ON_DISK) {
				ERROR("We were reading it from `%s'; maybe it changed "
				      "while we were reading it.",
				      lte->file_on_disk);
			}
			ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
			goto out_fclose;
		}
	}

	if (!raw && new_compressed_size >= original_size &&
	    out_ctype != WIM_COMPRESSION_TYPE_NONE)
	{
		/* Oops!  We compressed the resource to larger than the original
		 * size.  Write the resource uncompressed instead. */
		if (fseeko(out_fp, file_offset, SEEK_SET) != 0) {
			ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" "
					 "of output WIM file", file_offset);
			ret = WIMLIB_ERR_WRITE;
			goto out_fclose;
		}
		ret = write_wim_resource(lte, out_fp, WIM_COMPRESSION_TYPE_NONE,
					 out_res_entry);
		if (ret != 0)
			goto out_fclose;
		if (fflush(out_fp) != 0) {
			ERROR_WITH_ERRNO("Failed to flush output WIM file");
			ret = WIMLIB_ERR_WRITE;
			goto out_fclose;
		}
		if (ftruncate(fileno(out_fp), file_offset + out_res_entry->size) != 0) {
			ERROR_WITH_ERRNO("Failed to truncate output WIM file");
			ret = WIMLIB_ERR_WRITE;
		}
		goto out_fclose;
	}
	wimlib_assert(new_compressed_size <= original_size || raw);
	if (out_res_entry) {
		out_res_entry->size          = new_compressed_size;
		out_res_entry->original_size = original_size;
		out_res_entry->offset        = file_offset;
		out_res_entry->flags         = lte->resource_entry.flags
						& ~WIM_RESHDR_FLAG_COMPRESSED;
		if (out_ctype != WIM_COMPRESSION_TYPE_NONE)
			out_res_entry->flags |= WIM_RESHDR_FLAG_COMPRESSED;
	}
out_fclose:
	if (lte->resource_location == RESOURCE_IN_FILE_ON_DISK
	     && lte->file_on_disk_fp) {
		fclose(lte->file_on_disk_fp);
		lte->file_on_disk_fp = NULL;
	}
#ifdef WITH_NTFS_3G
	else if (lte->resource_location == RESOURCE_IN_NTFS_VOLUME) {
		if (lte->attr) {
			ntfs_attr_close(lte->attr);
			lte->attr = NULL;
		} if (ni) {
			ntfs_inode_close(ni);
		}
	}
#endif
out:
	FREE(chunk_tab);
	return ret;
}

/* Like write_wim_resource(), but the resource is specified by a buffer of
 * uncompressed data rather a lookup table entry; also writes the SHA1 hash of
 * the buffer to @hash.  */
static int write_wim_resource_from_buffer(const u8 *buf, u64 buf_size,
					  FILE *out_fp, int out_ctype,
					  struct resource_entry *out_res_entry,
					  u8 hash[SHA1_HASH_SIZE])
{
	/* Set up a temporary lookup table entry that we provide to
	 * write_wim_resource(). */
	struct lookup_table_entry lte;
	int ret;
	lte.resource_entry.flags         = 0;
	lte.resource_entry.original_size = buf_size;
	lte.resource_entry.size          = buf_size;
	lte.resource_entry.offset        = 0;
	lte.resource_location            = RESOURCE_IN_ATTACHED_BUFFER;
	lte.attached_buffer              = (u8*)buf;

	zero_out_hash(lte.hash);
	ret = write_wim_resource(&lte, out_fp, out_ctype, out_res_entry);
	if (ret != 0)
		return ret;
	copy_hash(hash, lte.hash);
	return 0;
}

/* 
 * Extracts the first @size bytes of the WIM resource specified by @lte to the
 * open file descriptor @fd.
 * 
 * Returns 0 on success; nonzero on failure.
 */
int extract_wim_resource_to_fd(const struct lookup_table_entry *lte, int fd,
			       u64 size)
{
	u64 bytes_remaining = size;
	u8 buf[min(WIM_CHUNK_SIZE, bytes_remaining)];
	u64 offset = 0;
	int ret = 0;
	u8 hash[SHA1_HASH_SIZE];

	SHA_CTX ctx;
	sha1_init(&ctx);

	while (bytes_remaining) {
		u64 to_read = min(bytes_remaining, WIM_CHUNK_SIZE);
		ret = read_wim_resource(lte, buf, to_read, offset, false);
		if (ret != 0)
			break;
		sha1_update(&ctx, buf, to_read);
		if (full_write(fd, buf, to_read) < 0) {
			ERROR_WITH_ERRNO("Error extracting WIM resource");
			return WIMLIB_ERR_WRITE;
		}
		bytes_remaining -= to_read;
		offset += to_read;
	}
	sha1_final(hash, &ctx);
	if (!hashes_equal(hash, lte->hash)) {
		ERROR("Invalid checksum on a WIM resource "
		      "(detected when extracting to external file)");
		ERROR("The following WIM resource is invalid:");
		print_lookup_table_entry(lte);
		return WIMLIB_ERR_INVALID_RESOURCE_HASH;
	}
	return 0;
}

/* 
 * Extracts the WIM resource specified by @lte to the open file descriptor @fd.
 * 
 * Returns 0 on success; nonzero on failure.
 */
int extract_full_wim_resource_to_fd(const struct lookup_table_entry *lte, int fd)
{
	return extract_wim_resource_to_fd(lte, fd, wim_resource_size(lte));
}

/* 
 * Copies the file resource specified by the lookup table entry @lte from the
 * input WIM to the output WIM that has its FILE * given by
 * ((WIMStruct*)wim)->out_fp.
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

	if ((lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA) &&
	    !w->write_metadata)
		return 0;

	ret = write_wim_resource(lte, w->out_fp,
				 wim_resource_compression_type(lte), 
				 &lte->output_resource_entry);
	if (ret != 0)
		return ret;
	lte->out_refcnt = lte->refcnt;
	lte->part_number = w->hdr.part_number;
	return 0;
}

/* 
 * Writes a dentry's resources, including the main file resource as well as all
 * alternate data streams, to the output file. 
 *
 * @dentry:  The dentry for the file.
 * @wim_p:   A pointer to the WIMStruct containing @dentry.
 *
 * @return zero on success, nonzero on failure. 
 */
int write_dentry_resources(struct dentry *dentry, void *wim_p)
{
	WIMStruct *w = wim_p;
	int ret = 0;
	struct lookup_table_entry *lte;
	int ctype = wimlib_get_compression_type(w);

	if (w->write_flags & WIMLIB_WRITE_FLAG_VERBOSE) {
		wimlib_assert(dentry->full_path_utf8);
		printf("Writing streams for `%s'\n", dentry->full_path_utf8);
	}

	for (unsigned i = 0; i <= dentry->inode->num_ads; i++) {
		lte = inode_stream_lte(dentry->inode, i, w->lookup_table);
		if (lte && ++lte->out_refcnt == 1) {
			ret = write_wim_resource(lte, w->out_fp, ctype,
						 &lte->output_resource_entry);
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
 * @imd:	Pointer to the image metadata structure.  Its `metadata_lte'
 * 		member specifies the lookup table entry for the metadata
 * 		resource.  The rest of the image metadata entry will be filled
 * 		in by this function.
 *
 * @return:	Zero on success, nonzero on failure.
 */
int read_metadata_resource(WIMStruct *w, struct image_metadata *imd)
{
	u8 *buf;
	u32 dentry_offset;
	int ret;
	struct dentry *dentry;
	struct inode_table inode_tab;
	const struct lookup_table_entry *metadata_lte;
	u64 metadata_len;
	u64 metadata_offset;
	struct hlist_head inode_list;

	metadata_lte = imd->metadata_lte;
	metadata_len = wim_resource_size(metadata_lte);
	metadata_offset = metadata_lte->resource_entry.offset;

	DEBUG("Reading metadata resource: length = %"PRIu64", "
	      "offset = %"PRIu64"", metadata_len, metadata_offset);

	/* There is no way the metadata resource could possibly be less than (8
	 * + WIM_DENTRY_DISK_SIZE) bytes, where the 8 is for security data (with
	 * no security descriptors) and WIM_DENTRY_DISK_SIZE is for the root
	 * dentry. */
	if (metadata_len < 8 + WIM_DENTRY_DISK_SIZE) {
		ERROR("Expected at least %u bytes for the metadata resource",
		      8 + WIM_DENTRY_DISK_SIZE);
		return WIMLIB_ERR_INVALID_RESOURCE_SIZE;
	}

	/* Allocate memory for the uncompressed metadata resource. */
	buf = MALLOC(metadata_len);

	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for uncompressed "
		      "metadata resource", metadata_len);
		return WIMLIB_ERR_NOMEM;
	}

	/* Read the metadata resource into memory.  (It may be compressed.) */
	ret = read_full_wim_resource(metadata_lte, buf);
	if (ret != 0)
		goto out_free_buf;

	DEBUG("Finished reading metadata resource into memory.");

	/* The root directory entry starts after security data, aligned on an
	 * 8-byte boundary within the metadata resource.
	 *
	 * The security data starts with a 4-byte integer giving its total
	 * length, so if we round that up to an 8-byte boundary that gives us
	 * the offset of the root dentry.
	 *
	 * Here we read the security data into a wim_security_data structure,
	 * and if successful, go ahead and calculate the offset in the metadata
	 * resource of the root dentry. */

	ret = read_security_data(buf, metadata_len, &imd->security_data);
	if (ret != 0)
		goto out_free_buf;

	get_u32(buf, &dentry_offset);
	if (dentry_offset == 0)
		dentry_offset = 8;
	dentry_offset = (dentry_offset + 7) & ~7;

	/* Allocate memory for the root dentry and read it into memory */
	dentry = MALLOC(sizeof(struct dentry));
	if (!dentry) {
		ERROR("Failed to allocate %zu bytes for root dentry",
		      sizeof(struct dentry));
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_security_data;
	}
		
	ret = read_dentry(buf, metadata_len, dentry_offset, dentry);

	/* This is the root dentry, so set its pointers correctly. */
	dentry->parent = dentry;
	dentry->next   = dentry;
	dentry->prev   = dentry;
	if (ret != 0)
		goto out_free_dentry_tree;
	inode_add_dentry(dentry, dentry->inode);

	/* Now read the entire directory entry tree into memory. */
	DEBUG("Reading dentry tree");
	ret = read_dentry_tree(buf, metadata_len, dentry);
	if (ret != 0)
		goto out_free_dentry_tree;

	/* Calculate the full paths in the dentry tree. */
	DEBUG("Calculating dentry full paths");
	ret = for_dentry_in_tree(dentry, calculate_dentry_full_path, NULL);
	if (ret != 0)
		goto out_free_dentry_tree;

	/* Build hash table that maps hard link group IDs to dentry sets */
	DEBUG("Building link group table");
	ret = init_inode_table(&inode_tab, 9001);
	if (ret != 0)
		goto out_free_dentry_tree;

	for_dentry_in_tree(dentry, inode_table_insert, &inode_tab);

	DEBUG("Fixing inconsistencies in the hard link groups");
	ret = fix_inodes(&inode_tab, &inode_list);
	destroy_inode_table(&inode_tab);
	if (ret != 0)
		goto out_free_dentry_tree;

	DEBUG("Running miscellaneous verifications on the dentry tree");
	for_lookup_table_entry(w->lookup_table, lte_zero_real_refcnt, NULL);
	ret = for_dentry_in_tree(dentry, verify_dentry, w);
	if (ret != 0)
		goto out_free_dentry_tree;

	DEBUG("Done reading image metadata");

	imd->root_dentry   = dentry;
	imd->inode_list = inode_list;
	goto out_free_buf;
out_free_dentry_tree:
	free_dentry_tree(dentry, NULL);
out_free_security_data:
	free_security_data(imd->security_data);
	imd->security_data = NULL;
out_free_buf:
	FREE(buf);
	return ret;
}

/* Write the metadata resource for the current WIM image. */
int write_metadata_resource(WIMStruct *w)
{
	u8 *buf;
	u8 *p;
	int ret;
	u64 subdir_offset;
	struct dentry *root;
	struct lookup_table_entry *lte;
	u64 metadata_original_size;
	const struct wim_security_data *sd;
	const unsigned random_tail_len = 20;

	DEBUG("Writing metadata resource for image %d", w->current_image);

	root = wim_root_dentry(w);
	sd = wim_security_data(w);

	/* We do not allow the security data pointer to be NULL, although it may
	 * point to an empty security data with no entries. */
	wimlib_assert(sd);

	/* Offset of first child of the root dentry.  It's equal to:
	 * - The total length of the security data, rounded to the next 8-byte
	 *   boundary,
	 * - plus the total length of the root dentry,
	 * - plus 8 bytes for an end-of-directory entry following the root
	 *   dentry (shouldn't really be needed, but just in case...)
	 */
	subdir_offset = ((sd->total_length + 7) & ~7) +
			dentry_correct_total_length(root) + 8;

	/* Calculate the subdirectory offsets for the entire dentry tree. */
	calculate_subdir_offsets(root, &subdir_offset);

	/* Total length of the metadata resource (uncompressed) */
	metadata_original_size = subdir_offset + random_tail_len;

	/* Allocate a buffer to contain the uncompressed metadata resource */
	buf = MALLOC(metadata_original_size);
	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for "
		      "metadata resource", metadata_original_size);
		return WIMLIB_ERR_NOMEM;
	}

	/* Write the security data into the resource buffer */
	p = write_security_data(sd, buf);

	/* Write the dentry tree into the resource buffer */
	DEBUG("Writing dentry tree.");
	p = write_dentry_tree(root, p);

	/* 
	 * Append 20 random bytes to the metadata resource so that we don't have
	 * identical metadata resources if we happen to append exactly the same
	 * image twice without any changes in timestamps.  If this were to
	 * happen, it would cause confusion about the number and order of images
	 * in the WIM.
	 */
	randomize_byte_array(p, random_tail_len);

	/* We MUST have exactly filled the buffer; otherwise we calculated its
	 * size incorrectly or wrote the data incorrectly. */
	wimlib_assert(p - buf + random_tail_len == metadata_original_size);

	/* Get the lookup table entry for the metadata resource so we can update
	 * it. */
	lte = wim_metadata_lookup_table_entry(w);

	/* Write the metadata resource to the output WIM using the proper
	 * compression type.  The lookup table entry for the metadata resource
	 * is updated. */
	ret = write_wim_resource_from_buffer(buf, metadata_original_size,
					     w->out_fp,
					     wimlib_get_compression_type(w),
					     &lte->output_resource_entry,
					     lte->hash);
	if (ret != 0)
		goto out;

	/* It's very likely the SHA1 message digest of the metadata resource, so
	 * re-insert the lookup table entry into the lookup table. */
	lookup_table_unlink(w->lookup_table, lte);
	lookup_table_insert(w->lookup_table, lte);

	/* We do not allow a metadata resource to be referenced multiple times,
	 * and the 20 random bytes appended to it should make it extremely
	 * likely for each metadata resource to be unique, even if the exact
	 * same image is captured. */
	wimlib_assert(lte->out_refcnt == 0);
	lte->out_refcnt = 1;

	/* Make sure that the resource entry is written marked with the metadata
	 * flag. */
	lte->output_resource_entry.flags |= WIM_RESHDR_FLAG_METADATA;
out:
	/* All the data has been written to the new WIM; no need for the buffer
	 * anymore */
	FREE(buf);
	return ret;
}
