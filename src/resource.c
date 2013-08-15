/*
 * resource.c
 *
 * Read uncompressed and compressed metadata and file resources from a WIM file.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/dentry.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/lookup_table.h"
#include "wimlib/resource.h"
#include "wimlib/sha1.h"

#ifdef __WIN32__
/* for read_win32_file_prefix(), read_win32_encrypted_file_prefix() */
#  include "wimlib/win32.h"
#endif

#ifdef WITH_NTFS_3G
/* for read_ntfs_file_prefix() */
#  include "wimlib/ntfs_3g.h"
#endif

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

/*
 *                            Compressed resources
 *
 * A compressed resource in a WIM consists of a number of consecutive LZX or
 * XPRESS-compressed chunks, each of which decompresses to 32768 bytes of data,
 * except possibly the last, which always decompresses to any remaining bytes.
 * In addition, immediately before the chunks, a table (the "chunk table")
 * provides the offset, in bytes relative to the end of the chunk table, of the
 * start of each compressed chunk, except for the first chunk which is omitted
 * as it always has an offset of 0.  Therefore, a compressed resource with N
 * chunks will have a chunk table with N - 1 entries.
 *
 * Additional information:
 *
 * - Entries in the chunk table are 4 bytes each, except if the uncompressed
 *   size of the resource is greater than 4 GiB, in which case the entries in
 *   the chunk table are 8 bytes each.  In either case, the entries are unsigned
 *   little-endian integers.
 *
 * - The chunk table is included in the compressed size of the resource provided
 *   in the corresponding entry in the WIM's stream lookup table.
 *
 * - The compressed size of a chunk is never greater than the uncompressed size.
 *   From the compressor's point of view, chunks that would have compressed to a
 *   size greater than or equal to their original size are in fact stored
 *   uncompressed.  From the decompresser's point of view, chunks with
 *   compressed size equal to their uncompressed size are in fact uncompressed.
 *
 * Furthermore, wimlib supports its own "pipable" WIM format, and for this the
 * structure of compressed resources was modified to allow piped reading and
 * writing.  To make sequential writing possible, the chunk table is placed
 * after the chunks rather than before the chunks, and to make sequential
 * reading possible, each chunk is prefixed with a 4-byte header giving its
 * compressed size as a 32-bit, unsigned, little-endian integer (less than or
 * equal to 32768).  Otherwise the details are the same.
 */

typedef int (*decompress_func_t)(const void *, unsigned, void *, unsigned);

static decompress_func_t
get_decompress_func(int ctype)
{
	if (ctype == WIMLIB_COMPRESSION_TYPE_LZX)
		return wimlib_lzx_decompress;
	else
		return wimlib_xpress_decompress;
}

/*
 * read_compressed_resource()-
 *
 * Read data from a compressed resource being read from a seekable WIM file.
 * The resource may be either pipable or non-pipable.
 *
 * @flags may be:
 *
 * 0:
 *	Just do a normal read, decompressing the data if necessary.
 *
 * WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS:
 *	Read the raw contents of the compressed chunks of the compressed
 *	resource.  For pipable resources, this does *not* include the chunk
 *	headers.  If a callback function is being used, it will be called once
 *	for each compressed chunk.  For non-pipable resources, this mode
 *	excludes the chunk table.  For pipable resources, this mode excludes the
 *	stream and chunk headers.
 */
static int
read_compressed_resource(const struct wim_lookup_table_entry *lte,
			 u64 size, consume_data_callback_t cb,
			 void *ctx_or_buf, int flags, u64 offset)
{
	int ret;

	/* Currently, reading raw compressed chunks is only guaranteed to work
	 * correctly when the full resource is requested.  Furthermore, in such
	 * cases the requested size is specified as the compressed size, but
	 * here we change it to an uncompressed size to avoid confusing the rest
	 * of this function.  */
	if (flags & WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS) {
		wimlib_assert(offset == 0);
		wimlib_assert(size == lte->resource_entry.size);
		size = wim_resource_size(lte);
	}

	wimlib_assert(offset + size <= wim_resource_size(lte));

	/* Handle the trivial case.  */
	if (size == 0)
		return 0;

	/* Get the appropriate decompression function.  */
	decompress_func_t decompress =
			get_decompress_func(wim_resource_compression_type(lte));

	/* Get the file descriptor for the WIM.  */
	struct filedes *in_fd = &lte->wim->in_fd;

	/* Calculate the number of chunks the resource is divided into.  */
	u64 num_chunks = wim_resource_chunks(lte);

	/* Calculate the number of entries in the chunk table; it's one less
	 * than the number of chunks, since the first chunk has no entry.  */
	u64 num_chunk_entries = num_chunks - 1;

	/* Calculate the 0-based index of the chunk at which the read starts.
	 */
	u64 start_chunk = offset / WIM_CHUNK_SIZE;

	/* Calculate the offset, within the start chunk, of the first byte of
	 * the read.  */
	u64 start_offset_in_chunk = offset % WIM_CHUNK_SIZE;

	/* Calculate the index of the chunk that contains the last byte of the
	 * read.  */
	u64 end_chunk = (offset + size - 1) / WIM_CHUNK_SIZE;

	/* Calculate the offset, within the end chunk, of the last byte of the
	 * read.  */
	u64 end_offset_in_chunk = (offset + size - 1) % WIM_CHUNK_SIZE;

	/* Calculate the number of chunk entries are actually needed to read the
	 * requested part of the resource.  Include an entry for the first chunk
	 * even though that doesn't exist in the on-disk table, but take into
	 * account that if the last chunk required for the read is not the last
	 * chunk of the resource, an extra chunk entry is needed so that the
	 * compressed size of the last chunk of the read can be determined.  */
	u64 num_alloc_chunk_entries = end_chunk - start_chunk + 1;
	if (end_chunk != num_chunks - 1)
		num_alloc_chunk_entries++;

	/* Set the size of each chunk table entry based on the resource's
	 * uncompressed size.  */
	u64 chunk_entry_size = (wim_resource_size(lte) > ((u64)1 << 32)) ? 8 : 4;

	/* Calculate the size, in bytes, of the full chunk table.  */
	u64 chunk_table_size = num_chunk_entries * chunk_entry_size;

	/* Allocate a buffer to hold a subset of the chunk table.  It will only
	 * contain offsets for the chunks that are actually needed for this
	 * read.  For speed, allocate the buffer on the stack unless it's too
	 * large.  */
	u64 *chunk_offsets;
	bool chunk_offsets_malloced;
	if (num_alloc_chunk_entries < 1024) {
		chunk_offsets = alloca(num_alloc_chunk_entries * sizeof(u64));
		chunk_offsets_malloced = false;
	} else {
		chunk_offsets = malloc(num_alloc_chunk_entries * sizeof(u64));
		if (!chunk_offsets) {
			ERROR("Failed to allocate chunk table "
			      "with %"PRIu64" entries", num_alloc_chunk_entries);
			return WIMLIB_ERR_NOMEM;
		}
		chunk_offsets_malloced = true;
	}

	/* Set the implicit offset of the first chunk if it's included in the
	 * needed chunks.  */
	if (start_chunk == 0)
		chunk_offsets[0] = 0;

	/* Calculate the index of the first needed entry in the chunk table.  */
	u64 start_table_idx = (start_chunk == 0) ? 0 : start_chunk - 1;

	/* Calculate the number of entries that need to be read from the chunk
	 * table.  */
	u64 num_needed_chunk_entries = (start_chunk == 0) ?
				num_alloc_chunk_entries - 1 : num_alloc_chunk_entries;

	/* Calculate the number of bytes of data that need to be read from the
	 * chunk table.  */
	size_t chunk_table_needed_size =
				num_needed_chunk_entries * chunk_entry_size;
	if ((u64)chunk_table_needed_size !=
	    num_needed_chunk_entries * chunk_entry_size)
	{
		ERROR("Compressed read request too large to fit into memory!");
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_chunk_offsets;
	}

	/* Calculate the byte offset, in the WIM file, of the first chunk table
	 * entry to read.  Take into account that if the WIM file is in the
	 * special "pipable" format, then the chunk table is at the end of the
	 * resource, not the beginning.  */
	u64 file_offset_of_needed_chunk_entries =
			lte->resource_entry.offset + (start_table_idx *
						      chunk_entry_size);
	if (lte->is_pipable)
		file_offset_of_needed_chunk_entries += lte->resource_entry.size -
						       chunk_table_size;

	/* Read the needed chunk table entries into the end of the chunk_offsets
	 * buffer.  */
	void *chunk_tab_data = (u8*)&chunk_offsets[num_alloc_chunk_entries] -
				chunk_table_needed_size;
	ret = full_pread(in_fd, chunk_tab_data, chunk_table_needed_size,
			 file_offset_of_needed_chunk_entries);
	if (ret)
		goto read_error;

	/* Now fill in chunk_offsets from the entries we have read in
	 * chunk_tab_data.  Careful: chunk_offsets aliases chunk_tab_data, which
	 * breaks C's aliasing rules when we read 32-bit integers and store
	 * 64-bit integers.  But since the operations are safe as long as the
	 * compiler doesn't mess with their order, we use the gcc may_alias
	 * extension to tell the compiler that loads from the 32-bit integers
	 * may alias stores to the 64-bit integers.  */
	{
		typedef le64 __attribute__((may_alias)) aliased_le64_t;
		typedef le32 __attribute__((may_alias)) aliased_le32_t;
		u64 *chunk_offsets_p = chunk_offsets;
		u64 i;

		if (start_chunk == 0)
			chunk_offsets_p++;

		if (chunk_entry_size == 4) {
			aliased_le32_t *raw_entries = (aliased_le32_t*)chunk_tab_data;
			for (i = 0; i < num_needed_chunk_entries; i++)
				chunk_offsets_p[i] = le32_to_cpu(raw_entries[i]);
		} else {
			aliased_le64_t *raw_entries = (aliased_le64_t*)chunk_tab_data;
			for (i = 0; i < num_needed_chunk_entries; i++)
				chunk_offsets_p[i] = le64_to_cpu(raw_entries[i]);
		}
	}

	/* Calculate file offset of the first chunk that needs to be read.  N.B.
	 * if the resource is pipable, the entries in the chunk table do *not*
	 * include the chunk headers.  */
	u64 cur_read_offset = lte->resource_entry.offset + chunk_offsets[0];
	if (!lte->is_pipable)
		cur_read_offset += chunk_table_size;
	else
		cur_read_offset += start_chunk *
				   sizeof(struct pwm_chunk_hdr);

	/* If using a callback function, allocate a temporary buffer that will
	 * be used to pass data to it.  If writing directly to a buffer instead,
	 * arrange to write data directly into it.  */
	u8 *out_p;
	if (cb)
		out_p = alloca(WIM_CHUNK_SIZE);
	else
		out_p = ctx_or_buf;

	/* Unless the raw compressed data was requested, allocate a temporary
	 * buffer for reading compressed chunks, each of which can be at most
	 * WIM_CHUNK_SIZE - 1 bytes.  This excludes compressed chunks that are a
	 * full WIM_CHUNK_SIZE bytes, which are handled separately.  */
	void *compressed_buf;
	if (!(flags & WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS))
		compressed_buf = alloca(WIM_CHUNK_SIZE - 1);

	/* Read, and possibly decompress, each needed chunk, either writing the
	 * data directly into the @ctx_or_buf buffer or passing it to the @cb
	 * callback function.  */
	for (u64 i = start_chunk; i <= end_chunk; i++) {

		/* If the resource is pipable, skip the chunk header.  */
		if (lte->is_pipable)
			cur_read_offset += sizeof(struct pwm_chunk_hdr);

		/* Calculate the sizes of the compressed chunk and of the
		 * uncompressed chunk.  */
		unsigned compressed_chunk_size;
		unsigned uncompressed_chunk_size;
		if (i != num_chunks - 1) {
			/* Not the last chunk.  Compressed size is given by
			 * difference of chunk table entries; uncompressed size
			 * is always 32768 bytes.  */
			compressed_chunk_size = chunk_offsets[i + 1 - start_chunk] -
						chunk_offsets[i - start_chunk];
			uncompressed_chunk_size = WIM_CHUNK_SIZE;
		} else {
			/* Last chunk.  Compressed size is the remaining size in
			 * the compressed resource; uncompressed size is the
			 * remaining size in the uncompressed resource.  */
			compressed_chunk_size = lte->resource_entry.size -
						chunk_table_size -
						chunk_offsets[i - start_chunk];
			if (lte->is_pipable)
				compressed_chunk_size -= num_chunks *
							 sizeof(struct pwm_chunk_hdr);

			if (wim_resource_size(lte) % WIM_CHUNK_SIZE == 0)
				uncompressed_chunk_size = WIM_CHUNK_SIZE;
			else
				uncompressed_chunk_size = wim_resource_size(lte) %
							  WIM_CHUNK_SIZE;
		}

		/* Calculate how much of this chunk needs to be read.  */

		unsigned partial_chunk_size;
		u64 start_offset = 0;
		u64 end_offset = WIM_CHUNK_SIZE - 1;

		if (flags & WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS) {
			partial_chunk_size = compressed_chunk_size;
		} else {
			if (i == start_chunk)
				start_offset = start_offset_in_chunk;

			if (i == end_chunk)
				end_offset = end_offset_in_chunk;

			partial_chunk_size = end_offset + 1 - start_offset;
		}

		if (compressed_chunk_size == uncompressed_chunk_size ||
		    (flags & WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS))
		{
			/* Chunk stored uncompressed, or reading raw chunk data.  */
			ret = full_pread(in_fd,
					 cb ? out_p + start_offset : out_p,
					 partial_chunk_size,
					 cur_read_offset + start_offset);
			if (ret)
				goto read_error;
		} else {
			/* Compressed chunk and not doing raw read.  */

			/* Read the compressed data into compressed_buf.  */
			ret = full_pread(in_fd,
					 compressed_buf,
					 compressed_chunk_size,
					 cur_read_offset);
			if (ret)
				goto read_error;

			/* For partial chunks and when writing directly to a
			 * buffer, we must buffer the uncompressed data because
			 * we don't need all of it.  */
			if (partial_chunk_size != uncompressed_chunk_size &&
			    cb == NULL)
			{
				u8 uncompressed_buf[uncompressed_chunk_size];

				ret = (*decompress)(compressed_buf,
						    compressed_chunk_size,
						    uncompressed_buf,
						    uncompressed_chunk_size);
				if (ret) {
					ERROR("Failed to decompress data.");
					ret = WIMLIB_ERR_DECOMPRESSION;
					errno = EINVAL;
					goto out_free_chunk_offsets;
				}
				memcpy(out_p, uncompressed_buf + start_offset,
				       partial_chunk_size);
			} else {
				ret = (*decompress)(compressed_buf,
						    compressed_chunk_size,
						    out_p,
						    uncompressed_chunk_size);
				if (ret) {
					ERROR("Failed to decompress data.");
					ret = WIMLIB_ERR_DECOMPRESSION;
					errno = EINVAL;
					goto out_free_chunk_offsets;
				}
			}
		}
		if (cb) {
			/* Feed the data to the callback function.  */
			ret = cb(out_p + start_offset,
				 partial_chunk_size, ctx_or_buf);
			if (ret)
				goto out_free_chunk_offsets;
		} else {
			/* No callback function provided; we are writing
			 * directly to a buffer.  Advance the pointer into this
			 * buffer by the number of uncompressed bytes that were
			 * written.  */
			out_p += partial_chunk_size;
		}
		cur_read_offset += compressed_chunk_size;
	}

	ret = 0;
out_free_chunk_offsets:
	if (chunk_offsets_malloced)
		FREE(chunk_offsets);
	return ret;

read_error:
	ERROR_WITH_ERRNO("Error reading compressed file resource");
	goto out_free_chunk_offsets;
}

/* Skip over the chunk table at the end of pipable, compressed resource being
 * read from a pipe.  */
static int
skip_chunk_table(const struct wim_lookup_table_entry *lte,
		 struct filedes *in_fd)
{
	u64 num_chunk_entries = wim_resource_chunks(lte) - 1;
	u64 chunk_entry_size = (wim_resource_size(lte) > ((u64)1 << 32)) ? 8 : 4;
	u64 chunk_table_size = num_chunk_entries * chunk_entry_size;
	int ret;

	if (num_chunk_entries != 0) {
		u8 dummy;
		ret = full_pread(in_fd, &dummy, 1,
				 in_fd->offset + chunk_table_size - 1);
		if (ret)
			return ret;
	}
	return 0;
}

/* Read and decompress data from a compressed, pipable resource being read from
 * a pipe.  */
static int
read_pipable_resource(const struct wim_lookup_table_entry *lte,
		      u64 size, consume_data_callback_t cb,
		      void *ctx_or_buf, int flags, u64 offset)
{
	struct filedes *in_fd;
	decompress_func_t decompress;
	int ret;
	u8 chunk[WIM_CHUNK_SIZE];
	u8 cchunk[WIM_CHUNK_SIZE - 1];

	/* Get pointers to appropriate decompression function and the input file
	 * descriptor.  */
	decompress = get_decompress_func(wim_resource_compression_type(lte));
	in_fd = &lte->wim->in_fd;

	/* This function currently assumes the entire resource is being read at
	 * once and that the raw compressed data isn't being requested.  This is
	 * based on the fact that this function currently only gets called
	 * during the operation of wimlib_extract_image_from_pipe().  */
	wimlib_assert(!(flags & WIMLIB_READ_RESOURCE_FLAG_RAW));
	wimlib_assert(offset == 0);
	wimlib_assert(size == wim_resource_size(lte));
	wimlib_assert(in_fd->offset == lte->resource_entry.offset);

	for (offset = 0; offset < size; offset += WIM_CHUNK_SIZE) {
		struct pwm_chunk_hdr chunk_hdr;
		u32 chunk_size;
		u32 cchunk_size;
		u8 *res_chunk;
		u32 res_chunk_size;

		/* Calculate uncompressed size of next chunk.  */
		chunk_size = min(WIM_CHUNK_SIZE, size - offset);

		/* Read the compressed size of the next chunk from the chunk
		 * header.  */
		ret = full_read(in_fd, &chunk_hdr, sizeof(chunk_hdr));
		if (ret)
			goto read_error;

		cchunk_size = le32_to_cpu(chunk_hdr.compressed_size);

		if (cchunk_size > WIM_CHUNK_SIZE) {
			errno = EINVAL;
			ret = WIMLIB_ERR_INVALID_PIPABLE_WIM;
			goto invalid;
		}

		/* Read chunk data.  */
		ret = full_read(in_fd, cchunk, cchunk_size);
		if (ret)
			goto read_error;

		if (flags & WIMLIB_READ_RESOURCE_FLAG_SEEK_ONLY)
			continue;

		/* Decompress chunk if needed.  Uncompressed size same
		 * as compressed size means the chunk is uncompressed.
		 */
		res_chunk_size = chunk_size;
		if (cchunk_size == chunk_size) {
			res_chunk = cchunk;
		} else {
			ret = (*decompress)(cchunk, cchunk_size,
					    chunk, chunk_size);
			if (ret) {
				errno = EINVAL;
				ret = WIMLIB_ERR_DECOMPRESSION;
				goto invalid;
			}
			res_chunk = chunk;
		}

		/* Feed the uncompressed data into the callback function or copy
		 * it into the provided buffer.  */
		if (cb) {
			ret = cb(res_chunk, res_chunk_size, ctx_or_buf);
			if (ret)
				return ret;
		} else {
			ctx_or_buf = mempcpy(ctx_or_buf, res_chunk,
					     res_chunk_size);
		}
	}

	ret = skip_chunk_table(lte, in_fd);
	if (ret)
		goto read_error;
	return 0;

read_error:
	ERROR_WITH_ERRNO("Error reading compressed file resource");
	return ret;

invalid:
	ERROR("Compressed file resource is invalid");
	return ret;
}

/*
 * read_partial_wim_resource()-
 *
 * Read a range of data from a uncompressed or compressed resource in a WIM
 * file.  Data is written into a buffer or fed into a callback function, as
 * documented in read_resource_prefix().
 *
 * @flags can be:
 *
 * 0:
 *	Just do a normal read, decompressing the data if necessary.  @size and
 *	@offset are interpreted relative to the uncompressed contents of the
 *	stream.
 *
 * WIMLIB_READ_RESOURCE_FLAG_RAW_FULL:
 *	Only valid when the resource is compressed:  Read the raw contents of
 *	the compressed resource.  If the resource is non-pipable, this includes
 *	the chunk table as well as the compressed chunks.  If the resource is
 *	pipable, this includes the compressed chunks--- including the chunk
 *	headers--- and the chunk table.  The stream header is still *not*
 *	included.
 *
 *	In this mode, @offset is relative to the beginning of the raw contents
 *	of the compressed resource--- that is, the chunk table if the resource
 *	is non-pipable, or the header for the first compressed chunk if the
 *	resource is pipable.  @size is the number of raw bytes to read, which
 *	must not overrun the end of the resource.  For example, if @offset is 0,
 *	then @size can be at most the raw size of the compressed resource
 *	(@lte->resource_entry.size).
 *
 * WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS:
 *	Only valid when the resource is compressed and is not being read from a
 *	pipe:  Read the raw contents of the compressed chunks of the compressed
 *	resource.  For pipable resources, this does *not* include the chunk
 *	headers.  If a callback function is being used, it will be called once
 *	for each compressed chunk.  The chunk table is excluded.  Also, for
 *	pipable resources, the stream and chunk headers are excluded.  In this
 *	mode, @size must be exactly the raw size of the compressed resource
 *	(@lte->resource_entry.size) and @offset must be 0.
 *
 * WIMLIB_READ_RESOURCE_FLAG_SEEK_ONLY:
 *	Only valid when the resource is being read from a pipe:  Skip over the
 *	requested data rather than feed it to the callback function or write it
 *	into the buffer.  No decompression is done.
 *	WIMLIB_READ_RESOURCE_FLAG_RAW_* may not be combined with this flag.
 *	@offset must be 0 and @size must be the uncompressed size of the
 *	resource.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_READ			  (errno set)
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE (errno set to 0)
 *	WIMLIB_ERR_NOMEM		  (errno set to ENOMEM)
 *	WIMLIB_ERR_DECOMPRESSION	  (errno set to EINVAL)
 *	WIMLIB_ERR_INVALID_PIPABLE_WIM    (errno set to EINVAL)
 *	
 *	or other error code returned by the @cb function.
 */
int
read_partial_wim_resource(const struct wim_lookup_table_entry *lte,
			  u64 size, consume_data_callback_t cb,
			  void *ctx_or_buf, int flags, u64 offset)
{
	struct filedes *in_fd;
	int ret;

	/* Make sure the resource is actually located in a WIM file and is not
	 * somewhere else.  */
	wimlib_assert(lte->resource_location == RESOURCE_IN_WIM);

	/* Retrieve input file descriptor for the WIM file.  */
	in_fd = &lte->wim->in_fd;

	/* Don't allow raw reads (either full or chunks) of uncompressed
	 * resources.  */
	wimlib_assert(!(flags & WIMLIB_READ_RESOURCE_FLAG_RAW) ||
		      resource_is_compressed(&lte->resource_entry));

	/* Don't allow seek-only reads unless reading from a pipe; also don't
	 * allow combining SEEK_ONLY with either RAW flag.  */
	wimlib_assert(!(flags & WIMLIB_READ_RESOURCE_FLAG_SEEK_ONLY) ||
		      (!filedes_is_seekable(in_fd) &&
		       !(flags & WIMLIB_READ_RESOURCE_FLAG_RAW)));

	DEBUG("Reading WIM resource: %"PRIu64" @ +%"PRIu64" "
	      "from %"PRIu64" @ +%"PRIu64" (readflags 0x%08x, resflags 0x%02x%s)",
	      size, offset,
	      lte->resource_entry.original_size, lte->resource_entry.offset,
	      flags, lte->resource_entry.flags,
	      (lte->is_pipable ? ", pipable" : ""));

	if ((flags & WIMLIB_READ_RESOURCE_FLAG_RAW_FULL) ||
	    !resource_is_compressed(&lte->resource_entry))
	{
		/* Reading raw resource contents or reading uncompressed
		 * resource.  */
		wimlib_assert(offset + size <= lte->resource_entry.size);
		offset += lte->resource_entry.offset;
		if (flags & WIMLIB_READ_RESOURCE_FLAG_SEEK_ONLY) {
			if (lte->resource_entry.size != 0) {
				u8 dummy;
				ret = full_pread(in_fd, &dummy, 1,
						 offset + lte->resource_entry.size - 1);
				if (ret)
					goto read_error;
			}
		} else if (cb) {
			/* Send data to callback function */
			u8 buf[min(WIM_CHUNK_SIZE, size)];
			while (size) {
				size_t bytes_to_read = min(WIM_CHUNK_SIZE,
							   size);
				ret = full_pread(in_fd, buf, bytes_to_read,
						 offset);
				if (ret)
					goto read_error;
				ret = cb(buf, bytes_to_read, ctx_or_buf);
				if (ret)
					goto out;
				size -= bytes_to_read;
				offset += bytes_to_read;
			}
		} else {
			/* Send data directly to a buffer */
			ret = full_pread(in_fd, ctx_or_buf, size, offset);
			if (ret)
				goto read_error;
		}
		ret = 0;
	} else if (lte->is_pipable && !filedes_is_seekable(in_fd)) {
		/* Reading compressed, pipable resource from pipe.  */
		ret = read_pipable_resource(lte, size, cb,
					    ctx_or_buf, flags, offset);
	} else {
		/* Reading compressed, possibly pipable resource from seekable
		 * file.  */
		ret = read_compressed_resource(lte, size, cb,
					       ctx_or_buf, flags, offset);
	}
	goto out;

read_error:
	ERROR_WITH_ERRNO("Error reading data from WIM");
out:
	return ret;
}


int
read_partial_wim_resource_into_buf(const struct wim_lookup_table_entry *lte,
				   size_t size, u64 offset, void *buf)
{
	return read_partial_wim_resource(lte, size, NULL, buf, 0, offset);
}

static int
read_wim_resource_prefix(const struct wim_lookup_table_entry *lte,
			 u64 size,
			 consume_data_callback_t cb,
			 void *ctx_or_buf,
			 int flags)
{
	return read_partial_wim_resource(lte, size, cb, ctx_or_buf, flags, 0);
}


#ifndef __WIN32__
static int
read_file_on_disk_prefix(const struct wim_lookup_table_entry *lte,
			 u64 size,
			 consume_data_callback_t cb,
			 void *ctx_or_buf,
			 int _ignored_flags)
{
	const tchar *filename = lte->file_on_disk;
	int ret;
	struct filedes fd;
	int raw_fd;

	DEBUG("Reading %"PRIu64" bytes from \"%"TS"\"",
	      size, lte->file_on_disk);

	raw_fd = open(filename, O_RDONLY);
	if (raw_fd < 0) {
		ERROR_WITH_ERRNO("Can't open \"%"TS"\"", filename);
		return WIMLIB_ERR_OPEN;
	}
	filedes_init(&fd, raw_fd);
	if (cb) {
		/* Send data to callback function */
		u8 buf[min(WIM_CHUNK_SIZE, size)];
		size_t bytes_to_read;
		while (size) {
			bytes_to_read = min(WIM_CHUNK_SIZE, size);
			ret = full_read(&fd, buf, bytes_to_read);
			if (ret)
				goto read_error;
			ret = cb(buf, bytes_to_read, ctx_or_buf);
			if (ret)
				goto out_close;
			size -= bytes_to_read;
		}
	} else {
		/* Send data directly to a buffer */
		ret = full_read(&fd, ctx_or_buf, size);
		if (ret)
			goto read_error;
	}
	ret = 0;
	goto out_close;

read_error:
	ERROR_WITH_ERRNO("Error reading \"%"TS"\"", filename);
out_close:
	filedes_close(&fd);
	return ret;
}
#endif /* !__WIN32__ */

static int
read_buffer_prefix(const struct wim_lookup_table_entry *lte,
		   u64 size, consume_data_callback_t cb,
		   void *ctx_or_buf, int _ignored_flags)
{
	const void *inbuf = lte->attached_buffer;
	int ret;

	if (cb) {
		while (size) {
			size_t chunk_size = min(WIM_CHUNK_SIZE, size);
			ret = cb(inbuf, chunk_size, ctx_or_buf);
			if (ret)
				return ret;
			size -= chunk_size;
			inbuf += chunk_size;
		}
	} else {
		memcpy(ctx_or_buf, inbuf, size);
	}
	return 0;
}

typedef int (*read_resource_prefix_handler_t)(const struct wim_lookup_table_entry *lte,
					      u64 size,
					      consume_data_callback_t cb,
					      void *ctx_or_buf,
					      int flags);

/*
 * read_resource_prefix()-
 *
 * Read the first @size bytes from a generic "resource", which may be located in
 * the WIM (compressed or uncompressed), in an external file, or directly in an
 * in-memory buffer.
 *
 * Feed the data either to a callback function (cb != NULL, passing it
 * ctx_or_buf), or write it directly into a buffer (cb == NULL, ctx_or_buf
 * specifies the buffer, which must have room for @size bytes).
 *
 * When using a callback function, it is called with chunks up to 32768 bytes in
 * size until the resource is exhausted.
 *
 * If the resource is located in a WIM file, @flags can be set as documented in
 * read_partial_wim_resource().  Otherwise @flags are ignored.
 */
int
read_resource_prefix(const struct wim_lookup_table_entry *lte,
		     u64 size, consume_data_callback_t cb, void *ctx_or_buf,
		     int flags)
{
	static const read_resource_prefix_handler_t handlers[] = {
		[RESOURCE_IN_WIM]             = read_wim_resource_prefix,
	#ifdef __WIN32__
		[RESOURCE_IN_FILE_ON_DISK]    = read_win32_file_prefix,
	#else
		[RESOURCE_IN_FILE_ON_DISK]    = read_file_on_disk_prefix,
	#endif
		[RESOURCE_IN_ATTACHED_BUFFER] = read_buffer_prefix,
	#ifdef WITH_FUSE
		[RESOURCE_IN_STAGING_FILE]    = read_file_on_disk_prefix,
	#endif
	#ifdef WITH_NTFS_3G
		[RESOURCE_IN_NTFS_VOLUME]     = read_ntfs_file_prefix,
	#endif
	#ifdef __WIN32__
		[RESOURCE_WIN32_ENCRYPTED]    = read_win32_encrypted_file_prefix,
	#endif
	};
	wimlib_assert(lte->resource_location < ARRAY_LEN(handlers)
		      && handlers[lte->resource_location] != NULL);
	return handlers[lte->resource_location](lte, size, cb, ctx_or_buf, flags);
}

int
read_full_resource_into_buf(const struct wim_lookup_table_entry *lte,
			    void *buf)
{
	return read_resource_prefix(lte, wim_resource_size(lte), NULL, buf, 0);
}

int
read_full_resource_into_alloc_buf(const struct wim_lookup_table_entry *lte,
				  void **buf_ret)
{
	int ret;
	void *buf;

	if ((size_t)lte->resource_entry.original_size !=
	    lte->resource_entry.original_size)
	{
		ERROR("Can't read %"PRIu64" byte resource into "
		      "memory", lte->resource_entry.original_size);
		return WIMLIB_ERR_NOMEM;
	}

	buf = MALLOC(lte->resource_entry.original_size);
	if (!buf)
		return WIMLIB_ERR_NOMEM;

	ret = read_full_resource_into_buf(lte, buf);
	if (ret) {
		FREE(buf);
		return ret;
	}

	*buf_ret = buf;
	return 0;
}

int
res_entry_to_data(const struct resource_entry *res_entry,
		  WIMStruct *wim, void **buf_ret)
{
	int ret;
	struct wim_lookup_table_entry *lte;

	lte = new_lookup_table_entry();
	if (!lte)
		return WIMLIB_ERR_NOMEM;

	copy_resource_entry(&lte->resource_entry, res_entry);
	lte->unhashed = 1;
	lte->part_number = wim->hdr.part_number;
	lte_init_wim(lte, wim);

	ret = read_full_resource_into_alloc_buf(lte, buf_ret);
	free_lookup_table_entry(lte);
	return ret;
}

struct extract_ctx {
	SHA_CTX sha_ctx;
	consume_data_callback_t extract_chunk;
	void *extract_chunk_arg;
};

static int
extract_chunk_sha1_wrapper(const void *chunk, size_t chunk_size,
			   void *_ctx)
{
	struct extract_ctx *ctx = _ctx;

	sha1_update(&ctx->sha_ctx, chunk, chunk_size);
	return ctx->extract_chunk(chunk, chunk_size, ctx->extract_chunk_arg);
}

/* Extracts the first @size bytes of a WIM resource to somewhere.  In the
 * process, the SHA1 message digest of the resource is checked if the full
 * resource is being extracted.
 *
 * @extract_chunk is a function that is called to extract each chunk of the
 * resource. */
int
extract_wim_resource(const struct wim_lookup_table_entry *lte,
		     u64 size,
		     consume_data_callback_t extract_chunk,
		     void *extract_chunk_arg)
{
	int ret;
	if (size == wim_resource_size(lte)) {
		/* Do SHA1 */
		struct extract_ctx ctx;
		ctx.extract_chunk = extract_chunk;
		ctx.extract_chunk_arg = extract_chunk_arg;
		sha1_init(&ctx.sha_ctx);
		ret = read_resource_prefix(lte, size,
					   extract_chunk_sha1_wrapper,
					   &ctx, 0);
		if (ret == 0) {
			u8 hash[SHA1_HASH_SIZE];
			sha1_final(hash, &ctx.sha_ctx);
			if (!hashes_equal(hash, lte->hash)) {
				if (wimlib_print_errors) {
					ERROR("Invalid SHA1 message digest "
					      "on the following WIM resource:");
					print_lookup_table_entry(lte, stderr);
					if (lte->resource_location == RESOURCE_IN_WIM)
						ERROR("The WIM file appears to be corrupt!");
				}
				ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
			}
		}
	} else {
		/* Don't do SHA1 */
		ret = read_resource_prefix(lte, size, extract_chunk,
					   extract_chunk_arg, 0);
	}
	return ret;
}

static int
extract_wim_chunk_to_fd(const void *buf, size_t len, void *_fd_p)
{
	struct filedes *fd = _fd_p;
	int ret = full_write(fd, buf, len);
	if (ret)
		ERROR_WITH_ERRNO("Error writing to file descriptor");
	return ret;
}

int
extract_wim_resource_to_fd(const struct wim_lookup_table_entry *lte,
			   struct filedes *fd, u64 size)
{
	return extract_wim_resource(lte, size, extract_wim_chunk_to_fd, fd);
}


static int
sha1_chunk(const void *buf, size_t len, void *ctx)
{
	sha1_update(ctx, buf, len);
	return 0;
}

/* Calculate the SHA1 message digest of a stream. */
int
sha1_resource(struct wim_lookup_table_entry *lte)
{
	int ret;
	SHA_CTX sha_ctx;

	sha1_init(&sha_ctx);
	ret = read_resource_prefix(lte, wim_resource_size(lte),
				   sha1_chunk, &sha_ctx, 0);
	if (ret == 0)
		sha1_final(lte->hash, &sha_ctx);
	return ret;
}

/* Translates a WIM resource entry from the on-disk format to an in-memory
 * format. */
void
get_resource_entry(const struct resource_entry_disk *disk_entry,
		   struct resource_entry *entry)
{
	/* Note: disk_entry may not be 8 byte aligned--- in that case, the
	 * offset and original_size members will be unaligned.  (This should be
	 * okay since `struct resource_entry_disk' is declared as packed.) */

	/* Read the size and flags into a bitfield portably... */
	entry->size = (((u64)disk_entry->size[0] <<  0) |
		       ((u64)disk_entry->size[1] <<  8) |
		       ((u64)disk_entry->size[2] << 16) |
		       ((u64)disk_entry->size[3] << 24) |
		       ((u64)disk_entry->size[4] << 32) |
		       ((u64)disk_entry->size[5] << 40) |
		       ((u64)disk_entry->size[6] << 48));
	entry->flags = disk_entry->flags;
	entry->offset = le64_to_cpu(disk_entry->offset);
	entry->original_size = le64_to_cpu(disk_entry->original_size);

	/* offset and original_size are truncated to 62 bits to avoid possible
	 * overflows, when converting to a signed 64-bit integer (off_t) or when
	 * adding size or original_size.  This is okay since no one would ever
	 * actually have a WIM bigger than 4611686018427387903 bytes... */
	if (entry->offset & 0xc000000000000000ULL) {
		WARNING("Truncating offset in resource entry");
		entry->offset &= 0x3fffffffffffffffULL;
	}
	if (entry->original_size & 0xc000000000000000ULL) {
		WARNING("Truncating original_size in resource entry");
		entry->original_size &= 0x3fffffffffffffffULL;
	}
}

/* Translates a WIM resource entry from an in-memory format into the on-disk
 * format. */
void
put_resource_entry(const struct resource_entry *entry,
		   struct resource_entry_disk *disk_entry)
{
	/* Note: disk_entry may not be 8 byte aligned--- in that case, the
	 * offset and original_size members will be unaligned.  (This should be
	 * okay since `struct resource_entry_disk' is declared as packed.) */
	u64 size = entry->size;

	disk_entry->size[0] = size >>  0;
	disk_entry->size[1] = size >>  8;
	disk_entry->size[2] = size >> 16;
	disk_entry->size[3] = size >> 24;
	disk_entry->size[4] = size >> 32;
	disk_entry->size[5] = size >> 40;
	disk_entry->size[6] = size >> 48;
	disk_entry->flags = entry->flags;
	disk_entry->offset = cpu_to_le64(entry->offset);
	disk_entry->original_size = cpu_to_le64(entry->original_size);
}
