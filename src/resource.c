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
#include <stdlib.h>
#include <unistd.h>

/*
 *                         Compressed WIM resources
 *
 * A compressed resource in a WIM consists of a number of compressed chunks,
 * each of which decompresses to a fixed chunk size (given in the WIM header;
 * usually 32768) except possibly the last, which always decompresses to any
 * remaining bytes.  In addition, immediately before the chunks, a table (the
 * "chunk table") provides the offset, in bytes relative to the end of the chunk
 * table, of the start of each compressed chunk, except for the first chunk
 * which is omitted as it always has an offset of 0.  Therefore, a compressed
 * resource with N chunks will have a chunk table with N - 1 entries.
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
 * compressed size as a 32-bit, unsigned, little-endian integer.  Otherwise the
 * details are the same.
 */


/* Decompress the specified chunk that uses the specified compression type
 * @ctype, part of a WIM with default chunk size @wim_chunk_size.  For LZX the
 * separate @wim_chunk_size is needed because it determines the window size used
 * for LZX compression.  */
static int
decompress(const void *cchunk, unsigned clen, void *uchunk, unsigned ulen,
	   int ctype, u32 wim_chunk_size)
{
	switch (ctype) {
	case WIMLIB_COMPRESSION_TYPE_LZX:
		return wimlib_lzx_decompress2(cchunk, clen,
					      uchunk, ulen, wim_chunk_size);
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		return wimlib_xpress_decompress(cchunk, clen,
						uchunk, ulen);
	case WIMLIB_COMPRESSION_TYPE_LZMS:
		return wimlib_lzms_decompress(cchunk, clen, uchunk, ulen);
	default:
		wimlib_assert(0);
		return -1;
	}
}

struct data_range {
	u64 offset;
	u64 size;
};

/* Alternate chunk table format for resources with WIM_RESHDR_FLAG_CONCAT set.
 */
struct alt_chunk_table_header_disk {
	/* Uncompressed size of the resource.  */
	le64 res_usize;

	/* Number of bytes each compressed chunk decompresses into, except
	 * possibly the last which decompresses into the remainder.  */
	le32 chunk_size;

	/* ??? */
	le32 unknown;

	/* This header is directly followed by a table of compressed sizes of
	 * the chunks.  */
} _packed_attribute;

/*
 * read_compressed_wim_resource() -
 *
 * Read data from a compressed WIM resource.
 *
 * @rspec
 *	Specification of the compressed WIM resource to read from.
 * @ranges
 *	Nonoverlapping, nonempty ranges of the uncompressed resource data to
 *	read, sorted by increasing offset.
 * @num_ranges
 *	Number of ranges in @ranges; must be at least 1.
 * @cb
 *	Callback function to feed the data being read.  Each call provides the
 *	next chunk of the requested data.  Each chunk will be of nonzero size
 *	and will not cross range boundaries, but otherwise is of unspecified
 *	size.
 * @cb_ctx
 *	Parameter to pass to @cb_ctx.
 * @raw_chunks_mode
 *	If %true, this function will provide the raw compressed chunks of the
 *	resource rather than the uncompressed data.  In this mode, only a single
 *	data range can be requested, and it must cover the entire uncompressed
 *	resource.
 *
 * Possible return values:
 *
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_READ			  (errno set)
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE (errno set to 0)
 *	WIMLIB_ERR_NOMEM		  (errno set to ENOMEM)
 *	WIMLIB_ERR_DECOMPRESSION	  (errno set to EINVAL)
 *
 *	or other error code returned by the @cb function.
 */
static int
read_compressed_wim_resource(const struct wim_resource_spec * const rspec,
			     const struct data_range * const ranges,
			     const size_t num_ranges,
			     const consume_data_callback_t cb,
			     void * const cb_ctx,
			     const bool raw_chunks_mode)
{
	int ret;
	int errno_save;

	u64 *chunk_offsets = NULL;
	u8 *ubuf = NULL;
	void *cbuf = NULL;
	bool chunk_offsets_malloced = false;
	bool ubuf_malloced = false;
	bool cbuf_malloced = false;

	/* Sanity checks  */
	wimlib_assert(rspec != NULL);
	wimlib_assert(rspec->ctype != WIMLIB_COMPRESSION_TYPE_NONE);
	wimlib_assert(is_power_of_2(rspec->cchunk_size));
	wimlib_assert(cb != NULL);
	wimlib_assert(num_ranges != 0);
	for (size_t i = 0; i < num_ranges; i++) {
		DEBUG("Range %zu/%zu: %"PRIu64"@+%"PRIu64" / %"PRIu64,
		      i + 1, num_ranges, ranges[i].size, ranges[i].offset,
		      rspec->uncompressed_size);
		wimlib_assert(ranges[i].size != 0);
		wimlib_assert(ranges[i].offset + ranges[i].size >= ranges[i].size);
		wimlib_assert(ranges[i].offset + ranges[i].size <= rspec->uncompressed_size);
	}
	for (size_t i = 0; i < num_ranges - 1; i++)
		wimlib_assert(ranges[i].offset + ranges[i].size <= ranges[i + 1].offset);

	if (raw_chunks_mode) {
		wimlib_assert(num_ranges == 1);
		wimlib_assert(ranges[0].offset == 0);
		wimlib_assert(ranges[0].size == rspec->uncompressed_size);
	}

	/* Get the offsets of the first and last bytes of the read.  */
	const u64 first_offset = ranges[0].offset;
	const u64 last_offset = ranges[num_ranges - 1].offset + ranges[num_ranges - 1].size - 1;

	/* Get the file descriptor for the WIM.  */
	struct filedes * const in_fd = &rspec->wim->in_fd;

	/* Determine if we're reading a pipable resource from a pipe or not.  */
	const bool is_pipe_read = !filedes_is_seekable(in_fd);

	/* Determine if the chunk table is in an altenate format.  */
	const bool alt_chunk_table = (rspec->flags & WIM_RESHDR_FLAG_CONCAT) && !is_pipe_read;

	/* Get the maximum size of uncompressed chunks in this resource, which
	 * we require be a power of 2.  */
	u32 chunk_size;
	u64 cur_read_offset = rspec->offset_in_wim;
	if (alt_chunk_table) {
		/* Alternate chunk table format.  */
		struct alt_chunk_table_header_disk hdr;

		ret = full_pread(in_fd, &hdr, sizeof(hdr), cur_read_offset);
		if (ret)
			goto read_error;
		cur_read_offset += sizeof(hdr);

		chunk_size = le32_to_cpu(hdr.chunk_size);

		if (!is_power_of_2(chunk_size)) {
			ERROR("Invalid compressed resource: "
			      "expected power-of-2 chunk size (got %u)", chunk_size);
			ret = WIMLIB_ERR_INVALID_CHUNK_SIZE;
			goto out_free_memory;
		}
	} else {
		chunk_size = rspec->cchunk_size;
	}
	const u32 chunk_order = bsr32(chunk_size);

	/* Calculate the total number of chunks the resource is divided into.  */
	const u64 num_chunks = (rspec->uncompressed_size + chunk_size - 1) >> chunk_order;

	/* Calculate the 0-based indices of the first and last chunks containing
	 * data that needs to be passed to the callback.  */
	const u64 first_needed_chunk = first_offset >> chunk_order;
	const u64 last_needed_chunk = last_offset >> chunk_order;

	/* Calculate the 0-based index of the first chunk that actually needs to
	 * be read.  This is normally first_needed_chunk, but for pipe reads we
	 * must always start from the 0th chunk.  */
	const u64 read_start_chunk = (is_pipe_read ? 0 : first_needed_chunk);

	/* Calculate the number of chunk offsets that are needed for the chunks
	 * being read.  */
	const u64 num_needed_chunk_offsets =
		last_needed_chunk - read_start_chunk + 1 +
		(last_needed_chunk < num_chunks - 1);

	/* Calculate the number of entries in the chunk table.  Normally, it's
	 * one less than the number of chunks, since the first chunk has no
	 * entry.  But in the alternate chunk table format, the chunk entries
	 * contain chunk sizes, not offsets, and there is one per chunk.  */
	const u64 num_chunk_entries = (alt_chunk_table ? num_chunks : num_chunks - 1);

	/* Set the size of each chunk table entry based on the resource's
	 * uncompressed size.  XXX:  Does the alternate chunk table really
	 * always have 4-byte entries?  */
	const u64 chunk_entry_size =
		(rspec->uncompressed_size > (1ULL << 32) && !alt_chunk_table)
			? 8 : 4;

	/* Calculate the size of the chunk table in bytes.  */
	const u64 chunk_table_size = num_chunk_entries * chunk_entry_size;

	/* Calculate the size of the chunk table in bytes, including the header
	 * in the case of the alternate chunk table format.  */
	const u64 chunk_table_full_size =
		(alt_chunk_table) ? chunk_table_size + sizeof(struct alt_chunk_table_header_disk)
				  : chunk_table_size;

	if (!is_pipe_read) {
		/* Read the needed chunk table entries into memory and use them
		 * to initialize the chunk_offsets array.  */

		u64 first_chunk_entry_to_read;
		u64 last_chunk_entry_to_read;

		if (alt_chunk_table) {
			/* The alternate chunk table contains chunk sizes, not
			 * offsets, so we always must read all preceding entries
			 * in order to determine offsets.  */
			first_chunk_entry_to_read = 0;
			last_chunk_entry_to_read = last_needed_chunk;
		} else {
			/* Here we must account for the fact that the first
			 * chunk has no explicit chunk table entry.  */

			if (read_start_chunk == 0)
				first_chunk_entry_to_read = 0;
			else
				first_chunk_entry_to_read = read_start_chunk - 1;

			if (last_needed_chunk == 0)
				last_chunk_entry_to_read = 0;
			else
				last_chunk_entry_to_read = last_needed_chunk - 1;

			if (last_needed_chunk < num_chunks - 1)
				last_chunk_entry_to_read++;
		}

		const u64 num_chunk_entries_to_read =
			last_chunk_entry_to_read - first_chunk_entry_to_read + 1;

		const u64 chunk_offsets_alloc_size =
			max(num_chunk_entries_to_read,
			    num_needed_chunk_offsets) * sizeof(chunk_offsets[0]);

		if ((size_t)chunk_offsets_alloc_size != chunk_offsets_alloc_size)
			goto oom;

		if (chunk_offsets_alloc_size <= STACK_MAX) {
			chunk_offsets = alloca(chunk_offsets_alloc_size);
		} else {
			chunk_offsets = MALLOC(chunk_offsets_alloc_size);
			if (chunk_offsets == NULL)
				goto oom;
			chunk_offsets_malloced = true;
		}

		const size_t chunk_table_size_to_read =
			num_chunk_entries_to_read * chunk_entry_size;

		const u64 file_offset_of_needed_chunk_entries =
			cur_read_offset
			+ (first_chunk_entry_to_read * chunk_entry_size)
			+ (rspec->is_pipable ? (rspec->size_in_wim - chunk_table_size) : 0);

		void * const chunk_table_data =
			(u8*)chunk_offsets +
			chunk_offsets_alloc_size -
			chunk_table_size_to_read;

		ret = full_pread(in_fd, chunk_table_data, chunk_table_size,
				 file_offset_of_needed_chunk_entries);
		if (ret)
			goto read_error;

		/* Now fill in chunk_offsets from the entries we have read in
		 * chunk_tab_data.  We break aliasing rules here to avoid having
		 * to allocate yet another array.  */
		typedef le64 __attribute__((may_alias)) aliased_le64_t;
		typedef le32 __attribute__((may_alias)) aliased_le32_t;
		u64 * chunk_offsets_p = chunk_offsets;

		if (alt_chunk_table) {
			u64 cur_offset = 0;
			aliased_le32_t *raw_entries = chunk_table_data;

			for (size_t i = 0; i < num_chunk_entries_to_read; i++) {
				u32 entry = le32_to_cpu(raw_entries[i]);
				if (i >= read_start_chunk)
					*chunk_offsets_p++ = cur_offset;
				cur_offset += entry;
			}
			if (last_needed_chunk < num_chunks - 1)
				*chunk_offsets_p = cur_offset;
		} else {
			if (read_start_chunk == 0)
				*chunk_offsets_p++ = 0;

			if (chunk_entry_size == 4) {
				aliased_le32_t *raw_entries = chunk_table_data;
				for (size_t i = 0; i < num_chunk_entries_to_read; i++)
					*chunk_offsets_p++ = le32_to_cpu(raw_entries[i]);
			} else {
				aliased_le64_t *raw_entries = chunk_table_data;
				for (size_t i = 0; i < num_chunk_entries_to_read; i++)
					*chunk_offsets_p++ = le64_to_cpu(raw_entries[i]);
			}
		}

		/* Set offset to beginning of first chunk to read.  */
		cur_read_offset += chunk_offsets[0];
		if (rspec->is_pipable)
			cur_read_offset += read_start_chunk * sizeof(struct pwm_chunk_hdr);
		else
			cur_read_offset += chunk_table_size;
	}

	/* Allocate buffer for holding the uncompressed data of each chunk.  */
	if (chunk_size <= STACK_MAX) {
		ubuf = alloca(chunk_size);
	} else {
		ubuf = MALLOC(chunk_size);
		if (ubuf == NULL)
			goto oom;
		ubuf_malloced = true;
	}

	/* Unless the raw compressed data was requested, allocate a temporary
	 * buffer for reading compressed chunks, each of which can be at most
	 * @chunk_size - 1 bytes.  This excludes compressed chunks that are a
	 * full @chunk_size bytes, which are actually stored uncompressed.  */
	if (!raw_chunks_mode) {
		if (chunk_size - 1 <= STACK_MAX) {
			cbuf = alloca(chunk_size - 1);
		} else {
			cbuf = MALLOC(chunk_size - 1);
			if (cbuf == NULL)
				goto oom;
			cbuf_malloced = true;
		}
	}

	/* Set current data range.  */
	const struct data_range *cur_range = ranges;
	const struct data_range * const end_range = &ranges[num_ranges];
	u64 cur_range_pos = cur_range->offset;
	u64 cur_range_end = cur_range->offset + cur_range->size;

	/* Read and process each needed chunk.  */
	for (u64 i = read_start_chunk; i <= last_needed_chunk; i++) {

		/* Calculate uncompressed size of next chunk.  */
		u32 chunk_usize;
		if ((i == num_chunks - 1) && (rspec->uncompressed_size & (chunk_size - 1)))
			chunk_usize = (rspec->uncompressed_size & (chunk_size - 1));
		else
			chunk_usize = chunk_size;

		/* Calculate compressed size of next chunk.  */
		u32 chunk_csize;
		if (is_pipe_read) {
			struct pwm_chunk_hdr chunk_hdr;

			ret = full_pread(in_fd, &chunk_hdr,
					 sizeof(chunk_hdr), cur_read_offset);
			if (ret)
				goto read_error;
			chunk_csize = le32_to_cpu(chunk_hdr.compressed_size);
		} else {
			if (i == num_chunks - 1) {
				chunk_csize = rspec->size_in_wim -
					      chunk_table_full_size -
					      chunk_offsets[i - read_start_chunk];
				if (rspec->is_pipable)
					chunk_csize -= num_chunks * sizeof(struct pwm_chunk_hdr);
			} else {
				chunk_csize = chunk_offsets[i + 1 - read_start_chunk] -
					      chunk_offsets[i - read_start_chunk];
			}
		}
		if (chunk_csize == 0 || chunk_csize > chunk_usize) {
			ERROR("Invalid chunk size in compressed resource!");
			errno = EINVAL;
			ret = WIMLIB_ERR_DECOMPRESSION;
			goto out_free_memory;
		}
		if (rspec->is_pipable)
			cur_read_offset += sizeof(struct pwm_chunk_hdr);

		/* Offsets in the uncompressed resource at which this chunk
		 * starts and ends.  */
		const u64 chunk_start_offset = i << chunk_order;
		const u64 chunk_end_offset = chunk_start_offset + chunk_usize;

		if (chunk_end_offset <= cur_range_pos) {

			/* The next range does not require data in this chunk,
			 * so skip it.  */
			cur_read_offset += chunk_csize;
			if (is_pipe_read) {
				u8 dummy;

				ret = full_pread(in_fd, &dummy, 1, cur_read_offset - 1);
				if (ret)
					goto read_error;
			}
		} else {

			/* Read the chunk and feed data to the callback
			 * function.  */
			u8 *cb_buf;

			ret = full_pread(in_fd,
					 cbuf,
					 chunk_csize,
					 cur_read_offset);
			if (ret)
				goto read_error;

			if (chunk_csize != chunk_usize && !raw_chunks_mode) {
				DEBUG("Decompressing chunk %"PRIu64" "
				      "(csize=%"PRIu64" usize=%"PRIu64"",
				      i, chunk_csize, chunk_usize);
				ret = decompress(cbuf,
						 chunk_csize,
						 ubuf,
						 chunk_usize,
						 rspec->ctype,
						 chunk_size);
				if (ret) {
					ERROR("Failed to decompress data!");
					ret = WIMLIB_ERR_DECOMPRESSION;
					errno = EINVAL;
					goto out_free_memory;
				}
				cb_buf = ubuf;
			} else {
				/* Raw chunks requested, or data stored
				 * uncompressed.  */
				cb_buf = cbuf;
			}
			cur_read_offset += chunk_csize;

			/* At least one range requires data in this chunk.  */
			do {
				size_t start, end, size;

				/* Calculate how many bytes of data should be
				 * sent to the callback function, taking into
				 * account that data sent to the callback
				 * function must not overlap range boundaries.
				 */
				start = cur_range_pos - chunk_start_offset;
				end = min(cur_range_end, chunk_end_offset) - chunk_start_offset;
				size = end - start;

				if (raw_chunks_mode)
					ret = (*cb)(&cb_buf[0], chunk_csize, cb_ctx);
				else
					ret = (*cb)(&cb_buf[start], size, cb_ctx);

				if (ret)
					goto out_free_memory;

				cur_range_pos += size;
				if (cur_range_pos == cur_range_end) {
					/* Advance to next range.  */
					if (++cur_range == end_range) {
						cur_range_pos = ~0ULL;
					} else {
						cur_range_pos = cur_range->offset;
						cur_range_end = cur_range->offset + cur_range->size;
					}
				}
			} while (cur_range_pos < chunk_end_offset);
		}
	}

	if (is_pipe_read &&
	    last_offset == rspec->uncompressed_size - 1 &&
	    chunk_table_size)
	{
		u8 dummy;
		/* If reading a pipable resource from a pipe and the full data
		 * was requested, skip the chunk table at the end so that the
		 * file descriptor is fully clear of the resource after this
		 * returns.  */
		cur_read_offset += chunk_table_size;
		ret = full_pread(in_fd, &dummy, 1, cur_read_offset - 1);
		if (ret)
			goto read_error;
	}
	ret = 0;
out_free_memory:
	errno_save = errno;
	if (chunk_offsets_malloced)
		FREE(chunk_offsets);
	if (ubuf_malloced)
		FREE(ubuf);
	if (cbuf_malloced)
		FREE(cbuf);
	errno = errno_save;
	return ret;

oom:
	ERROR("Not enough memory available to read size=%"PRIu64" bytes "
	      "from compressed WIM resource!", last_offset - first_offset + 1);
	errno = ENOMEM;
	ret = WIMLIB_ERR_NOMEM;
	goto out_free_memory;

read_error:
	ERROR_WITH_ERRNO("Error reading compressed WIM resource!");
	goto out_free_memory;
}

/* Read raw data from a file descriptor at the specified offset, feeding the
 * data it in chunks into the specified callback function.  */
static int
read_raw_file_data(struct filedes *in_fd, u64 size,
		   consume_data_callback_t cb, void *cb_ctx, u64 offset)
{
	u8 buf[BUFFER_SIZE];
	size_t bytes_to_read;
	int ret;

	while (size) {
		bytes_to_read = min(sizeof(buf), size);
		ret = full_pread(in_fd, buf, bytes_to_read, offset);
		if (ret) {
			ERROR_WITH_ERRNO("Read error");
			return ret;
		}
		ret = cb(buf, bytes_to_read, cb_ctx);
		if (ret)
			return ret;
		size -= bytes_to_read;
		offset += bytes_to_read;
	}
	return 0;
}

static int
bufferer_cb(const void *chunk, size_t size, void *_ctx)
{
	u8 **buf_p = _ctx;

	*buf_p = mempcpy(*buf_p, chunk, size);
	return 0;
}

/*
 * read_partial_wim_resource()-
 *
 * Read a range of data from an uncompressed or compressed resource in a WIM
 * file.  Data is fed chunk-by-chunk into the callback function @cb, passing it
 * the argument @cb_ctx.
 *
 * By default, this function provides the uncompressed data of the resource, and
 * @offset and @size and interpreted relative to the uncompressed contents of
 * the resource.  This behavior can be modified by either of the following
 * flags:
 *
 * WIMLIB_READ_RESOURCE_FLAG_RAW_FULL:
 *	Read @size bytes at @offset of the raw contents of the compressed
 *	resource.  In the case of pipable resources, this excludes the stream
 *	header.  Exclusive with WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS.
 *
 * WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS:
 *	Read the raw compressed chunks of the compressed resource.  @size must
 *	be the full uncompressed size, @offset must be 0, and @cb_chunk_size
 *	must be the resource chunk size.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_READ			  (errno set)
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE (errno set to 0)
 *	WIMLIB_ERR_NOMEM		  (errno set to ENOMEM)
 *	WIMLIB_ERR_DECOMPRESSION	  (errno set to EINVAL)
 *
 *	or other error code returned by the @cb function.
 */
static int
read_partial_wim_resource(const struct wim_resource_spec *rspec,
			  u64 offset, u64 size, consume_data_callback_t cb,
			  void *cb_ctx, int flags)
{
	/* Sanity checks.  */
	if (flags & WIMLIB_READ_RESOURCE_FLAG_RAW_FULL) {
		wimlib_assert(!(flags & WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS));
		wimlib_assert(offset + size >= offset);
		wimlib_assert(offset + size <= rspec->size_in_wim);
	} else if (flags & WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS) {
		wimlib_assert(offset == 0);
		wimlib_assert(offset == rspec->uncompressed_size);
	} else {
		wimlib_assert(offset + size >= offset);
		wimlib_assert(offset + size <= rspec->uncompressed_size);
	}

	DEBUG("Reading %"PRIu64" @ %"PRIu64" from WIM resource  "
	      "%"PRIu64" => %"PRIu64" @ %"PRIu64" (flags 0x%08x)",
	      size, offset, rspec->uncompressed_size,
	      rspec->size_in_wim, rspec->offset_in_wim, flags);

	/* Trivial case.  */
	if (size == 0)
		return 0;

	if ((flags & WIMLIB_READ_RESOURCE_FLAG_RAW_FULL) ||
	    rspec->ctype == WIMLIB_COMPRESSION_TYPE_NONE)
	{
		return read_raw_file_data(&rspec->wim->in_fd,
					  size,
					  cb,
					  cb_ctx,
					  rspec->offset_in_wim + offset);
	} else {
		bool raw_chunks = !!(flags & WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS);
		struct data_range range = {
			.offset = offset,
			.size = size,
		};
		return read_compressed_wim_resource(rspec, &range, 1,
						    cb, cb_ctx, raw_chunks);
	}
}

int
read_partial_wim_stream_into_buf(const struct wim_lookup_table_entry *lte,
				 size_t size, u64 offset, void *_buf)
{
	u8 *buf = _buf;

	wimlib_assert(lte->resource_location == RESOURCE_IN_WIM);

	return read_partial_wim_resource(lte->rspec,
					 lte->offset_in_res + offset,
					 size,
					 bufferer_cb,
					 &buf,
					 0);
}

static int
skip_chunk_cb(const void *chunk, size_t size, void *_ctx)
{
	return 0;
}

/* Skip over the data of the specified stream, which must correspond to a full
 * WIM resource.  */
int
skip_wim_stream(struct wim_lookup_table_entry *lte)
{
	wimlib_assert(lte->resource_location == RESOURCE_IN_WIM);
	wimlib_assert(!lte_is_partial(lte));
	return read_partial_wim_resource(lte->rspec,
					 0,
					 lte->rspec->uncompressed_size,
					 skip_chunk_cb,
					 NULL,
					 WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS);
}

static int
read_wim_stream_prefix(const struct wim_lookup_table_entry *lte, u64 size,
		       consume_data_callback_t cb, void *cb_ctx, int flags)
{
	return read_partial_wim_resource(lte->rspec,
					 lte->offset_in_res,
					 size,
					 cb,
					 cb_ctx,
					 flags);
}

#ifndef __WIN32__
/* This function handles reading stream data that is located in an external
 * file,  such as a file that has been added to the WIM image through execution
 * of a wimlib_add_command.
 *
 * This assumes the file can be accessed using the standard POSIX open(),
 * read(), and close().  On Windows this will not necessarily be the case (since
 * the file may need FILE_FLAG_BACKUP_SEMANTICS to be opened, or the file may be
 * encrypted), so Windows uses its own code for its equivalent case.  */
static int
read_file_on_disk_prefix(const struct wim_lookup_table_entry *lte, u64 size,
			 consume_data_callback_t cb, void *cb_ctx,
			 int _ignored_flags)
{
	int ret;
	int raw_fd;
	struct filedes fd;

	wimlib_assert(size <= lte->size);

	DEBUG("Reading %"PRIu64" bytes from \"%"TS"\"", size, lte->file_on_disk);

	raw_fd = open(lte->file_on_disk, O_BINARY | O_RDONLY);
	if (raw_fd < 0) {
		ERROR_WITH_ERRNO("Can't open \"%"TS"\"", lte->file_on_disk);
		return WIMLIB_ERR_OPEN;
	}
	filedes_init(&fd, raw_fd);
	ret = read_raw_file_data(&fd, size, cb, cb_ctx, 0);
	filedes_close(&fd);
	return ret;
}
#endif /* !__WIN32__ */

/* This function handles the trivial case of reading stream data that is, in
 * fact, already located in an in-memory buffer.  */
static int
read_buffer_prefix(const struct wim_lookup_table_entry *lte,
		   u64 size, consume_data_callback_t cb,
		   void *cb_ctx, int _ignored_flags)
{
	wimlib_assert(size <= lte->size);
	return (*cb)(lte->attached_buffer, size, cb_ctx);
}

typedef int (*read_stream_prefix_handler_t)(const struct wim_lookup_table_entry *lte,
					    u64 size,
					    consume_data_callback_t cb,
					    void *cb_ctx, int flags);

/*
 * read_stream_prefix()-
 *
 * Reads the first @size bytes from a generic "stream", which may be located in
 * any one of several locations, such as in a WIM file (compressed or
 * uncompressed), in an external file, or directly in an in-memory buffer.
 *
 * This function feeds the data to a callback function @cb.
 *
 * If the stream is located in a WIM file, @flags can be set as documented in
 * read_partial_wim_resource().  Otherwise @flags are ignored.
 *
 * Returns 0 on success; nonzero on error.  A nonzero value will be returned if
 * the stream data cannot be successfully read (for a number of different
 * reasons, depending on the stream location), or if @cb returned nonzero in
 * which case that error code will be returned.
 */
int
read_stream_prefix(const struct wim_lookup_table_entry *lte, u64 size,
		   consume_data_callback_t cb, void *cb_ctx, int flags)
{
	static const read_stream_prefix_handler_t handlers[] = {
		[RESOURCE_IN_WIM]             = read_wim_stream_prefix,
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
	return handlers[lte->resource_location](lte, size, cb, cb_ctx, flags);
}

/* Read the full uncompressed data of the specified stream into the specified
 * buffer, which must have space for at least lte->size bytes.  */
int
read_full_stream_into_buf(const struct wim_lookup_table_entry *lte, void *_buf)
{
	u8 *buf = _buf;
	return read_stream_prefix(lte, lte->size, bufferer_cb, &buf, 0);
}

/* Read the full uncompressed data of the specified stream.  A buffer sufficient
 * to hold the data is allocated and returned in @buf_ret.  */
int
read_full_stream_into_alloc_buf(const struct wim_lookup_table_entry *lte,
				void **buf_ret)
{
	int ret;
	void *buf;

	if ((size_t)lte->size != lte->size) {
		ERROR("Can't read %"PRIu64" byte stream into "
		      "memory", lte->size);
		return WIMLIB_ERR_NOMEM;
	}

	buf = MALLOC(lte->size);
	if (buf == NULL)
		return WIMLIB_ERR_NOMEM;

	ret = read_full_stream_into_buf(lte, buf);
	if (ret) {
		FREE(buf);
		return ret;
	}

	*buf_ret = buf;
	return 0;
}

/* Retrieve the full uncompressed data of the specified WIM resource.  */
static int
wim_resource_spec_to_data(struct wim_resource_spec *rspec, void **buf_ret)
{
	int ret;
	struct wim_lookup_table_entry *lte;

	lte = new_lookup_table_entry();
	if (lte == NULL)
		return WIMLIB_ERR_NOMEM;

	lte->unhashed = 1;
	lte_bind_wim_resource_spec(lte, rspec);
	lte->flags = rspec->flags;
	lte->size = rspec->uncompressed_size;
	lte->offset_in_res = 0;

	ret = read_full_stream_into_alloc_buf(lte, buf_ret);

	lte_unbind_wim_resource_spec(lte);
	free_lookup_table_entry(lte);
	return ret;
}

/* Retrieve the full uncompressed data of the specified WIM resource.  */
int
wim_reshdr_to_data(const struct wim_reshdr *reshdr, WIMStruct *wim, void **buf_ret)
{
	DEBUG("offset_in_wim=%"PRIu64", size_in_wim=%"PRIu64", "
	      "uncompressed_size=%"PRIu64,
	      reshdr->offset_in_wim, reshdr->size_in_wim, reshdr->uncompressed_size);

	struct wim_resource_spec rspec;
	wim_res_hdr_to_spec(reshdr, wim, &rspec);
	return wim_resource_spec_to_data(&rspec, buf_ret);
}

struct streamifier_context {
	struct read_stream_list_callbacks cbs;
	struct wim_lookup_table_entry *cur_stream;
	u64 cur_stream_offset;
	struct wim_lookup_table_entry *final_stream;
	size_t list_head_offset;
};

/* Callback for translating raw resource data into streams.  */
static int
streamifier_cb(const void *chunk, size_t size, void *_ctx)
{
	struct streamifier_context *ctx = _ctx;
	int ret;

	DEBUG("%zu bytes passed to streamifier", size);

	wimlib_assert(ctx->cur_stream != NULL);

	if (ctx->cur_stream_offset == 0) {
		/* Starting a new stream.  */
		DEBUG("Begin new stream (size=%"PRIu64").", ctx->cur_stream->size);
		ret = (*ctx->cbs.begin_stream)(ctx->cur_stream, true, ctx->cbs.begin_stream_ctx);
		if (ret)
			return ret;
	}

	/* Consume the chunk.  */
	ret = (*ctx->cbs.consume_chunk)(chunk, size, ctx->cbs.consume_chunk_ctx);
	if (ret)
		return ret;
	ctx->cur_stream_offset += size;

	if (ctx->cur_stream_offset == ctx->cur_stream->size) {
		/* Finished reading all the data for a stream; advance to the
		 * next one.  */
		DEBUG("End stream (size=%"PRIu64").", ctx->cur_stream->size);
		ret = (*ctx->cbs.end_stream)(ctx->cur_stream, 0, ctx->cbs.end_stream_ctx);
		if (ret)
			return ret;

		if (ctx->cur_stream != ctx->final_stream) {
			struct list_head *cur = (struct list_head *)
					((u8*)ctx->cur_stream + ctx->list_head_offset);
			struct list_head *next = cur->next;

			ctx->cur_stream = (struct wim_lookup_table_entry *)
					((u8*)next - ctx->list_head_offset);

			ctx->cur_stream_offset = 0;
		} else {
			ctx->cur_stream = NULL;
		}
	}
	return 0;
}

struct hasher_context {
	SHA_CTX sha_ctx;
	struct read_stream_list_callbacks cbs;
};

/* Callback for starting to read a stream while calculating its SHA1 message
 * digest.  */
static int
hasher_begin_stream(struct wim_lookup_table_entry *lte, bool is_partial_res,
		    void *_ctx)
{
	struct hasher_context *ctx = _ctx;

	sha1_init(&ctx->sha_ctx);

	if (ctx->cbs.begin_stream == NULL)
		return 0;
	else
		return (*ctx->cbs.begin_stream)(lte, is_partial_res,
						ctx->cbs.begin_stream_ctx);
}

/* Callback for continuing to read a stream while calculating its SHA1 message
 * digest.  */
static int
hasher_consume_chunk(const void *chunk, size_t size, void *_ctx)
{
	struct hasher_context *ctx = _ctx;

	sha1_update(&ctx->sha_ctx, chunk, size);
	if (ctx->cbs.consume_chunk == NULL)
		return 0;
	else
		return (*ctx->cbs.consume_chunk)(chunk, size, ctx->cbs.consume_chunk_ctx);
}

/* Callback for finishing reading a stream while calculating its SHA1 message
 * digest.  */
static int
hasher_end_stream(struct wim_lookup_table_entry *lte, int status, void *_ctx)
{
	struct hasher_context *ctx = _ctx;
	u8 hash[SHA1_HASH_SIZE];
	int ret;

	if (status) {
		ret = status;
		goto out_next_cb;
	}

	sha1_final(hash, &ctx->sha_ctx);

	if (lte->unhashed) {
		/* No SHA1 message digest was present before; fill it in with
		 * the calculated value.  */
		DEBUG("Set SHA1 message digest for stream (size=%"PRIu64").", lte->size);
		copy_hash(lte->hash, hash);
	} else {
		/* A SHA1 message digest was present before.  Verify that it is
		 * the same as the calculated value.  */
		if (!hashes_equal(hash, lte->hash)) {
			if (wimlib_print_errors) {
				ERROR("Invalid SHA1 message digest "
				      "on the following WIM stream:");
				print_lookup_table_entry(lte, stderr);
				if (lte->resource_location == RESOURCE_IN_WIM)
					ERROR("The WIM file appears to be corrupt!");
			}
			ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
			errno = EINVAL;
			goto out_next_cb;
		}
		DEBUG("SHA1 message digest okay for stream (size=%"PRIu64").", lte->size);
	}
	ret = 0;
out_next_cb:
	if (ctx->cbs.end_stream == NULL)
		return ret;
	else
		return (*ctx->cbs.end_stream)(lte, ret, ctx->cbs.end_stream_ctx);
}

/* Read the full data of the stream @lte, passing the data into the specified
 * callbacks (all of which are optional) and either checking or computing the
 * SHA1 message digest of the stream.  */
static int
read_full_stream_with_sha1(struct wim_lookup_table_entry *lte,
			   const struct read_stream_list_callbacks *cbs)
{
	int ret;

	struct hasher_context hasher_ctx = {
		.cbs = *cbs,
	};

	ret = hasher_begin_stream(lte, false, &hasher_ctx);
	if (ret)
		return ret;

	ret = read_stream_prefix(lte, lte->size, hasher_consume_chunk,
				 &hasher_ctx, 0);

	return hasher_end_stream(lte, ret, &hasher_ctx);
}

struct rechunkifier_context {
	u8 *buffer;
	u32 buffer_filled;
	u32 cb_chunk_size;

	const struct data_range *ranges;
	size_t num_ranges;
	size_t cur_range;
	u64 range_bytes_remaining;

	consume_data_callback_t cb;
	void *cb_ctx;
};

/* Wrapper callback for adjusting the data chunk size.  */
static int
rechunkifier_cb(const void *chunk, size_t size, void *_ctx)
{
	struct rechunkifier_context *ctx = _ctx;
	const u8 *chunkptr = chunk;
	size_t bytes_to_copy;
	int ret;

	wimlib_assert(ctx->cur_range != ctx->num_ranges);

	while (size) {

		/* Append more data to the buffer.  */
		bytes_to_copy = size;

		if (bytes_to_copy > ctx->cb_chunk_size - ctx->buffer_filled)
			bytes_to_copy = ctx->cb_chunk_size - ctx->buffer_filled;

		if (bytes_to_copy > ctx->range_bytes_remaining - ctx->buffer_filled)
			bytes_to_copy = ctx->range_bytes_remaining - ctx->buffer_filled;

		memcpy(&ctx->buffer[ctx->buffer_filled], chunkptr, bytes_to_copy);

		ctx->buffer_filled += bytes_to_copy;
		chunkptr += bytes_to_copy;
		size -= bytes_to_copy;
		ctx->range_bytes_remaining -= bytes_to_copy;

		if (ctx->buffer_filled == ctx->cb_chunk_size ||
		    ctx->range_bytes_remaining == 0)
		{
			/* Maximum chunk size reached, or current range ended.
			 * Call the next consume_data_callback_t and empty the
			 * buffer  */
			ret = (*ctx->cb)(ctx->buffer, ctx->buffer_filled, ctx->cb_ctx);
			if (ret)
				return ret;
			ctx->buffer_filled = 0;

			if (ctx->range_bytes_remaining == 0 &&
			    ++ctx->cur_range != ctx->num_ranges)
				ctx->range_bytes_remaining = ctx->ranges[ctx->cur_range].size;
		}
	}
	return 0;
}

/*
 * Read a list of streams, each of which may be in any supported location (e.g.
 * in a WIM or in an external file).  Unlike read_stream_prefix() or the
 * functions which call it, this function optimizes the case where multiple
 * streams are packed into a single compressed WIM resource and reads them all
 * consecutively, only decompressing the data one time.
 *
 * @stream_list
 *	List of streams (represented as `struct wim_lookup_table_entry's) to
 *	read.
 * @list_head_offset
 *	Offset of the `struct list_head' within each `struct
 *	wim_lookup_table_entry' that makes up the @stream_list.
 * @cb_chunk_size
 *	Size of chunks to provide to @consume_chunk.  For a given stream, all
 *	the chunks will be this size, except possibly the last which will be the
 *	remainder.  If @
 * @cbs TODO
 *
 * Returns 0 on success; a nonzero error code on failure.  Failure can occur due
 * to an error reading the data or due to an error status being returned by any
 * of the callback functions.
 */
int
read_stream_list(struct list_head *stream_list,
		 size_t list_head_offset,
		 u32 cb_chunk_size,
		 const struct read_stream_list_callbacks *cbs)
{
	int ret;
	struct list_head *cur, *next;
	struct wim_lookup_table_entry *lte;

	ret = sort_stream_list_by_sequential_order(stream_list, list_head_offset);
	if (ret)
		return ret;

	for (cur = stream_list->next, next = cur->next;
	     cur != stream_list;
	     cur = next, next = cur->next)
	{
		lte = (struct wim_lookup_table_entry*)((u8*)cur - list_head_offset);

		if (lte_is_partial(lte)) {

			struct wim_lookup_table_entry *lte_next, *lte_last;
			struct list_head *next2;
			size_t stream_count;

			/* The next stream is a proper sub-sequence of a WIM
			 * resource.  See if there are other streams in the same
			 * resource that need to be read.  Since
			 * sort_stream_list_by_sequential_order() sorted the
			 * streams by offset in the WIM, this can be determined
			 * by simply scanning forward in the list.  */

			lte_last = lte;
			stream_count = 1;
			for (next2 = next;
			     next2 != stream_list
			     && (lte_next = (struct wim_lookup_table_entry*)
						((u8*)next2 - list_head_offset),
				 lte_next->resource_location == RESOURCE_IN_WIM
				 && lte_next->rspec == lte->rspec);
			     next2 = next2->next)
			{
				lte_last = lte_next;
				stream_count++;
			}
			if (stream_count > 1) {
				/* Reading multiple streams combined into a
				 * single WIM resource.  They are in the stream
				 * list, sorted by offset; @lte specifies the
				 * first stream in the resource that needs to be
				 * read and @lte_last specifies the last stream
				 * in the resource that needs to be read.  */

				DEBUG("Reading %zu streams combined in same "
				      "WIM resource", stream_count);

				next = next2;

				struct data_range ranges[stream_count];

				{
					struct list_head *next3;
					size_t i;
					struct wim_lookup_table_entry *lte_cur;

					next3 = cur;
					for (i = 0; i < stream_count; i++) {
						lte_cur = (struct wim_lookup_table_entry*)
							((u8*)next3 - list_head_offset);
						ranges[i].offset = lte_cur->offset_in_res;
						ranges[i].size = lte_cur->size;
						next3 = next3->next;
					}
				}

				/* Set up a chain of callbacks.
				 *
				 * The first level is the
				 * streamifier_cb,
				 * which takes in chunks of data and divides
				 * them into the constituent streams.
				 *
				 * The second level are the SHA1 message digest
				 * callbacks, which checksum each stream.
				 *
				 * rechunkifier_cb handles dividing the read
				 * data into chunks of maximum size
				 * @cb_chunk_size.  If @cb_chunk_size is 0, then
				 * this callback is not needed.
				 *
				 * Finally, the last level of callbacks are
				 * @cbs, passed as arguments to this function.
				 */

				struct rechunkifier_context *rechunkifier_ctx = NULL;
				consume_data_callback_t last_cb;
				void *last_cb_ctx;

				if (cb_chunk_size != 0) {
					rechunkifier_ctx = alloca(sizeof(*rechunkifier_ctx));
					*rechunkifier_ctx = (struct rechunkifier_context) {
						.buffer			= MALLOC(cb_chunk_size),
						.buffer_filled		= 0,
						.cb_chunk_size		= cb_chunk_size,
						.ranges			= ranges,
						.num_ranges		= stream_count,
						.cur_range		= 0,
						.range_bytes_remaining	= ranges[0].size,
						.cb			= cbs->consume_chunk,
						.cb_ctx			= cbs->consume_chunk_ctx,
					};

					if (rechunkifier_ctx->buffer == NULL)
						return WIMLIB_ERR_NOMEM;
					last_cb = rechunkifier_cb;
					last_cb_ctx = rechunkifier_ctx;
				} else {
					rechunkifier_ctx = NULL;
					last_cb = cbs->consume_chunk;
					last_cb_ctx = cbs->consume_chunk_ctx;
				}

				struct hasher_context hasher_ctx = {
					.cbs = {
						.begin_stream		= cbs->begin_stream,
						.begin_stream_ctx	= cbs->begin_stream_ctx,
						.consume_chunk		= last_cb,
						.consume_chunk_ctx	= last_cb_ctx,
						.end_stream		= cbs->end_stream,
						.end_stream_ctx		= cbs->end_stream_ctx,
					},
				};

				struct streamifier_context streamifier_ctx = {
					.cbs = {
						.begin_stream		= hasher_begin_stream,
						.begin_stream_ctx	= &hasher_ctx,
						.consume_chunk		= hasher_consume_chunk,
						.consume_chunk_ctx	= &hasher_ctx,
						.end_stream		= hasher_end_stream,
						.end_stream_ctx		= &hasher_ctx,
					},
					.cur_stream		= lte,
					.cur_stream_offset	= 0,
					.final_stream		= lte_last,
					.list_head_offset	= list_head_offset,
				};

				ret = read_compressed_wim_resource(lte->rspec,
								   ranges,
								   stream_count,
								   streamifier_cb,
								   &streamifier_ctx,
								   false);
				if (rechunkifier_ctx != NULL)
					FREE(rechunkifier_ctx->buffer);

				if (ret) {
					if (streamifier_ctx.cur_stream_offset != 0) {
						ret = (*streamifier_ctx.cbs.end_stream)
							(streamifier_ctx.cur_stream,
							 ret,
							 streamifier_ctx.cbs.end_stream_ctx);
					}
					return ret;
				}
				continue;
			}
		}

		ret = read_full_stream_with_sha1(lte, cbs);
		if (ret > 0)
			return ret;
	}
	return 0;
}

/* Extracts the first @size bytes of a stream to somewhere.  In the process, the
 * SHA1 message digest of the uncompressed stream is checked if the full stream
 * is being extracted.
 *
 * @extract_chunk is the callback to extract each chunk of the stream.  */
int
extract_stream(struct wim_lookup_table_entry *lte, u64 size,
	       consume_data_callback_t extract_chunk, void *extract_chunk_arg)
{
	if (size == lte->size) {
		/* Do SHA1.  */
		struct read_stream_list_callbacks cbs = {
			.consume_chunk		= extract_chunk,
			.consume_chunk_ctx	= extract_chunk_arg,
		};
		return read_full_stream_with_sha1(lte, &cbs);
	} else {
		/* Don't do SHA1.  */
		return read_stream_prefix(lte, size, extract_chunk,
					  extract_chunk_arg, 0);
	}
}

/* Write a chunk of data to a file descriptor.  This function can be passed as a
 * consume_data_callback_t.  */
int
extract_chunk_to_fd(const void *chunk, size_t size, void *_fd_p)
{
	struct filedes *fd = _fd_p;

	int ret = full_write(fd, chunk, size);
	if (ret) {
		ERROR_WITH_ERRNO("Error writing to file descriptor");
		return ret;
	}

	return 0;
}

/* Extract the first @size bytes of the specified stream to the specified file
 * descriptor.  If @size is the full size of the stream, its SHA1 message digest
 * is also checked.  */
int
extract_stream_to_fd(struct wim_lookup_table_entry *lte,
		     struct filedes *fd, u64 size)
{
	return extract_stream(lte, size, extract_chunk_to_fd, fd);
}

/* Calculate the SHA1 message digest of a stream, storing it in @lte->hash.  */
int
sha1_stream(struct wim_lookup_table_entry *lte)
{
	struct read_stream_list_callbacks cbs = {
	};
	return read_full_stream_with_sha1(lte, &cbs);
}

/* Convert a WIM resource header to a stand-alone resource specification.  */
void
wim_res_hdr_to_spec(const struct wim_reshdr *reshdr, WIMStruct *wim,
		    struct wim_resource_spec *spec)
{
	spec->wim = wim;
	spec->offset_in_wim = reshdr->offset_in_wim;
	spec->size_in_wim = reshdr->size_in_wim;
	spec->uncompressed_size = reshdr->uncompressed_size;
	INIT_LIST_HEAD(&spec->lte_list);
	spec->flags = reshdr->flags;
	spec->is_pipable = wim_is_pipable(wim);
	if (spec->flags & (WIM_RESHDR_FLAG_COMPRESSED | WIM_RESHDR_FLAG_CONCAT)) {
		spec->ctype = wim->compression_type;
		spec->cchunk_size = wim->chunk_size;
	} else {
		spec->ctype = WIMLIB_COMPRESSION_TYPE_NONE;
		spec->cchunk_size = 0;
	}
}

/* Convert a stand-alone resource specification to a WIM resource header.  */
void
wim_res_spec_to_hdr(const struct wim_resource_spec *rspec,
		    struct wim_reshdr *reshdr)
{
	reshdr->offset_in_wim     = rspec->offset_in_wim;
	reshdr->size_in_wim       = rspec->size_in_wim;
	reshdr->flags             = rspec->flags;
	reshdr->uncompressed_size = rspec->uncompressed_size;
}

/* Translates a WIM resource header from the on-disk format into an in-memory
 * format.  */
int
get_wim_reshdr(const struct wim_reshdr_disk *disk_reshdr,
	       struct wim_reshdr *reshdr)
{
	reshdr->offset_in_wim = le64_to_cpu(disk_reshdr->offset_in_wim);
	reshdr->size_in_wim = (((u64)disk_reshdr->size_in_wim[0] <<  0) |
			      ((u64)disk_reshdr->size_in_wim[1] <<  8) |
			      ((u64)disk_reshdr->size_in_wim[2] << 16) |
			      ((u64)disk_reshdr->size_in_wim[3] << 24) |
			      ((u64)disk_reshdr->size_in_wim[4] << 32) |
			      ((u64)disk_reshdr->size_in_wim[5] << 40) |
			      ((u64)disk_reshdr->size_in_wim[6] << 48));
	reshdr->uncompressed_size = le64_to_cpu(disk_reshdr->uncompressed_size);
	reshdr->flags = disk_reshdr->flags;

	/* Avoid possible overflows.  */
	if (reshdr->offset_in_wim & 0xc000000000000000ULL)
		return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;

	if (reshdr->uncompressed_size & 0xc000000000000000ULL)
		return WIMLIB_ERR_INVALID_LOOKUP_TABLE_ENTRY;

	return 0;
}

/* Translates a WIM resource header from an in-memory format into the on-disk
 * format.  */
void
put_wim_reshdr(const struct wim_reshdr *reshdr,
	       struct wim_reshdr_disk *disk_reshdr)
{
	disk_reshdr->size_in_wim[0] = reshdr->size_in_wim  >>  0;
	disk_reshdr->size_in_wim[1] = reshdr->size_in_wim  >>  8;
	disk_reshdr->size_in_wim[2] = reshdr->size_in_wim  >> 16;
	disk_reshdr->size_in_wim[3] = reshdr->size_in_wim  >> 24;
	disk_reshdr->size_in_wim[4] = reshdr->size_in_wim  >> 32;
	disk_reshdr->size_in_wim[5] = reshdr->size_in_wim  >> 40;
	disk_reshdr->size_in_wim[6] = reshdr->size_in_wim  >> 48;
	disk_reshdr->flags = reshdr->flags;
	disk_reshdr->offset_in_wim = cpu_to_le64(reshdr->offset_in_wim);
	disk_reshdr->uncompressed_size = cpu_to_le64(reshdr->uncompressed_size);
}
