/*
 * resource.c
 *
 * Code for reading streams and resources, including compressed WIM resources.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "wimlib/alloca.h"
#include "wimlib/assert.h"
#include "wimlib/bitops.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/lookup_table.h"
#include "wimlib/resource.h"
#include "wimlib/sha1.h"
#include "wimlib/wim.h"

#ifdef __WIN32__
/* for read_winnt_file_prefix(), read_win32_encrypted_file_prefix() */
#  include "wimlib/win32.h"
#endif

#ifdef WITH_NTFS_3G
/* for read_ntfs_file_prefix() */
#  include "wimlib/ntfs_3g.h"
#endif


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


struct data_range {
	u64 offset;
	u64 size;
};

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
 *	next chunk of the requested data, uncompressed.  Each chunk will be of
 *	nonzero size and will not cross range boundaries, but otherwise will be
 *	of unspecified size.
 * @cb_ctx
 *	Parameter to pass to @cb_ctx.
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
			     void * const cb_ctx)
{
	int ret;
	int errno_save;

	u64 *chunk_offsets = NULL;
	u8 *ubuf = NULL;
	void *cbuf = NULL;
	bool chunk_offsets_malloced = false;
	bool ubuf_malloced = false;
	bool cbuf_malloced = false;
	struct wimlib_decompressor *decompressor = NULL;

	/* Sanity checks  */
	wimlib_assert(rspec != NULL);
	wimlib_assert(resource_is_compressed(rspec));
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

	/* Get the offsets of the first and last bytes of the read.  */
	const u64 first_offset = ranges[0].offset;
	const u64 last_offset = ranges[num_ranges - 1].offset + ranges[num_ranges - 1].size - 1;

	/* Get the file descriptor for the WIM.  */
	struct filedes * const in_fd = &rspec->wim->in_fd;

	/* Determine if we're reading a pipable resource from a pipe or not.  */
	const bool is_pipe_read = (rspec->is_pipable && !filedes_is_seekable(in_fd));

	/* Determine if the chunk table is in an alternate format.  */
	const bool alt_chunk_table = (rspec->flags & WIM_RESHDR_FLAG_SOLID)
					&& !is_pipe_read;

	/* Get the maximum size of uncompressed chunks in this resource, which
	 * we require be a power of 2.  */
	u64 cur_read_offset = rspec->offset_in_wim;
	int ctype = rspec->compression_type;
	u32 chunk_size = rspec->chunk_size;
	if (alt_chunk_table) {
		/* Alternate chunk table format.  Its header specifies the chunk
		 * size and compression format.  Note: it could be read here;
		 * however, the relevant data was already loaded into @rspec by
		 * read_wim_lookup_table().  */
		cur_read_offset += sizeof(struct alt_chunk_table_header_disk);
	}

	if (!is_power_of_2(chunk_size)) {
		ERROR("Invalid compressed resource: "
		      "expected power-of-2 chunk size (got %"PRIu32")",
		      chunk_size);
		ret = WIMLIB_ERR_INVALID_CHUNK_SIZE;
		errno = EINVAL;
		goto out_free_memory;
	}

	/* Get valid decompressor.  */
	if (ctype == rspec->wim->decompressor_ctype &&
	    chunk_size == rspec->wim->decompressor_max_block_size)
	{
		/* Cached decompressor.  */
		decompressor = rspec->wim->decompressor;
		rspec->wim->decompressor_ctype = WIMLIB_COMPRESSION_TYPE_NONE;
		rspec->wim->decompressor = NULL;
	} else {
		ret = wimlib_create_decompressor(ctype, chunk_size,
						 &decompressor);
		if (ret) {
			if (ret != WIMLIB_ERR_NOMEM)
				errno = EINVAL;
			goto out_free_memory;
		}
	}

	const u32 chunk_order = fls32(chunk_size);

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
	 * uncompressed size.  */
	const u64 chunk_entry_size = get_chunk_entry_size(rspec->uncompressed_size,
							  alt_chunk_table);

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

		ret = full_pread(in_fd, chunk_table_data, chunk_table_size_to_read,
				 file_offset_of_needed_chunk_entries);
		if (ret)
			goto read_error;

		/* Now fill in chunk_offsets from the entries we have read in
		 * chunk_tab_data.  We break aliasing rules here to avoid having
		 * to allocate yet another array.  */
		typedef le64 _may_alias_attribute aliased_le64_t;
		typedef le32 _may_alias_attribute aliased_le32_t;
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

	/* Allocate a temporary buffer for reading compressed chunks, each of
	 * which can be at most @chunk_size - 1 bytes.  This excludes compressed
	 * chunks that are a full @chunk_size bytes, which are actually stored
	 * uncompressed.  */
	if (chunk_size - 1 <= STACK_MAX) {
		cbuf = alloca(chunk_size - 1);
	} else {
		cbuf = MALLOC(chunk_size - 1);
		if (cbuf == NULL)
			goto oom;
		cbuf_malloced = true;
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
			u8 *read_buf;

			if (chunk_csize == chunk_usize)
				read_buf = ubuf;
			else
				read_buf = cbuf;

			ret = full_pread(in_fd,
					 read_buf,
					 chunk_csize,
					 cur_read_offset);
			if (ret)
				goto read_error;

			if (read_buf == cbuf) {
				DEBUG("Decompressing chunk %"PRIu64" "
				      "(csize=%"PRIu32" usize=%"PRIu32")",
				      i, chunk_csize, chunk_usize);
				ret = wimlib_decompress(cbuf,
							chunk_csize,
							ubuf,
							chunk_usize,
							decompressor);
				if (ret) {
					ERROR("Failed to decompress data!");
					ret = WIMLIB_ERR_DECOMPRESSION;
					errno = EINVAL;
					goto out_free_memory;
				}
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

				ret = (*cb)(&ubuf[start], size, cb_ctx);

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
	if (decompressor) {
		wimlib_free_decompressor(rspec->wim->decompressor);
		rspec->wim->decompressor = decompressor;
		rspec->wim->decompressor_ctype = ctype;
		rspec->wim->decompressor_max_block_size = chunk_size;
	}
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

static int
fill_zeroes(u64 size, consume_data_callback_t cb, void *cb_ctx)
{
	if (unlikely(size)) {
		u8 buf[min(size, BUFFER_SIZE)];

		memset(buf, 0, sizeof(buf));

		do {
			size_t len;
			int ret;

			len = min(size, BUFFER_SIZE);
			ret = cb(buf, len, cb_ctx);
			if (ret)
				return ret;
			size -= len;
		} while (size);
	}
	return 0;
}

/* Read raw data from a file descriptor at the specified offset, feeding the
 * data it in chunks into the specified callback function.  */
static int
read_raw_file_data(struct filedes *in_fd, u64 offset, u64 size,
		   consume_data_callback_t cb, void *cb_ctx)
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

/* A consume_data_callback_t implementation that simply concatenates all chunks
 * into a buffer.  */
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
 * file.
 *
 * @rspec
 *	Specification of the WIM resource to read from.
 * @offset
 *	Offset within the uncompressed resource at which to start reading.
 * @size
 *	Number of bytes to read.
 * @cb
 *	Callback function to feed the data being read.  Each call provides the
 *	next chunk of the requested data, uncompressed.  Each chunk will be of
 *	nonzero size and will not cross range boundaries, but otherwise will be
 *	of unspecified size.
 * @cb_ctx
 *	Parameter to pass to @cb_ctx.
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
			  u64 offset, u64 size,
			  consume_data_callback_t cb, void *cb_ctx)
{
	/* Sanity checks.  */
	wimlib_assert(offset + size >= offset);
	wimlib_assert(offset + size <= rspec->uncompressed_size);

	DEBUG("Reading %"PRIu64" @ %"PRIu64" from WIM resource  "
	      "%"PRIu64" => %"PRIu64" @ %"PRIu64,
	      size, offset, rspec->uncompressed_size,
	      rspec->size_in_wim, rspec->offset_in_wim);

	/* Trivial case.  */
	if (size == 0)
		return 0;

	if (resource_is_compressed(rspec)) {
		struct data_range range = {
			.offset = offset,
			.size = size,
		};
		return read_compressed_wim_resource(rspec, &range, 1,
						    cb, cb_ctx);
	} else {
		/* Reading uncompressed resource.  For completeness, handle the
		 * weird case where size_in_wim < uncompressed_size.  */

		u64 read_size;
		u64 zeroes_size;
		int ret;

		if (likely(offset + size <= rspec->size_in_wim) ||
		    rspec->is_pipable)
		{
			read_size = size;
			zeroes_size = 0;
		} else {
			if (offset >= rspec->size_in_wim) {
				read_size = 0;
				zeroes_size = size;
			} else {
				read_size = rspec->size_in_wim - offset;
				zeroes_size = offset + size - rspec->size_in_wim;
			}
		}

		ret = read_raw_file_data(&rspec->wim->in_fd,
					 rspec->offset_in_wim + offset,
					 read_size,
					 cb,
					 cb_ctx);
		if (ret)
			return ret;

		return fill_zeroes(zeroes_size, cb, cb_ctx);
	}
}

/* Read the specified range of uncompressed data from the specified stream,
 * which must be located into a WIM file, into the specified buffer.  */
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
					 &buf);
}

/* A consume_data_callback_t implementation that simply ignores the data
 * received.  */
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
	wimlib_assert(!(lte->flags & WIM_RESHDR_FLAG_SOLID));
	DEBUG("Skipping stream (size=%"PRIu64")", lte->size);
	return read_partial_wim_resource(lte->rspec,
					 0,
					 lte->rspec->uncompressed_size,
					 skip_chunk_cb,
					 NULL);
}

static int
read_wim_stream_prefix(const struct wim_lookup_table_entry *lte, u64 size,
		       consume_data_callback_t cb, void *cb_ctx)
{
	return read_partial_wim_resource(lte->rspec, lte->offset_in_res, size,
					 cb, cb_ctx);
}

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
			 consume_data_callback_t cb, void *cb_ctx)
{
	int ret;
	int raw_fd;
	struct filedes fd;

	wimlib_assert(size <= lte->size);

	DEBUG("Reading %"PRIu64" bytes from \"%"TS"\"", size, lte->file_on_disk);

	raw_fd = topen(lte->file_on_disk, O_BINARY | O_RDONLY);
	if (raw_fd < 0) {
		ERROR_WITH_ERRNO("Can't open \"%"TS"\"", lte->file_on_disk);
		return WIMLIB_ERR_OPEN;
	}
	filedes_init(&fd, raw_fd);
	ret = read_raw_file_data(&fd, 0, size, cb, cb_ctx);
	filedes_close(&fd);
	return ret;
}

#ifdef WITH_FUSE
static int
read_staging_file_prefix(const struct wim_lookup_table_entry *lte, u64 size,
			 consume_data_callback_t cb, void *cb_ctx)
{
	int raw_fd;
	struct filedes fd;
	int ret;

	wimlib_assert(size <= lte->size);

	DEBUG("Reading %"PRIu64" bytes from staging file \"%s\"",
	      size, lte->staging_file_name);

	raw_fd = openat(lte->staging_dir_fd, lte->staging_file_name,
			O_RDONLY | O_NOFOLLOW);
	if (raw_fd < 0) {
		ERROR_WITH_ERRNO("Can't open staging file \"%s\"",
				 lte->staging_file_name);
		return WIMLIB_ERR_OPEN;
	}
	filedes_init(&fd, raw_fd);
	ret = read_raw_file_data(&fd, 0, size, cb, cb_ctx);
	filedes_close(&fd);
	return ret;
}
#endif

/* This function handles the trivial case of reading stream data that is, in
 * fact, already located in an in-memory buffer.  */
static int
read_buffer_prefix(const struct wim_lookup_table_entry *lte,
		   u64 size, consume_data_callback_t cb, void *cb_ctx)
{
	wimlib_assert(size <= lte->size);
	return (*cb)(lte->attached_buffer, size, cb_ctx);
}

typedef int (*read_stream_prefix_handler_t)(const struct wim_lookup_table_entry *lte,
					    u64 size,
					    consume_data_callback_t cb,
					    void *cb_ctx);

/*
 * read_stream_prefix()-
 *
 * Reads the first @size bytes from a generic "stream", which may be located in
 * any one of several locations, such as in a WIM file (compressed or
 * uncompressed), in an external file, or directly in an in-memory buffer.
 *
 * This function feeds the data to a callback function @cb in chunks of
 * unspecified size.
 *
 * Returns 0 on success; nonzero on error.  A nonzero value will be returned if
 * the stream data cannot be successfully read (for a number of different
 * reasons, depending on the stream location), or if @cb returned nonzero in
 * which case that error code will be returned.
 */
static int
read_stream_prefix(const struct wim_lookup_table_entry *lte, u64 size,
		   consume_data_callback_t cb, void *cb_ctx)
{
	static const read_stream_prefix_handler_t handlers[] = {
		[RESOURCE_IN_WIM]             = read_wim_stream_prefix,
		[RESOURCE_IN_FILE_ON_DISK]    = read_file_on_disk_prefix,
		[RESOURCE_IN_ATTACHED_BUFFER] = read_buffer_prefix,
	#ifdef WITH_FUSE
		[RESOURCE_IN_STAGING_FILE]    = read_staging_file_prefix,
	#endif
	#ifdef WITH_NTFS_3G
		[RESOURCE_IN_NTFS_VOLUME]     = read_ntfs_file_prefix,
	#endif
	#ifdef __WIN32__
		[RESOURCE_IN_WINNT_FILE_ON_DISK] = read_winnt_file_prefix,
		[RESOURCE_WIN32_ENCRYPTED]    = read_win32_encrypted_file_prefix,
	#endif
	};
	wimlib_assert(lte->resource_location < ARRAY_LEN(handlers)
		      && handlers[lte->resource_location] != NULL);
	return handlers[lte->resource_location](lte, size, cb, cb_ctx);
}

/* Read the full uncompressed data of the specified stream into the specified
 * buffer, which must have space for at least lte->size bytes.  */
int
read_full_stream_into_buf(const struct wim_lookup_table_entry *lte, void *_buf)
{
	u8 *buf = _buf;
	return read_stream_prefix(lte, lte->size, bufferer_cb, &buf);
}

/* Retrieve the full uncompressed data of the specified stream.  A buffer large
 * enough hold the data is allocated and returned in @buf_ret.  */
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

/* Retrieve the full uncompressed data of the specified WIM resource.  A buffer
 * large enough hold the data is allocated and returned in @buf_ret.  */
static int
wim_resource_spec_to_data(struct wim_resource_spec *rspec, void **buf_ret)
{
	int ret;
	struct wim_lookup_table_entry *lte;

	lte = new_lookup_table_entry();
	if (lte == NULL)
		return WIMLIB_ERR_NOMEM;

	lte_bind_wim_resource_spec(lte, rspec);
	lte->flags = rspec->flags;
	lte->size = rspec->uncompressed_size;
	lte->offset_in_res = 0;

	ret = read_full_stream_into_alloc_buf(lte, buf_ret);

	lte_unbind_wim_resource_spec(lte);
	free_lookup_table_entry(lte);
	return ret;
}

/* Retrieve the full uncompressed data of a WIM resource specified as a raw
 * `wim_reshdr' and the corresponding WIM file.  A large enough hold the data is
 * allocated and returned in @buf_ret.  */
int
wim_reshdr_to_data(const struct wim_reshdr *reshdr, WIMStruct *wim, void **buf_ret)
{
	DEBUG("offset_in_wim=%"PRIu64", size_in_wim=%"PRIu64", "
	      "uncompressed_size=%"PRIu64,
	      reshdr->offset_in_wim, reshdr->size_in_wim,
	      reshdr->uncompressed_size);

	struct wim_resource_spec rspec;
	wim_res_hdr_to_spec(reshdr, wim, &rspec);
	return wim_resource_spec_to_data(&rspec, buf_ret);
}

int
wim_reshdr_to_hash(const struct wim_reshdr *reshdr, WIMStruct *wim,
		   u8 hash[SHA1_HASH_SIZE])
{
	struct wim_resource_spec rspec;
	int ret;
	struct wim_lookup_table_entry *lte;

	wim_res_hdr_to_spec(reshdr, wim, &rspec);

	lte = new_lookup_table_entry();
	if (lte == NULL)
		return WIMLIB_ERR_NOMEM;

	lte_bind_wim_resource_spec(lte, &rspec);
	lte->flags = rspec.flags;
	lte->size = rspec.uncompressed_size;
	lte->offset_in_res = 0;
	lte->unhashed = 1;

	ret = sha1_stream(lte);

	lte_unbind_wim_resource_spec(lte);
	copy_hash(hash, lte->hash);
	free_lookup_table_entry(lte);
	return ret;
}

struct streamifier_context {
	struct read_stream_list_callbacks cbs;
	struct wim_lookup_table_entry *cur_stream;
	struct wim_lookup_table_entry *next_stream;
	u64 cur_stream_offset;
	struct wim_lookup_table_entry *final_stream;
	size_t list_head_offset;
};

static struct wim_lookup_table_entry *
next_stream(struct wim_lookup_table_entry *lte, size_t list_head_offset)
{
	struct list_head *cur;

	cur = (struct list_head*)((u8*)lte + list_head_offset);

	return (struct wim_lookup_table_entry*)((u8*)cur->next - list_head_offset);
}

/* A consume_data_callback_t implementation that translates raw resource data
 * into streams, calling the begin_stream, consume_chunk, and end_stream
 * callback functions as appropriate.  */
static int
streamifier_cb(const void *chunk, size_t size, void *_ctx)
{
	struct streamifier_context *ctx = _ctx;
	int ret;

	DEBUG("%zu bytes passed to streamifier", size);

	wimlib_assert(ctx->cur_stream != NULL);
	wimlib_assert(size <= ctx->cur_stream->size - ctx->cur_stream_offset);

	if (ctx->cur_stream_offset == 0) {

		/* Starting a new stream.  */
		DEBUG("Begin new stream (size=%"PRIu64").",
		      ctx->cur_stream->size);

		ret = (*ctx->cbs.begin_stream)(ctx->cur_stream,
					       ctx->cbs.begin_stream_ctx);
		if (ret)
			return ret;
	}

	/* Consume the chunk.  */
	ret = (*ctx->cbs.consume_chunk)(chunk, size,
					ctx->cbs.consume_chunk_ctx);
	ctx->cur_stream_offset += size;
	if (ret)
		return ret;

	if (ctx->cur_stream_offset == ctx->cur_stream->size) {
		/* Finished reading all the data for a stream.  */

		ctx->cur_stream_offset = 0;

		DEBUG("End stream (size=%"PRIu64").", ctx->cur_stream->size);
		ret = (*ctx->cbs.end_stream)(ctx->cur_stream, 0,
					     ctx->cbs.end_stream_ctx);
		if (ret)
			return ret;

		/* Advance to next stream.  */
		ctx->cur_stream = ctx->next_stream;
		if (ctx->cur_stream != NULL) {
			if (ctx->cur_stream != ctx->final_stream)
				ctx->next_stream = next_stream(ctx->cur_stream,
							       ctx->list_head_offset);
			else
				ctx->next_stream = NULL;
		}
	}
	return 0;
}

struct hasher_context {
	SHA_CTX sha_ctx;
	int flags;
	struct read_stream_list_callbacks cbs;
};

/* Callback for starting to read a stream while calculating its SHA1 message
 * digest.  */
static int
hasher_begin_stream(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct hasher_context *ctx = _ctx;

	sha1_init(&ctx->sha_ctx);

	if (ctx->cbs.begin_stream == NULL)
		return 0;
	else
		return (*ctx->cbs.begin_stream)(lte, ctx->cbs.begin_stream_ctx);
}

/* A consume_data_callback_t implementation that continues calculating the SHA1
 * message digest of the stream being read, then optionally passes the data on
 * to another consume_data_callback_t implementation.  This allows checking the
 * SHA1 message digest of a stream being extracted, for example.  */
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
		/* Error occurred; the full stream may not have been read.  */
		ret = status;
		goto out_next_cb;
	}

	/* Retrieve the final SHA1 message digest.  */
	sha1_final(hash, &ctx->sha_ctx);

	if (lte->unhashed) {
		if (ctx->flags & COMPUTE_MISSING_STREAM_HASHES) {
			/* No SHA1 message digest was previously present for the
			 * stream.  Set it to the one just calculated.  */
			DEBUG("Set SHA1 message digest for stream "
			      "(size=%"PRIu64").", lte->size);
			copy_hash(lte->hash, hash);
		}
	} else {
		if (ctx->flags & VERIFY_STREAM_HASHES) {
			/* The stream already had a SHA1 message digest present.  Verify
			 * that it is the same as the calculated value.  */
			if (!hashes_equal(hash, lte->hash)) {
				if (wimlib_print_errors) {
					tchar expected_hashstr[SHA1_HASH_SIZE * 2 + 1];
					tchar actual_hashstr[SHA1_HASH_SIZE * 2 + 1];
					sprint_hash(lte->hash, expected_hashstr);
					sprint_hash(hash, actual_hashstr);
					ERROR("The stream is corrupted!\n"
					      "        (Expected SHA1=%"TS",\n"
					      "              got SHA1=%"TS")",
					      expected_hashstr, actual_hashstr);
				}
				ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
				errno = EINVAL;
				goto out_next_cb;
			}
			DEBUG("SHA1 message digest okay for "
			      "stream (size=%"PRIu64").", lte->size);
		}
	}
	ret = 0;
out_next_cb:
	if (ctx->cbs.end_stream == NULL)
		return ret;
	else
		return (*ctx->cbs.end_stream)(lte, ret, ctx->cbs.end_stream_ctx);
}

static int
read_full_stream_with_cbs(struct wim_lookup_table_entry *lte,
			  const struct read_stream_list_callbacks *cbs)
{
	int ret;

	ret = (*cbs->begin_stream)(lte, cbs->begin_stream_ctx);
	if (ret)
		return ret;

	ret = read_stream_prefix(lte, lte->size, cbs->consume_chunk,
				 cbs->consume_chunk_ctx);

	return (*cbs->end_stream)(lte, ret, cbs->end_stream_ctx);
}

/* Read the full data of the specified stream, passing the data into the
 * specified callbacks (all of which are optional) and either checking or
 * computing the SHA1 message digest of the stream.  */
static int
read_full_stream_with_sha1(struct wim_lookup_table_entry *lte,
			   const struct read_stream_list_callbacks *cbs)
{
	struct hasher_context hasher_ctx = {
		.flags = VERIFY_STREAM_HASHES | COMPUTE_MISSING_STREAM_HASHES,
		.cbs = *cbs,
	};
	struct read_stream_list_callbacks hasher_cbs = {
		.begin_stream		= hasher_begin_stream,
		.begin_stream_ctx	= &hasher_ctx,
		.consume_chunk		= hasher_consume_chunk,
		.consume_chunk_ctx	= &hasher_ctx,
		.end_stream		= hasher_end_stream,
		.end_stream_ctx		= &hasher_ctx,
	};
	return read_full_stream_with_cbs(lte, &hasher_cbs);
}

static int
read_streams_in_solid_resource(struct wim_lookup_table_entry *first_stream,
			       struct wim_lookup_table_entry *last_stream,
			       u64 stream_count,
			       size_t list_head_offset,
			       const struct read_stream_list_callbacks *sink_cbs)
{
	struct data_range *ranges;
	bool ranges_malloced;
	struct wim_lookup_table_entry *cur_stream;
	size_t i;
	int ret;
	u64 ranges_alloc_size;

	DEBUG("Reading %"PRIu64" streams combined in same WIM resource",
	      stream_count);

	/* Setup data ranges array (one range per stream to read); this way
	 * read_compressed_wim_resource() does not need to be aware of streams.
	 */

	ranges_alloc_size = stream_count * sizeof(ranges[0]);

	if (unlikely((size_t)ranges_alloc_size != ranges_alloc_size)) {
		ERROR("Too many streams in one resource!");
		return WIMLIB_ERR_NOMEM;
	}
	if (likely(ranges_alloc_size <= STACK_MAX)) {
		ranges = alloca(ranges_alloc_size);
		ranges_malloced = false;
	} else {
		ranges = MALLOC(ranges_alloc_size);
		if (ranges == NULL) {
			ERROR("Too many streams in one resource!");
			return WIMLIB_ERR_NOMEM;
		}
		ranges_malloced = true;
	}

	for (i = 0, cur_stream = first_stream;
	     i < stream_count;
	     i++, cur_stream = next_stream(cur_stream, list_head_offset))
	{
		ranges[i].offset = cur_stream->offset_in_res;
		ranges[i].size = cur_stream->size;
	}

	struct streamifier_context streamifier_ctx = {
		.cbs			= *sink_cbs,
		.cur_stream		= first_stream,
		.next_stream            = next_stream(first_stream, list_head_offset),
		.cur_stream_offset	= 0,
		.final_stream		= last_stream,
		.list_head_offset	= list_head_offset,
	};

	ret = read_compressed_wim_resource(first_stream->rspec,
					   ranges,
					   stream_count,
					   streamifier_cb,
					   &streamifier_ctx);

	if (ranges_malloced)
		FREE(ranges);

	if (ret) {
		if (streamifier_ctx.cur_stream_offset != 0) {
			ret = (*streamifier_ctx.cbs.end_stream)
				(streamifier_ctx.cur_stream,
				 ret,
				 streamifier_ctx.cbs.end_stream_ctx);
		}
	}
	return ret;
}

/*
 * Read a list of streams, each of which may be in any supported location (e.g.
 * in a WIM or in an external file).  Unlike read_stream_prefix() or the
 * functions which call it, this function optimizes the case where multiple
 * streams are combined into a single solid compressed WIM resource and reads
 * them all consecutively, only decompressing the data one time.
 *
 * @stream_list
 *	List of streams (represented as `struct wim_lookup_table_entry's) to
 *	read.
 * @list_head_offset
 *	Offset of the `struct list_head' within each `struct
 *	wim_lookup_table_entry' that makes up the @stream_list.
 * @cbs
 *	Callback functions to accept the stream data.
 * @flags
 *	Bitwise OR of zero or more of the following flags:
 *
 *	VERIFY_STREAM_HASHES:
 *		For all streams being read that have already had SHA1 message
 *		digests computed, calculate the SHA1 message digest of the read
 *		data and compare it with the previously computed value.  If they
 *		do not match, return WIMLIB_ERR_INVALID_RESOURCE_HASH.
 *
 *	COMPUTE_MISSING_STREAM_HASHES
 *		For all streams being read that have not yet had their SHA1
 *		message digests computed, calculate and save their SHA1 message
 *		digests.
 *
 *	STREAM_LIST_ALREADY_SORTED
 *		@stream_list is already sorted in sequential order for reading.
 *
 * The callback functions are allowed to delete the current stream from the list
 * if necessary.
 *
 * Returns 0 on success; a nonzero error code on failure.  Failure can occur due
 * to an error reading the data or due to an error status being returned by any
 * of the callback functions.
 */
int
read_stream_list(struct list_head *stream_list,
		 size_t list_head_offset,
		 const struct read_stream_list_callbacks *cbs,
		 int flags)
{
	int ret;
	struct list_head *cur, *next;
	struct wim_lookup_table_entry *lte;
	struct hasher_context *hasher_ctx;
	struct read_stream_list_callbacks *sink_cbs;

	if (!(flags & STREAM_LIST_ALREADY_SORTED)) {
		ret = sort_stream_list_by_sequential_order(stream_list, list_head_offset);
		if (ret)
			return ret;
	}

	if (flags & (VERIFY_STREAM_HASHES | COMPUTE_MISSING_STREAM_HASHES)) {
		hasher_ctx = alloca(sizeof(*hasher_ctx));
		*hasher_ctx = (struct hasher_context) {
			.flags	= flags,
			.cbs	= *cbs,
		};
		sink_cbs = alloca(sizeof(*sink_cbs));
		*sink_cbs = (struct read_stream_list_callbacks) {
			.begin_stream		= hasher_begin_stream,
			.begin_stream_ctx	= hasher_ctx,
			.consume_chunk		= hasher_consume_chunk,
			.consume_chunk_ctx	= hasher_ctx,
			.end_stream		= hasher_end_stream,
			.end_stream_ctx		= hasher_ctx,
		};
	} else {
		sink_cbs = (struct read_stream_list_callbacks*)cbs;
	}

	for (cur = stream_list->next, next = cur->next;
	     cur != stream_list;
	     cur = next, next = cur->next)
	{
		lte = (struct wim_lookup_table_entry*)((u8*)cur - list_head_offset);

		if (lte->flags & WIM_RESHDR_FLAG_SOLID &&
		    lte->size != lte->rspec->uncompressed_size)
		{

			struct wim_lookup_table_entry *lte_next, *lte_last;
			struct list_head *next2;
			u64 stream_count;

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
				next = next2;
				ret = read_streams_in_solid_resource(lte, lte_last,
								     stream_count,
								     list_head_offset,
								     sink_cbs);
				if (ret)
					return ret;
				continue;
			}
		}

		ret = read_full_stream_with_cbs(lte, sink_cbs);
		if (ret && ret != BEGIN_STREAM_STATUS_SKIP_STREAM)
			return ret;
	}
	return 0;
}

/* Extract the first @size bytes of the specified stream.
 *
 * If @size specifies the full uncompressed size of the stream, then the SHA1
 * message digest of the uncompressed stream is checked while being extracted.
 *
 * The uncompressed data of the resource is passed in chunks of unspecified size
 * to the @extract_chunk function, passing it @extract_chunk_arg.  */
int
extract_stream(struct wim_lookup_table_entry *lte, u64 size,
	       consume_data_callback_t extract_chunk, void *extract_chunk_arg)
{
	wimlib_assert(size <= lte->size);
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
					  extract_chunk_arg);
	}
}

/* A consume_data_callback_t implementation that writes the chunk of data to a
 * file descriptor.  */
static int
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
 * descriptor.  */
int
extract_stream_to_fd(struct wim_lookup_table_entry *lte,
		     struct filedes *fd, u64 size)
{
	return extract_stream(lte, size, extract_chunk_to_fd, fd);
}

/* Extract the full uncompressed contents of the specified stream to the
 * specified file descriptor.  */
int
extract_full_stream_to_fd(struct wim_lookup_table_entry *lte,
			  struct filedes *fd)
{
	return extract_stream_to_fd(lte, fd, lte->size);
}

/* Calculate the SHA1 message digest of a stream and store it in @lte->hash.  */
int
sha1_stream(struct wim_lookup_table_entry *lte)
{
	wimlib_assert(lte->unhashed);
	struct read_stream_list_callbacks cbs = {
	};
	return read_full_stream_with_sha1(lte, &cbs);
}

/* Convert a short WIM resource header to a stand-alone WIM resource
 * specification.
 *
 * Note: for solid resources some fields still need to be overridden.
 */
void
wim_res_hdr_to_spec(const struct wim_reshdr *reshdr, WIMStruct *wim,
		    struct wim_resource_spec *rspec)
{
	rspec->wim = wim;
	rspec->offset_in_wim = reshdr->offset_in_wim;
	rspec->size_in_wim = reshdr->size_in_wim;
	rspec->uncompressed_size = reshdr->uncompressed_size;
	INIT_LIST_HEAD(&rspec->stream_list);
	rspec->flags = reshdr->flags;
	rspec->is_pipable = wim_is_pipable(wim);
	if (rspec->flags & WIM_RESHDR_FLAG_COMPRESSED) {
		rspec->compression_type = wim->compression_type;
		rspec->chunk_size = wim->chunk_size;
	} else {
		rspec->compression_type = WIMLIB_COMPRESSION_TYPE_NONE;
		rspec->chunk_size = 0;
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
void
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
