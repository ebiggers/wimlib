/*
 * write.c
 *
 * Support for writing WIM files; write a WIM file, overwrite a WIM file, write
 * compressed file resources, etc.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
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

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
/* On BSD, this should be included before "wimlib/list.h" so that "wimlib/list.h" can
 * overwrite the LIST_HEAD macro. */
#  include <sys/file.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "wimlib/alloca.h"
#include "wimlib/assert.h"
#include "wimlib/chunk_compressor.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/header.h"
#include "wimlib/inode.h"
#include "wimlib/integrity.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/progress.h"
#include "wimlib/resource.h"
#ifdef __WIN32__
#  include "wimlib/win32.h" /* win32_rename_replacement() */
#endif
#include "wimlib/write.h"
#include "wimlib/xml.h"


/* wimlib internal flags used when writing resources.  */
#define WRITE_RESOURCE_FLAG_RECOMPRESS		0x00000001
#define WRITE_RESOURCE_FLAG_PIPABLE		0x00000002
#define WRITE_RESOURCE_FLAG_SOLID		0x00000004
#define WRITE_RESOURCE_FLAG_SEND_DONE_WITH_FILE	0x00000008

static inline int
write_flags_to_resource_flags(int write_flags)
{
	int write_resource_flags = 0;

	if (write_flags & WIMLIB_WRITE_FLAG_RECOMPRESS)
		write_resource_flags |= WRITE_RESOURCE_FLAG_RECOMPRESS;
	if (write_flags & WIMLIB_WRITE_FLAG_PIPABLE)
		write_resource_flags |= WRITE_RESOURCE_FLAG_PIPABLE;
	if (write_flags & WIMLIB_WRITE_FLAG_SOLID)
		write_resource_flags |= WRITE_RESOURCE_FLAG_SOLID;
	if (write_flags & WIMLIB_WRITE_FLAG_SEND_DONE_WITH_FILE_MESSAGES)
		write_resource_flags |= WRITE_RESOURCE_FLAG_SEND_DONE_WITH_FILE;
	return write_resource_flags;
}

struct filter_context {
	int write_flags;
	WIMStruct *wim;
};

/* Determine specified stream should be filtered out from the write.
 *
 * Return values:
 *
 *  < 0 : The stream should be hard-filtered; that is, not included in the
 *        output WIM at all.
 *    0 : The stream should not be filtered out.
 *  > 0 : The stream should be soft-filtered; that is, it already exists in the
 *	  WIM file and may not need to be written again.
 */
static int
stream_filtered(const struct wim_lookup_table_entry *lte,
		const struct filter_context *ctx)
{
	int write_flags;
	WIMStruct *wim;

	if (ctx == NULL)
		return 0;

	write_flags = ctx->write_flags;
	wim = ctx->wim;

	if (write_flags & WIMLIB_WRITE_FLAG_OVERWRITE &&
	    lte->resource_location == RESOURCE_IN_WIM &&
	    lte->rspec->wim == wim)
		return 1;

	if (write_flags & WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS &&
	    lte->resource_location == RESOURCE_IN_WIM &&
	    lte->rspec->wim != wim)
		return -1;

	return 0;
}

static bool
stream_hard_filtered(const struct wim_lookup_table_entry *lte,
		     struct filter_context *ctx)
{
	return stream_filtered(lte, ctx) < 0;
}

static inline int
may_soft_filter_streams(const struct filter_context *ctx)
{
	if (ctx == NULL)
		return 0;
	return ctx->write_flags & WIMLIB_WRITE_FLAG_OVERWRITE;
}

static inline int
may_hard_filter_streams(const struct filter_context *ctx)
{
	if (ctx == NULL)
		return 0;
	return ctx->write_flags & WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS;
}

static inline int
may_filter_streams(const struct filter_context *ctx)
{
	return (may_soft_filter_streams(ctx) ||
		may_hard_filter_streams(ctx));
}


/* Return true if the specified resource is compressed and the compressed data
 * can be reused with the specified output parameters.  */
static bool
can_raw_copy(const struct wim_lookup_table_entry *lte,
	     int write_resource_flags, int out_ctype, u32 out_chunk_size)
{
	const struct wim_resource_spec *rspec;

	if (write_resource_flags & WRITE_RESOURCE_FLAG_RECOMPRESS)
		return false;

	if (out_ctype == WIMLIB_COMPRESSION_TYPE_NONE)
		return false;

	if (lte->resource_location != RESOURCE_IN_WIM)
		return false;

	rspec = lte->rspec;

	if (rspec->is_pipable != !!(write_resource_flags & WRITE_RESOURCE_FLAG_PIPABLE))
		return false;

	if (rspec->flags & WIM_RESHDR_FLAG_COMPRESSED) {
		/* Normal compressed resource: Must use same compression type
		 * and chunk size.  */
		return (rspec->compression_type == out_ctype &&
			rspec->chunk_size == out_chunk_size);
	}

	if ((rspec->flags & WIM_RESHDR_FLAG_SOLID) &&
	    (write_resource_flags & WRITE_RESOURCE_FLAG_SOLID))
	{
		/* Solid resource: Such resources may contain multiple streams,
		 * and in general only a subset of them need to be written.  As
		 * a heuristic, re-use the raw data if more than two-thirds the
		 * uncompressed size is being written.  */

		/* Note: solid resources contain a header that specifies the
		 * compression type and chunk size; therefore we don't need to
		 * check if they are compatible with @out_ctype and
		 * @out_chunk_size.  */

		struct wim_lookup_table_entry *res_stream;
		u64 write_size = 0;

		list_for_each_entry(res_stream, &rspec->stream_list, rspec_node)
			if (res_stream->will_be_in_output_wim)
				write_size += res_stream->size;

		return (write_size > rspec->uncompressed_size * 2 / 3);
	}

	return false;
}

static u8
filter_resource_flags(u8 flags)
{
	return (flags & ~(WIM_RESHDR_FLAG_SOLID |
			  WIM_RESHDR_FLAG_COMPRESSED |
			  WIM_RESHDR_FLAG_SPANNED |
			  WIM_RESHDR_FLAG_FREE));
}

static void
stream_set_out_reshdr_for_reuse(struct wim_lookup_table_entry *lte)
{
	const struct wim_resource_spec *rspec;

	wimlib_assert(lte->resource_location == RESOURCE_IN_WIM);
	rspec = lte->rspec;

	if (rspec->flags & WIM_RESHDR_FLAG_SOLID) {

		wimlib_assert(lte->flags & WIM_RESHDR_FLAG_SOLID);

		lte->out_reshdr.offset_in_wim = lte->offset_in_res;
		lte->out_reshdr.uncompressed_size = 0;
		lte->out_reshdr.size_in_wim = lte->size;

		lte->out_res_offset_in_wim = rspec->offset_in_wim;
		lte->out_res_size_in_wim = rspec->size_in_wim;
		lte->out_res_uncompressed_size = rspec->uncompressed_size;
	} else {
		wimlib_assert(!(lte->flags & WIM_RESHDR_FLAG_SOLID));

		lte->out_reshdr.offset_in_wim = rspec->offset_in_wim;
		lte->out_reshdr.uncompressed_size = rspec->uncompressed_size;
		lte->out_reshdr.size_in_wim = rspec->size_in_wim;
	}
	lte->out_reshdr.flags = lte->flags;
}


/* Write the header for a stream in a pipable WIM.  */
static int
write_pwm_stream_header(const struct wim_lookup_table_entry *lte,
			struct filedes *out_fd,
			int additional_reshdr_flags)
{
	struct pwm_stream_hdr stream_hdr;
	u32 reshdr_flags;
	int ret;

	stream_hdr.magic = cpu_to_le64(PWM_STREAM_MAGIC);
	stream_hdr.uncompressed_size = cpu_to_le64(lte->size);
	if (additional_reshdr_flags & PWM_RESHDR_FLAG_UNHASHED) {
		zero_out_hash(stream_hdr.hash);
	} else {
		wimlib_assert(!lte->unhashed);
		copy_hash(stream_hdr.hash, lte->hash);
	}

	reshdr_flags = filter_resource_flags(lte->flags);
	reshdr_flags |= additional_reshdr_flags;
	stream_hdr.flags = cpu_to_le32(reshdr_flags);
	ret = full_write(out_fd, &stream_hdr, sizeof(stream_hdr));
	if (ret)
		ERROR_WITH_ERRNO("Write error");
	return ret;
}

struct write_streams_progress_data {
	wimlib_progress_func_t progfunc;
	void *progctx;
	union wimlib_progress_info progress;
	uint64_t next_progress;
};

static int
do_write_streams_progress(struct write_streams_progress_data *progress_data,
			  u64 complete_size,
			  u32 complete_count,
			  bool discarded)
{
	union wimlib_progress_info *progress = &progress_data->progress;
	int ret;

	if (discarded) {
		progress->write_streams.total_bytes -= complete_size;
		progress->write_streams.total_streams -= complete_count;
		if (progress_data->next_progress != ~(uint64_t)0 &&
		    progress_data->next_progress > progress->write_streams.total_bytes)
		{
			progress_data->next_progress = progress->write_streams.total_bytes;
		}
	} else {
		progress->write_streams.completed_bytes += complete_size;
		progress->write_streams.completed_streams += complete_count;
	}

	if (progress->write_streams.completed_bytes >= progress_data->next_progress)
	{
		ret = call_progress(progress_data->progfunc,
				    WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
				    progress,
				    progress_data->progctx);
		if (ret)
			return ret;

		if (progress_data->next_progress == progress->write_streams.total_bytes) {
			progress_data->next_progress = ~(uint64_t)0;
		} else {
			/* Handle rate-limiting of messages  */

			/* Send new message as soon as another 1/128 of the
			 * total has been written.  (Arbitrary number.)  */
			progress_data->next_progress =
				progress->write_streams.completed_bytes +
					progress->write_streams.total_bytes / 128;

			/* ... Unless that would be more than 5000000 bytes, in
			 * which case send the next after the next 5000000
			 * bytes.  (Another arbitrary number.)  */
			if (progress->write_streams.completed_bytes + 5000000 <
			    progress_data->next_progress)
				progress_data->next_progress =
					progress->write_streams.completed_bytes + 5000000;

			/* ... But always send a message as soon as we're
			 * completely done.  */
			if (progress->write_streams.total_bytes <
			    progress_data->next_progress)
				progress_data->next_progress =
					progress->write_streams.total_bytes;
		}
	}
	return 0;
}

struct write_streams_ctx {
	/* File descriptor the streams are being written to.  */
	struct filedes *out_fd;

	/* Lookup table for the WIMStruct on whose behalf the streams are being
	 * written.  */
	struct wim_lookup_table *lookup_table;

	/* Compression format to use.  */
	int out_ctype;

	/* Maximum uncompressed chunk size in compressed resources to use.  */
	u32 out_chunk_size;

	/* Flags that affect how the streams will be written.  */
	int write_resource_flags;

	/* Data used for issuing WRITE_STREAMS progress.  */
	struct write_streams_progress_data progress_data;

	struct filter_context *filter_ctx;

	/* Upper bound on the total number of bytes that need to be compressed.
	 * */
	u64 num_bytes_to_compress;

	/* Pointer to the chunk_compressor implementation being used for
	 * compressing chunks of data, or NULL if chunks are being written
	 * uncompressed.  */
	struct chunk_compressor *compressor;

	/* Buffer for dividing the read data into chunks of size
	 * @out_chunk_size.  */
	u8 *chunk_buf;

	/* Number of bytes in @chunk_buf that are currently filled.  */
	size_t chunk_buf_filled;

	/* List of streams that currently have chunks being compressed.  */
	struct list_head pending_streams;

	/* List of streams in the solid resource.  Streams are moved here after
	 * @pending_streams only when writing a solid resource.  */
	struct list_head solid_streams;

	/* Current uncompressed offset in the stream being read.  */
	u64 cur_read_stream_offset;

	/* Uncompressed size of the stream currently being read.  */
	u64 cur_read_stream_size;

	/* Current uncompressed offset in the stream being written.  */
	u64 cur_write_stream_offset;

	/* Uncompressed size of resource currently being written.  */
	u64 cur_write_res_size;

	/* Array that is filled in with compressed chunk sizes as a resource is
	 * being written.  */
	u64 *chunk_csizes;

	/* Index of next entry in @chunk_csizes to fill in.  */
	size_t chunk_index;

	/* Number of entries in @chunk_csizes currently allocated.  */
	size_t num_alloc_chunks;

	/* Offset in the output file of the start of the chunks of the resource
	 * currently being written.  */
	u64 chunks_start_offset;
};

/* Reserve space for the chunk table and prepare to accumulate the chunk table
 * in memory.  */
static int
begin_chunk_table(struct write_streams_ctx *ctx, u64 res_expected_size)
{
	u64 expected_num_chunks;
	u64 expected_num_chunk_entries;
	size_t reserve_size;
	int ret;

	/* Calculate the number of chunks and chunk entries that should be
	 * needed for the resource.  These normally will be the final values,
	 * but in SOLID mode some of the streams we're planning to write into
	 * the resource may be duplicates, and therefore discarded, potentially
	 * decreasing the number of chunk entries needed.  */
	expected_num_chunks = DIV_ROUND_UP(res_expected_size, ctx->out_chunk_size);
	expected_num_chunk_entries = expected_num_chunks;
	if (!(ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID))
		expected_num_chunk_entries--;

	/* Make sure the chunk_csizes array is long enough to store the
	 * compressed size of each chunk.  */
	if (expected_num_chunks > ctx->num_alloc_chunks) {
		u64 new_length = expected_num_chunks + 50;

		if ((size_t)new_length != new_length) {
			ERROR("Resource size too large (%"PRIu64" bytes!",
			      res_expected_size);
			return WIMLIB_ERR_NOMEM;
		}

		FREE(ctx->chunk_csizes);
		ctx->chunk_csizes = MALLOC(new_length * sizeof(ctx->chunk_csizes[0]));
		if (ctx->chunk_csizes == NULL) {
			ctx->num_alloc_chunks = 0;
			return WIMLIB_ERR_NOMEM;
		}
		ctx->num_alloc_chunks = new_length;
	}

	ctx->chunk_index = 0;

	if (!(ctx->write_resource_flags & WRITE_RESOURCE_FLAG_PIPABLE)) {
		/* Reserve space for the chunk table in the output file.  In the
		 * case of solid resources this reserves the upper bound for the
		 * needed space, not necessarily the exact space which will
		 * prove to be needed.  At this point, we just use @chunk_csizes
		 * for a buffer of 0's because the actual compressed chunk sizes
		 * are unknown.  */
		reserve_size = expected_num_chunk_entries *
			       get_chunk_entry_size(res_expected_size,
						    0 != (ctx->write_resource_flags &
							  WRITE_RESOURCE_FLAG_SOLID));
		if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID)
			reserve_size += sizeof(struct alt_chunk_table_header_disk);
		memset(ctx->chunk_csizes, 0, reserve_size);
		ret = full_write(ctx->out_fd, ctx->chunk_csizes, reserve_size);
		if (ret)
			return ret;
	}
	return 0;
}

static int
begin_write_resource(struct write_streams_ctx *ctx, u64 res_expected_size)
{
	int ret;

	wimlib_assert(res_expected_size != 0);

	if (ctx->compressor != NULL) {
		ret = begin_chunk_table(ctx, res_expected_size);
		if (ret)
			return ret;
	}

	/* Output file descriptor is now positioned at the offset at which to
	 * write the first chunk of the resource.  */
	ctx->chunks_start_offset = ctx->out_fd->offset;
	ctx->cur_write_stream_offset = 0;
	ctx->cur_write_res_size = res_expected_size;
	return 0;
}

static int
end_chunk_table(struct write_streams_ctx *ctx, u64 res_actual_size,
		u64 *res_start_offset_ret, u64 *res_store_size_ret)
{
	size_t actual_num_chunks;
	size_t actual_num_chunk_entries;
	size_t chunk_entry_size;
	int ret;

	actual_num_chunks = ctx->chunk_index;
	actual_num_chunk_entries = actual_num_chunks;
	if (!(ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID))
		actual_num_chunk_entries--;

	chunk_entry_size = get_chunk_entry_size(res_actual_size,
						0 != (ctx->write_resource_flags &
						      WRITE_RESOURCE_FLAG_SOLID));

	typedef le64 _may_alias_attribute aliased_le64_t;
	typedef le32 _may_alias_attribute aliased_le32_t;

	if (chunk_entry_size == 4) {
		aliased_le32_t *entries = (aliased_le32_t*)ctx->chunk_csizes;

		if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID) {
			for (size_t i = 0; i < actual_num_chunk_entries; i++)
				entries[i] = cpu_to_le32(ctx->chunk_csizes[i]);
		} else {
			u32 offset = ctx->chunk_csizes[0];
			for (size_t i = 0; i < actual_num_chunk_entries; i++) {
				u32 next_size = ctx->chunk_csizes[i + 1];
				entries[i] = cpu_to_le32(offset);
				offset += next_size;
			}
		}
	} else {
		aliased_le64_t *entries = (aliased_le64_t*)ctx->chunk_csizes;

		if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID) {
			for (size_t i = 0; i < actual_num_chunk_entries; i++)
				entries[i] = cpu_to_le64(ctx->chunk_csizes[i]);
		} else {
			u64 offset = ctx->chunk_csizes[0];
			for (size_t i = 0; i < actual_num_chunk_entries; i++) {
				u64 next_size = ctx->chunk_csizes[i + 1];
				entries[i] = cpu_to_le64(offset);
				offset += next_size;
			}
		}
	}

	size_t chunk_table_size = actual_num_chunk_entries * chunk_entry_size;
	u64 res_start_offset;
	u64 res_end_offset;

	if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_PIPABLE) {
		ret = full_write(ctx->out_fd, ctx->chunk_csizes, chunk_table_size);
		if (ret)
			goto write_error;
		res_end_offset = ctx->out_fd->offset;
		res_start_offset = ctx->chunks_start_offset;
	} else {
		res_end_offset = ctx->out_fd->offset;

		u64 chunk_table_offset;

		chunk_table_offset = ctx->chunks_start_offset - chunk_table_size;

		if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID) {
			struct alt_chunk_table_header_disk hdr;

			hdr.res_usize = cpu_to_le64(res_actual_size);
			hdr.chunk_size = cpu_to_le32(ctx->out_chunk_size);
			hdr.compression_format = cpu_to_le32(ctx->out_ctype);

			BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_XPRESS != 1);
			BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_LZX != 2);
			BUILD_BUG_ON(WIMLIB_COMPRESSION_TYPE_LZMS != 3);

			ret = full_pwrite(ctx->out_fd, &hdr, sizeof(hdr),
					  chunk_table_offset - sizeof(hdr));
			if (ret)
				goto write_error;
			res_start_offset = chunk_table_offset - sizeof(hdr);
		} else {
			res_start_offset = chunk_table_offset;
		}

		ret = full_pwrite(ctx->out_fd, ctx->chunk_csizes,
				  chunk_table_size, chunk_table_offset);
		if (ret)
			goto write_error;
	}

	*res_start_offset_ret = res_start_offset;
	*res_store_size_ret = res_end_offset - res_start_offset;

	return 0;

write_error:
	ERROR_WITH_ERRNO("Write error");
	return ret;
}

/* Finish writing a WIM resource by writing or updating the chunk table (if not
 * writing the data uncompressed) and loading its metadata into @out_reshdr.  */
static int
end_write_resource(struct write_streams_ctx *ctx, struct wim_reshdr *out_reshdr)
{
	int ret;
	u64 res_size_in_wim;
	u64 res_uncompressed_size;
	u64 res_offset_in_wim;

	wimlib_assert(ctx->cur_write_stream_offset == ctx->cur_write_res_size ||
		      (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID));
	res_uncompressed_size = ctx->cur_write_res_size;

	if (ctx->compressor) {
		ret = end_chunk_table(ctx, res_uncompressed_size,
				      &res_offset_in_wim, &res_size_in_wim);
		if (ret)
			return ret;
	} else {
		res_offset_in_wim = ctx->chunks_start_offset;
		res_size_in_wim = ctx->out_fd->offset - res_offset_in_wim;
	}
	out_reshdr->uncompressed_size = res_uncompressed_size;
	out_reshdr->size_in_wim = res_size_in_wim;
	out_reshdr->offset_in_wim = res_offset_in_wim;
	DEBUG("Finished writing resource: %"PRIu64" => %"PRIu64" @ %"PRIu64"",
	      res_uncompressed_size, res_size_in_wim, res_offset_in_wim);
	return 0;
}

/* No more data streams of the file at @path are needed.  */
static int
done_with_file(const tchar *path, wimlib_progress_func_t progfunc, void *progctx)
{
	union wimlib_progress_info info;

	info.done_with_file.path_to_file = path;

	return call_progress(progfunc, WIMLIB_PROGRESS_MSG_DONE_WITH_FILE,
			     &info, progctx);
}

static inline bool
is_file_stream(const struct wim_lookup_table_entry *lte)
{
	return lte->resource_location == RESOURCE_IN_FILE_ON_DISK
#ifdef __WIN32__
	    || lte->resource_location == RESOURCE_IN_WINNT_FILE_ON_DISK
	    || lte->resource_location == RESOURCE_WIN32_ENCRYPTED
#endif
	   ;
}

static int
do_done_with_stream(struct wim_lookup_table_entry *lte,
		    wimlib_progress_func_t progfunc, void *progctx)
{
	int ret;
	struct wim_inode *inode;

	if (!lte->may_send_done_with_file)
		return 0;

	inode = lte->file_inode;

	wimlib_assert(inode != NULL);
	wimlib_assert(inode->num_remaining_streams > 0);
	if (--inode->num_remaining_streams > 0)
		return 0;

#ifdef __WIN32__
	/* XXX: This logic really should be somewhere else.  */

	/* We want the path to the file, but lte->file_on_disk might actually
	 * refer to a named data stream.  Temporarily strip the named data
	 * stream from the path.  */
	wchar_t *p_colon = NULL;
	wchar_t *p_question_mark = NULL;
	const wchar_t *p_stream_name;

	p_stream_name = path_stream_name(lte->file_on_disk);
	if (unlikely(p_stream_name)) {
		p_colon = (wchar_t *)(p_stream_name - 1);
		wimlib_assert(*p_colon == L':');
		*p_colon = L'\0';
	}

	/* We also should use a fake Win32 path instead of a NT path  */
	if (!wcsncmp(lte->file_on_disk, L"\\??\\", 4)) {
		p_question_mark = &lte->file_on_disk[1];
		*p_question_mark = L'\\';
	}
#endif

	ret = done_with_file(lte->file_on_disk, progfunc, progctx);

#ifdef __WIN32__
	if (p_colon)
		*p_colon = L':';
	if (p_question_mark)
		*p_question_mark = L'?';
#endif
	return ret;
}

/* Handle WIMLIB_WRITE_FLAG_SEND_DONE_WITH_FILE_MESSAGES mode.  */
static inline int
done_with_stream(struct wim_lookup_table_entry *lte,
		 struct write_streams_ctx *ctx)
{
	if (likely(!(ctx->write_resource_flags &
		     WRITE_RESOURCE_FLAG_SEND_DONE_WITH_FILE)))
		return 0;
	return do_done_with_stream(lte, ctx->progress_data.progfunc,
				   ctx->progress_data.progctx);
}

/* Begin processing a stream for writing.  */
static int
write_stream_begin_read(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct write_streams_ctx *ctx = _ctx;
	int ret;

	wimlib_assert(lte->size > 0);

	ctx->cur_read_stream_offset = 0;
	ctx->cur_read_stream_size = lte->size;

	/* As an optimization, we allow some streams to be "unhashed", meaning
	 * their SHA1 message digests are unknown.  This is the case with
	 * streams that are added by scanning a directry tree with
	 * wimlib_add_image(), for example.  Since WIM uses single-instance
	 * streams, we don't know whether such each such stream really need to
	 * written until it is actually checksummed, unless it has a unique
	 * size.  In such cases we read and checksum the stream in this
	 * function, thereby advancing ahead of read_stream_list(), which will
	 * still provide the data again to write_stream_process_chunk().  This
	 * is okay because an unhashed stream cannot be in a WIM resource, which
	 * might be costly to decompress.  */
	if (ctx->lookup_table != NULL && lte->unhashed && !lte->unique_size) {

		struct wim_lookup_table_entry *lte_new;

		ret = hash_unhashed_stream(lte, ctx->lookup_table, &lte_new);
		if (ret)
			return ret;
		if (lte_new != lte) {
			/* Duplicate stream detected.  */

			if (lte_new->will_be_in_output_wim ||
			    stream_filtered(lte_new, ctx->filter_ctx))
			{
				/* The duplicate stream is already being
				 * included in the output WIM, or it would be
				 * filtered out if it had been.  Skip writing
				 * this stream (and reading it again) entirely,
				 * passing its output reference count to the
				 * duplicate stream in the former case.  */
				DEBUG("Discarding duplicate stream of "
				      "length %"PRIu64, lte->size);
				ret = do_write_streams_progress(&ctx->progress_data,
								lte->size,
								1, true);
				list_del(&lte->write_streams_list);
				list_del(&lte->lookup_table_list);
				if (lte_new->will_be_in_output_wim)
					lte_new->out_refcnt += lte->out_refcnt;
				if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID)
					ctx->cur_write_res_size -= lte->size;
				if (!ret)
					ret = done_with_stream(lte, ctx);
				free_lookup_table_entry(lte);
				if (ret)
					return ret;
				return BEGIN_STREAM_STATUS_SKIP_STREAM;
			} else {
				/* The duplicate stream can validly be written,
				 * but was not marked as such.  Discard the
				 * current stream entry and use the duplicate,
				 * but actually freeing the current entry must
				 * wait until read_stream_list() has finished
				 * reading its data.  */
				DEBUG("Stream duplicate, but not already "
				      "selected for writing.");
				list_replace(&lte->write_streams_list,
					     &lte_new->write_streams_list);
				list_replace(&lte->lookup_table_list,
					     &lte_new->lookup_table_list);
				lte->will_be_in_output_wim = 0;
				lte_new->out_refcnt = lte->out_refcnt;
				lte_new->will_be_in_output_wim = 1;
				lte_new->may_send_done_with_file = 0;
				lte = lte_new;
			}
		}
	}
	list_move_tail(&lte->write_streams_list, &ctx->pending_streams);
	return 0;
}

/* Rewrite a stream that was just written compressed as uncompressed instead.
 * This function is optional, but if a stream did not compress to less than its
 * original size, it might as well be written uncompressed.  */
static int
write_stream_uncompressed(struct wim_lookup_table_entry *lte,
			  struct filedes *out_fd)
{
	int ret;
	u64 begin_offset = lte->out_reshdr.offset_in_wim;
	u64 end_offset = out_fd->offset;

	if (filedes_seek(out_fd, begin_offset) == -1)
		return 0;

	ret = extract_full_stream_to_fd(lte, out_fd);
	if (ret) {
		/* Error reading the uncompressed data.  */
		if (out_fd->offset == begin_offset &&
		    filedes_seek(out_fd, end_offset) != -1)
		{
			/* Nothing was actually written yet, and we successfully
			 * seeked to the end of the compressed resource, so
			 * don't issue a hard error; just keep the compressed
			 * resource instead.  */
			WARNING("Recovered compressed stream of "
				"size %"PRIu64", continuing on.",
				lte->size);
			return 0;
		}
		return ret;
	}

	wimlib_assert(out_fd->offset - begin_offset == lte->size);

	if (out_fd->offset < end_offset &&
	    0 != ftruncate(out_fd->fd, out_fd->offset))
	{
		ERROR_WITH_ERRNO("Can't truncate output file to "
				 "offset %"PRIu64, out_fd->offset);
		return WIMLIB_ERR_WRITE;
	}

	lte->out_reshdr.size_in_wim = lte->size;
	lte->out_reshdr.flags &= ~(WIM_RESHDR_FLAG_COMPRESSED |
				   WIM_RESHDR_FLAG_SOLID);
	return 0;
}

/* Returns true if the specified stream should be truncated from the WIM file
 * and re-written as uncompressed.  lte->out_reshdr must be filled in from the
 * initial write of the stream.  */
static bool
should_rewrite_stream_uncompressed(const struct write_streams_ctx *ctx,
				   const struct wim_lookup_table_entry *lte)
{
	/* If the compressed data is smaller than the uncompressed data, prefer
	 * the compressed data.  */
	if (lte->out_reshdr.size_in_wim < lte->out_reshdr.uncompressed_size)
		return false;

	/* If we're not actually writing compressed data, then there's no need
	 * for re-writing.  */
	if (!ctx->compressor)
		return false;

	/* If writing a pipable WIM, everything we write to the output is final
	 * (it might actually be a pipe!).  */
	if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_PIPABLE)
		return false;

	/* If the stream that would need to be re-read is located in a solid
	 * resource in another WIM file, then re-reading it would be costly.  So
	 * don't do it.
	 *
	 * Exception: if the compressed size happens to be *exactly* the same as
	 * the uncompressed size, then the stream *must* be written uncompressed
	 * in order to remain compatible with the Windows Overlay Filesystem
	 * Filter Driver (WOF).
	 *
	 * TODO: we are currently assuming that the optimization for
	 * single-chunk resources in maybe_rewrite_stream_uncompressed()
	 * prevents this case from being triggered too often.  To fully prevent
	 * excessive decompressions in degenerate cases, we really should
	 * obtain the uncompressed data by decompressing the compressed data we
	 * wrote to the output file.
	 */
	if ((lte->flags & WIM_RESHDR_FLAG_SOLID) &&
	    (lte->out_reshdr.size_in_wim != lte->out_reshdr.uncompressed_size))
		return false;

	return true;
}

static int
maybe_rewrite_stream_uncompressed(struct write_streams_ctx *ctx,
				  struct wim_lookup_table_entry *lte)
{
	if (!should_rewrite_stream_uncompressed(ctx, lte))
		return 0;

	/* Regular (non-solid) WIM resources with exactly one chunk and
	 * compressed size equal to uncompressed size are exactly the same as
	 * the corresponding compressed data --- since there must be 0 entries
	 * in the chunk table and the only chunk must be stored uncompressed.
	 * In this case, there's no need to rewrite anything.  */
	if (ctx->chunk_index == 1 &&
	    lte->out_reshdr.size_in_wim == lte->out_reshdr.uncompressed_size)
	{
		lte->out_reshdr.flags &= ~WIM_RESHDR_FLAG_COMPRESSED;
		return 0;
	}

	return write_stream_uncompressed(lte, ctx->out_fd);
}

/* Write the next chunk of (typically compressed) data to the output WIM,
 * handling the writing of the chunk table.  */
static int
write_chunk(struct write_streams_ctx *ctx, const void *cchunk,
	    size_t csize, size_t usize)
{
	int ret;

	struct wim_lookup_table_entry *lte;
	u32 completed_stream_count;
	u32 completed_size;

	lte = list_entry(ctx->pending_streams.next,
			 struct wim_lookup_table_entry, write_streams_list);

	if (ctx->cur_write_stream_offset == 0 &&
	    !(ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID))
	{
		/* Starting to write a new stream in non-solid mode.  */

		if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_PIPABLE) {
			int additional_reshdr_flags = 0;
			if (ctx->compressor != NULL)
				additional_reshdr_flags |= WIM_RESHDR_FLAG_COMPRESSED;

			DEBUG("Writing pipable WIM stream header "
			      "(offset=%"PRIu64")", ctx->out_fd->offset);

			ret = write_pwm_stream_header(lte, ctx->out_fd,
						      additional_reshdr_flags);
			if (ret)
				return ret;
		}

		ret = begin_write_resource(ctx, lte->size);
		if (ret)
			return ret;
	}

	if (ctx->compressor != NULL) {
		/* Record the compresed chunk size.  */
		wimlib_assert(ctx->chunk_index < ctx->num_alloc_chunks);
		ctx->chunk_csizes[ctx->chunk_index++] = csize;

	       /* If writing a pipable WIM, before the chunk data write a chunk
		* header that provides the compressed chunk size.  */
		if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_PIPABLE) {
			struct pwm_chunk_hdr chunk_hdr = {
				.compressed_size = cpu_to_le32(csize),
			};
			ret = full_write(ctx->out_fd, &chunk_hdr,
					 sizeof(chunk_hdr));
			if (ret)
				goto write_error;
		}
	}

	/* Write the chunk data.  */
	ret = full_write(ctx->out_fd, cchunk, csize);
	if (ret)
		goto write_error;

	ctx->cur_write_stream_offset += usize;

	completed_size = usize;
	completed_stream_count = 0;
	if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID) {
		/* Wrote chunk in solid mode.  It may have finished multiple
		 * streams.  */
		struct wim_lookup_table_entry *next_lte;

		while (lte && ctx->cur_write_stream_offset >= lte->size) {

			ctx->cur_write_stream_offset -= lte->size;

			if (ctx->cur_write_stream_offset)
				next_lte = list_entry(lte->write_streams_list.next,
						      struct wim_lookup_table_entry,
						      write_streams_list);
			else
				next_lte = NULL;

			ret = done_with_stream(lte, ctx);
			if (ret)
				return ret;
			list_move_tail(&lte->write_streams_list, &ctx->solid_streams);
			completed_stream_count++;

			lte = next_lte;
		}
	} else {
		/* Wrote chunk in non-solid mode.  It may have finished a
		 * stream.  */
		if (ctx->cur_write_stream_offset == lte->size) {

			wimlib_assert(ctx->cur_write_stream_offset ==
				      ctx->cur_write_res_size);

			ret = end_write_resource(ctx, &lte->out_reshdr);
			if (ret)
				return ret;

			lte->out_reshdr.flags = filter_resource_flags(lte->flags);
			if (ctx->compressor != NULL)
				lte->out_reshdr.flags |= WIM_RESHDR_FLAG_COMPRESSED;

			ret = maybe_rewrite_stream_uncompressed(ctx, lte);
			if (ret)
				return ret;

			wimlib_assert(lte->out_reshdr.uncompressed_size == lte->size);

			ctx->cur_write_stream_offset = 0;

			ret = done_with_stream(lte, ctx);
			if (ret)
				return ret;
			list_del(&lte->write_streams_list);
			completed_stream_count++;
		}
	}

	return do_write_streams_progress(&ctx->progress_data,
					 completed_size, completed_stream_count,
					 false);

write_error:
	ERROR_WITH_ERRNO("Write error");
	return ret;
}

static int
submit_chunk_for_compression(struct write_streams_ctx *ctx,
			     const void *chunk, size_t size)
{
	/* While we are unable to submit the chunk for compression (due to too
	 * many chunks already outstanding), retrieve and write the next
	 * compressed chunk.  */
	while (!ctx->compressor->submit_chunk(ctx->compressor, chunk, size)) {
		const void *cchunk;
		u32 csize;
		u32 usize;
		bool bret;
		int ret;

		bret = ctx->compressor->get_chunk(ctx->compressor,
						  &cchunk, &csize, &usize);

		wimlib_assert(bret);

		ret = write_chunk(ctx, cchunk, csize, usize);
		if (ret)
			return ret;
	}
	return 0;
}

/* Process the next chunk of data to be written to a WIM resource.  */
static int
write_stream_process_chunk(const void *chunk, size_t size, void *_ctx)
{
	struct write_streams_ctx *ctx = _ctx;
	int ret;
	const u8 *chunkptr, *chunkend;

	wimlib_assert(size != 0);

	if (ctx->compressor == NULL) {
		/* Write chunk uncompressed.  */
		 ret = write_chunk(ctx, chunk, size, size);
		 if (ret)
			 return ret;
		 ctx->cur_read_stream_offset += size;
		 return 0;
	}

	/* Submit the chunk for compression, but take into account that the
	 * @size the chunk was provided in may not correspond to the
	 * @out_chunk_size being used for compression.  */
	chunkptr = chunk;
	chunkend = chunkptr + size;
	do {
		const u8 *resized_chunk;
		size_t needed_chunk_size;

		if (ctx->write_resource_flags & WRITE_RESOURCE_FLAG_SOLID) {
			needed_chunk_size = ctx->out_chunk_size;
		} else {
			u64 res_bytes_remaining;

			res_bytes_remaining = ctx->cur_read_stream_size -
					      ctx->cur_read_stream_offset;
			needed_chunk_size = min(ctx->out_chunk_size,
						ctx->chunk_buf_filled +
							res_bytes_remaining);
		}

		if (ctx->chunk_buf_filled == 0 &&
		    chunkend - chunkptr >= needed_chunk_size)
		{
			/* No intermediate buffering needed.  */
			resized_chunk = chunkptr;
			chunkptr += needed_chunk_size;
			ctx->cur_read_stream_offset += needed_chunk_size;
		} else {
			/* Intermediate buffering needed.  */
			size_t bytes_consumed;

			bytes_consumed = min(chunkend - chunkptr,
					     needed_chunk_size - ctx->chunk_buf_filled);

			memcpy(&ctx->chunk_buf[ctx->chunk_buf_filled],
			       chunkptr, bytes_consumed);

			chunkptr += bytes_consumed;
			ctx->cur_read_stream_offset += bytes_consumed;
			ctx->chunk_buf_filled += bytes_consumed;
			if (ctx->chunk_buf_filled == needed_chunk_size) {
				resized_chunk = ctx->chunk_buf;
				ctx->chunk_buf_filled = 0;
			} else {
				break;
			}

		}

		ret = submit_chunk_for_compression(ctx, resized_chunk,
						   needed_chunk_size);
		if (ret)
			return ret;

	} while (chunkptr != chunkend);
	return 0;
}

/* Finish processing a stream for writing.  It may not have been completely
 * written yet, as the chunk_compressor implementation may still have chunks
 * buffered or being compressed.  */
static int
write_stream_end_read(struct wim_lookup_table_entry *lte, int status, void *_ctx)
{
	struct write_streams_ctx *ctx = _ctx;

	wimlib_assert(ctx->cur_read_stream_offset == ctx->cur_read_stream_size || status);

	if (!lte->will_be_in_output_wim) {
		/* The 'lte' stream was a duplicate.  Now that its data has
		 * finished being read, it is being discarded in favor of the
		 * duplicate entry.  It therefore is no longer needed, and we
		 * can fire the DONE_WITH_FILE callback because the file will
		 * not be read again.
		 *
		 * Note: we can't yet fire DONE_WITH_FILE for non-duplicate
		 * streams, since it needs to be possible to re-read the file if
		 * it does not compress to less than its original size.  */
		if (!status)
			status = done_with_stream(lte, ctx);
		free_lookup_table_entry(lte);
	} else if (!status && lte->unhashed && ctx->lookup_table != NULL) {
		/* The 'lte' stream was not a duplicate and was previously
		 * unhashed.  Since we passed COMPUTE_MISSING_STREAM_HASHES to
		 * read_stream_list(), lte->hash is now computed and valid.  So
		 * turn this stream into a "hashed" stream.  */
		list_del(&lte->unhashed_list);
		lookup_table_insert(ctx->lookup_table, lte);
		lte->unhashed = 0;
	}
	return status;
}

/* Compute statistics about a list of streams that will be written.
 *
 * Assumes the streams are sorted such that all streams located in each distinct
 * WIM (specified by WIMStruct) are together.  */
static void
compute_stream_list_stats(struct list_head *stream_list,
			  struct write_streams_ctx *ctx)
{
	struct wim_lookup_table_entry *lte;
	u64 total_bytes = 0;
	u64 num_streams = 0;
	u64 total_parts = 0;
	WIMStruct *prev_wim_part = NULL;

	list_for_each_entry(lte, stream_list, write_streams_list) {
		num_streams++;
		total_bytes += lte->size;
		if (lte->resource_location == RESOURCE_IN_WIM) {
			if (prev_wim_part != lte->rspec->wim) {
				prev_wim_part = lte->rspec->wim;
				total_parts++;
			}
		}
	}
	ctx->progress_data.progress.write_streams.total_bytes       = total_bytes;
	ctx->progress_data.progress.write_streams.total_streams     = num_streams;
	ctx->progress_data.progress.write_streams.completed_bytes   = 0;
	ctx->progress_data.progress.write_streams.completed_streams = 0;
	ctx->progress_data.progress.write_streams.compression_type  = ctx->out_ctype;
	ctx->progress_data.progress.write_streams.total_parts       = total_parts;
	ctx->progress_data.progress.write_streams.completed_parts   = 0;
	ctx->progress_data.next_progress = 0;
}

/* Find streams in @stream_list that can be copied to the output WIM in raw form
 * rather than compressed.  Delete these streams from @stream_list and move them
 * to @raw_copy_streams.  Return the total uncompressed size of the streams that
 * need to be compressed.  */
static u64
find_raw_copy_streams(struct list_head *stream_list,
		      int write_resource_flags,
		      int out_ctype,
		      u32 out_chunk_size,
		      struct list_head *raw_copy_streams)
{
	struct wim_lookup_table_entry *lte, *tmp;
	u64 num_bytes_to_compress = 0;

	INIT_LIST_HEAD(raw_copy_streams);

	/* Initialize temporary raw_copy_ok flag.  */
	list_for_each_entry(lte, stream_list, write_streams_list)
		if (lte->resource_location == RESOURCE_IN_WIM)
			lte->rspec->raw_copy_ok = 0;

	list_for_each_entry_safe(lte, tmp, stream_list, write_streams_list) {
		if (lte->resource_location == RESOURCE_IN_WIM &&
		    lte->rspec->raw_copy_ok)
		{
			list_move_tail(&lte->write_streams_list,
				       raw_copy_streams);
		} else if (can_raw_copy(lte, write_resource_flags,
				 out_ctype, out_chunk_size))
		{
			lte->rspec->raw_copy_ok = 1;
			list_move_tail(&lte->write_streams_list,
				       raw_copy_streams);
		} else {
			num_bytes_to_compress += lte->size;
		}
	}

	return num_bytes_to_compress;
}

/* Copy a raw compressed resource located in another WIM file to the WIM file
 * being written.  */
static int
write_raw_copy_resource(struct wim_resource_spec *in_rspec,
			struct filedes *out_fd)
{
	u64 cur_read_offset;
	u64 end_read_offset;
	u8 buf[BUFFER_SIZE];
	size_t bytes_to_read;
	int ret;
	struct filedes *in_fd;
	struct wim_lookup_table_entry *lte;
	u64 out_offset_in_wim;

	DEBUG("Copying raw compressed data (size_in_wim=%"PRIu64", "
	      "uncompressed_size=%"PRIu64")",
	      in_rspec->size_in_wim, in_rspec->uncompressed_size);

	/* Copy the raw data.  */
	cur_read_offset = in_rspec->offset_in_wim;
	end_read_offset = cur_read_offset + in_rspec->size_in_wim;

	out_offset_in_wim = out_fd->offset;

	if (in_rspec->is_pipable) {
		if (cur_read_offset < sizeof(struct pwm_stream_hdr))
			return WIMLIB_ERR_INVALID_PIPABLE_WIM;
		cur_read_offset -= sizeof(struct pwm_stream_hdr);
		out_offset_in_wim += sizeof(struct pwm_stream_hdr);
	}
	in_fd = &in_rspec->wim->in_fd;
	wimlib_assert(cur_read_offset != end_read_offset);
	do {

		bytes_to_read = min(sizeof(buf), end_read_offset - cur_read_offset);

		ret = full_pread(in_fd, buf, bytes_to_read, cur_read_offset);
		if (ret)
			return ret;

		ret = full_write(out_fd, buf, bytes_to_read);
		if (ret)
			return ret;

		cur_read_offset += bytes_to_read;

	} while (cur_read_offset != end_read_offset);

	list_for_each_entry(lte, &in_rspec->stream_list, rspec_node) {
		if (lte->will_be_in_output_wim) {
			stream_set_out_reshdr_for_reuse(lte);
			if (in_rspec->flags & WIM_RESHDR_FLAG_SOLID)
				lte->out_res_offset_in_wim = out_offset_in_wim;
			else
				lte->out_reshdr.offset_in_wim = out_offset_in_wim;

		}
	}
	return 0;
}

/* Copy a list of raw compressed resources located in other WIM file(s) to the
 * WIM file being written.  */
static int
write_raw_copy_resources(struct list_head *raw_copy_streams,
			 struct filedes *out_fd,
			 struct write_streams_progress_data *progress_data)
{
	struct wim_lookup_table_entry *lte;
	int ret;

	list_for_each_entry(lte, raw_copy_streams, write_streams_list)
		lte->rspec->raw_copy_ok = 1;

	list_for_each_entry(lte, raw_copy_streams, write_streams_list) {
		if (lte->rspec->raw_copy_ok) {
			/* Write each solid resource only one time, no matter
			 * how many streams reference it.  */
			ret = write_raw_copy_resource(lte->rspec, out_fd);
			if (ret)
				return ret;
			lte->rspec->raw_copy_ok = 0;
		}
		ret = do_write_streams_progress(progress_data, lte->size,
						1, false);
		if (ret)
			return ret;
	}
	return 0;
}

/* Wait for and write all chunks pending in the compressor.  */
static int
finish_remaining_chunks(struct write_streams_ctx *ctx)
{
	const void *cdata;
	u32 csize;
	u32 usize;
	int ret;

	if (ctx->compressor == NULL)
		return 0;

	if (ctx->chunk_buf_filled != 0) {
		ret = submit_chunk_for_compression(ctx, ctx->chunk_buf,
						   ctx->chunk_buf_filled);
		if (ret)
			return ret;
	}

	while (ctx->compressor->get_chunk(ctx->compressor, &cdata, &csize, &usize)) {
		ret = write_chunk(ctx, cdata, csize, usize);
		if (ret)
			return ret;
	}
	return 0;
}

static void
remove_zero_length_streams(struct list_head *stream_list)
{
	struct wim_lookup_table_entry *lte, *tmp;

	list_for_each_entry_safe(lte, tmp, stream_list, write_streams_list) {
		wimlib_assert(lte->will_be_in_output_wim);
		if (lte->size == 0) {
			list_del(&lte->write_streams_list);
			lte->out_reshdr.offset_in_wim = 0;
			lte->out_reshdr.size_in_wim = 0;
			lte->out_reshdr.uncompressed_size = 0;
			lte->out_reshdr.flags = filter_resource_flags(lte->flags);
		}
	}
}

static void
init_done_with_file_info(struct list_head *stream_list)
{
	struct wim_lookup_table_entry *lte;

	list_for_each_entry(lte, stream_list, write_streams_list) {
		if (is_file_stream(lte)) {
			lte->file_inode->num_remaining_streams = 0;
			lte->may_send_done_with_file = 1;
		} else {
			lte->may_send_done_with_file = 0;
		}
	}

	list_for_each_entry(lte, stream_list, write_streams_list)
		if (lte->may_send_done_with_file)
			lte->file_inode->num_remaining_streams++;
}

/*
 * Write a list of streams to the output WIM file.
 *
 * @stream_list
 *	The list of streams to write, specified by a list of `struct
 *	wim_lookup_table_entry's linked by the 'write_streams_list' member.
 *
 * @out_fd
 *	The file descriptor, opened for writing, to which to write the streams.
 *
 * @write_resource_flags
 *	Flags to modify how the streams are written:
 *
 *	WRITE_RESOURCE_FLAG_RECOMPRESS:
 *		Force compression of all resources, even if they could otherwise
 *		be re-used by copying the raw data, due to being located in a WIM
 *		file with compatible compression parameters.
 *
 *	WRITE_RESOURCE_FLAG_PIPABLE:
 *		Write the resources in the wimlib-specific pipable format, and
 *		furthermore do so in such a way that no seeking backwards in
 *		@out_fd will be performed (so it may be a pipe).
 *
 *	WRITE_RESOURCE_FLAG_SOLID:
 *		Combine all the streams into a single resource rather than
 *		writing them in separate resources.  This flag is only valid if
 *		the WIM version number has been, or will be, set to
 *		WIM_VERSION_SOLID.  This flag may not be combined with
 *		WRITE_RESOURCE_FLAG_PIPABLE.
 *
 * @out_ctype
 *	Compression format to use to write the output streams, specified as one
 *	of the WIMLIB_COMPRESSION_TYPE_* constants.
 *	WIMLIB_COMPRESSION_TYPE_NONE is allowed.
 *
 * @out_chunk_size
 *	Chunk size to use to write the streams.  It must be a valid chunk size
 *	for the specified compression format @out_ctype, unless @out_ctype is
 *	WIMLIB_COMPRESSION_TYPE_NONE, in which case this parameter is ignored.
 *
 * @num_threads
 *	Number of threads to use to compress data.  If 0, a default number of
 *	threads will be chosen.  The number of threads still may be decreased
 *	from the specified value if insufficient memory is detected.
 *
 * @lookup_table
 *	If on-the-fly deduplication of unhashed streams is desired, this
 *	parameter must be pointer to the lookup table for the WIMStruct on whose
 *	behalf the streams are being written.  Otherwise, this parameter can be
 *	NULL.
 *
 * @filter_ctx
 *	If on-the-fly deduplication of unhashed streams is desired, this
 *	parameter can be a pointer to a context for stream filtering used to
 *	detect whether the duplicate stream has been hard-filtered or not.  If
 *	no streams are hard-filtered or no streams are unhashed, this parameter
 *	can be NULL.
 *
 * This function will write the streams in @stream_list to resources in
 * consecutive positions in the output WIM file, or to a single solid resource
 * if WRITE_RESOURCE_FLAG_SOLID was specified in @write_resource_flags.  In both
 * cases, the @out_reshdr of the `struct wim_lookup_table_entry' for each stream
 * written will be updated to specify its location, size, and flags in the
 * output WIM.  In the solid resource case, WIM_RESHDR_FLAG_SOLID will be set in
 * the @flags field of each @out_reshdr, and furthermore @out_res_offset_in_wim
 * and @out_res_size_in_wim of each @out_reshdr will be set to the offset and
 * size, respectively, in the output WIM of the solid resource containing the
 * corresponding stream.
 *
 * Each of the streams to write may be in any location supported by the
 * resource-handling code (specifically, read_stream_list()), such as the
 * contents of external file that has been logically added to the output WIM, or
 * a stream in another WIM file that has been imported, or even a stream in the
 * "same" WIM file of which a modified copy is being written.  In the case that
 * a stream is already in a WIM file and uses compatible compression parameters,
 * by default this function will re-use the raw data instead of decompressing
 * it, then recompressing it; however, with WRITE_RESOURCE_FLAG_RECOMPRESS
 * specified in @write_resource_flags, this is not done.
 *
 * As a further requirement, this function requires that the
 * @will_be_in_output_wim member be set to 1 on all streams in @stream_list as
 * well as any other streams not in @stream_list that will be in the output WIM
 * file, but set to 0 on any other streams in the output WIM's lookup table or
 * sharing a solid resource with a stream in @stream_list.  Still furthermore,
 * if on-the-fly deduplication of streams is possible, then all streams in
 * @stream_list must also be linked by @lookup_table_list along with any other
 * streams that have @will_be_in_output_wim set.
 *
 * This function handles on-the-fly deduplication of streams for which SHA1
 * message digests have not yet been calculated.  Such streams may or may not
 * need to be written.  If @lookup_table is non-NULL, then each stream in
 * @stream_list that has @unhashed set but not @unique_size set is checksummed
 * immediately before it would otherwise be read for writing in order to
 * determine if it is identical to another stream already being written or one
 * that would be filtered out of the output WIM using stream_filtered() with the
 * context @filter_ctx.  Each such duplicate stream will be removed from
 * @stream_list, its reference count transfered to the pre-existing duplicate
 * stream, its memory freed, and will not be written.  Alternatively, if a
 * stream in @stream_list is a duplicate with any stream in @lookup_table that
 * has not been marked for writing or would not be hard-filtered, it is freed
 * and the pre-existing duplicate is written instead, taking ownership of the
 * reference count and slot in the @lookup_table_list.
 *
 * Returns 0 if every stream was either written successfully or did not need to
 * be written; otherwise returns a non-zero error code.
 */
static int
write_stream_list(struct list_head *stream_list,
		  struct filedes *out_fd,
		  int write_resource_flags,
		  int out_ctype,
		  u32 out_chunk_size,
		  unsigned num_threads,
		  struct wim_lookup_table *lookup_table,
		  struct filter_context *filter_ctx,
		  wimlib_progress_func_t progfunc,
		  void *progctx)
{
	int ret;
	struct write_streams_ctx ctx;
	struct list_head raw_copy_streams;

	wimlib_assert((write_resource_flags &
		       (WRITE_RESOURCE_FLAG_SOLID |
			WRITE_RESOURCE_FLAG_PIPABLE)) !=
				(WRITE_RESOURCE_FLAG_SOLID |
				 WRITE_RESOURCE_FLAG_PIPABLE));

	remove_zero_length_streams(stream_list);

	if (list_empty(stream_list)) {
		DEBUG("No streams to write.");
		return 0;
	}

	/* If needed, set auxiliary information so that we can detect when the
	 * library has finished using each external file.  */
	if (unlikely(write_resource_flags & WRITE_RESOURCE_FLAG_SEND_DONE_WITH_FILE))
		init_done_with_file_info(stream_list);

	memset(&ctx, 0, sizeof(ctx));

	/* Pre-sorting the streams is required for compute_stream_list_stats().
	 * Afterwards, read_stream_list() need not sort them again.  */
	ret = sort_stream_list_by_sequential_order(stream_list,
						   offsetof(struct wim_lookup_table_entry,
							    write_streams_list));
	if (ret)
		return ret;

	ctx.out_fd = out_fd;
	ctx.lookup_table = lookup_table;
	ctx.out_ctype = out_ctype;
	ctx.out_chunk_size = out_chunk_size;
	ctx.write_resource_flags = write_resource_flags;
	ctx.filter_ctx = filter_ctx;

	if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE) {
		wimlib_assert(out_chunk_size != 0);
		if (out_chunk_size <= STACK_MAX) {
			ctx.chunk_buf = alloca(out_chunk_size);
		} else {
			ctx.chunk_buf = MALLOC(out_chunk_size);
			if (ctx.chunk_buf == NULL) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_destroy_context;
			}
		}
	}
	ctx.chunk_buf_filled = 0;

	compute_stream_list_stats(stream_list, &ctx);

	ctx.progress_data.progfunc = progfunc;
	ctx.progress_data.progctx = progctx;

	ctx.num_bytes_to_compress = find_raw_copy_streams(stream_list,
							  write_resource_flags,
							  out_ctype,
							  out_chunk_size,
							  &raw_copy_streams);

	DEBUG("Writing stream list "
	      "(offset = %"PRIu64", write_resource_flags=0x%08x, "
	      "out_ctype=%d, out_chunk_size=%u, num_threads=%u, "
	      "total_bytes=%"PRIu64", num_bytes_to_compress=%"PRIu64")",
	      out_fd->offset, write_resource_flags,
	      out_ctype, out_chunk_size, num_threads,
	      ctx.progress_data.progress.write_streams.total_bytes,
	      ctx.num_bytes_to_compress);

	if (ctx.num_bytes_to_compress == 0) {
		DEBUG("No compression needed; skipping to raw copy!");
		goto out_write_raw_copy_resources;
	}

	/* Unless uncompressed output was required, allocate a chunk_compressor
	 * to do compression.  There are serial and parallel implementations of
	 * the chunk_compressor interface.  We default to parallel using the
	 * specified number of threads, unless the upper bound on the number
	 * bytes needing to be compressed is less than a heuristic value.  */
	if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE) {

	#ifdef ENABLE_MULTITHREADED_COMPRESSION
		if (ctx.num_bytes_to_compress > max(2000000, out_chunk_size)) {
			ret = new_parallel_chunk_compressor(out_ctype,
							    out_chunk_size,
							    num_threads, 0,
							    &ctx.compressor);
			if (ret > 0) {
				WARNING("Couldn't create parallel chunk compressor: %"TS".\n"
					"          Falling back to single-threaded compression.",
					wimlib_get_error_string(ret));
			}
		}
	#endif

		if (ctx.compressor == NULL) {
			ret = new_serial_chunk_compressor(out_ctype, out_chunk_size,
							  &ctx.compressor);
			if (ret)
				goto out_destroy_context;
		}
	}

	if (ctx.compressor)
		ctx.progress_data.progress.write_streams.num_threads = ctx.compressor->num_threads;
	else
		ctx.progress_data.progress.write_streams.num_threads = 1;

	DEBUG("Actually using %u threads",
	      ctx.progress_data.progress.write_streams.num_threads);

	INIT_LIST_HEAD(&ctx.pending_streams);
	INIT_LIST_HEAD(&ctx.solid_streams);

	ret = call_progress(ctx.progress_data.progfunc,
			    WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
			    &ctx.progress_data.progress,
			    ctx.progress_data.progctx);
	if (ret)
		goto out_destroy_context;

	if (write_resource_flags & WRITE_RESOURCE_FLAG_SOLID) {
		ret = begin_write_resource(&ctx, ctx.num_bytes_to_compress);
		if (ret)
			goto out_destroy_context;
	}

	/* Read the list of streams needing to be compressed, using the
	 * specified callbacks to execute processing of the data.  */

	struct read_stream_list_callbacks cbs = {
		.begin_stream		= write_stream_begin_read,
		.begin_stream_ctx	= &ctx,
		.consume_chunk		= write_stream_process_chunk,
		.consume_chunk_ctx	= &ctx,
		.end_stream		= write_stream_end_read,
		.end_stream_ctx		= &ctx,
	};

	ret = read_stream_list(stream_list,
			       offsetof(struct wim_lookup_table_entry, write_streams_list),
			       &cbs,
			       STREAM_LIST_ALREADY_SORTED |
					VERIFY_STREAM_HASHES |
					COMPUTE_MISSING_STREAM_HASHES);

	if (ret)
		goto out_destroy_context;

	ret = finish_remaining_chunks(&ctx);
	if (ret)
		goto out_destroy_context;

	if (write_resource_flags & WRITE_RESOURCE_FLAG_SOLID) {
		struct wim_reshdr reshdr;
		struct wim_lookup_table_entry *lte;
		u64 offset_in_res;

		ret = end_write_resource(&ctx, &reshdr);
		if (ret)
			goto out_destroy_context;

		DEBUG("Ending solid resource: %lu %lu %lu.",
		      reshdr.offset_in_wim,
		      reshdr.size_in_wim,
		      reshdr.uncompressed_size);

		offset_in_res = 0;
		list_for_each_entry(lte, &ctx.solid_streams, write_streams_list) {
			lte->out_reshdr.size_in_wim = lte->size;
			lte->out_reshdr.flags = filter_resource_flags(lte->flags);
			lte->out_reshdr.flags |= WIM_RESHDR_FLAG_SOLID;
			lte->out_reshdr.uncompressed_size = 0;
			lte->out_reshdr.offset_in_wim = offset_in_res;
			lte->out_res_offset_in_wim = reshdr.offset_in_wim;
			lte->out_res_size_in_wim = reshdr.size_in_wim;
			lte->out_res_uncompressed_size = reshdr.uncompressed_size;
			offset_in_res += lte->size;
		}
		wimlib_assert(offset_in_res == reshdr.uncompressed_size);
	}

out_write_raw_copy_resources:
	/* Copy any compressed resources for which the raw data can be reused
	 * without decompression.  */
	ret = write_raw_copy_resources(&raw_copy_streams, ctx.out_fd,
				       &ctx.progress_data);

out_destroy_context:
	if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE && out_chunk_size > STACK_MAX)
		FREE(ctx.chunk_buf);
	FREE(ctx.chunk_csizes);
	if (ctx.compressor)
		ctx.compressor->destroy(ctx.compressor);
	DEBUG("Done (ret=%d)", ret);
	return ret;
}

static int
is_stream_in_solid_resource(struct wim_lookup_table_entry *lte, void *_ignore)
{
	return lte_is_partial(lte);
}

static bool
wim_has_solid_resources(WIMStruct *wim)
{
	return for_lookup_table_entry(wim->lookup_table,
				      is_stream_in_solid_resource, NULL);
}

static int
wim_write_stream_list(WIMStruct *wim,
		      struct list_head *stream_list,
		      int write_flags,
		      unsigned num_threads,
		      struct filter_context *filter_ctx)
{
	int out_ctype;
	u32 out_chunk_size;
	int write_resource_flags;

	write_resource_flags = write_flags_to_resource_flags(write_flags);

	/* wimlib v1.7.0: create a solid WIM file by default if the WIM version
	 * has been set to WIM_VERSION_SOLID and at least one stream in the
	 * WIM's lookup table is located in a solid resource (may be the same
	 * WIM, or a different one in the case of export).  */
	if (wim->hdr.wim_version == WIM_VERSION_SOLID &&
	    wim_has_solid_resources(wim))
	{
		write_resource_flags |= WRITE_RESOURCE_FLAG_SOLID;
	}

	if (write_resource_flags & WRITE_RESOURCE_FLAG_SOLID) {
		out_chunk_size = wim->out_solid_chunk_size;
		out_ctype = wim->out_solid_compression_type;
	} else {
		out_chunk_size = wim->out_chunk_size;
		out_ctype = wim->out_compression_type;
	}

	return write_stream_list(stream_list,
				 &wim->out_fd,
				 write_resource_flags,
				 out_ctype,
				 out_chunk_size,
				 num_threads,
				 wim->lookup_table,
				 filter_ctx,
				 wim->progfunc,
				 wim->progctx);
}

static int
write_wim_resource(struct wim_lookup_table_entry *lte,
		   struct filedes *out_fd,
		   int out_ctype,
		   u32 out_chunk_size,
		   int write_resource_flags)
{
	LIST_HEAD(stream_list);
	list_add(&lte->write_streams_list, &stream_list);
	lte->will_be_in_output_wim = 1;
	return write_stream_list(&stream_list,
				 out_fd,
				 write_resource_flags & ~WRITE_RESOURCE_FLAG_SOLID,
				 out_ctype,
				 out_chunk_size,
				 1,
				 NULL,
				 NULL,
				 NULL,
				 NULL);
}

int
write_wim_resource_from_buffer(const void *buf, size_t buf_size,
			       int reshdr_flags, struct filedes *out_fd,
			       int out_ctype,
			       u32 out_chunk_size,
			       struct wim_reshdr *out_reshdr,
			       u8 *hash,
			       int write_resource_flags)
{
	int ret;
	struct wim_lookup_table_entry *lte;

	/* Set up a temporary lookup table entry to provide to
	 * write_wim_resource().  */

	lte = new_lookup_table_entry();
	if (lte == NULL)
		return WIMLIB_ERR_NOMEM;

	lte->resource_location  = RESOURCE_IN_ATTACHED_BUFFER;
	lte->attached_buffer    = (void*)buf;
	lte->size               = buf_size;
	lte->flags              = reshdr_flags;

	if (write_resource_flags & WRITE_RESOURCE_FLAG_PIPABLE) {
		sha1_buffer(buf, buf_size, lte->hash);
		lte->unhashed = 0;
	} else {
		lte->unhashed = 1;
	}

	ret = write_wim_resource(lte, out_fd, out_ctype, out_chunk_size,
				 write_resource_flags);
	if (ret)
		goto out_free_lte;

	copy_reshdr(out_reshdr, &lte->out_reshdr);

	if (hash)
		copy_hash(hash, lte->hash);
	ret = 0;
out_free_lte:
	lte->resource_location = RESOURCE_NONEXISTENT;
	free_lookup_table_entry(lte);
	return ret;
}

struct stream_size_table {
	struct hlist_head *array;
	size_t num_entries;
	size_t capacity;
};

static int
init_stream_size_table(struct stream_size_table *tab, size_t capacity)
{
	tab->array = CALLOC(capacity, sizeof(tab->array[0]));
	if (tab->array == NULL)
		return WIMLIB_ERR_NOMEM;
	tab->num_entries = 0;
	tab->capacity = capacity;
	return 0;
}

static void
destroy_stream_size_table(struct stream_size_table *tab)
{
	FREE(tab->array);
}

static int
stream_size_table_insert(struct wim_lookup_table_entry *lte, void *_tab)
{
	struct stream_size_table *tab = _tab;
	size_t pos;
	struct wim_lookup_table_entry *same_size_lte;
	struct hlist_node *tmp;

	pos = hash_u64(lte->size) % tab->capacity;
	lte->unique_size = 1;
	hlist_for_each_entry(same_size_lte, tmp, &tab->array[pos], hash_list_2) {
		if (same_size_lte->size == lte->size) {
			lte->unique_size = 0;
			same_size_lte->unique_size = 0;
			break;
		}
	}

	hlist_add_head(&lte->hash_list_2, &tab->array[pos]);
	tab->num_entries++;
	return 0;
}

struct find_streams_ctx {
	WIMStruct *wim;
	int write_flags;
	struct list_head stream_list;
	struct stream_size_table stream_size_tab;
};

static void
reference_stream_for_write(struct wim_lookup_table_entry *lte,
			   struct list_head *stream_list, u32 nref)
{
	if (!lte->will_be_in_output_wim) {
		lte->out_refcnt = 0;
		list_add_tail(&lte->write_streams_list, stream_list);
		lte->will_be_in_output_wim = 1;
	}
	lte->out_refcnt += nref;
}

static int
fully_reference_stream_for_write(struct wim_lookup_table_entry *lte,
				 void *_stream_list)
{
	struct list_head *stream_list = _stream_list;
	lte->will_be_in_output_wim = 0;
	reference_stream_for_write(lte, stream_list, lte->refcnt);
	return 0;
}

static int
inode_find_streams_to_reference(const struct wim_inode *inode,
				const struct wim_lookup_table *table,
				struct list_head *stream_list)
{
	struct wim_lookup_table_entry *lte;
	unsigned i;

	wimlib_assert(inode->i_nlink > 0);

	for (i = 0; i <= inode->i_num_ads; i++) {
		lte = inode_stream_lte(inode, i, table);
		if (lte)
			reference_stream_for_write(lte, stream_list,
						   inode->i_nlink);
		else if (!is_zero_hash(inode_stream_hash(inode, i)))
			return WIMLIB_ERR_RESOURCE_NOT_FOUND;
	}
	return 0;
}

static int
do_stream_set_not_in_output_wim(struct wim_lookup_table_entry *lte, void *_ignore)
{
	lte->will_be_in_output_wim = 0;
	return 0;
}

static int
image_find_streams_to_reference(WIMStruct *wim)
{
	struct wim_image_metadata *imd;
	struct wim_inode *inode;
	struct wim_lookup_table_entry *lte;
	struct list_head *stream_list;
	int ret;

	imd = wim_get_current_image_metadata(wim);

	image_for_each_unhashed_stream(lte, imd)
		lte->will_be_in_output_wim = 0;

	stream_list = wim->private;
	image_for_each_inode(inode, imd) {
		ret = inode_find_streams_to_reference(inode,
						      wim->lookup_table,
						      stream_list);
		if (ret)
			return ret;
	}
	return 0;
}

static int
prepare_unfiltered_list_of_streams_in_output_wim(WIMStruct *wim,
						 int image,
						 int streams_ok,
						 struct list_head *stream_list_ret)
{
	int ret;

	INIT_LIST_HEAD(stream_list_ret);

	if (streams_ok && (image == WIMLIB_ALL_IMAGES ||
			   (image == 1 && wim->hdr.image_count == 1)))
	{
		/* Fast case:  Assume that all streams are being written and
		 * that the reference counts are correct.  */
		struct wim_lookup_table_entry *lte;
		struct wim_image_metadata *imd;
		unsigned i;

		for_lookup_table_entry(wim->lookup_table,
				       fully_reference_stream_for_write,
				       stream_list_ret);

		for (i = 0; i < wim->hdr.image_count; i++) {
			imd = wim->image_metadata[i];
			image_for_each_unhashed_stream(lte, imd)
				fully_reference_stream_for_write(lte, stream_list_ret);
		}
	} else {
		/* Slow case:  Walk through the images being written and
		 * determine the streams referenced.  */
		for_lookup_table_entry(wim->lookup_table,
				       do_stream_set_not_in_output_wim, NULL);
		wim->private = stream_list_ret;
		ret = for_image(wim, image, image_find_streams_to_reference);
		if (ret)
			return ret;
	}

	return 0;
}

struct insert_other_if_hard_filtered_ctx {
	struct stream_size_table *tab;
	struct filter_context *filter_ctx;
};

static int
insert_other_if_hard_filtered(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct insert_other_if_hard_filtered_ctx *ctx = _ctx;

	if (!lte->will_be_in_output_wim &&
	    stream_hard_filtered(lte, ctx->filter_ctx))
		stream_size_table_insert(lte, ctx->tab);
	return 0;
}

static int
determine_stream_size_uniquity(struct list_head *stream_list,
			       struct wim_lookup_table *lt,
			       struct filter_context *filter_ctx)
{
	int ret;
	struct stream_size_table tab;
	struct wim_lookup_table_entry *lte;

	ret = init_stream_size_table(&tab, 9001);
	if (ret)
		return ret;

	if (may_hard_filter_streams(filter_ctx)) {
		struct insert_other_if_hard_filtered_ctx ctx = {
			.tab = &tab,
			.filter_ctx = filter_ctx,
		};
		for_lookup_table_entry(lt, insert_other_if_hard_filtered, &ctx);
	}

	list_for_each_entry(lte, stream_list, write_streams_list)
		stream_size_table_insert(lte, &tab);

	destroy_stream_size_table(&tab);
	return 0;
}

static void
filter_stream_list_for_write(struct list_head *stream_list,
			     struct filter_context *filter_ctx)
{
	struct wim_lookup_table_entry *lte, *tmp;

	list_for_each_entry_safe(lte, tmp,
				 stream_list, write_streams_list)
	{
		int status = stream_filtered(lte, filter_ctx);

		if (status == 0) {
			/* Not filtered.  */
			continue;
		} else {
			if (status > 0) {
				/* Soft filtered.  */
			} else {
				/* Hard filtered.  */
				lte->will_be_in_output_wim = 0;
				list_del(&lte->lookup_table_list);
			}
			list_del(&lte->write_streams_list);
		}
	}
}

/*
 * prepare_stream_list_for_write() -
 *
 * Prepare the list of streams to write for writing a WIM containing the
 * specified image(s) with the specified write flags.
 *
 * @wim
 *	The WIMStruct on whose behalf the write is occurring.
 *
 * @image
 *	Image(s) from the WIM to write; may be WIMLIB_ALL_IMAGES.
 *
 * @write_flags
 *	WIMLIB_WRITE_FLAG_* flags for the write operation:
 *
 *	STREAMS_OK:  For writes of all images, assume that all streams in the
 *	lookup table of @wim and the per-image lists of unhashed streams should
 *	be taken as-is, and image metadata should not be searched for
 *	references.  This does not exclude filtering with OVERWRITE and
 *	SKIP_EXTERNAL_WIMS, below.
 *
 *	OVERWRITE:  Streams already present in @wim shall not be returned in
 *	@stream_list_ret.
 *
 *	SKIP_EXTERNAL_WIMS:  Streams already present in a WIM file, but not
 *	@wim, shall be returned in neither @stream_list_ret nor
 *	@lookup_table_list_ret.
 *
 * @stream_list_ret
 *	List of streams, linked by write_streams_list, that need to be written
 *	will be returned here.
 *
 *	Note that this function assumes that unhashed streams will be written;
 *	it does not take into account that they may become duplicates when
 *	actually hashed.
 *
 * @lookup_table_list_ret
 *	List of streams, linked by lookup_table_list, that need to be included
 *	in the WIM's lookup table will be returned here.  This will be a
 *	superset of the streams in @stream_list_ret.
 *
 *	This list will be a proper superset of @stream_list_ret if and only if
 *	WIMLIB_WRITE_FLAG_OVERWRITE was specified in @write_flags and some of
 *	the streams that would otherwise need to be written were already located
 *	in the WIM file.
 *
 *	All streams in this list will have @out_refcnt set to the number of
 *	references to the stream in the output WIM.  If
 *	WIMLIB_WRITE_FLAG_STREAMS_OK was specified in @write_flags, @out_refcnt
 *	may be as low as 0.
 *
 * @filter_ctx_ret
 *	A context for queries of stream filter status with stream_filtered() is
 *	returned in this location.
 *
 * In addition, @will_be_in_output_wim will be set to 1 in all stream entries
 * inserted into @lookup_table_list_ret and to 0 in all stream entries in the
 * lookup table of @wim not inserted into @lookup_table_list_ret.
 *
 * Still furthermore, @unique_size will be set to 1 on all stream entries in
 * @stream_list_ret that have unique size among all stream entries in
 * @stream_list_ret and among all stream entries in the lookup table of @wim
 * that are ineligible for being written due to filtering.
 *
 * Returns 0 on success; nonzero on read error, memory allocation error, or
 * otherwise.
 */
static int
prepare_stream_list_for_write(WIMStruct *wim, int image,
			      int write_flags,
			      struct list_head *stream_list_ret,
			      struct list_head *lookup_table_list_ret,
			      struct filter_context *filter_ctx_ret)
{
	int ret;
	struct wim_lookup_table_entry *lte;

	filter_ctx_ret->write_flags = write_flags;
	filter_ctx_ret->wim = wim;

	ret = prepare_unfiltered_list_of_streams_in_output_wim(
				wim,
				image,
				write_flags & WIMLIB_WRITE_FLAG_STREAMS_OK,
				stream_list_ret);
	if (ret)
		return ret;

	INIT_LIST_HEAD(lookup_table_list_ret);
	list_for_each_entry(lte, stream_list_ret, write_streams_list)
		list_add_tail(&lte->lookup_table_list, lookup_table_list_ret);

	ret = determine_stream_size_uniquity(stream_list_ret, wim->lookup_table,
					     filter_ctx_ret);
	if (ret)
		return ret;

	if (may_filter_streams(filter_ctx_ret))
		filter_stream_list_for_write(stream_list_ret, filter_ctx_ret);

	return 0;
}

static int
write_wim_streams(WIMStruct *wim, int image, int write_flags,
		  unsigned num_threads,
		  struct list_head *stream_list_override,
		  struct list_head *lookup_table_list_ret)
{
	int ret;
	struct list_head _stream_list;
	struct list_head *stream_list;
	struct wim_lookup_table_entry *lte;
	struct filter_context _filter_ctx;
	struct filter_context *filter_ctx;

	if (stream_list_override == NULL) {
		/* Normal case: prepare stream list from image(s) being written.
		 */
		stream_list = &_stream_list;
		filter_ctx = &_filter_ctx;
		ret = prepare_stream_list_for_write(wim, image, write_flags,
						    stream_list,
						    lookup_table_list_ret,
						    filter_ctx);
		if (ret)
			return ret;
	} else {
		/* Currently only as a result of wimlib_split() being called:
		 * use stream list already explicitly provided.  Use existing
		 * reference counts.  */
		stream_list = stream_list_override;
		filter_ctx = NULL;
		INIT_LIST_HEAD(lookup_table_list_ret);
		list_for_each_entry(lte, stream_list, write_streams_list) {
			lte->out_refcnt = lte->refcnt;
			lte->will_be_in_output_wim = 1;
			lte->unique_size = 0;
			list_add_tail(&lte->lookup_table_list, lookup_table_list_ret);
		}
	}

	return wim_write_stream_list(wim,
				     stream_list,
				     write_flags,
				     num_threads,
				     filter_ctx);
}

static int
write_wim_metadata_resources(WIMStruct *wim, int image, int write_flags)
{
	int ret;
	int start_image;
	int end_image;
	int write_resource_flags;

	if (write_flags & WIMLIB_WRITE_FLAG_NO_METADATA) {
		DEBUG("Not writing any metadata resources.");
		return 0;
	}

	write_resource_flags = write_flags_to_resource_flags(write_flags);

	write_resource_flags &= ~WRITE_RESOURCE_FLAG_SOLID;

	DEBUG("Writing metadata resources (offset=%"PRIu64")",
	      wim->out_fd.offset);

	ret = call_progress(wim->progfunc,
			    WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN,
			    NULL, wim->progctx);
	if (ret)
		return ret;

	if (image == WIMLIB_ALL_IMAGES) {
		start_image = 1;
		end_image = wim->hdr.image_count;
	} else {
		start_image = image;
		end_image = image;
	}

	for (int i = start_image; i <= end_image; i++) {
		struct wim_image_metadata *imd;

		imd = wim->image_metadata[i - 1];
		/* Build a new metadata resource only if image was modified from
		 * the original (or was newly added).  Otherwise just copy the
		 * existing one.  */
		if (imd->modified) {
			DEBUG("Image %u was modified; building and writing new "
			      "metadata resource", i);
			ret = write_metadata_resource(wim, i,
						      write_resource_flags);
		} else if (write_flags & WIMLIB_WRITE_FLAG_OVERWRITE) {
			DEBUG("Image %u was not modified; re-using existing "
			      "metadata resource.", i);
			stream_set_out_reshdr_for_reuse(imd->metadata_lte);
			ret = 0;
		} else {
			DEBUG("Image %u was not modified; copying existing "
			      "metadata resource.", i);
			ret = write_wim_resource(imd->metadata_lte,
						 &wim->out_fd,
						 wim->out_compression_type,
						 wim->out_chunk_size,
						 write_resource_flags);
		}
		if (ret)
			return ret;
	}

	return call_progress(wim->progfunc,
			     WIMLIB_PROGRESS_MSG_WRITE_METADATA_END,
			     NULL, wim->progctx);
}

static int
open_wim_writable(WIMStruct *wim, const tchar *path, int open_flags)
{
	int raw_fd;
	DEBUG("Opening \"%"TS"\" for writing.", path);

	raw_fd = topen(path, open_flags | O_BINARY, 0644);
	if (raw_fd < 0) {
		ERROR_WITH_ERRNO("Failed to open \"%"TS"\" for writing", path);
		return WIMLIB_ERR_OPEN;
	}
	filedes_init(&wim->out_fd, raw_fd);
	return 0;
}

static int
close_wim_writable(WIMStruct *wim, int write_flags)
{
	int ret = 0;

	if (!(write_flags & WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR)) {
		DEBUG("Closing WIM file.");
		if (filedes_valid(&wim->out_fd))
			if (filedes_close(&wim->out_fd))
				ret = WIMLIB_ERR_WRITE;
	}
	filedes_invalidate(&wim->out_fd);
	return ret;
}

static int
cmp_streams_by_out_rspec(const void *p1, const void *p2)
{
	const struct wim_lookup_table_entry *lte1, *lte2;

	lte1 = *(const struct wim_lookup_table_entry**)p1;
	lte2 = *(const struct wim_lookup_table_entry**)p2;

	if (lte1->out_reshdr.flags & WIM_RESHDR_FLAG_SOLID) {
		if (lte2->out_reshdr.flags & WIM_RESHDR_FLAG_SOLID) {
			if (lte1->out_res_offset_in_wim != lte2->out_res_offset_in_wim)
				return cmp_u64(lte1->out_res_offset_in_wim,
					       lte2->out_res_offset_in_wim);
		} else {
			return 1;
		}
	} else {
		if (lte2->out_reshdr.flags & WIM_RESHDR_FLAG_SOLID)
			return -1;
	}
	return cmp_u64(lte1->out_reshdr.offset_in_wim,
		       lte2->out_reshdr.offset_in_wim);
}

static int
write_wim_lookup_table(WIMStruct *wim, int image, int write_flags,
		       struct wim_reshdr *out_reshdr,
		       struct list_head *lookup_table_list)
{
	int ret;

	/* Set output resource metadata for streams already present in WIM.  */
	if (write_flags & WIMLIB_WRITE_FLAG_OVERWRITE) {
		struct wim_lookup_table_entry *lte;
		list_for_each_entry(lte, lookup_table_list, lookup_table_list)
		{
			if (lte->resource_location == RESOURCE_IN_WIM &&
			    lte->rspec->wim == wim)
			{
				stream_set_out_reshdr_for_reuse(lte);
			}
		}
	}

	ret = sort_stream_list(lookup_table_list,
			       offsetof(struct wim_lookup_table_entry, lookup_table_list),
			       cmp_streams_by_out_rspec);
	if (ret)
		return ret;

	/* Add entries for metadata resources.  */
	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_METADATA)) {
		int start_image;
		int end_image;

		if (image == WIMLIB_ALL_IMAGES) {
			start_image = 1;
			end_image = wim->hdr.image_count;
		} else {
			start_image = image;
			end_image = image;
		}

		/* Push metadata resource lookup table entries onto the front of
		 * the list in reverse order, so that they're written in order.
		 */
		for (int i = end_image; i >= start_image; i--) {
			struct wim_lookup_table_entry *metadata_lte;

			metadata_lte = wim->image_metadata[i - 1]->metadata_lte;
			wimlib_assert(metadata_lte->out_reshdr.flags & WIM_RESHDR_FLAG_METADATA);
			metadata_lte->out_refcnt = 1;
			list_add(&metadata_lte->lookup_table_list, lookup_table_list);
		}
	}

	return write_wim_lookup_table_from_stream_list(lookup_table_list,
						       &wim->out_fd,
						       wim->hdr.part_number,
						       out_reshdr,
						       write_flags_to_resource_flags(write_flags));
}

/*
 * finish_write():
 *
 * Finish writing a WIM file: write the lookup table, xml data, and integrity
 * table, then overwrite the WIM header.  By default, closes the WIM file
 * descriptor (@wim->out_fd) if successful.
 *
 * write_flags is a bitwise OR of the following:
 *
 *	(public) WIMLIB_WRITE_FLAG_CHECK_INTEGRITY:
 *		Include an integrity table.
 *
 *	(public) WIMLIB_WRITE_FLAG_FSYNC:
 *		fsync() the output file before closing it.
 *
 *	(public) WIMLIB_WRITE_FLAG_PIPABLE:
 *		Writing a pipable WIM, possibly to a pipe; include pipable WIM
 *		stream headers before the lookup table and XML data, and also
 *		write the WIM header at the end instead of seeking to the
 *		beginning.  Can't be combined with
 *		WIMLIB_WRITE_FLAG_CHECK_INTEGRITY.
 *
 *	(private) WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE:
 *		Don't write the lookup table.
 *
 *	(private) WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML:
 *		After writing the XML data but before writing the integrity
 *		table, write a temporary WIM header and flush the stream so that
 *		the WIM is less likely to become corrupted upon abrupt program
 *		termination.
 *	(private) WIMLIB_WRITE_FLAG_HEADER_AT_END:
 *		Instead of overwriting the WIM header at the beginning of the
 *		file, simply append it to the end of the file.  (Used when
 *		writing to pipe.)
 *	(private) WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR:
 *		Do not close the file descriptor @wim->out_fd on either success
 *		on failure.
 *	(private) WIMLIB_WRITE_FLAG_USE_EXISTING_TOTALBYTES:
 *		Use the existing <TOTALBYTES> stored in the in-memory XML
 *		information, rather than setting it to the offset of the XML
 *		data being written.
 *	(private) WIMLIB_WRITE_FLAG_OVERWRITE
 *		The existing WIM file is being updated in-place.  The entries
 *		from its integrity table may be re-used.
 */
static int
finish_write(WIMStruct *wim, int image, int write_flags,
	     struct list_head *lookup_table_list)
{
	int ret;
	off_t hdr_offset;
	int write_resource_flags;
	off_t old_lookup_table_end = 0;
	off_t new_lookup_table_end;
	u64 xml_totalbytes;
	struct integrity_table *old_integrity_table = NULL;

	DEBUG("image=%d, write_flags=%08x", image, write_flags);

	write_resource_flags = write_flags_to_resource_flags(write_flags);

	/* In the WIM header, there is room for the resource entry for a
	 * metadata resource labeled as the "boot metadata".  This entry should
	 * be zeroed out if there is no bootable image (boot_idx 0).  Otherwise,
	 * it should be a copy of the resource entry for the image that is
	 * marked as bootable.  This is not well documented...  */
	if (wim->hdr.boot_idx == 0) {
		zero_reshdr(&wim->hdr.boot_metadata_reshdr);
	} else {
		copy_reshdr(&wim->hdr.boot_metadata_reshdr,
			    &wim->image_metadata[
				wim->hdr.boot_idx - 1]->metadata_lte->out_reshdr);
	}

	/* If overwriting the WIM file containing an integrity table in-place,
	 * we'd like to re-use the information in the old integrity table
	 * instead of recalculating it.  But we might overwrite the old
	 * integrity table when we expand the XML data.  Read it into memory
	 * just in case.  */
	if ((write_flags & (WIMLIB_WRITE_FLAG_OVERWRITE |
			    WIMLIB_WRITE_FLAG_CHECK_INTEGRITY)) ==
		(WIMLIB_WRITE_FLAG_OVERWRITE |
		 WIMLIB_WRITE_FLAG_CHECK_INTEGRITY)
	    && wim_has_integrity_table(wim))
	{
		old_lookup_table_end = wim->hdr.lookup_table_reshdr.offset_in_wim +
				       wim->hdr.lookup_table_reshdr.size_in_wim;
		(void)read_integrity_table(wim,
					   old_lookup_table_end - WIM_HEADER_DISK_SIZE,
					   &old_integrity_table);
		/* If we couldn't read the old integrity table, we can still
		 * re-calculate the full integrity table ourselves.  Hence the
		 * ignoring of the return value.  */
	}

	/* Write lookup table.  */
	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE)) {
		ret = write_wim_lookup_table(wim, image, write_flags,
					     &wim->hdr.lookup_table_reshdr,
					     lookup_table_list);
		if (ret) {
			free_integrity_table(old_integrity_table);
			return ret;
		}
	}

	/* Write XML data.  */
	xml_totalbytes = wim->out_fd.offset;
	if (write_flags & WIMLIB_WRITE_FLAG_USE_EXISTING_TOTALBYTES)
		xml_totalbytes = WIM_TOTALBYTES_USE_EXISTING;
	ret = write_wim_xml_data(wim, image, xml_totalbytes,
				 &wim->hdr.xml_data_reshdr,
				 write_resource_flags);
	if (ret) {
		free_integrity_table(old_integrity_table);
		return ret;
	}

	/* Write integrity table (optional).  */
	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
		if (write_flags & WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML) {
			struct wim_header checkpoint_hdr;
			memcpy(&checkpoint_hdr, &wim->hdr, sizeof(struct wim_header));
			zero_reshdr(&checkpoint_hdr.integrity_table_reshdr);
			checkpoint_hdr.flags |= WIM_HDR_FLAG_WRITE_IN_PROGRESS;
			ret = write_wim_header_at_offset(&checkpoint_hdr,
							 &wim->out_fd, 0);
			if (ret) {
				free_integrity_table(old_integrity_table);
				return ret;
			}
		}

		new_lookup_table_end = wim->hdr.lookup_table_reshdr.offset_in_wim +
				       wim->hdr.lookup_table_reshdr.size_in_wim;

		ret = write_integrity_table(wim,
					    new_lookup_table_end,
					    old_lookup_table_end,
					    old_integrity_table);
		free_integrity_table(old_integrity_table);
		if (ret)
			return ret;
	} else {
		/* No integrity table.  */
		zero_reshdr(&wim->hdr.integrity_table_reshdr);
	}

	/* Now that all information in the WIM header has been determined, the
	 * preliminary header written earlier can be overwritten, the header of
	 * the existing WIM file can be overwritten, or the final header can be
	 * written to the end of the pipable WIM.  */
	wim->hdr.flags &= ~WIM_HDR_FLAG_WRITE_IN_PROGRESS;
	hdr_offset = 0;
	if (write_flags & WIMLIB_WRITE_FLAG_HEADER_AT_END)
		hdr_offset = wim->out_fd.offset;
	DEBUG("Writing new header @ %"PRIu64".", hdr_offset);
	ret = write_wim_header_at_offset(&wim->hdr, &wim->out_fd, hdr_offset);
	if (ret)
		return ret;

	/* Possibly sync file data to disk before closing.  On POSIX systems, it
	 * is necessary to do this before using rename() to overwrite an
	 * existing file with a new file.  Otherwise, data loss would occur if
	 * the system is abruptly terminated when the metadata for the rename
	 * operation has been written to disk, but the new file data has not.
	 */
	if (write_flags & WIMLIB_WRITE_FLAG_FSYNC) {
		DEBUG("Syncing WIM file.");
		if (fsync(wim->out_fd.fd)) {
			ERROR_WITH_ERRNO("Error syncing data to WIM file");
			return WIMLIB_ERR_WRITE;
		}
	}

	if (close_wim_writable(wim, write_flags)) {
		ERROR_WITH_ERRNO("Failed to close the output WIM file");
		return WIMLIB_ERR_WRITE;
	}

	return 0;
}

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)

/* Set advisory lock on WIM file (if not already done so)  */
int
lock_wim_for_append(WIMStruct *wim)
{
	if (wim->locked_for_append)
		return 0;
	if (!flock(wim->in_fd.fd, LOCK_EX | LOCK_NB)) {
		wim->locked_for_append = 1;
		return 0;
	}
	if (errno != EWOULDBLOCK)
		return 0;
	return WIMLIB_ERR_ALREADY_LOCKED;
}

/* Remove advisory lock on WIM file (if present)  */
void
unlock_wim_for_append(WIMStruct *wim)
{
	if (wim->locked_for_append) {
		flock(wim->in_fd.fd, LOCK_UN);
		wim->locked_for_append = 0;
	}
}
#endif

/*
 * write_pipable_wim():
 *
 * Perform the intermediate stages of creating a "pipable" WIM (i.e. a WIM
 * capable of being applied from a pipe).
 *
 * Pipable WIMs are a wimlib-specific modification of the WIM format such that
 * images can be applied from them sequentially when the file data is sent over
 * a pipe.  In addition, a pipable WIM can be written sequentially to a pipe.
 * The modifications made to the WIM format for pipable WIMs are:
 *
 * - Magic characters in header are "WLPWM\0\0\0" (wimlib pipable WIM) instead
 *   of "MSWIM\0\0\0".  This lets wimlib know that the WIM is pipable and also
 *   stops other software from trying to read the file as a normal WIM.
 *
 * - The header at the beginning of the file does not contain all the normal
 *   information; in particular it will have all 0's for the lookup table and
 *   XML data resource entries.  This is because this information cannot be
 *   determined until the lookup table and XML data have been written.
 *   Consequently, wimlib will write the full header at the very end of the
 *   file.  The header at the end, however, is only used when reading the WIM
 *   from a seekable file (not a pipe).
 *
 * - An extra copy of the XML data is placed directly after the header.  This
 *   allows image names and sizes to be determined at an appropriate time when
 *   reading the WIM from a pipe.  This copy of the XML data is ignored if the
 *   WIM is read from a seekable file (not a pipe).
 *
 * - The format of resources, or streams, has been modified to allow them to be
 *   used before the "lookup table" has been read.  Each stream is prefixed with
 *   a `struct pwm_stream_hdr' that is basically an abbreviated form of `struct
 *   wim_lookup_table_entry_disk' that only contains the SHA1 message digest,
 *   uncompressed stream size, and flags that indicate whether the stream is
 *   compressed.  The data of uncompressed streams then follows literally, while
 *   the data of compressed streams follows in a modified format.  Compressed
 *   streams do not begin with a chunk table, since the chunk table cannot be
 *   written until all chunks have been compressed.  Instead, each compressed
 *   chunk is prefixed by a `struct pwm_chunk_hdr' that gives its size.
 *   Furthermore, the chunk table is written at the end of the resource instead
 *   of the start.  Note: chunk offsets are given in the chunk table as if the
 *   `struct pwm_chunk_hdr's were not present; also, the chunk table is only
 *   used if the WIM is being read from a seekable file (not a pipe).
 *
 * - Metadata resources always come before other file resources (streams).
 *   (This does not by itself constitute an incompatibility with normal WIMs,
 *   since this is valid in normal WIMs.)
 *
 * - At least up to the end of the file resources, all components must be packed
 *   as tightly as possible; there cannot be any "holes" in the WIM.  (This does
 *   not by itself consititute an incompatibility with normal WIMs, since this
 *   is valid in normal WIMs.)
 *
 * Note: the lookup table, XML data, and header at the end are not used when
 * applying from a pipe.  They exist to support functionality such as image
 * application and export when the WIM is *not* read from a pipe.
 *
 *   Layout of pipable WIM:
 *
 * ---------+----------+--------------------+----------------+--------------+-----------+--------+
 * | Header | XML data | Metadata resources | File resources | Lookup table | XML data  | Header |
 * ---------+----------+--------------------+----------------+--------------+-----------+--------+
 *
 *   Layout of normal WIM:
 *
 * +--------+-----------------------------+-------------------------+
 * | Header | File and metadata resources | Lookup table | XML data |
 * +--------+-----------------------------+-------------------------+
 *
 * An optional integrity table can follow the final XML data in both normal and
 * pipable WIMs.  However, due to implementation details, wimlib currently can
 * only include an integrity table in a pipable WIM when writing it to a
 * seekable file (not a pipe).
 *
 * Do note that since pipable WIMs are not supported by Microsoft's software,
 * wimlib does not create them unless explicitly requested (with
 * WIMLIB_WRITE_FLAG_PIPABLE) and as stated above they use different magic
 * characters to identify the file.
 */
static int
write_pipable_wim(WIMStruct *wim, int image, int write_flags,
		  unsigned num_threads,
		  struct list_head *stream_list_override,
		  struct list_head *lookup_table_list_ret)
{
	int ret;
	struct wim_reshdr xml_reshdr;

	WARNING("Creating a pipable WIM, which will "
		"be incompatible\n"
		"          with Microsoft's software (wimgapi/imagex/Dism).");

	/* At this point, the header at the beginning of the file has already
	 * been written.  */

	/* For efficiency, when wimlib adds an image to the WIM with
	 * wimlib_add_image(), the SHA1 message digests of files is not
	 * calculated; instead, they are calculated while the files are being
	 * written.  However, this does not work when writing a pipable WIM,
	 * since when writing a stream to a pipable WIM, its SHA1 message digest
	 * needs to be known before the stream data is written.  Therefore,
	 * before getting much farther, we need to pre-calculate the SHA1
	 * message digests of all streams that will be written.  */
	ret = wim_checksum_unhashed_streams(wim);
	if (ret)
		return ret;

	/* Write extra copy of the XML data.  */
	ret = write_wim_xml_data(wim, image, WIM_TOTALBYTES_OMIT,
				 &xml_reshdr,
				 WRITE_RESOURCE_FLAG_PIPABLE);
	if (ret)
		return ret;

	/* Write metadata resources for the image(s) being included in the
	 * output WIM.  */
	ret = write_wim_metadata_resources(wim, image, write_flags);
	if (ret)
		return ret;

	/* Write streams needed for the image(s) being included in the output
	 * WIM, or streams needed for the split WIM part.  */
	return write_wim_streams(wim, image, write_flags, num_threads,
				 stream_list_override, lookup_table_list_ret);

	/* The lookup table, XML data, and header at end are handled by
	 * finish_write().  */
}

/* Write a standalone WIM or split WIM (SWM) part to a new file or to a file
 * descriptor.  */
int
write_wim_part(WIMStruct *wim,
	       const void *path_or_fd,
	       int image,
	       int write_flags,
	       unsigned num_threads,
	       unsigned part_number,
	       unsigned total_parts,
	       struct list_head *stream_list_override,
	       const u8 *guid)
{
	int ret;
	struct wim_header hdr_save;
	struct list_head lookup_table_list;

	if (total_parts == 1)
		DEBUG("Writing standalone WIM.");
	else
		DEBUG("Writing split WIM part %u/%u", part_number, total_parts);
	if (image == WIMLIB_ALL_IMAGES)
		DEBUG("Including all images.");
	else
		DEBUG("Including image %d only.", image);
	if (write_flags & WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR)
		DEBUG("File descriptor: %d", *(const int*)path_or_fd);
	else
		DEBUG("Path: \"%"TS"\"", (const tchar*)path_or_fd);
	DEBUG("Write flags: 0x%08x", write_flags);

	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY)
		DEBUG("\tCHECK_INTEGRITY");

	if (write_flags & WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY)
		DEBUG("\tNO_CHECK_INTEGRITY");

	if (write_flags & WIMLIB_WRITE_FLAG_PIPABLE)
		DEBUG("\tPIPABLE");

	if (write_flags & WIMLIB_WRITE_FLAG_NOT_PIPABLE)
		DEBUG("\tNOT_PIPABLE");

	if (write_flags & WIMLIB_WRITE_FLAG_RECOMPRESS)
		DEBUG("\tRECOMPRESS");

	if (write_flags & WIMLIB_WRITE_FLAG_FSYNC)
		DEBUG("\tFSYNC");

	if (write_flags & WIMLIB_WRITE_FLAG_REBUILD)
		DEBUG("\tREBUILD");

	if (write_flags & WIMLIB_WRITE_FLAG_SOFT_DELETE)
		DEBUG("\tSOFT_DELETE");

	if (write_flags & WIMLIB_WRITE_FLAG_IGNORE_READONLY_FLAG)
		DEBUG("\tIGNORE_READONLY_FLAG");

	if (write_flags & WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS)
		DEBUG("\tSKIP_EXTERNAL_WIMS");

	if (write_flags & WIMLIB_WRITE_FLAG_STREAMS_OK)
		DEBUG("\tSTREAMS_OK");

	if (write_flags & WIMLIB_WRITE_FLAG_RETAIN_GUID)
		DEBUG("\tRETAIN_GUID");

	if (write_flags & WIMLIB_WRITE_FLAG_SOLID)
		DEBUG("\tSOLID");

	if (write_flags & WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR)
		DEBUG("\tFILE_DESCRIPTOR");

	if (write_flags & WIMLIB_WRITE_FLAG_NO_METADATA)
		DEBUG("\tNO_METADATA");

	if (write_flags & WIMLIB_WRITE_FLAG_USE_EXISTING_TOTALBYTES)
		DEBUG("\tUSE_EXISTING_TOTALBYTES");

	if (num_threads == 0)
		DEBUG("Number of threads: autodetect");
	else
		DEBUG("Number of threads: %u", num_threads);
	DEBUG("Progress function: %s", (wim->progfunc ? "yes" : "no"));
	DEBUG("Stream list:       %s", (stream_list_override ? "specified" : "autodetect"));
	DEBUG("GUID:              %s", (write_flags &
					WIMLIB_WRITE_FLAG_RETAIN_GUID) ? "retain"
						: guid ? "explicit" : "generate new");

	/* Internally, this is always called with a valid part number and total
	 * parts.  */
	wimlib_assert(total_parts >= 1);
	wimlib_assert(part_number >= 1 && part_number <= total_parts);

	/* A valid image (or all images) must be specified.  */
	if (image != WIMLIB_ALL_IMAGES &&
	     (image < 1 || image > wim->hdr.image_count))
		return WIMLIB_ERR_INVALID_IMAGE;

	/* If we need to write metadata resources, make sure the ::WIMStruct has
	 * the needed information attached (e.g. is not a resource-only WIM,
	 * such as a non-first part of a split WIM).  */
	if (!wim_has_metadata(wim) &&
	    !(write_flags & WIMLIB_WRITE_FLAG_NO_METADATA))
		return WIMLIB_ERR_METADATA_NOT_FOUND;

	/* Check for contradictory flags.  */
	if ((write_flags & (WIMLIB_WRITE_FLAG_CHECK_INTEGRITY |
			    WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY))
				== (WIMLIB_WRITE_FLAG_CHECK_INTEGRITY |
				    WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY))
		return WIMLIB_ERR_INVALID_PARAM;

	if ((write_flags & (WIMLIB_WRITE_FLAG_PIPABLE |
			    WIMLIB_WRITE_FLAG_NOT_PIPABLE))
				== (WIMLIB_WRITE_FLAG_PIPABLE |
				    WIMLIB_WRITE_FLAG_NOT_PIPABLE))
		return WIMLIB_ERR_INVALID_PARAM;

	/* Save previous header, then start initializing the new one.  */
	memcpy(&hdr_save, &wim->hdr, sizeof(struct wim_header));

	/* Set default integrity, pipable, and solid flags.  */
	if (!(write_flags & (WIMLIB_WRITE_FLAG_PIPABLE |
			     WIMLIB_WRITE_FLAG_NOT_PIPABLE)))
		if (wim_is_pipable(wim)) {
			DEBUG("WIM is pipable; default to PIPABLE.");
			write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;
		}

	if (!(write_flags & (WIMLIB_WRITE_FLAG_CHECK_INTEGRITY |
			     WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY)))
		if (wim_has_integrity_table(wim)) {
			DEBUG("Integrity table present; default to CHECK_INTEGRITY.");
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;
		}

	if ((write_flags & (WIMLIB_WRITE_FLAG_PIPABLE |
			    WIMLIB_WRITE_FLAG_SOLID))
				    == (WIMLIB_WRITE_FLAG_PIPABLE |
					WIMLIB_WRITE_FLAG_SOLID))
	{
		ERROR("Cannot specify both PIPABLE and SOLID!");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	/* Set appropriate magic number.  */
	if (write_flags & WIMLIB_WRITE_FLAG_PIPABLE)
		wim->hdr.magic = PWM_MAGIC;
	else
		wim->hdr.magic = WIM_MAGIC;

	/* Set appropriate version number.  */
	if ((write_flags & WIMLIB_WRITE_FLAG_SOLID) ||
	    wim->out_compression_type == WIMLIB_COMPRESSION_TYPE_LZMS)
		wim->hdr.wim_version = WIM_VERSION_SOLID;
	else
		wim->hdr.wim_version = WIM_VERSION_DEFAULT;

	/* Clear header flags that will be set automatically.  */
	wim->hdr.flags &= ~(WIM_HDR_FLAG_METADATA_ONLY		|
			    WIM_HDR_FLAG_RESOURCE_ONLY		|
			    WIM_HDR_FLAG_SPANNED		|
			    WIM_HDR_FLAG_WRITE_IN_PROGRESS);

	/* Set SPANNED header flag if writing part of a split WIM.  */
	if (total_parts != 1)
		wim->hdr.flags |= WIM_HDR_FLAG_SPANNED;

	/* Set part number and total parts of split WIM.  This will be 1 and 1
	 * if the WIM is standalone.  */
	wim->hdr.part_number = part_number;
	wim->hdr.total_parts = total_parts;

	/* Set compression type if different.  */
	if (wim->compression_type != wim->out_compression_type) {
		ret = set_wim_hdr_cflags(wim->out_compression_type, &wim->hdr);
		wimlib_assert(ret == 0);
	}

	/* Set chunk size if different.  */
	wim->hdr.chunk_size = wim->out_chunk_size;

	/* Set GUID.  */
	if (!(write_flags & WIMLIB_WRITE_FLAG_RETAIN_GUID)) {
		if (guid)
			memcpy(wim->hdr.guid, guid, WIMLIB_GUID_LEN);
		else
			randomize_byte_array(wim->hdr.guid, WIMLIB_GUID_LEN);
	}

	/* Clear references to resources that have not been written yet.  */
	zero_reshdr(&wim->hdr.lookup_table_reshdr);
	zero_reshdr(&wim->hdr.xml_data_reshdr);
	zero_reshdr(&wim->hdr.boot_metadata_reshdr);
	zero_reshdr(&wim->hdr.integrity_table_reshdr);

	/* Set image count and boot index correctly for single image writes.  */
	if (image != WIMLIB_ALL_IMAGES) {
		wim->hdr.image_count = 1;
		if (wim->hdr.boot_idx == image)
			wim->hdr.boot_idx = 1;
		else
			wim->hdr.boot_idx = 0;
	}

	/* Split WIMs can't be bootable.  */
	if (total_parts != 1)
		wim->hdr.boot_idx = 0;

	/* Initialize output file descriptor.  */
	if (write_flags & WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR) {
		/* File descriptor was explicitly provided.  Return error if
		 * file descriptor is not seekable, unless writing a pipable WIM
		 * was requested.  */
		wim->out_fd.fd = *(const int*)path_or_fd;
		wim->out_fd.offset = 0;
		if (!filedes_is_seekable(&wim->out_fd)) {
			ret = WIMLIB_ERR_INVALID_PARAM;
			if (!(write_flags & WIMLIB_WRITE_FLAG_PIPABLE))
				goto out_restore_hdr;
			if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
				ERROR("Can't include integrity check when "
				      "writing pipable WIM to pipe!");
				goto out_restore_hdr;
			}
		}

	} else {
		/* Filename of WIM to write was provided; open file descriptor
		 * to it.  */
		ret = open_wim_writable(wim, (const tchar*)path_or_fd,
					O_TRUNC | O_CREAT | O_RDWR);
		if (ret)
			goto out_restore_hdr;
	}

	/* Write initial header.  This is merely a "dummy" header since it
	 * doesn't have all the information yet, so it will be overwritten later
	 * (unless writing a pipable WIM).  */
	if (!(write_flags & WIMLIB_WRITE_FLAG_PIPABLE))
		wim->hdr.flags |= WIM_HDR_FLAG_WRITE_IN_PROGRESS;
	ret = write_wim_header(&wim->hdr, &wim->out_fd);
	wim->hdr.flags &= ~WIM_HDR_FLAG_WRITE_IN_PROGRESS;
	if (ret)
		goto out_restore_hdr;

	/* Write metadata resources and streams.  */
	if (!(write_flags & WIMLIB_WRITE_FLAG_PIPABLE)) {
		/* Default case: create a normal (non-pipable) WIM.  */
		ret = write_wim_streams(wim, image, write_flags, num_threads,
					stream_list_override,
					&lookup_table_list);
		if (ret)
			goto out_restore_hdr;

		ret = write_wim_metadata_resources(wim, image, write_flags);
		if (ret)
			goto out_restore_hdr;
	} else {
		/* Non-default case: create pipable WIM.  */
		ret = write_pipable_wim(wim, image, write_flags, num_threads,
					stream_list_override,
					&lookup_table_list);
		if (ret)
			goto out_restore_hdr;
		write_flags |= WIMLIB_WRITE_FLAG_HEADER_AT_END;
	}


	/* Write lookup table, XML data, and (optional) integrity table.  */
	ret = finish_write(wim, image, write_flags, &lookup_table_list);
out_restore_hdr:
	memcpy(&wim->hdr, &hdr_save, sizeof(struct wim_header));
	(void)close_wim_writable(wim, write_flags);
	DEBUG("ret=%d", ret);
	return ret;
}

/* Write a standalone WIM to a file or file descriptor.  */
static int
write_standalone_wim(WIMStruct *wim, const void *path_or_fd,
		     int image, int write_flags, unsigned num_threads)
{
	return write_wim_part(wim, path_or_fd, image, write_flags,
			      num_threads, 1, 1, NULL, NULL);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_write(WIMStruct *wim, const tchar *path,
	     int image, int write_flags, unsigned num_threads)
{
	if (write_flags & ~WIMLIB_WRITE_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;

	if (path == NULL || path[0] == T('\0'))
		return WIMLIB_ERR_INVALID_PARAM;

	return write_standalone_wim(wim, path, image, write_flags, num_threads);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_write_to_fd(WIMStruct *wim, int fd,
		   int image, int write_flags, unsigned num_threads)
{
	if (write_flags & ~WIMLIB_WRITE_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;

	if (fd < 0)
		return WIMLIB_ERR_INVALID_PARAM;

	write_flags |= WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR;

	return write_standalone_wim(wim, &fd, image, write_flags, num_threads);
}

static bool
any_images_modified(WIMStruct *wim)
{
	for (int i = 0; i < wim->hdr.image_count; i++)
		if (wim->image_metadata[i]->modified)
			return true;
	return false;
}

static int
check_resource_offset(struct wim_lookup_table_entry *lte, void *_wim)
{
	const WIMStruct *wim = _wim;
	off_t end_offset = *(const off_t*)wim->private;

	if (lte->resource_location == RESOURCE_IN_WIM && lte->rspec->wim == wim &&
	    lte->rspec->offset_in_wim + lte->rspec->size_in_wim > end_offset)
		return WIMLIB_ERR_RESOURCE_ORDER;
	return 0;
}

/* Make sure no file or metadata resources are located after the XML data (or
 * integrity table if present)--- otherwise we can't safely overwrite the WIM in
 * place and we return WIMLIB_ERR_RESOURCE_ORDER.  */
static int
check_resource_offsets(WIMStruct *wim, off_t end_offset)
{
	int ret;
	unsigned i;

	wim->private = &end_offset;
	ret = for_lookup_table_entry(wim->lookup_table, check_resource_offset, wim);
	if (ret)
		return ret;

	for (i = 0; i < wim->hdr.image_count; i++) {
		ret = check_resource_offset(wim->image_metadata[i]->metadata_lte, wim);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Overwrite a WIM, possibly appending streams to it.
 *
 * A WIM looks like (or is supposed to look like) the following:
 *
 *                   Header (212 bytes)
 *                   Streams and metadata resources (variable size)
 *                   Lookup table (variable size)
 *                   XML data (variable size)
 *                   Integrity table (optional) (variable size)
 *
 * If we are not adding any streams or metadata resources, the lookup table is
 * unchanged--- so we only need to overwrite the XML data, integrity table, and
 * header.  This operation is potentially unsafe if the program is abruptly
 * terminated while the XML data or integrity table are being overwritten, but
 * before the new header has been written.  To partially alleviate this problem,
 * a special flag (WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML) is passed to
 * finish_write() to cause a temporary WIM header to be written after the XML
 * data has been written.  This may prevent the WIM from becoming corrupted if
 * the program is terminated while the integrity table is being calculated (but
 * no guarantees, due to write re-ordering...).
 *
 * If we are adding new streams or images (metadata resources), the lookup table
 * needs to be changed, and those streams need to be written.  In this case, we
 * try to perform a safe update of the WIM file by writing the streams *after*
 * the end of the previous WIM, then writing the new lookup table, XML data, and
 * (optionally) integrity table following the new streams.  This will produce a
 * layout like the following:
 *
 *                   Header (212 bytes)
 *                   (OLD) Streams and metadata resources (variable size)
 *                   (OLD) Lookup table (variable size)
 *                   (OLD) XML data (variable size)
 *                   (OLD) Integrity table (optional) (variable size)
 *                   (NEW) Streams and metadata resources (variable size)
 *                   (NEW) Lookup table (variable size)
 *                   (NEW) XML data (variable size)
 *                   (NEW) Integrity table (optional) (variable size)
 *
 * At all points, the WIM is valid as nothing points to the new data yet.  Then,
 * the header is overwritten to point to the new lookup table, XML data, and
 * integrity table, to produce the following layout:
 *
 *                   Header (212 bytes)
 *                   Streams and metadata resources (variable size)
 *                   Nothing (variable size)
 *                   More Streams and metadata resources (variable size)
 *                   Lookup table (variable size)
 *                   XML data (variable size)
 *                   Integrity table (optional) (variable size)
 *
 * This method allows an image to be appended to a large WIM very quickly, and
 * is crash-safe except in the case of write re-ordering, but the
 * disadvantage is that a small hole is left in the WIM where the old lookup
 * table, xml data, and integrity table were.  (These usually only take up a
 * small amount of space compared to the streams, however.)
 */
static int
overwrite_wim_inplace(WIMStruct *wim, int write_flags, unsigned num_threads)
{
	int ret;
	off_t old_wim_end;
	u64 old_lookup_table_end, old_xml_begin, old_xml_end;
	struct wim_header hdr_save;
	struct list_head stream_list;
	struct list_head lookup_table_list;
	struct filter_context filter_ctx;

	DEBUG("Overwriting `%"TS"' in-place", wim->filename);

	/* Save original header so it can be restored in case of error  */
	memcpy(&hdr_save, &wim->hdr, sizeof(struct wim_header));

	/* Set default integrity flag.  */
	if (!(write_flags & (WIMLIB_WRITE_FLAG_CHECK_INTEGRITY |
			     WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY)))
		if (wim_has_integrity_table(wim))
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;

	/* Set WIM version if writing solid resources.  */
	if (write_flags & WIMLIB_WRITE_FLAG_SOLID)
		wim->hdr.wim_version = WIM_VERSION_SOLID;

	/* Set additional flags for overwrite.  */
	write_flags |= WIMLIB_WRITE_FLAG_OVERWRITE |
		       WIMLIB_WRITE_FLAG_STREAMS_OK;

	/* Make sure that the integrity table (if present) is after the XML
	 * data, and that there are no stream resources, metadata resources, or
	 * lookup tables after the XML data.  Otherwise, these data would be
	 * overwritten. */
	old_xml_begin = wim->hdr.xml_data_reshdr.offset_in_wim;
	old_xml_end = old_xml_begin + wim->hdr.xml_data_reshdr.size_in_wim;
	old_lookup_table_end = wim->hdr.lookup_table_reshdr.offset_in_wim +
			       wim->hdr.lookup_table_reshdr.size_in_wim;
	if (wim->hdr.integrity_table_reshdr.offset_in_wim != 0 &&
	    wim->hdr.integrity_table_reshdr.offset_in_wim < old_xml_end) {
		WARNING("Didn't expect the integrity table to be before the XML data");
		ret = WIMLIB_ERR_RESOURCE_ORDER;
		goto out_restore_memory_hdr;
	}

	if (old_lookup_table_end > old_xml_begin) {
		WARNING("Didn't expect the lookup table to be after the XML data");
		ret = WIMLIB_ERR_RESOURCE_ORDER;
		goto out_restore_memory_hdr;
	}

	/* Set @old_wim_end, which indicates the point beyond which we don't
	 * allow any file and metadata resources to appear without returning
	 * WIMLIB_ERR_RESOURCE_ORDER (due to the fact that we would otherwise
	 * overwrite these resources). */
	if (!wim->image_deletion_occurred && !any_images_modified(wim)) {
		/* If no images have been modified and no images have been
		 * deleted, a new lookup table does not need to be written.  We
		 * shall write the new XML data and optional integrity table
		 * immediately after the lookup table.  Note that this may
		 * overwrite an existing integrity table. */
		DEBUG("Skipping writing lookup table "
		      "(no images modified or deleted)");
		old_wim_end = old_lookup_table_end;
		write_flags |= WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE |
			       WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML;
	} else if (wim->hdr.integrity_table_reshdr.offset_in_wim != 0) {
		/* Old WIM has an integrity table; begin writing new streams
		 * after it. */
		old_wim_end = wim->hdr.integrity_table_reshdr.offset_in_wim +
			      wim->hdr.integrity_table_reshdr.size_in_wim;
	} else {
		/* No existing integrity table; begin writing new streams after
		 * the old XML data. */
		old_wim_end = old_xml_end;
	}

	ret = check_resource_offsets(wim, old_wim_end);
	if (ret)
		goto out_restore_memory_hdr;

	ret = prepare_stream_list_for_write(wim, WIMLIB_ALL_IMAGES, write_flags,
					    &stream_list, &lookup_table_list,
					    &filter_ctx);
	if (ret)
		goto out_restore_memory_hdr;

	ret = open_wim_writable(wim, wim->filename, O_RDWR);
	if (ret)
		goto out_restore_memory_hdr;

	ret = lock_wim_for_append(wim);
	if (ret)
		goto out_close_wim;

	/* Set WIM_HDR_FLAG_WRITE_IN_PROGRESS flag in header. */
	wim->hdr.flags |= WIM_HDR_FLAG_WRITE_IN_PROGRESS;
	ret = write_wim_header_flags(wim->hdr.flags, &wim->out_fd);
	if (ret) {
		ERROR_WITH_ERRNO("Error updating WIM header flags");
		goto out_unlock_wim;
	}

	if (filedes_seek(&wim->out_fd, old_wim_end) == -1) {
		ERROR_WITH_ERRNO("Can't seek to end of WIM");
		ret = WIMLIB_ERR_WRITE;
		goto out_restore_physical_hdr;
	}

	ret = wim_write_stream_list(wim,
				    &stream_list,
				    write_flags,
				    num_threads,
				    &filter_ctx);
	if (ret)
		goto out_truncate;

	ret = write_wim_metadata_resources(wim, WIMLIB_ALL_IMAGES, write_flags);
	if (ret)
		goto out_truncate;

	ret = finish_write(wim, WIMLIB_ALL_IMAGES, write_flags,
			   &lookup_table_list);
	if (ret)
		goto out_truncate;

	unlock_wim_for_append(wim);
	return 0;

out_truncate:
	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE)) {
		WARNING("Truncating `%"TS"' to its original size (%"PRIu64" bytes)",
			wim->filename, old_wim_end);
		/* Return value of ftruncate() is ignored because this is
		 * already an error path.  */
		(void)ftruncate(wim->out_fd.fd, old_wim_end);
	}
out_restore_physical_hdr:
	(void)write_wim_header_flags(hdr_save.flags, &wim->out_fd);
out_unlock_wim:
	unlock_wim_for_append(wim);
out_close_wim:
	(void)close_wim_writable(wim, write_flags);
out_restore_memory_hdr:
	memcpy(&wim->hdr, &hdr_save, sizeof(struct wim_header));
	return ret;
}

static int
overwrite_wim_via_tmpfile(WIMStruct *wim, int write_flags, unsigned num_threads)
{
	size_t wim_name_len;
	int ret;

	DEBUG("Overwriting `%"TS"' via a temporary file", wim->filename);

	/* Write the WIM to a temporary file in the same directory as the
	 * original WIM. */
	wim_name_len = tstrlen(wim->filename);
	tchar tmpfile[wim_name_len + 10];
	tmemcpy(tmpfile, wim->filename, wim_name_len);
	randomize_char_array_with_alnum(tmpfile + wim_name_len, 9);
	tmpfile[wim_name_len + 9] = T('\0');

	ret = wimlib_write(wim, tmpfile, WIMLIB_ALL_IMAGES,
			   write_flags |
				WIMLIB_WRITE_FLAG_FSYNC |
				WIMLIB_WRITE_FLAG_RETAIN_GUID,
			   num_threads);
	if (ret) {
		tunlink(tmpfile);
		return ret;
	}

	if (filedes_valid(&wim->in_fd)) {
		filedes_close(&wim->in_fd);
		filedes_invalidate(&wim->in_fd);
	}

	/* Rename the new WIM file to the original WIM file.  Note: on Windows
	 * this actually calls win32_rename_replacement(), not _wrename(), so
	 * that removing the existing destination file can be handled.  */
	DEBUG("Renaming `%"TS"' to `%"TS"'", tmpfile, wim->filename);
	ret = trename(tmpfile, wim->filename);
	if (ret) {
		ERROR_WITH_ERRNO("Failed to rename `%"TS"' to `%"TS"'",
				 tmpfile, wim->filename);
	#ifdef __WIN32__
		if (ret < 0)
	#endif
		{
			tunlink(tmpfile);
		}
		return WIMLIB_ERR_RENAME;
	}

	union wimlib_progress_info progress;
	progress.rename.from = tmpfile;
	progress.rename.to = wim->filename;
	return call_progress(wim->progfunc, WIMLIB_PROGRESS_MSG_RENAME,
			     &progress, wim->progctx);
}

/* Determine if the specified WIM file may be updated by appending in-place
 * rather than writing and replacing it with an entirely new file.  */
static bool
can_overwrite_wim_inplace(const WIMStruct *wim, int write_flags)
{
	/* REBUILD flag forces full rebuild.  */
	if (write_flags & WIMLIB_WRITE_FLAG_REBUILD)
		return false;

	/* Image deletions cause full rebuild by default.  */
	if (wim->image_deletion_occurred &&
	    !(write_flags & WIMLIB_WRITE_FLAG_SOFT_DELETE))
		return false;

	/* Pipable WIMs cannot be updated in place, nor can a non-pipable WIM be
	 * turned into a pipable WIM in-place.  */
	if (wim_is_pipable(wim) || (write_flags & WIMLIB_WRITE_FLAG_PIPABLE))
		return false;

	/* The default compression type and compression chunk size selected for
	 * the output WIM must be the same as those currently used for the WIM.
	 */
	if (wim->compression_type != wim->out_compression_type)
		return false;
	if (wim->chunk_size != wim->out_chunk_size)
		return false;

	return true;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_overwrite(WIMStruct *wim, int write_flags, unsigned num_threads)
{
	int ret;
	u32 orig_hdr_flags;

	if (write_flags & ~WIMLIB_WRITE_MASK_PUBLIC)
		return WIMLIB_ERR_INVALID_PARAM;

	if (!wim->filename)
		return WIMLIB_ERR_NO_FILENAME;

	orig_hdr_flags = wim->hdr.flags;
	if (write_flags & WIMLIB_WRITE_FLAG_IGNORE_READONLY_FLAG)
		wim->hdr.flags &= ~WIM_HDR_FLAG_READONLY;
	ret = can_modify_wim(wim);
	wim->hdr.flags = orig_hdr_flags;
	if (ret)
		return ret;

	if (can_overwrite_wim_inplace(wim, write_flags)) {
		ret = overwrite_wim_inplace(wim, write_flags, num_threads);
		if (ret != WIMLIB_ERR_RESOURCE_ORDER)
			return ret;
		WARNING("Falling back to re-building entire WIM");
	}
	return overwrite_wim_via_tmpfile(wim, write_flags, num_threads);
}
