/*
 * write.c
 *
 * Support for writing WIM files; write a WIM file, overwrite a WIM file, write
 * compressed file resources, etc.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
/* On BSD, this should be included before "wimlib/list.h" so that "wimlib/list.h" can
 * overwrite the LIST_HEAD macro. */
#  include <sys/file.h>
#endif

#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/header.h"
#include "wimlib/integrity.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/write.h"
#include "wimlib/xml.h"

#ifdef __WIN32__
#  include "wimlib/win32.h" /* win32_get_number_of_processors() */
#endif

#ifdef ENABLE_MULTITHREADED_COMPRESSION
#  include <pthread.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif


#ifndef __WIN32__
#  include <sys/uio.h> /* for `struct iovec' */
#endif

static int
alloc_lzx_context(int write_resource_flags, struct wimlib_lzx_context **ctx_pp)
{
	struct wimlib_lzx_params params;
	params.size_of_this = sizeof(params);
	if (write_resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_COMPRESS_SLOW)
		params.algorithm = WIMLIB_LZX_ALGORITHM_SLOW;
	else
		params.algorithm = WIMLIB_LZX_ALGORITHM_FAST;
	params.use_defaults = 1;
	return wimlib_lzx_alloc_context(&params, ctx_pp);
}

static unsigned
compress_chunk(const void * uncompressed_data,
	       unsigned uncompressed_len,
	       void *compressed_data,
	       int out_ctype,
	       struct wimlib_lzx_context *comp_ctx)
{
	switch (out_ctype) {
	case WIMLIB_COMPRESSION_TYPE_XPRESS:
		return wimlib_xpress_compress(uncompressed_data,
					      uncompressed_len,
					      compressed_data);
	case WIMLIB_COMPRESSION_TYPE_LZX:
		return wimlib_lzx_compress2(uncompressed_data,
					    uncompressed_len,
					    compressed_data,
					    comp_ctx);
	default:
		wimlib_assert(0);
		return 0;
	}
}

/* Chunk table that's located at the beginning of each compressed resource in
 * the WIM.  (This is not the on-disk format; the on-disk format just has an
 * array of offsets.) */
struct chunk_table {
	u64 original_resource_size;
	u64 num_chunks;
	u64 table_disk_size;
	unsigned bytes_per_chunk_entry;
	void *cur_offset_p;
	union {
		u32 cur_offset_u32;
		u64 cur_offset_u64;
	};
	/* Beginning of chunk offsets, in either 32-bit or 64-bit little endian
	 * integers, including the first offset of 0, which will not be written.
	 * */
	u8 offsets[] _aligned_attribute(8);
};

/* Allocate and initializes a chunk table, then reserve space for it in the
 * output file unless writing a pipable resource.  */
static int
begin_wim_resource_chunk_tab(const struct wim_lookup_table_entry *lte,
			     struct filedes *out_fd,
			     struct chunk_table **chunk_tab_ret,
			     int resource_flags)
{
	u64 size;
	u64 num_chunks;
	unsigned bytes_per_chunk_entry;
	size_t alloc_size;
	struct chunk_table *chunk_tab;
	int ret;

	size = wim_resource_size(lte);
	num_chunks = wim_resource_chunks(lte);
	bytes_per_chunk_entry = (size > (1ULL << 32)) ? 8 : 4;
	alloc_size = sizeof(struct chunk_table) + num_chunks * sizeof(u64);
	chunk_tab = CALLOC(1, alloc_size);

	if (!chunk_tab) {
		ERROR("Failed to allocate chunk table for %"PRIu64" byte "
		      "resource", size);
		return WIMLIB_ERR_NOMEM;
	}
	chunk_tab->num_chunks = num_chunks;
	chunk_tab->original_resource_size = size;
	chunk_tab->bytes_per_chunk_entry = bytes_per_chunk_entry;
	chunk_tab->table_disk_size = chunk_tab->bytes_per_chunk_entry *
				     (num_chunks - 1);
	chunk_tab->cur_offset_p = chunk_tab->offsets;

	/* We don't know the correct offsets yet; so just write zeroes to
	 * reserve space for the table, so we can go back to it later after
	 * we've written the compressed chunks following it.
	 *
	 * Special case: if writing a pipable WIM, compressed resources are in a
	 * modified format (see comment above write_pipable_wim()) and do not
	 * have a chunk table at the beginning, so don't reserve any space for
	 * one.  */
	if (!(resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE)) {
		ret = full_write(out_fd, chunk_tab->offsets,
				 chunk_tab->table_disk_size);
		if (ret) {
			ERROR_WITH_ERRNO("Failed to write chunk table in compressed "
					 "file resource");
			FREE(chunk_tab);
			return ret;
		}
	}
	*chunk_tab_ret = chunk_tab;
	return 0;
}

/* Add the offset for the next chunk to the chunk table being constructed for a
 * compressed stream. */
static void
chunk_tab_record_chunk(struct chunk_table *chunk_tab, unsigned out_chunk_size)
{
	if (chunk_tab->bytes_per_chunk_entry == 4) {
		*(le32*)chunk_tab->cur_offset_p = cpu_to_le32(chunk_tab->cur_offset_u32);
		chunk_tab->cur_offset_p = (le32*)chunk_tab->cur_offset_p + 1;
		chunk_tab->cur_offset_u32 += out_chunk_size;
	} else {
		*(le64*)chunk_tab->cur_offset_p = cpu_to_le64(chunk_tab->cur_offset_u64);
		chunk_tab->cur_offset_p = (le64*)chunk_tab->cur_offset_p + 1;
		chunk_tab->cur_offset_u64 += out_chunk_size;
	}
}

/* Finishes a WIM chunk table and writes it to the output file at the correct
 * offset.  */
static int
finish_wim_resource_chunk_tab(struct chunk_table *chunk_tab,
			      struct filedes *out_fd,
			      off_t res_start_offset,
			      int write_resource_flags)
{
	int ret;

	if (write_resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE) {
		ret = full_write(out_fd,
				 chunk_tab->offsets +
					 chunk_tab->bytes_per_chunk_entry,
				 chunk_tab->table_disk_size);
	} else {
		ret  = full_pwrite(out_fd,
				   chunk_tab->offsets +
					   chunk_tab->bytes_per_chunk_entry,
				   chunk_tab->table_disk_size,
				   res_start_offset);
	}
	if (ret) {
		ERROR_WITH_ERRNO("Failed to write chunk table in compressed "
				 "file resource");
	}
	return ret;
}

/* Write the header for a stream in a pipable WIM.
 */
static int
write_pwm_stream_header(const struct wim_lookup_table_entry *lte,
			struct filedes *out_fd,
			int additional_reshdr_flags)
{
	struct pwm_stream_hdr stream_hdr;
	u32 reshdr_flags;
	int ret;

	stream_hdr.magic = PWM_STREAM_MAGIC;
	stream_hdr.uncompressed_size = cpu_to_le64(lte->resource_entry.original_size);
	if (additional_reshdr_flags & PWM_RESHDR_FLAG_UNHASHED) {
		zero_out_hash(stream_hdr.hash);
	} else {
		wimlib_assert(!lte->unhashed);
		copy_hash(stream_hdr.hash, lte->hash);
	}

	reshdr_flags = lte->resource_entry.flags & ~WIM_RESHDR_FLAG_COMPRESSED;
	reshdr_flags |= additional_reshdr_flags;
	stream_hdr.flags = cpu_to_le32(reshdr_flags);
	ret = full_write(out_fd, &stream_hdr, sizeof(stream_hdr));
	if (ret)
		ERROR_WITH_ERRNO("Error writing stream header");
	return ret;
}

static int
seek_and_truncate(struct filedes *out_fd, off_t offset)
{
	if (filedes_seek(out_fd, offset) == -1 ||
	    ftruncate(out_fd->fd, offset))
	{
		ERROR_WITH_ERRNO("Failed to truncate output WIM file");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

static int
finalize_and_check_sha1(SHA_CTX *sha_ctx, struct wim_lookup_table_entry *lte)
{
	u8 md[SHA1_HASH_SIZE];

	sha1_final(md, sha_ctx);
	if (lte->unhashed) {
		copy_hash(lte->hash, md);
	} else if (!hashes_equal(md, lte->hash)) {
		ERROR("WIM resource has incorrect hash!");
		if (lte_filename_valid(lte)) {
			ERROR("We were reading it from \"%"TS"\"; maybe "
			      "it changed while we were reading it.",
			      lte->file_on_disk);
		}
		return WIMLIB_ERR_INVALID_RESOURCE_HASH;
	}
	return 0;
}

struct write_resource_ctx {
	int out_ctype;
	struct wimlib_lzx_context *comp_ctx;
	struct chunk_table *chunk_tab;
	struct filedes *out_fd;
	SHA_CTX sha_ctx;
	bool doing_sha;
	int resource_flags;
};

static int
write_resource_cb(const void *chunk, size_t chunk_size, void *_ctx)
{
	struct write_resource_ctx *ctx = _ctx;
	const void *out_chunk;
	unsigned out_chunk_size;
	int ret;

	if (ctx->doing_sha)
		sha1_update(&ctx->sha_ctx, chunk, chunk_size);

	out_chunk = chunk;
	out_chunk_size = chunk_size;
	if (ctx->out_ctype != WIMLIB_COMPRESSION_TYPE_NONE) {
		void *compressed_chunk;
		unsigned compressed_size;

		/* Compress the chunk.  */
		compressed_chunk = alloca(chunk_size);

		compressed_size = compress_chunk(chunk, chunk_size,
						 compressed_chunk,
						 ctx->out_ctype,
						 ctx->comp_ctx);
		/* Use compressed data if compression to less than input size
		 * was successful.  */
		if (compressed_size) {
			out_chunk = compressed_chunk;
			out_chunk_size = compressed_size;
		}
	}

	if (ctx->chunk_tab) {
		/* Update chunk table accounting.  */
		chunk_tab_record_chunk(ctx->chunk_tab, out_chunk_size);

		/* If writing compressed chunks to a pipable WIM, before the
		 * chunk data write a chunk header that provides the compressed
		 * chunk size.  */
		if (ctx->resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE) {
			struct pwm_chunk_hdr chunk_hdr = {
				.compressed_size = cpu_to_le32(out_chunk_size),
			};
			ret = full_write(ctx->out_fd, &chunk_hdr,
					 sizeof(chunk_hdr));
			if (ret)
				goto error;
		}
	}

	/* Write the chunk data.  */
	ret = full_write(ctx->out_fd, out_chunk, out_chunk_size);
	if (ret)
		goto error;
	return 0;

error:
	ERROR_WITH_ERRNO("Failed to write WIM resource chunk");
	return ret;
}

/*
 * write_wim_resource()-
 *
 * Write a resource to an output WIM.
 *
 * @lte:
 *	Lookup table entry for the resource, which could be in another WIM, in
 *	an external file, or in another location.
 *
 * @out_fd:
 *	File descriptor opened to the output WIM.
 *
 * @out_ctype:
 *	One of the WIMLIB_COMPRESSION_TYPE_* constants to indicate which
 *	compression algorithm to use.
 *
 * @out_res_entry:
 *	On success, this is filled in with the offset, flags, compressed size,
 *	and uncompressed size of the resource in the output WIM.
 *
 * @resource_flags:
 *	* WIMLIB_WRITE_RESOURCE_FLAG_RECOMPRESS to force data to be recompressed even
 *	  if it could otherwise be copied directly from the input;
 *	* WIMLIB_WRITE_RESOURCE_FLAG_COMPRESS_SLOW to compress the data as much
 *	  as possible;
 *	* WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE if writing a resource for a pipable WIM
 *	  (and the output file descriptor may be a pipe).
 *
 * Additional notes:  The SHA1 message digest of the uncompressed data is
 * calculated (except when doing a raw copy --- see below).  If the @unhashed
 * flag is set on the lookup table entry, this message digest is simply copied
 * to it; otherwise, the message digest is compared with the existing one, and
 * the function will fail if they do not match.
 */
int
write_wim_resource(struct wim_lookup_table_entry *lte,
		   struct filedes *out_fd, int out_ctype,
		   struct resource_entry *out_res_entry,
		   int resource_flags,
		   struct wimlib_lzx_context **comp_ctx)
{
	struct write_resource_ctx write_ctx;
	off_t res_start_offset;
	u64 read_size;
	int ret;

	/* Mask out any irrelevant flags, since this function also uses this
	 * variable to store WIMLIB_READ_RESOURCE flags.  */
	resource_flags &= WIMLIB_WRITE_RESOURCE_MASK;

	/* Get current position in output WIM.  */
	res_start_offset = out_fd->offset;

	/* If we are not forcing the data to be recompressed, and the input
	 * resource is located in a WIM with the same compression type as that
	 * desired other than no compression, we can simply copy the compressed
	 * data without recompressing it.  This also means we must skip
	 * calculating the SHA1, as we never will see the uncompressed data.  */
	if (lte->resource_location == RESOURCE_IN_WIM &&
	    out_ctype == wim_resource_compression_type(lte) &&
	    out_ctype != WIMLIB_COMPRESSION_TYPE_NONE &&
	    !(resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_RECOMPRESS))
	{
		/* Normally we can request a RAW_FULL read, but if we're reading
		 * from a pipable resource and writing a non-pipable resource or
		 * vice versa, then a RAW_CHUNKS read needs to be requested so
		 * that the written resource can be appropriately formatted.
		 * However, in neither case is any actual decompression needed.
		 */
		if (lte->is_pipable == !!(resource_flags &
					  WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE))
			resource_flags |= WIMLIB_READ_RESOURCE_FLAG_RAW_FULL;
		else
			resource_flags |= WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS;
		write_ctx.doing_sha = false;
		read_size = lte->resource_entry.size;
	} else {
		write_ctx.doing_sha = true;
		sha1_init(&write_ctx.sha_ctx);
		read_size = lte->resource_entry.original_size;
	}


	/* If the output resource is to be compressed, initialize the chunk
	 * table and set the function to use for chunk compression.  Exceptions:
	 * no compression function is needed if doing a raw copy; also, no chunk
	 * table is needed if doing a *full* (not per-chunk) raw copy.  */
	write_ctx.out_ctype = WIMLIB_COMPRESSION_TYPE_NONE;
	write_ctx.chunk_tab = NULL;
	if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE) {
		if (!(resource_flags & WIMLIB_READ_RESOURCE_FLAG_RAW)) {
			write_ctx.out_ctype = out_ctype;
			if (out_ctype == WIMLIB_COMPRESSION_TYPE_LZX) {
				ret = alloc_lzx_context(resource_flags, comp_ctx);
				if (ret)
					goto out;
			}
			write_ctx.comp_ctx = *comp_ctx;
		}
		if (!(resource_flags & WIMLIB_READ_RESOURCE_FLAG_RAW_FULL)) {
			ret = begin_wim_resource_chunk_tab(lte, out_fd,
							   &write_ctx.chunk_tab,
							   resource_flags);
			if (ret)
				goto out;
		}
	}

	/* If writing a pipable resource, write the stream header and update
	 * @res_start_offset to be the end of the stream header.  */
	if (resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE) {
		int reshdr_flags = 0;
		if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE)
			reshdr_flags |= WIM_RESHDR_FLAG_COMPRESSED;
		ret = write_pwm_stream_header(lte, out_fd, reshdr_flags);
		if (ret)
			goto out_free_chunk_tab;
		res_start_offset = out_fd->offset;
	}

	/* Write the entire resource by reading the entire resource and feeding
	 * the data through the write_resource_cb function. */
	write_ctx.out_fd = out_fd;
	write_ctx.resource_flags = resource_flags;
try_write_again:
	ret = read_resource_prefix(lte, read_size,
				   write_resource_cb, &write_ctx, resource_flags);
	if (ret)
		goto out_free_chunk_tab;

	/* Verify SHA1 message digest of the resource, or set the hash for the
	 * first time. */
	if (write_ctx.doing_sha) {
		ret = finalize_and_check_sha1(&write_ctx.sha_ctx, lte);
		if (ret)
			goto out_free_chunk_tab;
	}

	/* Write chunk table if needed.  */
	if (write_ctx.chunk_tab) {
		ret = finish_wim_resource_chunk_tab(write_ctx.chunk_tab,
						    out_fd,
						    res_start_offset,
						    resource_flags);
		if (ret)
			goto out_free_chunk_tab;
	}

	/* Fill in out_res_entry with information about the newly written
	 * resource.  */
	out_res_entry->size          = out_fd->offset - res_start_offset;
	out_res_entry->flags         = lte->resource_entry.flags;
	if (out_ctype == WIMLIB_COMPRESSION_TYPE_NONE)
		out_res_entry->flags &= ~WIM_RESHDR_FLAG_COMPRESSED;
	else
		out_res_entry->flags |= WIM_RESHDR_FLAG_COMPRESSED;
	out_res_entry->offset        = res_start_offset;
	out_res_entry->original_size = wim_resource_size(lte);

	/* Check for resources compressed to greater than their original size
	 * and write them uncompressed instead.  (But never do this if writing
	 * to a pipe, and don't bother if we did a raw copy.)  */
	if (out_res_entry->size > out_res_entry->original_size &&
	    !(resource_flags & (WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE |
				WIMLIB_READ_RESOURCE_FLAG_RAW)))
	{
		DEBUG("Compressed %"PRIu64" => %"PRIu64" bytes; "
		      "writing uncompressed instead",
		      out_res_entry->original_size, out_res_entry->size);
		ret = seek_and_truncate(out_fd, res_start_offset);
		if (ret)
			goto out_free_chunk_tab;
		out_ctype = WIMLIB_COMPRESSION_TYPE_NONE;
		FREE(write_ctx.chunk_tab);
		write_ctx.out_ctype = WIMLIB_COMPRESSION_TYPE_NONE;
		write_ctx.chunk_tab = NULL;
		write_ctx.doing_sha = false;
		goto try_write_again;
	}
	if (resource_flags & (WIMLIB_READ_RESOURCE_FLAG_RAW)) {
		DEBUG("Copied raw compressed data "
		      "(%"PRIu64" => %"PRIu64" bytes @ +%"PRIu64", flags=0x%02x)",
		      out_res_entry->original_size, out_res_entry->size,
		      out_res_entry->offset, out_res_entry->flags);
	} else if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE) {
		DEBUG("Wrote compressed resource "
		      "(%"PRIu64" => %"PRIu64" bytes @ +%"PRIu64", flags=0x%02x)",
		      out_res_entry->original_size, out_res_entry->size,
		      out_res_entry->offset, out_res_entry->flags);
	} else {
		DEBUG("Wrote uncompressed resource "
		      "(%"PRIu64" bytes @ +%"PRIu64", flags=0x%02x)",
		      out_res_entry->original_size,
		      out_res_entry->offset, out_res_entry->flags);
	}
	ret = 0;
out_free_chunk_tab:
	FREE(write_ctx.chunk_tab);
out:
	return ret;
}

/* Like write_wim_resource(), but the resource is specified by a buffer of
 * uncompressed data rather a lookup table entry; also writes the SHA1 hash of
 * the buffer to @hash_ret.  */
int
write_wim_resource_from_buffer(const void *buf, size_t buf_size,
			       int reshdr_flags, struct filedes *out_fd,
			       int out_ctype,
			       struct resource_entry *out_res_entry,
			       u8 *hash_ret, int write_resource_flags,
			       struct wimlib_lzx_context **comp_ctx)
{
	/* Set up a temporary lookup table entry to provide to
	 * write_wim_resource(). */
	struct wim_lookup_table_entry lte;
	int ret;

	lte.resource_location            = RESOURCE_IN_ATTACHED_BUFFER;
	lte.attached_buffer              = (void*)buf;
	lte.resource_entry.original_size = buf_size;
	lte.resource_entry.flags         = reshdr_flags;

	if (write_resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE) {
		sha1_buffer(buf, buf_size, lte.hash);
		lte.unhashed = 0;
	} else {
		lte.unhashed = 1;
	}

	ret = write_wim_resource(&lte, out_fd, out_ctype, out_res_entry,
				 write_resource_flags, comp_ctx);
	if (ret)
		return ret;
	if (hash_ret)
		copy_hash(hash_ret, lte.hash);
	return 0;
}


#ifdef ENABLE_MULTITHREADED_COMPRESSION

/* Blocking shared queue (solves the producer-consumer problem) */
struct shared_queue {
	unsigned size;
	unsigned front;
	unsigned back;
	unsigned filled_slots;
	void **array;
	pthread_mutex_t lock;
	pthread_cond_t msg_avail_cond;
	pthread_cond_t space_avail_cond;
};

static int
shared_queue_init(struct shared_queue *q, unsigned size)
{
	wimlib_assert(size != 0);
	q->array = CALLOC(sizeof(q->array[0]), size);
	if (!q->array)
		goto err;
	q->filled_slots = 0;
	q->front = 0;
	q->back = size - 1;
	q->size = size;
	if (pthread_mutex_init(&q->lock, NULL)) {
		ERROR_WITH_ERRNO("Failed to initialize mutex");
		goto err;
	}
	if (pthread_cond_init(&q->msg_avail_cond, NULL)) {
		ERROR_WITH_ERRNO("Failed to initialize condition variable");
		goto err_destroy_lock;
	}
	if (pthread_cond_init(&q->space_avail_cond, NULL)) {
		ERROR_WITH_ERRNO("Failed to initialize condition variable");
		goto err_destroy_msg_avail_cond;
	}
	return 0;
err_destroy_msg_avail_cond:
	pthread_cond_destroy(&q->msg_avail_cond);
err_destroy_lock:
	pthread_mutex_destroy(&q->lock);
err:
	return WIMLIB_ERR_NOMEM;
}

static void
shared_queue_destroy(struct shared_queue *q)
{
	FREE(q->array);
	pthread_mutex_destroy(&q->lock);
	pthread_cond_destroy(&q->msg_avail_cond);
	pthread_cond_destroy(&q->space_avail_cond);
}

static void
shared_queue_put(struct shared_queue *q, void *obj)
{
	pthread_mutex_lock(&q->lock);
	while (q->filled_slots == q->size)
		pthread_cond_wait(&q->space_avail_cond, &q->lock);

	q->back = (q->back + 1) % q->size;
	q->array[q->back] = obj;
	q->filled_slots++;

	pthread_cond_broadcast(&q->msg_avail_cond);
	pthread_mutex_unlock(&q->lock);
}

static void *
shared_queue_get(struct shared_queue *q)
{
	void *obj;

	pthread_mutex_lock(&q->lock);
	while (q->filled_slots == 0)
		pthread_cond_wait(&q->msg_avail_cond, &q->lock);

	obj = q->array[q->front];
	q->array[q->front] = NULL;
	q->front = (q->front + 1) % q->size;
	q->filled_slots--;

	pthread_cond_broadcast(&q->space_avail_cond);
	pthread_mutex_unlock(&q->lock);
	return obj;
}

struct compressor_thread_params {
	struct shared_queue *res_to_compress_queue;
	struct shared_queue *compressed_res_queue;
	int out_ctype;
	struct wimlib_lzx_context *comp_ctx;
};

#define MAX_CHUNKS_PER_MSG 2

struct message {
	struct wim_lookup_table_entry *lte;
	u8 *uncompressed_chunks[MAX_CHUNKS_PER_MSG];
	u8 *compressed_chunks[MAX_CHUNKS_PER_MSG];
	unsigned uncompressed_chunk_sizes[MAX_CHUNKS_PER_MSG];
	struct iovec out_chunks[MAX_CHUNKS_PER_MSG];
	unsigned num_chunks;
	struct list_head list;
	bool complete;
	u64 begin_chunk;
};

static void
compress_chunks(struct message *msg, int out_ctype,
		struct wimlib_lzx_context *comp_ctx)
{
	for (unsigned i = 0; i < msg->num_chunks; i++) {
		unsigned len;

		len = compress_chunk(msg->uncompressed_chunks[i],
				     msg->uncompressed_chunk_sizes[i],
				     msg->compressed_chunks[i],
				     out_ctype,
				     comp_ctx);

		void *out_chunk;
		unsigned out_len;
		if (len) {
			/* To be written compressed */
			out_chunk = msg->compressed_chunks[i];
			out_len = len;
		} else {
			/* To be written uncompressed */
			out_chunk = msg->uncompressed_chunks[i];
			out_len = msg->uncompressed_chunk_sizes[i];
		}
		msg->out_chunks[i].iov_base = out_chunk;
		msg->out_chunks[i].iov_len = out_len;
	}
}

/* Compressor thread routine.  This is a lot simpler than the main thread
 * routine: just repeatedly get a group of chunks from the
 * res_to_compress_queue, compress them, and put them in the
 * compressed_res_queue.  A NULL pointer indicates that the thread should stop.
 * */
static void *
compressor_thread_proc(void *arg)
{
	struct compressor_thread_params *params = arg;
	struct shared_queue *res_to_compress_queue = params->res_to_compress_queue;
	struct shared_queue *compressed_res_queue = params->compressed_res_queue;
	struct message *msg;

	DEBUG("Compressor thread ready");
	while ((msg = shared_queue_get(res_to_compress_queue)) != NULL) {
		compress_chunks(msg, params->out_ctype, params->comp_ctx);
		shared_queue_put(compressed_res_queue, msg);
	}
	DEBUG("Compressor thread terminating");
	return NULL;
}
#endif /* ENABLE_MULTITHREADED_COMPRESSION */

struct write_streams_progress_data {
	wimlib_progress_func_t progress_func;
	union wimlib_progress_info progress;
	uint64_t next_progress;
	WIMStruct *prev_wim_part;
};

static void
do_write_streams_progress(struct write_streams_progress_data *progress_data,
			  struct wim_lookup_table_entry *lte,
			  bool stream_discarded)
{
	union wimlib_progress_info *progress = &progress_data->progress;
	bool new_wim_part;

	if (stream_discarded) {
		progress->write_streams.total_bytes -= wim_resource_size(lte);
		if (progress_data->next_progress != ~(uint64_t)0 &&
		    progress_data->next_progress > progress->write_streams.total_bytes)
		{
			progress_data->next_progress = progress->write_streams.total_bytes;
		}
	} else {
		progress->write_streams.completed_bytes += wim_resource_size(lte);
	}
	new_wim_part = false;
	if (lte->resource_location == RESOURCE_IN_WIM &&
	    lte->wim != progress_data->prev_wim_part)
	{
		if (progress_data->prev_wim_part) {
			new_wim_part = true;
			progress->write_streams.completed_parts++;
		}
		progress_data->prev_wim_part = lte->wim;
	}
	progress->write_streams.completed_streams++;
	if (progress_data->progress_func
	    && (progress->write_streams.completed_bytes >= progress_data->next_progress
		|| new_wim_part))
	{
		progress_data->progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
					     progress);
		if (progress_data->next_progress == progress->write_streams.total_bytes) {
			progress_data->next_progress = ~(uint64_t)0;
		} else {
			progress_data->next_progress =
				min(progress->write_streams.total_bytes,
				    progress->write_streams.completed_bytes +
				        progress->write_streams.total_bytes / 100);
		}
	}
}

struct serial_write_stream_ctx {
	struct filedes *out_fd;
	int out_ctype;
	struct wimlib_lzx_context **comp_ctx;
	int write_resource_flags;
};

static int
serial_write_stream(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct serial_write_stream_ctx *ctx = _ctx;
	return write_wim_resource(lte, ctx->out_fd,
				  ctx->out_ctype, &lte->output_resource_entry,
				  ctx->write_resource_flags,
				  ctx->comp_ctx);
}


/* Write a list of streams, taking into account that some streams may be
 * duplicates that are checksummed and discarded on the fly, and also delegating
 * the actual writing of a stream to a function @write_stream_cb, which is
 * passed the context @write_stream_ctx. */
static int
do_write_stream_list(struct list_head *stream_list,
		     struct wim_lookup_table *lookup_table,
		     int (*write_stream_cb)(struct wim_lookup_table_entry *, void *),
		     void *write_stream_ctx,
		     struct write_streams_progress_data *progress_data)
{
	int ret = 0;
	struct wim_lookup_table_entry *lte;
	bool stream_discarded;

	/* For each stream in @stream_list ... */
	while (!list_empty(stream_list)) {
		stream_discarded = false;
		lte = container_of(stream_list->next,
				   struct wim_lookup_table_entry,
				   write_streams_list);
		list_del(&lte->write_streams_list);
		if (lte->unhashed && !lte->unique_size) {
			/* Unhashed stream that shares a size with some other
			 * stream in the WIM we are writing.  The stream must be
			 * checksummed to know if we need to write it or not. */
			struct wim_lookup_table_entry *tmp;
			u32 orig_out_refcnt = lte->out_refcnt;

			ret = hash_unhashed_stream(lte, lookup_table, &tmp);
			if (ret)
				break;
			if (tmp != lte) {
				/* We found a duplicate stream.  'lte' was
				 * freed, so replace it with the duplicate.  */
				lte = tmp;

				/* 'out_refcnt' was transferred to the
				 * duplicate, and we can detect if the duplicate
				 * stream was already referenced for writing by
				 * checking if its 'out_refcnt' is higher than
				 * that of the original stream.  In such cases,
				 * the current stream can be discarded.  We can
				 * also discard the current stream if it was
				 * previously marked as filtered (e.g. already
				 * present in the WIM being written).  */
				if (lte->out_refcnt > orig_out_refcnt ||
				    lte->filtered) {
					DEBUG("Discarding duplicate stream of "
					      "length %"PRIu64,
					      wim_resource_size(lte));
					lte->no_progress = 0;
					stream_discarded = true;
					goto skip_to_progress;
				}
			}
		}

		/* Here, @lte is either a hashed stream or an unhashed stream
		 * with a unique size.  In either case we know that the stream
		 * has to be written.  In either case the SHA1 message digest
		 * will be calculated over the stream while writing it; however,
		 * in the former case this is done merely to check the data,
		 * while in the latter case this is done because we do not have
		 * the SHA1 message digest yet.  */
		wimlib_assert(lte->out_refcnt != 0);
		lte->deferred = 0;
		lte->no_progress = 0;
		ret = (*write_stream_cb)(lte, write_stream_ctx);
		if (ret)
			break;
		/* In parallel mode, some streams are deferred for later,
		 * serialized processing; ignore them here. */
		if (lte->deferred)
			continue;
		if (lte->unhashed) {
			list_del(&lte->unhashed_list);
			lookup_table_insert(lookup_table, lte);
			lte->unhashed = 0;
		}
	skip_to_progress:
		if (!lte->no_progress) {
			do_write_streams_progress(progress_data,
						  lte, stream_discarded);
		}
	}
	return ret;
}

static int
do_write_stream_list_serial(struct list_head *stream_list,
			    struct wim_lookup_table *lookup_table,
			    struct filedes *out_fd,
			    int out_ctype,
			    struct wimlib_lzx_context **comp_ctx,
			    int write_resource_flags,
			    struct write_streams_progress_data *progress_data)
{
	struct serial_write_stream_ctx ctx = {
		.out_fd = out_fd,
		.out_ctype = out_ctype,
		.write_resource_flags = write_resource_flags,
		.comp_ctx = comp_ctx,
	};
	return do_write_stream_list(stream_list,
				    lookup_table,
				    serial_write_stream,
				    &ctx,
				    progress_data);
}

static inline int
write_flags_to_resource_flags(int write_flags)
{
	int resource_flags = 0;

	if (write_flags & WIMLIB_WRITE_FLAG_RECOMPRESS)
		resource_flags |= WIMLIB_WRITE_RESOURCE_FLAG_RECOMPRESS;
	if (write_flags & WIMLIB_WRITE_FLAG_COMPRESS_SLOW)
		resource_flags |= WIMLIB_WRITE_RESOURCE_FLAG_COMPRESS_SLOW;
	if (write_flags & WIMLIB_WRITE_FLAG_PIPABLE)
		resource_flags |= WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE;
	return resource_flags;
}

static int
write_stream_list_serial(struct list_head *stream_list,
			 struct wim_lookup_table *lookup_table,
			 struct filedes *out_fd,
			 int out_ctype,
			 struct wimlib_lzx_context **comp_ctx,
			 int write_resource_flags,
			 struct write_streams_progress_data *progress_data)
{
	union wimlib_progress_info *progress = &progress_data->progress;
	DEBUG("Writing stream list of size %"PRIu64" (serial version)",
	      progress->write_streams.total_streams);
	progress->write_streams.num_threads = 1;
	if (progress_data->progress_func) {
		progress_data->progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
					     progress);
	}
	return do_write_stream_list_serial(stream_list,
					   lookup_table,
					   out_fd,
					   out_ctype,
					   comp_ctx,
					   write_resource_flags,
					   progress_data);
}

#ifdef ENABLE_MULTITHREADED_COMPRESSION
static int
write_wim_chunks(struct message *msg, struct filedes *out_fd,
		 struct chunk_table *chunk_tab,
		 int write_resource_flags)
{
	struct iovec *vecs;
	struct pwm_chunk_hdr *chunk_hdrs;
	unsigned nvecs;
	int ret;

	for (unsigned i = 0; i < msg->num_chunks; i++)
		chunk_tab_record_chunk(chunk_tab, msg->out_chunks[i].iov_len);

	if (!(write_resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE)) {
		nvecs = msg->num_chunks;
		vecs = msg->out_chunks;
	} else {
		/* Special case:  If writing a compressed resource to a pipable
		 * WIM, prefix each compressed chunk with a header that gives
		 * its compressed size.  */
		nvecs = msg->num_chunks * 2;
		vecs = alloca(nvecs * sizeof(vecs[0]));
		chunk_hdrs = alloca(msg->num_chunks * sizeof(chunk_hdrs[0]));

		for (unsigned i = 0; i < msg->num_chunks; i++) {
			chunk_hdrs[i].compressed_size = cpu_to_le32(msg->out_chunks[i].iov_len);
			vecs[i * 2].iov_base = &chunk_hdrs[i];
			vecs[i * 2].iov_len = sizeof(chunk_hdrs[i]);
			vecs[i * 2 + 1].iov_base = msg->out_chunks[i].iov_base;
			vecs[i * 2 + 1].iov_len = msg->out_chunks[i].iov_len;
		}
	}
	ret = full_writev(out_fd, vecs, nvecs);
	if (ret)
		ERROR_WITH_ERRNO("Failed to write WIM chunks");
	return ret;
}

struct main_writer_thread_ctx {
	struct list_head *stream_list;
	struct wim_lookup_table *lookup_table;
	struct filedes *out_fd;
	off_t res_start_offset;
	int out_ctype;
	struct wimlib_lzx_context **comp_ctx;
	int write_resource_flags;
	struct shared_queue *res_to_compress_queue;
	struct shared_queue *compressed_res_queue;
	size_t num_messages;
	struct write_streams_progress_data *progress_data;

	struct list_head available_msgs;
	struct list_head outstanding_streams;
	struct list_head serial_streams;
	size_t num_outstanding_messages;

	SHA_CTX next_sha_ctx;
	u64 next_chunk;
	u64 next_num_chunks;
	struct wim_lookup_table_entry *next_lte;

	struct message *msgs;
	struct message *next_msg;
	struct chunk_table *cur_chunk_tab;
};

static int
init_message(struct message *msg)
{
	for (size_t i = 0; i < MAX_CHUNKS_PER_MSG; i++) {
		msg->compressed_chunks[i] = MALLOC(WIM_CHUNK_SIZE);
		msg->uncompressed_chunks[i] = MALLOC(WIM_CHUNK_SIZE);
		if (msg->compressed_chunks[i] == NULL ||
		    msg->uncompressed_chunks[i] == NULL)
			return WIMLIB_ERR_NOMEM;
	}
	return 0;
}

static void
destroy_message(struct message *msg)
{
	for (size_t i = 0; i < MAX_CHUNKS_PER_MSG; i++) {
		FREE(msg->compressed_chunks[i]);
		FREE(msg->uncompressed_chunks[i]);
	}
}

static void
free_messages(struct message *msgs, size_t num_messages)
{
	if (msgs) {
		for (size_t i = 0; i < num_messages; i++)
			destroy_message(&msgs[i]);
		FREE(msgs);
	}
}

static struct message *
allocate_messages(size_t num_messages)
{
	struct message *msgs;

	msgs = CALLOC(num_messages, sizeof(struct message));
	if (!msgs)
		return NULL;
	for (size_t i = 0; i < num_messages; i++) {
		if (init_message(&msgs[i])) {
			free_messages(msgs, num_messages);
			return NULL;
		}
	}
	return msgs;
}

static void
main_writer_thread_destroy_ctx(struct main_writer_thread_ctx *ctx)
{
	while (ctx->num_outstanding_messages--)
		shared_queue_get(ctx->compressed_res_queue);
	free_messages(ctx->msgs, ctx->num_messages);
	FREE(ctx->cur_chunk_tab);
}

static int
main_writer_thread_init_ctx(struct main_writer_thread_ctx *ctx)
{
	/* Pre-allocate all the buffers that will be needed to do the chunk
	 * compression. */
	ctx->msgs = allocate_messages(ctx->num_messages);
	if (!ctx->msgs)
		return WIMLIB_ERR_NOMEM;

	/* Initially, all the messages are available to use. */
	INIT_LIST_HEAD(&ctx->available_msgs);
	for (size_t i = 0; i < ctx->num_messages; i++)
		list_add_tail(&ctx->msgs[i].list, &ctx->available_msgs);

	/* outstanding_streams is the list of streams that currently have had
	 * chunks sent off for compression.
	 *
	 * The first stream in outstanding_streams is the stream that is
	 * currently being written.
	 *
	 * The last stream in outstanding_streams is the stream that is
	 * currently being read and having chunks fed to the compressor threads.
	 * */
	INIT_LIST_HEAD(&ctx->outstanding_streams);
	ctx->num_outstanding_messages = 0;

	ctx->next_msg = NULL;

	/* Resources that don't need any chunks compressed are added to this
	 * list and written directly by the main thread. */
	INIT_LIST_HEAD(&ctx->serial_streams);

	ctx->cur_chunk_tab = NULL;

	return 0;
}

static int
receive_compressed_chunks(struct main_writer_thread_ctx *ctx)
{
	struct message *msg;
	struct wim_lookup_table_entry *cur_lte;
	int ret;

	wimlib_assert(!list_empty(&ctx->outstanding_streams));
	wimlib_assert(ctx->num_outstanding_messages != 0);

	cur_lte = container_of(ctx->outstanding_streams.next,
			       struct wim_lookup_table_entry,
			       being_compressed_list);

	/* Get the next message from the queue and process it.
	 * The message will contain 1 or more data chunks that have been
	 * compressed. */
	msg = shared_queue_get(ctx->compressed_res_queue);
	msg->complete = true;
	--ctx->num_outstanding_messages;

	/* Is this the next chunk in the current resource?  If it's not
	 * (i.e., an earlier chunk in a same or different resource
	 * hasn't been compressed yet), do nothing, and keep this
	 * message around until all earlier chunks are received.
	 *
	 * Otherwise, write all the chunks we can. */
	while (cur_lte != NULL &&
	       !list_empty(&cur_lte->msg_list)
	       && (msg = container_of(cur_lte->msg_list.next,
				      struct message,
				      list))->complete)
	{
		list_move(&msg->list, &ctx->available_msgs);
		if (msg->begin_chunk == 0) {
			/* First set of chunks.  */

			/* Write pipable WIM stream header if needed.  */
			if (ctx->write_resource_flags &
			    WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE)
			{
				ret = write_pwm_stream_header(cur_lte, ctx->out_fd,
							      WIM_RESHDR_FLAG_COMPRESSED);
				if (ret)
					return ret;
			}

			/* Save current offset.  */
			ctx->res_start_offset = ctx->out_fd->offset;

			/* Begin building the chunk table, and leave space for
			 * it if needed.  */
			ret = begin_wim_resource_chunk_tab(cur_lte,
							   ctx->out_fd,
							   &ctx->cur_chunk_tab,
							   ctx->write_resource_flags);
			if (ret)
				return ret;

		}

		/* Write the compressed chunks from the message. */
		ret = write_wim_chunks(msg, ctx->out_fd, ctx->cur_chunk_tab,
				       ctx->write_resource_flags);
		if (ret)
			return ret;

		/* Was this the last chunk of the stream?  If so, finish
		 * it. */
		if (list_empty(&cur_lte->msg_list) &&
		    msg->begin_chunk + msg->num_chunks == ctx->cur_chunk_tab->num_chunks)
		{
			u64 res_csize;

			ret = finish_wim_resource_chunk_tab(ctx->cur_chunk_tab,
							    ctx->out_fd,
							    ctx->res_start_offset,
							    ctx->write_resource_flags);
			if (ret)
				return ret;

			list_del(&cur_lte->being_compressed_list);

			res_csize = ctx->out_fd->offset - ctx->res_start_offset;

			FREE(ctx->cur_chunk_tab);
			ctx->cur_chunk_tab = NULL;

			/* Check for resources compressed to greater than or
			 * equal to their original size and write them
			 * uncompressed instead.  (But never do this if writing
			 * to a pipe.)  */
			if (res_csize >= wim_resource_size(cur_lte) &&
			    !(ctx->write_resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE))
			{
				DEBUG("Compressed %"PRIu64" => %"PRIu64" bytes; "
				      "writing uncompressed instead",
				      wim_resource_size(cur_lte), res_csize);
				ret = seek_and_truncate(ctx->out_fd, ctx->res_start_offset);
				if (ret)
					return ret;
				ret = write_wim_resource(cur_lte,
							 ctx->out_fd,
							 WIMLIB_COMPRESSION_TYPE_NONE,
							 &cur_lte->output_resource_entry,
							 ctx->write_resource_flags,
							 ctx->comp_ctx);
				if (ret)
					return ret;
			} else {
				cur_lte->output_resource_entry.size =
					res_csize;

				cur_lte->output_resource_entry.original_size =
					cur_lte->resource_entry.original_size;

				cur_lte->output_resource_entry.offset =
					ctx->res_start_offset;

				cur_lte->output_resource_entry.flags =
					cur_lte->resource_entry.flags |
						WIM_RESHDR_FLAG_COMPRESSED;

				DEBUG("Wrote compressed resource "
				      "(%"PRIu64" => %"PRIu64" bytes @ +%"PRIu64", flags=0x%02x)",
				      cur_lte->output_resource_entry.original_size,
				      cur_lte->output_resource_entry.size,
				      cur_lte->output_resource_entry.offset,
				      cur_lte->output_resource_entry.flags);
			}

			do_write_streams_progress(ctx->progress_data,
						  cur_lte, false);

			/* Since we just finished writing a stream, write any
			 * streams that have been added to the serial_streams
			 * list for direct writing by the main thread (e.g.
			 * resources that don't need to be compressed because
			 * the desired compression type is the same as the
			 * previous compression type). */
			if (!list_empty(&ctx->serial_streams)) {
				ret = do_write_stream_list_serial(&ctx->serial_streams,
								  ctx->lookup_table,
								  ctx->out_fd,
								  ctx->out_ctype,
								  ctx->comp_ctx,
								  ctx->write_resource_flags,
								  ctx->progress_data);
				if (ret)
					return ret;
			}

			/* Advance to the next stream to write. */
			if (list_empty(&ctx->outstanding_streams)) {
				cur_lte = NULL;
			} else {
				cur_lte = container_of(ctx->outstanding_streams.next,
						       struct wim_lookup_table_entry,
						       being_compressed_list);
			}
		}
	}
	return 0;
}

/* Called when the main thread has read a new chunk of data. */
static int
main_writer_thread_cb(const void *chunk, size_t chunk_size, void *_ctx)
{
	struct main_writer_thread_ctx *ctx = _ctx;
	int ret;
	struct message *next_msg;
	u64 next_chunk_in_msg;

	/* Update SHA1 message digest for the stream currently being read by the
	 * main thread. */
	sha1_update(&ctx->next_sha_ctx, chunk, chunk_size);

	/* We send chunks of data to the compressor chunks in batches which we
	 * refer to as "messages".  @next_msg is the message that is currently
	 * being prepared to send off.  If it is NULL, that indicates that we
	 * need to start a new message. */
	next_msg = ctx->next_msg;
	if (!next_msg) {
		/* We need to start a new message.  First check to see if there
		 * is a message available in the list of available messages.  If
		 * so, we can just take one.  If not, all the messages (there is
		 * a fixed number of them, proportional to the number of
		 * threads) have been sent off to the compressor threads, so we
		 * receive messages from the compressor threads containing
		 * compressed chunks of data.
		 *
		 * We may need to receive multiple messages before one is
		 * actually available to use because messages received that are
		 * *not* for the very next set of chunks to compress must be
		 * buffered until it's time to write those chunks. */
		while (list_empty(&ctx->available_msgs)) {
			ret = receive_compressed_chunks(ctx);
			if (ret)
				return ret;
		}

		next_msg = container_of(ctx->available_msgs.next,
					struct message, list);
		list_del(&next_msg->list);
		next_msg->complete = false;
		next_msg->begin_chunk = ctx->next_chunk;
		next_msg->num_chunks = min(MAX_CHUNKS_PER_MSG,
					   ctx->next_num_chunks - ctx->next_chunk);
		ctx->next_msg = next_msg;
	}

	/* Fill in the next chunk to compress */
	next_chunk_in_msg = ctx->next_chunk - next_msg->begin_chunk;

	next_msg->uncompressed_chunk_sizes[next_chunk_in_msg] = chunk_size;
	memcpy(next_msg->uncompressed_chunks[next_chunk_in_msg],
	       chunk, chunk_size);
	ctx->next_chunk++;
	if (++next_chunk_in_msg == next_msg->num_chunks) {
		/* Send off an array of chunks to compress */
		list_add_tail(&next_msg->list, &ctx->next_lte->msg_list);
		shared_queue_put(ctx->res_to_compress_queue, next_msg);
		++ctx->num_outstanding_messages;
		ctx->next_msg = NULL;
	}
	return 0;
}

static int
main_writer_thread_finish(void *_ctx)
{
	struct main_writer_thread_ctx *ctx = _ctx;
	int ret;
	while (ctx->num_outstanding_messages != 0) {
		ret = receive_compressed_chunks(ctx);
		if (ret)
			return ret;
	}
	wimlib_assert(list_empty(&ctx->outstanding_streams));
	return do_write_stream_list_serial(&ctx->serial_streams,
					   ctx->lookup_table,
					   ctx->out_fd,
					   ctx->out_ctype,
					   ctx->comp_ctx,
					   ctx->write_resource_flags,
					   ctx->progress_data);
}

static int
submit_stream_for_compression(struct wim_lookup_table_entry *lte,
			      struct main_writer_thread_ctx *ctx)
{
	int ret;

	/* Read the entire stream @lte, feeding its data chunks to the
	 * compressor threads.  Also SHA1-sum the stream; this is required in
	 * the case that @lte is unhashed, and a nice additional verification
	 * when @lte is already hashed. */
	sha1_init(&ctx->next_sha_ctx);
	ctx->next_chunk = 0;
	ctx->next_num_chunks = wim_resource_chunks(lte);
	ctx->next_lte = lte;
	INIT_LIST_HEAD(&lte->msg_list);
	list_add_tail(&lte->being_compressed_list, &ctx->outstanding_streams);
	ret = read_resource_prefix(lte, wim_resource_size(lte),
				   main_writer_thread_cb, ctx, 0);
	if (ret)
		return ret;
	wimlib_assert(ctx->next_chunk == ctx->next_num_chunks);
	return finalize_and_check_sha1(&ctx->next_sha_ctx, lte);
}

static int
main_thread_process_next_stream(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct main_writer_thread_ctx *ctx = _ctx;
	int ret;

	if (wim_resource_size(lte) < 1000 ||
	    ctx->out_ctype == WIMLIB_COMPRESSION_TYPE_NONE ||
	    (lte->resource_location == RESOURCE_IN_WIM &&
	     !(ctx->write_resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_RECOMPRESS) &&
	     lte->wim->compression_type == ctx->out_ctype))
	{
		/* Stream is too small or isn't being compressed.  Process it by
		 * the main thread when we have a chance.  We can't necessarily
		 * process it right here, as the main thread could be in the
		 * middle of writing a different stream. */
		list_add_tail(&lte->write_streams_list, &ctx->serial_streams);
		lte->deferred = 1;
		ret = 0;
	} else {
		ret = submit_stream_for_compression(lte, ctx);
	}
	lte->no_progress = 1;
	return ret;
}

static long
get_default_num_threads(void)
{
#ifdef __WIN32__
	return win32_get_number_of_processors();
#else
	return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

/* Equivalent to write_stream_list_serial(), except this takes a @num_threads
 * parameter and will perform compression using that many threads.  Falls
 * back to write_stream_list_serial() on certain errors, such as a failure to
 * create the number of threads requested.
 *
 * High level description of the algorithm for writing compressed streams in
 * parallel:  We perform compression on chunks of size WIM_CHUNK_SIZE bytes
 * rather than on full files.  The currently executing thread becomes the main
 * thread and is entirely in charge of reading the data to compress (which may
 * be in any location understood by the resource code--- such as in an external
 * file being captured, or in another WIM file from which an image is being
 * exported) and actually writing the compressed data to the output file.
 * Additional threads are "compressor threads" and all execute the
 * compressor_thread_proc, where they repeatedly retrieve buffers of data from
 * the main thread, compress them, and hand them back to the main thread.
 *
 * Certain streams, such as streams that do not need to be compressed (e.g.
 * input compression type same as output compression type) or streams of very
 * small size are placed in a list (main_writer_thread_ctx.serial_list) and
 * handled entirely by the main thread at an appropriate time.
 *
 * At any given point in time, multiple streams may be having chunks compressed
 * concurrently.  The stream that the main thread is currently *reading* may be
 * later in the list that the stream that the main thread is currently
 * *writing*.
 */
static int
write_stream_list_parallel(struct list_head *stream_list,
			   struct wim_lookup_table *lookup_table,
			   struct filedes *out_fd,
			   int out_ctype,
			   struct wimlib_lzx_context **comp_ctx,
			   int write_resource_flags,
			   struct write_streams_progress_data *progress_data,
			   unsigned num_threads)
{
	int ret;
	struct shared_queue res_to_compress_queue;
	struct shared_queue compressed_res_queue;
	pthread_t *compressor_threads = NULL;
	union wimlib_progress_info *progress = &progress_data->progress;

	if (num_threads == 0) {
		long nthreads = get_default_num_threads();
		if (nthreads < 1 || nthreads > UINT_MAX) {
			WARNING("Could not determine number of processors! Assuming 1");
			goto out_serial;
		} else if (nthreads == 1) {
			goto out_serial_quiet;
		} else {
			num_threads = nthreads;
		}
	}

	DEBUG("Writing stream list of size %"PRIu64" "
	      "(parallel version, num_threads=%u)",
	      progress->write_streams.total_streams, num_threads);

	progress->write_streams.num_threads = num_threads;

	static const size_t MESSAGES_PER_THREAD = 2;
	size_t queue_size = (size_t)(num_threads * MESSAGES_PER_THREAD);

	DEBUG("Initializing shared queues (queue_size=%zu)", queue_size);

	ret = shared_queue_init(&res_to_compress_queue, queue_size);
	if (ret)
		goto out_serial;

	ret = shared_queue_init(&compressed_res_queue, queue_size);
	if (ret)
		goto out_destroy_res_to_compress_queue;

	struct compressor_thread_params *params;

	params = CALLOC(num_threads, sizeof(params[0]));
	if (params == NULL) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_destroy_compressed_res_queue;
	}

	for (unsigned i = 0; i < num_threads; i++) {
		params[i].res_to_compress_queue = &res_to_compress_queue;
		params[i].compressed_res_queue = &compressed_res_queue;
		params[i].out_ctype = out_ctype;
		if (out_ctype == WIMLIB_COMPRESSION_TYPE_LZX) {
			ret = alloc_lzx_context(write_resource_flags,
						&params[i].comp_ctx);
			if (ret)
				goto out_free_params;
		}
	}

	compressor_threads = MALLOC(num_threads * sizeof(pthread_t));
	if (!compressor_threads) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_params;
	}

	for (unsigned i = 0; i < num_threads; i++) {
		DEBUG("pthread_create thread %u of %u", i + 1, num_threads);
		ret = pthread_create(&compressor_threads[i], NULL,
				     compressor_thread_proc, &params[i]);
		if (ret != 0) {
			ret = -1;
			ERROR_WITH_ERRNO("Failed to create compressor "
					 "thread %u of %u",
					 i + 1, num_threads);
			num_threads = i;
			goto out_join;
		}
	}

	if (progress_data->progress_func) {
		progress_data->progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
					     progress);
	}

	struct main_writer_thread_ctx ctx;
	ctx.stream_list           = stream_list;
	ctx.lookup_table          = lookup_table;
	ctx.out_fd                = out_fd;
	ctx.out_ctype             = out_ctype;
	ctx.comp_ctx		  = comp_ctx;
	ctx.res_to_compress_queue = &res_to_compress_queue;
	ctx.compressed_res_queue  = &compressed_res_queue;
	ctx.num_messages          = queue_size;
	ctx.write_resource_flags  = write_resource_flags;
	ctx.progress_data         = progress_data;
	ret = main_writer_thread_init_ctx(&ctx);
	if (ret)
		goto out_join;
	ret = do_write_stream_list(stream_list, lookup_table,
				   main_thread_process_next_stream,
				   &ctx, progress_data);
	if (ret)
		goto out_destroy_ctx;

	/* The main thread has finished reading all streams that are going to be
	 * compressed in parallel, and it now needs to wait for all remaining
	 * chunks to be compressed so that the remaining streams can actually be
	 * written to the output file.  Furthermore, any remaining streams that
	 * had processing deferred to the main thread need to be handled.  These
	 * tasks are done by the main_writer_thread_finish() function. */
	ret = main_writer_thread_finish(&ctx);
out_destroy_ctx:
	main_writer_thread_destroy_ctx(&ctx);
out_join:
	for (unsigned i = 0; i < num_threads; i++)
		shared_queue_put(&res_to_compress_queue, NULL);

	for (unsigned i = 0; i < num_threads; i++) {
		if (pthread_join(compressor_threads[i], NULL)) {
			WARNING_WITH_ERRNO("Failed to join compressor "
					   "thread %u of %u",
					   i + 1, num_threads);
		}
	}
	FREE(compressor_threads);
out_free_params:
	for (unsigned i = 0; i < num_threads; i++)
		wimlib_lzx_free_context(params[i].comp_ctx);
	FREE(params);
out_destroy_compressed_res_queue:
	shared_queue_destroy(&compressed_res_queue);
out_destroy_res_to_compress_queue:
	shared_queue_destroy(&res_to_compress_queue);
	if (ret >= 0 && ret != WIMLIB_ERR_NOMEM)
		return ret;
out_serial:
	WARNING("Falling back to single-threaded compression");
out_serial_quiet:
	return write_stream_list_serial(stream_list,
					lookup_table,
					out_fd,
					out_ctype,
					comp_ctx,
					write_resource_flags,
					progress_data);

}
#endif

/*
 * Write a list of streams to a WIM (@out_fd) using the compression type
 * @out_ctype and up to @num_threads compressor threads.
 */
static int
write_stream_list(struct list_head *stream_list,
		  struct wim_lookup_table *lookup_table,
		  struct filedes *out_fd, int out_ctype,
		  struct wimlib_lzx_context **comp_ctx,
		  int write_flags,
		  unsigned num_threads, wimlib_progress_func_t progress_func)
{
	struct wim_lookup_table_entry *lte;
	size_t num_streams = 0;
	u64 total_bytes = 0;
	u64 total_compression_bytes = 0;
	struct write_streams_progress_data progress_data;
	int ret;
	int write_resource_flags;
	unsigned total_parts = 0;
	WIMStruct *prev_wim_part = NULL;

	if (list_empty(stream_list)) {
		DEBUG("No streams to write.");
		return 0;
	}

	write_resource_flags = write_flags_to_resource_flags(write_flags);

	DEBUG("Writing stream list (offset = %"PRIu64", write_resource_flags=0x%08x)",
	      out_fd->offset, write_resource_flags);

	sort_stream_list_by_sequential_order(stream_list,
					     offsetof(struct wim_lookup_table_entry,
						      write_streams_list));

	/* Calculate the total size of the streams to be written.  Note: this
	 * will be the uncompressed size, as we may not know the compressed size
	 * yet, and also this will assume that every unhashed stream will be
	 * written (which will not necessarily be the case). */
	list_for_each_entry(lte, stream_list, write_streams_list) {
		num_streams++;
		total_bytes += wim_resource_size(lte);
		if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE
		       && (wim_resource_compression_type(lte) != out_ctype ||
			   (write_resource_flags & WIMLIB_WRITE_RESOURCE_FLAG_RECOMPRESS)))
		{
			total_compression_bytes += wim_resource_size(lte);
		}
		if (lte->resource_location == RESOURCE_IN_WIM) {
			if (prev_wim_part != lte->wim) {
				prev_wim_part = lte->wim;
				total_parts++;
			}
		}
	}

	memset(&progress_data, 0, sizeof(progress_data));
	progress_data.progress_func = progress_func;

	progress_data.progress.write_streams.total_bytes       = total_bytes;
	progress_data.progress.write_streams.total_streams     = num_streams;
	progress_data.progress.write_streams.completed_bytes   = 0;
	progress_data.progress.write_streams.completed_streams = 0;
	progress_data.progress.write_streams.num_threads       = num_threads;
	progress_data.progress.write_streams.compression_type  = out_ctype;
	progress_data.progress.write_streams.total_parts       = total_parts;
	progress_data.progress.write_streams.completed_parts   = 0;

	progress_data.next_progress = 0;
	progress_data.prev_wim_part = NULL;

#ifdef ENABLE_MULTITHREADED_COMPRESSION
	if (total_compression_bytes >= 2000000 && num_threads != 1)
		ret = write_stream_list_parallel(stream_list,
						 lookup_table,
						 out_fd,
						 out_ctype,
						 comp_ctx,
						 write_resource_flags,
						 &progress_data,
						 num_threads);
	else
#endif
		ret = write_stream_list_serial(stream_list,
					       lookup_table,
					       out_fd,
					       out_ctype,
					       comp_ctx,
					       write_resource_flags,
					       &progress_data);
	if (ret == 0)
		DEBUG("Successfully wrote stream list.");
	else
		DEBUG("Failed to write stream list.");
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
	if (!tab->array)
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

	pos = hash_u64(wim_resource_size(lte)) % tab->capacity;
	lte->unique_size = 1;
	hlist_for_each_entry(same_size_lte, tmp, &tab->array[pos], hash_list_2) {
		if (wim_resource_size(same_size_lte) == wim_resource_size(lte)) {
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
lte_reference_for_logical_write(struct wim_lookup_table_entry *lte,
				struct find_streams_ctx *ctx,
				unsigned nref)
{
	if (lte->out_refcnt == 0) {
		stream_size_table_insert(lte, &ctx->stream_size_tab);
		list_add_tail(&lte->write_streams_list, &ctx->stream_list);
	}
	lte->out_refcnt += nref;
}

static int
do_lte_full_reference_for_logical_write(struct wim_lookup_table_entry *lte,
					void *_ctx)
{
	struct find_streams_ctx *ctx = _ctx;
	lte->out_refcnt = 0;
	lte_reference_for_logical_write(lte, ctx,
					(lte->refcnt ? lte->refcnt : 1));
	return 0;
}

static int
inode_find_streams_to_write(struct wim_inode *inode,
			    struct wim_lookup_table *table,
			    struct find_streams_ctx *ctx)
{
	struct wim_lookup_table_entry *lte;
	unsigned i;

	for (i = 0; i <= inode->i_num_ads; i++) {
		lte = inode_stream_lte(inode, i, table);
		if (lte)
			lte_reference_for_logical_write(lte, ctx, inode->i_nlink);
		else if (!is_zero_hash(inode_stream_hash(inode, i)))
			return WIMLIB_ERR_RESOURCE_NOT_FOUND;
	}
	return 0;
}

static int
image_find_streams_to_write(WIMStruct *wim)
{
	struct find_streams_ctx *ctx;
	struct wim_image_metadata *imd;
	struct wim_inode *inode;
	struct wim_lookup_table_entry *lte;
	int ret;

	ctx = wim->private;
	imd = wim_get_current_image_metadata(wim);

	image_for_each_unhashed_stream(lte, imd)
		lte->out_refcnt = 0;

	/* Go through this image's inodes to find any streams that have not been
	 * found yet. */
	image_for_each_inode(inode, imd) {
		ret = inode_find_streams_to_write(inode, wim->lookup_table, ctx);
		if (ret)
			return ret;
	}
	return 0;
}

/*
 * Build a list of streams (via `struct wim_lookup_table_entry's) included in
 * the "logical write" of the WIM, meaning all streams that are referenced at
 * least once by dentries in the the image(s) being written.  'out_refcnt' on
 * each stream being included in the logical write is set to the number of
 * references from dentries in the image(s).  Furthermore, 'unique_size' on each
 * stream being included in the logical write is set to indicate whether that
 * stream has a unique size relative to the streams being included in the
 * logical write.  Still furthermore, 'part_number' on each stream being
 * included in the logical write is set to the part number given in the
 * in-memory header of @p wim.
 *
 * This is considered a "logical write" because it does not take into account
 * filtering out streams already present in the WIM (in the case of an in place
 * overwrite) or present in other WIMs (in case of creating delta WIM).
 */
static int
prepare_logical_stream_list(WIMStruct *wim, int image, bool streams_ok,
			    struct find_streams_ctx *ctx)
{
	int ret;
	struct wim_lookup_table_entry *lte;

	if (streams_ok && (image == WIMLIB_ALL_IMAGES ||
			   (image == 1 && wim->hdr.image_count == 1)))
	{
		/* Fast case:  Assume that all streams are being written and
		 * that the reference counts are correct.  */
		struct wim_lookup_table_entry *lte;
		struct wim_image_metadata *imd;
		unsigned i;

		for_lookup_table_entry(wim->lookup_table,
				       do_lte_full_reference_for_logical_write, ctx);
		for (i = 0; i < wim->hdr.image_count; i++) {
			imd = wim->image_metadata[i];
			image_for_each_unhashed_stream(lte, imd)
				do_lte_full_reference_for_logical_write(lte, ctx);
		}
	} else {
		/* Slow case:  Walk through the images being written and
		 * determine the streams referenced.  */
		for_lookup_table_entry(wim->lookup_table, lte_zero_out_refcnt, NULL);
		wim->private = ctx;
		ret = for_image(wim, image, image_find_streams_to_write);
		if (ret)
			return ret;
	}

	list_for_each_entry(lte, &ctx->stream_list, write_streams_list)
		lte->part_number = wim->hdr.part_number;
	return 0;
}

static int
process_filtered_stream(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct find_streams_ctx *ctx = _ctx;
	u16 filtered = 0;

	/* Calculate and set lte->filtered.  */
	if (lte->resource_location == RESOURCE_IN_WIM) {
		if (lte->wim == ctx->wim &&
		    (ctx->write_flags & WIMLIB_WRITE_FLAG_OVERWRITE))
			filtered |= FILTERED_SAME_WIM;
		if (lte->wim != ctx->wim &&
		    (ctx->write_flags & WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS))
			filtered |= FILTERED_EXTERNAL_WIM;
	}
	lte->filtered = filtered;

	/* Filtered streams get inserted into the stream size table too, unless
	 * they already were.  This is because streams that are checksummed
	 * on-the-fly during the write should not be written if they are
	 * duplicates of filtered stream.  */
	if (lte->filtered && lte->out_refcnt == 0)
		stream_size_table_insert(lte, &ctx->stream_size_tab);
	return 0;
}

static int
mark_stream_not_filtered(struct wim_lookup_table_entry *lte, void *_ignore)
{
	lte->filtered = 0;
	return 0;
}

/* Given the list of streams to include in a logical write of a WIM, handle
 * filtering out streams already present in the WIM or already present in
 * external WIMs, depending on the write flags provided.  */
static void
handle_stream_filtering(struct find_streams_ctx *ctx)
{
	struct wim_lookup_table_entry *lte, *tmp;

	if (!(ctx->write_flags & (WIMLIB_WRITE_FLAG_OVERWRITE |
				  WIMLIB_WRITE_FLAG_SKIP_EXTERNAL_WIMS)))
	{
		for_lookup_table_entry(ctx->wim->lookup_table,
				       mark_stream_not_filtered, ctx);
		return;
	}

	for_lookup_table_entry(ctx->wim->lookup_table,
			       process_filtered_stream, ctx);

	/* Streams in logical write list that were filtered can be removed.  */
	list_for_each_entry_safe(lte, tmp, &ctx->stream_list,
				 write_streams_list)
		if (lte->filtered)
			list_del(&lte->write_streams_list);
}

/* Prepares list of streams to write for the specified WIM image(s).  This wraps
 * around prepare_logical_stream_list() to handle filtering out streams already
 * present in the WIM or already present in external WIMs, depending on the
 * write flags provided.
 *
 * Note: some additional data is stored in each `struct wim_lookup_table_entry':
 *
 * - 'out_refcnt' is set to the number of references found for the logical write.
 *    This will be nonzero on all streams in the list returned by this function,
 *    but will also be nonzero on streams not in the list that were included in
 *    the logical write list, but filtered out from the returned list.
 * - 'filtered' is set to nonzero if the stream was filtered.  Filtered streams
 *   are not included in the list of streams returned by this function.
 * - 'unique_size' is set if the stream has a unique size among all streams in
 *   the logical write plus any filtered streams in the entire WIM that could
 *   potentially turn out to have the same checksum as a yet-to-be-checksummed
 *   stream being written.
 */
static int
prepare_stream_list(WIMStruct *wim, int image, int write_flags,
		    struct list_head *stream_list)
{
	int ret;
	bool streams_ok;
	struct find_streams_ctx ctx;

	INIT_LIST_HEAD(&ctx.stream_list);
	ret = init_stream_size_table(&ctx.stream_size_tab,
				     wim->lookup_table->capacity);
	if (ret)
		return ret;
	ctx.write_flags = write_flags;
	ctx.wim = wim;

	streams_ok = ((write_flags & WIMLIB_WRITE_FLAG_STREAMS_OK) != 0);

	ret = prepare_logical_stream_list(wim, image, streams_ok, &ctx);
	if (ret)
		goto out_destroy_table;

	handle_stream_filtering(&ctx);
	list_transfer(&ctx.stream_list, stream_list);
	ret = 0;
out_destroy_table:
	destroy_stream_size_table(&ctx.stream_size_tab);
	return ret;
}

static int
write_wim_streams(WIMStruct *wim, int image, int write_flags,
		  unsigned num_threads,
		  wimlib_progress_func_t progress_func,
		  struct list_head *stream_list_override)
{
	int ret;
	struct list_head _stream_list;
	struct list_head *stream_list;
	struct wim_lookup_table_entry *lte;

	if (stream_list_override == NULL) {
		/* Normal case: prepare stream list from image(s) being written.
		 */
		stream_list = &_stream_list;
		ret = prepare_stream_list(wim, image, write_flags, stream_list);
		if (ret)
			return ret;
	} else {
		/* Currently only as a result of wimlib_split() being called:
		 * use stream list already explicitly provided.  Use existing
		 * reference counts.  */
		stream_list = stream_list_override;
		list_for_each_entry(lte, stream_list, write_streams_list) {
			lte->out_refcnt = (lte->refcnt ? lte->refcnt : 1);
			lte->part_number = wim->hdr.part_number;
		}
	}

	return write_stream_list(stream_list,
				 wim->lookup_table,
				 &wim->out_fd,
				 wim->compression_type,
				 &wim->lzx_context,
				 write_flags,
				 num_threads,
				 progress_func);
}

static int
write_wim_metadata_resources(WIMStruct *wim, int image, int write_flags,
			     wimlib_progress_func_t progress_func)
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

	DEBUG("Writing metadata resources (offset=%"PRIu64")",
	      wim->out_fd.offset);

	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN, NULL);

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
			copy_resource_entry(&imd->metadata_lte->output_resource_entry,
					    &imd->metadata_lte->resource_entry);
			ret = 0;
		} else {
			DEBUG("Image %u was not modified; copying existing "
			      "metadata resource.", i);
			ret = write_wim_resource(imd->metadata_lte,
						 &wim->out_fd,
						 wim->compression_type,
						 &imd->metadata_lte->output_resource_entry,
						 write_resource_flags,
						 &wim->lzx_context);
		}
		if (ret)
			return ret;
	}
	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_METADATA_END, NULL);
	return 0;
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

	if (!(write_flags & WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR))
		if (filedes_valid(&wim->out_fd))
			if (filedes_close(&wim->out_fd))
				ret = WIMLIB_ERR_WRITE;
	filedes_invalidate(&wim->out_fd);
	return ret;
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
 *	(private) WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE:
 *		When (if) writing the integrity table, re-use entries from the
 *		existing integrity table, if possible.
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
 */
static int
finish_write(WIMStruct *wim, int image, int write_flags,
	     wimlib_progress_func_t progress_func,
	     struct list_head *stream_list_override)
{
	int ret;
	off_t hdr_offset;
	int write_resource_flags;
	off_t old_lookup_table_end;
	off_t new_lookup_table_end;
	u64 xml_totalbytes;

	write_resource_flags = write_flags_to_resource_flags(write_flags);

	/* In the WIM header, there is room for the resource entry for a
	 * metadata resource labeled as the "boot metadata".  This entry should
	 * be zeroed out if there is no bootable image (boot_idx 0).  Otherwise,
	 * it should be a copy of the resource entry for the image that is
	 * marked as bootable.  This is not well documented...  */
	if (wim->hdr.boot_idx == 0) {
		zero_resource_entry(&wim->hdr.boot_metadata_res_entry);
	} else {
		copy_resource_entry(&wim->hdr.boot_metadata_res_entry,
			    &wim->image_metadata[wim->hdr.boot_idx- 1
					]->metadata_lte->output_resource_entry);
	}

	/* Write lookup table.  (Save old position first.)  */
	old_lookup_table_end = wim->hdr.lookup_table_res_entry.offset +
			       wim->hdr.lookup_table_res_entry.size;
	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE)) {
		ret = write_wim_lookup_table(wim, image, write_flags,
					     &wim->hdr.lookup_table_res_entry,
					     stream_list_override);
		if (ret)
			return ret;
	}

	/* Write XML data.  */
	xml_totalbytes = wim->out_fd.offset;
	if (write_flags & WIMLIB_WRITE_FLAG_USE_EXISTING_TOTALBYTES)
		xml_totalbytes = WIM_TOTALBYTES_USE_EXISTING;
	ret = write_wim_xml_data(wim, image, xml_totalbytes,
				 &wim->hdr.xml_res_entry,
				 write_resource_flags);
	if (ret)
		return ret;

	/* Write integrity table (optional).  */
	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
		if (write_flags & WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML) {
			struct wim_header checkpoint_hdr;
			memcpy(&checkpoint_hdr, &wim->hdr, sizeof(struct wim_header));
			zero_resource_entry(&checkpoint_hdr.integrity);
			checkpoint_hdr.flags |= WIM_HDR_FLAG_WRITE_IN_PROGRESS;
			ret = write_wim_header_at_offset(&checkpoint_hdr,
							 &wim->out_fd, 0);
			if (ret)
				return ret;
		}

		if (!(write_flags & WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE))
			old_lookup_table_end = 0;

		new_lookup_table_end = wim->hdr.lookup_table_res_entry.offset +
				       wim->hdr.lookup_table_res_entry.size;

		ret = write_integrity_table(wim,
					    new_lookup_table_end,
					    old_lookup_table_end,
					    progress_func);
		if (ret)
			return ret;
	} else {
		/* No integrity table.  */
		zero_resource_entry(&wim->hdr.integrity);
	}

	/* Now that all information in the WIM header has been determined, the
	 * preliminary header written earlier can be overwritten, the header of
	 * the existing WIM file can be overwritten, or the final header can be
	 * written to the end of the pipable WIM.  */
	wim->hdr.flags &= ~WIM_HDR_FLAG_WRITE_IN_PROGRESS;
	hdr_offset = 0;
	if (write_flags & WIMLIB_WRITE_FLAG_HEADER_AT_END)
		hdr_offset = wim->out_fd.offset;
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
int
lock_wim(WIMStruct *wim, int fd)
{
	int ret = 0;
	if (fd != -1 && !wim->wim_locked) {
		ret = flock(fd, LOCK_EX | LOCK_NB);
		if (ret != 0) {
			if (errno == EWOULDBLOCK) {
				ERROR("`%"TS"' is already being modified or has been "
				      "mounted read-write\n"
				      "        by another process!", wim->filename);
				ret = WIMLIB_ERR_ALREADY_LOCKED;
			} else {
				WARNING_WITH_ERRNO("Failed to lock `%"TS"'",
						   wim->filename);
				ret = 0;
			}
		} else {
			wim->wim_locked = 1;
		}
	}
	return ret;
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
		  unsigned num_threads, wimlib_progress_func_t progress_func,
		  struct list_head *stream_list_override)
{
	int ret;
	struct resource_entry xml_res_entry;

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
				 &xml_res_entry,
				 WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE);
	if (ret)
		return ret;

	/* Write metadata resources for the image(s) being included in the
	 * output WIM.  */
	ret = write_wim_metadata_resources(wim, image, write_flags,
					   progress_func);
	if (ret)
		return ret;

	/* Write streams needed for the image(s) being included in the output
	 * WIM, or streams needed for the split WIM part.  */
	return write_wim_streams(wim, image, write_flags, num_threads,
				 progress_func, stream_list_override);

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
	       wimlib_progress_func_t progress_func,
	       unsigned part_number,
	       unsigned total_parts,
	       struct list_head *stream_list_override,
	       const u8 *guid)
{
	int ret;
	struct wim_header hdr_save;
	struct list_head lt_stream_list_override;

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
	if (write_flags & WIMLIB_WRITE_FLAG_REBUILD)
		DEBUG("\tREBUILD");
	if (write_flags & WIMLIB_WRITE_FLAG_RECOMPRESS)
		DEBUG("\tRECOMPRESS");
	if (write_flags & WIMLIB_WRITE_FLAG_FSYNC)
		DEBUG("\tFSYNC");
	if (write_flags & WIMLIB_WRITE_FLAG_SOFT_DELETE)
		DEBUG("\tFSYNC");
	if (write_flags & WIMLIB_WRITE_FLAG_IGNORE_READONLY_FLAG)
		DEBUG("\tIGNORE_READONLY_FLAG");
	if (write_flags & WIMLIB_WRITE_FLAG_PIPABLE)
		DEBUG("\tPIPABLE");
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
	DEBUG("Progress function: %s", (progress_func ? "yes" : "no"));
	DEBUG("Stream list:       %s", (stream_list_override ? "specified" : "autodetect"));
	DEBUG("GUID:              %s", ((guid || wim->guid_set_explicitly) ?
					"specified" : "generate new"));

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

	/* Set default integrity and pipable flags.  */
	if (!(write_flags & (WIMLIB_WRITE_FLAG_PIPABLE |
			     WIMLIB_WRITE_FLAG_NOT_PIPABLE)))
		if (wim_is_pipable(wim))
			write_flags |= WIMLIB_WRITE_FLAG_PIPABLE;

	if (!(write_flags & (WIMLIB_WRITE_FLAG_CHECK_INTEGRITY |
			     WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY)))
		if (wim_has_integrity_table(wim))
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;

	/* Set appropriate magic number.  */
	if (write_flags & WIMLIB_WRITE_FLAG_PIPABLE)
		wim->hdr.magic = PWM_MAGIC;
	else
		wim->hdr.magic = WIM_MAGIC;

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

	/* Use GUID if specified; otherwise generate a new one.  */
	if (guid)
		memcpy(wim->hdr.guid, guid, WIMLIB_GUID_LEN);
	else if (!wim->guid_set_explicitly)
		randomize_byte_array(wim->hdr.guid, WIMLIB_GUID_LEN);

	/* Clear references to resources that have not been written yet.  */
	zero_resource_entry(&wim->hdr.lookup_table_res_entry);
	zero_resource_entry(&wim->hdr.xml_res_entry);
	zero_resource_entry(&wim->hdr.boot_metadata_res_entry);
	zero_resource_entry(&wim->hdr.integrity);

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

	if (stream_list_override) {
		struct wim_lookup_table_entry *lte;
		INIT_LIST_HEAD(&lt_stream_list_override);
		list_for_each_entry(lte, stream_list_override,
				    write_streams_list)
		{
			list_add_tail(&lte->lookup_table_list,
				      &lt_stream_list_override);
		}
	}

	/* Write metadata resources and streams.  */
	if (!(write_flags & WIMLIB_WRITE_FLAG_PIPABLE)) {
		/* Default case: create a normal (non-pipable) WIM.  */
		ret = write_wim_streams(wim, image, write_flags, num_threads,
					progress_func, stream_list_override);
		if (ret)
			goto out_restore_hdr;

		ret = write_wim_metadata_resources(wim, image, write_flags,
						   progress_func);
		if (ret)
			goto out_restore_hdr;
	} else {
		/* Non-default case: create pipable WIM.  */
		ret = write_pipable_wim(wim, image, write_flags, num_threads,
					progress_func, stream_list_override);
		if (ret)
			goto out_restore_hdr;
		write_flags |= WIMLIB_WRITE_FLAG_HEADER_AT_END;
	}

	if (stream_list_override)
		stream_list_override = &lt_stream_list_override;

	/* Write lookup table, XML data, and (optional) integrity table.  */
	ret = finish_write(wim, image, write_flags, progress_func,
			   stream_list_override);
out_restore_hdr:
	memcpy(&wim->hdr, &hdr_save, sizeof(struct wim_header));
	(void)close_wim_writable(wim, write_flags);
	return ret;
}

/* Write a standalone WIM to a file or file descriptor.  */
static int
write_standalone_wim(WIMStruct *wim, const void *path_or_fd,
		     int image, int write_flags, unsigned num_threads,
		     wimlib_progress_func_t progress_func)
{
	return write_wim_part(wim, path_or_fd, image, write_flags,
			      num_threads, progress_func, 1, 1, NULL, NULL);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_write(WIMStruct *wim, const tchar *path,
	     int image, int write_flags, unsigned num_threads,
	     wimlib_progress_func_t progress_func)
{
	if (!path)
		return WIMLIB_ERR_INVALID_PARAM;

	write_flags &= WIMLIB_WRITE_MASK_PUBLIC;

	return write_standalone_wim(wim, path, image, write_flags,
				    num_threads, progress_func);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_write_to_fd(WIMStruct *wim, int fd,
		   int image, int write_flags, unsigned num_threads,
		   wimlib_progress_func_t progress_func)
{
	if (fd < 0)
		return WIMLIB_ERR_INVALID_PARAM;

	write_flags &= WIMLIB_WRITE_MASK_PUBLIC;
	write_flags |= WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR;

	return write_standalone_wim(wim, &fd, image, write_flags,
				    num_threads, progress_func);
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

	if (lte->resource_location == RESOURCE_IN_WIM && lte->wim == wim &&
	    lte->resource_entry.offset + lte->resource_entry.size > end_offset)
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
 * is is crash-safe except in the case of write re-ordering, but the
 * disadvantage is that a small hole is left in the WIM where the old lookup
 * table, xml data, and integrity table were.  (These usually only take up a
 * small amount of space compared to the streams, however.)
 */
static int
overwrite_wim_inplace(WIMStruct *wim, int write_flags,
		      unsigned num_threads,
		      wimlib_progress_func_t progress_func)
{
	int ret;
	struct list_head stream_list;
	off_t old_wim_end;
	u64 old_lookup_table_end, old_xml_begin, old_xml_end;
	struct wim_header hdr_save;

	DEBUG("Overwriting `%"TS"' in-place", wim->filename);

	/* Set default integrity flag.  */
	if (!(write_flags & (WIMLIB_WRITE_FLAG_CHECK_INTEGRITY |
			     WIMLIB_WRITE_FLAG_NO_CHECK_INTEGRITY)))
		if (wim_has_integrity_table(wim))
			write_flags |= WIMLIB_WRITE_FLAG_CHECK_INTEGRITY;

	/* Set additional flags for overwrite.  */
	write_flags |= WIMLIB_WRITE_FLAG_OVERWRITE |
		       WIMLIB_WRITE_FLAG_STREAMS_OK;

	/* Make sure that the integrity table (if present) is after the XML
	 * data, and that there are no stream resources, metadata resources, or
	 * lookup tables after the XML data.  Otherwise, these data would be
	 * overwritten. */
	old_xml_begin = wim->hdr.xml_res_entry.offset;
	old_xml_end = old_xml_begin + wim->hdr.xml_res_entry.size;
	old_lookup_table_end = wim->hdr.lookup_table_res_entry.offset +
			       wim->hdr.lookup_table_res_entry.size;
	if (wim->hdr.integrity.offset != 0 && wim->hdr.integrity.offset < old_xml_end) {
		WARNING("Didn't expect the integrity table to be before the XML data");
		return WIMLIB_ERR_RESOURCE_ORDER;
	}

	if (old_lookup_table_end > old_xml_begin) {
		WARNING("Didn't expect the lookup table to be after the XML data");
		return WIMLIB_ERR_RESOURCE_ORDER;
	}

	/* Set @old_wim_end, which indicates the point beyond which we don't
	 * allow any file and metadata resources to appear without returning
	 * WIMLIB_ERR_RESOURCE_ORDER (due to the fact that we would otherwise
	 * overwrite these resources). */
	if (!wim->deletion_occurred && !any_images_modified(wim)) {
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
	} else if (wim->hdr.integrity.offset) {
		/* Old WIM has an integrity table; begin writing new streams
		 * after it. */
		old_wim_end = wim->hdr.integrity.offset + wim->hdr.integrity.size;
	} else {
		/* No existing integrity table; begin writing new streams after
		 * the old XML data. */
		old_wim_end = old_xml_end;
	}

	ret = check_resource_offsets(wim, old_wim_end);
	if (ret)
		return ret;

	ret = prepare_stream_list(wim, WIMLIB_ALL_IMAGES, write_flags,
				  &stream_list);
	if (ret)
		return ret;

	ret = open_wim_writable(wim, wim->filename, O_RDWR);
	if (ret)
		return ret;

	ret = lock_wim(wim, wim->out_fd.fd);
	if (ret)
		goto out_close_wim;

	/* Save original header so it can be restored in case of error  */
	memcpy(&hdr_save, &wim->hdr, sizeof(struct wim_header));

	/* Set WIM_HDR_FLAG_WRITE_IN_PROGRESS flag in header. */
	wim->hdr.flags |= WIM_HDR_FLAG_WRITE_IN_PROGRESS;
	ret = write_wim_header_flags(wim->hdr.flags, &wim->out_fd);
	if (ret) {
		ERROR_WITH_ERRNO("Error updating WIM header flags");
		goto out_restore_memory_hdr;
	}

	if (filedes_seek(&wim->out_fd, old_wim_end) == -1) {
		ERROR_WITH_ERRNO("Can't seek to end of WIM");
		ret = WIMLIB_ERR_WRITE;
		goto out_restore_physical_hdr;
	}

	ret = write_stream_list(&stream_list,
				wim->lookup_table,
				&wim->out_fd,
				wim->compression_type,
				&wim->lzx_context,
				write_flags,
				num_threads,
				progress_func);
	if (ret)
		goto out_truncate;

	ret = write_wim_metadata_resources(wim, WIMLIB_ALL_IMAGES,
					   write_flags, progress_func);
	if (ret)
		goto out_truncate;

	write_flags |= WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE;
	ret = finish_write(wim, WIMLIB_ALL_IMAGES, write_flags,
			   progress_func, NULL);
	if (ret)
		goto out_truncate;

	goto out_unlock_wim;

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
out_restore_memory_hdr:
	memcpy(&wim->hdr, &hdr_save, sizeof(struct wim_header));
out_close_wim:
	(void)close_wim_writable(wim, write_flags);
out_unlock_wim:
	wim->wim_locked = 0;
	return ret;
}

static int
overwrite_wim_via_tmpfile(WIMStruct *wim, int write_flags,
			  unsigned num_threads,
			  wimlib_progress_func_t progress_func)
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
			   write_flags | WIMLIB_WRITE_FLAG_FSYNC,
			   num_threads, progress_func);
	if (ret) {
		tunlink(tmpfile);
		return ret;
	}

	close_wim(wim);

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

	if (progress_func) {
		union wimlib_progress_info progress;
		progress.rename.from = tmpfile;
		progress.rename.to = wim->filename;
		progress_func(WIMLIB_PROGRESS_MSG_RENAME, &progress);
	}
	return 0;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_overwrite(WIMStruct *wim, int write_flags,
		 unsigned num_threads,
		 wimlib_progress_func_t progress_func)
{
	int ret;
	u32 orig_hdr_flags;

	write_flags &= WIMLIB_WRITE_MASK_PUBLIC;

	if (write_flags & WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR)
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

	if ((!wim->deletion_occurred || (write_flags & WIMLIB_WRITE_FLAG_SOFT_DELETE))
	    && !(write_flags & (WIMLIB_WRITE_FLAG_REBUILD |
				WIMLIB_WRITE_FLAG_PIPABLE))
	    && !(wim_is_pipable(wim)))
	{
		ret = overwrite_wim_inplace(wim, write_flags, num_threads,
					    progress_func);
		if (ret != WIMLIB_ERR_RESOURCE_ORDER)
			return ret;
		WARNING("Falling back to re-building entire WIM");
	}
	return overwrite_wim_via_tmpfile(wim, write_flags, num_threads,
					 progress_func);
}
