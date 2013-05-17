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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#ifdef WITH_NTFS_3G
#  include <time.h>
#  include <ntfs-3g/attrib.h>
#  include <ntfs-3g/inode.h>
#  include <ntfs-3g/dir.h>
#endif

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#else
#  include <stdlib.h>
#endif

#include <limits.h>

#ifndef __WIN32__
#  include <sys/uio.h> /* for `struct iovec' */
#endif

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
	union {
		u64 offsets[0];
		u32 u32_offsets[0];
	};
};

/*
 * Allocates and initializes a chunk table, and reserves space for it in the
 * output file.
 */
static int
begin_wim_resource_chunk_tab(const struct wim_lookup_table_entry *lte,
			     int out_fd,
			     off_t file_offset,
			     struct chunk_table **chunk_tab_ret)
{
	u64 size = wim_resource_size(lte);
	u64 num_chunks = (size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;
	size_t alloc_size = sizeof(struct chunk_table) + num_chunks * sizeof(u64);
	struct chunk_table *chunk_tab = CALLOC(1, alloc_size);

	DEBUG("Begin chunk table for stream with size %"PRIu64, size);

	if (!chunk_tab) {
		ERROR("Failed to allocate chunk table for %"PRIu64" byte "
		      "resource", size);
		return WIMLIB_ERR_NOMEM;
	}
	chunk_tab->file_offset = file_offset;
	chunk_tab->num_chunks = num_chunks;
	chunk_tab->original_resource_size = size;
	chunk_tab->bytes_per_chunk_entry = (size >= (1ULL << 32)) ? 8 : 4;
	chunk_tab->table_disk_size = chunk_tab->bytes_per_chunk_entry *
				     (num_chunks - 1);
	chunk_tab->cur_offset = 0;
	chunk_tab->cur_offset_p = chunk_tab->offsets;

	if (full_write(out_fd, chunk_tab,
		       chunk_tab->table_disk_size) != chunk_tab->table_disk_size)
	{
		ERROR_WITH_ERRNO("Failed to write chunk table in compressed "
				 "file resource");
		FREE(chunk_tab);
		return WIMLIB_ERR_WRITE;
	}
	*chunk_tab_ret = chunk_tab;
	return 0;
}

/*
 * compress_func_t- Pointer to a function to compresses a chunk
 *                  of a WIM resource.  This may be either
 *                  wimlib_xpress_compress() (xpress-compress.c) or
 *                  wimlib_lzx_compress() (lzx-compress.c).
 *
 * @chunk:	  Uncompressed data of the chunk.
 * @chunk_size:	  Size of the uncompressed chunk, in bytes.
 * @out:	  Pointer to output buffer of size at least (@chunk_size - 1) bytes.
 *
 * Returns the size of the compressed data written to @out in bytes, or 0 if the
 * data could not be compressed to (@chunk_size - 1) bytes or fewer.
 *
 * As a special requirement, the compression code is optimized for the WIM
 * format and therefore requires (@chunk_size <= 32768).
 *
 * As another special requirement, the compression code will read up to 8 bytes
 * off the end of the @chunk array for performance reasons.  The values of these
 * bytes will not affect the output of the compression, but the calling code
 * must make sure that the buffer holding the uncompressed chunk is actually at
 * least (@chunk_size + 8) bytes, or at least that these extra bytes are in
 * mapped memory that will not cause a memory access violation if accessed.
 */
typedef unsigned (*compress_func_t)(const void *chunk, unsigned chunk_size,
				    void *out);

static compress_func_t
get_compress_func(int out_ctype)
{
	if (out_ctype == WIMLIB_COMPRESSION_TYPE_LZX)
		return wimlib_lzx_compress;
	else
		return wimlib_xpress_compress;
}

/*
 * Writes a chunk of a WIM resource to an output file.
 *
 * @chunk:	  Uncompressed data of the chunk.
 * @chunk_size:	  Size of the chunk (<= WIM_CHUNK_SIZE)
 * @out_fd:	  File descriptor to write the chunk to.
 * @compress:     Compression function to use (NULL if writing uncompressed
 *			data).
 * @chunk_tab:	  Pointer to chunk table being created.  It is updated with the
 * 			offset of the chunk we write.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
write_wim_resource_chunk(const void * restrict chunk,
			 unsigned chunk_size,
			 int out_fd,
			 compress_func_t compress,
			 struct chunk_table * restrict chunk_tab)
{
	const void *out_chunk;
	unsigned out_chunk_size;
	if (compress) {
		void *compressed_chunk = alloca(chunk_size);

		out_chunk_size = (*compress)(chunk, chunk_size, compressed_chunk);
		if (out_chunk_size) {
			/* Write compressed */
			out_chunk = compressed_chunk;
		} else {
			/* Write uncompressed */
			out_chunk = chunk;
			out_chunk_size = chunk_size;
		}
		*chunk_tab->cur_offset_p++ = chunk_tab->cur_offset;
		chunk_tab->cur_offset += out_chunk_size;
	} else {
		/* Write uncompressed */
		out_chunk = chunk;
		out_chunk_size = chunk_size;
	}
	if (full_write(out_fd, out_chunk, out_chunk_size) != out_chunk_size) {
		ERROR_WITH_ERRNO("Failed to write WIM resource chunk");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/*
 * Finishes a WIM chunk table and writes it to the output file at the correct
 * offset.
 *
 * The final size of the full compressed resource is returned in the
 * @compressed_size_p.
 */
static int
finish_wim_resource_chunk_tab(struct chunk_table *chunk_tab,
			      int out_fd, u64 *compressed_size_p)
{
	size_t bytes_written;

	if (chunk_tab->bytes_per_chunk_entry == 8) {
		array_cpu_to_le64(chunk_tab->offsets, chunk_tab->num_chunks);
	} else {
		for (u64 i = 0; i < chunk_tab->num_chunks; i++)
			chunk_tab->u32_offsets[i] = cpu_to_le32(chunk_tab->offsets[i]);
	}
	bytes_written = full_pwrite(out_fd,
				    (u8*)chunk_tab->offsets + chunk_tab->bytes_per_chunk_entry,
				    chunk_tab->table_disk_size,
				    chunk_tab->file_offset);
	if (bytes_written != chunk_tab->table_disk_size) {
		ERROR_WITH_ERRNO("Failed to write chunk table in compressed "
				 "file resource");
		return WIMLIB_ERR_WRITE;
	}
	*compressed_size_p = chunk_tab->cur_offset + chunk_tab->table_disk_size;
	return 0;
}

static int
seek_and_truncate(int out_fd, off_t offset)
{
	if (lseek(out_fd, offset, SEEK_SET) == -1 ||
	    ftruncate(out_fd, offset))
	{
		ERROR_WITH_ERRNO("Failed to truncate output WIM file");
		return WIMLIB_ERR_WRITE;
	} else {
		return 0;
	}
}

static int
finalize_and_check_sha1(SHA_CTX * restrict sha_ctx,
			struct wim_lookup_table_entry * restrict lte)
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
	compress_func_t compress;
	struct chunk_table *chunk_tab;
	int out_fd;
	SHA_CTX sha_ctx;
	bool doing_sha;
};

static int
write_resource_cb(const void *restrict chunk, size_t chunk_size,
		  void *restrict _ctx)
{
	struct write_resource_ctx *ctx = _ctx;

	if (ctx->doing_sha)
		sha1_update(&ctx->sha_ctx, chunk, chunk_size);
	return write_wim_resource_chunk(chunk, chunk_size,
					ctx->out_fd, ctx->compress,
					ctx->chunk_tab);
}

/*
 * Write a resource to an output WIM.
 *
 * @lte:  Lookup table entry for the resource, which could be in another WIM,
 *        in an external file, or in another location.
 *
 * @out_fd:  File descriptor opened to the output WIM.
 *
 * @out_ctype:  One of the WIMLIB_COMPRESSION_TYPE_* constants to indicate
 *              which compression algorithm to use.
 *
 * @out_res_entry:  On success, this is filled in with the offset, flags,
 *                  compressed size, and uncompressed size of the resource
 *                  in the output WIM.
 *
 * @flags:  WIMLIB_RESOURCE_FLAG_RECOMPRESS to force data to be recompressed
 *          even if it could otherwise be copied directly from the input.
 *
 * Additional notes:  The SHA1 message digest of the uncompressed data is
 * calculated (except when doing a raw copy --- see below).  If the @unhashed
 * flag is set on the lookup table entry, this message digest is simply copied
 * to it; otherwise, the message digest is compared with the existing one, and
 * the function will fail if they do not match.
 */
int
write_wim_resource(struct wim_lookup_table_entry *lte,
		   int out_fd, int out_ctype,
		   struct resource_entry *out_res_entry,
		   int flags)
{
	struct write_resource_ctx write_ctx;
	u64 read_size;
	u64 new_size;
	off_t offset;
	int ret;

	flags &= ~WIMLIB_RESOURCE_FLAG_RECOMPRESS;

	/* Get current position in output WIM */
	offset = filedes_offset(out_fd);
	if (offset == -1) {
		ERROR_WITH_ERRNO("Can't get position in output WIM");
		return WIMLIB_ERR_WRITE;
	}

	/* If we are not forcing the data to be recompressed, and the input
	 * resource is located in a WIM with the same compression type as that
	 * desired other than no compression, we can simply copy the compressed
	 * data without recompressing it.  This also means we must skip
	 * calculating the SHA1, as we never will see the uncompressed data. */
	if (!(flags & WIMLIB_RESOURCE_FLAG_RECOMPRESS) &&
	    lte->resource_location == RESOURCE_IN_WIM &&
	    out_ctype != WIMLIB_COMPRESSION_TYPE_NONE &&
	    wimlib_get_compression_type(lte->wim) == out_ctype)
	{
		flags |= WIMLIB_RESOURCE_FLAG_RAW;
		write_ctx.doing_sha = false;
		read_size = lte->resource_entry.size;
	} else {
		write_ctx.doing_sha = true;
		sha1_init(&write_ctx.sha_ctx);
		read_size = lte->resource_entry.original_size;
	}

	/* Initialize the chunk table and set the compression function if
	 * compressing the resource. */
	if (out_ctype == WIMLIB_COMPRESSION_TYPE_NONE ||
	    (flags & WIMLIB_RESOURCE_FLAG_RAW)) {
		write_ctx.compress = NULL;
		write_ctx.chunk_tab = NULL;
	} else {
		write_ctx.compress = get_compress_func(out_ctype);
		ret = begin_wim_resource_chunk_tab(lte, out_fd,
						   offset,
						   &write_ctx.chunk_tab);
		if (ret)
			return ret;
	}

	/* Write the entire resource by reading the entire resource and feeding
	 * the data through the write_resource_cb function. */
	write_ctx.out_fd = out_fd;
try_write_again:
	ret = read_resource_prefix(lte, read_size,
				   write_resource_cb, &write_ctx, flags);
	if (ret)
		goto out_free_chunk_tab;

	/* Verify SHA1 message digest of the resource, or set the hash for the
	 * first time. */
	if (write_ctx.doing_sha) {
		ret = finalize_and_check_sha1(&write_ctx.sha_ctx, lte);
		if (ret)
			goto out_free_chunk_tab;
	}

	out_res_entry->flags = lte->resource_entry.flags;
	out_res_entry->original_size = wim_resource_size(lte);
	out_res_entry->offset = offset;
	if (flags & WIMLIB_RESOURCE_FLAG_RAW) {
		/* Doing a raw write:  The new compressed size is the same as
		 * the compressed size in the other WIM. */
		new_size = lte->resource_entry.size;
	} else if (out_ctype == WIMLIB_COMPRESSION_TYPE_NONE) {
		/* Using WIMLIB_COMPRESSION_TYPE_NONE:  The new compressed size
		 * is the original size. */
		new_size = lte->resource_entry.original_size;
		out_res_entry->flags &= ~WIM_RESHDR_FLAG_COMPRESSED;
	} else {
		/* Using a different compression type:  Call
		 * finish_wim_resource_chunk_tab() and it will provide the new
		 * compressed size. */
		ret = finish_wim_resource_chunk_tab(write_ctx.chunk_tab, out_fd,
						    &new_size);
		if (ret)
			goto out_free_chunk_tab;
		if (new_size >= wim_resource_size(lte)) {
			/* Oops!  We compressed the resource to larger than the original
			 * size.  Write the resource uncompressed instead. */
			DEBUG("Compressed %"PRIu64" => %"PRIu64" bytes; "
			      "writing uncompressed instead",
			      wim_resource_size(lte), new_size);
			ret = seek_and_truncate(out_fd, offset);
			if (ret)
				goto out_free_chunk_tab;
			write_ctx.compress = NULL;
			write_ctx.doing_sha = false;
			out_ctype = WIMLIB_COMPRESSION_TYPE_NONE;
			goto try_write_again;
		}
		out_res_entry->flags |= WIM_RESHDR_FLAG_COMPRESSED;
	}
	out_res_entry->size = new_size;
	ret = 0;
out_free_chunk_tab:
	FREE(write_ctx.chunk_tab);
	return ret;
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
	compress_func_t compress;
};

#define MAX_CHUNKS_PER_MSG 2

struct message {
	struct wim_lookup_table_entry *lte;
	u8 *uncompressed_chunks[MAX_CHUNKS_PER_MSG];
	u8 *compressed_chunks[MAX_CHUNKS_PER_MSG];
	unsigned uncompressed_chunk_sizes[MAX_CHUNKS_PER_MSG];
	struct iovec out_chunks[MAX_CHUNKS_PER_MSG];
	size_t total_out_bytes;
	unsigned num_chunks;
	struct list_head list;
	bool complete;
	u64 begin_chunk;
};

static void
compress_chunks(struct message *msg, compress_func_t compress)
{
	msg->total_out_bytes = 0;
	for (unsigned i = 0; i < msg->num_chunks; i++) {
		unsigned len = compress(msg->uncompressed_chunks[i],
					msg->uncompressed_chunk_sizes[i],
					msg->compressed_chunks[i]);
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
		msg->total_out_bytes += out_len;
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
	compress_func_t compress = params->compress;
	struct message *msg;

	DEBUG("Compressor thread ready");
	while ((msg = shared_queue_get(res_to_compress_queue)) != NULL) {
		compress_chunks(msg, compress);
		shared_queue_put(compressed_res_queue, msg);
	}
	DEBUG("Compressor thread terminating");
	return NULL;
}
#endif /* ENABLE_MULTITHREADED_COMPRESSION */

static void
do_write_streams_progress(union wimlib_progress_info *progress,
			  wimlib_progress_func_t progress_func,
			  uint64_t size_added,
			  bool stream_discarded)
{
	if (stream_discarded) {
		progress->write_streams.total_bytes -= size_added;
		if (progress->write_streams._private != ~(uint64_t)0 &&
		    progress->write_streams._private > progress->write_streams.total_bytes)
		{
			progress->write_streams._private = progress->write_streams.total_bytes;
		}
	} else {
		progress->write_streams.completed_bytes += size_added;
	}
	progress->write_streams.completed_streams++;
	if (progress_func &&
	    progress->write_streams.completed_bytes >= progress->write_streams._private)
	{
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
			      progress);
		if (progress->write_streams._private == progress->write_streams.total_bytes) {
			progress->write_streams._private = ~(uint64_t)0;
		} else {
			progress->write_streams._private =
				min(progress->write_streams.total_bytes,
				    progress->write_streams.completed_bytes +
				        progress->write_streams.total_bytes / 100);
		}
	}
}

struct serial_write_stream_ctx {
	int out_fd;
	int out_ctype;
	int write_resource_flags;
};

static int
serial_write_stream(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct serial_write_stream_ctx *ctx = _ctx;
	return write_wim_resource(lte, ctx->out_fd,
				  ctx->out_ctype, &lte->output_resource_entry,
				  ctx->write_resource_flags);
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
		     wimlib_progress_func_t progress_func,
		     union wimlib_progress_info *progress)
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
			u32 orig_refcnt = lte->out_refcnt;

			ret = hash_unhashed_stream(lte, lookup_table, &tmp);
			if (ret)
				break;
			if (tmp != lte) {
				lte = tmp;
				/* We found a duplicate stream. */
				if (orig_refcnt != tmp->out_refcnt) {
					/* We have already written, or are going
					 * to write, the duplicate stream.  So
					 * just skip to the next stream. */
					DEBUG("Discarding duplicate stream of length %"PRIu64,
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
			do_write_streams_progress(progress,
						  progress_func,
						  wim_resource_size(lte),
						  stream_discarded);
		}
	}
	return ret;
}

static int
do_write_stream_list_serial(struct list_head *stream_list,
			    struct wim_lookup_table *lookup_table,
			    int out_fd,
			    int out_ctype,
			    int write_resource_flags,
			    wimlib_progress_func_t progress_func,
			    union wimlib_progress_info *progress)
{
	struct serial_write_stream_ctx ctx = {
		.out_fd = out_fd,
		.out_ctype = out_ctype,
		.write_resource_flags = write_resource_flags,
	};
	return do_write_stream_list(stream_list,
				    lookup_table,
				    serial_write_stream,
				    &ctx,
				    progress_func,
				    progress);
}

static inline int
write_flags_to_resource_flags(int write_flags)
{
	int resource_flags = 0;

	if (write_flags & WIMLIB_WRITE_FLAG_RECOMPRESS)
		resource_flags |= WIMLIB_RESOURCE_FLAG_RECOMPRESS;
	return resource_flags;
}

static int
write_stream_list_serial(struct list_head *stream_list,
			 struct wim_lookup_table *lookup_table,
			 int out_fd,
			 int out_ctype,
			 int write_resource_flags,
			 wimlib_progress_func_t progress_func,
			 union wimlib_progress_info *progress)
{
	DEBUG("Writing stream list (serial version)");
	progress->write_streams.num_threads = 1;
	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS, progress);
	return do_write_stream_list_serial(stream_list,
					   lookup_table,
					   out_fd,
					   out_ctype,
					   write_resource_flags,
					   progress_func,
					   progress);
}

#ifdef ENABLE_MULTITHREADED_COMPRESSION
static int
write_wim_chunks(struct message *msg, int out_fd,
		 struct chunk_table *chunk_tab)
{
	for (unsigned i = 0; i < msg->num_chunks; i++) {
		*chunk_tab->cur_offset_p++ = chunk_tab->cur_offset;
		chunk_tab->cur_offset += msg->out_chunks[i].iov_len;
	}
	if (full_writev(out_fd, msg->out_chunks,
			msg->num_chunks) != msg->total_out_bytes)
	{
		ERROR_WITH_ERRNO("Failed to write WIM chunks");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

struct main_writer_thread_ctx {
	struct list_head *stream_list;
	struct wim_lookup_table *lookup_table;
	int out_fd;
	int out_ctype;
	int write_resource_flags;
	struct shared_queue *res_to_compress_queue;
	struct shared_queue *compressed_res_queue;
	size_t num_messages;
	wimlib_progress_func_t progress_func;
	union wimlib_progress_info *progress;

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
			/* This is the first set of chunks.  Leave space
			 * for the chunk table in the output file. */
			off_t cur_offset = filedes_offset(ctx->out_fd);
			if (cur_offset == -1)
				return WIMLIB_ERR_WRITE;
			ret = begin_wim_resource_chunk_tab(cur_lte,
							   ctx->out_fd,
							   cur_offset,
							   &ctx->cur_chunk_tab);
			if (ret)
				return ret;
		}

		/* Write the compressed chunks from the message. */
		ret = write_wim_chunks(msg, ctx->out_fd, ctx->cur_chunk_tab);
		if (ret)
			return ret;

		/* Was this the last chunk of the stream?  If so, finish
		 * it. */
		if (list_empty(&cur_lte->msg_list) &&
		    msg->begin_chunk + msg->num_chunks == ctx->cur_chunk_tab->num_chunks)
		{
			u64 res_csize;
			off_t offset;

			ret = finish_wim_resource_chunk_tab(ctx->cur_chunk_tab,
							    ctx->out_fd,
							    &res_csize);
			if (ret)
				return ret;

			list_del(&cur_lte->being_compressed_list);

			/* Grab the offset of this stream in the output file
			 * from the chunk table before we free it. */
			offset = ctx->cur_chunk_tab->file_offset;

			FREE(ctx->cur_chunk_tab);
			ctx->cur_chunk_tab = NULL;

			if (res_csize >= wim_resource_size(cur_lte)) {
				/* Oops!  We compressed the resource to
				 * larger than the original size.  Write
				 * the resource uncompressed instead. */
				DEBUG("Compressed %"PRIu64" => %"PRIu64" bytes; "
				      "writing uncompressed instead",
				      wim_resource_size(cur_lte), res_csize);
				ret = seek_and_truncate(ctx->out_fd, offset);
				if (ret)
					return ret;
				ret = write_wim_resource(cur_lte,
							 ctx->out_fd,
							 WIMLIB_COMPRESSION_TYPE_NONE,
							 &cur_lte->output_resource_entry,
							 ctx->write_resource_flags);
				if (ret)
					return ret;
			} else {
				cur_lte->output_resource_entry.size =
					res_csize;

				cur_lte->output_resource_entry.original_size =
					cur_lte->resource_entry.original_size;

				cur_lte->output_resource_entry.offset =
					offset;

				cur_lte->output_resource_entry.flags =
					cur_lte->resource_entry.flags |
						WIM_RESHDR_FLAG_COMPRESSED;
			}

			do_write_streams_progress(ctx->progress,
						  ctx->progress_func,
						  wim_resource_size(cur_lte),
						  false);

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
								  ctx->write_resource_flags,
								  ctx->progress_func,
								  ctx->progress);
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
					   ctx->write_resource_flags,
					   ctx->progress_func,
					   ctx->progress);
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
	if (ret == 0) {
		wimlib_assert(ctx->next_chunk == ctx->next_num_chunks);
		ret = finalize_and_check_sha1(&ctx->next_sha_ctx, lte);
	}
	return ret;
}

static int
main_thread_process_next_stream(struct wim_lookup_table_entry *lte, void *_ctx)
{
	struct main_writer_thread_ctx *ctx = _ctx;
	int ret;

	if (wim_resource_size(lte) < 1000 ||
	    ctx->out_ctype == WIMLIB_COMPRESSION_TYPE_NONE ||
	    (lte->resource_location == RESOURCE_IN_WIM &&
	     !(ctx->write_resource_flags & WIMLIB_RESOURCE_FLAG_RECOMPRESS) &&
	     wimlib_get_compression_type(lte->wim) == ctx->out_ctype))
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
			   int out_fd,
			   int out_ctype,
			   int write_resource_flags,
			   wimlib_progress_func_t progress_func,
			   union wimlib_progress_info *progress,
			   unsigned num_threads)
{
	int ret;
	struct shared_queue res_to_compress_queue;
	struct shared_queue compressed_res_queue;
	pthread_t *compressor_threads = NULL;

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

	DEBUG("Writing stream list (parallel version, num_threads=%u)",
	      num_threads);

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

	struct compressor_thread_params params;
	params.res_to_compress_queue = &res_to_compress_queue;
	params.compressed_res_queue = &compressed_res_queue;
	params.compress = get_compress_func(out_ctype);

	compressor_threads = MALLOC(num_threads * sizeof(pthread_t));
	if (!compressor_threads) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_destroy_compressed_res_queue;
	}

	for (unsigned i = 0; i < num_threads; i++) {
		DEBUG("pthread_create thread %u of %u", i + 1, num_threads);
		ret = pthread_create(&compressor_threads[i], NULL,
				     compressor_thread_proc, &params);
		if (ret != 0) {
			ret = -1;
			ERROR_WITH_ERRNO("Failed to create compressor "
					 "thread %u of %u",
					 i + 1, num_threads);
			num_threads = i;
			goto out_join;
		}
	}

	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS, progress);

	struct main_writer_thread_ctx ctx;
	ctx.stream_list           = stream_list;
	ctx.lookup_table          = lookup_table;
	ctx.out_fd                = out_fd;
	ctx.out_ctype             = out_ctype;
	ctx.res_to_compress_queue = &res_to_compress_queue;
	ctx.compressed_res_queue  = &compressed_res_queue;
	ctx.num_messages          = queue_size;
	ctx.write_resource_flags  = write_resource_flags;
	ctx.progress_func         = progress_func;
	ctx.progress              = progress;
	ret = main_writer_thread_init_ctx(&ctx);
	if (ret)
		goto out_join;
	ret = do_write_stream_list(stream_list, lookup_table,
				   main_thread_process_next_stream,
				   &ctx, progress_func, progress);
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
					write_resource_flags,
					progress_func,
					progress);

}
#endif

/*
 * Write a list of streams to a WIM (@out_fd) using the compression type
 * @out_ctype and up to @num_threads compressor threads.
 */
static int
write_stream_list(struct list_head *stream_list,
		  struct wim_lookup_table *lookup_table,
		  int out_fd, int out_ctype, int write_flags,
		  unsigned num_threads, wimlib_progress_func_t progress_func)
{
	struct wim_lookup_table_entry *lte;
	size_t num_streams = 0;
	u64 total_bytes = 0;
	u64 total_compression_bytes = 0;
	union wimlib_progress_info progress;
	int ret;
	int write_resource_flags;

	if (list_empty(stream_list))
		return 0;

	write_resource_flags = write_flags_to_resource_flags(write_flags);

	/* Calculate the total size of the streams to be written.  Note: this
	 * will be the uncompressed size, as we may not know the compressed size
	 * yet, and also this will assume that every unhashed stream will be
	 * written (which will not necessarily be the case). */
	list_for_each_entry(lte, stream_list, write_streams_list) {
		num_streams++;
		total_bytes += wim_resource_size(lte);
		if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE
		       && (wim_resource_compression_type(lte) != out_ctype ||
			   (write_resource_flags & WIMLIB_RESOURCE_FLAG_RECOMPRESS)))
		{
			total_compression_bytes += wim_resource_size(lte);
		}
	}
	progress.write_streams.total_bytes       = total_bytes;
	progress.write_streams.total_streams     = num_streams;
	progress.write_streams.completed_bytes   = 0;
	progress.write_streams.completed_streams = 0;
	progress.write_streams.num_threads       = num_threads;
	progress.write_streams.compression_type  = out_ctype;
	progress.write_streams._private          = 0;

#ifdef ENABLE_MULTITHREADED_COMPRESSION
	if (total_compression_bytes >= 2000000 && num_threads != 1)
		ret = write_stream_list_parallel(stream_list,
						 lookup_table,
						 out_fd,
						 out_ctype,
						 write_resource_flags,
						 progress_func,
						 &progress,
						 num_threads);
	else
#endif
		ret = write_stream_list_serial(stream_list,
					       lookup_table,
					       out_fd,
					       out_ctype,
					       write_resource_flags,
					       progress_func,
					       &progress);
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


struct lte_overwrite_prepare_args {
	WIMStruct *wim;
	off_t end_offset;
	struct list_head stream_list;
	struct stream_size_table stream_size_tab;
};

/* First phase of preparing streams for an in-place overwrite.  This is called
 * on all streams, both hashed and unhashed, except the metadata resources. */
static int
lte_overwrite_prepare(struct wim_lookup_table_entry *lte, void *_args)
{
	struct lte_overwrite_prepare_args *args = _args;

	wimlib_assert(!(lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA));
	if (lte->resource_location != RESOURCE_IN_WIM || lte->wim != args->wim)
		list_add_tail(&lte->write_streams_list, &args->stream_list);
	lte->out_refcnt = lte->refcnt;
	stream_size_table_insert(lte, &args->stream_size_tab);
	return 0;
}

/* Second phase of preparing streams for an in-place overwrite.  This is called
 * on existing metadata resources and hashed streams, but not unhashed streams.
 *
 * NOTE: lte->output_resource_entry is in union with lte->hash_list_2, so
 * lte_overwrite_prepare_2() must be called after lte_overwrite_prepare(), as
 * the latter uses lte->hash_list_2, while the former expects to set
 * lte->output_resource_entry. */
static int
lte_overwrite_prepare_2(struct wim_lookup_table_entry *lte, void *_args)
{
	struct lte_overwrite_prepare_args *args = _args;

	if (lte->resource_location == RESOURCE_IN_WIM && lte->wim == args->wim) {
		/* We can't do an in place overwrite on the WIM if there are
		 * streams after the XML data. */
		if (lte->resource_entry.offset +
		    lte->resource_entry.size > args->end_offset)
		{
		#ifdef ENABLE_ERROR_MESSAGES
			ERROR("The following resource is after the XML data:");
			print_lookup_table_entry(lte, stderr);
		#endif
			return WIMLIB_ERR_RESOURCE_ORDER;
		}
		copy_resource_entry(&lte->output_resource_entry,
				    &lte->resource_entry);
	}
	return 0;
}

/* Given a WIM that we are going to overwrite in place with zero or more
 * additional streams added, construct a list the list of new unique streams
 * ('struct wim_lookup_table_entry's) that must be written, plus any unhashed
 * streams that need to be added but may be identical to other hashed or
 * unhashed streams.  These unhashed streams are checksummed while the streams
 * are being written.  To aid this process, the member @unique_size is set to 1
 * on streams that have a unique size and therefore must be written.
 *
 * The out_refcnt member of each 'struct wim_lookup_table_entry' is set to
 * indicate the number of times the stream is referenced in only the streams
 * that are being written; this may still be adjusted later when unhashed
 * streams are being resolved.
 */
static int
prepare_streams_for_overwrite(WIMStruct *wim, off_t end_offset,
			      struct list_head *stream_list)
{
	int ret;
	struct lte_overwrite_prepare_args args;
	unsigned i;

	args.wim = wim;
	args.end_offset = end_offset;
	ret = init_stream_size_table(&args.stream_size_tab,
				     wim->lookup_table->capacity);
	if (ret)
		return ret;

	INIT_LIST_HEAD(&args.stream_list);
	for (i = 0; i < wim->hdr.image_count; i++) {
		struct wim_image_metadata *imd;
		struct wim_lookup_table_entry *lte;

 		imd = wim->image_metadata[i];
		image_for_each_unhashed_stream(lte, imd)
			lte_overwrite_prepare(lte, &args);
	}
	for_lookup_table_entry(wim->lookup_table, lte_overwrite_prepare, &args);
	list_transfer(&args.stream_list, stream_list);

	for (i = 0; i < wim->hdr.image_count; i++) {
		ret = lte_overwrite_prepare_2(wim->image_metadata[i]->metadata_lte,
					      &args);
		if (ret)
			goto out_destroy_stream_size_table;
	}
	ret = for_lookup_table_entry(wim->lookup_table,
				     lte_overwrite_prepare_2, &args);
out_destroy_stream_size_table:
	destroy_stream_size_table(&args.stream_size_tab);
	return ret;
}


struct find_streams_ctx {
	struct list_head stream_list;
	struct stream_size_table stream_size_tab;
};

static void
inode_find_streams_to_write(struct wim_inode *inode,
			    struct wim_lookup_table *table,
			    struct list_head *stream_list,
			    struct stream_size_table *tab)
{
	struct wim_lookup_table_entry *lte;
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		lte = inode_stream_lte(inode, i, table);
		if (lte) {
			if (lte->out_refcnt == 0) {
				if (lte->unhashed)
					stream_size_table_insert(lte, tab);
				list_add_tail(&lte->write_streams_list, stream_list);
			}
			lte->out_refcnt += inode->i_nlink;
		}
	}
}

static int
image_find_streams_to_write(WIMStruct *w)
{
	struct find_streams_ctx *ctx;
	struct wim_image_metadata *imd;
	struct wim_inode *inode;
	struct wim_lookup_table_entry *lte;

	ctx = w->private;
 	imd = wim_get_current_image_metadata(w);

	image_for_each_unhashed_stream(lte, imd)
		lte->out_refcnt = 0;

	/* Go through this image's inodes to find any streams that have not been
	 * found yet. */
	image_for_each_inode(inode, imd) {
		inode_find_streams_to_write(inode, w->lookup_table,
					    &ctx->stream_list,
					    &ctx->stream_size_tab);
	}
	return 0;
}

/* Given a WIM that from which one or all of the images is being written, build
 * the list of unique streams ('struct wim_lookup_table_entry's) that must be
 * written, plus any unhashed streams that need to be written but may be
 * identical to other hashed or unhashed streams being written.  These unhashed
 * streams are checksummed while the streams are being written.  To aid this
 * process, the member @unique_size is set to 1 on streams that have a unique
 * size and therefore must be written.
 *
 * The out_refcnt member of each 'struct wim_lookup_table_entry' is set to
 * indicate the number of times the stream is referenced in only the streams
 * that are being written; this may still be adjusted later when unhashed
 * streams are being resolved.
 */
static int
prepare_stream_list(WIMStruct *wim, int image, struct list_head *stream_list)
{
	int ret;
	struct find_streams_ctx ctx;

	for_lookup_table_entry(wim->lookup_table, lte_zero_out_refcnt, NULL);
	ret = init_stream_size_table(&ctx.stream_size_tab,
				     wim->lookup_table->capacity);
	if (ret)
		return ret;
	for_lookup_table_entry(wim->lookup_table, stream_size_table_insert,
			       &ctx.stream_size_tab);
	INIT_LIST_HEAD(&ctx.stream_list);
	wim->private = &ctx;
	ret = for_image(wim, image, image_find_streams_to_write);
	destroy_stream_size_table(&ctx.stream_size_tab);
	if (ret == 0)
		list_transfer(&ctx.stream_list, stream_list);
	return ret;
}

/* Writes the streams for the specified @image in @wim to @wim->out_fd.
 */
static int
write_wim_streams(WIMStruct *wim, int image, int write_flags,
		  unsigned num_threads,
		  wimlib_progress_func_t progress_func)
{
	int ret;
	struct list_head stream_list;

	ret = prepare_stream_list(wim, image, &stream_list);
	if (ret)
		return ret;
	return write_stream_list(&stream_list,
				 wim->lookup_table,
				 wim->out_fd,
				 wimlib_get_compression_type(wim),
				 write_flags,
				 num_threads,
				 progress_func);
}

/*
 * Finish writing a WIM file: write the lookup table, xml data, and integrity
 * table (optional), then overwrite the WIM header.
 *
 * write_flags is a bitwise OR of the following:
 *
 * 	(public)  WIMLIB_WRITE_FLAG_CHECK_INTEGRITY:
 * 		Include an integrity table.
 *
 * 	(private) WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE:
 * 		Don't write the lookup table.
 *
 * 	(private) WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE:
 * 		When (if) writing the integrity table, re-use entries from the
 * 		existing integrity table, if possible.
 *
 * 	(private) WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML:
 * 		After writing the XML data but before writing the integrity
 * 		table, write a temporary WIM header and flush the stream so that
 * 		the WIM is less likely to become corrupted upon abrupt program
 * 		termination.
 *
 * 	(private) WIMLIB_WRITE_FLAG_FSYNC:
 * 		fsync() the output file before closing it.
 *
 */
int
finish_write(WIMStruct *w, int image, int write_flags,
	     wimlib_progress_func_t progress_func)
{
	int ret;
	struct wim_header hdr;

	/* @hdr will be the header for the new WIM.  First copy all the data
	 * from the header in the WIMStruct; then set all the fields that may
	 * have changed, including the resource entries, boot index, and image
	 * count.  */
	memcpy(&hdr, &w->hdr, sizeof(struct wim_header));

	/* Set image count and boot index correctly for single image writes */
	if (image != WIMLIB_ALL_IMAGES) {
		hdr.image_count = 1;
		if (hdr.boot_idx == image)
			hdr.boot_idx = 1;
		else
			hdr.boot_idx = 0;
	}

	/* In the WIM header, there is room for the resource entry for a
	 * metadata resource labeled as the "boot metadata".  This entry should
	 * be zeroed out if there is no bootable image (boot_idx 0).  Otherwise,
	 * it should be a copy of the resource entry for the image that is
	 * marked as bootable.  This is not well documented...  */
	if (hdr.boot_idx == 0) {
		zero_resource_entry(&hdr.boot_metadata_res_entry);
	} else {
		copy_resource_entry(&hdr.boot_metadata_res_entry,
			    &w->image_metadata[ hdr.boot_idx- 1
					]->metadata_lte->output_resource_entry);
	}

	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE)) {
		ret = write_lookup_table(w, image, &hdr.lookup_table_res_entry);
		if (ret)
			goto out_close_wim;
	}

	ret = write_xml_data(w->wim_info, image, w->out_fd,
			     (write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE) ?
			      wim_info_get_total_bytes(w->wim_info) : 0,
			     &hdr.xml_res_entry);
	if (ret)
		goto out_close_wim;

	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
		if (write_flags & WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML) {
			struct wim_header checkpoint_hdr;
			memcpy(&checkpoint_hdr, &hdr, sizeof(struct wim_header));
			zero_resource_entry(&checkpoint_hdr.integrity);
			ret = write_header(&checkpoint_hdr, w->out_fd);
			if (ret)
				goto out_close_wim;
		}

		off_t old_lookup_table_end;
		off_t new_lookup_table_end;
		if (write_flags & WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE) {
			old_lookup_table_end = w->hdr.lookup_table_res_entry.offset +
					       w->hdr.lookup_table_res_entry.size;
		} else {
			old_lookup_table_end = 0;
		}
		new_lookup_table_end = hdr.lookup_table_res_entry.offset +
				       hdr.lookup_table_res_entry.size;

		ret = write_integrity_table(w->out_fd,
					    &hdr.integrity,
					    new_lookup_table_end,
					    old_lookup_table_end,
					    progress_func);
		if (ret)
			goto out_close_wim;
	} else {
		zero_resource_entry(&hdr.integrity);
	}

	ret = write_header(&hdr, w->out_fd);
	if (ret)
		goto out_close_wim;

	if (write_flags & WIMLIB_WRITE_FLAG_FSYNC) {
		if (fsync(w->out_fd)) {
			ERROR_WITH_ERRNO("Error syncing data to WIM file");
			ret = WIMLIB_ERR_WRITE;
		}
	}
out_close_wim:
	if (close(w->out_fd)) {
		ERROR_WITH_ERRNO("Failed to close the output WIM file");
		if (ret == 0)
			ret = WIMLIB_ERR_WRITE;
	}
	w->out_fd = -1;
	return ret;
}

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
int
lock_wim(WIMStruct *w, int fd)
{
	int ret = 0;
	if (fd != -1 && !w->wim_locked) {
		ret = flock(fd, LOCK_EX | LOCK_NB);
		if (ret != 0) {
			if (errno == EWOULDBLOCK) {
				ERROR("`%"TS"' is already being modified or has been "
				      "mounted read-write\n"
				      "        by another process!", w->filename);
				ret = WIMLIB_ERR_ALREADY_LOCKED;
			} else {
				WARNING_WITH_ERRNO("Failed to lock `%"TS"'",
						   w->filename);
				ret = 0;
			}
		} else {
			w->wim_locked = 1;
		}
	}
	return ret;
}
#endif

static int
open_wim_writable(WIMStruct *w, const tchar *path, int open_flags)
{
	w->out_fd = topen(path, open_flags | O_BINARY, 0644);
	if (w->out_fd == -1) {
		ERROR_WITH_ERRNO("Failed to open `%"TS"' for writing", path);
		return WIMLIB_ERR_OPEN;
	}
	return 0;
}


void
close_wim_writable(WIMStruct *w)
{
	if (w->out_fd != -1) {
		if (close(w->out_fd))
			WARNING_WITH_ERRNO("Failed to close output WIM");
		w->out_fd = -1;
	}
}

/* Open file stream and write dummy header for WIM. */
int
begin_write(WIMStruct *w, const tchar *path, int write_flags)
{
	int ret;
	int open_flags = O_TRUNC | O_CREAT;
	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY)
		open_flags |= O_RDWR;
	else
		open_flags |= O_WRONLY;
	ret = open_wim_writable(w, path, open_flags);
	if (ret)
		return ret;
	/* Write dummy header. It will be overwritten later. */
	ret = write_header(&w->hdr, w->out_fd);
	if (ret)
		return ret;
	if (lseek(w->out_fd, WIM_HEADER_DISK_SIZE, SEEK_SET) == -1) {
		ERROR_WITH_ERRNO("Failed to seek to end of WIM header");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/* Writes a stand-alone WIM to a file.  */
WIMLIBAPI int
wimlib_write(WIMStruct *w, const tchar *path,
	     int image, int write_flags, unsigned num_threads,
	     wimlib_progress_func_t progress_func)
{
	int ret;

	if (!path)
		return WIMLIB_ERR_INVALID_PARAM;

	write_flags &= WIMLIB_WRITE_MASK_PUBLIC;

	if (image != WIMLIB_ALL_IMAGES &&
	     (image < 1 || image > w->hdr.image_count))
		return WIMLIB_ERR_INVALID_IMAGE;

	if (w->hdr.total_parts != 1) {
		ERROR("Cannot call wimlib_write() on part of a split WIM");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	ret = begin_write(w, path, write_flags);
	if (ret)
		goto out_close_wim;

	ret = write_wim_streams(w, image, write_flags, num_threads,
				progress_func);
	if (ret)
		goto out_close_wim;

	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN, NULL);

	ret = for_image(w, image, write_metadata_resource);
	if (ret)
		goto out_close_wim;

	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_METADATA_END, NULL);

	ret = finish_write(w, image, write_flags, progress_func);
	/* finish_write() closed the WIM for us */
	goto out;
out_close_wim:
	close_wim_writable(w);
out:
	DEBUG("wimlib_write(path=%"TS") = %d", path, ret);
	return ret;
}

static bool
any_images_modified(WIMStruct *w)
{
	for (int i = 0; i < w->hdr.image_count; i++)
		if (w->image_metadata[i]->modified)
			return true;
	return false;
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
overwrite_wim_inplace(WIMStruct *w, int write_flags,
		      unsigned num_threads,
		      wimlib_progress_func_t progress_func)
{
	int ret;
	struct list_head stream_list;
	off_t old_wim_end;
	u64 old_lookup_table_end, old_xml_begin, old_xml_end;
	int open_flags;

	DEBUG("Overwriting `%"TS"' in-place", w->filename);

	/* Make sure that the integrity table (if present) is after the XML
	 * data, and that there are no stream resources, metadata resources, or
	 * lookup tables after the XML data.  Otherwise, these data would be
	 * overwritten. */
	old_xml_begin = w->hdr.xml_res_entry.offset;
	old_xml_end = old_xml_begin + w->hdr.xml_res_entry.size;
	old_lookup_table_end = w->hdr.lookup_table_res_entry.offset +
			       w->hdr.lookup_table_res_entry.size;
	if (w->hdr.integrity.offset != 0 && w->hdr.integrity.offset < old_xml_end) {
		ERROR("Didn't expect the integrity table to be before the XML data");
		return WIMLIB_ERR_RESOURCE_ORDER;
	}

	if (old_lookup_table_end > old_xml_begin) {
		ERROR("Didn't expect the lookup table to be after the XML data");
		return WIMLIB_ERR_RESOURCE_ORDER;
	}

	/* Set @old_wim_end, which indicates the point beyond which we don't
	 * allow any file and metadata resources to appear without returning
	 * WIMLIB_ERR_RESOURCE_ORDER (due to the fact that we would otherwise
	 * overwrite these resources). */
	if (!w->deletion_occurred && !any_images_modified(w)) {
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
	} else if (w->hdr.integrity.offset) {
		/* Old WIM has an integrity table; begin writing new streams
		 * after it. */
		old_wim_end = w->hdr.integrity.offset + w->hdr.integrity.size;
	} else {
		/* No existing integrity table; begin writing new streams after
		 * the old XML data. */
		old_wim_end = old_xml_end;
	}

	ret = prepare_streams_for_overwrite(w, old_wim_end, &stream_list);
	if (ret)
		return ret;

	open_flags = 0;
	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY)
		open_flags |= O_RDWR;
	else
		open_flags |= O_WRONLY;
	ret = open_wim_writable(w, w->filename, open_flags);
	if (ret)
		return ret;

	ret = lock_wim(w, w->out_fd);
	if (ret) {
		close_wim_writable(w);
		return ret;
	}

	if (lseek(w->out_fd, old_wim_end, SEEK_SET) == -1) {
		ERROR_WITH_ERRNO("Can't seek to end of WIM");
		close_wim_writable(w);
		w->wim_locked = 0;
		return WIMLIB_ERR_WRITE;
	}

	DEBUG("Writing newly added streams (offset = %"PRIu64")",
	      old_wim_end);
	ret = write_stream_list(&stream_list,
				w->lookup_table,
				w->out_fd,
				wimlib_get_compression_type(w),
				write_flags,
				num_threads,
				progress_func);
	if (ret)
		goto out_truncate;

	for (int i = 0; i < w->hdr.image_count; i++) {
		if (w->image_metadata[i]->modified) {
			select_wim_image(w, i + 1);
			ret = write_metadata_resource(w);
			if (ret)
				goto out_truncate;
		}
	}
	write_flags |= WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE;
	ret = finish_write(w, WIMLIB_ALL_IMAGES, write_flags,
			   progress_func);
out_truncate:
	close_wim_writable(w);
	if (ret != 0 && !(write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE)) {
		WARNING("Truncating `%"TS"' to its original size (%"PRIu64" bytes)",
			w->filename, old_wim_end);
		/* Return value of truncate() is ignored because this is already
		 * an error path. */
		(void)ttruncate(w->filename, old_wim_end);
	}
	w->wim_locked = 0;
	return ret;
}

static int
overwrite_wim_via_tmpfile(WIMStruct *w, int write_flags,
			  unsigned num_threads,
			  wimlib_progress_func_t progress_func)
{
	size_t wim_name_len;
	int ret;

	DEBUG("Overwriting `%"TS"' via a temporary file", w->filename);

	/* Write the WIM to a temporary file in the same directory as the
	 * original WIM. */
	wim_name_len = tstrlen(w->filename);
	tchar tmpfile[wim_name_len + 10];
	tmemcpy(tmpfile, w->filename, wim_name_len);
	randomize_char_array_with_alnum(tmpfile + wim_name_len, 9);
	tmpfile[wim_name_len + 9] = T('\0');

	ret = wimlib_write(w, tmpfile, WIMLIB_ALL_IMAGES,
			   write_flags | WIMLIB_WRITE_FLAG_FSYNC,
			   num_threads, progress_func);
	if (ret) {
		ERROR("Failed to write the WIM file `%"TS"'", tmpfile);
		goto out_unlink;
	}

	close_wim(w);

	DEBUG("Renaming `%"TS"' to `%"TS"'", tmpfile, w->filename);
	/* Rename the new file to the old file .*/
	if (trename(tmpfile, w->filename) != 0) {
		ERROR_WITH_ERRNO("Failed to rename `%"TS"' to `%"TS"'",
				 tmpfile, w->filename);
		ret = WIMLIB_ERR_RENAME;
		goto out_unlink;
	}

	if (progress_func) {
		union wimlib_progress_info progress;
		progress.rename.from = tmpfile;
		progress.rename.to = w->filename;
		progress_func(WIMLIB_PROGRESS_MSG_RENAME, &progress);
	}
	goto out;
out_unlink:
	/* Remove temporary file. */
	if (tunlink(tmpfile) != 0)
		WARNING_WITH_ERRNO("Failed to remove `%"TS"'", tmpfile);
out:
	return ret;
}

/*
 * Writes a WIM file to the original file that it was read from, overwriting it.
 */
WIMLIBAPI int
wimlib_overwrite(WIMStruct *w, int write_flags,
		 unsigned num_threads,
		 wimlib_progress_func_t progress_func)
{
	write_flags &= WIMLIB_WRITE_MASK_PUBLIC;

	if (!w->filename)
		return WIMLIB_ERR_NO_FILENAME;

	if (w->hdr.total_parts != 1) {
		ERROR("Cannot modify a split WIM");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	if ((!w->deletion_occurred || (write_flags & WIMLIB_WRITE_FLAG_SOFT_DELETE))
	    && !(write_flags & WIMLIB_WRITE_FLAG_REBUILD))
	{
		int ret;
		ret = overwrite_wim_inplace(w, write_flags, num_threads,
					    progress_func);
		if (ret == WIMLIB_ERR_RESOURCE_ORDER)
			WARNING("Falling back to re-building entire WIM");
		else
			return ret;
	}
	return overwrite_wim_via_tmpfile(w, write_flags, num_threads,
					 progress_func);
}
