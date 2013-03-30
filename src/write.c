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

#include "config.h"

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
/* On BSD, this should be included before "list.h" so that "list.h" can
 * overwrite the LIST_HEAD macro. */
#  include <sys/file.h>
#endif

#ifdef __WIN32__
#  include "win32.h"
#endif

#include "list.h"
#include "wimlib_internal.h"
#include "buffer_io.h"
#include "dentry.h"
#include "lookup_table.h"
#include "xml.h"

#ifdef ENABLE_MULTITHREADED_COMPRESSION
#  include <pthread.h>
#endif

#include <unistd.h>
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

#if defined(__WIN32__) && !defined(INVALID_HANDLE_VALUE)
#  define INVALID_HANDLE_VALUE ((HANDLE)(-1))
#endif

static int
fflush_and_ftruncate(FILE *fp, off_t size)
{
	int ret;

	ret = fflush(fp);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to flush data to output WIM file");
		return WIMLIB_ERR_WRITE;
	}
	ret = ftruncate(fileno(fp), size);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to truncate output WIM file to "
				 "%"PRIu64" bytes", size);
		return WIMLIB_ERR_WRITE;
	}
	return 0;
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
begin_wim_resource_chunk_tab(const struct wim_lookup_table_entry *lte,
			     FILE *out_fp,
			     off_t file_offset,
			     struct chunk_table **chunk_tab_ret)
{
	u64 size = wim_resource_size(lte);
	u64 num_chunks = (size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;
	size_t alloc_size = sizeof(struct chunk_table) + num_chunks * sizeof(u64);
	struct chunk_table *chunk_tab = CALLOC(1, alloc_size);
	int ret;

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

	ret = 0;
out:
	*chunk_tab_ret = chunk_tab;
	return ret;
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

compress_func_t
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
 * @out_fp:	  FILE * to write tho chunk to.
 * @out_ctype:	  Compression type to use when writing the chunk (ignored if no
 * 			chunk table provided)
 * @chunk_tab:	  Pointer to chunk table being created.  It is updated with the
 * 			offset of the chunk we write.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int
write_wim_resource_chunk(const void *chunk, unsigned chunk_size,
			 FILE *out_fp, compress_func_t compress,
			 struct chunk_table *chunk_tab)
{
	const u8 *out_chunk;
	unsigned out_chunk_size;
	if (chunk_tab) {
		u8 *compressed_chunk = alloca(chunk_size);

		out_chunk_size = compress(chunk, chunk_size, compressed_chunk);
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
	if (fwrite(out_chunk, 1, out_chunk_size, out_fp) != out_chunk_size) {
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
			      FILE *out_fp, u64 *compressed_size_p)
{
	size_t bytes_written;
	if (fseeko(out_fp, chunk_tab->file_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" of output "
				 "WIM file", chunk_tab->file_offset);
		return WIMLIB_ERR_WRITE;
	}

	if (chunk_tab->bytes_per_chunk_entry == 8) {
		array_cpu_to_le64(chunk_tab->offsets, chunk_tab->num_chunks);
	} else {
		for (u64 i = 0; i < chunk_tab->num_chunks; i++)
			((u32*)chunk_tab->offsets)[i] =
				cpu_to_le32(chunk_tab->offsets[i]);
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

static int
write_uncompressed_resource_and_truncate(struct wim_lookup_table_entry *lte,
					 FILE *out_fp,
					 off_t file_offset,
					 struct resource_entry *out_res_entry)
{
	int ret;
	if (fseeko(out_fp, file_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" of "
				 "output WIM file", file_offset);
		return WIMLIB_ERR_WRITE;
	}
	ret = write_wim_resource(lte, out_fp,
				 WIMLIB_COMPRESSION_TYPE_NONE,
				 out_res_entry,
				 0);
	if (ret)
		return ret;

	return fflush_and_ftruncate(out_fp,
				    file_offset + wim_resource_size(lte));
}

struct write_resource_ctx {
	compress_func_t compress;
	struct chunk_table *chunk_tab;
	FILE *out_fp;
	SHA_CTX sha_ctx;
	bool doing_sha;
};

static int
write_resource_cb(const void *chunk, size_t chunk_size, void *_ctx)
{
	struct write_resource_ctx *ctx = _ctx;

	if (ctx->doing_sha)
		sha1_update(&ctx->sha_ctx, chunk, chunk_size);

	if (ctx->compress) {
		return write_wim_resource_chunk(chunk, chunk_size,
						ctx->out_fp, ctx->compress,
						ctx->chunk_tab);
	} else {
		if (fwrite(chunk, 1, chunk_size, ctx->out_fp) != chunk_size) {
			ERROR_WITH_ERRNO("Error writing to output WIM");
			return WIMLIB_ERR_WRITE;
		} else {
			return 0;
		}
	}
}

int
write_wim_resource(struct wim_lookup_table_entry *lte,
		   FILE *out_fp, int out_ctype,
		   struct resource_entry *out_res_entry,
		   int flags)
{
	struct write_resource_ctx write_ctx;
	u64 new_size;
	off_t offset;
	int ret;

	if (wim_resource_size(lte) == 0) {
		/* Empty resource; nothing needs to be done, so just return
		 * success. */
		return 0;
	}

	offset = ftello(out_fp);
	if (offset == -1) {
		ERROR_WITH_ERRNO("Can't get position in output WIM");
		return WIMLIB_ERR_WRITE;
	}

	/* Can we simply copy the compressed data without recompressing it? */

	if (!(flags & WIMLIB_RESOURCE_FLAG_RECOMPRESS) &&
	    lte->resource_location == RESOURCE_IN_WIM &&
	    wimlib_get_compression_type(lte->wim) == out_ctype)
	{
		flags |= WIMLIB_RESOURCE_FLAG_RAW;
		write_ctx.doing_sha = false;
	} else {
		write_ctx.doing_sha = true;
		sha1_init(&write_ctx.sha_ctx);
	}

	/* Initialize the chunk table and set the compression function if
	 * compressing the resource. */
	if (out_ctype == WIMLIB_COMPRESSION_TYPE_NONE ||
	    (flags & WIMLIB_RESOURCE_FLAG_RAW)) {
		write_ctx.compress = NULL;
		write_ctx.chunk_tab = NULL;
	} else {
		write_ctx.compress = get_compress_func(out_ctype);
		ret = begin_wim_resource_chunk_tab(lte, out_fp,
						   offset,
						   &write_ctx.chunk_tab);
		if (ret)
			return ret;
	}

	/* Write the data */
	write_ctx.out_fp = out_fp;
	ret = read_resource_prefix(lte, wim_resource_size(lte),
				   write_resource_cb, &write_ctx, 0);

	/* Verify SHA1 message digest of the resource, or set the hash for the
	 * first time. */
	if (write_ctx.doing_sha) {
		u8 md[SHA1_HASH_SIZE];
		sha1_final(md, &write_ctx.sha_ctx);
		if (lte->unhashed) {
			copy_hash(lte->hash, md);
		} else if (!hashes_equal(md, lte->hash)) {
			ERROR("WIM resource has incorrect hash!");
			if (lte_filename_valid(lte)) {
				ERROR("We were reading it from \"%"TS"\"; maybe "
				      "it changed while we were reading it.",
				      lte->file_on_disk);
			}
			ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
			goto out_free_chunk_tab;
		}
	}

	out_res_entry->flags = lte->resource_entry.flags;
	out_res_entry->original_size = wim_resource_size(lte);
	out_res_entry->offset = offset;
	if (flags & WIMLIB_RESOURCE_FLAG_RAW) {
		/* Doing a raw write:  The new compressed size is the same as
		 * the compressed size in the other WIM. */
		new_size = lte->resource_entry.size;
		out_res_entry->flags = lte->resource_entry.flags;
	} else if (out_ctype == WIMLIB_COMPRESSION_TYPE_NONE) {
		/* Using WIMLIB_COMPRESSION_TYPE_NONE:  The new compressed size
		 * is the original size. */
		new_size = lte->resource_entry.original_size;
		out_res_entry->flags &= ~WIM_RESHDR_FLAG_COMPRESSED;
	} else {
		/* Using a different compression type:  Call
		 * finish_wim_resource_chunk_tab() and it will provide the new
		 * compressed size. */
		ret = finish_wim_resource_chunk_tab(write_ctx.chunk_tab, out_fp,
						    &new_size);
		if (ret)
			goto out_free_chunk_tab;
		if (new_size >= wim_resource_size(lte)) {
			/* Oops!  We compressed the resource to larger than the original
			 * size.  Write the resource uncompressed instead. */
			ret = write_uncompressed_resource_and_truncate(lte,
								       out_fp,
								       offset,
								       out_res_entry);
			goto out_free_chunk_tab;
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
		return WIMLIB_ERR_NOMEM;
	q->filled_slots = 0;
	q->front = 0;
	q->back = size - 1;
	q->size = size;
	pthread_mutex_init(&q->lock, NULL);
	pthread_cond_init(&q->msg_avail_cond, NULL);
	pthread_cond_init(&q->space_avail_cond, NULL);
	return 0;
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
	u8 *out_compressed_chunks[MAX_CHUNKS_PER_MSG];
	u8 *compressed_chunks[MAX_CHUNKS_PER_MSG];
	unsigned uncompressed_chunk_sizes[MAX_CHUNKS_PER_MSG];
	unsigned compressed_chunk_sizes[MAX_CHUNKS_PER_MSG];
	unsigned num_chunks;
	struct list_head list;
	bool complete;
	u64 begin_chunk;
};

static void
compress_chunks(struct message *msg, compress_func_t compress)
{
	for (unsigned i = 0; i < msg->num_chunks; i++) {
		DEBUG2("compress chunk %u of %u", i, msg->num_chunks);
		unsigned len = compress(msg->uncompressed_chunks[i],
					msg->uncompressed_chunk_sizes[i],
					msg->compressed_chunks[i]);
		if (len) {
			/* To be written compressed */
			msg->out_compressed_chunks[i] = msg->compressed_chunks[i];
			msg->compressed_chunk_sizes[i] = len;
		} else {
			/* To be written uncompressed */
			msg->out_compressed_chunks[i] = msg->uncompressed_chunks[i];
			msg->compressed_chunk_sizes[i] = msg->uncompressed_chunk_sizes[i];

		}
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
			  uint64_t size_added)
{
	progress->write_streams.completed_bytes += size_added;
	progress->write_streams.completed_streams++;
	if (progress_func &&
	    progress->write_streams.completed_bytes >= progress->write_streams._private)
	{
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS,
			      progress);
		if (progress->write_streams._private == progress->write_streams.total_bytes) {
			progress->write_streams._private = ~0;
		} else {
			progress->write_streams._private =
				min(progress->write_streams.total_bytes,
				    progress->write_streams.completed_bytes +
				        progress->write_streams.total_bytes / 100);
		}
	}
}

static int
sha1_chunk(const void *buf, size_t len, void *ctx)
{
	sha1_update(ctx, buf, len);
	return 0;
}

static int
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

enum {
	STREAMS_MERGED = 0,
	STREAMS_NOT_MERGED = 1,
};

static int
do_write_stream_list(struct list_head *my_resources,
		     struct wim_lookup_table *lookup_table,
		     FILE *out_fp,
		     int out_ctype,
		     wimlib_progress_func_t progress_func,
		     union wimlib_progress_info *progress,
		     int write_resource_flags)
{
	int ret;
	struct wim_lookup_table_entry *lte;

	while (!list_empty(my_resources)) {
		lte = container_of(my_resources->next,
				   struct wim_lookup_table_entry,
				   write_streams_list);
		list_del(&lte->write_streams_list);
		if (lte->unhashed && !lte->unique_size) {
			struct wim_lookup_table_entry *duplicate_lte;

			ret = sha1_resource(lte);
			if (ret)
				return ret;
			list_del(&lte->staging_list);

			duplicate_lte = __lookup_resource(lookup_table, lte->hash);
			if (duplicate_lte) {
				bool new_stream = (duplicate_lte->out_refcnt == 0);
				duplicate_lte->refcnt += lte->refcnt;
				duplicate_lte->out_refcnt += lte->refcnt;
				free_lookup_table_entry(lte);

				if (new_stream)
					lte = duplicate_lte;
				else
					continue;
			} else {
				lookup_table_insert(lookup_table, lte);
				lte->out_refcnt = lte->refcnt;
				lte->unhashed = 0;
			}
		}

		wimlib_assert(lte->out_refcnt != 0);

		ret = write_wim_resource(lte,
					 out_fp,
					 out_ctype,
					 &lte->output_resource_entry,
					 write_resource_flags);
		if (ret)
			return ret;
		if (lte->unhashed) {
			wimlib_assert(__lookup_resource(lookup_table, lte->hash) == NULL);
			lookup_table_insert(lookup_table, lte);
			lte->unhashed = 0;
		}
		do_write_streams_progress(progress,
					  progress_func,
					  wim_resource_size(lte));
	}
	return 0;
}

static int
write_stream_list_serial(struct list_head *stream_list,
			 struct wim_lookup_table *lookup_table,
			 FILE *out_fp,
			 int out_ctype,
			 int write_flags,
			 wimlib_progress_func_t progress_func,
			 union wimlib_progress_info *progress)
{
	int write_resource_flags;

	if (write_flags & WIMLIB_WRITE_FLAG_RECOMPRESS)
		write_resource_flags = WIMLIB_RESOURCE_FLAG_RECOMPRESS;
	else
		write_resource_flags = 0;
	progress->write_streams.num_threads = 1;
	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS, progress);
	return do_write_stream_list(stream_list,
				    lookup_table,
				    out_fp,
				    out_ctype, progress_func,
				    progress, write_resource_flags);
}

#ifdef ENABLE_MULTITHREADED_COMPRESSION
static int
write_wim_chunks(struct message *msg, FILE *out_fp,
		 struct chunk_table *chunk_tab)
{
	for (unsigned i = 0; i < msg->num_chunks; i++) {
		unsigned chunk_csize = msg->compressed_chunk_sizes[i];

		DEBUG2("Write wim chunk %u of %u (csize = %u)",
		      i, msg->num_chunks, chunk_csize);

		if (fwrite(msg->out_compressed_chunks[i], 1, chunk_csize, out_fp)
		    != chunk_csize)
		{
			ERROR_WITH_ERRNO("Failed to write WIM chunk");
			return WIMLIB_ERR_WRITE;
		}

		*chunk_tab->cur_offset_p++ = chunk_tab->cur_offset;
		chunk_tab->cur_offset += chunk_csize;
	}
	return 0;
}

/*
 * This function is executed by the main thread when the resources are being
 * compressed in parallel.  The main thread is in change of all reading of the
 * uncompressed data and writing of the compressed data.  The compressor threads
 * *only* do compression from/to in-memory buffers.
 *
 * Each unit of work given to a compressor thread is up to MAX_CHUNKS_PER_MSG
 * chunks of compressed data to compress, represented in a `struct message'.
 * Each message is passed from the main thread to a worker thread through the
 * res_to_compress_queue, and it is passed back through the
 * compressed_res_queue.
 */
static int
main_writer_thread_proc(struct list_head *stream_list,
			FILE *out_fp,
			int out_ctype,
			struct shared_queue *res_to_compress_queue,
			struct shared_queue *compressed_res_queue,
			size_t num_messages,
			int write_flags,
			wimlib_progress_func_t progress_func,
			union wimlib_progress_info *progress)
{
	int ret;
	struct chunk_table *cur_chunk_tab = NULL;
	struct message *msgs = CALLOC(num_messages, sizeof(struct message));
	struct wim_lookup_table_entry *next_lte = NULL;

	// Initially, all the messages are available to use.
	LIST_HEAD(available_msgs);

	if (!msgs) {
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}

	for (size_t i = 0; i < num_messages; i++)
		list_add(&msgs[i].list, &available_msgs);

	// outstanding_resources is the list of resources that currently have
	// had chunks sent off for compression.
	//
	// The first stream in outstanding_resources is the stream that is
	// currently being written (cur_lte).
	//
	// The last stream in outstanding_resources is the stream that is
	// currently being read and chunks fed to the compressor threads
	// (next_lte).
	//
	// Depending on the number of threads and the sizes of the resource,
	// the outstanding streams list may contain streams between cur_lte and
	// next_lte that have all their chunks compressed or being compressed,
	// but haven't been written yet.
	//
	LIST_HEAD(outstanding_resources);
	struct list_head *next_resource = stream_list->next;
	u64 next_chunk = 0;
	u64 next_num_chunks = 0;

	// As in write_wim_resource(), each resource we read is checksummed.
	SHA_CTX next_sha_ctx;
	u8 next_hash[SHA1_HASH_SIZE];

	// Resources that don't need any chunks compressed are added to this
	// list and written directly by the main thread.
	LIST_HEAD(my_resources);

	struct wim_lookup_table_entry *cur_lte = NULL;
	struct message *msg;

#ifdef WITH_NTFS_3G
	ntfs_inode *ni = NULL;
#endif

	DEBUG("Initializing buffers for uncompressed "
	      "and compressed data (%zu bytes needed)",
	      num_messages * MAX_CHUNKS_PER_MSG * WIM_CHUNK_SIZE * 2);

	// Pre-allocate all the buffers that will be needed to do the chunk
	// compression.
	for (size_t i = 0; i < num_messages; i++) {
		for (size_t j = 0; j < MAX_CHUNKS_PER_MSG; j++) {
			msgs[i].compressed_chunks[j] = MALLOC(WIM_CHUNK_SIZE);

			// The extra 8 bytes is because longest_match() in
			// lz77.c may read a little bit off the end of the
			// uncompressed data.  It doesn't need to be
			// initialized--- we really just need to avoid accessing
			// an unmapped page.
			msgs[i].uncompressed_chunks[j] = MALLOC(WIM_CHUNK_SIZE + 8);
			if (msgs[i].compressed_chunks[j] == NULL ||
			    msgs[i].uncompressed_chunks[j] == NULL)
			{
				ret = WIMLIB_ERR_NOMEM;
				goto out;
			}
		}
	}

	// This loop is executed until all resources have been written, except
	// possibly a few that have been added to the @my_resources list for
	// writing later.
	while (1) {
		// Send chunks to the compressor threads until either (a) there
		// are no more messages available since they were all sent off,
		// or (b) there are no more resources that need to be
		// compressed.
		while (!list_empty(&available_msgs)) {
			if (next_chunk == next_num_chunks) {
				// If next_chunk == next_num_chunks, there are
				// no more chunks to write in the current
				// stream.  So, check the SHA1 message digest of
				// the stream that was just finished (unless
				// next_lte == NULL, which is the case the very
				// first time this loop is entered, and also
				// near the very end of the compression when
				// there are no more streams.)  Then, advance to
				// the next stream (if there is one).
				if (next_lte != NULL) {
				#ifdef WITH_NTFS_3G
					end_wim_resource_read(next_lte, ni);
					ni = NULL;
				#else
					end_wim_resource_read(next_lte);
				#endif
					DEBUG2("Finalize SHA1 md (next_num_chunks=%zu)",
					       next_num_chunks);
					sha1_final(next_hash, &next_sha_ctx);
					if (!hashes_equal(next_lte->hash, next_hash)) {
						ERROR("WIM resource has incorrect hash!");
						if (next_lte->resource_location ==
						    RESOURCE_IN_FILE_ON_DISK)
						{
							ERROR("We were reading it from `%"TS"'; "
							      "maybe it changed while we were "
							      "reading it.",
							      next_lte->file_on_disk);
						}
						ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
						goto out;
					}
				}

				// Advance to the next resource.
				//
				// If the next resource needs no compression, just write
				// it with this thread (not now though--- we could be in
				// the middle of writing another resource.)  Keep doing
				// this until we either get to the end of the resources
				// list, or we get to a resource that needs compression.
				while (1) {
					if (next_resource == stream_list) {
						// No more resources to send for
						// compression
						next_lte = NULL;
						break;
					}
					next_lte = container_of(next_resource,
								struct wim_lookup_table_entry,
								staging_list);
					next_resource = next_resource->next;
					if ((!(write_flags & WIMLIB_WRITE_FLAG_RECOMPRESS)
					       && wim_resource_compression_type(next_lte) == out_ctype)
					    || wim_resource_size(next_lte) == 0)
					{
						list_add_tail(&next_lte->staging_list,
							      &my_resources);
					} else {
						list_add_tail(&next_lte->staging_list,
							      &outstanding_resources);
						next_chunk = 0;
						next_num_chunks = wim_resource_chunks(next_lte);
						sha1_init(&next_sha_ctx);
						INIT_LIST_HEAD(&next_lte->msg_list);
					#ifdef WITH_NTFS_3G
						ret = prepare_resource_for_read(next_lte, &ni);
					#else
						ret = prepare_resource_for_read(next_lte);
					#endif

						if (ret != 0)
							goto out;
						if (cur_lte == NULL) {
							// Set cur_lte for the
							// first time
							cur_lte = next_lte;
						}
						break;
					}
				}
			}

			if (next_lte == NULL) {
				// No more resources to send for compression
				break;
			}

			// Get a message from the available messages
			// list
			msg = container_of(available_msgs.next,
					   struct message,
					   list);

			// ... and delete it from the available messages
			// list
			list_del(&msg->list);

			// Initialize the message with the chunks to
			// compress.
			msg->num_chunks = min(next_num_chunks - next_chunk,
					      MAX_CHUNKS_PER_MSG);
			msg->lte = next_lte;
			msg->complete = false;
			msg->begin_chunk = next_chunk;

			unsigned size = WIM_CHUNK_SIZE;
			for (unsigned i = 0; i < msg->num_chunks; i++) {

				// Read chunk @next_chunk of the stream into the
				// message so that a compressor thread can
				// compress it.

				if (next_chunk == next_num_chunks - 1) {
					size = MODULO_NONZERO(wim_resource_size(next_lte),
							      WIM_CHUNK_SIZE);
				}

				DEBUG2("Read resource (size=%u, offset=%zu)",
				      size, next_chunk * WIM_CHUNK_SIZE);

				msg->uncompressed_chunk_sizes[i] = size;

				ret = read_wim_resource(next_lte,
							msg->uncompressed_chunks[i],
							size,
							next_chunk * WIM_CHUNK_SIZE,
							0);
				if (ret != 0)
					goto out;
				sha1_update(&next_sha_ctx,
					    msg->uncompressed_chunks[i], size);
				next_chunk++;
			}

			// Send the compression request
			list_add_tail(&msg->list, &next_lte->msg_list);
			shared_queue_put(res_to_compress_queue, msg);
			DEBUG2("Compression request sent");
		}

		// If there are no outstanding resources, there are no more
		// resources that need to be written.
		if (list_empty(&outstanding_resources)) {
			ret = 0;
			goto out;
		}

		// Get the next message from the queue and process it.
		// The message will contain 1 or more data chunks that have been
		// compressed.
		msg = shared_queue_get(compressed_res_queue);
		msg->complete = true;

		// Is this the next chunk in the current resource?  If it's not
		// (i.e., an earlier chunk in a same or different resource
		// hasn't been compressed yet), do nothing, and keep this
		// message around until all earlier chunks are received.
		//
		// Otherwise, write all the chunks we can.
		while (cur_lte != NULL &&
		       !list_empty(&cur_lte->msg_list) &&
		       (msg = container_of(cur_lte->msg_list.next,
					   struct message,
					   list))->complete)
		{
			DEBUG2("Complete msg (begin_chunk=%"PRIu64")", msg->begin_chunk);
			if (msg->begin_chunk == 0) {
				DEBUG2("Begin chunk tab");

				// This is the first set of chunks.  Leave space
				// for the chunk table in the output file.
				off_t cur_offset = ftello(out_fp);
				if (cur_offset == -1) {
					ret = WIMLIB_ERR_WRITE;
					goto out;
				}
				ret = begin_wim_resource_chunk_tab(cur_lte,
								   out_fp,
								   cur_offset,
								   &cur_chunk_tab);
				if (ret != 0)
					goto out;
			}

			// Write the compressed chunks from the message.
			ret = write_wim_chunks(msg, out_fp, cur_chunk_tab);
			if (ret != 0)
				goto out;

			list_del(&msg->list);

			// This message is available to use for different chunks
			// now.
			list_add(&msg->list, &available_msgs);

			// Was this the last chunk of the stream?  If so, finish
			// it.
			if (list_empty(&cur_lte->msg_list) &&
			    msg->begin_chunk + msg->num_chunks == cur_chunk_tab->num_chunks)
			{
				DEBUG2("Finish wim chunk tab");
				u64 res_csize;
				ret = finish_wim_resource_chunk_tab(cur_chunk_tab,
								    out_fp,
								    &res_csize);
				if (ret != 0)
					goto out;

				if (res_csize >= wim_resource_size(cur_lte)) {
					/* Oops!  We compressed the resource to
					 * larger than the original size.  Write
					 * the resource uncompressed instead. */
					ret = write_uncompressed_resource_and_truncate(
							 cur_lte,
							 out_fp,
							 cur_chunk_tab->file_offset,
							 &cur_lte->output_resource_entry);
					if (ret != 0)
						goto out;
				} else {
					cur_lte->output_resource_entry.size =
						res_csize;

					cur_lte->output_resource_entry.original_size =
						cur_lte->resource_entry.original_size;

					cur_lte->output_resource_entry.offset =
						cur_chunk_tab->file_offset;

					cur_lte->output_resource_entry.flags =
						cur_lte->resource_entry.flags |
							WIM_RESHDR_FLAG_COMPRESSED;
				}

				do_write_streams_progress(progress, progress_func,
							  wim_resource_size(cur_lte));

				FREE(cur_chunk_tab);
				cur_chunk_tab = NULL;

				struct list_head *next = cur_lte->staging_list.next;
				list_del(&cur_lte->staging_list);

				if (next == &outstanding_resources)
					cur_lte = NULL;
				else
					cur_lte = container_of(cur_lte->staging_list.next,
							       struct wim_lookup_table_entry,
							       staging_list);

				// Since we just finished writing a stream,
				// write any streams that have been added to the
				// my_resources list for direct writing by the
				// main thread (e.g. resources that don't need
				// to be compressed because the desired
				// compression type is the same as the previous
				// compression type).
				ret = do_write_stream_list(&my_resources,
							   out_fp,
							   out_ctype,
							   progress_func,
							   progress,
							   0);
				if (ret != 0)
					goto out;
			}
		}
	}

out:
	if (ret == WIMLIB_ERR_NOMEM) {
		ERROR("Could not allocate enough memory for "
		      "multi-threaded compression");
	}

	if (next_lte) {
#ifdef WITH_NTFS_3G
		end_wim_resource_read(next_lte, ni);
#else
		end_wim_resource_read(next_lte);
#endif
	}

	if (ret == 0) {
		ret = do_write_stream_list(&my_resources, out_fp,
					   out_ctype, progress_func,
					   progress, 0);
	} else {
		if (msgs) {
			size_t num_available_msgs = 0;
			struct list_head *cur;

			list_for_each(cur, &available_msgs) {
				num_available_msgs++;
			}

			while (num_available_msgs < num_messages) {
				shared_queue_get(compressed_res_queue);
				num_available_msgs++;
			}
		}
	}

	if (msgs) {
		for (size_t i = 0; i < num_messages; i++) {
			for (size_t j = 0; j < MAX_CHUNKS_PER_MSG; j++) {
				FREE(msgs[i].compressed_chunks[j]);
				FREE(msgs[i].uncompressed_chunks[j]);
			}
		}
		FREE(msgs);
	}

	FREE(cur_chunk_tab);
	return ret;
}

static long
get_default_num_threads()
{
#ifdef __WIN32__
	return win32_get_number_of_processors();
#else
	return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

static int
write_stream_list_parallel(struct list_head *stream_list,
			   struct wim_lookup_table *lookup_table,
			   FILE *out_fp,
			   int out_ctype,
			   int write_flags,
			   unsigned num_threads,
			   wimlib_progress_func_t progress_func,
			   union wimlib_progress_info *progress)
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
		} else {
			num_threads = nthreads;
		}
	}

	progress->write_streams.num_threads = num_threads;
	wimlib_assert(stream_list->next != stream_list);

	static const double MESSAGES_PER_THREAD = 2.0;
	size_t queue_size = (size_t)(num_threads * MESSAGES_PER_THREAD);

	DEBUG("Initializing shared queues (queue_size=%zu)", queue_size);

	ret = shared_queue_init(&res_to_compress_queue, queue_size);
	if (ret != 0)
		goto out_serial;

	ret = shared_queue_init(&compressed_res_queue, queue_size);
	if (ret != 0)
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
		DEBUG("pthread_create thread %u", i);
		ret = pthread_create(&compressor_threads[i], NULL,
				     compressor_thread_proc, &params);
		if (ret != 0) {
			ret = -1;
			ERROR_WITH_ERRNO("Failed to create compressor "
					 "thread %u", i);
			num_threads = i;
			goto out_join;
		}
	}

	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_STREAMS, progress);

	ret = main_writer_thread_proc(stream_list,
				      out_fp,
				      out_ctype,
				      &res_to_compress_queue,
				      &compressed_res_queue,
				      queue_size,
				      write_flags,
				      progress_func,
				      progress);
out_join:
	for (unsigned i = 0; i < num_threads; i++)
		shared_queue_put(&res_to_compress_queue, NULL);

	for (unsigned i = 0; i < num_threads; i++) {
		if (pthread_join(compressor_threads[i], NULL)) {
			WARNING_WITH_ERRNO("Failed to join compressor "
					   "thread %u", i);
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
	return write_stream_list_serial(stream_list,
					lookup_table,
					out_fp,
					out_ctype,
					write_flags,
					progress_func,
					progress);

}
#endif

/*
 * Write a list of streams to a WIM (@out_fp) using the compression type
 * @out_ctype and up to @num_threads compressor threads.
 */
static int
write_stream_list(struct list_head *stream_list,
		  struct wim_lookup_table *lookup_table,
		  FILE *out_fp, int out_ctype, int write_flags,
		  unsigned num_threads, wimlib_progress_func_t progress_func)
{
	struct wim_lookup_table_entry *lte;
	size_t num_streams = 0;
	u64 total_bytes = 0;
	u64 total_compression_bytes = 0;
	union wimlib_progress_info progress;
	int ret;

	list_for_each_entry(lte, stream_list, write_streams_list) {
		num_streams++;
		total_bytes += wim_resource_size(lte);
		if (out_ctype != WIMLIB_COMPRESSION_TYPE_NONE
		       && (wim_resource_compression_type(lte) != out_ctype ||
			   (write_flags & WIMLIB_WRITE_FLAG_RECOMPRESS)))
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
	if (total_compression_bytes >= 1000000 && num_threads != 1)
		ret = write_stream_list_parallel(stream_list,
						 lookup_table,
						 out_fp,
						 out_ctype,
						 write_flags,
						 num_threads,
						 progress_func,
						 &progress);
	else
#endif
		ret = write_stream_list_serial(stream_list,
					       lookup_table,
					       out_fp,
					       out_ctype,
					       write_flags,
					       progress_func,
					       &progress);
	return ret;
}

struct lte_overwrite_prepare_args {
	WIMStruct *wim;
	off_t end_offset;
	struct list_head *stream_list;
};

static int
lte_overwrite_prepare(struct wim_lookup_table_entry *lte, void *arg)
{
	struct lte_overwrite_prepare_args *args = arg;

	if (lte->resource_location == RESOURCE_IN_WIM &&
	    lte->wim == args->wim &&
	    lte->resource_entry.offset + lte->resource_entry.size > args->end_offset)
	{
	#ifdef ENABLE_ERROR_MESSAGES
		ERROR("The following resource is after the XML data:");
		print_lookup_table_entry(lte, stderr);
	#endif
		return WIMLIB_ERR_RESOURCE_ORDER;
	}

	lte->out_refcnt = lte->refcnt;
	memcpy(&lte->output_resource_entry, &lte->resource_entry,
	       sizeof(struct resource_entry));
	if (!(lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA))
		if (lte->resource_location != RESOURCE_IN_WIM || lte->wim != args->wim)
			list_add(&lte->staging_list, args->stream_list);
	return 0;
}

static int
wim_prepare_streams(WIMStruct *wim, off_t end_offset,
		    struct list_head *stream_list)
{
	struct lte_overwrite_prepare_args args = {
		.wim         = wim,
		.end_offset  = end_offset,
		.stream_list = stream_list,
	};
	int ret;

	for (int i = 0; i < wim->hdr.image_count; i++) {
		ret = lte_overwrite_prepare(wim->image_metadata[i]->metadata_lte,
					    &args);
		if (ret)
			return ret;
	}
	return for_lookup_table_entry(wim->lookup_table,
				      lte_overwrite_prepare, &args);
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
	size_t pos = hash_u64(wim_resource_size(lte)) % tab->capacity;
	struct wim_lookup_table_entry *hashed_lte;
	struct hlist_node *tmp;

	lte->unique_size = 1;
	hlist_for_each_entry(hashed_lte, tmp, &tab->array[pos], hash_list_2) {
		if (wim_resource_size(hashed_lte) == wim_resource_size(lte)) {
			lte->unique_size = 0;
			hashed_lte->unique_size = 0;
			break;
		}
	}

	hlist_add_head(&lte->hash_list_2, &tab->array[pos]);
	tab->num_entries++;
	return 0;
}


struct find_streams_ctx {
	struct list_head stream_list;
	struct stream_size_table stream_size_tab;
};

static int
inode_find_streams_to_write(struct wim_inode *inode,
			    struct wim_lookup_table *table,
			    struct list_head *stream_list,
			    struct stream_size_table *tab)
{
	struct wim_lookup_table_entry *lte;
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		lte = inode_stream_lte(inode, i, table);
		if (lte) {
			if (lte->out_refcnt == 0)
				list_add_tail(&lte->write_streams_list, stream_list);
			lte->out_refcnt += inode->i_nlink;
			if (lte->unhashed)
				stream_size_table_insert(lte, tab);
		}
	}
	return 0;
}

static int
image_find_streams_to_write(WIMStruct *w)
{
	struct wim_image_metadata *imd;
	struct find_streams_ctx *ctx;
	struct wim_inode *inode;
	struct hlist_node *cur;

	ctx = w->private;
 	imd = wim_get_current_image_metadata(w);
	hlist_for_each_entry(inode, cur, &imd->inode_list, i_hlist) {
		inode_find_streams_to_write(inode, w->lookup_table,
					    &ctx->stream_list,
					    &ctx->stream_size_tab);
	}
	return 0;
}

static int
write_wim_streams(WIMStruct *w, int image, int write_flags,
		  unsigned num_threads,
		  wimlib_progress_func_t progress_func)
{
	struct find_streams_ctx ctx;
	int ret;

	for_lookup_table_entry(w->lookup_table, lte_zero_out_refcnt, NULL);
	ret = init_stream_size_table(&ctx.stream_size_tab, 9001);
	if (ret)
		return ret;
	for_lookup_table_entry(w->lookup_table, stream_size_table_insert,
			       &ctx.stream_size_tab);

	INIT_LIST_HEAD(&ctx.stream_list);
	w->private = &ctx;
	for_image(w, image, image_find_streams_to_write);
	destroy_stream_size_table(&ctx.stream_size_tab);
	ret = write_stream_list(&ctx.stream_list,
				w->lookup_table,
				w->out_fp,
				wimlib_get_compression_type(w), write_flags,
				num_threads, progress_func);
	return ret;
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
 * 	(public)  WIMLIB_WRITE_FLAG_SHOW_PROGRESS:
 * 		Show progress information when (if) writing the integrity table.
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
	FILE *out = w->out_fp;

	/* @hdr will be the header for the new WIM.  First copy all the data
	 * from the header in the WIMStruct; then set all the fields that may
	 * have changed, including the resource entries, boot index, and image
	 * count.  */
	memcpy(&hdr, &w->hdr, sizeof(struct wim_header));

	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE)) {
		ret = write_lookup_table(w, image, &hdr.lookup_table_res_entry);
		if (ret != 0)
			goto out;
	}

	ret = write_xml_data(w->wim_info, image, out,
			     (write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE) ?
			      wim_info_get_total_bytes(w->wim_info) : 0,
			     &hdr.xml_res_entry);
	if (ret != 0)
		goto out;

	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
		if (write_flags & WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML) {
			struct wim_header checkpoint_hdr;
			memcpy(&checkpoint_hdr, &hdr, sizeof(struct wim_header));
			memset(&checkpoint_hdr.integrity, 0, sizeof(struct resource_entry));
			if (fseeko(out, 0, SEEK_SET) != 0) {
				ERROR_WITH_ERRNO("Failed to seek to beginning "
						 "of WIM being written");
				ret = WIMLIB_ERR_WRITE;
				goto out;
			}
			ret = write_header(&checkpoint_hdr, out);
			if (ret != 0)
				goto out;

			if (fflush(out) != 0) {
				ERROR_WITH_ERRNO("Can't write data to WIM");
				ret = WIMLIB_ERR_WRITE;
				goto out;
			}

			if (fseeko(out, 0, SEEK_END) != 0) {
				ERROR_WITH_ERRNO("Failed to seek to end "
						 "of WIM being written");
				ret = WIMLIB_ERR_WRITE;
				goto out;
			}
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

		ret = write_integrity_table(out,
					    &hdr.integrity,
					    new_lookup_table_end,
					    old_lookup_table_end,
					    progress_func);
		if (ret != 0)
			goto out;
	} else {
		memset(&hdr.integrity, 0, sizeof(struct resource_entry));
	}

	/*
	 * In the WIM header, there is room for the resource entry for a
	 * metadata resource labeled as the "boot metadata".  This entry should
	 * be zeroed out if there is no bootable image (boot_idx 0).  Otherwise,
	 * it should be a copy of the resource entry for the image that is
	 * marked as bootable.  This is not well documented...
	 */

	/* Set image count and boot index correctly for single image writes */
	if (image != WIMLIB_ALL_IMAGES) {
		hdr.image_count = 1;
		if (hdr.boot_idx == image)
			hdr.boot_idx = 1;
		else
			hdr.boot_idx = 0;
	}

	if (hdr.boot_idx == 0) {
		memset(&hdr.boot_metadata_res_entry, 0,
		       sizeof(struct resource_entry));
	} else {
		memcpy(&hdr.boot_metadata_res_entry,
		       &w->image_metadata[
			  hdr.boot_idx - 1]->metadata_lte->output_resource_entry,
		       sizeof(struct resource_entry));
	}

	if (fseeko(out, 0, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to beginning of WIM "
				 "being written");
		ret = WIMLIB_ERR_WRITE;
		goto out;
	}

	ret = write_header(&hdr, out);
	if (ret)
		goto out;

	if (write_flags & WIMLIB_WRITE_FLAG_FSYNC) {
		if (fflush(out) != 0
		    || fsync(fileno(out)) != 0)
		{
			ERROR_WITH_ERRNO("Error flushing data to WIM file");
			ret = WIMLIB_ERR_WRITE;
		}
	}
out:
	if (fclose(out) != 0) {
		ERROR_WITH_ERRNO("Failed to close the WIM file");
		if (ret == 0)
			ret = WIMLIB_ERR_WRITE;
	}
	w->out_fp = NULL;
	return ret;
}

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
int
lock_wim(WIMStruct *w, FILE *fp)
{
	int ret = 0;
	if (fp && !w->wim_locked) {
		ret = flock(fileno(fp), LOCK_EX | LOCK_NB);
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
open_wim_writable(WIMStruct *w, const tchar *path,
		  bool trunc, bool also_readable)
{
	const tchar *mode;
	if (trunc)
		if (also_readable)
			mode = T("w+b");
		else
			mode = T("wb");
	else
		mode = T("r+b");

	wimlib_assert(w->out_fp == NULL);
	w->out_fp = tfopen(path, mode);
	if (w->out_fp) {
		return 0;
	} else {
		ERROR_WITH_ERRNO("Failed to open `%"TS"' for writing", path);
		return WIMLIB_ERR_OPEN;
	}
}


void
close_wim_writable(WIMStruct *w)
{
	if (w->out_fp) {
		if (fclose(w->out_fp) != 0) {
			WARNING_WITH_ERRNO("Failed to close output WIM");
		}
		w->out_fp = NULL;
	}
}

/* Open file stream and write dummy header for WIM. */
int
begin_write(WIMStruct *w, const tchar *path, int write_flags)
{
	int ret;
	ret = open_wim_writable(w, path, true,
				(write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) != 0);
	if (ret != 0)
		return ret;
	/* Write dummy header. It will be overwritten later. */
	return write_header(&w->hdr, w->out_fp);
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
	if (ret != 0)
		goto out;

	ret = write_wim_streams(w, image, write_flags, num_threads,
				progress_func);
	if (ret != 0)
		goto out;

	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_METADATA_BEGIN, NULL);

	ret = for_image(w, image, write_metadata_resource);
	if (ret != 0)
		goto out;

	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_WRITE_METADATA_END, NULL);

	ret = finish_write(w, image, write_flags, progress_func);
out:
	close_wim_writable(w);
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

	DEBUG("Overwriting `%"TS"' in-place", w->filename);

	/* Make sure that the integrity table (if present) is after the XML
	 * data, and that there are no stream resources, metadata resources, or
	 * lookup tables after the XML data.  Otherwise, these data would be
	 * overwritten. */
	if (w->hdr.integrity.offset != 0 &&
	    w->hdr.integrity.offset < w->hdr.xml_res_entry.offset) {
		ERROR("Didn't expect the integrity table to be before the XML data");
		return WIMLIB_ERR_RESOURCE_ORDER;
	}

	if (w->hdr.lookup_table_res_entry.offset > w->hdr.xml_res_entry.offset) {
		ERROR("Didn't expect the lookup table to be after the XML data");
		return WIMLIB_ERR_RESOURCE_ORDER;
	}


	if (w->hdr.integrity.offset)
		old_wim_end = w->hdr.integrity.offset + w->hdr.integrity.size;
	else
		old_wim_end = w->hdr.xml_res_entry.offset + w->hdr.xml_res_entry.size;

	if (!w->deletion_occurred && !any_images_modified(w)) {
		/* If no images have been modified and no images have been
		 * deleted, a new lookup table does not need to be written. */
		old_wim_end = w->hdr.lookup_table_res_entry.offset +
			      w->hdr.lookup_table_res_entry.size;
		write_flags |= WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE |
			       WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML;
	}
	INIT_LIST_HEAD(&stream_list);
	ret = wim_prepare_streams(w, old_wim_end, &stream_list);
	if (ret != 0)
		return ret;

	ret = open_wim_writable(w, w->filename, false,
				(write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) != 0);
	if (ret != 0)
		return ret;

	ret = lock_wim(w, w->out_fp);
	if (ret != 0) {
		fclose(w->out_fp);
		w->out_fp = NULL;
		return ret;
	}

	if (fseeko(w->out_fp, old_wim_end, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Can't seek to end of WIM");
		fclose(w->out_fp);
		w->out_fp = NULL;
		w->wim_locked = 0;
		return WIMLIB_ERR_WRITE;
	}

	if (!list_empty(&stream_list)) {
		DEBUG("Writing newly added streams (offset = %"PRIu64")",
		      old_wim_end);
		ret = write_stream_list(&stream_list,
					w->lookup_table,
					w->out_fp,
					wimlib_get_compression_type(w),
					write_flags, num_threads,
					progress_func);
		if (ret != 0)
			goto out_ftruncate;
	} else {
		DEBUG("No new streams were added");
	}

	for (int i = 0; i < w->hdr.image_count; i++) {
		if (w->image_metadata[i]->modified) {
			select_wim_image(w, i + 1);
			ret = write_metadata_resource(w);
			if (ret)
				goto out_ftruncate;
		}
	}
	write_flags |= WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE;
	ret = finish_write(w, WIMLIB_ALL_IMAGES, write_flags,
			   progress_func);
out_ftruncate:
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
	if (ret != 0) {
		ERROR("Failed to write the WIM file `%"TS"'", tmpfile);
		goto err;
	}

	DEBUG("Renaming `%"TS"' to `%"TS"'", tmpfile, w->filename);

#ifdef __WIN32__
	/* Windows won't let you delete open files unless FILE_SHARE_DELETE was
	 * specified to CreateFile().  The WIM was opened with fopen(), which
	 * didn't provided this flag to CreateFile, so the handle must be closed
	 * before executing the rename(). */
	if (w->fp != NULL) {
		fclose(w->fp);
		w->fp = NULL;
	}
#endif

	/* Rename the new file to the old file .*/
	if (trename(tmpfile, w->filename) != 0) {
		ERROR_WITH_ERRNO("Failed to rename `%"TS"' to `%"TS"'",
				 tmpfile, w->filename);
		ret = WIMLIB_ERR_RENAME;
		goto err;
	}

	if (progress_func) {
		union wimlib_progress_info progress;
		progress.rename.from = tmpfile;
		progress.rename.to = w->filename;
		progress_func(WIMLIB_PROGRESS_MSG_RENAME, &progress);
	}

	/* Close the original WIM file that was opened for reading. */
	if (w->fp != NULL) {
		fclose(w->fp);
		w->fp = NULL;
	}

	/* Re-open the WIM read-only. */
	w->fp = tfopen(w->filename, T("rb"));
	if (w->fp == NULL) {
		ret = WIMLIB_ERR_REOPEN;
		WARNING_WITH_ERRNO("Failed to re-open `%"TS"' read-only",
				   w->filename);
		FREE(w->filename);
		w->filename = NULL;
	}
	return ret;
err:
	/* Remove temporary file. */
	if (tunlink(tmpfile) != 0)
		WARNING_WITH_ERRNO("Failed to remove `%"TS"'", tmpfile);
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
