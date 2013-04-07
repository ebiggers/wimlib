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

#include "wimlib_internal.h"
#include "dentry.h"
#include "lookup_table.h"
#include "buffer_io.h"
#include "sha1.h"

#ifdef __WIN32__
#  include "win32.h"
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif

/* Write @n bytes from @buf to the file descriptor @fd, retrying on internupt
 * and on short writes.
 *
 * Returns short count and set errno on failure. */
static ssize_t
full_write(int fd, const void *buf, size_t n)
{
	const void *p = buf;
	ssize_t ret;
	ssize_t total = 0;

	while (total != n) {
		ret = write(fd, p, n);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			else
				break;
		}
		total += ret;
		p += ret;
	}
	return total;
}

/* Read @n bytes from the file descriptor @fd to the buffer @buf, retrying on
 * internupt and on short reads.
 *
 * Returns short count and set errno on failure. */
static size_t
full_read(int fd, void *buf, size_t n)
{
	size_t bytes_remaining = n;
	while (bytes_remaining) {
		ssize_t bytes_read = read(fd, buf, bytes_remaining);
		if (bytes_read < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		bytes_remaining -= bytes_read;
		buf += bytes_read;
	}
	return n - bytes_remaining;
}

/*
 * Reads all or part of a compressed WIM resource.
 *
 * Returns zero on success, nonzero on failure.
 */
static int
read_compressed_resource(FILE *fp,
			 u64 resource_compressed_size,
			 u64 resource_uncompressed_size,
			 u64 resource_offset,
			 int resource_ctype,
			 u64 len,
			 u64 offset,
			 consume_data_callback_t cb,
			 void *ctx_or_buf)
{
	int ret;

	/* Trivial case */
	if (len == 0)
		return 0;

	int (*decompress)(const void *, unsigned, void *, unsigned);
	/* Set the appropriate decompress function. */
	if (resource_ctype == WIMLIB_COMPRESSION_TYPE_LZX)
		decompress = wimlib_lzx_decompress;
	else
		decompress = wimlib_xpress_decompress;

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

	/* Calculate how many chunks the resource consists of in its entirety.
	 * */
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

	/* Allocate the chunk table.  It will only contain offsets for the
	 * chunks that are actually needed for this read. */
	u64 *chunk_offsets;
	bool chunk_offsets_malloced;
	if (num_needed_chunks < 1000) {
		chunk_offsets = alloca(num_needed_chunks * sizeof(u64));
		chunk_offsets_malloced = false;
	} else {
		chunk_offsets = malloc(num_needed_chunks * sizeof(u64));
		if (!chunk_offsets) {
			ERROR("Failed to allocate chunk table "
			      "with %"PRIu64" entries", num_needed_chunks);
			return WIMLIB_ERR_NOMEM;
		}
		chunk_offsets_malloced = true;
	}

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
	if (fseeko(fp, file_offset_of_needed_chunk_entries, SEEK_SET))
		goto read_error;

	/* Number of bytes we need to read from the chunk table. */
	size_t size = num_needed_chunk_entries * chunk_entry_size;

	/* Read the raw data into the end of the chunk_offsets array to
	 * avoid allocating another array. */
	void *chunk_tab_buf = (void*)&chunk_offsets[num_needed_chunks] - size;

	if (fread(chunk_tab_buf, 1, size, fp) != size)
		goto read_error;

	/* Now fill in chunk_offsets from the entries we have read in
	 * chunk_tab_buf. */

	u64 *chunk_tab_p = chunk_offsets;
	if (start_chunk == 0)
		chunk_tab_p++;

	if (chunk_entry_size == 4) {
		u32 *entries = (u32*)chunk_tab_buf;
		while (num_needed_chunk_entries--)
			*chunk_tab_p++ = le32_to_cpu(*entries++);
	} else {
		u64 *entries = (u64*)chunk_tab_buf;
		while (num_needed_chunk_entries--)
			*chunk_tab_p++ = le64_to_cpu(*entries++);
	}

	/* Done with the chunk table now.  We must now seek to the first chunk
	 * that is needed for the read. */

	u64 file_offset_of_first_needed_chunk = resource_offset +
				chunk_table_size + chunk_offsets[0];
	if (fseeko(fp, file_offset_of_first_needed_chunk, SEEK_SET))
		goto read_error;

	/* Pointer to current position in the output buffer for uncompressed
	 * data.  Alternatively, if using a callback function, we repeatedly
	 * fill a temporary buffer to feed data into the callback function.  */
	u8 *out_p;
	if (cb)
		out_p = alloca(WIM_CHUNK_SIZE);
	else
		out_p = ctx_or_buf;

	/* Buffer for compressed data.  While most compressed chunks will have a
	 * size much less than WIM_CHUNK_SIZE, WIM_CHUNK_SIZE - 1 is the maximum
	 * size in the worst-case.  This assumption is valid only if chunks that
	 * happen to compress to more than the uncompressed size (i.e. a
	 * sequence of random bytes) are always stored uncompressed. But this seems
	 * to be the case in M$'s WIM files, even though it is undocumented. */
	void *compressed_buf = alloca(WIM_CHUNK_SIZE - 1);

	/* Decompress all the chunks. */
	for (u64 i = start_chunk; i <= end_chunk; i++) {

		/* Calculate the sizes of the compressed chunk and of the
		 * uncompressed chunk. */
		unsigned compressed_chunk_size;
		unsigned uncompressed_chunk_size;
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

		unsigned partial_chunk_size = end_offset + 1 - start_offset;
		bool is_partial_chunk = (partial_chunk_size != uncompressed_chunk_size);

		/* This is undocumented, but chunks can be uncompressed.  This
		 * appears to always be the case when the compressed chunk size
		 * is equal to the uncompressed chunk size. */
		if (compressed_chunk_size == uncompressed_chunk_size) {
			/* Uncompressed chunk */

			if (start_offset != 0)
				if (fseeko(fp, start_offset, SEEK_CUR))
					goto read_error;
			if (fread(out_p, 1, partial_chunk_size, fp) != partial_chunk_size)
				goto read_error;
		} else {
			/* Compressed chunk */

			/* Read the compressed data into compressed_buf. */
			if (fread(compressed_buf, 1, compressed_chunk_size,
						fp) != compressed_chunk_size)
				goto read_error;

			/* For partial chunks and when writing directly to a
			 * buffer, we must buffer the uncompressed data because
			 * we don't need all of it. */
			if (is_partial_chunk && !cb) {
				u8 uncompressed_buf[uncompressed_chunk_size];

				ret = decompress(compressed_buf,
						 compressed_chunk_size,
						 uncompressed_buf,
						 uncompressed_chunk_size);
				if (ret) {
					ret = WIMLIB_ERR_DECOMPRESSION;
					goto out;
				}
				memcpy(out_p, uncompressed_buf + start_offset,
				       partial_chunk_size);
			} else {
				ret = decompress(compressed_buf,
						 compressed_chunk_size,
						 out_p,
						 uncompressed_chunk_size);
				if (ret) {
					ret = WIMLIB_ERR_DECOMPRESSION;
					goto out;
				}
			}
		}
		if (cb) {
			/* Feed the data to the callback function */
			ret = cb(out_p + start_offset,
				 partial_chunk_size, ctx_or_buf);
			if (ret)
				goto out;
		} else {
			/* No callback function provided; we are writing
			 * directly to a buffer.  Advance the pointer into this
			 * buffer by the number of uncompressed bytes that were
			 * written.  */
			out_p += partial_chunk_size;
		}
	}

	ret = 0;
out:
	if (chunk_offsets_malloced)
		FREE(chunk_offsets);
	return ret;

read_error:
	if (feof(fp))
		ERROR("Unexpected EOF in compressed file resource");
	else
		ERROR_WITH_ERRNO("Error reading compressed file resource");
	ret = WIMLIB_ERR_READ;
	goto out;
}

/*
 * Reads uncompressed data from an open file stream.
 */
int
read_uncompressed_resource(FILE *fp, u64 offset, u64 len, void *contents_ret)
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
const void *
get_resource_entry(const void *p, struct resource_entry *entry)
{
	u64 size;
	u8 flags;

	p = get_u56(p, &size);
	p = get_u8(p, &flags);
	entry->size = size;
	entry->flags = flags;

	/* offset and original_size are truncated to 62 bits to avoid possible
	 * overflows, when converting to a signed 64-bit integer (off_t) or when
	 * adding size or original_size.  This is okay since no one would ever
	 * actually have a WIM bigger than 4611686018427387903 bytes... */
	p = get_u64(p, &entry->offset);
	if (entry->offset & 0xc000000000000000ULL) {
		WARNING("Truncating offset in resource entry");
		entry->offset &= 0x3fffffffffffffffULL;
	}
	p = get_u64(p, &entry->original_size);
	if (entry->original_size & 0xc000000000000000ULL) {
		WARNING("Truncating original_size in resource entry");
		entry->original_size &= 0x3fffffffffffffffULL;
	}
	return p;
}

/* Copies the struct resource_entry @entry to the memory pointed to by @p in the
 * on-disk format.  A pointer to the byte after the memory written at @p is
 * returned. */
void *
put_resource_entry(void *p, const struct resource_entry *entry)
{
	p = put_u56(p, entry->size);
	p = put_u8(p, entry->flags);
	p = put_u64(p, entry->offset);
	p = put_u64(p, entry->original_size);
	return p;
}

static FILE *
wim_get_fp(WIMStruct *w)
{
#ifdef WITH_FUSE
	pthread_mutex_lock(&w->fp_tab_mutex);
	FILE *fp;

	wimlib_assert(w->filename != NULL);

	for (size_t i = 0; i < w->num_allocated_fps; i++) {
		if (w->fp_tab[i]) {
			fp = w->fp_tab[i];
			w->fp_tab[i] = NULL;
			goto out_unlock;
		}
	}
	DEBUG("Opening extra file descriptor to `%"TS"'", w->filename);
	fp = tfopen(w->filename, T("rb"));
	if (!fp)
		ERROR_WITH_ERRNO("Failed to open `%"TS"'", w->filename);
out_unlock:
	pthread_mutex_unlock(&w->fp_tab_mutex);
#else /* WITH_FUSE */
	fp = w->fp;
#endif /* !WITH_FUSE */
	return fp;
}

static int
wim_release_fp(WIMStruct *w, FILE *fp)
{
	int ret = 0;
#ifdef WITH_FUSE
	FILE **fp_tab;

	pthread_mutex_lock(&w->fp_tab_mutex);

	for (size_t i = 0; i < w->num_allocated_fps; i++) {
		if (w->fp_tab[i] == NULL) {
			w->fp_tab[i] = fp;
			goto out_unlock;
		}
	}

	fp_tab = REALLOC(w->fp_tab, sizeof(FILE*) * (w->num_allocated_fps + 4));
	if (!fp_tab) {
		ret = WIMLIB_ERR_NOMEM;
		fclose(fp);
		goto out_unlock;
	}
	w->fp_tab = fp_tab;
	memset(&w->fp_tab[w->num_allocated_fps], 0, 4 * sizeof(FILE*));
	w->fp_tab[w->num_allocated_fps] = fp;
	w->num_allocated_fps += 4;
out_unlock:
	pthread_mutex_unlock(&w->fp_tab_mutex);
#endif /* WITH_FUSE */
	return ret;
}

static int
read_partial_wim_resource(const struct wim_lookup_table_entry *lte,
			  u64 size,
			  consume_data_callback_t cb,
			  void *ctx_or_buf,
			  int flags,
			  u64 offset)
{
	FILE *wim_fp;
	WIMStruct *wim;
	int ret;

	wimlib_assert(lte->resource_location == RESOURCE_IN_WIM);
	wimlib_assert(offset + size <= lte->resource_entry.original_size);

	wim = lte->wim;

	if (flags & WIMLIB_RESOURCE_FLAG_THREADSAFE_READ) {
		wim_fp = wim_get_fp(wim);
		if (!wim_fp) {
			ret = -1;
			goto out;
		}
	} else {
		wim_fp = lte->wim->fp;
	}

	wimlib_assert(wim_fp != NULL);

	if (lte->resource_entry.flags & WIM_RESHDR_FLAG_COMPRESSED &&
	    !(flags & WIMLIB_RESOURCE_FLAG_RAW))
	{
		ret = read_compressed_resource(wim_fp,
					       lte->resource_entry.size,
					       lte->resource_entry.original_size,
					       lte->resource_entry.offset,
					       wimlib_get_compression_type(wim),
					       size,
					       offset,
					       cb,
					       ctx_or_buf);
	} else {
		offset += lte->resource_entry.offset;

		if (fseeko(wim_fp, offset, SEEK_SET)) {
			ERROR_WITH_ERRNO("Failed to seek to offset %"PRIu64
					 " in WIM", offset);
			ret = WIMLIB_ERR_READ;
			goto out_release_fp;
		}
		if (cb) {
			/* Send data to callback function */
			u8 buf[min(WIM_CHUNK_SIZE, size)];
			while (size) {
				size_t bytes_to_read = min(WIM_CHUNK_SIZE, size);
				size_t bytes_read = fread(buf, 1, bytes_to_read, wim_fp);

				if (bytes_read != bytes_to_read)
					goto read_error;
				ret = cb(buf, bytes_read, ctx_or_buf);
				if (ret)
					goto out_release_fp;
				size -= bytes_read;
			}
		} else {
			/* Send data directly to a buffer */
			if (fread(ctx_or_buf, 1, size, wim_fp) != size)
				goto read_error;
		}
		ret = 0;
	}
	goto out_release_fp;
read_error:
	if (ferror(wim_fp)) {
		ERROR_WITH_ERRNO("Error reading data from WIM");
	} else {
		ERROR("Unexpected EOF in WIM!");
	}
	ret = WIMLIB_ERR_READ;
out_release_fp:
	if (flags & WIMLIB_RESOURCE_FLAG_THREADSAFE_READ)
		ret |= wim_release_fp(wim, wim_fp);
out:
	if (ret) {
		if (errno == 0)
			errno = EIO;
	}
	return ret;
}


int
read_partial_wim_resource_into_buf(const struct wim_lookup_table_entry *lte,
				   size_t size, u64 offset, void *buf,
				   bool threadsafe)
{
	return read_partial_wim_resource(lte, size, NULL, buf,
					 threadsafe ? WIMLIB_RESOURCE_FLAG_THREADSAFE_READ : 0,
					 offset);
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


static int
read_file_on_disk_prefix(const struct wim_lookup_table_entry *lte,
			 u64 size,
			 consume_data_callback_t cb,
			 void *ctx_or_buf,
			 int _ignored_flags)
{
	const tchar *filename = lte->file_on_disk;
	int ret;
	int fd;
	size_t bytes_read;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		ERROR_WITH_ERRNO("Can't open \"%"TS"\"", filename);
		return WIMLIB_ERR_OPEN;
	}
	if (cb) {
		/* Send data to callback function */
		u8 buf[min(WIM_CHUNK_SIZE, size)];
		size_t bytes_to_read;
		while (size) {
			bytes_to_read = min(WIM_CHUNK_SIZE, size);
			bytes_read = full_read(fd, buf, bytes_to_read);
			if (bytes_read != bytes_to_read)
				goto read_error;
			ret = cb(buf, bytes_read, ctx_or_buf);
			if (ret)
				goto out_close;
			size -= bytes_read;
		}
	} else {
		/* Send data directly to a buffer */
		bytes_read = full_read(fd, ctx_or_buf, size);
		if (bytes_read != size)
			goto read_error;
	}
	ret = 0;
	goto out_close;
read_error:
	ERROR_WITH_ERRNO("Error reading \"%"TS"\"", filename);
	ret = WIMLIB_ERR_READ;
out_close:
	close(fd);
	return ret;
}

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
 * If the resource is located in a WIM file, @flags can be:
 *   * WIMLIB_RESOURCE_FLAG_THREADSAFE_READ if it must be safe to access the resource
 *     concurrently by multiple threads.
 *   * WIMLIB_RESOURCE_FLAG_RAW if the raw compressed data is to be supplied
 *     instead of the uncompressed data.
 * Otherwise, the @flags are ignored.
 */
int
read_resource_prefix(const struct wim_lookup_table_entry *lte,
		     u64 size, consume_data_callback_t cb, void *ctx_or_buf,
		     int flags)
{
	static const read_resource_prefix_handler_t handlers[] = {
		[RESOURCE_IN_WIM]             = read_wim_resource_prefix,
		[RESOURCE_IN_FILE_ON_DISK]    = read_file_on_disk_prefix,
		[RESOURCE_IN_ATTACHED_BUFFER] = read_buffer_prefix,
	#ifdef WITH_FUSE
		[RESOURCE_IN_STAGING_FILE]    = read_file_on_disk_prefix,
	#endif
	#ifdef WITH_NTFS_3G
		[RESOURCE_IN_NTFS_VOLUME]     = read_ntfs_file_prefix,
	#endif
	#ifdef __WIN32__
		[RESOURCE_WIN32]              = read_win32_file_prefix,
		[RESOURCE_WIN32_ENCRYPTED]    = read_win32_encrypted_file_prefix,
	#endif
	};
	wimlib_assert(lte->resource_location < ARRAY_LEN(handlers)
		      && handlers[lte->resource_location] != NULL);
	return handlers[lte->resource_location](lte, size, cb, ctx_or_buf, flags);
}

int
read_full_resource_into_buf(const struct wim_lookup_table_entry *lte,
			    void *buf, bool thread_safe)
{
	return read_resource_prefix(lte,
				    wim_resource_size(lte),
				    NULL, buf,
				    thread_safe ? WIMLIB_RESOURCE_FLAG_THREADSAFE_READ : 0);
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
			#ifdef ENABLE_ERROR_MESSAGES
				ERROR_WITH_ERRNO("Invalid SHA1 message digest "
						 "on the following WIM resource:");
				print_lookup_table_entry(lte, stderr);
				if (lte->resource_location == RESOURCE_IN_WIM)
					ERROR("The WIM file appears to be corrupt!");
				ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
			#endif
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
	int fd = *(int*)_fd_p;
	ssize_t ret = full_write(fd, buf, len);
	if (ret < len) {
		ERROR_WITH_ERRNO("Error writing to file descriptor");
		return WIMLIB_ERR_WRITE;
	} else {
		return 0;
	}
}

int
extract_wim_resource_to_fd(const struct wim_lookup_table_entry *lte,
			   int fd, u64 size)
{
	return extract_wim_resource(lte, size, extract_wim_chunk_to_fd, &fd);
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

/*
 * Copies the file resource specified by the lookup table entry @lte from the
 * input WIM to the output WIM that has its FILE * given by
 * ((WIMStruct*)wim)->out_fp.
 *
 * The output_resource_entry, out_refcnt, and part_number fields of @lte are
 * updated.
 *
 * (This function is confusing and should be refactored somehow.)
 */
int
copy_resource(struct wim_lookup_table_entry *lte, void *wim)
{
	WIMStruct *w = wim;
	int ret;

	ret = write_wim_resource(lte, w->out_fp,
				 wim_resource_compression_type(lte),
				 &lte->output_resource_entry, 0);
	if (ret == 0) {
		lte->out_refcnt = lte->refcnt;
		lte->part_number = w->hdr.part_number;
	}
	return ret;
}
