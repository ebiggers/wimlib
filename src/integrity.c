/*
 * integrity.c
 *
 * WIM files can optionally contain a table of SHA1 message digests at the end,
 * one digest for each chunk of the file of some specified size (often 10 MB).
 * This file implements the checking and writing of this table.
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

#include "wimlib/assert.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/integrity.h"
#include "wimlib/resource.h"
#include "wimlib/sha1.h"
#include "wimlib/wim.h"

/* Size, in bytes, of each SHA1-summed chunk, when wimlib writes integrity
 * information. */
#define INTEGRITY_CHUNK_SIZE 10485760

/* Only use a different chunk size for compatiblity with an existing integrity
 * table if the chunk size is between these two numbers. */
#define INTEGRITY_MIN_CHUNK_SIZE 4096
#define INTEGRITY_MAX_CHUNK_SIZE 134217728

struct integrity_table {
	u32 size;
	u32 num_entries;
	u32 chunk_size;
	u8  sha1sums[][20];
} _packed_attribute;

static int
calculate_chunk_sha1(struct filedes *in_fd, size_t this_chunk_size,
		     off_t offset, u8 sha1_md[])
{
	u8 buf[BUFFER_SIZE];
	SHA_CTX ctx;
	size_t bytes_remaining;
	size_t bytes_to_read;
	int ret;

	bytes_remaining = this_chunk_size;
	sha1_init(&ctx);
	do {
		bytes_to_read = min(bytes_remaining, sizeof(buf));
		ret = full_pread(in_fd, buf, bytes_to_read, offset);
		if (ret) {
			ERROR_WITH_ERRNO("Read error while calculating "
					 "integrity checksums");
			return ret;
		}
		sha1_update(&ctx, buf, bytes_to_read);
		bytes_remaining -= bytes_to_read;
		offset += bytes_to_read;
	} while (bytes_remaining);
	sha1_final(sha1_md, &ctx);
	return 0;
}


/*
 * read_integrity_table: -  Reads the integrity table from a WIM file.
 *
 * @wim:
 *	WIMStruct for the WIM file; @wim->hdr.integrity specifies the location
 *	of the integrity table.  The integrity table must exist (i.e.
 *	res_entry->offset must not be 0).  @wim->in_fd is expected to be a
 *	seekable file descriptor to the WIM file opened for reading.
 *
 * @num_checked_bytes:
 *	Number of bytes of data that should be checked by the integrity table.
 *
 * @table_ret:
 *	On success, a pointer to an in-memory structure containing the integrity
 *	information is written to this location.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_INTEGRITY_TABLE
 *	WIMLIB_ERR_NOMEM
 *	WIMLIB_ERR_READ
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 */
static int
read_integrity_table(WIMStruct *wim, u64 num_checked_bytes,
		     struct integrity_table **table_ret)
{
	struct integrity_table *table;
	int ret;

	if (wim->hdr.integrity.size < 8)
		goto invalid;

	DEBUG("Reading integrity table (offset %"PRIu64", "
	      "original_size %"PRIu64")",
	      wim->hdr.integrity.offset, wim->hdr.integrity.original_size);

	ret = res_entry_to_data(&wim->hdr.integrity, wim, (void**)&table);
	if (ret)
		return ret;

	table->size        = le32_to_cpu(table->size);
	table->num_entries = le32_to_cpu(table->num_entries);
	table->chunk_size  = le32_to_cpu(table->chunk_size);

	DEBUG("table->size = %u, table->num_entries = %u, "
	      "table->chunk_size = %u",
	      table->size, table->num_entries, table->chunk_size);

	if (table->size != wim->hdr.integrity.original_size ||
	    table->size != (u64)table->num_entries * SHA1_HASH_SIZE + 12 ||
	    table->chunk_size == 0 ||
	    table->num_entries != DIV_ROUND_UP(num_checked_bytes, table->chunk_size))
	{
		FREE(table);
		goto invalid;
	}

	*table_ret = table;
	return 0;

invalid:
	ERROR("Integrity table is invalid");
	return WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
}

/*
 * calculate_integrity_table():
 *
 * Calculates an integrity table for the data in a file beginning at offset 208
 * (WIM_HEADER_DISK_SIZE).
 *
 * @in_fd:
 *	File descriptor for the file to be checked, opened for reading.  Does
 *	not need to be at any specific location in the file.
 *
 * @new_check_end:
 *	Offset of byte after the last byte to be checked.
 *
 * @old_table:
 *	If non-NULL, a pointer to the table containing the previously calculated
 *	integrity data for a prefix of this file.
 *
 * @old_check_end:
 *	If @old_table is non-NULL, the byte after the last byte that was checked
 *	in the old table.  Must be less than or equal to new_check_end.
 *
 * @progress_func:
 *	If non-NULL, a progress function that will be called after every
 *	calculated chunk.
 *
 * @integrity_table_ret:
 *	On success, a pointer to the calculated integrity table is written into
 *	this location.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_NOMEM
 *	WIMLIB_ERR_READ
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 */
static int
calculate_integrity_table(struct filedes *in_fd,
			  off_t new_check_end,
			  const struct integrity_table *old_table,
			  off_t old_check_end,
			  wimlib_progress_func_t progress_func,
			  struct integrity_table **integrity_table_ret)
{
	int ret;
	size_t chunk_size = INTEGRITY_CHUNK_SIZE;

	/* If an old table is provided, set the chunk size to be compatible with
	 * the old chunk size, unless the old chunk size was weird. */
	if (old_table != NULL) {
		if (old_table->num_entries == 0 ||
		    old_table->chunk_size < INTEGRITY_MIN_CHUNK_SIZE ||
		    old_table->chunk_size > INTEGRITY_MAX_CHUNK_SIZE)
			old_table = NULL;
		else
			chunk_size = old_table->chunk_size;
	}


	u64 old_check_bytes = old_check_end - WIM_HEADER_DISK_SIZE;
	u64 new_check_bytes = new_check_end - WIM_HEADER_DISK_SIZE;

	u32 old_num_chunks = DIV_ROUND_UP(old_check_bytes, chunk_size);
	u32 new_num_chunks = DIV_ROUND_UP(new_check_bytes, chunk_size);

	size_t old_last_chunk_size = MODULO_NONZERO(old_check_bytes, chunk_size);
	size_t new_last_chunk_size = MODULO_NONZERO(new_check_bytes, chunk_size);

	size_t new_table_size = 12 + new_num_chunks * SHA1_HASH_SIZE;

	struct integrity_table *new_table = MALLOC(new_table_size);
	if (!new_table)
		return WIMLIB_ERR_NOMEM;
	new_table->num_entries = new_num_chunks;
	new_table->size = new_table_size;
	new_table->chunk_size = chunk_size;

	u64 offset = WIM_HEADER_DISK_SIZE;
	union wimlib_progress_info progress;

	if (progress_func) {
		progress.integrity.total_bytes      = new_check_bytes;
		progress.integrity.total_chunks     = new_num_chunks;
		progress.integrity.completed_chunks = 0;
		progress.integrity.completed_bytes  = 0;
		progress.integrity.chunk_size       = chunk_size;
		progress.integrity.filename         = NULL;
		progress_func(WIMLIB_PROGRESS_MSG_CALC_INTEGRITY,
			      &progress);
	}

	for (u32 i = 0; i < new_num_chunks; i++) {
		size_t this_chunk_size;
		if (i == new_num_chunks - 1)
			this_chunk_size = new_last_chunk_size;
		else
			this_chunk_size = chunk_size;
		if (old_table &&
		    ((this_chunk_size == chunk_size && i < old_num_chunks - 1) ||
		      (i == old_num_chunks - 1 && this_chunk_size == old_last_chunk_size)))
		{
			/* Can use SHA1 message digest from old integrity table
			 * */
			copy_hash(new_table->sha1sums[i], old_table->sha1sums[i]);
		} else {
			/* Calculate the SHA1 message digest of this chunk */
			ret = calculate_chunk_sha1(in_fd, this_chunk_size,
						   offset, new_table->sha1sums[i]);
			if (ret) {
				FREE(new_table);
				return ret;
			}
		}
		offset += this_chunk_size;
		if (progress_func) {
			progress.integrity.completed_chunks++;
			progress.integrity.completed_bytes += this_chunk_size;
			progress_func(WIMLIB_PROGRESS_MSG_CALC_INTEGRITY,
				      &progress);
		}
	}
	*integrity_table_ret = new_table;
	return 0;
}

/*
 * write_integrity_table():
 *
 * Writes a WIM integrity table (a list of SHA1 message digests of raw 10 MiB
 * chunks of the file).
 *
 * This function can optionally re-use entries from an older integrity table.
 * To do this, make @integrity_res_entry point to the resource entry for the
 * older table (note: this is an input-output parameter), and set
 * @old_lookup_table_end to the offset of the byte directly following the last
 * byte checked by the old table.  If the old integrity table is invalid or
 * cannot be read, a warning is printed and the integrity information is
 * re-calculated.
 *
 * @wim:
 *	WIMStruct for the WIM file.  @wim->out_fd must be a seekable descriptor
 *	to the new WIM file, opened read-write, positioned at the location at
 *	which the integrity table is to be written.  Furthermore,
 *	@wim->hdr.integrity is expected to be a resource entry which will be set
 *	to the integrity table information on success.  In addition, if
 *	@old_lookup_table_end != 0, @wim->hdr.integrity must initially contain
 *	information about the old integrity table, and @wim->in_fd must be a
 *	seekable descriptor to the original WIM file opened for reading.
 *
 * @new_lookup_table_end:
 *	The offset of the byte directly following the lookup table in the WIM
 *	being written.
 *
 * @old_lookup_table_end:
 *	If nonzero, the offset of the byte directly following the old lookup
 *	table in the WIM.
 *
 * @progress_func
 *	If non-NULL, a progress function that will be called after every
 *	calculated chunk.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_INTEGRITY_TABLE
 *	WIMLIB_ERR_NOMEM
 *	WIMLIB_ERR_READ
 *	WIMLIB_ERR_UNEXPECTED_END_OF_FILE
 *	WIMLIB_ERR_WRITE
 */
int
write_integrity_table(WIMStruct *wim,
		      off_t new_lookup_table_end,
		      off_t old_lookup_table_end,
		      wimlib_progress_func_t progress_func)
{
	struct integrity_table *old_table;
	struct integrity_table *new_table;
	int ret;
	off_t cur_offset;
	u32 new_table_size;

	wimlib_assert(old_lookup_table_end <= new_lookup_table_end);

	cur_offset = wim->out_fd.offset;

	if (wim->hdr.integrity.offset == 0 || old_lookup_table_end == 0) {
		old_table = NULL;
	} else {
		ret = read_integrity_table(wim,
					   old_lookup_table_end - WIM_HEADER_DISK_SIZE,
					   &old_table);
		if (ret == WIMLIB_ERR_INVALID_INTEGRITY_TABLE) {
			WARNING("Old integrity table is invalid! "
				"Ignoring it");
		} else if (ret != 0) {
			WARNING("Can't read old integrity table! "
				"Ignoring it");
		}
	}

	ret = calculate_integrity_table(&wim->out_fd, new_lookup_table_end,
					old_table, old_lookup_table_end,
					progress_func, &new_table);
	if (ret)
		goto out_free_old_table;

	new_table_size = new_table->size;

	new_table->size        = cpu_to_le32(new_table->size);
	new_table->num_entries = cpu_to_le32(new_table->num_entries);
	new_table->chunk_size  = cpu_to_le32(new_table->chunk_size);

	ret = write_wim_resource_from_buffer(new_table,
					     new_table_size,
					     0,
					     &wim->out_fd,
					     WIMLIB_COMPRESSION_TYPE_NONE,
					     &wim->hdr.integrity,
					     NULL,
					     0);
	FREE(new_table);
out_free_old_table:
	FREE(old_table);
	return ret;
}

/*
 * verify_integrity():
 *
 * Checks a WIM for consistency with the integrity table.
 *
 * @in_fd:
 *	File descriptor to the WIM file, opened for reading.
 *
 * @table:
 *	The integrity table for the WIM, read into memory.
 *
 * @bytes_to_check:
 *	Number of bytes in the WIM that need to be checked (offset of end of the
 *	lookup table minus offset of end of the header).
 *
 * @progress_func
 *	If non-NULL, a progress function that will be called after every
 *	verified chunk.
 *
 * Returns:
 *	> 0 (WIMLIB_ERR_READ, WIMLIB_ERR_UNEXPECTED_END_OF_FILE) on error
 *	0 (WIM_INTEGRITY_OK) if the integrity was checked successfully and there
 *	were no inconsistencies.
 *	-1 (WIM_INTEGRITY_NOT_OK) if the WIM failed the integrity check.
 */
static int
verify_integrity(struct filedes *in_fd, const tchar *filename,
		 const struct integrity_table *table,
		 u64 bytes_to_check,
		 wimlib_progress_func_t progress_func)
{
	int ret;
	u64 offset = WIM_HEADER_DISK_SIZE;
	u8 sha1_md[SHA1_HASH_SIZE];
	union wimlib_progress_info progress;

	if (progress_func) {
		progress.integrity.total_bytes      = bytes_to_check;
		progress.integrity.total_chunks     = table->num_entries;
		progress.integrity.completed_chunks = 0;
		progress.integrity.completed_bytes  = 0;
		progress.integrity.chunk_size       = table->chunk_size;
		progress.integrity.filename         = filename;
		progress_func(WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY,
			      &progress);
	}
	for (u32 i = 0; i < table->num_entries; i++) {
		size_t this_chunk_size;
		if (i == table->num_entries - 1)
			this_chunk_size = MODULO_NONZERO(bytes_to_check,
							 table->chunk_size);
		else
			this_chunk_size = table->chunk_size;

		ret = calculate_chunk_sha1(in_fd, this_chunk_size, offset, sha1_md);
		if (ret)
			return ret;

		if (!hashes_equal(sha1_md, table->sha1sums[i]))
			return WIM_INTEGRITY_NOT_OK;

		offset += this_chunk_size;
		if (progress_func) {
			progress.integrity.completed_chunks++;
			progress.integrity.completed_bytes += this_chunk_size;
			progress_func(WIMLIB_PROGRESS_MSG_VERIFY_INTEGRITY,
				      &progress);
		}
	}
	return WIM_INTEGRITY_OK;
}


/*
 * check_wim_integrity():
 *
 * Verifies the integrity of the WIM by making sure the SHA1 message digests of
 * ~10 MiB chunks of the WIM match up with the values given in the integrity
 * table.
 *
 * @wim:
 *	The WIM, opened for reading.
 *
 * @progress_func
 *	If non-NULL, a progress function that will be called after every
 *	verified chunk.
 *
 * Returns:
 *	> 0 (WIMLIB_ERR_INVALID_INTEGRITY_TABLE, WIMLIB_ERR_READ,
 *	     WIMLIB_ERR_UNEXPECTED_END_OF_FILE) on error
 *	0 (WIM_INTEGRITY_OK) if the integrity was checked successfully and there
 *	were no inconsistencies.
 *	-1 (WIM_INTEGRITY_NOT_OK) if the WIM failed the integrity check.
 *	-2 (WIM_INTEGRITY_NONEXISTENT) if the WIM contains no integrity
 *	information.
 */
int
check_wim_integrity(WIMStruct *wim, wimlib_progress_func_t progress_func)
{
	int ret;
	u64 bytes_to_check;
	struct integrity_table *table;
	u64 end_lookup_table_offset;

	if (wim->hdr.integrity.offset == 0) {
		DEBUG("No integrity information.");
		return WIM_INTEGRITY_NONEXISTENT;
	}

	end_lookup_table_offset = wim->hdr.lookup_table_res_entry.offset +
				  wim->hdr.lookup_table_res_entry.size;

	if (end_lookup_table_offset < WIM_HEADER_DISK_SIZE) {
		ERROR("WIM lookup table ends before WIM header ends!");
		return WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
	}

	bytes_to_check = end_lookup_table_offset - WIM_HEADER_DISK_SIZE;

	ret = read_integrity_table(wim, bytes_to_check, &table);
	if (ret)
		return ret;
	ret = verify_integrity(&wim->in_fd, wim->filename, table,
			       bytes_to_check, progress_func);
	FREE(table);
	return ret;
}
