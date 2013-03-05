/*
 * integrity.c
 *
 * WIM files can optionally contain a table of SHA1 message digests at the end,
 * one digest for each chunk of the file of some specified size (often 10 MB).
 * This file implements the checking and writing of this table.
 */

/*
 * Copyright (C) 2012, 2013 Biggers
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

#include "wimlib_internal.h"
#include "buffer_io.h"
#include "sha1.h"

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
	u8  sha1sums[0][20];
};

static int calculate_chunk_sha1(FILE *fp, size_t this_chunk_size,
				off_t offset, u8 sha1_md[])
{
	int ret;
	u8 buf[BUFFER_SIZE];
	SHA_CTX ctx;
	size_t bytes_remaining;
	size_t bytes_to_read;
	size_t bytes_read;

	ret = fseeko(fp, offset, SEEK_SET);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Can't seek to offset "
				 "%"PRIu64" in WIM", offset);
		return WIMLIB_ERR_READ;
	}
	bytes_remaining = this_chunk_size;
	sha1_init(&ctx);
	do {
		bytes_to_read = min(bytes_remaining, sizeof(buf));
		bytes_read = fread(buf, 1, bytes_to_read, fp);
		if (bytes_read != bytes_to_read) {
			if (feof(fp)) {
				ERROR("Unexpected EOF while calculating "
				      "integrity checksums");
			} else {
				ERROR_WITH_ERRNO("File stream error while "
						 "calculating integrity "
						 "checksums");
			}
			return WIMLIB_ERR_READ;
		}
		sha1_update(&ctx, buf, bytes_read);
		bytes_remaining -= bytes_read;
	} while (bytes_remaining);
	sha1_final(sha1_md, &ctx);
	return 0;
}


/*
 * read_integrity_table: -  Reads the integrity table from a WIM file.
 *
 * @res_entry:
 * 	The resource entry that specifies the location of the integrity table.
 * 	The integrity table must exist (i.e. res_entry->offset must not be 0).
 *
 * @fp:
 * 	FILE * to the WIM file, opened for reading.
 *
 * @num_checked_bytes:
 * 	Number of bytes of data that should be checked by the integrity table.
 *
 * @table ret:
 * 	On success, a pointer to an in-memory structure containing the integrity
 * 	information is written to this location.
 *
 * Returns 0 on success; nonzero on failure.  The possible error codes are:
 *
 *     * WIMLIB_ERR_INVALID_INTEGRITY_TABLE:  The integrity table is invalid.
 *     * WIMLIB_ERR_NOMEM:  Could not allocate memory to store the integrity
 *     			    data.
 *     * WIMLIB_ERR_READ:   Could not read the integrity data from the WIM file.
 */
static int read_integrity_table(const struct resource_entry *res_entry,
				FILE *fp,
				u64 num_checked_bytes,
				struct integrity_table **table_ret)
{
	struct integrity_table *table = NULL;
	int ret = 0;
	u64 expected_size;
	u64 expected_num_entries;

	if (resource_is_compressed(res_entry)) {
		ERROR("Didn't expect a compressed integrity table");
		return WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
	}

	if (res_entry->size < 8 || res_entry->size  > 0xffffffff) {
		ERROR("Integrity table resource header is invalid");
		return WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
	}

	/* Read the integrity table into memory. */
	if ((table = MALLOC(res_entry->size)) == NULL) {
		ERROR("Can't allocate %"PRIu64" bytes for integrity table",
		      (u64)res_entry->size);
		return WIMLIB_ERR_NOMEM;
	}

	ret = read_uncompressed_resource(fp, res_entry->offset,
					 res_entry->size, (void*)table);

	if (ret != 0) {
		ERROR("Failed to read integrity table (size = %u, "
		      " offset = %"PRIu64")",
		      (unsigned)res_entry->size, res_entry->offset);
		goto out;
	}

	table->size        = le32_to_cpu(table->size);
	table->num_entries = le32_to_cpu(table->num_entries);
	table->chunk_size  = le32_to_cpu(table->chunk_size);

	if (table->size != res_entry->size) {
		ERROR("Inconsistent integrity table sizes: Table header says "
		      "%u bytes but resource entry says %u bytes",
		      table->size, (unsigned)res_entry->size);
		ret = WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
		goto out;
	}

	DEBUG("table->size = %u, table->num_entries = %u, "
	      "table->chunk_size = %u",
	      table->size, table->num_entries, table->chunk_size);

	expected_size = (u64)table->num_entries * SHA1_HASH_SIZE + 12;

	if (table->size != expected_size) {
		ERROR("Integrity table is %u bytes, but expected %"PRIu64" "
		      "bytes to hold %u entries",
		      table->size, expected_size, table->num_entries);
		ret = WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
		goto out;
	}

	if (table->chunk_size == 0) {
		ERROR("Cannot use integrity chunk size of 0");
		ret = WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
		goto out;
	}

	expected_num_entries = DIV_ROUND_UP(num_checked_bytes, table->chunk_size);

	if (table->num_entries != expected_num_entries) {
		ERROR("%"PRIu64" integrity table entries would be required "
		      "to checksum the %"PRIu64" bytes from the end of the "
		      "header to the",
		      expected_num_entries, num_checked_bytes);
		ERROR("end of the lookup table with a chunk size of %u, but "
		      "there were only %u entries",
		      table->chunk_size, table->num_entries);
		ret = WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
	}
out:
	if (ret == 0)
		*table_ret = table;
	else
		FREE(table);
	return ret;
}

/*
 * calculate_integrity_table():
 *
 * Calculates an integrity table for the data in a file beginning at offset 208
 * (WIM_HEADER_DISK_SIZE).
 *
 * @fp:
 * 	FILE * for the file to be checked, opened for reading.  Does not need to
 * 	be at any specific location in the file.
 *
 * @new_check_end:
 * 	Offset of byte after the last byte to be checked.
 *
 * @old_table:
 * 	If non-NULL, a pointer to the table containing the previously calculated
 * 	integrity data for a prefix of this file.
 *
 * @old_check_end:
 * 	If @old_table is non-NULL, the byte after the last byte that was checked
 * 	in the old table.  Must be less than or equal to new_check_end.
 *
 * @progress_func:
 * 	If non-NULL, a progress function that will be called after every
 * 	calculated chunk.
 *
 * @integrity_table_ret:
 * 	On success, a pointer to the calculated integrity table is written into
 * 	this location.
 *
 * Returns 0 on success; nonzero on failure.
 */
static int calculate_integrity_table(FILE *fp,
				     off_t new_check_end,
				     const struct integrity_table *old_table,
				     off_t old_check_end,
				     wimlib_progress_func_t progress_func,
				     struct integrity_table **integrity_table_ret)
{
	int ret = 0;
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
			ret = calculate_chunk_sha1(fp, this_chunk_size,
						   offset, new_table->sha1sums[i]);
			if (ret != 0)
				break;
		}
		offset += this_chunk_size;
		if (progress_func) {
			progress.integrity.completed_chunks++;
			progress.integrity.completed_bytes += this_chunk_size;
			progress_func(WIMLIB_PROGRESS_MSG_CALC_INTEGRITY,
				      &progress);
		}
	}
	if (ret == 0)
		*integrity_table_ret = new_table;
	else
		FREE(new_table);
	return ret;
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
 * @fp:
 * 	FILE * to the WIM file, opened read-write, positioned at the location at
 * 	which the integrity table is to be written.
 *
 * @integrity_res_entry:
 * 	Resource entry which will be set to point to the integrity table on
 * 	success.  In addition, if @old_lookup_table_end != 0, this initially
 * 	must point to the resource entry for the old integrity table for the
 * 	WIM.
 *
 * @new_lookup_table_end:
 * 	The offset of the byte directly following the lookup table in the WIM
 * 	being written.
 *
 * @old_lookup_table_end:
 * 	If nonzero, the offset of the byte directly following the old lookup
 * 	table in the WIM.
 *
 * @progress_func
 * 	If non-NULL, a progress function that will be called after every
 * 	calculated chunk.
 *
 * Returns:
 * 	0 on success, nonzero on failure.  The possible error codes are:
 * 	   * WIMLIB_ERR_WRITE:  Could not write the integrity table.
 * 	   * WIMLIB_ERR_READ:   Could not read a chunk of data that needed
 * 				to be checked.
 */
int write_integrity_table(FILE *fp,
			  struct resource_entry *integrity_res_entry,
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

	cur_offset = ftello(fp);
	if (cur_offset == -1)
		return WIMLIB_ERR_WRITE;

	if (integrity_res_entry->offset == 0 || old_lookup_table_end == 0) {
		old_table = NULL;
	} else {
		ret = read_integrity_table(integrity_res_entry, fp,
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

	ret = calculate_integrity_table(fp, new_lookup_table_end,
					old_table, old_lookup_table_end,
					progress_func, &new_table);
	if (ret != 0)
		goto out_free_old_table;

	new_table_size = new_table->size;

	new_table->size        = cpu_to_le32(new_table->size);
	new_table->num_entries = cpu_to_le32(new_table->num_entries);
	new_table->chunk_size  = cpu_to_le32(new_table->chunk_size);

	if (fseeko(fp, cur_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" of WIM to "
				 "write integrity table", cur_offset);
		ret = WIMLIB_ERR_WRITE;
		goto out_free_new_table;
	}

	if (fwrite(new_table, 1, new_table_size, fp) != new_table_size) {
		ERROR_WITH_ERRNO("Failed to write WIM integrity table");
		ret = WIMLIB_ERR_WRITE;
	} else {
		integrity_res_entry->offset        = cur_offset;
		integrity_res_entry->size          = new_table_size;
		integrity_res_entry->original_size = new_table_size;
		integrity_res_entry->flags         = 0;
		ret = 0;
	}
out_free_new_table:
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
 * @fp:
 * 	FILE * to the WIM file, opened for reading.
 *
 * @table:
 * 	The integrity table for the WIM, read into memory.
 *
 * @bytes_to_check:
 * 	Number of bytes in the WIM that need to be checked (offset of end of the
 * 	lookup table minus offset of end of the header).
 *
 * @progress_func
 * 	If non-NULL, a progress function that will be called after every
 * 	verified chunk.
 *
 * Returns:
 * 	> 0 (WIMLIB_ERR_*) on error
 * 	0 (WIM_INTEGRITY_OK) if the integrity was checked successfully and there
 * 	were no inconsistencies.
 * 	-1 (WIM_INTEGRITY_NOT_OK) if the WIM failed the integrity check.
 */
static int verify_integrity(FILE *fp, const char *filename,
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

		ret = calculate_chunk_sha1(fp, this_chunk_size, offset, sha1_md);
		if (ret != 0)
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
 * @w:
 * 	The WIM, opened for reading, and with the header already read.
 *
 * @progress_func
 * 	If non-NULL, a progress function that will be called after every
 * 	verified chunk.
 *
 * Returns:
 * 	> 0 (WIMLIB_ERR_*) on error
 * 	0 (WIM_INTEGRITY_OK) if the integrity was checked successfully and there
 * 	were no inconsistencies.
 * 	-1 (WIM_INTEGRITY_NOT_OK) if the WIM failed the integrity check.
 * 	-2 (WIM_INTEGRITY_NONEXISTENT) if the WIM contains no integrity
 * 	information.
 */
int check_wim_integrity(WIMStruct *w, wimlib_progress_func_t progress_func)
{
	int ret;
	u64 bytes_to_check;
	struct integrity_table *table;
	u64 end_lookup_table_offset;

	if (w->hdr.integrity.offset == 0) {
		DEBUG("No integrity information.");
		return WIM_INTEGRITY_NONEXISTENT;
	}

	end_lookup_table_offset = w->hdr.lookup_table_res_entry.offset +
				  w->hdr.lookup_table_res_entry.size;

	if (end_lookup_table_offset < WIM_HEADER_DISK_SIZE) {
		ERROR("WIM lookup table ends before WIM header ends!");
		return WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
	}

	bytes_to_check = end_lookup_table_offset - WIM_HEADER_DISK_SIZE;

	ret = read_integrity_table(&w->hdr.integrity, w->fp,
				   bytes_to_check, &table);
	if (ret != 0)
		return ret;
	ret = verify_integrity(w->fp, w->filename, table,
			       bytes_to_check, progress_func);
	FREE(table);
	return ret;
}
