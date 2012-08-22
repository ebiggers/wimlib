/*
 * integrity.c
 *
 * WIM files can optionally contain an array of SHA1 message digests at the end,
 * one digest for each 1 MB of the file.  This file implements the checking of
 * the digests, and the writing of the digests for new WIM files.
 */

/*
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "wimlib_internal.h"
#include "io.h"
#include "sha1.h"

/* Size, in bytes, of each SHA1-summed chunk, when wimlib writes integrity
 * information. */
#define INTEGRITY_CHUNK_SIZE 10485760

/*
 * Verifies the integrity of a WIM. 
 *
 * @fp:		   FILE* of the WIM, currently positioned at the end of the header. 
 * @num_bytes:	   Number of bytes to verify the integrity of.
 * @chunk_size:	   Chunk size per SHA1 message digest.
 * @sha1sums:	   Array of SHA1 message digests; 20 bytes each, one per chunk.
 * @show_progress: Nonzero if the percent complete is to be printed after every
 * 			chunk.
 * @status:	   On success, set to WIM_INTEGRITY_OK or WIM_INTEGRITY_NOT_OK 
 * 			based on whether the WIM is intact or not.
 */
static int verify_integrity(FILE *fp, u64 num_bytes, u32 chunk_size, 
			    const u8 *sha1sums, int show_progress,
			    int *status)
{
	char  *chunk_buf;
	u8     resblock[SHA1_HASH_SIZE];
	u64    bytes_remaining;
	size_t bytes_to_read;
	uint   percent_done;
	int    ret;

	chunk_buf = MALLOC(chunk_size);
	if (!chunk_buf) {
		ERROR("Failed to allocate %u byte buffer for integrity chunks",
		      chunk_size);
		return WIMLIB_ERR_NOMEM;
	}
	bytes_remaining = num_bytes;
	while (bytes_remaining != 0) {
		if (show_progress) {
			percent_done = (num_bytes - bytes_remaining) * 100 / 
					num_bytes;
			printf("Verifying integrity of WIM (%"PRIu64" bytes "
					"remaining, %u%% done)       \r", 
					bytes_remaining, percent_done);
			fflush(stdout);
		}
		bytes_to_read = min(chunk_size, bytes_remaining);
		if (fread(chunk_buf, 1, bytes_to_read, fp) != bytes_to_read) {
			if (feof(fp)) {
				ERROR("Unexpected EOF while verifying "
				      "integrity of WIM");
			} else {
				ERROR_WITH_ERRNO("File stream error while "
						 "verifying integrity of WIM");
			}
			ret = WIMLIB_ERR_READ;
			goto verify_integrity_error;
		}
		sha1_buffer(chunk_buf, bytes_to_read, resblock);
		if (!hashes_equal(resblock, sha1sums)) {
			*status = WIM_INTEGRITY_NOT_OK;
			goto verify_integrity_done;
		}
		sha1sums += SHA1_HASH_SIZE;
		bytes_remaining -= bytes_to_read;
	}
	*status = WIM_INTEGRITY_OK;
verify_integrity_done:
	ret = 0;
verify_integrity_error:
	FREE(chunk_buf);
	if (show_progress)
		putchar('\n');
	return ret;
}

/*
 * Verifies the integrity of the WIM. 
 *
 * @show_progress: Nonzero if the percent complete is to be printed after every
 * 			chunk.
 * @status:	   On success, set to WIM_INTEGRITY_OK, WIM_INTEGRITY_NOT_OK,
 * 			or WIM_INTEGRITY_NONEXISTENT.
 *
 * Returns: 0, WIMLIB_ERR_INVALID_INTEGRITY_TABLE, WIMLIB_ERR_NOMEM, or
 * WIMLIB_ERR_READ.  If nonzero, the boolean pointed to by @ok is not changed.
 */
int check_wim_integrity(WIMStruct *w, int show_progress, int *status)
{

	struct resource_entry *res_entry;
	int ctype;
	u8 *buf = NULL;
	int ret;
	u32 integrity_table_size;
	u32 num_entries;
	u32 chunk_size;
	const u8 *p;
	u64 expected_size;
	u64 end_lookup_table_offset;
	u64 bytes_to_check;
	u64 expected_num_entries;

	res_entry = &w->hdr.integrity;
	if (res_entry->size == 0) {
		DEBUG("No integrity information.");
		*status = WIM_INTEGRITY_NONEXISTENT;
		return 0;
	}
	if (res_entry->original_size < 12) {
		ERROR("Integrity table is too short");
		return WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
	}
	if (res_entry->flags & WIM_RESHDR_FLAG_COMPRESSED) {
		ERROR("Didn't expect a compressed integrity table");
		return WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
	}

	/* Read the integrity table into memory. */
	buf = MALLOC(res_entry->original_size);
	if (!buf) {
		ERROR("Out of memory (needed %zu bytes for integrity table)",
		      res_entry->original_size);
		ret = WIMLIB_ERR_NOMEM;
		goto out;
	}
	ret = read_uncompressed_resource(w->fp, res_entry->offset,
					 res_entry->original_size, buf);
	if (ret != 0) {
		ERROR("Failed to read integrity table (size = %"PRIu64", "
		      "original_size = %"PRIu64", offset = "
		      "%"PRIu64")",
		      (u64)res_entry->size, res_entry->original_size,
		      res_entry->offset);
		goto out;
	}

	p = get_u32(buf, &integrity_table_size);
	p = get_u32(p, &num_entries);
	p = get_u32(p, &chunk_size);

	/* p now points to the array of SHA1 message digests for the WIM. */

	/* Make sure the integrity table is the right size. */
	if (integrity_table_size != res_entry->original_size) {
		ERROR("Inconsistent integrity table sizes: header says %u "
		      "bytes but resource entry says "
		      "%"PRIu64" bytes",
		      integrity_table_size, res_entry->original_size);
		ret = WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
		goto out;
	}

	DEBUG("integrity_table_size = %u, num_entries = %u, chunk_size = %u",
	      integrity_table_size, num_entries, chunk_size);


	expected_size = num_entries * SHA1_HASH_SIZE + 12;

	if (integrity_table_size != expected_size) {
		ERROR("Integrity table is %u bytes, but expected %"PRIu64" "
		      "bytes to hold %u entries", 
		      integrity_table_size, expected_size, num_entries);
		ret = WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
		goto out;
	}

	if (chunk_size == 0) {
		ERROR("Cannot use integrity chunk size of 0");
		ret = WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
		goto out;
	}

	end_lookup_table_offset = w->hdr.lookup_table_res_entry.offset +
				  w->hdr.lookup_table_res_entry.size;

	bytes_to_check = end_lookup_table_offset - WIM_HEADER_DISK_SIZE;

	expected_num_entries = (bytes_to_check + chunk_size - 1) / chunk_size;

	if (num_entries != expected_num_entries) {
		ERROR("%"PRIu64" entries would be required to checksum "
		      "the %"PRIu64" bytes from the end of the header to the",
		      expected_num_entries, bytes_to_check);
		ERROR("end of the lookup table with a chunk size of %u, but "
		      "there were only %u entries", chunk_size, num_entries);
		ret = WIMLIB_ERR_INVALID_INTEGRITY_TABLE;
		goto out;
	}

	/* The integrity checking starts after the header, so seek to the offset
	 * in the WIM after the header. */

	if (fseeko(w->fp, WIM_HEADER_DISK_SIZE, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %u of WIM to check "
				 "integrity", WIM_HEADER_DISK_SIZE);
		ret = WIMLIB_ERR_READ;
		goto out;
	}
	/* call verify_integrity(), which does the actual checking of the SHA1
	 * message digests. */
	ret = verify_integrity(w->fp, bytes_to_check, chunk_size, p, 
			       show_progress, status);
out:
	FREE(buf);
	return ret;
}

/* 
 * Writes integrity information to the output stream for a WIM file being
 * written. 
 *
 * @end_header_offset is the offset of the byte after the header, which is the
 * 	beginning of the region that is checksummed.
 *
 * @end_lookup_table_offset is the offset of the byte after the lookup table,
 * 	which is the end of the region that is checksummed. 
 */
int write_integrity_table(FILE *out, u64 end_header_offset, 
			  u64 end_lookup_table_offset, int show_progress)
{
	u64   bytes_to_check;
	u64   bytes_remaining;
	u8   *buf;
	u8   *p;
	char *chunk_buf;
	u32   num_entries;
	u32   integrity_table_size;
	int   ret;

	DEBUG("Writing integrity table");
	if (fseeko(out, end_header_offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" of WIM to "
				 "calculate integrity data", end_header_offset);
		return WIMLIB_ERR_WRITE;
	}

	bytes_to_check = end_lookup_table_offset - end_header_offset;
	num_entries = bytes_to_check / INTEGRITY_CHUNK_SIZE +
			(bytes_to_check % INTEGRITY_CHUNK_SIZE != 0);
	integrity_table_size = num_entries * SHA1_HASH_SIZE + 3 * sizeof(u32);

	DEBUG("integrity table size = %u", integrity_table_size);


	buf = MALLOC(integrity_table_size);
	if (!buf) {
		ERROR("Failed to allocate %u bytes for integrity table",
		      integrity_table_size);
		return WIMLIB_ERR_NOMEM;
	}

	p = put_u32(buf, integrity_table_size);
	p = put_u32(p, num_entries);
	p = put_u32(p, INTEGRITY_CHUNK_SIZE);

	chunk_buf = MALLOC(INTEGRITY_CHUNK_SIZE);
	if (!chunk_buf) {
		ERROR("Failed to allocate %u bytes for integrity chunk buffer",
		      INTEGRITY_CHUNK_SIZE);
		ret = WIMLIB_ERR_NOMEM;
		goto err2;
	}

	bytes_remaining = bytes_to_check;

	DEBUG("Bytes to check = %"PRIu64, bytes_to_check);

	while (bytes_remaining != 0) {

		uint percent_done = (bytes_to_check - bytes_remaining) * 
				    100 / bytes_to_check;

		if (show_progress) {
			printf("Calculating integrity checksums for WIM "
					"(%"PRIu64" bytes remaining, %u%% "
					"done)      \r", 
					bytes_remaining, percent_done);
			fflush(stdout);
		}


		size_t bytes_to_read = min(INTEGRITY_CHUNK_SIZE, bytes_remaining);
		size_t bytes_read = fread(chunk_buf, 1, bytes_to_read, out);
		if (bytes_read != bytes_to_read) {
			if (feof(out)) {
				ERROR("Unexpected EOF while calculating "
				      "integrity checksums");
			} else {
				ERROR_WITH_ERRNO("File stream error while "
						 "calculating integrity "
						 "checksums");
			}
			ret = WIMLIB_ERR_READ;
			goto err2;
		}
		sha1_buffer(chunk_buf, bytes_read, p);
		p += SHA1_HASH_SIZE;
		bytes_remaining -= bytes_read;
	}
	if (show_progress)
		puts("Calculating integrity checksums for WIM "
				"(0 bytes remaining, 100% done)"
				"                       ");

	if (fseeko(out, 0, SEEK_END) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to end of WIM to write "
				 "integrity table");
		ret = WIMLIB_ERR_WRITE;
		goto err1;
	}

	if (fwrite(buf, 1, integrity_table_size, out) != integrity_table_size) {
		ERROR_WITH_ERRNO("Failed to write integrity table to end of "
				 "WIM");
		ret = WIMLIB_ERR_WRITE;
		goto err1;
	}
	ret = 0;
err1:
	FREE(chunk_buf);
err2:
	FREE(buf);
	return ret;
}
