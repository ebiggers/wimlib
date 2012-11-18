/*
 * write.c
 *
 * Support for writing WIM files; write a WIM file, overwrite a WIM file, write
 * compressed file resources, etc.
 */

/*
 * Copyright (C) 2010 Carl Thijssen
 * Copyright (C) 2012 Eric Biggers
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
#include "io.h"
#include "dentry.h"
#include "lookup_table.h"
#include "xml.h"
#include "lzx.h"
#include "xpress.h"
#include <unistd.h>
#include <semaphore.h>
#include <pthread.h>
#include <errno.h>

#ifdef WITH_NTFS_3G
#include <time.h>
#include <ntfs-3g/attrib.h>
#include <ntfs-3g/inode.h>
#include <ntfs-3g/dir.h>
#endif


#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif


/* Reopens the FILE* for a WIM read-write. */
static int reopen_rw(WIMStruct *w)
{
	FILE *fp;

	if (fclose(w->fp) != 0)
		ERROR_WITH_ERRNO("Failed to close the file `%s'", w->filename);
	w->fp = NULL;
	fp = fopen(w->filename, "r+b");
	if (!fp) {
		ERROR_WITH_ERRNO("Failed to open `%s' for reading and writing",
		      		 w->filename);
		return WIMLIB_ERR_OPEN;
	}
	w->fp = fp;
	return 0;
}



/*
 * Writes a WIM file to the original file that it was read from, overwriting it.
 */
WIMLIBAPI int wimlib_overwrite(WIMStruct *w, int write_flags)
{
	const char *wimfile_name;
	size_t wim_name_len;
	int ret;

	if (!w)
		return WIMLIB_ERR_INVALID_PARAM;

	write_flags &= ~WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE;

	wimfile_name = w->filename;

	DEBUG("Replacing WIM file `%s'.", wimfile_name);

	if (!wimfile_name)
		return WIMLIB_ERR_NO_FILENAME;

	/* Write the WIM to a temporary file. */
	/* XXX should the temporary file be somewhere else? */
	wim_name_len = strlen(wimfile_name);
	char tmpfile[wim_name_len + 10];
	memcpy(tmpfile, wimfile_name, wim_name_len);
	randomize_char_array_with_alnum(tmpfile + wim_name_len, 9);
	tmpfile[wim_name_len + 9] = '\0';

	ret = wimlib_write(w, tmpfile, WIM_ALL_IMAGES, write_flags);
	if (ret != 0) {
		ERROR("Failed to write the WIM file `%s'", tmpfile);
		if (unlink(tmpfile) != 0)
			WARNING("Failed to remove `%s'", tmpfile);
		return ret;
	}

	DEBUG("Closing original WIM file.");
	/* Close the original WIM file that was opened for reading. */
	if (w->fp) {
		if (fclose(w->fp) != 0) {
			WARNING("Failed to close the file `%s'", wimfile_name);
		}
		w->fp = NULL;
	}

	DEBUG("Renaming `%s' to `%s'", tmpfile, wimfile_name);

	/* Rename the new file to the old file .*/
	if (rename(tmpfile, wimfile_name) != 0) {
		ERROR_WITH_ERRNO("Failed to rename `%s' to `%s'",
				 tmpfile, wimfile_name);
		/* Remove temporary file. */
		if (unlink(tmpfile) != 0)
			ERROR_WITH_ERRNO("Failed to remove `%s'", tmpfile);
		return WIMLIB_ERR_RENAME;
	}

	if (write_flags & WIMLIB_WRITE_FLAG_VERBOSE)
		printf("Successfully renamed `%s' to `%s'\n", tmpfile, wimfile_name);

	return 0;
}

static int check_resource_offset(struct lookup_table_entry *lte, void *arg)
{
	u64 xml_data_offset = *(u64*)arg;
	if (lte->resource_entry.offset > xml_data_offset) {
		ERROR("The following resource is *after* the XML data:");
		print_lookup_table_entry(lte);
		return WIMLIB_ERR_RESOURCE_ORDER;
	}
	return 0;
}

WIMLIBAPI int wimlib_overwrite_xml_and_header(WIMStruct *w, int write_flags)
{
	int ret;
	FILE *fp;
	u8 *integrity_table = NULL;
	off_t xml_end;
	off_t xml_size;
	size_t bytes_written;

	DEBUG("Overwriting XML and header of `%s', write_flags = %#x",
	      w->filename, write_flags);

	if (!w->filename)
		return WIMLIB_ERR_NO_FILENAME;

	write_flags &= ~WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE;

	/* Make sure that the integrity table (if present) is after the XML
	 * data, and that there are no stream resources, metadata resources, or
	 * lookup tables after the XML data.  Otherwise, these data would be
	 * destroyed by this function. */
	if (w->hdr.integrity.offset != 0 &&
	    w->hdr.integrity.offset < w->hdr.xml_res_entry.offset) {
		ERROR("Didn't expect the integrity table to be before the XML data");
		return WIMLIB_ERR_RESOURCE_ORDER;
	}

	if (w->hdr.lookup_table_res_entry.offset >
	    w->hdr.xml_res_entry.offset) {
		ERROR("Didn't expect the lookup table to be after the XML data");
		return WIMLIB_ERR_RESOURCE_ORDER;
	}

	ret = for_lookup_table_entry(w->lookup_table, check_resource_offset,
				     &w->hdr.xml_res_entry.offset);
	if (ret != 0)
		return ret;

	ret = reopen_rw(w);
	if (ret != 0)
		return ret;

	fp = w->fp;

	/* The old integrity table is still OK, as the SHA1 message digests in
	 * the integrity table include neither the header nor the XML data.
	 * Save it for later if it exists and an integrity table was required.
	 * */
	if ((write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY)
	     && w->hdr.integrity.offset != 0)
	{
		DEBUG("Reading existing integrity table.");
		integrity_table = MALLOC(w->hdr.integrity.size);
		if (!integrity_table)
			return WIMLIB_ERR_NOMEM;

		ret = read_uncompressed_resource(fp, w->hdr.integrity.offset,
						 w->hdr.integrity.original_size,
						 integrity_table);
		if (ret != 0)
			goto err;
		DEBUG("Done reading existing integrity table.");
	}

	DEBUG("Overwriting XML data.");
	/* Overwrite the XML data. */
	if (fseeko(fp, w->hdr.xml_res_entry.offset, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" "
				 "for XML data", w->hdr.xml_res_entry.offset);
		ret = WIMLIB_ERR_WRITE;
		goto err;
	}
	ret = write_xml_data(w->wim_info, WIM_ALL_IMAGES, fp, 0);
	if (ret != 0)
		goto err;

	DEBUG("Updating XML resource entry.");
	/* Update the XML resource entry in the WIM header. */
	xml_end = ftello(fp);
	if (xml_end == -1) {
		ret = WIMLIB_ERR_WRITE;
		goto err;
	}
	xml_size = xml_end - w->hdr.xml_res_entry.offset;
	w->hdr.xml_res_entry.size = xml_size;
	w->hdr.xml_res_entry.original_size = xml_size;
	/* XML data offset is unchanged. */

	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
		DEBUG("Writing integrity table.");
		w->hdr.integrity.offset = xml_end;
		if (integrity_table) {
			/* The existing integrity table was saved. */
			bytes_written = fwrite(integrity_table, 1,
					       w->hdr.integrity.size, fp);
			if (bytes_written != w->hdr.integrity.size) {
				ERROR_WITH_ERRNO("Failed to write integrity "
						 "table");
				ret = WIMLIB_ERR_WRITE;
				goto err;
			}
			FREE(integrity_table);
		} else {
			/* There was no existing integrity table, so a new one
			 * must be calculated. */
			ret = write_integrity_table(fp, WIM_HEADER_DISK_SIZE,
					w->hdr.lookup_table_res_entry.offset +
					w->hdr.lookup_table_res_entry.size,
					write_flags & WIMLIB_WRITE_FLAG_SHOW_PROGRESS);
			if (ret != 0)
				return ret;

			off_t end_integrity = ftello(fp);
			if (end_integrity == -1)
				return WIMLIB_ERR_WRITE;

			off_t integrity_size           = end_integrity - xml_end;
			w->hdr.integrity.size          = integrity_size;
			w->hdr.integrity.original_size = integrity_size;
			w->hdr.integrity.flags         = 0;
		}
	} else {
		DEBUG("Truncating file to end of XML data.");
		/* No integrity table to write.  The file should be truncated
		 * because it's possible that the old file was longer (due to it
		 * including an integrity table, or due to its XML data being
		 * longer) */
		if (fflush(fp) != 0) {
			ERROR_WITH_ERRNO("Failed to flush stream for file `%s'",
					 w->filename);
			return WIMLIB_ERR_WRITE;
		}
		if (ftruncate(fileno(fp), xml_end) != 0) {
			ERROR_WITH_ERRNO("Failed to truncate `%s' to %"PRIu64" "
					 "bytes", w->filename, xml_end);
			return WIMLIB_ERR_WRITE;
		}
		memset(&w->hdr.integrity, 0, sizeof(struct resource_entry));
	}

	DEBUG("Overwriting header.");
	/* Overwrite the header. */
	if (fseeko(fp, 0, SEEK_SET) != 0) {
		ERROR_WITH_ERRNO("Failed to seek to beginning of `%s'",
				 w->filename);
		return WIMLIB_ERR_WRITE;
	}

	ret = write_header(&w->hdr, fp);
	if (ret != 0)
		return ret;

	DEBUG("Closing `%s'.", w->filename);
	if (fclose(fp) != 0) {
		ERROR_WITH_ERRNO("Failed to close `%s'", w->filename);
		return WIMLIB_ERR_WRITE;
	}
	w->fp = NULL;
	DEBUG("Done.");
	return 0;
err:
	FREE(integrity_table);
	return ret;
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
begin_wim_resource_chunk_tab(const struct lookup_table_entry *lte,
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

typedef int (*compress_func_t)(const void *, unsigned, void *, unsigned *);

compress_func_t get_compress_func(int out_ctype)
{
	if (out_ctype == WIM_COMPRESSION_TYPE_LZX)
		return lzx_compress;
	else
		return xpress_compress;
}


/*
 * Compresses a chunk of a WIM resource.
 *
 * @chunk:		Uncompressed data of the chunk.
 * @chunk_size:		Size of the uncompressed chunk in bytes.
 * @compressed_chunk:	Pointer to output buffer of size at least
 * 				(@chunk_size - 1) bytes.
 * @compressed_chunk_len_ret:	Pointer to an unsigned int into which the size
 * 					of the compressed chunk will be
 * 					returned.
 * @ctype:	Type of compression to use.  Must be WIM_COMPRESSION_TYPE_LZX
 * 		or WIM_COMPRESSION_TYPE_XPRESS.
 *
 * Returns zero if compressed succeeded, and nonzero if the chunk could not be
 * compressed to any smaller than @chunk_size.  This function cannot fail for
 * any other reasons.
 */
static int compress_chunk(const u8 chunk[], unsigned chunk_size,
			  u8 compressed_chunk[],
			  unsigned *compressed_chunk_len_ret,
			  int ctype)
{
	compress_func_t compress = get_compress_func(ctype);
	return (*compress)(chunk, chunk_size, compressed_chunk,
			   compressed_chunk_len_ret);
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
static int write_wim_resource_chunk(const u8 chunk[], unsigned chunk_size,
				    FILE *out_fp, int out_ctype,
				    struct chunk_table *chunk_tab)
{
	const u8 *out_chunk;
	unsigned out_chunk_size;

	wimlib_assert(chunk_size <= WIM_CHUNK_SIZE);

	if (!chunk_tab) {
		out_chunk = chunk;
		out_chunk_size = chunk_size;
	} else {
		u8 *compressed_chunk = alloca(chunk_size);
		int ret;

		ret = compress_chunk(chunk, chunk_size, compressed_chunk,
				     &out_chunk_size, out_ctype);
		if (ret == 0) {
			out_chunk = compressed_chunk;
		} else {
			out_chunk = chunk;
			out_chunk_size = chunk_size;
		}
		*chunk_tab->cur_offset_p++ = chunk_tab->cur_offset;
		chunk_tab->cur_offset += out_chunk_size;
	}

	if (fwrite(out_chunk, 1, out_chunk_size, out_fp) != out_chunk_size) {
		ERROR_WITH_ERRNO("Failed to write WIM resource chunk");
		return WIMLIB_ERR_WRITE;
	}
	return 0;
}

/*
 * Finishes a WIM chunk tale and writes it to the output file at the correct
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

static int prepare_resource_for_read(struct lookup_table_entry *lte

					#ifdef WITH_NTFS_3G
					, ntfs_inode **ni_ret
					#endif
		)
{
	if (lte->resource_location == RESOURCE_IN_FILE_ON_DISK
	     && !lte->file_on_disk_fp)
	{
		wimlib_assert(lte->file_on_disk);
		lte->file_on_disk_fp = fopen(lte->file_on_disk, "rb");
		if (!lte->file_on_disk_fp) {
			ERROR_WITH_ERRNO("Failed to open the file `%s' for "
					 "reading", lte->file_on_disk);
			return WIMLIB_ERR_OPEN;
		}
	}
#ifdef WITH_NTFS_3G
	else if (lte->resource_location == RESOURCE_IN_NTFS_VOLUME
		  && !lte->attr)
	{
		struct ntfs_location *loc = lte->ntfs_loc;
		ntfs_inode *ni;
		wimlib_assert(loc);
		ni = ntfs_pathname_to_inode(*loc->ntfs_vol_p, NULL, loc->path_utf8);
		if (!ni) {
			ERROR_WITH_ERRNO("Failed to open inode `%s' in NTFS "
					 "volume", loc->path_utf8);
			return WIMLIB_ERR_NTFS_3G;
		}
		lte->attr = ntfs_attr_open(ni,
					   loc->is_reparse_point ? AT_REPARSE_POINT : AT_DATA,
					   (ntfschar*)loc->stream_name_utf16,
					   loc->stream_name_utf16_num_chars);
		if (!lte->attr) {
			ERROR_WITH_ERRNO("Failed to open attribute of `%s' in "
					 "NTFS volume", loc->path_utf8);
			ntfs_inode_close(ni);
			return WIMLIB_ERR_NTFS_3G;
		}
		*ni_ret = ni;
	}
#endif
	return 0;
}

static void end_wim_resource_read(struct lookup_table_entry *lte
				#ifdef WITH_NTFS_3G
					, ntfs_inode *ni
				#endif
					)
{
	if (lte->resource_location == RESOURCE_IN_FILE_ON_DISK
	    && lte->file_on_disk_fp) {
		fclose(lte->file_on_disk_fp);
		lte->file_on_disk_fp = NULL;
	}
#ifdef WITH_NTFS_3G
	else if (lte->resource_location == RESOURCE_IN_NTFS_VOLUME) {
		if (lte->attr) {
			ntfs_attr_close(lte->attr);
			lte->attr = NULL;
		}
		if (ni)
			ntfs_inode_close(ni);
	}
#endif
}

/*
 * Writes a WIM resource to a FILE * opened for writing.  The resource may be
 * written uncompressed or compressed depending on the @out_ctype parameter.
 *
 * If by chance the resource compresses to more than the original size (this may
 * happen with random data or files than are pre-compressed), the resource is
 * instead written uncompressed (and this is reflected in the @out_res_entry by
 * removing the WIM_RESHDR_FLAG_COMPRESSED flag).
 *
 * @lte:	The lookup table entry for the WIM resource.
 * @out_fp:	The FILE * to write the resource to.
 * @out_ctype:  The compression type of the resource to write.  Note: if this is
 * 			the same as the compression type of the WIM resource we
 * 			need to read, we simply copy the data (i.e. we do not
 * 			uncompress it, then compress it again).
 * @out_res_entry:  If non-NULL, a resource entry that is filled in with the
 * 		    offset, original size, compressed size, and compression flag
 * 		    of the output resource.
 *
 * Returns 0 on success; nonzero on failure.
 */
int write_wim_resource(struct lookup_table_entry *lte,
		       FILE *out_fp, int out_ctype,
		       struct resource_entry *out_res_entry,
		       int flags)
{
	u64 bytes_remaining;
	u64 original_size;
	u64 old_compressed_size;
	u64 new_compressed_size;
	u64 offset;
	int ret;
	struct chunk_table *chunk_tab = NULL;
	bool raw;
	off_t file_offset;
#ifdef WITH_NTFS_3G
	ntfs_inode *ni = NULL;
#endif

	wimlib_assert(lte);

	/* Original size of the resource */
 	original_size = wim_resource_size(lte);

	/* Compressed size of the resource (as it exists now) */
	old_compressed_size = wim_resource_compressed_size(lte);

	/* Current offset in output file */
	file_offset = ftello(out_fp);
	if (file_offset == -1) {
		ERROR_WITH_ERRNO("Failed to get offset in output "
				 "stream");
		return WIMLIB_ERR_WRITE;
	}

	/* Are the compression types the same?  If so, do a raw copy (copy
	 * without decompressing and recompressing the data). */
	raw = (wim_resource_compression_type(lte) == out_ctype
	       && out_ctype != WIM_COMPRESSION_TYPE_NONE);

	if (raw) {
		flags |= WIMLIB_RESOURCE_FLAG_RAW;
		bytes_remaining = old_compressed_size;
	} else {
		flags &= ~WIMLIB_RESOURCE_FLAG_RAW;
		bytes_remaining = original_size;
	}

	/* Empty resource; nothing needs to be done, so just return success. */
	if (bytes_remaining == 0)
		return 0;

	/* Buffer for reading chunks for the resource */
	u8 buf[min(WIM_CHUNK_SIZE, bytes_remaining)];

	/* If we are writing a compressed resource and not doing a raw copy, we
	 * need to initialize the chunk table */
	if (out_ctype != WIM_COMPRESSION_TYPE_NONE && !raw) {
		ret = begin_wim_resource_chunk_tab(lte, out_fp, file_offset,
						   &chunk_tab);
		if (ret != 0)
			goto out;
	}

	/* If the WIM resource is in an external file, open a FILE * to it so we
	 * don't have to open a temporary one in read_wim_resource() for each
	 * chunk. */
#ifdef WITH_NTFS_3G
	ret = prepare_resource_for_read(lte, &ni);
#else
	ret = prepare_resource_for_read(lte);
#endif
	if (ret != 0)
		goto out;

	/* If we aren't doing a raw copy, we will compute the SHA1 message
	 * digest of the resource as we read it, and verify it's the same as the
	 * hash given in the lookup table entry once we've finished reading the
	 * resource. */
	SHA_CTX ctx;
	if (!raw)
		sha1_init(&ctx);

	/* While there are still bytes remaining in the WIM resource, read a
	 * chunk of the resource, update SHA1, then write that chunk using the
	 * desired compression type. */
	offset = 0;
	do {
		u64 to_read = min(bytes_remaining, WIM_CHUNK_SIZE);
		ret = read_wim_resource(lte, buf, to_read, offset, flags);
		if (ret != 0)
			goto out_fclose;
		if (!raw)
			sha1_update(&ctx, buf, to_read);
		ret = write_wim_resource_chunk(buf, to_read, out_fp,
					       out_ctype, chunk_tab);
		if (ret != 0)
			goto out_fclose;
		bytes_remaining -= to_read;
		offset += to_read;
	} while (bytes_remaining);

	/* Raw copy:  The new compressed size is the same as the old compressed
	 * size
	 *
	 * Using WIM_COMPRESSION_TYPE_NONE:  The new compressed size is the
	 * original size
	 *
	 * Using a different compression type:  Call
	 * finish_wim_resource_chunk_tab() and it will provide the new
	 * compressed size.
	 */
	if (raw) {
		new_compressed_size = old_compressed_size;
	} else {
		if (out_ctype == WIM_COMPRESSION_TYPE_NONE)
			new_compressed_size = original_size;
		else {
			ret = finish_wim_resource_chunk_tab(chunk_tab, out_fp,
							    &new_compressed_size);
			if (ret != 0)
				goto out_fclose;
		}
	}

	/* Verify SHA1 message digest of the resource, unless we are doing a raw
	 * write (in which case we never even saw the uncompressed data).  Or,
	 * if the hash we had before is all 0's, just re-set it to be the new
	 * hash. */
	if (!raw) {
		u8 md[SHA1_HASH_SIZE];
		sha1_final(md, &ctx);
		if (is_zero_hash(lte->hash)) {
			copy_hash(lte->hash, md);
		} else if (!hashes_equal(md, lte->hash)) {
			ERROR("WIM resource has incorrect hash!");
			if (lte->resource_location == RESOURCE_IN_FILE_ON_DISK) {
				ERROR("We were reading it from `%s'; maybe it changed "
				      "while we were reading it.",
				      lte->file_on_disk);
			}
			ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
			goto out_fclose;
		}
	}

	if (!raw && new_compressed_size >= original_size &&
	    out_ctype != WIM_COMPRESSION_TYPE_NONE)
	{
		/* Oops!  We compressed the resource to larger than the original
		 * size.  Write the resource uncompressed instead. */
		if (fseeko(out_fp, file_offset, SEEK_SET) != 0) {
			ERROR_WITH_ERRNO("Failed to seek to byte %"PRIu64" "
					 "of output WIM file", file_offset);
			ret = WIMLIB_ERR_WRITE;
			goto out_fclose;
		}
		ret = write_wim_resource(lte, out_fp, WIM_COMPRESSION_TYPE_NONE,
					 out_res_entry, flags);
		if (ret != 0)
			goto out_fclose;
		if (fflush(out_fp) != 0) {
			ERROR_WITH_ERRNO("Failed to flush output WIM file");
			ret = WIMLIB_ERR_WRITE;
			goto out_fclose;
		}
		if (ftruncate(fileno(out_fp), file_offset + out_res_entry->size) != 0) {
			ERROR_WITH_ERRNO("Failed to truncate output WIM file");
			ret = WIMLIB_ERR_WRITE;
			goto out_fclose;
		}
	} else {
		if (out_res_entry) {
			out_res_entry->size          = new_compressed_size;
			out_res_entry->original_size = original_size;
			out_res_entry->offset        = file_offset;
			out_res_entry->flags         = lte->resource_entry.flags
							& ~WIM_RESHDR_FLAG_COMPRESSED;
			if (out_ctype != WIM_COMPRESSION_TYPE_NONE)
				out_res_entry->flags |= WIM_RESHDR_FLAG_COMPRESSED;
		}
	}
	ret = 0;
out_fclose:
#ifdef WITH_NTFS_3G
	end_wim_resource_read(lte, ni);
#else
	end_wim_resource_read(lte);
#endif
out:
	FREE(chunk_tab);
	return ret;
}


struct shared_queue {
	sem_t filled_slots;
	sem_t empty_slots;
	pthread_mutex_t lock;
	unsigned front;
	unsigned back;
	void **array;
	unsigned size;
};

static int shared_queue_init(struct shared_queue *q, unsigned size)
{
	q->array = CALLOC(sizeof(q->array[0]), size);
	if (!q->array)
		return WIMLIB_ERR_NOMEM;

	sem_init(&q->filled_slots, 0, 0);
	sem_init(&q->empty_slots, 0, size);
	pthread_mutex_init(&q->lock, NULL);
	q->front = 0;
	q->back = size - 1;
	q->size = size;
	return 0;
}

static void shared_queue_destroy(struct shared_queue *q)
{
	sem_destroy(&q->filled_slots);
	sem_destroy(&q->empty_slots);
	pthread_mutex_destroy(&q->lock);
	FREE(q->array);
}

static void shared_queue_put(struct shared_queue *q, void *obj)
{
	sem_wait(&q->empty_slots);
	pthread_mutex_lock(&q->lock);

	q->back = (q->back + 1) % q->size;
	q->array[q->back] = obj;

	sem_post(&q->filled_slots);
	pthread_mutex_unlock(&q->lock);
}

static void *shared_queue_get(struct shared_queue *q)
{
	sem_wait(&q->filled_slots);
	pthread_mutex_lock(&q->lock);

	void *obj = q->array[q->front];
	q->array[q->front] = NULL;
	q->front = (q->front + 1) % q->size;

	sem_post(&q->empty_slots);
	pthread_mutex_unlock(&q->lock);
	return obj;
}

static inline int shared_queue_get_filled(struct shared_queue *q)
{
	int sval;
	sem_getvalue(&q->filled_slots, &sval);
	return sval;
}

struct compressor_thread_params {
	struct shared_queue *res_to_compress_queue;
	struct shared_queue *compressed_res_queue;
	compress_func_t compress;
};

#define MAX_CHUNKS_PER_MSG 2

struct message {
	struct lookup_table_entry *lte;
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

static void compress_chunks(struct message *msg, compress_func_t compress)
{
	for (unsigned i = 0; i < msg->num_chunks; i++) {
		DEBUG2("compress chunk %u of %u", i, msg->num_chunks);
		int ret = compress(msg->uncompressed_chunks[i],
				   msg->uncompressed_chunk_sizes[i],
				   msg->compressed_chunks[i],
				   &msg->compressed_chunk_sizes[i]);
		if (ret == 0) {
			msg->out_compressed_chunks[i] = msg->compressed_chunks[i];
		} else {
			msg->out_compressed_chunks[i] = msg->uncompressed_chunks[i];
			msg->compressed_chunk_sizes[i] = msg->uncompressed_chunk_sizes[i];
		}
	}
}

static void *compressor_thread_proc(void *arg)
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
}

static int write_stream_list_serial(struct list_head *stream_list,
				    FILE *out_fp, int out_ctype,
				    int write_flags)
{
	struct lookup_table_entry *lte;
	int ret;

	list_for_each_entry(lte, stream_list, staging_list) {
		ret = write_wim_resource(lte, out_fp, out_ctype,
					 &lte->output_resource_entry, 0);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int write_wim_chunks(struct message *msg, FILE *out_fp,
			    struct chunk_table *chunk_tab)
{
	for (unsigned i = 0; i < msg->num_chunks; i++) {
		unsigned chunk_csize = msg->compressed_chunk_sizes[i];

		DEBUG2("Write wim chunk %u of %u (csize = %u)",
		      i, msg->num_chunks, chunk_csize);

		if (fwrite(msg->out_compressed_chunks[i], 1, chunk_csize, out_fp)
		    != chunk_csize)
		{
			ERROR_WITH_ERRNO("Failed to write WIM");
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
static int main_writer_thread_proc(struct list_head *stream_list,
				   FILE *out_fp,
				   int out_ctype,
				   struct shared_queue *res_to_compress_queue,
				   struct shared_queue *compressed_res_queue,
				   size_t queue_size)
{
	int ret;


	struct message msgs[queue_size];
	ZERO_ARRAY(msgs);

	// Initially, all the messages are available to use.
	LIST_HEAD(available_msgs);
	for (size_t i = 0; i < ARRAY_LEN(msgs); i++)
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
	struct lookup_table_entry *next_lte = container_of(next_resource,
							   struct lookup_table_entry,
							   staging_list);
	next_resource = next_resource->next;
	u64 next_chunk = 0;
	u64 next_num_chunks = wim_resource_chunks(next_lte);
	INIT_LIST_HEAD(&next_lte->msg_list);
	list_add_tail(&next_lte->staging_list, &outstanding_resources);

	// As in write_wim_resource(), each resource we read is checksummed.
	SHA_CTX next_sha_ctx;
	sha1_init(&next_sha_ctx);
	u8 next_hash[SHA1_HASH_SIZE];

	// Resources that don't need any chunks compressed are added to this
	// list and written directly by the main thread.
	LIST_HEAD(my_resources);

	struct lookup_table_entry *cur_lte = next_lte;
	struct chunk_table *cur_chunk_tab = NULL;
	struct lookup_table_entry *lte;
	struct message *msg;

#ifdef WITH_NTFS_3G
	ntfs_inode *ni = NULL;
#endif

#ifdef WITH_NTFS_3G
	ret = prepare_resource_for_read(next_lte, &ni);
#else
	ret = prepare_resource_for_read(next_lte);
#endif

	DEBUG("Initializing buffers for uncompressed "
	      "and compressed data (%zu bytes needed)",
	      queue_size * MAX_CHUNKS_PER_MSG * WIM_CHUNK_SIZE * 2);

	// Pre-allocate all the buffers that will be needed to do the chunk
	// compression.
	for (size_t i = 0; i < ARRAY_LEN(msgs); i++) {
		for (size_t j = 0; j < MAX_CHUNKS_PER_MSG; j++) {
			msgs[i].compressed_chunks[j] = MALLOC(WIM_CHUNK_SIZE);
			msgs[i].uncompressed_chunks[j] = MALLOC(WIM_CHUNK_SIZE);
			if (msgs[i].compressed_chunks[j] == NULL ||
			    msgs[i].uncompressed_chunks[j] == NULL)
			{
				ERROR("Could not allocate enough memory for "
				      "multi-threaded compression");
				ret = WIMLIB_ERR_NOMEM;
				goto out;
			}
		}
	}

	while (1) {
		// Send chunks to the compressor threads until either (a) there
		// are no more messages available since they were all sent off,
		// or (b) there are no more resources that need to be
		// compressed.
		while (!list_empty(&available_msgs) && next_lte != NULL) {

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

				if (next_chunk == next_num_chunks - 1 &&
				     wim_resource_size(next_lte) % WIM_CHUNK_SIZE != 0)
				{
					size = wim_resource_size(next_lte) % WIM_CHUNK_SIZE;
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

			if (next_chunk != next_num_chunks)
				// More chunks to send for this resource
				continue;

			// Done sending compression requests for a resource!
			// Check the SHA1 message digest.
			DEBUG2("Finalize SHA1 md (next_num_chunks=%zu)", next_num_chunks);
			sha1_final(next_hash, &next_sha_ctx);
			if (!hashes_equal(next_lte->hash, next_hash)) {
				ERROR("WIM resource has incorrect hash!");
				if (next_lte->resource_location == RESOURCE_IN_FILE_ON_DISK) {
					ERROR("We were reading it from `%s'; maybe it changed "
					      "while we were reading it.",
					      next_lte->file_on_disk);
				}
				ret = WIMLIB_ERR_INVALID_RESOURCE_HASH;
				goto out;
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
					next_lte = NULL;
					break;
				}
			#ifdef WITH_NTFS_3G
				end_wim_resource_read(next_lte, ni);
				ni = NULL;
			#else
				end_wim_resource_read(next_lte);
			#endif

				next_lte = container_of(next_resource,
							struct lookup_table_entry,
							staging_list);
				next_resource = next_resource->next;
				if ((next_lte->resource_location == RESOURCE_IN_WIM
				    && wimlib_get_compression_type(next_lte->wim) == out_ctype)
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
					DEBUG2("Updated next_lte");
					break;
				}
			}
		}

		// If there are no outstanding resources, there are no more
		// resources that need to be written.
		if (list_empty(&outstanding_resources)) {
			DEBUG("No outstanding resources! Done");
			ret = 0;
			goto out;
		}

		// Get the next message from the queue and process it.
		// The message will contain 1 or more data chunks that have been
		// compressed.
		DEBUG2("Waiting for message");
		msg = shared_queue_get(compressed_res_queue);
		msg->complete = true;

		DEBUG2("Received msg (begin_chunk=%"PRIu64")", msg->begin_chunk);

		list_for_each_entry(msg, &cur_lte->msg_list, list) {
			DEBUG2("complete=%d", msg->complete);
		}

		// Is this the next chunk in the current resource?  If it's not
		// (i.e., an earlier chunk in a same or different resource
		// hasn't been compressed yet), do nothing, and keep this
		// message around until all earlier chunks are received.
		//
		// Otherwise, write all the chunks we can.
		while (!list_empty(&cur_lte->msg_list)
		        && (msg = container_of(cur_lte->msg_list.next,
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

			// Was this the last chunk of the stream?  If so,
			// finish it.
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


				cur_lte->output_resource_entry.size =
					res_csize;

				cur_lte->output_resource_entry.original_size =
					cur_lte->resource_entry.original_size;

				cur_lte->output_resource_entry.offset =
					cur_chunk_tab->file_offset;

				cur_lte->output_resource_entry.flags =
					cur_lte->resource_entry.flags |
						WIM_RESHDR_FLAG_COMPRESSED;

				FREE(cur_chunk_tab);
				cur_chunk_tab = NULL;

				struct list_head *next = cur_lte->staging_list.next;
				list_del(&cur_lte->staging_list);

				if (next == &outstanding_resources) {
					DEBUG("No more outstanding resources");
					ret = 0;
					goto out;
				} else {
					cur_lte = container_of(cur_lte->staging_list.next,
							       struct lookup_table_entry,
							       staging_list);
				}

				// Since we just finished writing a stream,
				// write any streams that have been added to the
				// my_resources list for direct writing by the
				// main thread (e.g. resources that don't need
				// to be compressed because the desired
				// compression type is the same as the previous
				// compression type).
				struct lookup_table_entry *tmp;
				list_for_each_entry_safe(lte,
							 tmp,
							 &my_resources,
							 staging_list)
				{
					ret = write_wim_resource(lte,
								 out_fp,
								 out_ctype,
								 &lte->output_resource_entry,
								 0);
					list_del(&lte->staging_list);
					if (ret != 0)
						goto out;
				}
			}
		}
	}

out:
#ifdef WITH_NTFS_3G
	end_wim_resource_read(cur_lte, ni);
#else
	end_wim_resource_read(cur_lte);
#endif
	if (ret == 0) {
		list_for_each_entry(lte, &my_resources, staging_list) {
			ret = write_wim_resource(lte, out_fp,
						 out_ctype,
						 &lte->output_resource_entry,
						 0);
			if (ret != 0)
				break;
		}
	} else {
		size_t num_available_msgs = 0;
		struct list_head *cur;

		list_for_each(cur, &available_msgs) {
			num_available_msgs++;
		}

		while (num_available_msgs < ARRAY_LEN(msgs)) {
			shared_queue_get(compressed_res_queue);
			num_available_msgs++;
		}
	}

	DEBUG("Freeing messages");

	for (size_t i = 0; i < ARRAY_LEN(msgs); i++) {
		for (size_t j = 0; j < MAX_CHUNKS_PER_MSG; j++) {
			FREE(msgs[i].compressed_chunks[j]);
			FREE(msgs[i].uncompressed_chunks[j]);
		}
	}

	if (cur_chunk_tab != NULL)
		FREE(cur_chunk_tab);
	return ret;
}

static int write_stream_list_parallel(struct list_head *stream_list,
				      FILE *out_fp, int out_ctype,
				      int write_flags)
{
	int ret;
	long nthreads;
	struct shared_queue res_to_compress_queue;
	struct shared_queue compressed_res_queue;

	nthreads = sysconf(_SC_NPROCESSORS_ONLN);
	if (nthreads < 1) {
		WARNING("Could not determine number of processors! Assuming 1");
		goto out_serial;
	}

	wimlib_assert(stream_list->next != stream_list);

	{
		pthread_t compressor_threads[nthreads];

		static const double MESSAGES_PER_THREAD = 2.0;
		size_t queue_size = (size_t)(nthreads * MESSAGES_PER_THREAD);

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

		for (long i = 0; i < nthreads; i++) {
			DEBUG("pthread_create thread %ld", i);
			ret = pthread_create(&compressor_threads[i], NULL,
					     compressor_thread_proc, &params);
			if (ret != 0) {
				ERROR_WITH_ERRNO("Failed to create compressor "
						 "thread %ld", i);
				nthreads = i;
				goto out_join;
			}
		}

		if (write_flags & WIMLIB_WRITE_FLAG_VERBOSE) {
			printf("Writing compressed data using %ld threads...\n",
			       nthreads);
		}

		ret = main_writer_thread_proc(stream_list,
					      out_fp,
					      out_ctype,
					      &res_to_compress_queue,
					      &compressed_res_queue,
					      queue_size);

	out_join:
		for (long i = 0; i < nthreads; i++)
			shared_queue_put(&res_to_compress_queue, NULL);

		for (long i = 0; i < nthreads; i++) {
			if (pthread_join(compressor_threads[i], NULL)) {
				WARNING("Failed to join compressor thread %ld: %s",
					i, strerror(errno));
			}
		}
	}
	shared_queue_destroy(&compressed_res_queue);
out_destroy_res_to_compress_queue:
	shared_queue_destroy(&res_to_compress_queue);
	if (ret >= 0 && ret != WIMLIB_ERR_NOMEM)
		return ret;
out_serial:
	WARNING("Falling back to single-threaded compression");
	return write_stream_list_serial(stream_list, out_fp,
					out_ctype, write_flags);
}

static int write_stream_list(struct list_head *stream_list, FILE *out_fp,
			     int out_ctype, int write_flags)
{
	struct lookup_table_entry *lte;
	size_t num_streams = 0;
	u64 total_size = 0;
	bool compression_needed = false;

	list_for_each_entry(lte, stream_list, staging_list) {
		num_streams++;
		total_size += wim_resource_size(lte);
		if (!compression_needed
		    && out_ctype != WIM_COMPRESSION_TYPE_NONE
		    && (lte->resource_location != RESOURCE_IN_WIM
		        || wimlib_get_compression_type(lte->wim) != out_ctype)
		    && wim_resource_size(lte) != 0)
			compression_needed = true;
	}

	if (write_flags & WIMLIB_WRITE_FLAG_VERBOSE) {
		printf("Preparing to write %zu streams "
		       "(%"PRIu64" total bytes uncompressed)\n",
		       num_streams, total_size);
		printf("Using compression type %s\n",
		       wimlib_get_compression_type_string(out_ctype));
	}

	if (compression_needed && total_size >= 1000000) {
		return write_stream_list_parallel(stream_list, out_fp,
						  out_ctype, write_flags);
	} else {
		if (write_flags & WIMLIB_WRITE_FLAG_VERBOSE) {
			puts("Using 1 thread (no compression needed)");
		}

		return write_stream_list_serial(stream_list, out_fp,
						out_ctype, write_flags);
	}
}


static int dentry_find_streams_to_write(struct dentry *dentry,
					void *wim)
{
	WIMStruct *w = wim;
	struct list_head *stream_list = w->private;
	struct lookup_table_entry *lte;
	for (unsigned i = 0; i <= dentry->d_inode->num_ads; i++) {
		lte = inode_stream_lte(dentry->d_inode, i, w->lookup_table);
		if (lte && ++lte->out_refcnt == 1)
			list_add(&lte->staging_list, stream_list);
	}
	return 0;
}

static int find_streams_to_write(WIMStruct *w)
{
	return for_dentry_in_tree(wim_root_dentry(w),
				  dentry_find_streams_to_write, w);
}

static int write_wim_streams(WIMStruct *w, int image, int write_flags)
{

	LIST_HEAD(stream_list);

	w->private = &stream_list;
	for_image(w, image, find_streams_to_write);
	return write_stream_list(&stream_list, w->out_fp,
				 wimlib_get_compression_type(w), write_flags);
}

/*
 * Write the lookup table, xml data, and integrity table, then overwrite the WIM
 * header.
 */
int finish_write(WIMStruct *w, int image, int write_flags)
{
	off_t lookup_table_offset;
	off_t xml_data_offset;
	off_t lookup_table_size;
	off_t integrity_offset;
	off_t xml_data_size;
	off_t end_offset;
	off_t integrity_size;
	int ret;
	struct wim_header hdr;
	FILE *out = w->out_fp;

	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE)) {
		/* Write the lookup table. */
		lookup_table_offset = ftello(out);
		if (lookup_table_offset == -1)
			return WIMLIB_ERR_WRITE;

		DEBUG("Writing lookup table (offset %"PRIu64")",
		      lookup_table_offset);
		ret = write_lookup_table(w->lookup_table, out);
		if (ret != 0)
			return ret;
	}

	xml_data_offset = ftello(out);
	if (xml_data_offset == -1)
		return WIMLIB_ERR_WRITE;

	/* @hdr will be the header for the new WIM.  First copy all the data
	 * from the header in the WIMStruct; then set all the fields that may
	 * have changed, including the resource entries, boot index, and image
	 * count.  */
	memcpy(&hdr, &w->hdr, sizeof(struct wim_header));
	if (!(write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE)) {
		lookup_table_size = xml_data_offset - lookup_table_offset;
		hdr.lookup_table_res_entry.offset = lookup_table_offset;
		hdr.lookup_table_res_entry.size = lookup_table_size;
	}
	hdr.lookup_table_res_entry.original_size = hdr.lookup_table_res_entry.size;
	hdr.lookup_table_res_entry.flags = WIM_RESHDR_FLAG_METADATA;

	DEBUG("Writing XML data (offset %"PRIu64")", xml_data_offset);
	ret = write_xml_data(w->wim_info, image, out,
			     (write_flags & WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE) ?
			     	wim_info_get_total_bytes(w->wim_info) : 0);
	if (ret != 0)
		return ret;

	integrity_offset = ftello(out);
	if (integrity_offset == -1)
		return WIMLIB_ERR_WRITE;
	xml_data_size = integrity_offset - xml_data_offset;

	hdr.xml_res_entry.offset                 = xml_data_offset;
	hdr.xml_res_entry.size                   = xml_data_size;
	hdr.xml_res_entry.original_size          = xml_data_size;
	hdr.xml_res_entry.flags                  = 0;

	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
		ret = write_integrity_table(out, WIM_HEADER_DISK_SIZE,
					    xml_data_offset,
					    write_flags & WIMLIB_WRITE_FLAG_SHOW_PROGRESS);
		if (ret != 0)
			return ret;
		end_offset = ftello(out);
		if (end_offset == -1)
			return WIMLIB_ERR_WRITE;
		integrity_size              = end_offset - integrity_offset;
		hdr.integrity.offset        = integrity_offset;
		hdr.integrity.size          = integrity_size;
		hdr.integrity.original_size = integrity_size;
	} else {
		hdr.integrity.offset        = 0;
		hdr.integrity.size          = 0;
		hdr.integrity.original_size = 0;
	}
	hdr.integrity.flags = 0;

	DEBUG("Updating WIM header.");

	/*
	 * In the WIM header, there is room for the resource entry for a
	 * metadata resource labeled as the "boot metadata".  This entry should
	 * be zeroed out if there is no bootable image (boot_idx 0).  Otherwise,
	 * it should be a copy of the resource entry for the image that is
	 * marked as bootable.  This is not well documented...
	 */
	if (hdr.boot_idx == 0 || !w->image_metadata
			|| (image != WIM_ALL_IMAGES && image != hdr.boot_idx)) {
		memset(&hdr.boot_metadata_res_entry, 0,
		       sizeof(struct resource_entry));
	} else {
		memcpy(&hdr.boot_metadata_res_entry,
		       &w->image_metadata[
			  hdr.boot_idx - 1].metadata_lte->output_resource_entry,
		       sizeof(struct resource_entry));
	}

	/* Set image count and boot index correctly for single image writes */
	if (image != WIM_ALL_IMAGES) {
		hdr.image_count = 1;
		if (hdr.boot_idx == image)
			hdr.boot_idx = 1;
		else
			hdr.boot_idx = 0;
	}


	if (fseeko(out, 0, SEEK_SET) != 0)
		return WIMLIB_ERR_WRITE;

	ret = write_header(&hdr, out);
	if (ret != 0)
		return ret;

	DEBUG("Closing output file.");
	wimlib_assert(w->out_fp != NULL);
	if (fclose(w->out_fp) != 0) {
		ERROR_WITH_ERRNO("Failed to close the WIM file");
		ret = WIMLIB_ERR_WRITE;
	}
	w->out_fp = NULL;
	return ret;
}

/* Open file stream and write dummy header for WIM. */
int begin_write(WIMStruct *w, const char *path, int write_flags)
{
	const char *mode;
	DEBUG("Opening `%s' for new WIM", path);

	/* checking the integrity requires going back over the file to read it.
	 * XXX
	 * (It also would be possible to keep a running sha1sum as the file is
	 * written-- this would be faster, but a bit more complicated) */
	if (write_flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY)
		mode = "w+b";
	else
		mode = "wb";

	if (w->out_fp)
		fclose(w->out_fp);

	w->out_fp = fopen(path, mode);
	if (!w->out_fp) {
		ERROR_WITH_ERRNO("Failed to open the file `%s' for writing",
				 path);
		return WIMLIB_ERR_OPEN;
	}

	/* Write dummy header. It will be overwritten later. */
	return write_header(&w->hdr, w->out_fp);
}

/* Writes a stand-alone WIM to a file.  */
WIMLIBAPI int wimlib_write(WIMStruct *w, const char *path,
			   int image, int write_flags)
{
	int ret;

	if (!w || !path)
		return WIMLIB_ERR_INVALID_PARAM;

	write_flags &= ~WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE;

	if (image != WIM_ALL_IMAGES &&
	     (image < 1 || image > w->hdr.image_count))
		return WIMLIB_ERR_INVALID_IMAGE;


	if (w->hdr.total_parts != 1) {
		ERROR("Cannot call wimlib_write() on part of a split WIM");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	if (image == WIM_ALL_IMAGES)
		DEBUG("Writing all images to `%s'.", path);
	else
		DEBUG("Writing image %d to `%s'.", image, path);

	ret = begin_write(w, path, write_flags);
	if (ret != 0)
		return ret;

	for_lookup_table_entry(w->lookup_table, lte_zero_out_refcnt, NULL);

	ret = write_wim_streams(w, image, write_flags);

	if (ret != 0) {
		/*ERROR("Failed to write WIM file resources to `%s'", path);*/
		return ret;
	}

	ret = for_image(w, image, write_metadata_resource);

	if (ret != 0) {
		/*ERROR("Failed to write WIM image metadata to `%s'", path);*/
		return ret;
	}

	ret = finish_write(w, image, write_flags);
	if (ret != 0)
		return ret;

	if (write_flags & WIMLIB_WRITE_FLAG_VERBOSE)
		printf("Successfully wrote `%s'\n", path);
	return 0;
}
