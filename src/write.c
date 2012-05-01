/*
 * write.c
 *
 * Support for writing WIM files; write a WIM file, overwrite a WIM file, write
 * compressed file resources, etc.
 *
 * Copyright (C) 2010 Carl Thijssen
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files 
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */
#include "wimlib_internal.h"
#include "io.h"
#include "lookup_table.h"
#include "dentry.h"
#include "sha1.h"
#include "lzx.h"
#include "xml.h"
#include "xpress.h"
#include <unistd.h>



/* Used for buffering FILE IO */
#define BUFFER_SIZE 4096

/*
 * Copies bytes between two file streams.
 *
 * Copies @len bytes from @in to @out, at the current position in @out, and at
 * an offset of @in_offset in @in.
 */
static int copy_between_files(FILE *in, off_t in_offset, FILE *out, size_t len)
{
	u8 buf[BUFFER_SIZE];
	size_t n;

	if (fseeko(in, in_offset, SEEK_SET) != 0) {
		ERROR("Failed to seek to byte %"PRIu64" of input file: %m\n",
				in_offset);
		return WIMLIB_ERR_READ;
	}
	/* To reduce memory usage and improve speed, read and write BUFFER_SIZE
	 * bytes at a time. */
	while (len != 0) {
		n = min(len, BUFFER_SIZE);
		if (fread(buf, 1, n, in) != n) {
			if (feof(in)) {
				ERROR("Unexpected EOF when copying data "
						"between files\n");
			} else {
				ERROR("Error copying data between files: %m\n");
			}
			return WIMLIB_ERR_READ;
		}

		if (fwrite(buf, 1, n, out) != n) {
			ERROR("Error copying data between files: %m\n");
			return WIMLIB_ERR_WRITE;
		}
		len -= n;
	}
	return 0;
}


/* 
 * Uncompresses a WIM file resource and writes it uncompressed to a file stream.
 *
 * @in:	            The file stream that contains the file resource.
 * @size:           The size of the resource in the input file.
 * @original_size:  The original (uncompressed) size of the resource. 
 * @offset:	    The offset of the start of the resource in @in.
 * @input_ctype:    The compression type of the resource in @in.
 * @out:	    The file stream to write the file resource to.
 */
static int uncompress_resource(FILE *in, u64 size, u64 original_size,
			       off_t offset, int input_ctype, FILE *out)
{
	int ret;
	u8 buf[WIM_CHUNK_SIZE];
	/* Determine how many compressed chunks the file is divided into. */
	u64 num_chunks;
	u64 i;
	u64 uncompressed_offset;
	u64 uncompressed_chunk_size;
	
	num_chunks = (original_size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;

	for (i = 0; i < num_chunks; i++) {

		uncompressed_offset = i * WIM_CHUNK_SIZE;
		uncompressed_chunk_size = min(WIM_CHUNK_SIZE, 
					original_size - uncompressed_offset);

		ret = read_resource(in, size, original_size, offset, input_ctype, 
					uncompressed_chunk_size, 
					uncompressed_offset, buf);
		if (ret != 0)
			return ret;

		if (fwrite(buf, 1, uncompressed_chunk_size, out) != 
						uncompressed_chunk_size) {
			ERROR("Failed to write file resource: %m\n");
			return WIMLIB_ERR_WRITE;
		}
	}
	return 0;
}

/* 
 * Transfers a file resource between two files, writing it compressed.  The file
 * resource in the input file may be either compressed or uncompressed.
 * Alternatively, the input resource may be in-memory, but it must be
 * uncompressed.
 *
 * @in:	            The file stream that contains the file resource.  Ignored
 * 			if uncompressed_resource != NULL.
 * @uncompressed_resource:	If this pointer is not NULL, it points to an
 * 					array of @original_size bytes that are
 * 					the uncompressed input resource.
 * @size:           The size of the resource in the input file.
 * @original_size:  The original (uncompressed) size of the resource. 
 * @offset:	    The offset of the start of the resource in @in.  Ignored
 * 			if uncompressed_resource != NULL.
 * @input_ctype:    The compression type of the resource in @in.  Ignored if
 * 			uncompressed_resource != NULL.
 * @out:	    The file stream to write the file resource to.
 * @output_type:    The compression type to use when writing the resource to
 * 			@out.
 * @new_size_ret:   A location into which the new compressed size of the file
 * 			resource in returned.
 */
static int recompress_resource(FILE *in, const u8 uncompressed_resource[], 
					u64 size, u64 original_size,
					off_t offset, int input_ctype, FILE *out,
					int output_ctype, u64 *new_size_ret)
{
	int ret;
	int (*compress)(const void *, uint, void *, uint *);
	if (output_ctype == WIM_COMPRESSION_TYPE_LZX)
		compress = lzx_compress;
	else
		compress = xpress_compress;

	u8 uncompressed_buf[WIM_CHUNK_SIZE];
	u8 compressed_buf[WIM_CHUNK_SIZE - 1];

	/* Determine how many compressed chunks the file needs to be divided
	 * into. */
	u64 num_chunks = (original_size + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;

	u64 num_chunk_entries = num_chunks - 1;

	/* Size of the chunk entries--- 8 bytes for files over 4GB, otherwise 4
	 * bytes */
	uint chunk_entry_size = (original_size >= (u64)1 << 32) ?  8 : 4;

	/* Array in which to construct the chunk offset table. */
	u64 chunk_offsets[num_chunk_entries];

	/* Offset of the start of the chunk table in the output file. */
	off_t chunk_tab_offset = ftello(out);

	/* Total size of the chunk table (as written to the file) */
	u64 chunk_tab_size = chunk_entry_size * num_chunk_entries;

	/* Reserve space for the chunk table. */
	if (fwrite(chunk_offsets, 1, chunk_tab_size, out) != chunk_tab_size) {
		ERROR("Failed to write chunk offset table: %m\n");
		return WIMLIB_ERR_WRITE;
	}

	/* Read each chunk of the file, compress it, write it to the output
	 * file, and update th chunk offset table. */
	u64 cur_chunk_offset = 0;
	for (u64 i = 0; i < num_chunks; i++) {

		u64 uncompressed_offset = i * WIM_CHUNK_SIZE;
		u64 uncompressed_chunk_size = min(WIM_CHUNK_SIZE, 
					original_size - uncompressed_offset);

		const u8 *uncompressed_p;
		if (uncompressed_resource != NULL) {
			uncompressed_p = uncompressed_resource + 
							uncompressed_offset;

		} else {
			/* Read chunk i of the file into uncompressed_buf. */
			ret = read_resource(in, size, original_size, offset, input_ctype, 
						uncompressed_chunk_size, 
						uncompressed_offset, 
						uncompressed_buf);
			if (ret != 0)
				return ret;
			uncompressed_p = uncompressed_buf;
		}

		if (i != 0)
			chunk_offsets[i - 1] = cur_chunk_offset;

		uint compressed_len;

		ret = compress(uncompressed_p, uncompressed_chunk_size, 
			       compressed_buf, &compressed_len);

		/* if compress() returned nonzero, the compressed chunk would
		 * have been at least as large as the uncompressed chunk.  In
		 * this situation, the WIM format requires that the uncompressed
		 * chunk be written instead. */
		const u8 *buf_to_write;
		uint len_to_write;
		if (ret == 0) {
			buf_to_write = compressed_buf;
			len_to_write = compressed_len;
		} else {
			buf_to_write = uncompressed_p;
			len_to_write = uncompressed_chunk_size;
		}

		if (fwrite(buf_to_write, 1, len_to_write, out) != len_to_write) {
			ERROR("Failed to write compressed file resource: %m\n");
			return WIMLIB_ERR_WRITE;
		}
		cur_chunk_offset += len_to_write;
	}

	/* The chunk offset after the last chunk, plus the size of the chunk
	 * table, gives the total compressed size of the resource. */
	*new_size_ret = cur_chunk_offset + chunk_tab_size;

	/* Now that all entries of the chunk table are determined, rewind the
	 * stream to where the chunk table was, and write it back out. */

	if (fseeko(out, chunk_tab_offset, SEEK_SET) != 0) {
		ERROR("Failed to seek to beginning of chunk table: %m\n");
		return WIMLIB_ERR_READ;
	}

	if (chunk_entry_size == 8) {
		array_to_le64(chunk_offsets, num_chunk_entries);

		if (fwrite(chunk_offsets, 1, chunk_tab_size, out) != 
				chunk_tab_size) {
			ERROR("Failed to write chunk table: %m\n");
			return WIMLIB_ERR_WRITE;
		}
	} else {
		u32 chunk_entries_small[num_chunk_entries];
		for (u64 i = 0; i < num_chunk_entries; i++)
			chunk_entries_small[i] = to_le32(chunk_offsets[i]);
		if (fwrite(chunk_entries_small, 1, chunk_tab_size, out) != 
				chunk_tab_size) {
			ERROR("Failed to write chunk table: %m\n");
			return WIMLIB_ERR_WRITE;
		}
	}

	if (fseeko(out, 0, SEEK_END) != 0) {
		ERROR("Failed to seek to end of output file: %m\n");
		return WIMLIB_ERR_WRITE;
	}

	return 0;
}

int write_resource_from_memory(const u8 resource[], int out_ctype,
			       u64 resource_original_size, FILE *out,
			       u64 *resource_size_ret)
{
	if (out_ctype == WIM_COMPRESSION_TYPE_NONE) {
		if (fwrite(resource, 1, resource_original_size, out) != 
					resource_original_size) {
			ERROR("Failed to write resource of length "
					"%"PRIu64": %m\n", 
					resource_original_size);
			return WIMLIB_ERR_WRITE;
		}
		*resource_size_ret = resource_original_size;
		return 0;
	} else {
		return recompress_resource(NULL, resource, resource_original_size,
				resource_original_size, 0, 0, out, out_ctype, 
							resource_size_ret);
	}
}


/* 
 * Transfers a file resource from a FILE* opened for reading to a FILE* opened
 * for writing, possibly changing the compression type. 
 *
 * @in:			The FILE* that contains the file resource.
 * @size:		The (compressed) size of the file resource.
 * @original_size:	The uncompressed size of the file resource.
 * @offset:		The offset of the file resource in the input file.
 * @input_ctype:	The compression type of the file resource in the input
 * 				file.
 * @out:		The FILE* for the output file.  The file resource is 
 * 				written at the current position of @out.
 * @output_ctype:	The compression type to which the file resource will be
 * 				converted.
 * @output_res_entry:	A pointer to a resource entry that, upon successful
 * 				return of this function,  will have the size,
 * 				original size, offset, and flags fields filled
 * 				in for the file resource written to the output
 * 				file.
 */
static int transfer_file_resource(FILE *in, u64 size, u64 original_size, 
				  off_t offset, int input_ctype, FILE *out, 
				  int output_ctype, 
				  struct resource_entry *output_res_entry)
{
	int ret;

	/* Handle zero-length files */
	if (original_size == 0) {
		memset(output_res_entry, 0, sizeof(*output_res_entry));
		return 0;
	}

	/* Get current offset in the output file. */
	output_res_entry->offset = ftello(out);
	if (output_res_entry->offset == -1) {
		ERROR("Failed to get output position: %m\n");
		return WIMLIB_ERR_WRITE;
	}

	if (output_ctype == input_ctype) {
		/* The same compression types; simply copy the resource. */

		ret = copy_between_files(in, offset, out, size);
		if (ret != 0)
			return ret;
		output_res_entry->size = size;
	} else {
		/* Different compression types. */

		if (output_ctype == WIM_COMPRESSION_TYPE_NONE) {
			/* Uncompress a compressed file resource */
			ret = uncompress_resource(in, size,
						original_size, offset, 
						input_ctype, out);
			if (ret != 0)
				return ret;
			output_res_entry->size = original_size;
		} else {
			u64 new_size;
			/* Compress an uncompressed file resource, or compress a
			 * compressed file resource using a different
			 * compression type (the latter is currently unsupported
			 * since only LZX compression is supported. */
			ret = recompress_resource(in, NULL, size, original_size,
						offset, input_ctype, out, 
						output_ctype, &new_size);
			if (ret != 0)
				return ret;
			output_res_entry->size = new_size;
		}

	}

	output_res_entry->original_size = original_size;
	if (output_ctype == WIM_COMPRESSION_TYPE_NONE)
		output_res_entry->flags = 0;
	else
		output_res_entry->flags = WIM_RESHDR_FLAG_COMPRESSED;
	return 0;
}

/* 
 * Writes a file resource to the output file. 
 *
 * @dentry:  The dentry for the file resource.
 * @wim_p:  A pointer to the WIMStruct.  The fields of interest to this
 * 	function are the input and output file streams and the lookup table. 
 * @return zero on success, nonzero on failure. 
 */
static int write_file_resource(struct dentry *dentry, void *wim_p)
{
	WIMStruct *w;
	FILE *out;
	FILE *in;
	struct lookup_table_entry *lte;
	int in_wim_ctype;
	int out_wim_ctype;
	int input_res_ctype;
	struct resource_entry *input_res_entry;
	struct resource_entry *output_res_entry;
	u64 len;
	int ret;

	w = wim_p;
	out = w->out_fp;

	/* Directories don't need file resources. */
	if (dentry_is_directory(dentry))
		return 0;

	/* Get the lookup entry for the file resource. */
	lte = wim_lookup_resource(w, dentry);
	if (!lte)
		return 0;

	/* No need to write file resources twice.  (This indicates file
	 * resources that are part of a hard link set.) */
	if (++lte->out_refcnt != 1)
		return 0;

	out_wim_ctype = wimlib_get_compression_type(w);
	output_res_entry = &lte->output_resource_entry;

	/* Figure out if we can read the resource from the WIM file, or
	 * if we have to read it from the filesystem outside. */
	if (lte->file_on_disk) {

		/* Read from disk (uncompressed) */

		len = lte->resource_entry.original_size;

		in = fopen(lte->file_on_disk, "rb");
		if (!in) {
			ERROR("Failed to open the file `%s': %m\n",
					lte->file_on_disk);
			return WIMLIB_ERR_OPEN;
		}

		if (w->verbose)
			puts(lte->file_on_disk);

		ret = transfer_file_resource(in, len, len, 0,
					     WIM_COMPRESSION_TYPE_NONE, out, 
					     out_wim_ctype, output_res_entry);
		fclose(in);
	} else {

		/* Read from input WIM (possibly compressed) */

		/* It may be a different WIM file, in the case of
		 * exporting images from one WIM file to another */
		if (lte->other_wim_fp) {
			/* Different WIM file. */
			in = lte->other_wim_fp;
			in_wim_ctype = lte->other_wim_ctype;
		} else {
			/* Same WIM file. */
			in = w->fp;
			in_wim_ctype = out_wim_ctype;
		}
		input_res_entry = &lte->resource_entry;
		input_res_ctype = resource_compression_type(
					in_wim_ctype, 
					input_res_entry->flags);

		ret = transfer_file_resource(in, 
					input_res_entry->size,
					input_res_entry->original_size, 
					input_res_entry->offset,
					input_res_ctype, 
					out, 
					out_wim_ctype,
					output_res_entry);
	}
	return ret;
}

/* Reopens the FILE* for a WIM read-write. */
static int reopen_rw(WIMStruct *w)
{
	FILE *fp;

	if (fclose(w->fp) != 0)
		ERROR("Failed to close the file `%s': %m\n", w->filename);
	fp = fopen(w->filename, "r+b");
	if (!fp) {
		ERROR("Failed to open `%s' for reading and writing: "
				"%m\n", w->filename);
		return WIMLIB_ERR_OPEN;
	}
	w->fp = fp;
	return 0;
}



/* 
 * Writes a WIM file to the original file that it was read from, overwriting it.
 */
WIMLIBAPI int wimlib_overwrite(WIMStruct *w, int flags)
{
	const char *wimfile_name;
	size_t wim_name_len;
	int ret;
	
	wimfile_name = w->filename;

	DEBUG("Replacing WIM file `%s'\n", wimfile_name);

	if (!wimfile_name)
		return WIMLIB_ERR_NO_FILENAME;

	/* Write the WIM to a temporary file. */
	/* XXX should the temporary file be somewhere else? */
	wim_name_len = strlen(wimfile_name);
	char tmpfile[wim_name_len + 10];
	memcpy(tmpfile, wimfile_name, wim_name_len);
	randomize_char_array_with_alnum(tmpfile + wim_name_len, 9);
	tmpfile[wim_name_len + 9] = '\0';

	ret = wimlib_write(w, tmpfile, WIM_ALL_IMAGES, flags);
	if (ret != 0) {
		ERROR("Failed to write the WIM file `%s'!\n", tmpfile);
		return ret;
	}

	DEBUG("Closing original WIM file.\n");
	/* Close the original WIM file that was opened for reading. */
	if (w->fp) {
		if (fclose(w->fp) != 0) {
			DEBUG("WARNING: Failed to close the file `%s'\n",
					wimfile_name);
		}
		w->fp = NULL;
	}

	DEBUG("Renaming `%s' to `%s'\n", tmpfile, wimfile_name);

	/* Rename the new file to the old file .*/
	if (rename(tmpfile, wimfile_name) != 0) {
		ERROR("Failed to rename `%s' to `%s': %m\n", tmpfile, 
								wimfile_name);
		/* Remove temporary file. */
		if (unlink(tmpfile) != 0)
			ERROR("Failed to remove `%s': %m\n", tmpfile);
		return WIMLIB_ERR_RENAME;
	}

	return 0;
}


WIMLIBAPI int wimlib_overwrite_xml_and_header(WIMStruct *w, int flags)
{
	int ret;
	FILE *fp;
	u8 *integrity_table = NULL;
	off_t xml_end;
	off_t xml_size;
	size_t bytes_written;

	DEBUG("Overwriting XML and header of `%s', flags = %d\n", 
				w->filename, flags);
	if (!w->filename)
		return WIMLIB_ERR_NO_FILENAME;

	ret = reopen_rw(w);
	if (ret != 0)
		return ret;

	fp = w->fp;

	/* The old integrity table is still OK, as the SHA1 message digests in
	 * the integrity table include neither the header nor the XML data.
	 * Save it for later if it exists and an integrity table was required.
	 * */
	if (flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY && 
			w->hdr.integrity.offset != 0) {
		DEBUG("Reading existing integrity table.\n");
		integrity_table = MALLOC(w->hdr.integrity.size);
		if (!integrity_table)
			return WIMLIB_ERR_NOMEM;

		ret = read_uncompressed_resource(fp, w->hdr.integrity.offset,
						 w->hdr.integrity.original_size,
						 integrity_table);
		if (ret != 0)
			goto err;
		DEBUG("Done reading existing integrity table.\n");
	}

	DEBUG("Overwriting XML data.\n");
	/* Overwrite the XML data. */
	if (fseeko(fp, w->hdr.xml_res_entry.offset, SEEK_SET) != 0) {
		ERROR("Failed to seek to byte %"PRIu64" for XML data: "
				"%m\n", w->hdr.xml_res_entry.offset);
		ret = WIMLIB_ERR_WRITE;
		goto err;
	}
	ret = write_xml_data(w->wim_info, WIM_ALL_IMAGES, fp);
	if (ret != 0)
		goto err;

	DEBUG("Updating XML resource entry.\n");
	/* Update the XML resource entry in the WIM header. */
	xml_end = ftello(fp);
	if (xml_end == -1) {
		ret = WIMLIB_ERR_WRITE;
		goto err;
	}
	xml_size = xml_end - w->hdr.xml_res_entry.offset;
	w->hdr.xml_res_entry.size = xml_size;
	w->hdr.xml_res_entry.original_size = xml_size;

	if (flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
		DEBUG("Writing integrity table.\n");
		w->hdr.integrity.offset        = xml_end;
		if (integrity_table) {
			/* The existing integrity table was saved. */
			bytes_written = fwrite(integrity_table, 1, 
					       w->hdr.integrity.size, fp);
			if (bytes_written != w->hdr.integrity.size) {
				ERROR("Failed to write integrity table: %m\n");
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
					flags & WIMLIB_WRITE_FLAG_SHOW_PROGRESS);
			if (ret != 0)
				goto err;

			off_t integrity_size           = ftello(fp) - xml_end;
			w->hdr.integrity.size          = integrity_size;
			w->hdr.integrity.original_size = integrity_size;
			w->hdr.integrity.flags         = 0;
		}
	} else {
		DEBUG("Truncating file to end of XML data.\n");
		/* No integrity table to write.  The file should be truncated
		 * because it's possible that the old file was longer (due to it
		 * including an integrity table, or due to its XML data being
		 * longer) */
		if (fflush(fp) != 0) {
			ERROR("Failed to flush stream for file `%s': %m\n",
					w->filename);
			return WIMLIB_ERR_WRITE;
		}
		if (ftruncate(fileno(fp), xml_end) != 0) {
			ERROR("Failed to truncate `%s' to %"PRIu64" "
					"bytes: %m\n", 
					w->filename, xml_end);
			return WIMLIB_ERR_WRITE;
		}
		memset(&w->hdr.integrity, 0, sizeof(struct resource_entry));
	}

	DEBUG("Overwriting header.\n");
	/* Overwrite the header. */
	if (fseeko(fp, 0, SEEK_SET) != 0) {
		ERROR("Failed to seek to beginning of `%s': %m\n",
				w->filename);
		return WIMLIB_ERR_WRITE;
	}

	ret = write_header(&w->hdr, fp);
	if (ret != 0)
		return ret;;

	DEBUG("Closing file.\n");
	if (fclose(fp) != 0) {
		ERROR("Failed to close `%s': %m\n", w->filename);
		return WIMLIB_ERR_WRITE;
	}
	w->fp = NULL;
	DEBUG("Done.\n");
	return 0;
err:
	FREE(integrity_table);
	return ret;
}

/* Write the metadata resource for the current image. */
static int write_metadata_resource(WIMStruct *w)
{
	FILE *out;
	u8 *buf;
	u8 *p;
	int ret;
	off_t subdir_offset;
	struct dentry *root;
	struct lookup_table_entry *lte;
	struct resource_entry *res_entry;
	off_t metadata_offset;
	u64 metadata_original_size;
	u64 metadata_compressed_size;
	int metadata_ctype;
	u8  hash[WIM_HASH_SIZE];

	DEBUG("Writing metadata resource for image %u\n", w->current_image);

	out = w->out_fp;
	root = wim_root_dentry(w);
	metadata_ctype = wimlib_get_compression_type(w);
	metadata_offset = ftello(out);
	if (metadata_offset == -1)
		return WIMLIB_ERR_WRITE;

	subdir_offset = 8 + root->length + 8;
	calculate_subdir_offsets(root, &subdir_offset);
	metadata_original_size = subdir_offset;
	buf = MALLOC(metadata_original_size);
	if (!buf) {
		ERROR("Failed to allocate %"PRIu64" bytes for "
				"metadata resource\n", metadata_original_size);
		return WIMLIB_ERR_NOMEM;
	}
	p = buf;
	#if 0
	/* Write the security data. */
	p = write_security_data(wim_security_data(w), p);
	#else
	p = put_u32(p, 8); /* Total length of security data. */
	p = put_u32(p, 0); /* Number of security data entries. */
	#endif

	DEBUG("Writing dentry tree.\n");
	p = write_dentry_tree(root, p);

	/* Like file resources, the lookup table entry for a metadata resource
	 * uses for the hash code a SHA1 message digest of its uncompressed
	 * contents. */
	sha1_buffer(buf, metadata_original_size, hash);

	ret = write_resource_from_memory(buf, 
					 metadata_ctype,
					 metadata_original_size, 
					 out,
					 &metadata_compressed_size);
	FREE(buf);
	if (ret != 0)
		return ret;

	/* Update the lookup table entry, including the hash and output resource
	 * entry fields, for this image's metadata resource.  */
	lte = wim_metadata_lookup_table_entry(w);
	res_entry = &lte->output_resource_entry;
	lte->out_refcnt++;
	if (memcmp(hash, lte->hash, WIM_HASH_SIZE) != 0) {
		lookup_table_unlink(w->lookup_table, lte);
		memcpy(lte->hash, hash, WIM_HASH_SIZE);
		lookup_table_insert(w->lookup_table, lte);
	}
	res_entry->original_size = metadata_original_size;
	res_entry->offset        = metadata_offset;
	res_entry->size          = metadata_compressed_size;
	res_entry->flags         = WIM_RESHDR_FLAG_METADATA;
	if (metadata_ctype != WIM_COMPRESSION_TYPE_NONE)
		res_entry->flags |= WIM_RESHDR_FLAG_COMPRESSED;
	return 0;
}

/* Write the file resources for the current image. */
static int write_file_resources(WIMStruct *w)
{

	DEBUG("Writing file resources for image %u\n", w->current_image);
	return for_dentry_in_tree(wim_root_dentry(w), write_file_resource, w);
}

/* Write lookup table, xml data, lookup table, and rewrite header */
static int finish_write(WIMStruct *w, int image, FILE *out, int flags)
{
	off_t lookup_table_offset;
	off_t xml_data_offset;
	off_t lookup_table_size;
	off_t integrity_offset;
	off_t xml_data_size;
	off_t end_offset;
	off_t integrity_size;
	int ret;
	int i;
	struct wim_header hdr;

	lookup_table_offset = ftello(out);
	if (lookup_table_offset == -1)
		return WIMLIB_ERR_WRITE;

	DEBUG("Writing lookup table.\n");
	/* Write the lookup table. */
	ret = write_lookup_table(w->lookup_table, out);
	if (ret != 0)
		return ret;

	DEBUG("Writing XML data.\n");

	xml_data_offset = ftello(out);
	if (xml_data_offset == -1)
		return WIMLIB_ERR_WRITE;

	/* @hdr will be the header for the new WIM.  First copy all the data
	 * from the header in the WIMStruct; then set all the fields that may
	 * have changed, including the resource entries, boot index, and image
	 * count.  */
	memcpy(&hdr, &w->hdr, sizeof(struct wim_header));
	lookup_table_size = xml_data_offset - lookup_table_offset;
	hdr.lookup_table_res_entry.offset        = lookup_table_offset;
	hdr.lookup_table_res_entry.size          = lookup_table_size;
	hdr.lookup_table_res_entry.original_size = lookup_table_size;
	hdr.lookup_table_res_entry.flags         = WIM_RESHDR_FLAG_METADATA;

	ret = write_xml_data(w->wim_info, image, out);
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

	if (flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) {
		ret = write_integrity_table(out, WIM_HEADER_DISK_SIZE, 
					    xml_data_offset, 
					    flags & WIMLIB_WRITE_FLAG_SHOW_PROGRESS);
		if (ret != 0)
			return ret;
		end_offset = ftello(out);
		if (end_offset == -1)
			return WIMLIB_ERR_WRITE;
		integrity_size = end_offset - integrity_offset;
		hdr.integrity.offset = integrity_offset;
		hdr.integrity.size   = integrity_size;
		hdr.integrity.original_size = integrity_size;
	} else {
		hdr.integrity.offset        = 0;
		hdr.integrity.size          = 0;
		hdr.integrity.original_size = 0;
	}
	hdr.integrity.flags = 0;

	DEBUG("Updating WIM header.\n");


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
		       &w->image_metadata[hdr.boot_idx - 1].lookup_table_entry->
					output_resource_entry,
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

	return write_header(&hdr, out);
}

/* Writes the WIM to a file.  */
WIMLIBAPI int wimlib_write(WIMStruct *w, const char *path, int image, int flags)
{
	int ret;
	const char *mode;
	FILE *out;

	if (image != WIM_ALL_IMAGES && 
			(image < 1 || image > w->hdr.image_count))
		return WIMLIB_ERR_INVALID_IMAGE;

	if (image == WIM_ALL_IMAGES)
		DEBUG("Writing all images to `%s'\n", path);
	else
		DEBUG("Writing image %d to `%s'\n", image, path);

	/* checking the integrity requires going back over the file to read it.
	 * XXX 
	 * (It also would be possible to keep a running sha1sum as the file
	 * as written-- this would be faster, but a bit more complicated) */
	if (flags & WIMLIB_WRITE_FLAG_CHECK_INTEGRITY) 
		mode = "w+b";
	else
		mode = "wb";

	out = fopen(path, mode);
	if (!out) {
		ERROR("Failed to open the file `%s' for writing!\n", 
				path);
		return WIMLIB_ERR_OPEN;
	}

	w->out_fp = out;

	/* Write dummy header. It will be overwritten later. */
	ret = write_header(&w->hdr, out);
	if (ret != 0)
		goto done;

	for_lookup_table_entry(w->lookup_table, zero_out_refcnts, NULL);

	ret = for_image(w, image, write_file_resources);
	if (ret != 0) {
		ERROR("Failed to write file resources!\n");
		goto done;
	}

	ret = for_image(w, image, write_metadata_resource);

	if (ret != 0) {
		ERROR("Failed to write image metadata!\n");
		goto done;
	}

	ret = finish_write(w, image, out, flags);

done:
	DEBUG("Closing output file.\n");
	w->out_fp = NULL;
	if (fclose(out) != 0) {
		ERROR("Failed to close the file `%s': %m\n", path);
		ret = WIMLIB_ERR_WRITE;
	}
	return ret;
}
