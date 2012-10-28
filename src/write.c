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
#include <unistd.h>


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


/* Write the file resources for the current image. */
static int write_file_resources(WIMStruct *w)
{
	DEBUG("Writing file resources for image %u.", w->current_image);
	return for_dentry_in_tree(wim_root_dentry(w), write_dentry_resources, w);
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

	return write_header(&hdr, out);
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
		goto out;

	for_lookup_table_entry(w->lookup_table, lte_zero_out_refcnt, NULL);

	w->write_flags = write_flags;

	ret = for_image(w, image, write_file_resources);
	if (ret != 0) {
		ERROR("Failed to write WIM file resources to `%s'", path);
		goto out;
	}

	ret = for_image(w, image, write_metadata_resource);

	if (ret != 0) {
		ERROR("Failed to write WIM image metadata to `%s'", path);
		goto out;
	}

	ret = finish_write(w, image, write_flags);

out:
	DEBUG("Closing output file.");
	if (w->out_fp != NULL) {
		if (fclose(w->out_fp) != 0) {
			ERROR_WITH_ERRNO("Failed to close the file `%s'", path);
			ret = WIMLIB_ERR_WRITE;
		}
		w->out_fp = NULL;
	}
	return ret;
}
