/*
 * wim.c
 *
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
#include "xml.h"
#include <stdlib.h>

static int print_metadata(WIMStruct *w)
{
#if 0
	print_security_data(wim_security_data(w));
#endif
	return for_dentry_in_tree(wim_root_dentry(w), print_dentry, 
				  w->lookup_table);
}


static int print_files(WIMStruct *w)
{
	return for_dentry_in_tree(wim_root_dentry(w), print_dentry_full_path, 
				  NULL);
}

static WIMStruct *new_wim_struct()
{
	WIMStruct *w;
	
	w = CALLOC(1, sizeof(WIMStruct));
	if (!w)
		return NULL;
	w->link_type      = WIM_LINK_TYPE_HARD;
	w->current_image  = WIM_NO_IMAGE;
	return w;
}

/* 
 * Calls a function on images in the WIM.  If @image is WIM_ALL_IMAGES, @visitor
 * is called on the WIM once for each image, with each image selected as the
 * current image in turn.  If @image is a certain image, @visitor is called on
 * the WIM only once, with that image selected.
 */
int for_image(WIMStruct *w, int image, int (*visitor)(WIMStruct *))
{
	int ret;
	int i;
	int image_count;

	DEBUG("for_image(w = %p, image = %d, visitor = %p)\n", 
				w, image, visitor);

	if (image == WIM_ALL_IMAGES) {
		image_count = w->hdr.image_count;
		for (i = 1; i <= image_count; i++) {
			ret = wimlib_select_image(w, i);
			if (ret != 0)
				return ret;
			ret = visitor(w);
			if (ret != 0)
				return ret;
		}
	} else {
		ret = wimlib_select_image(w, image);
		if (ret != 0)
			return ret;
		ret = visitor(w);
	}
	return ret;
}

static int sort_image_metadata_by_position(const void *p1, const void *p2)
{
	struct image_metadata *bmd1 = (struct image_metadata*)p1;
	struct image_metadata *bmd2 = (struct image_metadata*)p2;
	u64 offset1 = bmd1->lookup_table_entry->resource_entry.offset;
	u64 offset2 = bmd2->lookup_table_entry->resource_entry.offset;
	if (offset1 < offset2)
		return -1;
	else if (offset1 > offset2)
		return 1;
	else
		return 0;
}

/* 
 * If @lte points to a metadata resource, append it to the list of metadata
 * resources in the WIMStruct.
 */
static int append_metadata_resource_entry(struct lookup_table_entry *lte, 
					  void *wim_p)
{
	WIMStruct *w = wim_p;

	if (lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA) {
		if (w->current_image == w->hdr.image_count) {
			ERROR("Expected only %u images, but found more!\n",
					w->hdr.image_count);
			return WIMLIB_ERR_IMAGE_COUNT;
		} else {
			DEBUG("Found metadata resource for image %u at "
				"offset %"PRIu64"\n", w->current_image + 1, 
				lte->resource_entry.offset);
			w->image_metadata[
				w->current_image++].lookup_table_entry = lte;
		}
	}

	/* Do nothing if not a metadata resource. */
	return 0;
}

/* Returns the compression type given in the flags of a WIM header. */
int wim_hdr_flags_compression_type(int wim_hdr_flags)
{
	if (wim_hdr_flags & WIM_HDR_FLAG_COMPRESSION) {
		if (wim_hdr_flags & WIM_HDR_FLAG_COMPRESS_LZX)
			return WIM_COMPRESSION_TYPE_LZX;
		else if (wim_hdr_flags & WIM_HDR_FLAG_COMPRESS_XPRESS)
			return WIM_COMPRESSION_TYPE_XPRESS;
		else
			return WIM_COMPRESSION_TYPE_INVALID;
	} else {
		return WIM_COMPRESSION_TYPE_NONE;
	}
}

int wim_resource_compression_type(const WIMStruct *w, 
				  const struct resource_entry *entry)
{
	int wim_ctype = wimlib_get_compression_type(w);
	return resource_compression_type(wim_ctype, entry->flags);
}

WIMLIBAPI void wimlib_set_verbose(WIMStruct *w, bool verbose)
{
	w->verbose = verbose;
}

/*
 * Creates a WIMStruct for a new WIM file.
 */
WIMLIBAPI int wimlib_create_new_wim(int ctype, WIMStruct **w_ret)
{
	WIMStruct *w;
	struct lookup_table *table;
	int ret;

	DEBUG("Creating new WIM with %s compression\n", 
			wimlib_get_compression_type_string(ctype));

	/* Allocate the WIMStruct. */
	w = new_wim_struct();
	if (!w)
		return WIMLIB_ERR_NOMEM;

	ret = init_header(&w->hdr, ctype);
	if (ret != 0)
		goto err;

	table = new_lookup_table(9001);
	if (!table) {
		ret = WIMLIB_ERR_NOMEM;
		goto err;
	}
	w->lookup_table = table;
	*w_ret = w;
	return 0;
err:
	FREE(w);
	return ret;
}

WIMLIBAPI int wimlib_get_num_images(const WIMStruct *w)
{
	return w->hdr.image_count;
}

int wimlib_select_image(WIMStruct *w, int image)
{
	DEBUG("Selecting image %u\n", image);

	if (image == w->current_image)
		return 0;

	if (image > w->hdr.image_count || image < 1) {
		ERROR("Cannot select image %u: There are only %u images!\n",
				image, w->hdr.image_count);
		return WIMLIB_ERR_INVALID_IMAGE;
	}


	/* If a valid image is selected, it can be freed if it is not modified.
	 * */
	if (w->current_image != WIM_NO_IMAGE && 
				!wim_current_image_is_modified(w)) {

		struct image_metadata *imd;

		DEBUG("Freeing image %u\n", w->current_image);
		imd = wim_get_current_image_metadata(w);
		free_dentry_tree(imd->root_dentry, NULL, false);
#if 0
		destroy_security_data(&imd->security_data);
#endif
		imd->root_dentry = NULL;
	}

	w->current_image = image;

	if (wim_root_dentry(w))
		return 0;
	else
		return read_metadata_resource(w->fp, 
				wim_metadata_resource_entry(w),
				wimlib_get_compression_type(w), 
				/*wim_security_data(w), */
				wim_root_dentry_p(w));
}


/* Returns the compression type of the WIM file. */
WIMLIBAPI int wimlib_get_compression_type(const WIMStruct *w)
{
	return wim_hdr_flags_compression_type(w->hdr.flags);
}

WIMLIBAPI const char *wimlib_get_compression_type_string(int ctype)
{
	switch (ctype) {
		case WIM_COMPRESSION_TYPE_NONE:
			return "None";
		case WIM_COMPRESSION_TYPE_LZX:
			return "LZX";
		case WIM_COMPRESSION_TYPE_XPRESS:
			return "XPRESS";
		default:
			return "Invalid";
	}
}

/*
 * Returns the number of an image in the WIM file, given a string that is either
 * the number of the image, or the name of the image.  The images are numbered
 * starting at 1.
 */
WIMLIBAPI int wimlib_resolve_image(WIMStruct *w, const char *image_name_or_num)
{
	char *p;
	int image;
	int i;

	if (!image_name_or_num)
		return WIM_NO_IMAGE;

	if (strcmp(image_name_or_num, "all") == 0)
		return WIM_ALL_IMAGES;
	image = strtoul(image_name_or_num, &p, 10);
	if (*p == '\0') {
		if (image < 1 || image > w->hdr.image_count)
			return WIM_NO_IMAGE;
		return image;
	} else {
		for (i = 1; i <= w->hdr.image_count; i++) {
			if (strcmp(image_name_or_num, 
					wimlib_get_image_name(w, i)) == 0)
				return i;
		}
		return WIM_NO_IMAGE;
	}
}


/* Prints some basic information about a WIM file. */
WIMLIBAPI void wimlib_print_wim_information(const WIMStruct *w)
{
	const struct wim_header *hdr;
	
	hdr = &w->hdr;
	puts("WIM Information:");
	puts("----------------");
	printf("Path:           %s\n", w->filename);
	fputs ("GUID:           0x", stdout);
	print_byte_field(hdr->guid, WIM_GID_LEN);
	putchar('\n');
	printf("Image Count:    %d\n", hdr->image_count);
	printf("Compression:    %s\n", wimlib_get_compression_type_string(
						wimlib_get_compression_type(w)));
	printf("Part Number:    %d/%d\n", 1, 1);
	printf("Boot Index:     %d\n", hdr->boot_idx);
	printf("Size:           %"PRIu64" bytes\n", 
				wim_info_get_total_bytes(w->wim_info));
	printf("Integrity Info: %s\n", (w->hdr.integrity.size != 0) ? "yes" : "no");
	putchar('\n');
}

WIMLIBAPI bool wimlib_has_integrity_table(const WIMStruct *w)
{
	return w->hdr.integrity.size != 0;
}


WIMLIBAPI void wimlib_print_available_images(const WIMStruct *w, int image)
{
	if (image == WIM_ALL_IMAGES) {
		puts("Available Images:");
		puts("-----------------");
	} else {
		int n;
		int i;

		n = printf("Information for Image %d\n", image);
		for (i = 0; i < n - 1; i++)
			putchar('-');
		putchar('\n');

	}
	print_image_info(w->wim_info, image);
}


/* Prints the metadata for the specified image, which may be WIM_ALL_IMAGES, but
 * not WIM_NO_IMAGE. */
WIMLIBAPI int wimlib_print_metadata(WIMStruct *w, int image)
{
	return for_image(w, image, print_metadata);
}

WIMLIBAPI int wimlib_print_files(WIMStruct *w, int image)
{
	return for_image(w, image, print_files);
}

/* Sets the index of the bootable image. */
WIMLIBAPI int wimlib_set_boot_idx(WIMStruct *w, int boot_idx)
{
	if (boot_idx < 0 || boot_idx > w->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;
	w->hdr.boot_idx = boot_idx;
	if (boot_idx == 0) {
		memset(&w->hdr.boot_metadata_res_entry, 0, 
		       sizeof(struct resource_entry));
	} else {
		memcpy(&w->hdr.boot_metadata_res_entry,
		       &w->image_metadata[boot_idx - 1].lookup_table_entry->
		       					resource_entry, 
		       sizeof(struct resource_entry));
	}
	return 0;
}

WIMLIBAPI int wimlib_get_boot_idx(const WIMStruct *w)
{
	return w->hdr.boot_idx;
}

/* 
 * Begins the reading of a WIM file; opens the file and reads its header and
 * lookup table, and optionally checks the integrity.
 */
static int wim_begin_read(WIMStruct *w, const char *in_wim_path, int flags)
{
	int ret;
	uint xml_num_images;
	int integrity_status;

	DEBUG("Reading the WIM file `%s'\n", in_wim_path);

	w->filename = STRDUP(in_wim_path);
	if (!w->filename) {
		ERROR("Failed to allocate memory for WIM filename.\n");
		return WIMLIB_ERR_NOMEM;
	}

	w->fp = fopen(in_wim_path, "rb");

	if (!w->fp) {
		ERROR("Failed to open the file \"%s\" for reading: %m\n",
				in_wim_path);
		ret = WIMLIB_ERR_OPEN;
		goto done;
	}

	ret = read_header(w->fp, &w->hdr);
	if (ret != 0)
		goto done;

	DEBUG("Wim file contains %u images\n", w->hdr.image_count);

	/* If the boot index is invalid, print a warning and set it to 0 */
	if (w->hdr.boot_idx > w->hdr.image_count) {
		WARNING("In `%s', image %u is marked as bootable,\n"
			"\tbut there are only %u images!\n",
			 in_wim_path, w->hdr.boot_idx, w->hdr.image_count);
		w->hdr.boot_idx = 0;
	}

	if (wimlib_get_compression_type(w) == WIM_COMPRESSION_TYPE_INVALID) {
		ERROR("Invalid compression type (WIM header flags "
				"= %x)\n", w->hdr.flags);
		ret = WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
		goto done;
	}


	if (flags & WIMLIB_OPEN_FLAG_CHECK_INTEGRITY) {
		ret = check_wim_integrity(w, 
					  flags & WIMLIB_OPEN_FLAG_SHOW_PROGRESS, 
					  &integrity_status);
		if (ret != 0) {
			ERROR("Error in check_wim_integrity()\n");
			goto done;
		}
		if (integrity_status == WIM_INTEGRITY_NONEXISTENT) {
			WARNING("No integrity information; skipping "
					"integrity check.\n");
		} else if (integrity_status == WIM_INTEGRITY_NOT_OK) {
			ERROR("WIM is not intact! (Failed integrity check)\n");
			ret = WIMLIB_ERR_INTEGRITY;
			goto done;
		}
	}

	if (resource_is_compressed(&w->hdr.lookup_table_res_entry)) {
		ERROR("Didn't expect a compressed lookup table!\n");
		ERROR("Ask the author to implement support for this.\n");
		ret = WIMLIB_ERR_COMPRESSED_LOOKUP_TABLE;
		goto done;
	}

	ret = read_lookup_table(w->fp, w->hdr.lookup_table_res_entry.offset,
				w->hdr.lookup_table_res_entry.size, 
				&w->lookup_table);
	
	if (ret != 0)
		goto done;

	w->image_metadata = CALLOC(w->hdr.image_count, 
				   sizeof(struct image_metadata));

	if (!w->image_metadata) {
		ERROR("Failed to allocate memory for %u metadata structures\n",
				w->hdr.image_count);
		goto done;
	}
	w->current_image = 0;

	DEBUG("Looking for metadata resources in the lookup table.\n");

	/* Find the images in the WIM by searching the lookup table. */
	ret = for_lookup_table_entry(w->lookup_table, 
	  			     append_metadata_resource_entry, w);

	if (ret != 0)
		goto done;

	/* Make sure all the expected images were found.  (We already have
	 * returned false if *extra* images were found) */
	if (w->current_image != w->hdr.image_count) {
		ERROR("Only found %u images in WIM, but expected %u!\n",
				w->current_image, w->hdr.image_count);
		ret = WIMLIB_ERR_IMAGE_COUNT;
		goto done;
	}

	w->current_image = WIM_NO_IMAGE;

	/* Sort images by the position of their metadata resources.  I'm
	 * assuming that is what determines the other of the images in the WIM
	 * file, rather than their order in the lookup table, which may be
	 * random because of hashing. */
	qsort(w->image_metadata, w->hdr.image_count, 
	      sizeof(struct image_metadata), sort_image_metadata_by_position);

	/* Read the XML data. */
	ret = read_xml_data(w->fp, &w->hdr.xml_res_entry, 
			    &w->xml_data, &w->wim_info);

	if (ret != 0) {
		ERROR("Missing or invalid XML data\n");
		goto done;
	}

	xml_num_images = wim_info_get_num_images(w->wim_info);
	if (xml_num_images != w->hdr.image_count) {
		ERROR("In the file `%s', there are %u <IMAGE> elements "
				"in the XML data,\n", in_wim_path, 
							xml_num_images);
		ERROR("but %u images in the WIM!  There must be "
				"exactly one <IMAGE> element per image.\n",
				w->hdr.image_count);
		ret = WIMLIB_ERR_IMAGE_COUNT;
		goto done;
	}

	DEBUG("Done beginning read of WIM file.\n");
	ret = 0;
done:
	return ret;
}


/*
 * Opens a WIM file and creates a WIMStruct for it.
 */
WIMLIBAPI int wimlib_open_wim(const char *wim_file, int flags, 
			      WIMStruct **w_ret)
{
	WIMStruct *w;
	int ret;

	DEBUG("wim_file = `%s', flags = %d\n", wim_file, flags);
	w = new_wim_struct();
	if (!w)
		return WIMLIB_ERR_NOMEM;

	ret = wim_begin_read(w, wim_file, flags);
	if (ret != 0) {
		ERROR("Could not begin reading the WIM file `%s'\n", wim_file);
		FREE(w);
		return ret;
	}
	*w_ret = w;
	return 0;
}

/**
 * Frees internal memory allocated by WIMLIB for a WIM file, and closes it if it
 * is still open.
 */
void wimlib_destroy(WIMStruct *w)
{

}

/* Frees the memory for the WIMStruct, including all internal memory; also
 * closes all files associated with the WIMStruct.  */
WIMLIBAPI void wimlib_free(WIMStruct *w)
{
	uint i;

	if (!w)
		return;
	if (w->fp)
		fclose(w->fp);
	if (w->out_fp)
		fclose(w->out_fp);

	free_lookup_table(w->lookup_table);

	FREE(w->filename);
	FREE(w->output_dir);
	FREE(w->xml_data);
	free_wim_info(w->wim_info);
	if (w->image_metadata) {
		for (i = 0; i < w->hdr.image_count; i++)
			free_dentry_tree(w->image_metadata[i].root_dentry, 
					 NULL, false);
		FREE(w->image_metadata);
	}
	FREE(w);
}

