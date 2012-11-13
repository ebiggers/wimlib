/*
 * wim.c
 */

/*
 * Copyright (C) 2010 Carl Thijssen
 * Copyright (C) 2012 Eric Biggers
 *
 * wimlib - Library for working with WIM files
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
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>

#include "dentry.h"

#ifdef WITH_NTFS_3G
#include <time.h>
#include <ntfs-3g/volume.h>
#endif

#include "wimlib_internal.h"
#include "io.h"
#include "lookup_table.h"
#include "xml.h"


static int print_metadata(WIMStruct *w)
{
	DEBUG("Printing metadata for image %d", w->current_image);
	print_security_data(wim_security_data(w));
	return for_dentry_in_tree(wim_root_dentry(w), print_dentry,
				  w->lookup_table);
}


static int print_files(WIMStruct *w)
{
	return for_dentry_in_tree(wim_root_dentry(w), print_dentry_full_path,
				  NULL);
}

WIMStruct *new_wim_struct()
{
	WIMStruct *w = CALLOC(1, sizeof(WIMStruct));
	if (pthread_mutex_init(&w->fp_tab_mutex, NULL) != 0) {
		ERROR_WITH_ERRNO("Failed to initialize mutex");
		FREE(w);
		w = NULL;
	}
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
	int start;
	int end;
	int i;

	if (image == WIM_ALL_IMAGES) {
		start = 1;
		end = w->hdr.image_count;
	} else if (image >= 1 && image <= w->hdr.image_count) {
		start = image;
		end = image;
	} else {
		return WIMLIB_ERR_INVALID_IMAGE;
	}
	for (i = start; i <= end; i++) {
		ret = select_wim_image(w, i);
		if (ret != 0)
			return ret;
		ret = visitor(w);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int sort_image_metadata_by_position(const void *p1, const void *p2)
{
	const struct image_metadata *imd1 = p1;
	const struct image_metadata *imd2 = p2;
	u64 offset1 = imd1->metadata_lte->resource_entry.offset;
	u64 offset2 = imd2->metadata_lte->resource_entry.offset;
	if (offset1 < offset2)
		return -1;
	else if (offset1 > offset2)
		return 1;
	else
		return 0;
}

/*
 * If @lte points to a metadata resource, append it to the list of metadata
 * resources in the WIMStruct.  Otherwise, do nothing.
 */
static int append_metadata_resource_entry(struct lookup_table_entry *lte,
					  void *wim_p)
{
	WIMStruct *w = wim_p;
	int ret = 0;

	if (lte->resource_entry.flags & WIM_RESHDR_FLAG_METADATA) {
		if (w->current_image == w->hdr.image_count) {
			ERROR("Expected only %u images, but found more",
			      w->hdr.image_count);
			ret = WIMLIB_ERR_IMAGE_COUNT;
		} else {
			DEBUG("Found metadata resource for image %u at "
			      "offset %"PRIu64".",
			      w->current_image + 1,
			      lte->resource_entry.offset);
			w->image_metadata[
				w->current_image++].metadata_lte = lte;
		}
	}
	return ret;
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

/*
 * Creates a WIMStruct for a new WIM file.
 */
WIMLIBAPI int wimlib_create_new_wim(int ctype, WIMStruct **w_ret)
{
	WIMStruct *w;
	struct lookup_table *table;
	int ret;

	DEBUG("Creating new WIM with %s compression.",
	      wimlib_get_compression_type_string(ctype));

	/* Allocate the WIMStruct. */
	w = new_wim_struct();
	if (!w)
		return WIMLIB_ERR_NOMEM;

	ret = init_header(&w->hdr, ctype);
	if (ret != 0)
		goto out_free;

	table = new_lookup_table(9001);
	if (!table) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_free;
	}
	w->lookup_table = table;
	*w_ret = w;
	return 0;
out_free:
	FREE(w);
	return ret;
}

WIMLIBAPI int wimlib_get_num_images(const WIMStruct *w)
{
	return w->hdr.image_count;
}

int select_wim_image(WIMStruct *w, int image)
{
	struct image_metadata *imd;

	DEBUG("Selecting image %d", image);

	if (image == w->current_image)
		return 0;

	if (image < 1 || image > w->hdr.image_count) {
		ERROR("Cannot select image %d: There are only %u images",
		      image, w->hdr.image_count);
		return WIMLIB_ERR_INVALID_IMAGE;
	}


	/* If a valid image is currently selected, it can be freed if it is not
	 * modified.  */
	if (w->current_image != WIM_NO_IMAGE) {
		imd = wim_get_current_image_metadata(w);
		if (!imd->modified) {
			DEBUG("Freeing image %u", w->current_image);
			destroy_image_metadata(imd, NULL);
			imd->root_dentry = NULL;
			imd->security_data = NULL;
		}
	}

	w->current_image = image;
	imd = wim_get_current_image_metadata(w);

	if (imd->root_dentry) {
		return 0;
	} else {
		#ifdef ENABLE_DEBUG
		DEBUG("Reading metadata resource specified by the following "
		      "lookup table entry:");
		print_lookup_table_entry(imd->metadata_lte);
		#endif
		return read_metadata_resource(w, imd);
	}
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

	if (strcmp(image_name_or_num, "all") == 0
	    || strcmp(image_name_or_num, "*") == 0)
		return WIM_ALL_IMAGES;
	image = strtol(image_name_or_num, &p, 10);
	if (p != image_name_or_num && *p == '\0') {
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
	printf("Part Number:    %d/%d\n", hdr->part_number, hdr->total_parts);
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
	int first;
	int last;
	int i;
	int n;
	if (image == WIM_ALL_IMAGES) {
		n = printf("Available Images:\n");
		first = 1;
		last = w->hdr.image_count;
	} else if (image >= 1 && image <= w->hdr.image_count) {
		n = printf("Information for Image %d\n", image);
		first = image;
		last = image;
	} else {
		printf("wimlib_print_available_images(): Invalid image %d",
		       image);
		return;
	}
	for (i = 0; i < n - 1; i++)
		putchar('-');
	putchar('\n');
	for (i = first; i <= last; i++)
		print_image_info(w->wim_info, i);
}


/* Prints the metadata for the specified image, which may be WIM_ALL_IMAGES, but
 * not WIM_NO_IMAGE. */
WIMLIBAPI int wimlib_print_metadata(WIMStruct *w, int image)
{
	if (!w)
		return WIMLIB_ERR_INVALID_PARAM;
	if (w->hdr.part_number != 1) {
		ERROR("Cannot show the metadata from part %hu of a %hu-part split WIM!",
		       w->hdr.part_number, w->hdr.total_parts);
		ERROR("Select the first part of the split WIM to see the metadata.");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}
	return for_image(w, image, print_metadata);
}

WIMLIBAPI int wimlib_print_files(WIMStruct *w, int image)
{
	if (!w)
		return WIMLIB_ERR_INVALID_PARAM;
	if (w->hdr.part_number != 1) {
		ERROR("Cannot list the files from part %hu of a %hu-part split WIM!",
		       w->hdr.part_number, w->hdr.total_parts);
		ERROR("Select the first part of the split WIM if you'd like to list the files.");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}
	return for_image(w, image, print_files);
}

/* Sets the index of the bootable image. */
WIMLIBAPI int wimlib_set_boot_idx(WIMStruct *w, int boot_idx)
{
	if (!w)
		return WIMLIB_ERR_INVALID_PARAM;
	if (w->hdr.total_parts != 1) {
		ERROR("Cannot modify the boot index of a split WIM!");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}
	if (boot_idx < 0 || boot_idx > w->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;
	w->hdr.boot_idx = boot_idx;
	return 0;
}

WIMLIBAPI int wimlib_get_part_number(const WIMStruct *w, int *total_parts_ret)
{
	if (total_parts_ret)
		*total_parts_ret = w->hdr.total_parts;
	return w->hdr.part_number;
}


WIMLIBAPI int wimlib_get_boot_idx(const WIMStruct *w)
{
	return w->hdr.boot_idx;
}

/*
 * Begins the reading of a WIM file; opens the file and reads its header and
 * lookup table, and optionally checks the integrity.
 */
static int begin_read(WIMStruct *w, const char *in_wim_path, int open_flags)
{
	int ret;
	uint xml_num_images;

	DEBUG("Reading the WIM file `%s'", in_wim_path);

	w->filename = realpath(in_wim_path, NULL);
	if (!w->filename) {
		ERROR("Failed to allocate memory for WIM filename");
		return WIMLIB_ERR_NOMEM;
	}

	w->fp = fopen(in_wim_path, "rb");

	if (!w->fp) {
		ERROR_WITH_ERRNO("Failed to open the file `%s' for reading",
				 in_wim_path);
		return WIMLIB_ERR_OPEN;
	}

	ret = read_header(w->fp, &w->hdr, open_flags);
	if (ret != 0)
		return ret;

	DEBUG("Wim file contains %u images", w->hdr.image_count);

	/* If the boot index is invalid, print a warning and set it to 0 */
	if (w->hdr.boot_idx > w->hdr.image_count) {
		WARNING("In `%s', image %u is marked as bootable, "
			"but there are only %u images in the WIM",
			in_wim_path, w->hdr.boot_idx, w->hdr.image_count);
		w->hdr.boot_idx = 0;
	}

	if (wimlib_get_compression_type(w) == WIM_COMPRESSION_TYPE_INVALID) {
		ERROR("Invalid compression type (WIM header flags = %x)",
		      w->hdr.flags);
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
	}


	if (open_flags & WIMLIB_OPEN_FLAG_CHECK_INTEGRITY) {
		int integrity_status;
		ret = check_wim_integrity(w,
					  open_flags & WIMLIB_OPEN_FLAG_SHOW_PROGRESS,
					  &integrity_status);
		if (ret != 0)
			return ret;
		if (integrity_status == WIM_INTEGRITY_NONEXISTENT) {
			WARNING("No integrity information for `%s'; skipping "
				"integrity check.", w->filename);
		} else if (integrity_status == WIM_INTEGRITY_NOT_OK) {
			ERROR("WIM is not intact! (Failed integrity check)");
			return WIMLIB_ERR_INTEGRITY;
		}
	}

	if (resource_is_compressed(&w->hdr.lookup_table_res_entry)) {
		ERROR("Didn't expect a compressed lookup table!");
		ERROR("Ask the author to implement support for this.");
		return WIMLIB_ERR_COMPRESSED_LOOKUP_TABLE;
	}

	ret = read_lookup_table(w);
	if (ret != 0)
		return ret;

	w->image_metadata = CALLOC(w->hdr.image_count,
				   sizeof(struct image_metadata));

	if (!w->image_metadata) {
		ERROR("Failed to allocate memory for %u metadata structures",
		      w->hdr.image_count);
		return WIMLIB_ERR_NOMEM;
	}
	w->current_image = 0;

	DEBUG("Looking for metadata resources in the lookup table.");

	/* Find the images in the WIM by searching the lookup table. */
	ret = for_lookup_table_entry(w->lookup_table,
	  			     append_metadata_resource_entry, w);

	if (ret != 0)
		return ret;

	/* Make sure all the expected images were found.  (We already have
	 * returned false if *extra* images were found) */
	if (w->current_image != w->hdr.image_count &&
	    w->hdr.part_number == 1)
	{
		ERROR("Only found %u images in WIM, but expected %u",
		      w->current_image, w->hdr.image_count);
		return WIMLIB_ERR_IMAGE_COUNT;
	}


	/* Sort images by the position of their metadata resources.  I'm
	 * assuming that is what determines the other of the images in the WIM
	 * file, rather than their order in the lookup table, which is random
	 * because of hashing. */
	qsort(w->image_metadata, w->current_image,
	      sizeof(struct image_metadata), sort_image_metadata_by_position);

	w->current_image = WIM_NO_IMAGE;

	/* Read the XML data. */
	ret = read_xml_data(w->fp, &w->hdr.xml_res_entry,
			    &w->xml_data, &w->wim_info);

	if (ret != 0) {
		ERROR("Missing or invalid XML data");
		return ret;
	}

	xml_num_images = wim_info_get_num_images(w->wim_info);
	if (xml_num_images != w->hdr.image_count) {
		ERROR("In the file `%s', there are %u <IMAGE> elements "
		      "in the XML data,", in_wim_path, xml_num_images);
		ERROR("but %u images in the WIM!  There must be exactly one "
		      "<IMAGE> element per image.", w->hdr.image_count);
		return WIMLIB_ERR_IMAGE_COUNT;
	}

	DEBUG("Done beginning read of WIM file `%s'.", in_wim_path);
	return 0;
}


/*
 * Opens a WIM file and creates a WIMStruct for it.
 */
WIMLIBAPI int wimlib_open_wim(const char *wim_file, int open_flags,
			      WIMStruct **w_ret)
{
	WIMStruct *w;
	int ret;

	DEBUG("wim_file = `%s', open_flags = %#x", wim_file, open_flags);
	w = new_wim_struct();
	if (!w) {
		ERROR("Failed to allocate memory for WIMStruct");
		return WIMLIB_ERR_NOMEM;
	}

	ret = begin_read(w, wim_file, open_flags);
	if (ret == 0) {
		*w_ret = w;
	} else {
		DEBUG("Could not begin reading the WIM file `%s'", wim_file);
		wimlib_free(w);
	}
	return ret;
}

/* Frees the memory for the WIMStruct, including all internal memory; also
 * closes all files associated with the WIMStruct.  */
WIMLIBAPI void wimlib_free(WIMStruct *w)
{
	DEBUG2("Freeing WIMStruct");

	if (!w)
		return;
	if (w->fp)
		fclose(w->fp);
	if (w->out_fp)
		fclose(w->out_fp);

	if (w->fp_tab) {
		for (size_t i = 0; i < w->num_allocated_fps; i++)
			if (w->fp_tab[i])
				fclose(w->fp_tab[i]);
		FREE(w->fp_tab);
	}
	pthread_mutex_destroy(&w->fp_tab_mutex);

	free_lookup_table(w->lookup_table);

	FREE(w->filename);
	FREE(w->xml_data);
	free_wim_info(w->wim_info);
	if (w->image_metadata) {
		for (uint i = 0; i < w->hdr.image_count; i++)
			destroy_image_metadata(&w->image_metadata[i], NULL);
		FREE(w->image_metadata);
	}
#ifdef WITH_NTFS_3G
	if (w->ntfs_vol) {
		DEBUG("Unmounting NTFS volume");
		ntfs_umount(w->ntfs_vol, FALSE);
	}
#endif
	FREE(w);
}

