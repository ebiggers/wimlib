/*
 * wim.c - Stuff that doesn't fit into any other file
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __WIN32__
#  include "win32.h"
#else
#  include <langinfo.h>
#endif

#include "buffer_io.h"
#include "dentry.h"
#include "lookup_table.h"
#include "wimlib_internal.h"
#include "xml.h"

static int
image_print_metadata(WIMStruct *w)
{
	DEBUG("Printing metadata for image %d", w->current_image);
	print_security_data(wim_security_data(w));
	return for_dentry_in_tree(wim_root_dentry(w), print_dentry,
				  w->lookup_table);
}


static int
image_print_files(WIMStruct *w)
{
	return for_dentry_in_tree(wim_root_dentry(w), print_dentry_full_path,
				  NULL);
}

static WIMStruct *
new_wim_struct()
{
	WIMStruct *w = CALLOC(1, sizeof(WIMStruct));
#ifdef WITH_FUSE
	if (pthread_mutex_init(&w->fp_tab_mutex, NULL) != 0) {
		ERROR_WITH_ERRNO("Failed to initialize mutex");
		FREE(w);
		w = NULL;
	}
#endif
	return w;

}

/*
 * Calls a function on images in the WIM.  If @image is WIMLIB_ALL_IMAGES, @visitor
 * is called on the WIM once for each image, with each image selected as the
 * current image in turn.  If @image is a certain image, @visitor is called on
 * the WIM only once, with that image selected.
 */
int
for_image(WIMStruct *w, int image, int (*visitor)(WIMStruct *))
{
	int ret;
	int start;
	int end;
	int i;

	if (image == WIMLIB_ALL_IMAGES) {
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

/* Returns the compression type given in the flags of a WIM header. */
static int
wim_hdr_flags_compression_type(int wim_hdr_flags)
{
	if (wim_hdr_flags & WIM_HDR_FLAG_COMPRESSION) {
		if (wim_hdr_flags & WIM_HDR_FLAG_COMPRESS_LZX)
			return WIMLIB_COMPRESSION_TYPE_LZX;
		else if (wim_hdr_flags & WIM_HDR_FLAG_COMPRESS_XPRESS)
			return WIMLIB_COMPRESSION_TYPE_XPRESS;
		else
			return WIMLIB_COMPRESSION_TYPE_INVALID;
	} else {
		return WIMLIB_COMPRESSION_TYPE_NONE;
	}
}

/*
 * Creates a WIMStruct for a new WIM file.
 */
WIMLIBAPI int
wimlib_create_new_wim(int ctype, WIMStruct **w_ret)
{
	WIMStruct *w;
	struct wim_lookup_table *table;
	int ret;

	DEBUG("Creating new WIM with %"TS" compression.",
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

WIMLIBAPI int
wimlib_get_num_images(const WIMStruct *w)
{
	return w->hdr.image_count;
}

int
select_wim_image(WIMStruct *w, int image)
{
	struct wim_image_metadata *imd;
	int ret;

	DEBUG("Selecting image %d", image);

	if (image == WIMLIB_NO_IMAGE) {
		ERROR("Invalid image: %d", WIMLIB_NO_IMAGE);
		return WIMLIB_ERR_INVALID_IMAGE;
	}

	if (image == w->current_image)
		return 0;

	if (image < 1 || image > w->hdr.image_count) {
		ERROR("Cannot select image %d: There are only %u images",
		      image, w->hdr.image_count);
		return WIMLIB_ERR_INVALID_IMAGE;
	}

	/* If a valid image is currently selected, it can be freed if it is not
	 * modified.  */
	if (w->current_image != WIMLIB_NO_IMAGE) {
		imd = wim_get_current_image_metadata(w);
		if (!imd->modified) {
			wimlib_assert(list_empty(&imd->unhashed_streams));
			DEBUG("Freeing image %u", w->current_image);
			destroy_image_metadata(imd, NULL, false);
		}
	}
	w->current_image = image;
	imd = wim_get_current_image_metadata(w);
	if (imd->root_dentry) {
		ret = 0;
	} else {
		#ifdef ENABLE_DEBUG
		DEBUG("Reading metadata resource specified by the following "
		      "lookup table entry:");
		print_lookup_table_entry(imd->metadata_lte, stderr);
		#endif
		ret = read_metadata_resource(w, imd);
		if (ret)
			w->current_image = WIMLIB_NO_IMAGE;
	}
	return ret;
}


/* Returns the compression type of the WIM file. */
WIMLIBAPI int
wimlib_get_compression_type(const WIMStruct *w)
{
	return wim_hdr_flags_compression_type(w->hdr.flags);
}

WIMLIBAPI const tchar *
wimlib_get_compression_type_string(int ctype)
{
	switch (ctype) {
		case WIMLIB_COMPRESSION_TYPE_NONE:
			return T("None");
		case WIMLIB_COMPRESSION_TYPE_LZX:
			return T("LZX");
		case WIMLIB_COMPRESSION_TYPE_XPRESS:
			return T("XPRESS");
		default:
			return T("Invalid");
	}
}

/*
 * Returns the number of an image in the WIM file, given a string that is either
 * the number of the image, or the name of the image.  The images are numbered
 * starting at 1.
 */
WIMLIBAPI int
wimlib_resolve_image(WIMStruct *w, const tchar *image_name_or_num)
{
	tchar *p;
	long image;
	int i;

	if (!image_name_or_num || !*image_name_or_num)
		return WIMLIB_NO_IMAGE;

	if (!tstrcasecmp(image_name_or_num, T("all"))
	    || !tstrcasecmp(image_name_or_num, T("*")))
		return WIMLIB_ALL_IMAGES;
	image = tstrtol(image_name_or_num, &p, 10);
	if (p != image_name_or_num && *p == T('\0') && image > 0) {
		if (image > w->hdr.image_count)
			return WIMLIB_NO_IMAGE;
		return image;
	} else {
		for (i = 1; i <= w->hdr.image_count; i++) {
			if (!tstrcmp(image_name_or_num,
				     wimlib_get_image_name(w, i)))
				return i;
		}
		return WIMLIB_NO_IMAGE;
	}
}

/* Prints some basic information about a WIM file. */
WIMLIBAPI void
wimlib_print_wim_information(const WIMStruct *w)
{
	const struct wim_header *hdr;

	hdr = &w->hdr;
	tputs(T("WIM Information:"));
	tputs(T("----------------"));
	tprintf(T("Path:           %"TS"\n"), w->filename);
	tfputs(T("GUID:           0x"), stdout);
	print_byte_field(hdr->guid, WIM_GID_LEN, stdout);
	tputchar(T('\n'));
	tprintf(T("Image Count:    %d\n"), hdr->image_count);
	tprintf(T("Compression:    %"TS"\n"),
		wimlib_get_compression_type_string(wimlib_get_compression_type(w)));
	tprintf(T("Part Number:    %d/%d\n"), hdr->part_number, hdr->total_parts);
	tprintf(T("Boot Index:     %d\n"), hdr->boot_idx);
	tprintf(T("Size:           %"PRIu64" bytes\n"),
		wim_info_get_total_bytes(w->wim_info));
	tprintf(T("Integrity Info: %"TS"\n"),
		(w->hdr.integrity.offset != 0) ? T("yes") : T("no"));
	tputchar(T('\n'));
}

WIMLIBAPI bool
wimlib_has_integrity_table(const WIMStruct *w)
{
	return w->hdr.integrity.size != 0;
}

WIMLIBAPI void
wimlib_print_available_images(const WIMStruct *w, int image)
{
	int first;
	int last;
	int i;
	int n;
	if (image == WIMLIB_ALL_IMAGES) {
		n = tprintf(T("Available Images:\n"));
		first = 1;
		last = w->hdr.image_count;
	} else if (image >= 1 && image <= w->hdr.image_count) {
		n = tprintf(T("Information for Image %d\n"), image);
		first = image;
		last = image;
	} else {
		tprintf(T("wimlib_print_available_images(): Invalid image %d"),
			image);
		return;
	}
	for (i = 0; i < n - 1; i++)
		tputchar(T('-'));
	tputchar(T('\n'));
	for (i = first; i <= last; i++)
		print_image_info(w->wim_info, i);
}


/* Prints the metadata for the specified image, which may be WIMLIB_ALL_IMAGES, but
 * not WIMLIB_NO_IMAGE. */
WIMLIBAPI int
wimlib_print_metadata(WIMStruct *w, int image)
{
	if (w->hdr.part_number != 1) {
		ERROR("Cannot show the metadata from part %hu of a %hu-part split WIM!",
		       w->hdr.part_number, w->hdr.total_parts);
		ERROR("Select the first part of the split WIM to see the metadata.");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}
	return for_image(w, image, image_print_metadata);
}

WIMLIBAPI int
wimlib_print_files(WIMStruct *w, int image)
{
	if (w->hdr.part_number != 1) {
		ERROR("Cannot list the files from part %hu of a %hu-part split WIM!",
		       w->hdr.part_number, w->hdr.total_parts);
		ERROR("Select the first part of the split WIM if you'd like to list the files.");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}
	return for_image(w, image, image_print_files);
}

/* Sets the index of the bootable image. */
WIMLIBAPI int
wimlib_set_boot_idx(WIMStruct *w, int boot_idx)
{
	if (w->hdr.total_parts != 1) {
		ERROR("Cannot modify the boot index of a split WIM!");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}
	if (boot_idx < 0 || boot_idx > w->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;
	w->hdr.boot_idx = boot_idx;
	return 0;
}

WIMLIBAPI int
wimlib_get_part_number(const WIMStruct *w, int *total_parts_ret)
{
	if (total_parts_ret)
		*total_parts_ret = w->hdr.total_parts;
	return w->hdr.part_number;
}


WIMLIBAPI int
wimlib_get_boot_idx(const WIMStruct *w)
{
	return w->hdr.boot_idx;
}

/*
 * Begins the reading of a WIM file; opens the file and reads its header and
 * lookup table, and optionally checks the integrity.
 */
static int
begin_read(WIMStruct *w, const tchar *in_wim_path, int open_flags,
	   wimlib_progress_func_t progress_func)
{
	int ret;
	int xml_num_images;

	DEBUG("Reading the WIM file `%"TS"'", in_wim_path);

	w->fp = tfopen(in_wim_path, T("rb"));
	if (!w->fp) {
		ERROR_WITH_ERRNO("Failed to open `%"TS"' for reading",
				 in_wim_path);
		return WIMLIB_ERR_OPEN;
	}

	/* The absolute path to the WIM is requested so that wimlib_overwrite()
	 * still works even if the process changes its working directory.  This
	 * actually happens if a WIM is mounted read-write, since the FUSE
	 * thread changes directory to "/", and it needs to be able to find the
	 * WIM file again.
	 *
	 * This will break if the full path to the WIM changes in the
	 * intervening time...
	 *
	 * Warning: in Windows native builds, realpath() calls the replacement
	 * function in win32.c.
	 */
	w->filename = realpath(in_wim_path, NULL);
	if (!w->filename) {
		ERROR_WITH_ERRNO("Failed to resolve WIM filename");
		if (errno == ENOMEM)
			return WIMLIB_ERR_NOMEM;
		else
			return WIMLIB_ERR_OPEN;
	}

	ret = read_header(w->fp, &w->hdr, open_flags);
	if (ret)
		return ret;

	DEBUG("According to header, WIM contains %u images", w->hdr.image_count);

	/* If the boot index is invalid, print a warning and set it to 0 */
	if (w->hdr.boot_idx > w->hdr.image_count) {
		WARNING("In `%"TS"', image %u is marked as bootable, "
			"but there are only %u images in the WIM",
			in_wim_path, w->hdr.boot_idx, w->hdr.image_count);
		w->hdr.boot_idx = 0;
	}

	if (wimlib_get_compression_type(w) == WIMLIB_COMPRESSION_TYPE_INVALID) {
		ERROR("Invalid compression type (WIM header flags = 0x%x)",
		      w->hdr.flags);
		return WIMLIB_ERR_INVALID_COMPRESSION_TYPE;
	}

	if (open_flags & WIMLIB_OPEN_FLAG_CHECK_INTEGRITY) {
		ret = check_wim_integrity(w, progress_func);
		if (ret == WIM_INTEGRITY_NONEXISTENT) {
			WARNING("No integrity information for `%"TS"'; skipping "
				"integrity check.", in_wim_path);
		} else if (ret == WIM_INTEGRITY_NOT_OK) {
			ERROR("WIM is not intact! (Failed integrity check)");
			return WIMLIB_ERR_INTEGRITY;
		} else if (ret != WIM_INTEGRITY_OK) {
			return ret;
		}
	}

	if (w->hdr.image_count != 0 && w->hdr.part_number == 1) {
		w->image_metadata = new_image_metadata_array(w->hdr.image_count);
		if (!w->image_metadata)
			return WIMLIB_ERR_NOMEM;
	}

	ret = read_lookup_table(w);
	if (ret)
		return ret;

	ret = read_xml_data(w->fp, &w->hdr.xml_res_entry,
			    &w->xml_data, &w->wim_info);
	if (ret)
		return ret;

	xml_num_images = wim_info_get_num_images(w->wim_info);
	if (xml_num_images != w->hdr.image_count) {
		ERROR("In the file `%"TS"', there are %u <IMAGE> elements "
		      "in the XML data,", in_wim_path, xml_num_images);
		ERROR("but %u images in the WIM!  There must be exactly one "
		      "<IMAGE> element per image.", w->hdr.image_count);
		return WIMLIB_ERR_IMAGE_COUNT;
	}

	DEBUG("Done beginning read of WIM file `%"TS"'.", in_wim_path);
	return 0;
}

/*
 * Opens a WIM file and creates a WIMStruct for it.
 */
WIMLIBAPI int
wimlib_open_wim(const tchar *wim_file, int open_flags,
		WIMStruct **w_ret,
		wimlib_progress_func_t progress_func)
{
	WIMStruct *w;
	int ret;

	if (!wim_file || !w_ret)
		return WIMLIB_ERR_INVALID_PARAM;

	w = new_wim_struct();
	if (!w)
		return WIMLIB_ERR_NOMEM;

	ret = begin_read(w, wim_file, open_flags, progress_func);
	if (ret == 0)
		*w_ret = w;
	else
		wimlib_free(w);
	return ret;
}

void
destroy_image_metadata(struct wim_image_metadata *imd,
		       struct wim_lookup_table *table,
		       bool free_metadata_lte)
{
	free_dentry_tree(imd->root_dentry, table);
	imd->root_dentry = NULL;
	free_security_data(imd->security_data);
	imd->security_data = NULL;

	if (free_metadata_lte) {
		free_lookup_table_entry(imd->metadata_lte);
		imd->metadata_lte = NULL;
	}
	if (!table) {
		struct wim_lookup_table_entry *lte, *tmp;
		list_for_each_entry_safe(lte, tmp, &imd->unhashed_streams, unhashed_list)
			free_lookup_table_entry(lte);
	}
	INIT_LIST_HEAD(&imd->unhashed_streams);
	INIT_LIST_HEAD(&imd->inode_list);
#ifdef WITH_NTFS_3G
	if (imd->ntfs_vol) {
		do_ntfs_umount(imd->ntfs_vol);	
		imd->ntfs_vol = NULL;
	}
#endif
}

void
put_image_metadata(struct wim_image_metadata *imd,
		   struct wim_lookup_table *table)
{
	if (imd && --imd->refcnt == 0) {
		destroy_image_metadata(imd, table, true);
		FREE(imd);
	}
}

/* Appends the specified image metadata structure to the array of image metadata
 * for a WIM, and increments the image count. */
int
append_image_metadata(WIMStruct *w, struct wim_image_metadata *imd)
{
	struct wim_image_metadata **imd_array;

	DEBUG("Reallocating image metadata array for image_count = %u",
	      w->hdr.image_count + 1);
	imd_array = REALLOC(w->image_metadata,
			    sizeof(w->image_metadata[0]) * (w->hdr.image_count + 1));

	if (!imd_array)
		return WIMLIB_ERR_NOMEM;
	w->image_metadata = imd_array;
	imd_array[w->hdr.image_count++] = imd;
	return 0;
}


struct wim_image_metadata *
new_image_metadata()
{
	struct wim_image_metadata *imd;

	imd = CALLOC(1, sizeof(*imd));
	if (imd) {
		imd->refcnt = 1;
		INIT_LIST_HEAD(&imd->inode_list);
		INIT_LIST_HEAD(&imd->unhashed_streams);
		DEBUG("Created new image metadata (refcnt=1)");
	} else {
		ERROR_WITH_ERRNO("Failed to allocate new image metadata structure");
	}
	return imd;
}

struct wim_image_metadata **
new_image_metadata_array(unsigned num_images)
{
	struct wim_image_metadata **imd_array;

	DEBUG("Creating new image metadata array for %u images",
	      num_images);

	imd_array = CALLOC(num_images, sizeof(imd_array[0]));

	if (!imd_array) {
		ERROR("Failed to allocate memory for %u image metadata structures",
		      num_images);
		return NULL;
	}
	for (unsigned i = 0; i < num_images; i++) {
		imd_array[i] = new_image_metadata();
		if (!imd_array[i]) {
			for (unsigned j = 0; j < i; j++)
				put_image_metadata(imd_array[j], NULL);
			FREE(imd_array);
			return NULL;
		}
	}
	return imd_array;
}

/* Checksum all streams that are unhashed (other than the metadata streams),
 * merging them into the lookup table as needed.  This is a no-op unless the
 * library has previously used to add or mount an image using the same
 * WIMStruct. */
int
wim_checksum_unhashed_streams(WIMStruct *w)
{
	int ret;
	for (int i = 0; i < w->hdr.image_count; i++) {
		struct wim_lookup_table_entry *lte, *tmp;
		list_for_each_entry_safe(lte, tmp,
					 &w->image_metadata[i]->unhashed_streams,
					 unhashed_list)
		{
			ret = hash_unhashed_stream(lte, w->lookup_table, NULL);
			if (ret)
				return ret;
		}
	}
	return 0;
}

/* Frees the memory for the WIMStruct, including all internal memory; also
 * closes all files associated with the WIMStruct.  */
WIMLIBAPI void
wimlib_free(WIMStruct *w)
{
	DEBUG("Freeing WIMStruct");

	if (!w)
		return;
	if (w->fp)
		fclose(w->fp);
	if (w->out_fp)
		fclose(w->out_fp);

#ifdef WITH_FUSE
	if (w->fp_tab) {
		for (size_t i = 0; i < w->num_allocated_fps; i++)
			if (w->fp_tab[i])
				fclose(w->fp_tab[i]);
		FREE(w->fp_tab);
	}
	pthread_mutex_destroy(&w->fp_tab_mutex);
#endif

	free_lookup_table(w->lookup_table);

	FREE(w->filename);
	FREE(w->xml_data);
	free_wim_info(w->wim_info);
	if (w->image_metadata) {
		for (unsigned i = 0; i < w->hdr.image_count; i++)
			put_image_metadata(w->image_metadata[i], NULL);
		FREE(w->image_metadata);
	}
	FREE(w);
	DEBUG("Freed WIMStruct");
}

static bool
test_locale_ctype_utf8()
{
#ifdef __WIN32__
	return false;
#else
	char *ctype = nl_langinfo(CODESET);

	return (!strstr(ctype, "UTF-8") ||
		!strstr(ctype, "UTF8") ||
		!strstr(ctype, "utf8") ||
		!strstr(ctype, "utf-8"));
#endif
}

/* Get global memory allocations out of the way,
 * single-threaded programs like 'imagex'. */
WIMLIBAPI int
wimlib_global_init()
{
	libxml_global_init();
#ifdef WITH_NTFS_3G
	libntfs3g_global_init();
#endif
	wimlib_mbs_is_utf8 = test_locale_ctype_utf8();
#ifdef __WIN32__
	win32_global_init();
#endif
	return 0;
}

/* Free global memory allocations.  Not strictly necessary if the process using
 * wimlib is just about to exit (as is the case for 'imagex'). */
WIMLIBAPI void
wimlib_global_cleanup()
{
	libxml_global_cleanup();
	iconv_global_cleanup();
#ifdef __WIN32__
	win32_global_cleanup();
#endif
}
