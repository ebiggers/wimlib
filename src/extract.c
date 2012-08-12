/*
 * extract.c
 *
 * Support for extracting WIM files.
 */

/*
 * Copyright (C) 2010 Carl Thijssen
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
#include "dentry.h"
#include "lookup_table.h"
#include "xml.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>


/* 
 * Extracts a regular file from the WIM archive. 
 *
 * @dentry:  		The directory entry for the file, which must be a
 *				regular file.
 * @output_path:   	The path to which the file is to be extracted.
 * @lookup_table:	The lookup table for the WIM file.
 * @wim_fp:  		The FILE* for the WIM, opened for reading.
 * @wim_ctype:  	The type of compression used in the WIM.
 * @link_type:		One of WIM_LINK_TYPE_*; specifies what to do with
 * 			files that are hard-linked inside the WIM.
 * @is_multi_image_extraction: 
 * 			True if the image currently being extracted is just one 
 * 			image of a multi-image extraction.  This is needed so
 * 			that cross-image symbolic links can be created
 * 			correctly.
 */
static int extract_regular_file(WIMStruct *w, 
				const struct dentry *dentry, 
				const char *output_path)
{
	struct lookup_table *lookup_table;
	int link_type;
	bool is_multi_image_extraction;
	struct lookup_table_entry *lte;
	int ret;
	int out_fd;
	const struct resource_entry *res_entry;

	lookup_table = w->lookup_table;
	link_type = w->link_type;
	is_multi_image_extraction = w->is_multi_image_extraction;
	lte = lookup_resource(lookup_table, dentry->hash);

	/* If we already extracted the same file or a hard link copy of it, we
	 * may be able to simply create a link.  The exact action is specified
	 * by the current @link_type. */
	if (link_type != WIM_LINK_TYPE_NONE && lte && lte->out_refcnt != 0) {
		wimlib_assert(lte->file_on_disk);

		if (link_type == WIM_LINK_TYPE_HARD) {
			if (link(lte->file_on_disk, output_path) != 0) {
				ERROR("Failed to hard link `%s' to `%s': %m\n",
						output_path, lte->file_on_disk);
				return WIMLIB_ERR_LINK;
			}
		} else {
			int num_path_components;
			int num_output_dir_path_components;
			size_t file_on_disk_len;
			char *p;
			const char *p2;
			size_t i;

			num_path_components = 
				get_num_path_components(dentry->full_path_utf8) - 1;
			num_output_dir_path_components =
				get_num_path_components(w->output_dir);

			if (is_multi_image_extraction) {
				num_path_components++;
				num_output_dir_path_components--;
			}
			file_on_disk_len = strlen(lte->file_on_disk);

			char buf[file_on_disk_len + 3 * num_path_components + 1];
			p = &buf[0];

			for (i = 0; i < num_path_components; i++) {
				*p++ = '.';
				*p++ = '.';
				*p++ = '/';
			}
			p2 = lte->file_on_disk;
			while (*p2 == '/')
				p2++;
			while (num_output_dir_path_components--)
				p2 = path_next_part(p2, NULL);
			strcpy(p, p2);
			if (symlink(buf, output_path) != 0) {
				ERROR("Failed to symlink `%s' to `%s': %m\n",
						buf, lte->file_on_disk);
				return WIMLIB_ERR_LINK;
			}

		}
		return 0;
	} 

	/* Otherwise, we must actually extract the file contents. */

	out_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out_fd == -1) {
		ERROR("Failed to open the file `%s' for writing: "
				"%m\n", output_path);
		return WIMLIB_ERR_OPEN;
	}

	/* Extract empty file, with no lookup table entry... */
	if (!lte) {
		DEBUG("Empty file `%s'\n", output_path);
		ret = 0;
		goto done;
	}

	res_entry = &lte->resource_entry;

	ret = extract_resource_to_fd(w, res_entry, out_fd, 
				     res_entry->original_size);

	if (ret != 0) {
		ERROR("Failed to extract resource to `%s'!\n", output_path);
		goto done;
	}

	/* Mark the lookup table entry to indicate this file has been extracted. */
	lte->out_refcnt++;
	FREE(lte->file_on_disk);
	lte->file_on_disk = STRDUP(output_path);
	if (lte->file_on_disk)
		ret = 0;
	else
		ret = WIMLIB_ERR_NOMEM;
done:
	close(out_fd);
	return ret;
}

/* 
 * Extracts a directory from the WIM archive. 
 *
 * @dentry:		The directory entry for the directory.
 * @output_path:   	The path to which the directory is to be extracted to.
 * @return: 		True on success, false on failure. 
 */
static int extract_directory(struct dentry *dentry, const char *output_path)
{
	/* Compute the output path directory to the directory. */
	if (mkdir(output_path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) 
	{
		switch (errno) {
		case EEXIST: /* Already existing directory is OK */
		case EACCES: /* We may have permissions to extract files inside
				 the directory, but not for the directory
				 itself. */
			return 0;
		default:
			ERROR("Cannot create directory `%s': %m\n",
					output_path);
			return WIMLIB_ERR_MKDIR;
		}
	}
	return 0;
}


/* 
 * Extracts a file or directory from the WIM archive.  For use in
 * for_dentry_in_tree().
 *
 * @dentry:	The dentry to extract.
 * @arg:	A pointer to the WIMStruct for the WIM file.
 */
static int extract_regular_file_or_directory(struct dentry *dentry, void *arg)
{
	WIMStruct *w = (WIMStruct*)arg;
	size_t len = strlen(w->output_dir);
	char output_path[len + dentry->full_path_utf8_len + 1];

	if (w->verbose)
		puts(dentry->full_path_utf8);

	memcpy(output_path, w->output_dir, len);
	memcpy(output_path + len, dentry->full_path_utf8, dentry->full_path_utf8_len);
	output_path[len + dentry->full_path_utf8_len] = '\0';


	if (dentry_is_regular_file(dentry)) {
		return extract_regular_file(w, dentry, output_path);
	} else {
		if (dentry_is_root(dentry)) /* Root doesn't need to be extracted. */
			return 0;
		else
			return extract_directory(dentry, output_path);
	}
}

static int extract_single_image(WIMStruct *w, int image)
{
	DEBUG("Extracting image %d\n", image);

	int ret;
	ret = wimlib_select_image(w, image);
	if (ret != 0)
		return ret;

	return for_dentry_in_tree(wim_root_dentry(w),
				  extract_regular_file_or_directory, w);
}


/* Extracts all images from the WIM to w->output_dir, with the images placed in
 * subdirectories named by their image names. */
static int extract_all_images(WIMStruct *w)
{
	size_t image_name_max_len = max(xml_get_max_image_name_len(w), 20);
	size_t output_path_len = strlen(w->output_dir);
	char buf[output_path_len + 1 + image_name_max_len + 1];
	int ret;
	int image;
	const char *image_name;

	DEBUG("Attempting to extract all images from `%s'\n", w->filename);

	memcpy(buf, w->output_dir, output_path_len);
	buf[output_path_len] = '/';
	for (image = 1; image <= w->hdr.image_count; image++) {
		buf[output_path_len + 1] = '\0';
		
		image_name = wimlib_get_image_name(w, image);
		if (*image_name) {
			strncat(buf + output_path_len + 1, image_name, 
				image_name_max_len);
		} else {
			/* Image name is empty. Use image number instead */
			sprintf(buf + output_path_len + 1, "%d", image);
		}
		ret = wimlib_set_output_dir(w, buf);
		if (ret != 0)
			goto done;
		ret = extract_single_image(w, image);
		if (ret != 0)
			goto done;
	}
	ret = 0;
done:
	buf[output_path_len + 1] = '\0';
	wimlib_set_output_dir(w, buf);
	return ret;
}

/* Extracts a single image or all images from a WIM file. */
WIMLIBAPI int wimlib_extract_image(WIMStruct *w, int image)
{
	if (!w->output_dir) {
		ERROR("No output directory selected.\n");
		return WIMLIB_ERR_NOTDIR;
	}
	if (image == WIM_ALL_IMAGES) {
		w->is_multi_image_extraction = true;
		return extract_all_images(w);
	} else {
		w->is_multi_image_extraction = false;
		return extract_single_image(w, image);
	}

}

/* Set the output directory for WIM extraction.  The directory is created using
 * mkdir().  Fails if directory cannot be created or already exists. */
WIMLIBAPI int wimlib_set_output_dir(WIMStruct *w, const char *dir)
{
	char *p;
	DEBUG("Setting output directory to `%s'\n", dir);

	if (!dir) {
		ERROR("Must specify a directory!\n");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	p = STRDUP(dir);
	if (!p) {
		ERROR("Out of memory!\n");
		return WIMLIB_ERR_NOMEM;
	}

	if (mkdir(dir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
		if (errno == EEXIST) {
			DEBUG("`%s' already exists\n", dir);
			goto done;
		}
		ERROR("Cannot create directory `%s': %m\n", dir);
		FREE(p);
		return WIMLIB_ERR_MKDIR;
	} else {
		DEBUG("Created directory `%s'\n", dir);
	}
done:
	FREE(w->output_dir);
	w->output_dir = p;
	return 0;
}

WIMLIBAPI int wimlib_set_link_type(WIMStruct *w, int link_type)
{
	switch (link_type) {
		case WIM_LINK_TYPE_NONE:
		case WIM_LINK_TYPE_HARD:
		case WIM_LINK_TYPE_SYMBOLIC:
			w->link_type = link_type;
			return 0;
		default:
			return WIMLIB_ERR_INVALID_PARAM;
	}
}

