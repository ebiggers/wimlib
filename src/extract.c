/*
 * extract.c
 *
 * Support for extracting WIM files.
 *
 * This code does NOT contain any filesystem-specific features.  In particular,
 * security information (i.e. file permissions) and alternate data streams are
 * ignored, except possibly to read an alternate data stream that contains
 * symbolic link data.
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


#include "config.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/time.h>

#ifdef HAVE_UTIME_H
#include <utime.h>
#endif

#include <unistd.h>

#include "dentry.h"
#include "lookup_table.h"
#include "timestamp.h"
#include "wimlib_internal.h"
#include "xml.h"


static int extract_regular_file_linked(const struct dentry *dentry,
				       const char *output_dir,
				       const char *output_path,
				       int extract_flags,
				       struct lookup_table_entry *lte)
{
	/* This mode overrides the normal hard-link extraction and
	 * instead either symlinks or hardlinks *all* identical files in
	 * the WIM, even if they are in a different image (in the case
	 * of a multi-image extraction) */
	wimlib_assert(lte->extracted_file != NULL);

	if (extract_flags & WIMLIB_EXTRACT_FLAG_HARDLINK) {
		if (link(lte->extracted_file, output_path) != 0) {
			ERROR_WITH_ERRNO("Failed to hard link "
					 "`%s' to `%s'",
					 output_path, lte->extracted_file);
			return WIMLIB_ERR_LINK;
		}
	} else {
		int num_path_components;
		int num_output_dir_path_components;
		size_t extracted_file_len;
		char *p;
		const char *p2;
		size_t i;

		wimlib_assert(extract_flags & WIMLIB_EXTRACT_FLAG_SYMLINK);

		num_path_components =
			get_num_path_components(dentry->full_path_utf8) - 1;
		num_output_dir_path_components =
			get_num_path_components(output_dir);

		if (extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE) {
			num_path_components++;
			num_output_dir_path_components--;
		}
		extracted_file_len = strlen(lte->extracted_file);

		char buf[extracted_file_len + 3 * num_path_components + 1];
		p = &buf[0];

		for (i = 0; i < num_path_components; i++) {
			*p++ = '.';
			*p++ = '.';
			*p++ = '/';
		}
		p2 = lte->extracted_file;
		while (*p2 == '/')
			p2++;
		while (num_output_dir_path_components--)
			p2 = path_next_part(p2, NULL);
		strcpy(p, p2);
		if (symlink(buf, output_path) != 0) {
			ERROR_WITH_ERRNO("Failed to symlink `%s' to "
					 "`%s'",
					 buf, lte->extracted_file);
			return WIMLIB_ERR_LINK;
		}

	}
	return 0;
}

static int extract_regular_file_unlinked(WIMStruct *w,
					 struct dentry *dentry,
				         const char *output_path,
				         int extract_flags,
				         struct lookup_table_entry *lte)
{
	/* Normal mode of extraction.  Regular files and hard links are
	 * extracted in the way that they appear in the WIM. */

	int out_fd;
	int ret;
	struct inode *inode = dentry->d_inode;

	if (!((extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE)
		&& (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
				     WIMLIB_EXTRACT_FLAG_HARDLINK))))
	{
		/* If the dentry is one of a hard link set of at least 2
		 * dentries and one of the other dentries has already been
		 * extracted, make a hard link to the file corresponding to this
		 * already-extracted directory.  Otherwise, extract the file,
		 * and set the inode->extracted_file field so that other
		 * dentries in the hard link group can link to it. */
		if (inode->link_count > 1) {
			if (inode->extracted_file) {
				DEBUG("Extracting hard link `%s' => `%s'",
				      output_path, inode->extracted_file);
				if (link(inode->extracted_file, output_path) != 0) {
					ERROR_WITH_ERRNO("Failed to hard link "
							 "`%s' to `%s'",
							 output_path,
							 inode->extracted_file);
					return WIMLIB_ERR_LINK;
				}
				return 0;
			}
			FREE(inode->extracted_file);
			inode->extracted_file = STRDUP(output_path);
			if (!inode->extracted_file) {
				ERROR("Failed to allocate memory for filename");
				return WIMLIB_ERR_NOMEM;
			}
		}
	}

	/* Extract the contents of the file to @output_path. */

	out_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (out_fd == -1) {
		ERROR_WITH_ERRNO("Failed to open the file `%s' for writing",
				 output_path);
		return WIMLIB_ERR_OPEN;
	}

	if (!lte) {
		/* Empty file with no lookup table entry */
		DEBUG("Empty file `%s'.", output_path);
		ret = 0;
		goto out;
	}

	ret = extract_full_wim_resource_to_fd(lte, out_fd);
	if (ret != 0) {
		ERROR("Failed to extract resource to `%s'", output_path);
		goto out;
	}

out:
	if (close(out_fd) != 0) {
		ERROR_WITH_ERRNO("Failed to close file `%s'", output_path);
		ret = WIMLIB_ERR_WRITE;
	}
	return ret;
}

/*
 * Extracts a regular file from the WIM archive.
 */
static int extract_regular_file(WIMStruct *w,
				struct dentry *dentry,
				const char *output_dir,
				const char *output_path,
				int extract_flags)
{
	struct lookup_table_entry *lte;
	const struct inode *inode = dentry->d_inode;

	lte = inode_unnamed_lte(inode, w->lookup_table);

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			      WIMLIB_EXTRACT_FLAG_HARDLINK)) && lte) {
		if (lte->extracted_file) {
			return extract_regular_file_linked(dentry, output_dir,
							   output_path,
							   extract_flags, lte);
		} else {
			lte->extracted_file = STRDUP(output_path);
			if (!lte->extracted_file)
				return WIMLIB_ERR_NOMEM;
		}
	}

	return extract_regular_file_unlinked(w, dentry, output_path,
					     extract_flags, lte);

}

static int extract_symlink(const struct dentry *dentry, const char *output_path,
			   const WIMStruct *w)
{
	char target[4096];
	ssize_t ret = inode_readlink(dentry->d_inode, target,
				     sizeof(target), w, 0);
	if (ret <= 0) {
		ERROR("Could not read the symbolic link from dentry `%s'",
		      dentry->full_path_utf8);
		return WIMLIB_ERR_INVALID_DENTRY;
	}
	ret = symlink(target, output_path);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to symlink `%s' to `%s'",
				 output_path, target);
		return WIMLIB_ERR_LINK;
	}
	return 0;
}

/*
 * Extracts a directory from the WIM archive.
 *
 * @dentry:		The directory entry for the directory.
 * @output_path:   	The path to which the directory is to be extracted to.
 * @return: 		True on success, false on failure.
 */
static int extract_directory(const char *output_path, bool is_root)
{
	int ret;
	struct stat stbuf;
	ret = stat(output_path, &stbuf);
	if (ret == 0) {
		if (S_ISDIR(stbuf.st_mode)) {
			/*if (!is_root)*/
				/*WARNING("`%s' already exists", output_path);*/
			return 0;
		} else {
			ERROR("`%s' is not a directory", output_path);
			return WIMLIB_ERR_MKDIR;
		}
	} else {
		if (errno != ENOENT) {
			ERROR_WITH_ERRNO("Failed to stat `%s'", output_path);
			return WIMLIB_ERR_STAT;
		}
	}
	/* Compute the output path directory to the directory. */
	if (mkdir(output_path, S_IRWXU | S_IRGRP | S_IXGRP |
			       S_IROTH | S_IXOTH) != 0) {
		ERROR_WITH_ERRNO("Cannot create directory `%s'",
				 output_path);
		return WIMLIB_ERR_MKDIR;
	}
	return 0;
}

struct extract_args {
	WIMStruct *w;
	int extract_flags;
	const char *output_dir;
	unsigned num_lutimes_warnings;
};

/*
 * Extracts a file, directory, or symbolic link from the WIM archive.  For use
 * in for_dentry_in_tree().
 */
static int extract_dentry(struct dentry *dentry, void *arg)
{
	struct extract_args *args = arg;
	WIMStruct *w = args->w;
	int extract_flags = args->extract_flags;
	size_t len = strlen(args->output_dir);
	char output_path[len + dentry->full_path_utf8_len + 1];

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NO_STREAMS)
		if (inode_unnamed_lte(dentry->d_inode, w->lookup_table) != NULL)
			return 0;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE) {
		wimlib_assert(dentry->full_path_utf8);
		puts(dentry->full_path_utf8);
	}

	memcpy(output_path, args->output_dir, len);
	memcpy(output_path + len, dentry->full_path_utf8, dentry->full_path_utf8_len);
	output_path[len + dentry->full_path_utf8_len] = '\0';


	if (dentry_is_symlink(dentry))
		return extract_symlink(dentry, output_path, w);
	else if (dentry_is_directory(dentry))
		return extract_directory(output_path, dentry_is_root(dentry));
	else
		return extract_regular_file(w, dentry, args->output_dir,
					    output_path, extract_flags);
}

/* Apply timestamp to extracted file */
static int apply_dentry_timestamps(struct dentry *dentry, void *arg)
{
	struct extract_args *args = arg;
	size_t len = strlen(args->output_dir);
	char output_path[len + dentry->full_path_utf8_len + 1];
	const struct inode *inode = dentry->d_inode;
	int ret;

	memcpy(output_path, args->output_dir, len);
	memcpy(output_path + len, dentry->full_path_utf8, dentry->full_path_utf8_len);
	output_path[len + dentry->full_path_utf8_len] = '\0';

	struct timeval tv[2];
	wim_timestamp_to_timeval(inode->last_access_time, &tv[0]);
	wim_timestamp_to_timeval(inode->last_write_time, &tv[1]);
	#ifdef HAVE_LUTIMES
	ret = lutimes(output_path, tv);
	#else
	ret = -1;
	errno = ENOSYS;
	#endif
	if (ret != 0) {
		#ifdef HAVE_UTIME
		if (errno == ENOSYS) {
			struct utimbuf buf;
			buf.actime = wim_timestamp_to_unix(inode->last_access_time);
			buf.modtime = wim_timestamp_to_unix(inode->last_write_time);
			if (utime(output_path, &buf) == 0)
				return 0;
		}
		#endif
		if (errno != ENOSYS || args->num_lutimes_warnings < 10) {
			/*WARNING("Failed to set timestamp on file `%s': %s",*/
				/*output_path, strerror(errno));*/
			args->num_lutimes_warnings++;
		}
	}
	return 0;
}


static int dentry_add_streams_for_extraction(struct dentry *dentry,
					     void *wim)
{
	WIMStruct *w = wim;
	struct list_head *stream_list;
	struct lookup_table_entry *lte;

	lte = inode_unnamed_lte(dentry->d_inode, w->lookup_table);
	if (lte) {
		if (++lte->out_refcnt == 1) {
			INIT_LIST_HEAD(&lte->dentry_list);
			stream_list = w->private;
			list_add_tail(&lte->staging_list, stream_list);
		}
		list_add_tail(&dentry->tmp_list, &lte->dentry_list);
	}
	return 0;
}

static int cmp_streams_by_wim_position(const void *p1, const void *p2)
{
	const struct lookup_table_entry *lte1, *lte2;
	lte1 = *(const struct lookup_table_entry**)p1;
	lte2 = *(const struct lookup_table_entry**)p2;
	if (lte1->resource_entry.offset < lte2->resource_entry.offset)
		return -1;
	else if (lte1->resource_entry.offset > lte2->resource_entry.offset)
		return 1;
	else
		return 0;
}

static int sort_stream_list_by_wim_position(struct list_head *stream_list)
{
	struct list_head *cur;
	size_t num_streams;
	struct lookup_table_entry **array;
	size_t i;
	size_t array_size;

	DEBUG("Sorting stream list by wim position");

	num_streams = 0;
	list_for_each(cur, stream_list)
		num_streams++;
	array_size = num_streams * sizeof(array[0]);

	DEBUG("num_streams = %zu", num_streams);

	array = MALLOC(array_size);
	if (!array) {
		ERROR("Failed to allocate %zu bytes to sort stream entries",
		      array_size);
		return WIMLIB_ERR_NOMEM;
	}
	cur = stream_list->next;
	for (i = 0; i < num_streams; i++) {
		array[i] = container_of(cur, struct lookup_table_entry, staging_list);
		cur = cur->next;
	}

	qsort(array, num_streams, sizeof(array[0]), cmp_streams_by_wim_position);

	INIT_LIST_HEAD(stream_list);
	for (i = 0; i < num_streams; i++)
		list_add_tail(&array[i]->staging_list, stream_list);
	FREE(array);
	return 0;
}

static u64 calculate_bytes_to_extract(struct list_head *stream_list,
				      int extract_flags)
{
	struct lookup_table_entry *lte;
	struct dentry *dentry;
	u64 total_size = 0;
	list_for_each_entry(lte, stream_list, staging_list) {
		u64 size = wim_resource_size(lte);
		if (extract_flags &
		    (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
		{
			total_size += size;
		} else {
			list_for_each_entry(dentry, &lte->dentry_list,
					    tmp_list)
			{
				dentry->d_inode->found = false;
			}
			list_for_each_entry(dentry, &lte->dentry_list,
					    tmp_list)
			{
				if (!dentry->d_inode->found) {
					dentry->d_inode->found = true;
					total_size += size;
				}
			}
		}
	}
	return total_size;
}

static int extract_single_image(WIMStruct *w, int image,
				const char *output_dir, int extract_flags)
{
	int ret;
	struct dentry *root;
	const char *image_name;

	DEBUG("Extracting image %d", image);

	ret = select_wim_image(w, image);
	if (ret != 0)
		return ret;

	root = wim_root_dentry(w);

	struct extract_args args = {
		.w                    = w,
		.extract_flags        = extract_flags,
		.output_dir           = output_dir,
		.num_lutimes_warnings = 0,
	};

	image_name = wimlib_get_image_name(w, image);
	if (!image_name)
		image_name = "unnamed";

	if (extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL) {
		for_lookup_table_entry(w->lookup_table, lte_zero_out_refcnt,
				       NULL);
		args.extract_flags |= WIMLIB_EXTRACT_FLAG_NO_STREAMS;
		if (args.extract_flags & WIMLIB_EXTRACT_FLAG_SHOW_PROGRESS) {
			printf("Creating directory structure for image %d (%s)...\n",
			       image, image_name);
		}
	} else {
		if (args.extract_flags & WIMLIB_EXTRACT_FLAG_SHOW_PROGRESS) {
			printf("Extracting image %d (%s)...\n",
			       image, image_name);
		}
	}

	ret = for_dentry_in_tree(root, extract_dentry, &args);
	if (ret != 0)
		return ret;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL) {
		struct list_head stream_list;
		struct lookup_table_entry *lte;
		struct lookup_table_entry *tmp;
		struct dentry *dentry;
		u64 total_size;
		u64 cur_size;
		u64 next_size;
		u64 one_percent;
		unsigned cur_percent;

		INIT_LIST_HEAD(&stream_list);
		w->private = &stream_list;
		for_dentry_in_tree(root, dentry_add_streams_for_extraction, w);
		ret = sort_stream_list_by_wim_position(&stream_list);
		args.extract_flags &= ~WIMLIB_EXTRACT_FLAG_NO_STREAMS;
		if (ret != 0) {
			WARNING("Falling back to non-sequential image extraction");
			ret = for_dentry_in_tree(root, extract_dentry, &args);
			if (ret != 0)
				return ret;
			goto out;
		}

		total_size = calculate_bytes_to_extract(&stream_list, args.extract_flags);
		one_percent = total_size / 100;
		cur_size = 0;
		next_size = 0;
		cur_percent = 0;
		puts("Extracting files...");
		list_for_each_entry_safe(lte, tmp, &stream_list, staging_list) {
			list_del(&lte->staging_list);
			list_for_each_entry(dentry, &lte->dentry_list, tmp_list) {
				if ((!dentry->d_inode->extracted_file) &&
				     (args.extract_flags & WIMLIB_EXTRACT_FLAG_SHOW_PROGRESS))
				{
					show_stream_op_progress(&cur_size, &next_size,
								total_size, one_percent,
								&cur_percent, lte,
								"extracted");
				}
				ret = extract_dentry(dentry, &args);
				if (ret != 0)
					return ret;
			}
		}
		finish_stream_op_progress(total_size, "extracted");
	}
out:
	return for_dentry_in_tree_depth(root, apply_dentry_timestamps, &args);
}


/* Extracts all images from the WIM to @output_dir, with the images placed in
 * subdirectories named by their image names. */
static int extract_all_images(WIMStruct *w, const char *output_dir,
			      int extract_flags)
{
	size_t image_name_max_len = max(xml_get_max_image_name_len(w), 20);
	size_t output_path_len = strlen(output_dir);
	char buf[output_path_len + 1 + image_name_max_len + 1];
	int ret;
	int image;
	const char *image_name;

	DEBUG("Attempting to extract all images from `%s' to `%s'",
	      w->filename, output_dir);

	ret = extract_directory(output_dir, true);
	if (ret != 0)
		return ret;

	memcpy(buf, output_dir, output_path_len);
	buf[output_path_len] = '/';
	for (image = 1; image <= w->hdr.image_count; image++) {

		image_name = wimlib_get_image_name(w, image);
		if (*image_name) {
			strcpy(buf + output_path_len + 1, image_name);
		} else {
			/* Image name is empty. Use image number instead */
			sprintf(buf + output_path_len + 1, "%d", image);
		}
		ret = extract_single_image(w, image, buf, extract_flags);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/* Extracts a single image or all images from a WIM file. */
WIMLIBAPI int wimlib_extract_image(WIMStruct *w, int image,
				   const char *output_dir,
				   int extract_flags,
				   WIMStruct **additional_swms,
				   unsigned num_additional_swms)
{
	struct lookup_table *joined_tab, *w_tab_save;
	int ret;

	DEBUG("w->filename = %s, image = %d, output_dir = %s, flags = 0x%x, "
	      "num_additional_swms = %u",
	      w->filename, image, output_dir, extract_flags, num_additional_swms);

	if (!w || !output_dir)
		return WIMLIB_ERR_INVALID_PARAM;

	extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
			== (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
		return WIMLIB_ERR_INVALID_PARAM;

	ret = verify_swm_set(w, additional_swms, num_additional_swms);
	if (ret != 0)
		return ret;

	if (num_additional_swms) {
		ret = new_joined_lookup_table(w, additional_swms,
					      num_additional_swms, &joined_tab);
		if (ret != 0)
			return ret;
		w_tab_save = w->lookup_table;
		w->lookup_table = joined_tab;
	}

	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(w->lookup_table,
				       lte_zero_extracted_file,
				       NULL);
		extract_flags &= ~WIMLIB_EXTRACT_FLAG_SEQUENTIAL;
	}

	if (image == WIM_ALL_IMAGES) {
		extract_flags |= WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;
		ret = extract_all_images(w, output_dir, extract_flags);
	} else {
		extract_flags &= ~WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;
		ret = extract_single_image(w, image, output_dir, extract_flags);
	}
	if (num_additional_swms) {
		free_lookup_table(w->lookup_table);
		w->lookup_table = w_tab_save;
	}

	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(w->lookup_table,
				       lte_free_extracted_file,
				       NULL);
	}
	return ret;

}
