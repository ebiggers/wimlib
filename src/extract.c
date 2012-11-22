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

#ifdef WITH_NTFS_3G
#include <ntfs-3g/volume.h>
#endif

static int extract_regular_file_linked(struct dentry *dentry,
				       const char *output_path,
				       struct apply_args *args,
				       struct lookup_table_entry *lte)
{
	/* This mode overrides the normal hard-link extraction and
	 * instead either symlinks or hardlinks *all* identical files in
	 * the WIM, even if they are in a different image (in the case
	 * of a multi-image extraction) */

	if (args->extract_flags & WIMLIB_EXTRACT_FLAG_HARDLINK) {
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

		num_path_components =
			get_num_path_components(dentry->full_path_utf8) - 1;
		num_output_dir_path_components =
			get_num_path_components(args->target);

		if (args->extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE) {
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

static int extract_regular_file_unlinked(struct dentry *dentry,
				         struct apply_args *args,
				         const char *output_path,
				         struct lookup_table_entry *lte)
{
	/* Normal mode of extraction.  Regular files and hard links are
	 * extracted in the way that they appear in the WIM. */

	int out_fd;
	int ret;
	struct inode *inode = dentry->d_inode;

	if (!((args->extract_flags & WIMLIB_EXTRACT_FLAG_MULTI_IMAGE)
		&& (args->extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
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
	args->progress.extract.completed_bytes += wim_resource_size(lte);
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
static int extract_regular_file(struct dentry *dentry,
				struct apply_args *args,
				const char *output_path)
{
	struct lookup_table_entry *lte;
	const struct inode *inode = dentry->d_inode;

	lte = inode_unnamed_lte_resolved(inode);

	if (lte && (args->extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
					   WIMLIB_EXTRACT_FLAG_HARDLINK)))
	{
		if (lte->extracted_file) {
			return extract_regular_file_linked(dentry, output_path, args, lte);
		} else {
			lte->extracted_file = STRDUP(output_path);
			if (!lte->extracted_file)
				return WIMLIB_ERR_NOMEM;
		}
	}
	return extract_regular_file_unlinked(dentry, args, output_path, lte);
}

static int extract_symlink(struct dentry *dentry,
			   struct apply_args *args,
			   const char *output_path)
{
	char target[4096];
	ssize_t ret = inode_readlink(dentry->d_inode, target,
				     sizeof(target), args->w, 0);
	struct lookup_table_entry *lte;

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
	lte = inode_unnamed_lte_resolved(dentry->d_inode);
	args->progress.extract.completed_bytes += wim_resource_size(lte);
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

/*
 * Extracts a file, directory, or symbolic link from the WIM archive.  For use
 * in for_dentry_in_tree().
 */
static int apply_dentry_normal(struct dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	int extract_flags = args->extract_flags;
	struct inode *inode = dentry->d_inode;
	size_t len;
	int ret;

	if (dentry->is_extracted)
		return 0;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NO_STREAMS)
		if (inode_unnamed_lte_resolved(inode))
			return 0;

	if ((extract_flags & WIMLIB_EXTRACT_FLAG_VERBOSE) &&
	     args->progress_func)
	{
		args->progress.extract.cur_path = dentry->full_path_utf8;
		args->progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DENTRY,
				    &args->progress);
	}

	len = strlen(args->target);
	char output_path[len + dentry->full_path_utf8_len + 1];
	memcpy(output_path, args->target, len);
	memcpy(output_path + len, dentry->full_path_utf8, dentry->full_path_utf8_len);
	output_path[len + dentry->full_path_utf8_len] = '\0';

	if (inode_is_symlink(inode))
		ret = extract_symlink(dentry, args, output_path);
	else if (inode_is_directory(inode))
		ret = extract_directory(output_path, false);
	else
		ret = extract_regular_file(dentry, args, output_path);
	if (ret == 0)
		dentry->is_extracted = 1;
	return ret;
}

/* Apply timestamp to extracted file */
static int apply_dentry_timestamps_normal(struct dentry *dentry, void *arg)
{
	struct apply_args *args = arg;
	size_t len = strlen(args->target);
	char output_path[len + dentry->full_path_utf8_len + 1];
	const struct inode *inode = dentry->d_inode;
	int ret;

	memcpy(output_path, args->target, len);
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

	num_streams = 0;
	list_for_each(cur, stream_list)
		num_streams++;
	array_size = num_streams * sizeof(array[0]);
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

static void calculate_bytes_to_extract(struct list_head *stream_list,
				       int extract_flags,
				       union wimlib_progress_info *progress)
{
	struct lookup_table_entry *lte;
	struct inode *inode;
	u64 total_bytes = 0;
	u64 num_streams = 0;

	/* For each stream to be extracted... */
	list_for_each_entry(lte, stream_list, staging_list) {
		if (extract_flags &
		    (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
		{
			/* In the symlink or hard link extraction mode, each
			 * stream will be extracted one time regardless of how
			 * many dentries share the stream. */
			wimlib_assert(!(extract_flags & WIMLIB_EXTRACT_FLAG_NTFS));
			if (!lte->extracted_file) {
				num_streams++;
				total_bytes += wim_resource_size(lte);
			}
		} else {
			list_for_each_entry(inode, &lte->inode_list,
					    lte_inode_list)
			{
				num_streams++;
				total_bytes += wim_resource_size(lte);
			}
		}
	}
	progress->extract.num_streams = num_streams;
	progress->extract.total_bytes = total_bytes;
	progress->extract.completed_bytes = 0;
}

static void maybe_add_stream_for_extraction(struct lookup_table_entry *lte,
					    struct list_head *stream_list)
{
	if (lte->out_refcnt == 0) {
		lte->out_refcnt = 1;
		INIT_LIST_HEAD(&lte->inode_list);
		list_add_tail(&lte->staging_list, stream_list);
	}
}

static void inode_find_streams_for_extraction(struct inode *inode,
					      struct list_head *stream_list,
					      int extract_flags)
{
	struct lookup_table_entry *lte;
	bool inode_added = false;

	lte = inode_unnamed_lte_resolved(inode);

	if (lte) {
		maybe_add_stream_for_extraction(lte, stream_list);
		list_add_tail(&inode->lte_inode_list, &lte->inode_list);
		inode_added = true;
	}
#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		for (unsigned i = 0; i < inode->num_ads; i++) {
			if (inode->ads_entries[i].stream_name_len != 0) {
				lte = inode_stream_lte_resolved(inode, i + 1);
				if (lte) {
					maybe_add_stream_for_extraction(lte,
									stream_list);
					if (!inode_added) {
						list_add_tail(&inode->lte_inode_list,
							      &lte->inode_list);
						inode_added = true;
					}
				}
			}
		}
	}
#endif
}

static void find_streams_for_extraction(struct hlist_head *inode_list,
					struct list_head *stream_list,
					struct lookup_table *lookup_table,
					int extract_flags)
{
	struct inode *inode;
	struct hlist_node *cur;
	struct dentry *dentry;

	for_lookup_table_entry(lookup_table, lte_zero_out_refcnt, NULL);
	INIT_LIST_HEAD(stream_list);
	hlist_for_each_entry(inode, cur, inode_list, hlist) {
		if (!inode->resolved)
			inode_resolve_ltes(inode, lookup_table);
		inode_for_each_dentry(dentry, inode)
			dentry->is_extracted = 0;
		inode_find_streams_for_extraction(inode, stream_list,
						  extract_flags);
	}
}

struct apply_operations {
	int (*apply_dentry)(struct dentry *dentry, void *arg);
	int (*apply_dentry_timestamps)(struct dentry *dentry, void *arg);
};

static const struct apply_operations normal_apply_operations = {
	.apply_dentry = apply_dentry_normal,
	.apply_dentry_timestamps = apply_dentry_timestamps_normal,
};

#ifdef WITH_NTFS_3G
static const struct apply_operations ntfs_apply_operations = {
	.apply_dentry = wim_apply_dentry_ntfs,
	.apply_dentry_timestamps = wim_apply_dentry_timestamps,
};
#endif

static int apply_stream_list(struct list_head *stream_list,
			     struct apply_args *args,
			     const struct apply_operations *ops,
			     wimlib_progress_func_t progress_func)
{
	uint64_t bytes_per_progress = args->progress.extract.total_bytes / 100;
	uint64_t next_progress = bytes_per_progress;
	struct lookup_table_entry *lte;
	struct inode *inode;
	struct dentry *dentry;
	int ret = 0;
	list_for_each_entry(lte, stream_list, staging_list) {
		list_for_each_entry(inode, &lte->inode_list, lte_inode_list) {
			inode_for_each_dentry(dentry, inode) {
				ret = ops->apply_dentry(dentry, args);
				if (ret != 0)
					goto out;
				if (args->progress.extract.completed_bytes >= next_progress) {
					progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_STREAMS,
						      &args->progress);
					next_progress += bytes_per_progress;
				}
			}
		}
	}
out:
	return ret;
}

static int extract_single_image(WIMStruct *w, int image,
				const char *target, int extract_flags,
				wimlib_progress_func_t progress_func)
{
	int ret;
	struct list_head stream_list;
	struct hlist_head *inode_list;

	struct apply_args args;
	const struct apply_operations *ops;

	args.w                    = w;
	args.target               = target;
	args.extract_flags        = extract_flags;
	args.num_lutimes_warnings = 0;
	args.target               = target;
	args.stream_list          = &stream_list;
	args.progress_func	  = progress_func;

	if (progress_func) {
		args.progress.extract.image      = image;
		args.progress.extract.image_name = wimlib_get_image_name(w, image);
		args.progress.extract.target     = target;
	}

#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		args.vol = ntfs_mount(target, 0);
		if (!args.vol) {
			ERROR_WITH_ERRNO("Failed to mount NTFS volume `%s'", target);
			return WIMLIB_ERR_NTFS_3G;
		}
	}
#endif

#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS)
		ops = &ntfs_apply_operations;
	else
#endif
		ops = &normal_apply_operations;

	ret = select_wim_image(w, image);
	if (ret != 0)
		goto out;

	inode_list = &w->image_metadata[image - 1].inode_list;
	find_streams_for_extraction(inode_list,
				    &stream_list,
				    w->lookup_table,
				    extract_flags);

	calculate_bytes_to_extract(&stream_list, extract_flags,
				   &args.progress);

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_BEGIN,
			      &args.progress);
	}

	if (extract_flags & WIMLIB_EXTRACT_FLAG_SEQUENTIAL) {
		ret = sort_stream_list_by_wim_position(&stream_list);
		if (ret != 0) {
			WARNING("Falling back to non-sequential extraction");
			extract_flags &= ~WIMLIB_EXTRACT_FLAG_SEQUENTIAL;
		}
	}

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_BEGIN,
			      &args.progress);
	}


	args.extract_flags |= WIMLIB_EXTRACT_FLAG_NO_STREAMS;
	ret = for_dentry_in_tree(wim_root_dentry(w), ops->apply_dentry, &args);
	args.extract_flags &= ~WIMLIB_EXTRACT_FLAG_NO_STREAMS;
	if (ret != 0)
		goto out;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_DIR_STRUCTURE_END,
			      &args.progress);
	}

	ret = apply_stream_list(&stream_list, &args, ops, progress_func);
	if (ret != 0)
		goto out;

	if (progress_func)
		progress_func(WIMLIB_PROGRESS_MSG_APPLY_TIMESTAMPS, NULL);

	ret = for_dentry_in_tree_depth(wim_root_dentry(w),
				       ops->apply_dentry_timestamps, &args);
	if (ret != 0)
		goto out;

	if (progress_func) {
		progress_func(WIMLIB_PROGRESS_MSG_EXTRACT_IMAGE_END,
			      &args.progress);
	}
out:
#ifdef WITH_NTFS_3G
	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
		if (ntfs_umount(args.vol, FALSE) != 0) {
			ERROR_WITH_ERRNO("Failed to unmount NTFS volume `%s'", args.target);
			if (ret == 0)
				ret = WIMLIB_ERR_NTFS_3G;
		}
	}
#endif
	return ret;
}


/* Extracts all images from the WIM to @output_dir, with the images placed in
 * subdirectories named by their image names. */
static int extract_all_images(WIMStruct *w, const char *target,
			      int extract_flags,
			      wimlib_progress_func_t progress_func)
{
	size_t image_name_max_len = max(xml_get_max_image_name_len(w), 20);
	size_t output_path_len = strlen(target);
	char buf[output_path_len + 1 + image_name_max_len + 1];
	int ret;
	int image;
	const char *image_name;

	ret = extract_directory(target, true);
	if (ret != 0)
		return ret;

	memcpy(buf, target, output_path_len);
	buf[output_path_len] = '/';
	for (image = 1; image <= w->hdr.image_count; image++) {
		image_name = wimlib_get_image_name(w, image);
		if (image_name && *image_name) {
			strcpy(buf + output_path_len + 1, image_name);
		} else {
			/* Image name is empty. Use image number instead */
			sprintf(buf + output_path_len + 1, "%d", image);
		}
		ret = extract_single_image(w, image, buf, extract_flags,
					   progress_func);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/* Extracts a single image or all images from a WIM file. */
WIMLIBAPI int wimlib_extract_image(WIMStruct *w, int image,
				   const char *target,
				   int extract_flags,
				   WIMStruct **additional_swms,
				   unsigned num_additional_swms,
				   wimlib_progress_func_t progress_func)
{
	struct lookup_table *joined_tab, *w_tab_save;
	int ret;

	if (!w || !target)
		return WIMLIB_ERR_INVALID_PARAM;

	extract_flags &= WIMLIB_EXTRACT_MASK_PUBLIC;

	if ((extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
			== (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))
		return WIMLIB_ERR_INVALID_PARAM;

	if (extract_flags & WIMLIB_EXTRACT_FLAG_NTFS) {
#ifdef WITH_NTFS_3G
		if ((extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK | WIMLIB_EXTRACT_FLAG_HARDLINK))) {
			ERROR("Cannot specify symlink or hardlink flags when applying ");
			ERROR("directly to a NTFS volume");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (image == WIMLIB_ALL_IMAGES) {
			ERROR("Can only apply a single image when applying "
			      "directly to a NTFS volume");
			return WIMLIB_ERR_INVALID_PARAM;
		}
#else
		ERROR("wimlib was compiled without support for NTFS-3g, so");
		ERROR("we cannot apply a WIM image directly to a NTFS volume");
		return WIMLIB_ERR_UNSUPPORTED;
#endif
	}

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

	if (image == WIMLIB_ALL_IMAGES) {
		extract_flags |= WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;
		ret = extract_all_images(w, target, extract_flags,
					 progress_func);
	} else {
		extract_flags &= ~WIMLIB_EXTRACT_FLAG_MULTI_IMAGE;
		ret = extract_single_image(w, image, target, extract_flags,
					   progress_func);
	}

	if (extract_flags & (WIMLIB_EXTRACT_FLAG_SYMLINK |
			     WIMLIB_EXTRACT_FLAG_HARDLINK))
	{
		for_lookup_table_entry(w->lookup_table,
				       lte_free_extracted_file,
				       NULL);
	}

	if (num_additional_swms) {
		free_lookup_table(w->lookup_table);
		w->lookup_table = w_tab_save;
	}
	return ret;
}
