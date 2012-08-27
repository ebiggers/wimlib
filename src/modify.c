/*
 * modify.c
 *
 * Support for modifying WIM files with image-level operations (delete an image,
 * add an image, export an imagex from one WIM to another.)  There is nothing
 * here that lets you change individual files in the WIM; for that you will need
 * to look at the filesystem implementation in mount.c.
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
#include "util.h"
#include "sha1.h"
#include "dentry.h"
#include "xml.h"
#include "lookup_table.h"
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <fnmatch.h>
#include <ctype.h>
#include <unistd.h>

/** Private flag: Used to mark that we currently adding the root directory of
 * the WIM. */
#define WIMLIB_ADD_IMAGE_FLAG_ROOT 0x80000000

void destroy_image_metadata(struct image_metadata *imd,struct lookup_table *lt)
{
	free_dentry_tree(imd->root_dentry, lt);
	free_security_data(imd->security_data);
	free_link_group_table(imd->lgt);

	/* Get rid of the lookup table entry for this image's metadata resource
	 * */
	if (lt)
		lookup_table_remove(lt, imd->metadata_lte);
}

/* 
 * Recursively builds a dentry tree from a directory tree on disk, outside the
 * WIM file.
 *
 * @root:  A dentry that has already been created for the root of the dentry
 * 	   tree.
 * @root_disk_path:  The path to the root of the tree on disk. 
 * @lookup_table: The lookup table for the WIM file.  For each file added to the
 * 		dentry tree being built, an entry is added to the lookup table, 
 * 		unless an identical file is already in the lookup table.  These
 * 		lookup table entries that are added point to the file on disk.
 *
 * @return:	0 on success, nonzero on failure.  It is a failure if any of
 *		the files cannot be `stat'ed, or if any of the needed
 *		directories cannot be opened or read.  Failure to add the files
 *		to the WIM may still occur later when trying to actually read 
 *		the regular files in the tree into the WIM as file resources.
 */
static int build_dentry_tree(struct dentry **root_ret, const char *root_disk_path,
			     struct lookup_table *lookup_table,
			     struct wim_security_data *sd,
			     const struct capture_config *config,
			     int add_flags,
			     void *extra_arg)
{
	struct stat root_stbuf;
	int ret = 0;
	int (*stat_fn)(const char *restrict, struct stat *restrict);
	struct dentry *root;

	if (exclude_path(root_disk_path, config, true)) {
		if (add_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
			printf("Excluding file `%s' from capture\n",
			       root_disk_path);
		*root_ret = NULL;
		return 0;
	}


	if (add_flags & WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE)
		stat_fn = stat;
	else
		stat_fn = lstat;

	if (add_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
		printf("Scanning `%s'\n", root_disk_path);


	ret = (*stat_fn)(root_disk_path, &root_stbuf);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to stat `%s'", root_disk_path);
		return WIMLIB_ERR_STAT;
	}

	if ((add_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) && 
	      !S_ISDIR(root_stbuf.st_mode)) {
		ERROR("`%s' is not a directory", root_disk_path);
		return WIMLIB_ERR_NOTDIR;
	}
	if (!S_ISREG(root_stbuf.st_mode) && !S_ISDIR(root_stbuf.st_mode)
	    && !S_ISLNK(root_stbuf.st_mode)) {
		ERROR("`%s' is not a regular file, directory, or symbolic link.");
		return WIMLIB_ERR_SPECIAL_FILE;
	}

	root = new_dentry(path_basename(root_disk_path));
	if (!root)
		return WIMLIB_ERR_NOMEM;

	stbuf_to_dentry(&root_stbuf, root);
	add_flags &= ~WIMLIB_ADD_IMAGE_FLAG_ROOT;
	root->resolved = true;

	if (dentry_is_directory(root)) {
		/* Open the directory on disk */
		DIR *dir;
		struct dirent *p;
		struct dentry *child;

		dir = opendir(root_disk_path);
		if (!dir) {
			ERROR_WITH_ERRNO("Failed to open the directory `%s'",
					 root_disk_path);
			return WIMLIB_ERR_OPEN;
		}

		/* Buffer for names of files in directory. */
		size_t len = strlen(root_disk_path);
		char name[len + 1 + FILENAME_MAX + 1];
		memcpy(name, root_disk_path, len);
		name[len] = '/';

		/* Create a dentry for each entry in the directory on disk, and recurse
		 * to any subdirectories. */
		while ((p = readdir(dir)) != NULL) {
			if (p->d_name[0] == '.' && (p->d_name[1] == '\0'
			      || (p->d_name[1] == '.' && p->d_name[2] == '\0')))
					continue;
			strcpy(name + len + 1, p->d_name);
			ret = build_dentry_tree(&child, name, lookup_table,
						sd, config,
						add_flags, extra_arg);
			if (ret != 0)
				break;
			if (child)
				link_dentry(child, root);
		}
		closedir(dir);
	} else if (dentry_is_symlink(root)) {
		/* Archiving a symbolic link */
		size_t symlink_buf_len;
		char deref_name_buf[4096];
		ssize_t deref_name_len;
		
		deref_name_len = readlink(root_disk_path, deref_name_buf,
					  sizeof(deref_name_buf) - 1);
		if (deref_name_len == -1) {
			ERROR_WITH_ERRNO("Failed to read target of "
					 "symbolic link `%s'", root_disk_path);
			return WIMLIB_ERR_READLINK;
		}
		deref_name_buf[deref_name_len] = '\0';
		DEBUG("Read symlink `%s'", deref_name_buf);
		ret = dentry_set_symlink(root, deref_name_buf,
					 lookup_table, NULL);
	} else {
		/* Regular file */
		struct lookup_table_entry *lte;
		u8 hash[SHA1_HASH_SIZE];

		/* For each regular file, we must check to see if the file is in
		 * the lookup table already; if it is, we increment its refcnt;
		 * otherwise, we create a new lookup table entry and insert it.
		 * */
		ret = sha1sum(root_disk_path, hash);
		if (ret != 0)
			return ret;

		lte = __lookup_resource(lookup_table, hash);
		if (lte) {
			lte->refcnt++;
			DEBUG("Add lte reference %u for `%s'", lte->refcnt,
			      root_disk_path);
		} else {
			char *file_on_disk = STRDUP(root_disk_path);
			if (!file_on_disk) {
				ERROR("Failed to allocate memory for file path");
				return WIMLIB_ERR_NOMEM;
			}
			lte = new_lookup_table_entry();
			if (!lte) {
				FREE(file_on_disk);
				return WIMLIB_ERR_NOMEM;
			}
			lte->file_on_disk = file_on_disk;
			lte->resource_location = RESOURCE_IN_FILE_ON_DISK;
			lte->resource_entry.original_size = root_stbuf.st_size;
			lte->resource_entry.size = root_stbuf.st_size;
			copy_hash(lte->hash, hash);
			lookup_table_insert(lookup_table, lte);
		}
		root->lte = lte;
	}
	*root_ret = root;
	return ret;
}

struct wim_pair {
	WIMStruct *src_wim;
	WIMStruct *dest_wim;
};

/* 
 * This function takes in a dentry that was previously located only in image(s)
 * in @src_wim, but now is being added to @dest_wim. If there is in fact already a
 * lookup table entry for this file in the lookup table of the destination WIM
 * file, we simply increment its reference count.  Otherwise, a new lookup table
 * entry is created that references the location of the file resource in the
 * source WIM file through the other_wim_fp field of the lookup table entry.
 */
static int add_lte_to_dest_wim(struct dentry *dentry, void *arg)
{
	WIMStruct *src_wim, *dest_wim;

	src_wim = ((struct wim_pair*)arg)->src_wim;
	dest_wim = ((struct wim_pair*)arg)->dest_wim;

	wimlib_assert(!dentry->resolved);

	for (unsigned i = 0; i < (unsigned)dentry->num_ads + 1; i++) {
		struct lookup_table_entry *src_lte, *dest_lte;
		src_lte = dentry_stream_lte_unresolved(dentry, i,
						       src_wim->lookup_table);
		if (!src_lte)
			continue;
		dest_lte = dentry_stream_lte_unresolved(dentry, i,
							dest_wim->lookup_table);
		if (dest_lte) {
			dest_lte->refcnt++;
		} else {
			dest_lte = new_lookup_table_entry();
			if (!dest_lte)
				return WIMLIB_ERR_NOMEM;
			dest_lte->resource_location = RESOURCE_IN_WIM;
			dest_lte->wim = src_wim;
			memcpy(&dest_lte->resource_entry, 
			       &src_lte->resource_entry, 
			       sizeof(struct resource_entry));
			copy_hash(dest_lte->hash,
				  dentry_stream_hash_unresolved(dentry, i));
			lookup_table_insert(dest_wim->lookup_table, dest_lte);
		}
	}
	return 0;
}

/*
 * Adds an image (given by its dentry tree) to the image metadata array of a WIM
 * file, adds an entry to the lookup table for the image metadata, updates the
 * image count in the header, and selects the new image. 
 *
 * Does not update the XML data.
 *
 * @w:		  The WIMStruct for the WIM file.
 * @root_dentry:  The root of the directory tree for the image.
 */
static int add_new_dentry_tree(WIMStruct *w, struct dentry *root_dentry,
			       struct wim_security_data *sd)
{
	struct lookup_table_entry *metadata_lte;
	struct image_metadata *imd;
	struct image_metadata *new_imd;
	struct link_group_table *lgt;

	DEBUG("Reallocating image metadata array for image_count = %u",
	      w->hdr.image_count + 1);
	imd = CALLOC((w->hdr.image_count + 1), sizeof(struct image_metadata));

	if (!imd) {
		ERROR("Failed to allocate memory for new image metadata array");
		return WIMLIB_ERR_NOMEM;
	}

	memcpy(imd, w->image_metadata, 
	       w->hdr.image_count * sizeof(struct image_metadata));
	
	metadata_lte = new_lookup_table_entry();
	if (!metadata_lte)
		goto out_free_imd;

	lgt = new_link_group_table(9001);
	if (!lgt)
		goto out_free_security_data;

	metadata_lte->resource_entry.flags = WIM_RESHDR_FLAG_METADATA;
	random_hash(metadata_lte->hash);
	lookup_table_insert(w->lookup_table, metadata_lte);

	new_imd = &imd[w->hdr.image_count];

	new_imd->root_dentry	= root_dentry;
	new_imd->metadata_lte	= metadata_lte;
	new_imd->security_data  = sd;
	new_imd->lgt		= lgt;
	new_imd->modified	= true;

	FREE(w->image_metadata);
	w->image_metadata	= imd;
	w->hdr.image_count++;

	/* Change the current image to the new one. */
	return wimlib_select_image(w, w->hdr.image_count);
out_free_security_data:
	FREE(sd);
out_free_metadata_lte:
	FREE(metadata_lte);
out_free_imd:
	FREE(imd);
	return WIMLIB_ERR_NOMEM;

}

/*
 * Copies an image, or all the images, from a WIM file, into another WIM file.
 */
WIMLIBAPI int wimlib_export_image(WIMStruct *src_wim, 
				  int src_image, 
				  WIMStruct *dest_wim, 
				  const char *dest_name, 
				  const char *dest_description, 
				  int flags)
{
	int i;
	int ret;
	struct dentry *root;
	struct wim_pair wims;
	struct wim_security_data *sd;

	if (src_image == WIM_ALL_IMAGES) {
		if (src_wim->hdr.image_count > 1) {

			/* multi-image export. */

			if ((flags & WIMLIB_EXPORT_FLAG_BOOT) && 
			      (src_wim->hdr.boot_idx == 0))
			{
				/* Specifying the boot flag on a multi-image
				 * source WIM makes the boot index default to
				 * the bootable image in the source WIM.  It is
				 * an error if there is no such bootable image.
				 * */
				ERROR("Cannot specify `boot' flag when "
				      "exporting multiple images from a WIM "
				      "with no bootable images");
				return WIMLIB_ERR_INVALID_PARAM;
			}
			if (dest_name || dest_description) {
				ERROR("Image name or image description was "
				      "specified, but we are exporting "
				      "multiple images");
				return WIMLIB_ERR_INVALID_PARAM;
			}
			for (i = 1; i <= src_wim->hdr.image_count; i++) {
				int export_flags = flags;

				if (i != src_wim->hdr.boot_idx)
					export_flags &= ~WIMLIB_EXPORT_FLAG_BOOT;

				ret = wimlib_export_image(src_wim, i, dest_wim, 
							  NULL,
							  dest_description,
							  export_flags);
				if (ret != 0)
					return ret;
			}
			return 0;
		} else {
			src_image = 1; 
		}
	}

	ret = wimlib_select_image(src_wim, src_image);
	if (ret != 0) {
		ERROR("Could not select image %d from the WIM `%s' "
		      "to export it", src_image, src_wim->filename);
		return ret;
	}

	if (!dest_name) {
		dest_name = wimlib_get_image_name(src_wim, src_image);
		DEBUG("Using name `%s' for source image %d",
		      dest_name, src_image);
	}

	DEBUG("Exporting image %d from `%s'", src_image, src_wim->filename);

	if (wimlib_image_name_in_use(dest_wim, dest_name)) {
		ERROR("There is already an image named `%s' in the "
		      "destination WIM", dest_name);
		return WIMLIB_ERR_IMAGE_NAME_COLLISION;
	}


	/* Cleaning up here on failure would be hard.  For example, we could
	 * fail to allocate memory in add_lte_to_dest_wim(),
	 * leaving the lookup table entries in the destination WIM in an
	 * inconsistent state.  Until these issues can be resolved,
	 * wimlib_export_image() is documented as leaving dest_wim is an
	 * indeterminate state.  */
	root = wim_root_dentry(src_wim);
	sd = wim_security_data(src_wim);
	for_dentry_in_tree(root, increment_dentry_refcnt, NULL);
	wims.src_wim = src_wim;
	wims.dest_wim = dest_wim;
	ret = for_dentry_in_tree(root, add_lte_to_dest_wim, &wims);
	if (ret != 0)
		return ret;
	ret = add_new_dentry_tree(dest_wim, root, sd);
	if (ret != 0)
		return ret;
	sd->refcnt++;

	if (flags & WIMLIB_EXPORT_FLAG_BOOT) {
		DEBUG("Setting boot_idx to %d", dest_wim->hdr.image_count);
		dest_wim->hdr.boot_idx = dest_wim->hdr.image_count;
	}

	return xml_export_image(src_wim->wim_info, src_image, &dest_wim->wim_info,
				dest_name, dest_description);
}

/* 
 * Deletes an image from the WIM. 
 */
WIMLIBAPI int wimlib_delete_image(WIMStruct *w, int image)
{
	int num_images;
	int i;
	int ret;

	if (image == WIM_ALL_IMAGES) {
		num_images = w->hdr.image_count;
		for (i = 1; i <= num_images; i++) {
			/* Always delete the first image, since by the end
			 * there won't be any more than that!  */
			ret = wimlib_delete_image(w, 1);
			if (ret != 0)
				return ret;
		}
		return 0;
	}

	DEBUG("Deleting image %d", image);

	/* Even if the dentry tree is not allocated, we must select it (and
	 * therefore allocate it) so that we can decrement the reference counts
	 * in the lookup table.  */
	ret = wimlib_select_image(w, image);
	if (ret != 0)
		return ret;

	/* Free the dentry tree, any lookup table entries that have their
	 * refcnt decremented to 0, and the security data. */
	destroy_image_metadata(wim_get_current_image_metadata(w),
			       w->lookup_table);

	/* Get rid of the empty slot in the image metadata array. */
	memmove(&w->image_metadata[image - 1], &w->image_metadata[image],
		(w->hdr.image_count - image) * sizeof(struct image_metadata));

	/* Decrement the image count. */
	if (--w->hdr.image_count == 0) {
		FREE(w->image_metadata);
		w->image_metadata = NULL;
	}

	/* Fix the boot index. */
	if (w->hdr.boot_idx == image)
		w->hdr.boot_idx = 0;
	else if (w->hdr.boot_idx > image)
		w->hdr.boot_idx--;

	w->current_image = WIM_NO_IMAGE;

	/* Remove the image from the XML information. */
	xml_delete_image(&w->wim_info, image);
	return 0;
}

enum pattern_type {
	NONE = 0,
	EXCLUSION_LIST,
	EXCLUSION_EXCEPTION,
	COMPRESSION_EXCLUSION_LIST,
	ALIGNMENT_LIST,
};

static const char *default_config =
"[ExclusionList]\n"
"\\$ntfs.log\n"
"\\hiberfil.sys\n"
"\\pagefile.sys\n"
"\"\\System Volume Information\"\n"
"\\RECYCLER\n"
"\\Windows\\CSC\n"
"\n"
"[CompressionExclusionList]\n"
"*.mp3\n"
"*.zip\n"
"*.cab\n"
"\\WINDOWS\\inf\\*.pnf\n";

static void destroy_pattern_list(struct pattern_list *list)
{
	FREE(list->pats);
}

static void destroy_capture_config(struct capture_config *config)
{
	destroy_pattern_list(&config->exclusion_list);
	destroy_pattern_list(&config->exclusion_exception);
	destroy_pattern_list(&config->compression_exclusion_list);
	destroy_pattern_list(&config->alignment_list);
	FREE(config->config_str);
	FREE(config->prefix);
	memset(config, 0, sizeof(*config));
}

static int pattern_list_add_pattern(struct pattern_list *list,
				    const char *pattern)
{
	const char **pats;
	if (list->num_pats >= list->num_allocated_pats) {
		pats = REALLOC(list->pats,
			       sizeof(list->pats[0]) * (list->num_allocated_pats + 8));
		if (!pats)
			return WIMLIB_ERR_NOMEM;
		list->num_allocated_pats += 8;
		list->pats = pats;
	}
	list->pats[list->num_pats++] = pattern;
	return 0;
}

static int init_capture_config(const char *_config_str, size_t config_len,
			       const char *_prefix, struct capture_config *config)
{
	char *config_str;
	char *prefix;
	char *p;
	char *eol;
	char *next_p;
	size_t next_bytes_remaining;
	size_t bytes_remaining;
	enum pattern_type type = NONE;
	int ret;
	unsigned long line_no = 0;

	DEBUG("config_len = %zu", config_len);
	bytes_remaining = config_len;
	memset(config, 0, sizeof(*config));
	config_str = MALLOC(config_len);
	if (!config_str) {
		ERROR("Could not duplicate capture config string");
		return WIMLIB_ERR_NOMEM;
	}
	prefix = STRDUP(_prefix);
	if (!prefix) {
		FREE(config_str);
		return WIMLIB_ERR_NOMEM;
	}
	
	memcpy(config_str, _config_str, config_len);
	next_p = config_str;
	config->config_str = config_str;
	config->prefix = prefix;
	config->prefix_len = strlen(prefix);
	while (bytes_remaining) {
		line_no++;
		p = next_p;
		eol = memchr(p, '\n', bytes_remaining);
		if (!eol) {
			ERROR("Expected end-of-line in capture config file on "
			      "line %lu", line_no);
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
			goto out_destroy;
		}
		
		next_p = eol + 1;
		bytes_remaining -= (eol - p) + 1;
		if (eol == p)
			continue;

		if (*(eol - 1) == '\r')
			eol--;
		*eol = '\0';

		/* Translate backslash to forward slash */
		for (char *pp = p; pp != eol; pp++)
			if (*pp == '\\')
				*pp = '/';

		/* Remove drive letter */
		if (eol - p > 2 && isalpha(*p) && *(p + 1) == ':')
			p += 2;

		if (strcmp(p, "[ExclusionList]") == 0)
			type = EXCLUSION_LIST;
		else if (strcmp(p, "[ExclusionException]") == 0)
			type = EXCLUSION_EXCEPTION;
		else if (strcmp(p, "[CompressionExclusionList]") == 0)
			type = COMPRESSION_EXCLUSION_LIST;
		else if (strcmp(p, "[AlignmentList]") == 0)
			type = ALIGNMENT_LIST;
		else switch (type) {
		case EXCLUSION_LIST:
			DEBUG("Adding pattern \"%s\" to exclusion list", p);
			ret = pattern_list_add_pattern(&config->exclusion_list, p);
			break;
		case EXCLUSION_EXCEPTION:
			DEBUG("Adding pattern \"%s\" to exclusion exception list", p);
			ret = pattern_list_add_pattern(&config->exclusion_exception, p);
			break;
		case COMPRESSION_EXCLUSION_LIST:
			DEBUG("Adding pattern \"%s\" to compression exclusion list", p);
			ret = pattern_list_add_pattern(&config->compression_exclusion_list, p);
			break;
		case ALIGNMENT_LIST:
			DEBUG("Adding pattern \"%s\" to alignment list", p);
			ret = pattern_list_add_pattern(&config->alignment_list, p);
			break;
		default:
			ERROR("Line %lu of capture configuration is not "
			      "in a block (such as [ExclusionList])",
			      line_no);
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
			goto out_destroy;
		}
		if (ret != 0)
			goto out_destroy;
	}
	return 0;
out_destroy:
	destroy_capture_config(config);
	return ret;
}

static bool match_pattern(const char *path, const char *path_basename,
			  const struct pattern_list *list)
{
	for (size_t i = 0; i < list->num_pats; i++) {
		const char *pat = list->pats[i];
		const char *string;
		if (pat[0] == '/')
			/* Absolute path from root of capture */
			string = path;
		else {
			if (strchr(pat, '/'))
				/* Relative path from root of capture */
				string = path + 1;
			else
				/* A file name pattern */
				string = path_basename;
		}
		if (fnmatch(pat, string, FNM_PATHNAME
			#ifdef FNM_CASEFOLD
					| FNM_CASEFOLD
			#endif
			) == 0)
		{
			DEBUG("`%s' matches the pattern \"%s\"",
			      string, pat);
			return true;
		}
	}
	return false;
}

static void print_pattern_list(const struct pattern_list *list)
{
	for (size_t i = 0; i < list->num_pats; i++)
		printf("    %s\n", list->pats[i]);
}

static void print_capture_config(const struct capture_config *config)
{
	if (config->exclusion_list.num_pats) {
		puts("Files or folders excluded from image capture:");
		print_pattern_list(&config->exclusion_list);
		putchar('\n');
	}
}

bool exclude_path(const char *path, const struct capture_config *config,
		  bool exclude_prefix)
{
	const char *basename = path_basename(path);
	if (exclude_prefix) {
		wimlib_assert(strlen(path) >= config->prefix_len);
		if (memcmp(config->prefix, path, config->prefix_len) == 0
		     && path[config->prefix_len] == '/')
			path += config->prefix_len;
	}
	return match_pattern(path, basename, &config->exclusion_list) && 
		!match_pattern(path, basename, &config->exclusion_exception);

}



int do_add_image(WIMStruct *w, const char *dir, const char *name,
		 const char *config_str, size_t config_len,
		 int flags,
		 int (*capture_tree)(struct dentry **, const char *,
			 	     struct lookup_table *, 
				     struct wim_security_data *,
				     const struct capture_config *,
				     int, void *),
		 void *extra_arg)
{
	struct dentry *root_dentry = NULL;
	struct image_metadata *imd;
	struct wim_security_data *sd;
	struct capture_config config;
	int ret;

	DEBUG("Adding dentry tree from dir `%s'.", dir);

	if (!name || !*name) {
		ERROR("Must specify a non-empty string for the image name");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (!dir) {
		ERROR("Must specify the name of a directory");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (wimlib_image_name_in_use(w, name)) {
		ERROR("There is already an image named \"%s\" in `%s'",
		      name, w->filename);
		return WIMLIB_ERR_IMAGE_NAME_COLLISION;
	}

	DEBUG("Initializing capture configuration");
	if (!config_str) {
		DEBUG("Using default capture configuration");
		config_str = default_config;
		config_len = strlen(default_config);
	}
	ret = init_capture_config(config_str, config_len, dir, &config);
	if (ret != 0)
		return ret;
	print_capture_config(&config);

	DEBUG("Allocating security data");

	sd = CALLOC(1, sizeof(struct wim_security_data));
	if (!sd)
		goto out_destroy_config;
	sd->total_length = 8;
	sd->refcnt = 1;

	DEBUG("Building dentry tree.");
	ret = (*capture_tree)(&root_dentry, dir, w->lookup_table, sd,
			      &config, flags | WIMLIB_ADD_IMAGE_FLAG_ROOT,
			      extra_arg);
	destroy_capture_config(&config);

	if (ret != 0) {
		ERROR("Failed to build dentry tree for `%s'", dir);
		goto out_free_dentry_tree;
	}

	DEBUG("Calculating full paths of dentries.");
	ret = for_dentry_in_tree(root_dentry, calculate_dentry_full_path, NULL);
	if (ret != 0)
		goto out_free_dentry_tree;

	ret = add_new_dentry_tree(w, root_dentry, sd);
	if (ret != 0)
		goto out_free_dentry_tree;

	DEBUG("Inserting dentries into hard link group table");
	ret = for_dentry_in_tree(root_dentry, link_group_table_insert, 
				 w->image_metadata[w->hdr.image_count - 1].lgt);
	if (ret != 0)
		goto out_destroy_imd;
	DEBUG("Assigning hard link groups");
	assign_link_groups(w->image_metadata[w->hdr.image_count - 1].lgt);

	if (flags & WIMLIB_ADD_IMAGE_FLAG_BOOT)
		wimlib_set_boot_idx(w, w->hdr.image_count);

	ret = xml_add_image(w, root_dentry, name);
	if (ret != 0)
		goto out_destroy_imd;

	return 0;
out_destroy_imd:
	destroy_image_metadata(&w->image_metadata[w->hdr.image_count - 1],
			       w->lookup_table);
	w->hdr.image_count--;
	return ret;
out_free_dentry_tree:
	free_dentry_tree(root_dentry, w->lookup_table);
out_free_sd:
	free_security_data(sd);
out_destroy_config:
	destroy_capture_config(&config);
	return ret;
}

/*
 * Adds an image to a WIM file from a directory tree on disk.
 */
WIMLIBAPI int wimlib_add_image(WIMStruct *w, const char *dir, 
			       const char *name, const char *config_str,
			       size_t config_len, int flags)
{
	return do_add_image(w, dir, name, config_str, config_len, flags,
			    build_dentry_tree, NULL);
}
