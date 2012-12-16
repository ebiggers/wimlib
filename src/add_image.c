/*
 * add_image.c
 */

/*
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
#include "dentry.h"
#include "timestamp.h"
#include "lookup_table.h"
#include "xml.h"
#include <string.h>
#include <fnmatch.h>
#include <ctype.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>

/** Private flag: Used to mark that we currently adding the root directory of
 * the WIM image. */
#define WIMLIB_ADD_IMAGE_FLAG_ROOT 0x80000000

/*
 * Adds an image (given by its dentry tree) to the image metadata array of a WIM
 * file, adds an entry to the lookup table for the image metadata, updates the
 * image count in the header, and selects the new image.
 *
 * Does not update the XML data.
 *
 * On failure, WIMLIB_ERR_NOMEM is returned and no changes are made.  Otherwise,
 * 0 is returned and the image metadata array of @w is modified.
 *
 * @w:		  The WIMStruct for the WIM file.
 * @root_dentry:  The root of the directory tree for the image.
 * @sd:		  The security data for the image.
 */
int add_new_dentry_tree(WIMStruct *w, struct dentry *root_dentry,
			       struct wim_security_data *sd)
{
	struct lookup_table_entry *metadata_lte;
	struct image_metadata *imd;
	struct image_metadata *new_imd;
	int ret;

	wimlib_assert(root_dentry != NULL);

	DEBUG("Reallocating image metadata array for image_count = %u",
	      w->hdr.image_count + 1);
	imd = CALLOC((w->hdr.image_count + 1), sizeof(struct image_metadata));

	if (!imd) {
		ERROR("Failed to allocate memory for new image metadata array");
		goto err;
	}

	memcpy(imd, w->image_metadata,
	       w->hdr.image_count * sizeof(struct image_metadata));

	metadata_lte = new_lookup_table_entry();
	if (!metadata_lte)
		goto err_free_imd;

	metadata_lte->resource_entry.flags = WIM_RESHDR_FLAG_METADATA;
	random_hash(metadata_lte->hash);
	lookup_table_insert(w->lookup_table, metadata_lte);

	new_imd = &imd[w->hdr.image_count];

	new_imd->root_dentry	= root_dentry;
	new_imd->metadata_lte	= metadata_lte;
	new_imd->security_data  = sd;
	new_imd->modified	= true;

	FREE(w->image_metadata);
	w->image_metadata	= imd;
	w->hdr.image_count++;

	/* Change the current image to the new one.  There should not be any
	 * ways for this to fail, since the image is valid and the dentry tree
	 * is already in memory. */
	ret = select_wim_image(w, w->hdr.image_count);
	wimlib_assert(ret == 0);
	return ret;
err_free_imd:
	FREE(imd);
err:
	return WIMLIB_ERR_NOMEM;

}


/*
 * Recursively builds a dentry tree from a directory tree on disk, outside the
 * WIM file.
 *
 * @root_ret:   Place to return a pointer to the root of the dentry tree.  Only
 *		modified if successful.  NULL if the file or directory was
 *		excluded from capture.
 *
 * @root_disk_path:  The path to the root of the directory tree on disk.
 *
 * @lookup_table: The lookup table for the WIM file.  For each file added to the
 * 		dentry tree being built, an entry is added to the lookup table,
 * 		unless an identical stream is already in the lookup table.
 * 		These lookup table entries that are added point to the path of
 * 		the file on disk.
 *
 * @sd:		Ignored.  (Security data only captured in NTFS mode.)
 *
 * @capture_config:
 * 		Configuration for files to be excluded from capture.
 *
 * @add_flags:  Bitwise or of WIMLIB_ADD_IMAGE_FLAG_*
 *
 * @extra_arg:	Ignored. (Only used in NTFS mode.)
 *
 * @return:	0 on success, nonzero on failure.  It is a failure if any of
 *		the files cannot be `stat'ed, or if any of the needed
 *		directories cannot be opened or read.  Failure to add the files
 *		to the WIM may still occur later when trying to actually read
 *		the on-disk files during a call to wimlib_write() or
 *		wimlib_overwrite().
 */
static int build_dentry_tree(struct dentry **root_ret,
			     const char *root_disk_path,
			     struct lookup_table *lookup_table,
			     struct wim_security_data *sd,
			     const struct capture_config *config,
			     int add_image_flags,
			     wimlib_progress_func_t progress_func,
			     void *extra_arg)
{
	struct stat root_stbuf;
	int ret = 0;
	int (*stat_fn)(const char *restrict, struct stat *restrict);
	struct dentry *root;
	const char *filename;
	struct inode *inode;

	if (exclude_path(root_disk_path, config, true)) {
		if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) {
			ERROR("Cannot exclude the root directory from capture");
			return WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
		}
		if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
		    && progress_func)
		{
			union wimlib_progress_info info;
			info.scan.cur_path = root_disk_path;
			info.scan.excluded = true;
			progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
		}
		*root_ret = NULL;
		return 0;
	}

	if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
	    && progress_func)
	{
		union wimlib_progress_info info;
		info.scan.cur_path = root_disk_path;
		info.scan.excluded = false;
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
	}

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE)
		stat_fn = stat;
	else
		stat_fn = lstat;

	ret = (*stat_fn)(root_disk_path, &root_stbuf);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to stat `%s'", root_disk_path);
		return WIMLIB_ERR_STAT;
	}

	if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) &&
	      !S_ISDIR(root_stbuf.st_mode)) {
		ERROR("`%s' is not a directory", root_disk_path);
		return WIMLIB_ERR_NOTDIR;
	}
	if (!S_ISREG(root_stbuf.st_mode) && !S_ISDIR(root_stbuf.st_mode)
	    && !S_ISLNK(root_stbuf.st_mode)) {
		ERROR("`%s' is not a regular file, directory, or symbolic link.",
		      root_disk_path);
		return WIMLIB_ERR_SPECIAL_FILE;
	}

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT)
		filename = "";
	else
		filename = path_basename(root_disk_path);

	root = new_dentry_with_timeless_inode(filename);
	if (!root)
		return WIMLIB_ERR_NOMEM;

	inode = root->d_inode;

#ifdef HAVE_STAT_NANOSECOND_PRECISION
	inode->creation_time = timespec_to_wim_timestamp(&root_stbuf.st_mtim);
	inode->last_write_time = timespec_to_wim_timestamp(&root_stbuf.st_mtim);
	inode->last_access_time = timespec_to_wim_timestamp(&root_stbuf.st_atim);
#else
	inode->creation_time = unix_timestamp_to_wim(root_stbuf.st_mtime);
	inode->last_write_time = unix_timestamp_to_wim(root_stbuf.st_mtime);
	inode->last_access_time = unix_timestamp_to_wim(root_stbuf.st_atime);
#endif
	if (sizeof(ino_t) >= 8)
		inode->ino = (u64)root_stbuf.st_ino;
	else
		inode->ino = (u64)root_stbuf.st_ino |
				   ((u64)root_stbuf.st_dev << ((sizeof(ino_t) * 8) & 63));

	add_image_flags &= ~WIMLIB_ADD_IMAGE_FLAG_ROOT;
	inode->resolved = true;

	if (S_ISREG(root_stbuf.st_mode)) { /* Archiving a regular file */

		struct lookup_table_entry *lte;
		u8 hash[SHA1_HASH_SIZE];

		inode->attributes = FILE_ATTRIBUTE_NORMAL;

		/* Empty files do not have to have a lookup table entry. */
		if (root_stbuf.st_size == 0)
			goto out;

		/* For each regular file, we must check to see if the file is in
		 * the lookup table already; if it is, we increment its refcnt;
		 * otherwise, we create a new lookup table entry and insert it.
		 * */

		ret = sha1sum(root_disk_path, hash);
		if (ret != 0)
			goto out;

		lte = __lookup_resource(lookup_table, hash);
		if (lte) {
			lte->refcnt++;
			DEBUG("Add lte reference %u for `%s'", lte->refcnt,
			      root_disk_path);
		} else {
			char *file_on_disk = STRDUP(root_disk_path);
			if (!file_on_disk) {
				ERROR("Failed to allocate memory for file path");
				ret = WIMLIB_ERR_NOMEM;
				goto out;
			}
			lte = new_lookup_table_entry();
			if (!lte) {
				FREE(file_on_disk);
				ret = WIMLIB_ERR_NOMEM;
				goto out;
			}
			lte->file_on_disk = file_on_disk;
			lte->resource_location = RESOURCE_IN_FILE_ON_DISK;
			lte->resource_entry.original_size = root_stbuf.st_size;
			lte->resource_entry.size = root_stbuf.st_size;
			copy_hash(lte->hash, hash);
			lookup_table_insert(lookup_table, lte);
		}
		root->d_inode->lte = lte;
	} else if (S_ISDIR(root_stbuf.st_mode)) { /* Archiving a directory */

		inode->attributes = FILE_ATTRIBUTE_DIRECTORY;

		DIR *dir;
		struct dirent entry, *result;
		struct dentry *child;

		dir = opendir(root_disk_path);
		if (!dir) {
			ERROR_WITH_ERRNO("Failed to open the directory `%s'",
					 root_disk_path);
			ret = WIMLIB_ERR_OPEN;
			goto out;
		}

		/* Buffer for names of files in directory. */
		size_t len = strlen(root_disk_path);
		char name[len + 1 + FILENAME_MAX + 1];
		memcpy(name, root_disk_path, len);
		name[len] = '/';

		/* Create a dentry for each entry in the directory on disk, and recurse
		 * to any subdirectories. */
		while (1) {
			errno = 0;
			ret = readdir_r(dir, &entry, &result);
			if (ret != 0) {
				ret = WIMLIB_ERR_READ;
				ERROR_WITH_ERRNO("Error reading the "
						 "directory `%s'",
						 root_disk_path);
				break;
			}
			if (result == NULL)
				break;
			if (result->d_name[0] == '.' && (result->d_name[1] == '\0'
			      || (result->d_name[1] == '.' && result->d_name[2] == '\0')))
					continue;
			strcpy(name + len + 1, result->d_name);
			ret = build_dentry_tree(&child, name, lookup_table,
						NULL, config, add_image_flags,
						progress_func, NULL);
			if (ret != 0)
				break;
			if (child)
				dentry_add_child(root, child);
		}
		closedir(dir);
	} else { /* Archiving a symbolic link */
		inode->attributes = FILE_ATTRIBUTE_REPARSE_POINT;
		inode->reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;

		/* The idea here is to call readlink() to get the UNIX target of
		 * the symbolic link, then turn the target into a reparse point
		 * data buffer that contains a relative or absolute symbolic
		 * link (NOT a junction point or *full* path symbolic link with
		 * drive letter).
		 */

		char deref_name_buf[4096];
		ssize_t deref_name_len;

		deref_name_len = readlink(root_disk_path, deref_name_buf,
					  sizeof(deref_name_buf) - 1);
		if (deref_name_len >= 0) {
			deref_name_buf[deref_name_len] = '\0';
			DEBUG("Read symlink `%s'", deref_name_buf);
			ret = inode_set_symlink(root->d_inode, deref_name_buf,
						lookup_table, NULL);
			if (ret == 0) {
				/*
				 * Unfortunately, Windows seems to have the
				 * concept of "file" symbolic links as being
				 * different from "directory" symbolic links...
				 * so FILE_ATTRIBUTE_DIRECTORY needs to be set
				 * on the symbolic link if the *target* of the
				 * symbolic link is a directory.
				 */
				struct stat stbuf;
				if (stat(root_disk_path, &stbuf) == 0 &&
				    S_ISDIR(stbuf.st_mode))
				{
					inode->attributes |= FILE_ATTRIBUTE_DIRECTORY;
				}
			}
		} else {
			ERROR_WITH_ERRNO("Failed to read target of "
					 "symbolic link `%s'", root_disk_path);
			ret = WIMLIB_ERR_READLINK;
		}
	}
out:
	if (ret == 0)
		*root_ret = root;
	else
		free_dentry_tree(root, lookup_table);
	return ret;
}


enum pattern_type {
	NONE = 0,
	EXCLUSION_LIST,
	EXCLUSION_EXCEPTION,
	COMPRESSION_EXCLUSION_LIST,
	ALIGNMENT_LIST,
};

/* Default capture configuration file when none is specified. */
static const char *default_config =
"[ExclusionList]\n"
"\\$ntfs.log\n"
"\\hiberfil.sys\n"
"\\pagefile.sys\n"
"\\System Volume Information\n"
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

/* Parses the contents of the image capture configuration file and fills in a
 * `struct capture_config'. */
static int init_capture_config(const char *_config_str, size_t config_len,
			       const char *_prefix, struct capture_config *config)
{
	char *config_str;
	char *prefix;
	char *p;
	char *eol;
	char *next_p;
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
		bytes_remaining -= (next_p - p);
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

		ret = 0;
		if (strcmp(p, "[ExclusionList]") == 0)
			type = EXCLUSION_LIST;
		else if (strcmp(p, "[ExclusionException]") == 0)
			type = EXCLUSION_EXCEPTION;
		else if (strcmp(p, "[CompressionExclusionList]") == 0)
			type = COMPRESSION_EXCLUSION_LIST;
		else if (strcmp(p, "[AlignmentList]") == 0)
			type = ALIGNMENT_LIST;
		else if (p[0] == '[' && strrchr(p, ']')) {
			ERROR("Unknown capture configuration section `%s'", p);
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
		} else switch (type) {
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
			break;
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

/* Return true if the image capture configuration file indicates we should
 * exclude the filename @path from capture.
 *
 * If @exclude_prefix is %true, the part of the path up and including the name
 * of the directory being captured is not included in the path for matching
 * purposes.  This allows, for example, a pattern like /hiberfil.sys to match a
 * file /mnt/windows7/hiberfil.sys if we are capturing the /mnt/windows7
 * directory.
 */
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

WIMLIBAPI int wimlib_add_image(WIMStruct *w, const char *source,
			       const char *name, const char *config_str,
			       size_t config_len, int add_image_flags,
			       wimlib_progress_func_t progress_func)
{
	int (*capture_tree)(struct dentry **, const char *,
			    struct lookup_table *,
			    struct wim_security_data *,
			    const struct capture_config *,
			    int, wimlib_progress_func_t, void *);
	void *extra_arg;

	struct dentry *root_dentry = NULL;
	struct wim_security_data *sd;
	struct capture_config config;
	struct inode_table inode_tab;
	struct hlist_head inode_list;
	int ret;

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NTFS) {
#ifdef WITH_NTFS_3G
		if (add_image_flags & (WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE)) {
			ERROR("Cannot dereference files when capturing directly from NTFS");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		capture_tree = build_dentry_tree_ntfs;
		extra_arg = &w->ntfs_vol;
#else
		ERROR("wimlib was compiled without support for NTFS-3g, so\n"
		      "        cannot capture a WIM image directly from a NTFS volume!");
		return WIMLIB_ERR_UNSUPPORTED;
#endif
	} else {
		capture_tree = build_dentry_tree;
		extra_arg = NULL;
	}

	DEBUG("Adding dentry tree from directory or NTFS volume `%s'.", source);

	if (!name || !*name) {
		ERROR("Must specify a non-empty string for the image name");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (!source || !*source) {
		ERROR("Must specify the name of a directory or NTFS volume");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (w->hdr.total_parts != 1) {
		ERROR("Cannot add an image to a split WIM");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
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
	ret = init_capture_config(config_str, config_len, source, &config);
	if (ret != 0)
		return ret;
	print_capture_config(&config);

	DEBUG("Allocating security data");

	sd = CALLOC(1, sizeof(struct wim_security_data));
	if (!sd) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_destroy_config;
	}
	sd->total_length = 8;
	sd->refcnt = 1;

	if (progress_func) {
		union wimlib_progress_info progress;
		progress.scan.source = source;
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_BEGIN, &progress);
	}

	DEBUG("Building dentry tree.");
	ret = (*capture_tree)(&root_dentry, source, w->lookup_table, sd,
			      &config, add_image_flags | WIMLIB_ADD_IMAGE_FLAG_ROOT,
			      progress_func, extra_arg);
	destroy_capture_config(&config);

	if (ret != 0) {
		ERROR("Failed to build dentry tree for `%s'", source);
		goto out_free_security_data;
	}

	if (progress_func) {
		union wimlib_progress_info progress;
		progress.scan.source = source;
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_END, &progress);
	}

	DEBUG("Calculating full paths of dentries.");
	ret = for_dentry_in_tree(root_dentry, calculate_dentry_full_path, NULL);
	if (ret != 0)
		goto out_free_dentry_tree;

	ret = add_new_dentry_tree(w, root_dentry, sd);
	if (ret != 0)
		goto out_free_dentry_tree;

	DEBUG("Inserting dentries into inode table");
	ret = init_inode_table(&inode_tab, 9001);
	if (ret != 0)
		goto out_destroy_imd;

	for_dentry_in_tree(root_dentry, inode_table_insert, &inode_tab);

	DEBUG("Cleaning up the hard link groups");
	ret = fix_inodes(&inode_tab, &inode_list);
	destroy_inode_table(&inode_tab);
	if (ret != 0)
		goto out_destroy_imd;

	DEBUG("Assigning hard link group IDs");
	assign_inode_numbers(&inode_list);

	ret = xml_add_image(w, name);
	if (ret != 0)
		goto out_destroy_imd;

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_BOOT)
		wimlib_set_boot_idx(w, w->hdr.image_count);
	return 0;
out_destroy_imd:
	destroy_image_metadata(&w->image_metadata[w->hdr.image_count - 1],
			       w->lookup_table);
	w->hdr.image_count--;
	return ret;
out_free_dentry_tree:
	free_dentry_tree(root_dentry, w->lookup_table);
out_free_security_data:
	free_security_data(sd);
out_destroy_config:
	destroy_capture_config(&config);
	return ret;
}
