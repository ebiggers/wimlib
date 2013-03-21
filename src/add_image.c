/*
 * add_image.c
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#ifdef __WIN32__
#  include "win32.h"
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <fnmatch.h>
#  include "timestamp.h"
#endif

#include "wimlib_internal.h"
#include "dentry.h"
#include "lookup_table.h"
#include "xml.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_ALLOCA_H
#  include <alloca.h>
#endif

/*
 * Adds the dentry tree and security data for a new image to the image metadata
 * array of the WIMStruct.
 */
int
add_new_dentry_tree(WIMStruct *w, struct wim_dentry *root_dentry,
		    struct wim_security_data *sd)
{
	struct wim_lookup_table_entry *metadata_lte;
	struct wim_image_metadata *imd;
	struct wim_image_metadata *new_imd;

	wimlib_assert(root_dentry != NULL);

	DEBUG("Reallocating image metadata array for image_count = %u",
	      w->hdr.image_count + 1);
	imd = CALLOC((w->hdr.image_count + 1), sizeof(struct wim_image_metadata));

	if (!imd) {
		ERROR("Failed to allocate memory for new image metadata array");
		goto err;
	}

	memcpy(imd, w->image_metadata,
	       w->hdr.image_count * sizeof(struct wim_image_metadata));

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
	new_imd->modified	= 1;

	FREE(w->image_metadata);
	w->image_metadata = imd;
	w->hdr.image_count++;
	return 0;
err_free_imd:
	FREE(imd);
err:
	return WIMLIB_ERR_NOMEM;

}

#ifndef __WIN32__
/*
 * build_dentry_tree():
 * 	Recursively builds a tree of WIM dentries from an on-disk directory
 * 	tree.
 *
 * @root_ret:   Place to return a pointer to the root of the dentry tree.  Only
 *		modified if successful.  Set to NULL if the file or directory was
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
 * @extra_arg:	Ignored in UNIX builds; used to pass sd_set pointer in Windows
 *		builds.
 *
 * @return:	0 on success, nonzero on failure.  It is a failure if any of
 *		the files cannot be `stat'ed, or if any of the needed
 *		directories cannot be opened or read.  Failure to add the files
 *		to the WIM may still occur later when trying to actually read
 *		the on-disk files during a call to wimlib_write() or
 *		wimlib_overwrite().
 */
static int
unix_build_dentry_tree(struct wim_dentry **root_ret,
		       const mbchar *root_disk_path,
		       struct wim_lookup_table *lookup_table,
		       struct wim_security_data *sd,
		       const struct capture_config *config,
		       int add_image_flags,
		       wimlib_progress_func_t progress_func,
		       void *extra_arg)
{
	struct wim_dentry *root = NULL;
	int ret = 0;
	struct wim_inode *inode;

	if (exclude_path(root_disk_path, config, true)) {
		if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) {
			ERROR("Cannot exclude the root directory from capture");
			ret = WIMLIB_ERR_INVALID_CAPTURE_CONFIG;
			goto out;
		}
		if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
		    && progress_func)
		{
			union wimlib_progress_info info;
			info.scan.cur_path = root_disk_path;
			info.scan.excluded = true;
			progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
		}
		goto out;
	}

	if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_VERBOSE)
	    && progress_func)
	{
		union wimlib_progress_info info;
		info.scan.cur_path = root_disk_path;
		info.scan.excluded = false;
		progress_func(WIMLIB_PROGRESS_MSG_SCAN_DENTRY, &info);
	}

	/* UNIX version of capturing a directory tree */
	struct stat root_stbuf;
	int (*stat_fn)(const char *restrict, struct stat *restrict);
	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE)
		stat_fn = stat;
	else
		stat_fn = lstat;

	ret = (*stat_fn)(root_disk_path, &root_stbuf);
	if (ret != 0) {
		ERROR_WITH_ERRNO("Failed to stat `%s'", root_disk_path);
		goto out;
	}

	if ((add_image_flags & WIMLIB_ADD_IMAGE_FLAG_ROOT) &&
	      !S_ISDIR(root_stbuf.st_mode))
	{
		/* Do a dereference-stat in case the root is a symbolic link.
		 * This case is allowed, provided that the symbolic link points
		 * to a directory. */
		ret = stat(root_disk_path, &root_stbuf);
		if (ret != 0) {
			ERROR_WITH_ERRNO("Failed to stat `%s'", root_disk_path);
			ret = WIMLIB_ERR_STAT;
			goto out;
		}
		if (!S_ISDIR(root_stbuf.st_mode)) {
			ERROR("`%s' is not a directory", root_disk_path);
			ret = WIMLIB_ERR_NOTDIR;
			goto out;
		}
	}
	if (!S_ISREG(root_stbuf.st_mode) && !S_ISDIR(root_stbuf.st_mode)
	    && !S_ISLNK(root_stbuf.st_mode)) {
		ERROR("`%s' is not a regular file, directory, or symbolic link.",
		      root_disk_path);
		ret = WIMLIB_ERR_SPECIAL_FILE;
		goto out;
	}

	ret = new_dentry_with_timeless_inode(path_basename(root_disk_path),
					     &root);
	if (ret)
		goto out;

	inode = root->d_inode;

#ifdef HAVE_STAT_NANOSECOND_PRECISION
	inode->i_creation_time = timespec_to_wim_timestamp(root_stbuf.st_mtim);
	inode->i_last_write_time = timespec_to_wim_timestamp(root_stbuf.st_mtim);
	inode->i_last_access_time = timespec_to_wim_timestamp(root_stbuf.st_atim);
#else
	inode->i_creation_time = unix_timestamp_to_wim(root_stbuf.st_mtime);
	inode->i_last_write_time = unix_timestamp_to_wim(root_stbuf.st_mtime);
	inode->i_last_access_time = unix_timestamp_to_wim(root_stbuf.st_atime);
#endif
	/* Leave the inode number at 0 for directories. */
	if (!S_ISDIR(root_stbuf.st_mode)) {
		if (sizeof(ino_t) >= 8)
			inode->i_ino = (u64)root_stbuf.st_ino;
		else
			inode->i_ino = (u64)root_stbuf.st_ino |
					   ((u64)root_stbuf.st_dev <<
					    	((sizeof(ino_t) * 8) & 63));
	}
	inode->i_resolved = 1;
	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) {
		ret = inode_set_unix_data(inode, root_stbuf.st_uid,
					  root_stbuf.st_gid,
					  root_stbuf.st_mode,
					  lookup_table,
					  UNIX_DATA_ALL | UNIX_DATA_CREATE);
		if (ret)
			goto out;
	}
	add_image_flags &= ~(WIMLIB_ADD_IMAGE_FLAG_ROOT | WIMLIB_ADD_IMAGE_FLAG_SOURCE);
	if (S_ISREG(root_stbuf.st_mode)) { /* Archiving a regular file */

		struct wim_lookup_table_entry *lte;
		u8 hash[SHA1_HASH_SIZE];

		inode->i_attributes = FILE_ATTRIBUTE_NORMAL;

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
			mbchar *file_on_disk = STRDUP(root_disk_path);
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
		root->d_inode->i_lte = lte;
	} else if (S_ISDIR(root_stbuf.st_mode)) { /* Archiving a directory */

		inode->i_attributes = FILE_ATTRIBUTE_DIRECTORY;

		DIR *dir;
		struct dirent entry, *result;
		struct wim_dentry *child;

		dir = opendir(root_disk_path);
		if (!dir) {
			ERROR_WITH_ERRNO("Failed to open the directory `%s'",
					 root_disk_path);
			ret = WIMLIB_ERR_OPEN;
			goto out;
		}

		/* Buffer for names of files in directory. */
		size_t len = strlen(root_disk_path);
		mbchar name[len + 1 + FILENAME_MAX + 1];
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
			ret = unix_build_dentry_tree(&child, name,
						     lookup_table,
						     NULL, config,
						     add_image_flags,
						     progress_func, NULL);
			if (ret != 0)
				break;
			if (child)
				dentry_add_child(root, child);
		}
		closedir(dir);
	} else { /* Archiving a symbolic link */
		inode->i_attributes = FILE_ATTRIBUTE_REPARSE_POINT;
		inode->i_reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;

		/* The idea here is to call readlink() to get the UNIX target of
		 * the symbolic link, then turn the target into a reparse point
		 * data buffer that contains a relative or absolute symbolic
		 * link (NOT a junction point or *full* path symbolic link with
		 * drive letter).
		 */

		mbchar deref_name_buf[4096];
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
					inode->i_attributes |= FILE_ATTRIBUTE_DIRECTORY;
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
#endif /* !__WIN32__ */

enum pattern_type {
	NONE = 0,
	EXCLUSION_LIST,
	EXCLUSION_EXCEPTION,
	COMPRESSION_EXCLUSION_LIST,
	ALIGNMENT_LIST,
};

#define COMPAT_DEFAULT_CONFIG

/* Default capture configuration file when none is specified. */
static const mbchar *default_config =
#ifdef COMPAT_DEFAULT_CONFIG /* XXX: This policy is being moved to library
				users.  The next ABI-incompatible library
				version will default to the empty string here. */
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
#else
"";
#endif

static void
destroy_pattern_list(struct pattern_list *list)
{
	FREE(list->pats);
}

static void
destroy_capture_config(struct capture_config *config)
{
	destroy_pattern_list(&config->exclusion_list);
	destroy_pattern_list(&config->exclusion_exception);
	destroy_pattern_list(&config->compression_exclusion_list);
	destroy_pattern_list(&config->alignment_list);
	FREE(config->config_str);
	FREE(config->prefix);
	memset(config, 0, sizeof(*config));
}

static int
pattern_list_add_pattern(struct pattern_list *list, const mbchar *pattern)
{
	const mbchar **pats;
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
static int
init_capture_config(struct capture_config *config,
		    const mbchar *_config_str, size_t config_len)
{
	mbchar *config_str;
	mbchar *p;
	mbchar *eol;
	mbchar *next_p;
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

	memcpy(config_str, _config_str, config_len);
	next_p = config_str;
	config->config_str = config_str;
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
		for (mbchar *pp = p; pp != eol; pp++)
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

static int capture_config_set_prefix(struct capture_config *config,
				     const mbchar *_prefix)
{
	mbchar *prefix = STRDUP(_prefix);

	if (!prefix)
		return WIMLIB_ERR_NOMEM;
	FREE(config->prefix);
	config->prefix = prefix;
	config->prefix_len = strlen(prefix);
	return 0;
}

static bool match_pattern(const mbchar *path,
			  const mbchar *path_basename,
			  const struct pattern_list *list)
{
	for (size_t i = 0; i < list->num_pats; i++) {
		const mbchar *pat = list->pats[i];
		const mbchar *string;
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

		/* Warning: on Windows native builds, fnmatch() calls the
		 * replacement function in win32.c. */
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

/* Return true if the image capture configuration file indicates we should
 * exclude the filename @path from capture.
 *
 * If @exclude_prefix is %true, the part of the path up and including the name
 * of the directory being captured is not included in the path for matching
 * purposes.  This allows, for example, a pattern like /hiberfil.sys to match a
 * file /mnt/windows7/hiberfil.sys if we are capturing the /mnt/windows7
 * directory.
 */
bool
exclude_path(const mbchar *path, const struct capture_config *config,
	     bool exclude_prefix)
{
	const mbchar *basename = path_basename(path);
	if (exclude_prefix) {
		wimlib_assert(strlen(path) >= config->prefix_len);
		if (memcmp(config->prefix, path, config->prefix_len) == 0
		     && path[config->prefix_len] == '/')
			path += config->prefix_len;
	}
	return match_pattern(path, basename, &config->exclusion_list) &&
		!match_pattern(path, basename, &config->exclusion_exception);

}

/* Strip leading and trailing forward slashes from a string.  Modifies it in
 * place and returns the stripped string. */
static const char *
canonicalize_target_path(char *target_path)
{
	char *p;
	if (target_path == NULL)
		return "";
	for (;;) {
		if (*target_path == '\0')
			return target_path;
		else if (*target_path == '/')
			target_path++;
		else
			break;
	}

	p = target_path + strlen(target_path) - 1;
	while (*p == '/')
		*p-- = '\0';
	return target_path;
}

#ifdef __WIN32__
static void
zap_backslashes(char *s)
{
	while (*s) {
		if (*s == '\\')
			*s = '/';
		s++;
	}
}
#endif

/* Strip leading and trailing slashes from the target paths */
static void
canonicalize_targets(struct wimlib_capture_source *sources, size_t num_sources)
{
	while (num_sources--) {
		DEBUG("Canonicalizing { source: \"%s\", target=\"%s\"}",
		      sources->fs_source_path,
		      sources->wim_target_path);
#ifdef __WIN32__
		/* The Windows API can handle forward slashes.  Just get rid of
		 * backslashes to avoid confusing other parts of the library
		 * code. */
		zap_backslashes(sources->fs_source_path);
		if (sources->wim_target_path)
			zap_backslashes(sources->wim_target_path);
#endif
		sources->wim_target_path =
			(char*)canonicalize_target_path(sources->wim_target_path);
		DEBUG("Canonical target: \"%s\"", sources->wim_target_path);
		sources++;
	}
}

static int
capture_source_cmp(const void *p1, const void *p2)
{
	const struct wimlib_capture_source *s1 = p1, *s2 = p2;
	return strcmp(s1->wim_target_path, s2->wim_target_path);
}

/* Sorts the capture sources lexicographically by target path.  This occurs
 * after leading and trailing forward slashes are stripped.
 *
 * One purpose of this is to make sure that target paths that are inside other
 * target paths are added after the containing target paths. */
static void
sort_sources(struct wimlib_capture_source *sources, size_t num_sources)
{
	qsort(sources, num_sources, sizeof(sources[0]), capture_source_cmp);
}

static int
check_sorted_sources(struct wimlib_capture_source *sources, size_t num_sources,
		     int add_image_flags)
{
	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NTFS) {
		if (num_sources != 1) {
			ERROR("Must specify exactly 1 capture source "
			      "(the NTFS volume) in NTFS mode!");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (sources[0].wim_target_path[0] != '\0') {
			ERROR("In NTFS capture mode the target path inside "
			      "the image must be the root directory!");
			return WIMLIB_ERR_INVALID_PARAM;
		}
	} else if (num_sources != 0) {
		/* This code is disabled because the current code
		 * unconditionally attempts to do overlays.  So, duplicate
		 * target paths are OK. */
	#if 0
		if (num_sources > 1 && sources[0].wim_target_path[0] == '\0') {
			ERROR("Cannot specify root target when using multiple "
			      "capture sources!");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		for (size_t i = 0; i < num_sources - 1; i++) {
			size_t len = strlen(sources[i].wim_target_path);
			size_t j = i + 1;
			const char *target1 = sources[i].wim_target_path;
			do {
				const char *target2 = sources[j].wim_target_path;
				DEBUG("target1=%s, target2=%s",
				      target1,target2);
				if (strncmp(target1, target2, len) ||
				    target2[len] > '/')
					break;
				if (target2[len] == '/') {
					ERROR("Invalid target `%s': is a prefix of `%s'",
					      target1, target2);
					return WIMLIB_ERR_INVALID_PARAM;
				}
				if (target2[len] == '\0') {
					ERROR("Invalid target `%s': is a duplicate of `%s'",
					      target1, target2);
					return WIMLIB_ERR_INVALID_PARAM;
				}
			} while (++j != num_sources);
		}
	#endif
	}
	return 0;

}

/* Creates a new directory to place in the WIM image.  This is to create parent
 * directories that are not part of any target as needed.  */
static int
new_filler_directory(const mbchar *name, struct wim_dentry **dentry_ret)
{
	int ret;
	struct wim_dentry *dentry;

	DEBUG("Creating filler directory \"%s\"", name);
	ret = new_dentry_with_inode(name, &dentry);
	if (ret == 0) {
		/* Leave the inode number as 0 for now.  The final inode number
		 * will be assigned later by assign_inode_numbers(). */
		dentry->d_inode->i_resolved = 1;
		dentry->d_inode->i_attributes = FILE_ATTRIBUTE_DIRECTORY;
		*dentry_ret = dentry;
	}
	return ret;
}

/* Transfers the children of @branch to @target.  It is an error if @target is
 * not a directory or if both @branch and @target contain a child dentry with
 * the same name. */
static int
do_overlay(struct wim_dentry *target, struct wim_dentry *branch)
{
	struct rb_root *rb_root;

	DEBUG("Doing overlay \"%W\" => \"%W\"",
	      branch->file_name, target->file_name);

	if (!dentry_is_directory(target)) {
		ERROR("Cannot overlay directory \"%W\" over non-directory",
		      branch->file_name);
		return WIMLIB_ERR_INVALID_OVERLAY;
	}

	rb_root = &branch->d_inode->i_children;
	while (rb_root->rb_node) { /* While @branch has children... */
		struct wim_dentry *child = rbnode_dentry(rb_root->rb_node);
		/* Move @child to the directory @target */
		unlink_dentry(child);
		if (!dentry_add_child(target, child)) {
			/* Revert the change to avoid leaking the directory tree
			 * rooted at @child */
			dentry_add_child(branch, child);
			ERROR("Overlay error: file \"%W\" already exists "
			      "as a child of \"%W\"",
			      child->file_name, target->file_name);
			return WIMLIB_ERR_INVALID_OVERLAY;
		}
	}
	free_dentry(branch);
	return 0;

}

/* Attach or overlay a branch onto the WIM image.
 *
 * @root_p:
 * 	Pointer to the root of the WIM image, or pointer to NULL if it has not
 * 	been created yet.
 * @branch
 * 	Branch to add.
 * @target_path:
 * 	Path in the WIM image to add the branch, with leading and trailing
 * 	slashes stripped.
 */
static int
attach_branch(struct wim_dentry **root_p, struct wim_dentry *branch,
	      mbchar *target_path)
{
	mbchar *slash;
	struct wim_dentry *dentry, *parent, *target;
	int ret;

	DEBUG("Attaching branch \"%W\" => \"%s\"",
	      branch->file_name, target_path);

	if (*target_path == '\0') {
		/* Target: root directory */
		if (*root_p) {
			/* Overlay on existing root */
			return do_overlay(*root_p, branch);
		} else  {
			/* Set as root */
			*root_p = branch;
			return 0;
		}
	}

	/* Adding a non-root branch.  Create root if it hasn't been created
	 * already. */
	if (!*root_p) {
		ret  = new_filler_directory("", root_p);
		if (ret)
			return ret;
	}

	/* Walk the path to the branch, creating filler directories as needed.
	 * */
	parent = *root_p;
	while ((slash = strchr(target_path, '/'))) {
		*slash = '\0';
		dentry = get_dentry_child_with_name(parent, target_path);
		if (!dentry) {
			ret = new_filler_directory(target_path, &dentry);
			if (ret)
				return ret;
			dentry_add_child(parent, dentry);
		}
		parent = dentry;
		target_path = slash;
		/* Skip over slashes.  Note: this cannot overrun the length of
		 * the string because the last character cannot be a slash, as
		 * trailing slashes were tripped.  */
		do {
			++target_path;
		} while (*target_path == '/');
	}

	/* If the target path already existed, overlay the branch onto it.
	 * Otherwise, set the branch as the target path. */
	target = get_dentry_child_with_utf16le_name(parent, branch->file_name,
						    branch->file_name_nbytes);
	if (target) {
		return do_overlay(target, branch);
	} else {
		dentry_add_child(parent, branch);
		return 0;
	}
}

WIMLIBAPI int
wimlib_add_image_multisource(WIMStruct *w,
			     struct wimlib_capture_source *sources,
			     size_t num_sources,
			     const utf8char *name,
			     const mbchar *config_str,
			     size_t config_len,
			     int add_image_flags,
			     wimlib_progress_func_t progress_func)
{
	int (*capture_tree)(struct wim_dentry **,
			    const mbchar *,
			    struct wim_lookup_table *,
			    struct wim_security_data *,
			    const struct capture_config *,
			    int,
			    wimlib_progress_func_t,
			    void *);
	void *extra_arg;
	struct wim_dentry *root_dentry;
	struct wim_dentry *branch;
	struct wim_security_data *sd;
	struct capture_config config;
	struct wim_image_metadata *imd;
	int ret;

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_NTFS) {
#ifdef WITH_NTFS_3G
		if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE) {
			ERROR("Cannot dereference files when capturing directly from NTFS");
			return WIMLIB_ERR_INVALID_PARAM;
		}
		if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) {
			ERROR("Capturing UNIX owner and mode not supported "
			      "when capturing directly from NTFS");
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
	#ifdef __WIN32__
		capture_tree = win32_build_dentry_tree;
	#else
		capture_tree = unix_build_dentry_tree;
	#endif
		extra_arg = NULL;
	}

#ifdef __WIN32__
	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_UNIX_DATA) {
		ERROR("Capturing UNIX-specific data is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_DEREFERENCE) {
		ERROR("Dereferencing symbolic links is not supported on Windows");
		return WIMLIB_ERR_INVALID_PARAM;
	}
#endif

	if (!name || !*name) {
		ERROR("Must specify a non-empty string for the image name");
		return WIMLIB_ERR_INVALID_PARAM;
	}

	if (w->hdr.total_parts != 1) {
		ERROR("Cannot add an image to a split WIM");
		return WIMLIB_ERR_SPLIT_UNSUPPORTED;
	}

	if (wimlib_image_name_in_use(w, name)) {
		ERROR("There is already an image named \"%U\" in the WIM!",
		      name);
		return WIMLIB_ERR_IMAGE_NAME_COLLISION;
	}

	if (!config_str) {
		DEBUG("Using default capture configuration");
		config_str = default_config;
		config_len = strlen(default_config);
	}
	ret = init_capture_config(&config, config_str, config_len);
	if (ret)
		goto out;

	DEBUG("Allocating security data");
	sd = CALLOC(1, sizeof(struct wim_security_data));
	if (!sd) {
		ret = WIMLIB_ERR_NOMEM;
		goto out_destroy_capture_config;
	}
	sd->total_length = 8;
	sd->refcnt = 1;

	DEBUG("Using %zu capture sources", num_sources);
	canonicalize_targets(sources, num_sources);
	sort_sources(sources, num_sources);
	ret = check_sorted_sources(sources, num_sources, add_image_flags);
	if (ret) {
		ret = WIMLIB_ERR_INVALID_PARAM;
		goto out_free_security_data;
	}

	DEBUG("Building dentry tree.");
	root_dentry = NULL;

	for (size_t i = 0; i < num_sources; i++) {
		int flags;
		union wimlib_progress_info progress;

		DEBUG("Building dentry tree for source %zu of %zu "
		      "(\"%s\" => \"%s\")", i + 1, num_sources,
		      sources[i].fs_source_path,
		      sources[i].wim_target_path);
		if (progress_func) {
			memset(&progress, 0, sizeof(progress));
			progress.scan.source = sources[i].fs_source_path;
			progress.scan.wim_target_path = sources[i].wim_target_path;
			progress_func(WIMLIB_PROGRESS_MSG_SCAN_BEGIN, &progress);
		}
		ret = capture_config_set_prefix(&config,
						sources[i].fs_source_path);
		if (ret)
			goto out_free_dentry_tree;
		flags = add_image_flags | WIMLIB_ADD_IMAGE_FLAG_SOURCE;
		if (!*sources[i].wim_target_path)
			flags |= WIMLIB_ADD_IMAGE_FLAG_ROOT;
		ret = (*capture_tree)(&branch, sources[i].fs_source_path,
				      w->lookup_table, sd,
				      &config,
				      flags,
				      progress_func, extra_arg);
		if (ret) {
			ERROR("Failed to build dentry tree for `%s'",
			      sources[i].fs_source_path);
			goto out_free_dentry_tree;
		}
		if (branch) {
			/* Use the target name, not the source name, for
			 * the root of each branch from a capture
			 * source.  (This will also set the root dentry
			 * of the entire image to be unnamed.) */
			ret = set_dentry_name(branch,
					      path_basename(sources[i].wim_target_path));
			if (ret)
				goto out_free_branch;

			ret = attach_branch(&root_dentry, branch,
					    sources[i].wim_target_path);
			if (ret)
				goto out_free_branch;
		}
		if (progress_func)
			progress_func(WIMLIB_PROGRESS_MSG_SCAN_END, &progress);
	}

	if (root_dentry == NULL) {
		ret = new_filler_directory("" , &root_dentry);
		if (ret)
			goto out_free_dentry_tree;
	}

	DEBUG("Calculating full paths of dentries.");
	ret = for_dentry_in_tree(root_dentry, calculate_dentry_full_path, NULL);
	if (ret)
		goto out_free_dentry_tree;

	ret = add_new_dentry_tree(w, root_dentry, sd);
	if (ret)
		goto out_free_dentry_tree;

	imd = &w->image_metadata[w->hdr.image_count - 1];

	ret = dentry_tree_fix_inodes(root_dentry, &imd->inode_list);
	if (ret)
		goto out_destroy_imd;

	DEBUG("Assigning hard link group IDs");
	assign_inode_numbers(&imd->inode_list);

	ret = xml_add_image(w, name);
	if (ret)
		goto out_destroy_imd;

	if (add_image_flags & WIMLIB_ADD_IMAGE_FLAG_BOOT)
		wimlib_set_boot_idx(w, w->hdr.image_count);
	ret = 0;
	goto out_destroy_capture_config;
out_destroy_imd:
	destroy_image_metadata(&w->image_metadata[w->hdr.image_count - 1],
			       w->lookup_table);
	w->hdr.image_count--;
	goto out;
out_free_branch:
	free_dentry_tree(branch, w->lookup_table);
out_free_dentry_tree:
	free_dentry_tree(root_dentry, w->lookup_table);
out_free_security_data:
	free_security_data(sd);
out_destroy_capture_config:
	destroy_capture_config(&config);
out:
	return ret;
}

WIMLIBAPI int
wimlib_add_image(WIMStruct *w,
		 const mbchar *source,
		 const utf8char *name,
		 const mbchar *config_str,
		 size_t config_len,
		 int add_image_flags,
		 wimlib_progress_func_t progress_func)
{
	if (!source || !*source)
		return WIMLIB_ERR_INVALID_PARAM;

	mbchar *fs_source_path = STRDUP(source);
	int ret;
	struct wimlib_capture_source capture_src = {
		.fs_source_path = fs_source_path,
		.wim_target_path = NULL,
		.reserved = 0,
	};
	ret = wimlib_add_image_multisource(w, &capture_src, 1, name,
					   config_str, config_len,
					   add_image_flags, progress_func);
	FREE(fs_source_path);
	return ret;
}
