/*
 * dentry.c
 *
 * A dentry (directory entry) contains the metadata for a file.  In the WIM file
 * format, the dentries are stored in the "metadata resource" section right
 * after the security data.  Each image in the WIM file has its own metadata
 * resource with its own security data and dentry tree.  Dentries in different
 * images may share file resources by referring to the same lookup table
 * entries.
 */

/*
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "dentry.h"
#include "io.h"
#include "lookup_table.h"
#include "sha1.h"
#include "timestamp.h"
#include "wimlib_internal.h"


static u64 __dentry_correct_length_unaligned(u16 file_name_len,
					     u16 short_name_len)
{
	u64 length = WIM_DENTRY_DISK_SIZE;
	if (file_name_len)
		length += file_name_len + 2;
	if (short_name_len)
		length += short_name_len + 2;
	return length;
}

static u64 dentry_correct_length_unaligned(const struct dentry *dentry)
{
	return __dentry_correct_length_unaligned(dentry->file_name_len,
						 dentry->short_name_len);
}

/* Return the "correct" value to write in the length field of the dentry, based
 * on the file name length and short name length */
static u64 dentry_correct_length(const struct dentry *dentry)
{
	return (dentry_correct_length_unaligned(dentry) + 7) & ~7;
}

/*
 * Returns true if @dentry has the UTF-8 file name @name that has length
 * @name_len.
 */
static bool dentry_has_name(const struct dentry *dentry, const char *name, 
			    size_t name_len)
{
	if (dentry->file_name_utf8_len != name_len)
		return false;
	return memcmp(dentry->file_name_utf8, name, name_len) == 0;
}

static inline bool ads_entry_has_name(const struct ads_entry *entry,
				      const char *name, size_t name_len)
{
	if (entry->stream_name_utf8_len != name_len)
		return false;
	return memcmp(entry->stream_name_utf8, name, name_len) == 0;
}

/* Duplicates a UTF-8 name into UTF-8 and UTF-16 strings and returns the strings
 * and their lengths in the pointer arguments */
int get_names(char **name_utf16_ret, char **name_utf8_ret,
	      u16 *name_utf16_len_ret, u16 *name_utf8_len_ret,
	      const char *name)
{
	size_t utf8_len;
	size_t utf16_len;
	char *name_utf16, *name_utf8;

	utf8_len = strlen(name);

	name_utf16 = utf8_to_utf16(name, utf8_len, &utf16_len);

	if (!name_utf16)
		return WIMLIB_ERR_NOMEM;

	name_utf8 = MALLOC(utf8_len + 1);
	if (!name_utf8) {
		FREE(name_utf8);
		return WIMLIB_ERR_NOMEM;
	}
	memcpy(name_utf8, name, utf8_len + 1);
	FREE(*name_utf8_ret);
	FREE(*name_utf16_ret);
	*name_utf8_ret      = name_utf8;
	*name_utf16_ret     = name_utf16;
	*name_utf8_len_ret  = utf8_len;
	*name_utf16_len_ret = utf16_len;
	return 0;
}

/* Changes the name of a dentry to @new_name.  Only changes the file_name and
 * file_name_utf8 fields; does not change the short_name, short_name_utf8, or
 * full_path_utf8 fields.  Also recalculates its length. */
static int change_dentry_name(struct dentry *dentry, const char *new_name)
{
	int ret;

	ret = get_names(&dentry->file_name, &dentry->file_name_utf8,
			&dentry->file_name_len, &dentry->file_name_utf8_len,
			 new_name);
	FREE(dentry->short_name);
	dentry->short_name_len = 0;
	if (ret == 0)
		dentry->length = dentry_correct_length(dentry);
	return ret;
}

/*
 * Changes the name of an alternate data stream */
static int change_ads_name(struct ads_entry *entry, const char *new_name)
{
	return get_names(&entry->stream_name, &entry->stream_name_utf8,
			 &entry->stream_name_len,
			 &entry->stream_name_utf8_len,
			 new_name);
}

/* Returns the total length of a WIM alternate data stream entry on-disk,
 * including the stream name, the null terminator, AND the padding after the
 * entry to align the next one (or the next dentry) on an 8-byte boundary. */
static u64 ads_entry_total_length(const struct ads_entry *entry)
{
	u64 len = WIM_ADS_ENTRY_DISK_SIZE;
	if (entry->stream_name_len)
		len += entry->stream_name_len + 2;
	return (len + 7) & ~7;
}


static u64 __dentry_total_length(const struct dentry *dentry, u64 length)
{
	const struct inode *inode = dentry->d_inode;
	for (u16 i = 0; i < inode->num_ads; i++)
		length += ads_entry_total_length(&inode->ads_entries[i]);
	return (length + 7) & ~7;
}

u64 dentry_correct_total_length(const struct dentry *dentry)
{
	return __dentry_total_length(dentry,
				     dentry_correct_length_unaligned(dentry));
}

/* Real length of a dentry, including the alternate data stream entries, which
 * are not included in the dentry->length field... */
static u64 dentry_total_length(const struct dentry *dentry)
{
	return __dentry_total_length(dentry, dentry->length);
}

/* Transfers file attributes from a `stat' buffer to an inode. */
void stbuf_to_inode(const struct stat *stbuf, struct inode *inode)
{
	if (S_ISLNK(stbuf->st_mode)) {
		inode->attributes = FILE_ATTRIBUTE_REPARSE_POINT;
		inode->reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;
	} else if (S_ISDIR(stbuf->st_mode)) {
		inode->attributes = FILE_ATTRIBUTE_DIRECTORY;
	} else {
		inode->attributes = FILE_ATTRIBUTE_NORMAL;
	}
	if (sizeof(ino_t) >= 8)
		inode->ino = (u64)stbuf->st_ino;
	else
		inode->ino = (u64)stbuf->st_ino |
				   ((u64)stbuf->st_dev << (sizeof(ino_t) * 8));
	/* Set timestamps */
	inode->creation_time = timespec_to_wim_timestamp(&stbuf->st_mtim);
	inode->last_write_time = timespec_to_wim_timestamp(&stbuf->st_mtim);
	inode->last_access_time = timespec_to_wim_timestamp(&stbuf->st_atim);
}

#ifdef WITH_FUSE
/* Transfers file attributes from a struct inode to a `stat' buffer. 
 *
 * The lookup table entry tells us which stream in the inode we are statting.
 * For a named data stream, everything returned is the same as the unnamed data
 * stream except possibly the size and block count. */
int inode_to_stbuf(const struct inode *inode, struct lookup_table_entry *lte,
		   struct stat *stbuf)
{
	if (inode_is_symlink(inode))
		stbuf->st_mode = S_IFLNK | 0777;
	else if (inode_is_directory(inode))
		stbuf->st_mode = S_IFDIR | 0755;
	else
		stbuf->st_mode = S_IFREG | 0644;

	stbuf->st_ino   = (ino_t)inode->ino;
	stbuf->st_nlink = inode->link_count;
	stbuf->st_uid   = getuid();
	stbuf->st_gid   = getgid();

	if (lte) {
		if (lte->resource_location == RESOURCE_IN_STAGING_FILE) {
			wimlib_assert(lte->staging_file_name);
			struct stat native_stat;
			if (stat(lte->staging_file_name, &native_stat) != 0) {
				DEBUG("Failed to stat `%s': %m",
				      lte->staging_file_name);
				return -errno;
			}
			stbuf->st_size = native_stat.st_size;
		} else {
			stbuf->st_size = wim_resource_size(lte);
		}
	} else {
		stbuf->st_size = 0;
	}

	stbuf->st_atime   = wim_timestamp_to_unix(inode->last_access_time);
	stbuf->st_mtime   = wim_timestamp_to_unix(inode->last_write_time);
	stbuf->st_ctime   = wim_timestamp_to_unix(inode->creation_time);
	stbuf->st_blocks  = (stbuf->st_size + 511) / 512;
	return 0;
}
#endif

/* 
 * Calls a function on all directory entries in a directory tree.  It is called
 * on a parent before its children.
 */
int for_dentry_in_tree(struct dentry *root, 
		       int (*visitor)(struct dentry*, void*), void *arg)
{
	int ret;
	struct dentry *child;

	ret = visitor(root, arg);

	if (ret != 0)
		return ret;

	child = root->d_inode->children;

	if (!child)
		return 0;

	do {
		ret = for_dentry_in_tree(child, visitor, arg);
		if (ret != 0)
			return ret;
		child = child->next;
	} while (child != root->d_inode->children);
	return 0;
}

/* 
 * Like for_dentry_in_tree(), but the visitor function is always called on a
 * dentry's children before on itself.
 */
int for_dentry_in_tree_depth(struct dentry *root, 
			     int (*visitor)(struct dentry*, void*), void *arg)
{
	int ret;
	struct dentry *child;
	struct dentry *next;

	child = root->d_inode->children;
	if (child) {
		do {
			next = child->next;
			ret = for_dentry_in_tree_depth(child, visitor, arg);
			if (ret != 0)
				return ret;
			child = next;
		} while (child != root->d_inode->children);
	}
	return visitor(root, arg);
}

/* 
 * Calculate the full path of @dentry, based on its parent's full path and on
 * its UTF-8 file name. 
 */
int calculate_dentry_full_path(struct dentry *dentry, void *ignore)
{
	char *full_path;
	u32 full_path_len;
	if (dentry_is_root(dentry)) {
		full_path = MALLOC(2);
		if (!full_path)
			goto oom;
		full_path[0] = '/';
		full_path[1] = '\0';
		full_path_len = 1;
	} else {
		char *parent_full_path;
		u32 parent_full_path_len;
		const struct dentry *parent = dentry->parent;

		if (dentry_is_root(parent)) {
			parent_full_path = "";
			parent_full_path_len = 0;
		} else {
			parent_full_path = parent->full_path_utf8;
			parent_full_path_len = parent->full_path_utf8_len;
		}

		full_path_len = parent_full_path_len + 1 +
				dentry->file_name_utf8_len;
		full_path = MALLOC(full_path_len + 1);
		if (!full_path)
			goto oom;

		memcpy(full_path, parent_full_path, parent_full_path_len);
		full_path[parent_full_path_len] = '/';
		memcpy(full_path + parent_full_path_len + 1,
		       dentry->file_name_utf8,
		       dentry->file_name_utf8_len);
		full_path[full_path_len] = '\0';
	}
	FREE(dentry->full_path_utf8);
	dentry->full_path_utf8 = full_path;
	dentry->full_path_utf8_len = full_path_len;
	return 0;
oom:
	ERROR("Out of memory while calculating dentry full path");
	return WIMLIB_ERR_NOMEM;
}

/* 
 * Recursively calculates the subdir offsets for a directory tree. 
 *
 * @dentry:  The root of the directory tree.
 * @subdir_offset_p:  The current subdirectory offset; i.e., the subdirectory
 * 	offset for @dentry. 
 */
void calculate_subdir_offsets(struct dentry *dentry, u64 *subdir_offset_p)
{
	struct dentry *child;

	child = dentry->d_inode->children;
	dentry->subdir_offset = *subdir_offset_p;

	if (child) {
		/* Advance the subdir offset by the amount of space the children
		 * of this dentry take up. */
		do {
			*subdir_offset_p += dentry_correct_total_length(child);
			child = child->next;
		} while (child != dentry->d_inode->children);

		/* End-of-directory dentry on disk. */
		*subdir_offset_p += 8;

		/* Recursively call calculate_subdir_offsets() on all the
		 * children. */
		do {
			calculate_subdir_offsets(child, subdir_offset_p);
			child = child->next;
		} while (child != dentry->d_inode->children);
	} else {
		/* On disk, childless directories have a valid subdir_offset
		 * that points to an 8-byte end-of-directory dentry.  Regular
		 * files or reparse points have a subdir_offset of 0. */
		if (dentry_is_directory(dentry))
			*subdir_offset_p += 8;
		else
			dentry->subdir_offset = 0;
	}
}

/* Returns the child of @dentry that has the file name @name.  
 * Returns NULL if no child has the name. */
struct dentry *get_dentry_child_with_name(const struct dentry *dentry, 
					  const char *name)
{
	struct dentry *child;
	size_t name_len;
	
	child = dentry->d_inode->children;
	if (child) {
		name_len = strlen(name);
		do {
			if (dentry_has_name(child, name, name_len))
				return child;
			child = child->next;
		} while (child != dentry->d_inode->children);
	}
	return NULL;
}

/* Retrieves the dentry that has the UTF-8 @path relative to the dentry
 * @cur_dir.  Returns NULL if no dentry having the path is found. */
static struct dentry *get_dentry_relative_path(struct dentry *cur_dir,
					       const char *path)
{
	struct dentry *child;
	size_t base_len;
	const char *new_path;

	if (*path == '\0')
		return cur_dir;

	child = cur_dir->d_inode->children;
	if (child) {
		new_path = path_next_part(path, &base_len);
		do {
			if (dentry_has_name(child, path, base_len))
				return get_dentry_relative_path(child, new_path);
			child = child->next;
		} while (child != cur_dir->d_inode->children);
	}
	return NULL;
}

/* Returns the dentry corresponding to the UTF-8 @path, or NULL if there is no
 * such dentry. */
struct dentry *get_dentry(WIMStruct *w, const char *path)
{
	struct dentry *root = wim_root_dentry(w);
	while (*path == '/')
		path++;
	return get_dentry_relative_path(root, path);
}

struct inode *wim_pathname_to_inode(WIMStruct *w, const char *path)
{
	struct dentry *dentry;
	dentry = get_dentry(w, path);
	if (!dentry)
		return NULL;
	else
		return dentry->d_inode;
}

/* Returns the dentry that corresponds to the parent directory of @path, or NULL
 * if the dentry is not found. */
struct dentry *get_parent_dentry(WIMStruct *w, const char *path)
{
	size_t path_len = strlen(path);
	char buf[path_len + 1];

	memcpy(buf, path, path_len + 1);

	to_parent_name(buf, path_len);

	return get_dentry(w, buf);
}

/* Prints the full path of a dentry. */
int print_dentry_full_path(struct dentry *dentry, void *ignore)
{
	if (dentry->full_path_utf8)
		puts(dentry->full_path_utf8);
	return 0;
}

/* We want to be able to show the names of the file attribute flags that are
 * set. */
struct file_attr_flag {
	u32 flag;
	const char *name;
};
struct file_attr_flag file_attr_flags[] = {
	{FILE_ATTRIBUTE_READONLY,	    "READONLY"},
	{FILE_ATTRIBUTE_HIDDEN,		    "HIDDEN"},
	{FILE_ATTRIBUTE_SYSTEM,		    "SYSTEM"},
	{FILE_ATTRIBUTE_DIRECTORY,	    "DIRECTORY"},
	{FILE_ATTRIBUTE_ARCHIVE,	    "ARCHIVE"},
	{FILE_ATTRIBUTE_DEVICE,		    "DEVICE"},
	{FILE_ATTRIBUTE_NORMAL,		    "NORMAL"},
	{FILE_ATTRIBUTE_TEMPORARY,	    "TEMPORARY"},
	{FILE_ATTRIBUTE_SPARSE_FILE,	    "SPARSE_FILE"},
	{FILE_ATTRIBUTE_REPARSE_POINT,	    "REPARSE_POINT"},
	{FILE_ATTRIBUTE_COMPRESSED,	    "COMPRESSED"},
	{FILE_ATTRIBUTE_OFFLINE,	    "OFFLINE"},
	{FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,"NOT_CONTENT_INDEXED"},
	{FILE_ATTRIBUTE_ENCRYPTED,	    "ENCRYPTED"},
	{FILE_ATTRIBUTE_VIRTUAL,	    "VIRTUAL"},
};

/* Prints a directory entry.  @lookup_table is a pointer to the lookup table, if
 * available.  If the dentry is unresolved and the lookup table is NULL, the
 * lookup table entries will not be printed.  Otherwise, they will be. */
int print_dentry(struct dentry *dentry, void *lookup_table)
{
	const u8 *hash;
	struct lookup_table_entry *lte;
	const struct inode *inode = dentry->d_inode;
	time_t time;
	char *p;

	printf("[DENTRY]\n");
	printf("Length            = %"PRIu64"\n", dentry->length);
	printf("Attributes        = 0x%x\n", inode->attributes);
	for (unsigned i = 0; i < ARRAY_LEN(file_attr_flags); i++)
		if (file_attr_flags[i].flag & inode->attributes)
			printf("    FILE_ATTRIBUTE_%s is set\n",
				file_attr_flags[i].name);
	printf("Security ID       = %d\n", inode->security_id);
	printf("Subdir offset     = %"PRIu64"\n", dentry->subdir_offset);

	/* Translate the timestamps into something readable */
	time = wim_timestamp_to_unix(inode->creation_time);
	p = asctime(gmtime(&time));
	*(strrchr(p, '\n')) = '\0';
	printf("Creation Time     = %s UTC\n", p);

	time = wim_timestamp_to_unix(inode->last_access_time);
	p = asctime(gmtime(&time));
	*(strrchr(p, '\n')) = '\0';
	printf("Last Access Time  = %s UTC\n", p);

	time = wim_timestamp_to_unix(inode->last_write_time);
	p = asctime(gmtime(&time));
	*(strrchr(p, '\n')) = '\0';
	printf("Last Write Time   = %s UTC\n", p);

	printf("Reparse Tag       = 0x%"PRIx32"\n", inode->reparse_tag);
	printf("Hard Link Group   = 0x%"PRIx64"\n", inode->ino);
	printf("Hard Link Group Size = %"PRIu32"\n", inode->link_count);
	printf("Number of Alternate Data Streams = %hu\n", inode->num_ads);
	printf("Filename          = \"");
	print_string(dentry->file_name, dentry->file_name_len);
	puts("\"");
	printf("Filename Length   = %hu\n", dentry->file_name_len);
	printf("Filename (UTF-8)  = \"%s\"\n", dentry->file_name_utf8);
	printf("Filename (UTF-8) Length = %hu\n", dentry->file_name_utf8_len);
	printf("Short Name        = \"");
	print_string(dentry->short_name, dentry->short_name_len);
	puts("\"");
	printf("Short Name Length = %hu\n", dentry->short_name_len);
	printf("Full Path (UTF-8) = \"%s\"\n", dentry->full_path_utf8);
	lte = inode_stream_lte(dentry->d_inode, 0, lookup_table);
	if (lte) {
		print_lookup_table_entry(lte);
	} else {
		hash = inode_stream_hash(inode, 0);
		if (hash) {
			printf("Hash              = 0x"); 
			print_hash(hash);
			putchar('\n');
			putchar('\n');
		}
	}
	for (u16 i = 0; i < inode->num_ads; i++) {
		printf("[Alternate Stream Entry %u]\n", i);
		printf("Name = \"%s\"\n", inode->ads_entries[i].stream_name_utf8);
		printf("Name Length (UTF-16) = %u\n",
			inode->ads_entries[i].stream_name_len);
		hash = inode_stream_hash(inode, i + 1);
		if (hash) {
			printf("Hash              = 0x"); 
			print_hash(hash);
			putchar('\n');
		}
		print_lookup_table_entry(inode_stream_lte(inode, i + 1,
							  lookup_table));
	}
	return 0;
}

/* Initializations done on every `struct dentry'. */
static void dentry_common_init(struct dentry *dentry)
{
	memset(dentry, 0, sizeof(struct dentry));
	dentry->refcnt = 1;
}

static struct inode *new_timeless_inode()
{
	struct inode *inode = CALLOC(1, sizeof(struct inode));
	if (!inode)
		return NULL;
	inode->security_id = -1;
	inode->link_count = 1;
#ifdef WITH_FUSE
	inode->next_stream_id = 1;
#endif
	INIT_LIST_HEAD(&inode->dentry_list);
	return inode;
}

static struct inode *new_inode()
{
	struct inode *inode = new_timeless_inode();
	if (!inode)
		return NULL;
	u64 now = get_wim_timestamp();
	inode->creation_time = now;
	inode->last_access_time = now;
	inode->last_write_time = now;
	return inode;
}

/* 
 * Creates an unlinked directory entry.
 *
 * @name:  The UTF-8 filename of the new dentry.
 *
 * Returns a pointer to the new dentry, or NULL if out of memory.
 */
struct dentry *new_dentry(const char *name)
{
	struct dentry *dentry;
	
	dentry = MALLOC(sizeof(struct dentry));
	if (!dentry)
		goto err;

	dentry_common_init(dentry);
	if (change_dentry_name(dentry, name) != 0)
		goto err;

	dentry->next   = dentry;
	dentry->prev   = dentry;
	dentry->parent = dentry;

	return dentry;
err:
	FREE(dentry);
	ERROR("Failed to allocate new dentry");
	return NULL;
}


static struct dentry *__new_dentry_with_inode(const char *name, bool timeless)
{
	struct dentry *dentry;
	dentry = new_dentry(name);
	if (dentry) {
		if (timeless)
			dentry->d_inode = new_timeless_inode();
		else
			dentry->d_inode = new_inode();
		if (dentry->d_inode) {
			inode_add_dentry(dentry, dentry->d_inode);
		} else {
			free_dentry(dentry);
			dentry = NULL;
		}
	}
	return dentry;
}

struct dentry *new_dentry_with_timeless_inode(const char *name)
{
	return __new_dentry_with_inode(name, true);
}

struct dentry *new_dentry_with_inode(const char *name)
{
	return __new_dentry_with_inode(name, false);
}


static int init_ads_entry(struct ads_entry *ads_entry, const char *name)
{
	int ret = 0;
	memset(ads_entry, 0, sizeof(*ads_entry));
	if (name && *name)
		ret = change_ads_name(ads_entry, name);
	return ret;
}

static void destroy_ads_entry(struct ads_entry *ads_entry)
{
	FREE(ads_entry->stream_name);
	FREE(ads_entry->stream_name_utf8);
}


/* Frees an inode. */
void free_inode(struct inode *inode)
{
	if (inode) {
		if (inode->ads_entries) {
			for (u16 i = 0; i < inode->num_ads; i++)
				destroy_ads_entry(&inode->ads_entries[i]);
			FREE(inode->ads_entries);
		}
	#ifdef WITH_FUSE
		wimlib_assert(inode->num_opened_fds == 0);
		FREE(inode->fds);
	#endif
		FREE(inode);
	}
}

/* Decrements link count on an inode and frees it if the link count reaches 0.
 * */
static void put_inode(struct inode *inode)
{
	wimlib_assert(inode);
	wimlib_assert(inode->link_count);
	if (--inode->link_count == 0) {
	#ifdef WITH_FUSE
		if (inode->num_opened_fds == 0)
	#endif
		{
			free_inode(inode);
			inode = NULL;
		}
	}
}

/* Frees a WIM dentry. 
 *
 * The inode is freed only if its link count is decremented to 0.
 */
void free_dentry(struct dentry *dentry)
{
	wimlib_assert(dentry);
	struct inode *inode;

	FREE(dentry->file_name);
	FREE(dentry->file_name_utf8);
	FREE(dentry->short_name);
	FREE(dentry->full_path_utf8);
	put_inode(dentry->d_inode);
	FREE(dentry);
}

void put_dentry(struct dentry *dentry)
{
	wimlib_assert(dentry);
	wimlib_assert(dentry->refcnt);

	if (--dentry->refcnt == 0)
		free_dentry(dentry);
}

/* 
 * This function is passed as an argument to for_dentry_in_tree_depth() in order
 * to free a directory tree.  __args is a pointer to a `struct free_dentry_args'.
 */
static int do_free_dentry(struct dentry *dentry, void *__lookup_table)
{
	struct lookup_table *lookup_table = __lookup_table;
	unsigned i;

	if (lookup_table) {
		struct lookup_table_entry *lte;
		struct inode *inode = dentry->d_inode;
		wimlib_assert(inode->link_count);
		for (i = 0; i <= inode->num_ads; i++) {
			lte = inode_stream_lte(inode, i, lookup_table);
			if (lte)
				lte_decrement_refcnt(lte, lookup_table);
		}
	}

	put_dentry(dentry);
	return 0;
}

/* 
 * Unlinks and frees a dentry tree.
 *
 * @root: 		The root of the tree.
 * @lookup_table:  	The lookup table for dentries.  If non-NULL, the
 * 			reference counts in the lookup table for the lookup
 * 			table entries corresponding to the dentries will be
 * 			decremented.
 */
void free_dentry_tree(struct dentry *root, struct lookup_table *lookup_table)
{
	if (!root || !root->parent)
		return;
	for_dentry_in_tree_depth(root, do_free_dentry, lookup_table);
}

int increment_dentry_refcnt(struct dentry *dentry, void *ignore)
{
	dentry->refcnt++;
	return 0;
}

/* 
 * Links a dentry into the directory tree.
 *
 * @dentry: The dentry to link.
 * @parent: The dentry that will be the parent of @dentry.
 */
void link_dentry(struct dentry *dentry, struct dentry *parent)
{
	wimlib_assert(dentry_is_directory(parent));
	dentry->parent = parent;
	if (parent->d_inode->children) {
		/* Not an only child; link to siblings. */
		dentry->next = parent->d_inode->children;
		dentry->prev = parent->d_inode->children->prev;
		dentry->next->prev = dentry;
		dentry->prev->next = dentry;
	} else {
		/* Only child; link to parent. */
		parent->d_inode->children = dentry;
		dentry->next = dentry;
		dentry->prev = dentry;
	}
}


#ifdef WITH_FUSE
/* 
 * Unlink a dentry from the directory tree. 
 *
 * Note: This merely removes it from the in-memory tree structure.
 */
void unlink_dentry(struct dentry *dentry)
{
	if (dentry_is_root(dentry))
		return;
	if (dentry_is_only_child(dentry)) {
		dentry->parent->d_inode->children = NULL;
	} else {
		if (dentry_is_first_sibling(dentry))
			dentry->parent->d_inode->children = dentry->next;
		dentry->next->prev = dentry->prev;
		dentry->prev->next = dentry->next;
	}
}
#endif

/* Parameters for calculate_dentry_statistics(). */
struct image_statistics {
	struct lookup_table *lookup_table;
	u64 *dir_count;
	u64 *file_count;
	u64 *total_bytes;
	u64 *hard_link_bytes;
};

static int calculate_dentry_statistics(struct dentry *dentry, void *arg)
{
	struct image_statistics *stats;
	struct lookup_table_entry *lte; 
	
	stats = arg;

	if (dentry_is_directory(dentry) && !dentry_is_root(dentry))
		++*stats->dir_count;
	else
		++*stats->file_count;

	for (unsigned i = 0; i <= dentry->d_inode->num_ads; i++) {
		lte = inode_stream_lte(dentry->d_inode, i, stats->lookup_table);
		if (lte) {
			*stats->total_bytes += wim_resource_size(lte);
			if (++lte->out_refcnt == 1)
				*stats->hard_link_bytes += wim_resource_size(lte);
		}
	}
	return 0;
}

/* Calculates some statistics about a dentry tree. */
void calculate_dir_tree_statistics(struct dentry *root, struct lookup_table *table, 
				   u64 *dir_count_ret, u64 *file_count_ret, 
				   u64 *total_bytes_ret, 
				   u64 *hard_link_bytes_ret)
{
	struct image_statistics stats;
	*dir_count_ret         = 0;
	*file_count_ret        = 0;
	*total_bytes_ret       = 0;
	*hard_link_bytes_ret   = 0;
	stats.lookup_table     = table;
	stats.dir_count       = dir_count_ret;
	stats.file_count      = file_count_ret;
	stats.total_bytes     = total_bytes_ret;
	stats.hard_link_bytes = hard_link_bytes_ret;
	for_lookup_table_entry(table, lte_zero_out_refcnt, NULL);
	for_dentry_in_tree(root, calculate_dentry_statistics, &stats);
}

static inline struct dentry *inode_first_dentry(struct inode *inode)
{
	wimlib_assert(inode->dentry_list.next != &inode->dentry_list);
	return container_of(inode->dentry_list.next, struct dentry,
		 	    inode_dentry_list);
}

static int verify_inode(struct inode *inode, const WIMStruct *w)
{
	const struct lookup_table *table = w->lookup_table;
	const struct wim_security_data *sd = wim_const_security_data(w);
	const struct dentry *first_dentry = inode_first_dentry(inode);
	int ret = WIMLIB_ERR_INVALID_DENTRY;

	/* Check the security ID */
	if (inode->security_id < -1) {
		ERROR("Dentry `%s' has an invalid security ID (%d)",
			first_dentry->full_path_utf8, inode->security_id);
		goto out;
	}
	if (inode->security_id >= sd->num_entries) {
		ERROR("Dentry `%s' has an invalid security ID (%d) "
		      "(there are only %u entries in the security table)",
			first_dentry->full_path_utf8, inode->security_id,
			sd->num_entries);
		goto out;
	}

	/* Check that lookup table entries for all the resources exist, except
	 * if the SHA1 message digest is all 0's, which indicates there is
	 * intentionally no resource there.  */
	if (w->hdr.total_parts == 1) {
		for (unsigned i = 0; i <= inode->num_ads; i++) {
			struct lookup_table_entry *lte;
			const u8 *hash;
			hash = inode_stream_hash_unresolved(inode, i);
			lte = __lookup_resource(table, hash);
			if (!lte && !is_zero_hash(hash)) {
				ERROR("Could not find lookup table entry for stream "
				      "%u of dentry `%s'", i, first_dentry->full_path_utf8);
				goto out;
			}
			if (lte && (lte->real_refcnt += inode->link_count) > lte->refcnt)
			{
			#ifdef ENABLE_ERROR_MESSAGES
				WARNING("The following lookup table entry "
					"has a reference count of %u, but",
					lte->refcnt);
				WARNING("We found %zu references to it",
					lte->real_refcnt);
				WARNING("(One dentry referencing it is at `%s')",
					 first_dentry->full_path_utf8);

				print_lookup_table_entry(lte);
			#endif
				/* Guess what!  install.wim for Windows 8
				 * contains a stream with 2 dentries referencing
				 * it, but the lookup table entry has reference
				 * count of 1.  So we will need to handle this
				 * case and not just make it be an error...  I'm
				 * just setting the reference count to the
				 * number of references we found.
				 * (Unfortunately, even after doing this, the
				 * reference count could be too low if it's also
				 * referenced in other WIM images) */

			#if 1
				lte->refcnt = lte->real_refcnt;
				WARNING("Fixing reference count");
			#else
				goto out;
			#endif
			}
		}
	}

	/* Make sure there is only one un-named stream. */
	unsigned num_unnamed_streams = 0;
	for (unsigned i = 0; i <= inode->num_ads; i++) {
		const u8 *hash;
		hash = inode_stream_hash_unresolved(inode, i);
		if (!inode_stream_name_len(inode, i) && !is_zero_hash(hash))
			num_unnamed_streams++;
	}
	if (num_unnamed_streams > 1) {
		ERROR("Dentry `%s' has multiple (%u) un-named streams", 
		      first_dentry->full_path_utf8, num_unnamed_streams);
		goto out;
	}
	inode->verified = true;
	ret = 0;
out:
	return ret;
}

/* Run some miscellaneous verifications on a WIM dentry */
int verify_dentry(struct dentry *dentry, void *wim)
{
	const WIMStruct *w = wim;
	const struct inode *inode = dentry->d_inode;
	int ret = WIMLIB_ERR_INVALID_DENTRY;

	if (!dentry->d_inode->verified) {
		ret = verify_inode(dentry->d_inode, w);
		if (ret != 0)
			goto out;
	}

	/* Cannot have a short name but no long name */
	if (dentry->short_name_len && !dentry->file_name_len) {
		ERROR("Dentry `%s' has a short name but no long name",
		      dentry->full_path_utf8);
		goto out;
	}

	/* Make sure root dentry is unnamed */
	if (dentry_is_root(dentry)) {
		if (dentry->file_name_len) {
			ERROR("The root dentry is named `%s', but it must "
			      "be unnamed", dentry->file_name_utf8);
			goto out;
		}
	}

#if 0
	/* Check timestamps */
	if (inode->last_access_time < inode->creation_time ||
	    inode->last_write_time < inode->creation_time) {
		WARNING("Dentry `%s' was created after it was last accessed or "
		      "written to", dentry->full_path_utf8);
	}
#endif

	ret = 0;
out:
	return ret;
}


#ifdef WITH_FUSE
/* Returns the alternate data stream entry belonging to @inode that has the
 * stream name @stream_name. */
struct ads_entry *inode_get_ads_entry(struct inode *inode,
				      const char *stream_name,
				      u16 *idx_ret)
{
	size_t stream_name_len;
	if (!stream_name)
		return NULL;
	if (inode->num_ads) {
		u16 i = 0;
		stream_name_len = strlen(stream_name);
		do {
			if (ads_entry_has_name(&inode->ads_entries[i],
					       stream_name, stream_name_len))
			{
				if (idx_ret)
					*idx_ret = i;
				return &inode->ads_entries[i];
			}
		} while (++i != inode->num_ads);
	}
	return NULL;
}
#endif

#if defined(WITH_FUSE) || defined(WITH_NTFS_3G)
/* 
 * Add an alternate stream entry to an inode and return a pointer to it, or NULL
 * if memory could not be allocated.
 */
struct ads_entry *inode_add_ads(struct inode *inode, const char *stream_name)
{
	u16 num_ads;
	struct ads_entry *ads_entries;
	struct ads_entry *new_entry;

	DEBUG("Add alternate data stream \"%s\"", stream_name);

	if (inode->num_ads >= 0xfffe) {
		ERROR("Too many alternate data streams in one inode!");
		return NULL;
	}
 	num_ads = inode->num_ads + 1;
	ads_entries = REALLOC(inode->ads_entries,
			      num_ads * sizeof(inode->ads_entries[0]));
	if (!ads_entries) {
		ERROR("Failed to allocate memory for new alternate data stream");
		return NULL;
	}
	inode->ads_entries = ads_entries;

	new_entry = &inode->ads_entries[num_ads - 1];
	if (init_ads_entry(new_entry, stream_name) != 0)
		return NULL;
#ifdef WITH_FUSE
	new_entry->stream_id = inode->next_stream_id++;
#endif
	inode->num_ads = num_ads;
	return new_entry;
}
#endif

#ifdef WITH_FUSE
/* Remove an alternate data stream from the inode  */
void inode_remove_ads(struct inode *inode, u16 idx,
		      struct lookup_table *lookup_table)
{
	struct ads_entry *ads_entry;
	struct lookup_table_entry *lte;

	wimlib_assert(idx < inode->num_ads);
	wimlib_assert(inode->resolved);

	ads_entry = &inode->ads_entries[idx];

	DEBUG("Remove alternate data stream \"%s\"", ads_entry->stream_name_utf8);

	lte = ads_entry->lte;
	if (lte)
		lte_decrement_refcnt(lte, lookup_table);

	destroy_ads_entry(ads_entry);

	memcpy(&inode->ads_entries[idx],
	       &inode->ads_entries[idx + 1],
	       (inode->num_ads - idx - 1) * sizeof(inode->ads_entries[0]));
	inode->num_ads--;
}
#endif



/* 
 * Reads the alternate data stream entries for a dentry.
 *
 * @p:	Pointer to buffer that starts with the first alternate stream entry.
 *
 * @inode:	Inode to load the alternate data streams into.
 * 			@inode->num_ads must have been set to the number of
 * 			alternate data streams that are expected.
 *
 * @remaining_size:	Number of bytes of data remaining in the buffer pointed
 * 				to by @p.
 *
 * The format of the on-disk alternate stream entries is as follows:
 *
 * struct ads_entry_on_disk {
 * 	u64  length;          // Length of the entry, in bytes.  This includes
 *				    all fields (including the stream name and 
 *				    null terminator if present, AND the padding!).
 * 	u64  reserved;        // Seems to be unused
 * 	u8   hash[20];        // SHA1 message digest of the uncompressed stream
 * 	u16  stream_name_len; // Length of the stream name, in bytes
 * 	char stream_name[];   // Stream name in UTF-16LE, @stream_name_len bytes long,
 *                                  not including null terminator
 * 	u16  zero;            // UTF-16 null terminator for the stream name, NOT
 * 	                            included in @stream_name_len.  Based on what
 * 	                            I've observed from filenames in dentries,
 * 	                            this field should not exist when
 * 	                            (@stream_name_len == 0), but you can't
 * 	                            actually tell because of the padding anyway
 * 	                            (provided that the padding is zeroed, which
 * 	                            it always seems to be).
 *	char padding[];       // Padding to make the size a multiple of 8 bytes.
 * };
 *
 * In addition, the entries are 8-byte aligned.
 *
 * Return 0 on success or nonzero on failure.  On success, inode->ads_entries
 * is set to an array of `struct ads_entry's of length inode->num_ads.  On
 * failure, @inode is not modified.
 */
static int read_ads_entries(const u8 *p, struct inode *inode,
			    u64 remaining_size)
{
	u16 num_ads;
	struct ads_entry *ads_entries;
	int ret;

 	num_ads = inode->num_ads;
 	ads_entries = CALLOC(num_ads, sizeof(inode->ads_entries[0]));
	if (!ads_entries) {
		ERROR("Could not allocate memory for %"PRIu16" "
		      "alternate data stream entries", num_ads);
		return WIMLIB_ERR_NOMEM;
	}

	for (u16 i = 0; i < num_ads; i++) {
		struct ads_entry *cur_entry;
		u64 length;
		u64 length_no_padding;
		u64 total_length;
		size_t utf8_len;
		const u8 *p_save = p;

		cur_entry = &ads_entries[i];

	#ifdef WITH_FUSE
		ads_entries[i].stream_id = i + 1;
	#endif

		/* Read the base stream entry, excluding the stream name. */
		if (remaining_size < WIM_ADS_ENTRY_DISK_SIZE) {
			ERROR("Stream entries go past end of metadata resource");
			ERROR("(remaining_size = %"PRIu64")", remaining_size);
			ret = WIMLIB_ERR_INVALID_DENTRY;
			goto out_free_ads_entries;
		}

		p = get_u64(p, &length);
		p += 8; /* Skip the reserved field */
		p = get_bytes(p, SHA1_HASH_SIZE, (u8*)cur_entry->hash);
		p = get_u16(p, &cur_entry->stream_name_len);

		cur_entry->stream_name = NULL;
		cur_entry->stream_name_utf8 = NULL;

		/* Length including neither the null terminator nor the padding
		 * */
		length_no_padding = WIM_ADS_ENTRY_DISK_SIZE +
				    cur_entry->stream_name_len;

		/* Length including the null terminator and the padding */
		total_length = ((length_no_padding + 2) + 7) & ~7;

		wimlib_assert(total_length == ads_entry_total_length(cur_entry));

		if (remaining_size < length_no_padding) {
			ERROR("Stream entries go past end of metadata resource");
			ERROR("(remaining_size = %"PRIu64" bytes, "
			      "length_no_padding = %"PRIu64" bytes)",
			      remaining_size, length_no_padding);
			ret = WIMLIB_ERR_INVALID_DENTRY;
			goto out_free_ads_entries;
		}

		/* The @length field in the on-disk ADS entry is expected to be
		 * equal to @total_length, which includes all of the entry and
		 * the padding that follows it to align the next ADS entry to an
		 * 8-byte boundary.  However, to be safe, we'll accept the
		 * length field as long as it's not less than the un-padded
		 * total length and not more than the padded total length. */
		if (length < length_no_padding || length > total_length) {
			ERROR("Stream entry has unexpected length "
			      "field (length field = %"PRIu64", "
			      "unpadded total length = %"PRIu64", "
			      "padded total length = %"PRIu64")",
			      length, length_no_padding, total_length);
			ret = WIMLIB_ERR_INVALID_DENTRY;
			goto out_free_ads_entries;
		}

		if (cur_entry->stream_name_len) {
			cur_entry->stream_name = MALLOC(cur_entry->stream_name_len);
			if (!cur_entry->stream_name) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_ads_entries;
			}
			get_bytes(p, cur_entry->stream_name_len,
				  (u8*)cur_entry->stream_name);
			cur_entry->stream_name_utf8 = utf16_to_utf8(cur_entry->stream_name,
								    cur_entry->stream_name_len,
								    &utf8_len);
			cur_entry->stream_name_utf8_len = utf8_len;

			if (!cur_entry->stream_name_utf8) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_ads_entries;
			}
		}
		/* It's expected that the size of every ADS entry is a multiple
		 * of 8.  However, to be safe, I'm allowing the possibility of
		 * an ADS entry at the very end of the metadata resource ending
		 * un-aligned.  So although we still need to increment the input
		 * pointer by @total_length to reach the next ADS entry, it's
		 * possible that less than @total_length is actually remaining
		 * in the metadata resource. We should set the remaining size to
		 * 0 bytes if this happens. */
		p = p_save + total_length;
		if (remaining_size < total_length)
			remaining_size = 0;
		else
			remaining_size -= total_length;
	}
	inode->ads_entries = ads_entries;
#ifdef WITH_FUSE
	inode->next_stream_id = inode->num_ads + 1;
#endif
	return 0;
out_free_ads_entries:
	for (u16 i = 0; i < num_ads; i++)
		destroy_ads_entry(&ads_entries[i]);
	FREE(ads_entries);
	return ret;
}

/* 
 * Reads a directory entry, including all alternate data stream entries that
 * follow it, from the WIM image's metadata resource.
 *
 * @metadata_resource:	Buffer containing the uncompressed metadata resource.
 * @metadata_resource_len:   Length of the metadata resource.
 * @offset:	Offset of this directory entry in the metadata resource.
 * @dentry:	A `struct dentry' that will be filled in by this function.
 *
 * Return 0 on success or nonzero on failure.  On failure, @dentry have been
 * modified, bu it will be left with no pointers to any allocated buffers.
 * On success, the dentry->length field must be examined.  If zero, this was a
 * special "end of directory" dentry and not a real dentry.  If nonzero, this
 * was a real dentry.
 */
int read_dentry(const u8 metadata_resource[], u64 metadata_resource_len, 
		u64 offset, struct dentry *dentry)
{
	const u8 *p;
	u64 calculated_size;
	char *file_name = NULL;
	char *file_name_utf8 = NULL;
	char *short_name = NULL;
	u16 short_name_len;
	u16 file_name_len;
	size_t file_name_utf8_len = 0;
	int ret;
	struct inode *inode = NULL;

	dentry_common_init(dentry);

	/*Make sure the dentry really fits into the metadata resource.*/
	if (offset + 8 > metadata_resource_len || offset + 8 < offset) {
		ERROR("Directory entry starting at %"PRIu64" ends past the "
		      "end of the metadata resource (size %"PRIu64")",
		      offset, metadata_resource_len);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	/* Before reading the whole dentry, we need to read just the length.
	 * This is because a dentry of length 8 (that is, just the length field)
	 * terminates the list of sibling directory entries. */

	p = get_u64(&metadata_resource[offset], &dentry->length);

	/* A zero length field (really a length of 8, since that's how big the
	 * directory entry is...) indicates that this is the end of directory
	 * dentry.  We do not read it into memory as an actual dentry, so just
	 * return successfully in that case. */
	if (dentry->length == 0)
		return 0;

	/* If the dentry does not overflow the metadata resource buffer and is
	 * not too short, read the rest of it (excluding the alternate data
	 * streams, but including the file name and short name variable-length
	 * fields) into memory. */
	if (offset + dentry->length >= metadata_resource_len
	    || offset + dentry->length < offset)
	{
		ERROR("Directory entry at offset %"PRIu64" and with size "
		      "%"PRIu64" ends past the end of the metadata resource "
		      "(size %"PRIu64")",
		      offset, dentry->length, metadata_resource_len);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	if (dentry->length < WIM_DENTRY_DISK_SIZE) {
		ERROR("Directory entry has invalid length of %"PRIu64" bytes",
		      dentry->length);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	inode = new_timeless_inode();
	if (!inode)
		return WIMLIB_ERR_NOMEM;

	p = get_u32(p, &inode->attributes);
	p = get_u32(p, (u32*)&inode->security_id);
	p = get_u64(p, &dentry->subdir_offset);

	/* 2 unused fields */
	p += 2 * sizeof(u64);
	/*p = get_u64(p, &dentry->unused1);*/
	/*p = get_u64(p, &dentry->unused2);*/

	p = get_u64(p, &inode->creation_time);
	p = get_u64(p, &inode->last_access_time);
	p = get_u64(p, &inode->last_write_time);

	p = get_bytes(p, SHA1_HASH_SIZE, inode->hash);
	
	/*
	 * I don't know what's going on here.  It seems like M$ screwed up the
	 * reparse points, then put the fields in the same place and didn't
	 * document it.  The WIM_HDR_FLAG_RP_FIX flag in the WIM header might
	 * have something to do with this, but it's not documented.
	 */
	if (inode->attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		/* ??? */
		p += 4;
		p = get_u32(p, &inode->reparse_tag);
		p += 4;
	} else {
		p = get_u32(p, &inode->reparse_tag);
		p = get_u64(p, &inode->ino);
	}

	/* By the way, the reparse_reserved field does not actually exist (at
	 * least when the file is not a reparse point) */
	
	p = get_u16(p, &inode->num_ads);

	p = get_u16(p, &short_name_len);
	p = get_u16(p, &file_name_len);

	/* We now know the length of the file name and short name.  Make sure
	 * the length of the dentry is large enough to actually hold them. 
	 *
	 * The calculated length here is unaligned to allow for the possibility
	 * that the dentry->length names an unaligned length, although this
	 * would be unexpected. */
	calculated_size = __dentry_correct_length_unaligned(file_name_len,
							    short_name_len);

	if (dentry->length < calculated_size) {
		ERROR("Unexpected end of directory entry! (Expected "
		      "at least %"PRIu64" bytes, got %"PRIu64" bytes. "
		      "short_name_len = %hu, file_name_len = %hu)", 
		      calculated_size, dentry->length,
		      short_name_len, file_name_len);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	/* Read the filename if present.  Note: if the filename is empty, there
	 * is no null terminator following it. */
	if (file_name_len) {
		file_name = MALLOC(file_name_len);
		if (!file_name) {
			ERROR("Failed to allocate %hu bytes for dentry file name",
			      file_name_len);
			return WIMLIB_ERR_NOMEM;
		}
		p = get_bytes(p, file_name_len, file_name);

		/* Convert filename to UTF-8. */
		file_name_utf8 = utf16_to_utf8(file_name, file_name_len, 
					       &file_name_utf8_len);

		if (!file_name_utf8) {
			ERROR("Failed to allocate memory to convert UTF-16 "
			      "filename (%hu bytes) to UTF-8", file_name_len);
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_file_name;
		}
		if (*(u16*)p)
			WARNING("Expected two zero bytes following the file name "
				"`%s', but found non-zero bytes", file_name_utf8);
		p += 2;
	}

	/* Align the calculated size */
	calculated_size = (calculated_size + 7) & ~7;

	if (dentry->length > calculated_size) {
		/* Weird; the dentry says it's longer than it should be.  Note
		 * that the length field does NOT include the size of the
		 * alternate stream entries. */

		/* Strangely, some directory entries inexplicably have a little
		 * over 70 bytes of extra data.  The exact amount of data seems
		 * to be 72 bytes, but it is aligned on the next 8-byte
		 * boundary.  It does NOT seem to be alternate data stream
		 * entries.  Here's an example of the aligned data:
		 *
		 * 01000000 40000000 6c786bba c58ede11 b0bb0026 1870892a b6adb76f
		 * e63a3e46 8fca8653 0d2effa1 6c786bba c58ede11 b0bb0026 1870892a
		 * 00000000 00000000 00000000 00000000
		 *
		 * Here's one interpretation of how the data is laid out.
		 *
		 * struct unknown {
		 * 	u32 field1; (always 0x00000001)
		 * 	u32 field2; (always 0x40000000)
		 * 	u8  data[48]; (???)
		 * 	u64 reserved1; (always 0)
		 * 	u64 reserved2; (always 0)
		 * };*/
		DEBUG("Dentry for file or directory `%s' has %zu extra "
		      "bytes of data",
		      file_name_utf8, dentry->length - calculated_size);
	}

	/* Read the short filename if present.  Note: if there is no short
	 * filename, there is no null terminator following it. */
	if (short_name_len) {
		short_name = MALLOC(short_name_len);
		if (!short_name) {
			ERROR("Failed to allocate %hu bytes for short filename",
			      short_name_len);
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_file_name_utf8;
		}

		p = get_bytes(p, short_name_len, short_name);
		if (*(u16*)p)
			WARNING("Expected two zero bytes following the file name "
				"`%s', but found non-zero bytes", file_name_utf8);
		p += 2;
	}

	/* 
	 * Read the alternate data streams, if present.  dentry->num_ads tells
	 * us how many they are, and they will directly follow the dentry
	 * on-disk.
	 *
	 * Note that each alternate data stream entry begins on an 8-byte
	 * aligned boundary, and the alternate data stream entries are NOT
	 * included in the dentry->length field for some reason.
	 */
	if (inode->num_ads != 0) {
		if (calculated_size > metadata_resource_len - offset) {
			ERROR("Not enough space in metadata resource for "
			      "alternate stream entries");
			ret = WIMLIB_ERR_INVALID_DENTRY;
			goto out_free_short_name;
		}
		ret = read_ads_entries(&metadata_resource[offset + calculated_size],
				       inode,
				       metadata_resource_len - offset - calculated_size);
		if (ret != 0)
			goto out_free_short_name;
	}

	/* We've read all the data for this dentry.  Set the names and their
	 * lengths, and we've done. */
	dentry->d_inode              = inode;
	dentry->file_name          = file_name;
	dentry->file_name_utf8     = file_name_utf8;
	dentry->short_name         = short_name;
	dentry->file_name_len      = file_name_len;
	dentry->file_name_utf8_len = file_name_utf8_len;
	dentry->short_name_len     = short_name_len;
	return 0;
out_free_short_name:
	FREE(short_name);
out_free_file_name_utf8:
	FREE(file_name_utf8);
out_free_file_name:
	FREE(file_name);
out_free_inode:
	free_inode(inode);
	return ret;
}

/* Reads the children of a dentry, and all their children, ..., etc. from the
 * metadata resource and into the dentry tree.
 *
 * @metadata_resource:	An array that contains the uncompressed metadata
 * 			resource for the WIM file.
 *
 * @metadata_resource_len:  The length of the uncompressed metadata resource, in
 * 			    bytes.
 *
 * @dentry:	A pointer to a `struct dentry' that is the root of the directory
 *		tree and has already been read from the metadata resource.  It
 *		does not need to be the real root because this procedure is
 *		called recursively.
 *
 * @return:	Zero on success, nonzero on failure.
 */
int read_dentry_tree(const u8 metadata_resource[], u64 metadata_resource_len,
		     struct dentry *dentry)
{
	u64 cur_offset = dentry->subdir_offset;
	struct dentry *prev_child = NULL;
	struct dentry *first_child = NULL;
	struct dentry *child;
	struct dentry cur_child;
	int ret;

	/* 
	 * If @dentry has no child dentries, nothing more needs to be done for
	 * this branch.  This is the case for regular files, symbolic links, and
	 * *possibly* empty directories (although an empty directory may also
	 * have one child dentry that is the special end-of-directory dentry)
	 */
	if (cur_offset == 0)
		return 0;

	/* Find and read all the children of @dentry. */
	while (1) {

		/* Read next child of @dentry into @cur_child. */
		ret = read_dentry(metadata_resource, metadata_resource_len, 
				  cur_offset, &cur_child);
		if (ret != 0)
			break;

		/* Check for end of directory. */
		if (cur_child.length == 0)
			break;

		/* Not end of directory.  Allocate this child permanently and
		 * link it to the parent and previous child. */
		child = MALLOC(sizeof(struct dentry));
		if (!child) {
			ERROR("Failed to allocate %zu bytes for new dentry",
			      sizeof(struct dentry));
			ret = WIMLIB_ERR_NOMEM;
			break;
		}
		memcpy(child, &cur_child, sizeof(struct dentry));

		if (prev_child) {
			prev_child->next = child;
			child->prev = prev_child;
		} else {
			first_child = child;
		}

		child->parent = dentry;
		prev_child = child;
		inode_add_dentry(child, child->d_inode);

		/* If there are children of this child, call this procedure
		 * recursively. */
		if (child->subdir_offset != 0) {
			ret = read_dentry_tree(metadata_resource, 
					       metadata_resource_len, child);
			if (ret != 0)
				break;
		}

		/* Advance to the offset of the next child.  Note: We need to
		 * advance by the TOTAL length of the dentry, not by the length
		 * child->length, which although it does take into account the
		 * padding, it DOES NOT take into account alternate stream
		 * entries. */
		cur_offset += dentry_total_length(child);
	}

	/* Link last child to first one, and set parent's children pointer to
	 * the first child.  */
	if (prev_child) {
		prev_child->next = first_child;
		first_child->prev = prev_child;
	}
	dentry->d_inode->children = first_child;
	return ret;
}

/* 
 * Writes a WIM dentry to an output buffer.
 *
 * @dentry:  The dentry structure.
 * @p:       The memory location to write the data to.
 * @return:  Pointer to the byte after the last byte we wrote as part of the
 * 		dentry.
 */
static u8 *write_dentry(const struct dentry *dentry, u8 *p)
{
	u8 *orig_p = p;
	const u8 *hash;
	const struct inode *inode = dentry->d_inode;

	/* We calculate the correct length of the dentry ourselves because the
	 * dentry->length field may been set to an unexpected value from when we
	 * read the dentry in (for example, there may have been unknown data
	 * appended to the end of the dentry...) */
	u64 length = dentry_correct_length(dentry);

	p = put_u64(p, length);
	p = put_u32(p, inode->attributes);
	p = put_u32(p, inode->security_id);
	p = put_u64(p, dentry->subdir_offset);
	p = put_u64(p, 0); /* unused1 */
	p = put_u64(p, 0); /* unused2 */
	p = put_u64(p, inode->creation_time);
	p = put_u64(p, inode->last_access_time);
	p = put_u64(p, inode->last_write_time);
	hash = inode_stream_hash(inode, 0);
	p = put_bytes(p, SHA1_HASH_SIZE, hash);
	if (inode->attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		p = put_zeroes(p, 4);
		p = put_u32(p, inode->reparse_tag);
		p = put_zeroes(p, 4);
	} else {
		u64 link_group_id;
		p = put_u32(p, 0);
		if (inode->link_count == 1)
			link_group_id = 0;
		else
			link_group_id = inode->ino;
		p = put_u64(p, link_group_id);
	}
	p = put_u16(p, inode->num_ads);
	p = put_u16(p, dentry->short_name_len);
	p = put_u16(p, dentry->file_name_len);
	if (dentry->file_name_len) {
		p = put_bytes(p, dentry->file_name_len, (u8*)dentry->file_name);
		p = put_u16(p, 0); /* filename padding, 2 bytes. */
	}
	if (dentry->short_name) {
		p = put_bytes(p, dentry->short_name_len, (u8*)dentry->short_name);
		p = put_u16(p, 0); /* short name padding, 2 bytes */
	}

	/* Align to 8-byte boundary */
	wimlib_assert(length >= (p - orig_p) && length - (p - orig_p) <= 7);
	p = put_zeroes(p, length - (p - orig_p));

	/* Write the alternate data streams, if there are any.  Please see
	 * read_ads_entries() for comments about the format of the on-disk
	 * alternate data stream entries. */
	for (u16 i = 0; i < inode->num_ads; i++) {
		p = put_u64(p, ads_entry_total_length(&inode->ads_entries[i]));
		p = put_u64(p, 0); /* Unused */
		hash = inode_stream_hash(inode, i + 1);
		p = put_bytes(p, SHA1_HASH_SIZE, hash);
		p = put_u16(p, inode->ads_entries[i].stream_name_len);
		if (inode->ads_entries[i].stream_name_len) {
			p = put_bytes(p, inode->ads_entries[i].stream_name_len,
					 (u8*)inode->ads_entries[i].stream_name);
			p = put_u16(p, 0);
		}
		p = put_zeroes(p, (8 - (p - orig_p) % 8) % 8);
	}
	wimlib_assert(p - orig_p == __dentry_total_length(dentry, length));
	return p;
}

/* Recursive function that writes a dentry tree rooted at @parent, not including
 * @parent itself, which has already been written. */
static u8 *write_dentry_tree_recursive(const struct dentry *parent, u8 *p)
{
	const struct dentry *child;

	/* Nothing to do if this dentry has no children. */
	if (parent->subdir_offset == 0)
		return p;

	/* Write child dentries and end-of-directory entry. 
	 *
	 * Note: we need to write all of this dentry's children before
	 * recursively writing the directory trees rooted at each of the child
	 * dentries, since the on-disk dentries for a dentry's children are
	 * always located at consecutive positions in the metadata resource! */
	child = parent->d_inode->children;
	if (child) {
		do {
			p = write_dentry(child, p);
			child = child->next;
		} while (child != parent->d_inode->children);
	}

	/* write end of directory entry */
	p = put_u64(p, 0);

	/* Recurse on children. */
	if (child) {
		do {
			p = write_dentry_tree_recursive(child, p);
			child = child->next;
		} while (child != parent->d_inode->children);
	}
	return p;
}

/* Writes a directory tree to the metadata resource.
 *
 * @root:	Root of the dentry tree.
 * @p:		Pointer to a buffer with enough space for the dentry tree.
 *
 * Returns pointer to the byte after the last byte we wrote.
 */
u8 *write_dentry_tree(const struct dentry *root, u8 *p)
{
	wimlib_assert(dentry_is_root(root));

	/* If we're the root dentry, we have no parent that already
	 * wrote us, so we need to write ourselves. */
	p = write_dentry(root, p);

	/* Write end of directory entry after the root dentry just to be safe;
	 * however the root dentry obviously cannot have any siblings. */
	p = put_u64(p, 0);

	/* Recursively write the rest of the dentry tree. */
	return write_dentry_tree_recursive(root, p);
}

