/*
 * dentry.c
 *
 * A dentry (directory entry) contains the metadata for a file.  In the WIM file
 * format, the dentries are stored in the "metadata resource" section right
 * after the security data.  Each image in the WIM file has its own metadata
 * resource with its own security data and dentry tree.  Dentries in different
 * images may share file resources by referring to the same lookup table
 * entries.
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
#include "dentry.h"
#include "io.h"
#include "timestamp.h"
#include "lookup_table.h"
#include <unistd.h>
#include <sys/stat.h>


/* Transfers file attributes from a `stat' buffer to a struct dentry. */
void stbuf_to_dentry(const struct stat *stbuf, struct dentry *dentry)
{
	if (S_ISDIR(stbuf->st_mode))
		dentry->attributes = WIM_FILE_ATTRIBUTE_DIRECTORY;
	else
		dentry->attributes = WIM_FILE_ATTRIBUTE_NORMAL;
}

/* Transfers file attributes from a struct dentry to a `stat' buffer. */
void dentry_to_stbuf(const struct dentry *dentry, struct stat *stbuf, 
		     const struct lookup_table *table)
{
	struct lookup_table_entry *lte;

	if (dentry_is_directory(dentry))
		stbuf->st_mode = S_IFDIR | 0755;
	else
		stbuf->st_mode = S_IFREG | 0644;

	if (table)
		lte = lookup_resource(table, dentry->hash);
	else
		lte = NULL;

	if (lte) {
		stbuf->st_nlink = lte->refcnt;
		stbuf->st_size = lte->resource_entry.original_size;
	} else {
		stbuf->st_nlink = 1;
		stbuf->st_size = 0;
	}
	stbuf->st_uid     = getuid();
	stbuf->st_gid     = getgid();
	stbuf->st_atime   = ms_timestamp_to_unix(dentry->last_access_time);
	stbuf->st_mtime   = ms_timestamp_to_unix(dentry->last_write_time);
	stbuf->st_ctime   = ms_timestamp_to_unix(dentry->creation_time);
	stbuf->st_blocks  = (stbuf->st_size + 511) / 512;
}

/* Makes all timestamp fields for the dentry be the current time. */
void dentry_update_all_timestamps(struct dentry *dentry)
{
	u64 now = get_timestamp();
	dentry->creation_time       = now;
	dentry->last_access_time    = now;
	dentry->last_write_time     = now;
}

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

	child = root->children;

	if (!child)
		return 0;

	do {
		ret = for_dentry_in_tree(child, visitor, arg);
		if (ret != 0)
			return ret;
		child = child->next;
	} while (child != root->children);
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

	child = root->children;
	if (child) {
		do {
			next = child->next;
			ret = for_dentry_in_tree_depth(child, visitor, arg);
			if (ret != 0)
				return ret;
			child = next;
		} while (child != root->children);
	}
	return visitor(root, arg);
}

/* 
 * Calculate the full path of @dentry, based on its parent's full path and on
 * its UTF-8 file name. 
 */
int calculate_dentry_full_path(struct dentry *dentry, void *ignore)
{
	int parent_len;
	int len;
	char *parent_full_path;
	char *full_path;

	FREE(dentry->full_path_utf8);

	if (dentry_is_root(dentry)) {
		dentry->full_path_utf8 = MALLOC(2);
		if (!dentry->full_path_utf8) {
			ERROR("Out of memory!\n");
			return WIMLIB_ERR_NOMEM;
		}

		dentry->full_path_utf8[0] = '/';
		dentry->full_path_utf8[1] = '\0';
		dentry->full_path_utf8_len = 1;
		return 0;
	}

	if (dentry_is_root(dentry->parent)) {
		parent_len = 0;
		parent_full_path = "";
	} else {
		parent_len = dentry->parent->full_path_utf8_len;
		parent_full_path = dentry->parent->full_path_utf8;
	}

	len = parent_len + 1 + dentry->file_name_utf8_len;
	full_path = MALLOC(len + 1);
	if (!full_path) {
		ERROR("Out of memory!\n");
		return WIMLIB_ERR_NOMEM;
	}

	memcpy(full_path, parent_full_path, parent_len);
	full_path[parent_len] = '/';
	memcpy(full_path + parent_len + 1, dentry->file_name_utf8, 
				dentry->file_name_utf8_len);
	full_path[len] = '\0';
	dentry->full_path_utf8 = full_path;
	dentry->full_path_utf8_len = len;
	return 0;
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

	child = dentry->children;
	dentry->subdir_offset = *subdir_offset_p;
	if (child) {

		/* Advance the subdir offset by the amount of space the children
		 * of this dentry take up. */
		do {
			*subdir_offset_p += child->length;
			child = child->next;
		} while (child != dentry->children);

		/* End-of-directory dentry on disk. */
		*subdir_offset_p += 8;

		/* Recursively call calculate_subdir_offsets() on all the
		 * children. */
		do {
			calculate_subdir_offsets(child, subdir_offset_p);
			child = child->next;
		} while (child != dentry->children);
	} else {
		/* On disk, childless directories have a valid subdir_offset
		 * that points to an 8-byte end-of-directory dentry.  Regular
		 * files have a subdir_offset of 0. */
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
	
	child = dentry->children;
	if (child) {
		name_len = strlen(name);
		do {
			if (dentry_has_name(child, name, name_len))
				return child;
			child = child->next;
		} while (child != dentry->children);
	}
	return NULL;
}

/* Retrieves the dentry that has the UTF-8 @path relative to the dentry
 * @cur_dir.  Returns NULL if no dentry having the path is found. */
static struct dentry *get_dentry_relative_path(struct dentry *cur_dir, const char *path)
{
	struct dentry *child;
	size_t base_len;
	const char *new_path;

	if (*path == '\0')
		return cur_dir;

	child = cur_dir->children;
	if (child) {
		new_path = path_next_part(path, &base_len);
		do {
			if (dentry_has_name(child, path, base_len))
				return get_dentry_relative_path(child, new_path);
			child = child->next;
		} while (child != cur_dir->children);
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

/* Returns the parent directory for the @path. */
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

/* Prints a directory entry.  @lookup_table is a pointer to the lookup table, or
 * NULL if the resource entry for the dentry is not to be printed. */
int print_dentry(struct dentry *dentry, void *lookup_table)
{
	struct lookup_table_entry *lte;

	printf("Length            = %"PRIu64"\n", dentry->length);
	printf("Attributes        = 0x%x\n", dentry->attributes);
	/*printf("Security ID       = %d\n", dentry->security_id);*/
	printf("Subdir offset     = %"PRIu64"\n", dentry->subdir_offset);
	/*printf("Unused1           = %"PRIu64"\n", dentry->unused1);*/
	/*printf("Unused2           = %"PRIu64"\n", dentry->unused2);*/
	printf("Creation Time     = %"PRIu64"\n", dentry->creation_time);
	printf("Last Access Time  = %"PRIu64"\n", dentry->last_access_time);
	printf("Last Write Time   = %"PRIu64"\n", dentry->last_write_time);
	printf("Creation Time     = 0x%"PRIx64"\n", dentry->creation_time);
	printf("Hash              = "); 
	print_hash(dentry->hash); 
	putchar('\n');
	/*printf("Reparse Tag       = %u\n", dentry->reparse_tag);*/
	printf("Hard Link Group   = %"PRIu64"\n", dentry->hard_link);
	/*printf("Number of Streams = %hu\n", dentry->streams);*/
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
	if (lookup_table) {
		lte = lookup_resource(lookup_table, dentry->hash);
		if (lte)
			print_lookup_table_entry(lte, NULL);
		else
			putchar('\n');
	} else {
		putchar('\n');
	}
	return 0;
}

static inline void dentry_common_init(struct dentry *dentry)
{
	memset(dentry, 0, sizeof(struct dentry));
	dentry->refcnt = 1;
	/* We are currently ignoring the security data. */
	/*dentry->security_id = -1;*/
}

/* 
 * Creates an unlinked directory entry.
 *
 * @name:    The base name of the new dentry.
 * @return:  A pointer to the new dentry, or NULL if out of memory.
 */
struct dentry *new_dentry(const char *name)
{
	struct dentry *dentry;
	
	dentry = MALLOC(sizeof(struct dentry));
	if (!dentry)
		return NULL;

	dentry_common_init(dentry);
	if (change_dentry_name(dentry, name) != 0) {
		FREE(dentry);
		return NULL;
	}

	dentry_update_all_timestamps(dentry);
	dentry->next   = dentry;
	dentry->prev   = dentry;
	dentry->parent = dentry;
	return dentry;
}


void free_dentry(struct dentry *dentry)
{
	FREE(dentry->file_name);
	FREE(dentry->file_name_utf8);
	FREE(dentry->short_name);
	FREE(dentry->full_path_utf8);
	FREE(dentry);
}

/* Arguments for do_free_dentry(). */
struct free_dentry_args {
	struct lookup_table *lookup_table;
	bool decrement_refcnt;
};

/* 
 * This function is passed as an argument to for_dentry_in_tree_depth() in order
 * to free a directory tree.  __args is a pointer to a `struct free_dentry_args'.
 */
static int do_free_dentry(struct dentry *dentry, void *__args)
{
	struct free_dentry_args *args = (struct free_dentry_args*)__args;

	if (args->decrement_refcnt && !dentry_is_directory(dentry)) {
		lookup_table_decrement_refcnt(args->lookup_table, 
					      dentry->hash);
	}

	wimlib_assert(dentry->refcnt >= 1);
	if (--dentry->refcnt == 0)
		free_dentry(dentry);
	return 0;
}

/* 
 * Unlinks and frees a dentry tree.
 *
 * @root: 		The root of the tree.
 * @lookup_table:  	The lookup table for dentries.
 * @decrement_refcnt:  	True if the dentries in the tree are to have their 
 * 			reference counts in the lookup table decremented.
 */
void free_dentry_tree(struct dentry *root, struct lookup_table *lookup_table, 
		      bool decrement_refcnt)
{
	if (!root || !root->parent)
		return;

	struct free_dentry_args args;
	args.lookup_table        = lookup_table;
	args.decrement_refcnt    = decrement_refcnt;
	for_dentry_in_tree_depth(root, do_free_dentry, &args);
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
	dentry->parent = parent;
	if (parent->children) {
		/* Not an only child; link to siblings. */
		dentry->next = parent->children;
		dentry->prev = parent->children->prev;
		dentry->next->prev = dentry;
		dentry->prev->next = dentry;
	} else {
		/* Only child; link to parent. */
		parent->children = dentry;
		dentry->next = dentry;
		dentry->prev = dentry;
	}
}

/* Unlink a dentry from the directory tree. */
void unlink_dentry(struct dentry *dentry)
{
	if (dentry_is_root(dentry))
		return;
	if (dentry_is_only_child(dentry)) {
		dentry->parent->children = NULL;
	} else {
		if (dentry_is_first_sibling(dentry))
			dentry->parent->children = dentry->next;
		dentry->next->prev = dentry->prev;
		dentry->prev->next = dentry->next;
	}
}


/* Recalculates the length of @dentry based on its file name length and short
 * name length.  */
static inline void recalculate_dentry_size(struct dentry *dentry)
{
	dentry->length = WIM_DENTRY_DISK_SIZE + dentry->file_name_len + 
			 2 + dentry->short_name_len;
	/* Must be multiple of 8. */
	dentry->length += (8 - dentry->length % 8) % 8;
}

/* Changes the name of a dentry to @new_name.  Only changes the file_name and
 * file_name_utf8 fields; does not change the short_name, short_name_utf8, or
 * full_path_utf8 fields.  Also recalculates its length. */
int change_dentry_name(struct dentry *dentry, const char *new_name)
{
	size_t utf8_len;
	size_t utf16_len;

	FREE(dentry->file_name);

	utf8_len = strlen(new_name);

	dentry->file_name = utf8_to_utf16(new_name, utf8_len, &utf16_len);

	if (!dentry->file_name)
		return WIMLIB_ERR_NOMEM;

	FREE(dentry->file_name_utf8);
	dentry->file_name_utf8 = MALLOC(utf8_len + 1);
	if (!dentry->file_name_utf8) {
		FREE(dentry->file_name);
		dentry->file_name = NULL;
		return WIMLIB_ERR_NOMEM;
	}

	dentry->file_name_len = utf16_len;
	dentry->file_name_utf8_len = utf8_len;
	memcpy(dentry->file_name_utf8, new_name, utf8_len + 1);
	recalculate_dentry_size(dentry);
	return 0;
}

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
	lte = lookup_resource(stats->lookup_table, dentry->hash);

	if (dentry_is_directory(dentry) && !dentry_is_root(dentry))
		++*stats->dir_count;
	else
		++*stats->file_count;

	if (lte) {
		u64 size = lte->resource_entry.original_size;
		*stats->total_bytes += size;
		if (++lte->out_refcnt == 1)
			*stats->hard_link_bytes += size;
	}
	return 0;
}

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
	for_lookup_table_entry(table, zero_out_refcnts, NULL);
	for_dentry_in_tree(root, calculate_dentry_statistics, &stats);
}

/* 
 * Reads a directory entry from the metadata resource.
 */
int read_dentry(const u8 metadata_resource[], u64 metadata_resource_len, 
					u64 offset, struct dentry *dentry)
{
	const u8 *p;
	u64 calculated_size;
	char *file_name;
	char *file_name_utf8;
	char *short_name;
	u16 short_name_len;
	u16 file_name_len;
	size_t file_name_utf8_len;

	dentry_common_init(dentry);

	/*Make sure the dentry really fits into the metadata resource.*/
	if (offset + 8 > metadata_resource_len) {
		ERROR("Directory entry starting at %"PRIu64" ends past the "
			"end of the metadata resource (size %"PRIu64")!\n",
			offset, metadata_resource_len);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	/* Before reading the whole entry, we need to read just the length.
	 * This is because an entry of length 8 (that is, just the length field)
	 * terminates the list of sibling directory entries. */

	p = get_u64(&metadata_resource[offset], &dentry->length);

	/* A zero length field (really a length of 8, since that's how big the
	 * directory entry is...) indicates that this is the end of directory
	 * dentry.  We do not read it into memory as an actual dentry, so just
	 * return true in that case. */
	if (dentry->length == 0)
		return 0;

	if (offset + dentry->length >= metadata_resource_len) {
		ERROR("Directory entry at offset %"PRIu64" and with size "
				"%"PRIu64" ends past the end of the metadata resource "
				"(size %"PRIu64")!\n", offset, dentry->length,
				metadata_resource_len);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	/* If it is a recognized length, read the rest of the directory entry.
	 * Note: The root directory entry has no name, and its length does not
	 * include the short name length field.  */
	if (dentry->length < WIM_DENTRY_DISK_SIZE) {
		ERROR("Directory entry has invalid length of "
				"%"PRIu64" bytes\n", dentry->length);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	p = get_u32(p, &dentry->attributes);
	/* Currently ignoring security ID. */
	p += sizeof(u32);
	p = get_u64(p, &dentry->subdir_offset);

	/* 2 unused fields */
	p += 2 * sizeof(u64);

	p = get_u64(p, &dentry->creation_time);
	p = get_u64(p, &dentry->last_access_time);
	p = get_u64(p, &dentry->last_write_time);

	p = get_bytes(p, WIM_HASH_SIZE, dentry->hash);
	
	/* Currently ignoring reparse_tag. */
	p += sizeof(u32);

	/* The reparse_reserved field does not actually exist. */

	p = get_u64(p, &dentry->hard_link);
	
	/* Currently ignoring streams. */
	p += sizeof(u16);

	p = get_u16(p, &short_name_len);
	p = get_u16(p, &file_name_len);

	calculated_size = WIM_DENTRY_DISK_SIZE + file_name_len + 2 +
			  short_name_len;

	if (dentry->length < calculated_size) {
		ERROR("Unexpected end of directory entry! (Expected "
				"%"PRIu64" bytes, got %"PRIu64" bytes. "
				"short_name_len = %hu, file_name_len = %hu)\n", 
				calculated_size, dentry->length,
				short_name_len, file_name_len);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	/* Read the filename. */
	file_name = MALLOC(file_name_len);
	if (!file_name) {
		ERROR("Failed to allocate %hu bytes for dentry file name!\n",
				file_name_len);
		return WIMLIB_ERR_NOMEM;
	}
	p = get_bytes(p, file_name_len, file_name);

	/* Convert filename to UTF-8. */
	file_name_utf8 = utf16_to_utf8(file_name, file_name_len, 
				       &file_name_utf8_len);

	if (!file_name_utf8) {
		ERROR("Failed to allocate memory to convert UTF16 "
				"filename (%hu bytes) to UTF8\n",
				file_name_len);
		goto err_nomem2;
	}

	/* Undocumented padding between file name and short name.  This probably
	 * is supposed to be a terminating NULL character. */
	p += 2;

	/* Read the short filename. */
	short_name = MALLOC(short_name_len);
	if (!short_name) {
		ERROR("Failed to allocate %hu bytes for short filename\n",
				short_name_len);
		goto err_nomem1;
	}

	get_bytes(p, short_name_len, short_name);

	dentry->file_name          = file_name;
	dentry->file_name_utf8     = file_name_utf8;
	dentry->short_name         = short_name;
	dentry->file_name_len      = file_name_len;
	dentry->file_name_utf8_len = file_name_utf8_len;
	dentry->short_name_len     = short_name_len;
	return 0;
err_nomem1:
	FREE(dentry->file_name_utf8);
err_nomem2:
	FREE(dentry->file_name);
	return WIMLIB_ERR_NOMEM;
}

/* 
 * Writes a dentry to an output buffer.
 *
 * @dentry:  The dentry structure.
 * @p:       The memory location to write the data to.
 * @return:  True on success, false on failure.
 */
static u8 *write_dentry(const struct dentry *dentry, u8 *p)
{
	u8 *orig_p = p;
	memset(p, 0, dentry->length);
	p = put_u64(p, dentry->length);
	p = put_u32(p, dentry->attributes);
	p = put_u32(p, (u32)(-1)); /* security id */
	p = put_u64(p, dentry->subdir_offset);
	p = put_u64(p, 0); /* unused1 */
	p = put_u64(p, 0); /* unused2 */
	p = put_u64(p, dentry->creation_time);
	p = put_u64(p, dentry->last_access_time);
	p = put_u64(p, dentry->last_write_time);
	p = put_bytes(p, WIM_HASH_SIZE, dentry->hash);
	p = put_u32(p, 0); /* reparse_tag */
	p = put_u64(p, dentry->hard_link);
	p = put_u16(p, 0); /*streams */
	p = put_u16(p, dentry->short_name_len);
	p = put_u16(p, dentry->file_name_len);
	p = put_bytes(p, dentry->file_name_len, (u8*)dentry->file_name);
	p = put_u16(p, 0); /* filename padding, 2 bytes. */
	p = put_bytes(p, dentry->short_name_len, (u8*)dentry->short_name);
	return orig_p + dentry->length;
}

/* Recursive function that writes a dentry tree rooted at @tree, not including
 * @tree itself, which has already been written, except in the case of the root
 * dentry, which is written right away, along with an end-of-directory entry. */
u8 *write_dentry_tree(const struct dentry *tree, u8 *p)
{
	const struct dentry *child;

	if (dentry_is_root(tree)) {
		p = write_dentry(tree, p);

		/* write end of directory entry */
		p = put_u64(p, 0);
	} else {
		/* Nothing to do for a regular file. */
		if (dentry_is_regular_file(tree))
			return p;
	}

	/* Write child dentries and end-of-directory entry. */
	child = tree->children;
	if (child) {
		do {
			p = write_dentry(child, p);
			child = child->next;
		} while (child != tree->children);
	}

	/* write end of directory entry */
	p = put_u64(p, 0);

	/* Recurse on children. */
	if (child) {
		do {
			p = write_dentry_tree(child, p);
			child = child->next;
		} while (child != tree->children);
	}
	return p;
}

/* Reads the children of a dentry, and all their children, ..., etc. from the
 * metadata resource and into the dentry tree.
 *
 * @metadata_resource:	An array that contains the uncompressed metadata
 * 				resource for the WIM file.
 * @metadata_resource_len:	The length of @metadata_resource.
 * @dentry:	A pointer to a struct dentry that is the root of the directory tree
 * 		and has already been read from the metadata resource.  It does not 
 * 		need to be the real root, because this procedure is called 
 * 		recursively.
 * @return:	True on success, false on failure. 
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

	/* If @dentry is a regular file, nothing more needs to be done for this
	 * branch. */
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
		if (cur_child.length == 0) {
			ret = 0;
			break;
		}

		/* Not end of directory.  Allocate this child permanently and
		 * link it to the parent and previous child. */
		child = MALLOC(sizeof(struct dentry));
		if (!child) {
			ERROR("Failed to allocate %zu bytes for new dentry!\n",
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

		/* If there are children of this child, call this procedure
		 * recursively. */
		if (child->subdir_offset != 0) {
			ret = read_dentry_tree(metadata_resource, 
					       metadata_resource_len, child);
			if (ret != 0)
				break;
		}

		/* Advance to the offset of the next child. */
		cur_offset += child->length;
	}

	/* Link last child to first one, and set parent's
	 * children pointer to the first child.  */
	if (prev_child) {
		prev_child->next = first_child;
		first_child->prev = prev_child;
	}
	dentry->children = first_child;
	return ret;
}
