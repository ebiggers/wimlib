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
 *
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
#include "io.h"
#include "timestamp.h"
#include "lookup_table.h"
#include "sha1.h"
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

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

/* Real length of a dentry, including the alternate data stream entries, which
 * are not included in the dentry->length field... */
u64 dentry_total_length(const struct dentry *dentry)
{
	u64 length = (dentry->length + 7) & ~7;
	for (u16 i = 0 ; i < dentry->num_ads; i++)
		length += ads_entry_length(&dentry->ads_entries[i]);
	return length;
}

/* Transfers file attributes from a `stat' buffer to a struct dentry. */
void stbuf_to_dentry(const struct stat *stbuf, struct dentry *dentry)
{
	if (S_ISLNK(stbuf->st_mode)) {
		dentry->attributes = FILE_ATTRIBUTE_REPARSE_POINT;
		dentry->reparse_tag = WIM_IO_REPARSE_TAG_SYMLINK;
	} else if (S_ISDIR(stbuf->st_mode)) {
		dentry->attributes = FILE_ATTRIBUTE_DIRECTORY;
	} else {
		dentry->attributes = FILE_ATTRIBUTE_NORMAL;
	}
	if (sizeof(ino_t) >= 8)
		dentry->hard_link = (u64)stbuf->st_ino;
	else
		dentry->hard_link = (u64)stbuf->st_ino |
				   ((u64)stbuf->st_dev << (sizeof(ino_t) * 8));
}


/* Makes all timestamp fields for the dentry be the current time. */
void dentry_update_all_timestamps(struct dentry *dentry)
{
	u64 now = get_timestamp();
	dentry->creation_time    = now;
	dentry->last_access_time = now;
	dentry->last_write_time  = now;
}

struct ads_entry *dentry_get_ads_entry(struct dentry *dentry,
				       const char *stream_name)
{
	size_t stream_name_len = strlen(stream_name);
	if (!stream_name)
		return NULL;
	for (u16 i = 0; i < dentry->num_ads; i++)
		if (ads_entry_has_name(&dentry->ads_entries[i],
				       stream_name, stream_name_len))
			return &dentry->ads_entries[i];
	return NULL;
}

static void ads_entry_init(struct ads_entry *ads_entry)
{
	memset(ads_entry, 0, sizeof(struct ads_entry));
	INIT_LIST_HEAD(&ads_entry->lte_group_list.list);
	ads_entry->lte_group_list.type = STREAM_TYPE_ADS;
}

/* Add an alternate stream entry to a dentry and return a pointer to it, or NULL
 * on failure. */
struct ads_entry *dentry_add_ads(struct dentry *dentry, const char *stream_name)
{
	u16 num_ads = dentry->num_ads + 1;
	struct ads_entry *ads_entries;
	struct ads_entry *new_entry;
	if (num_ads == 0xffff)
		return NULL;
	ads_entries = MALLOC(num_ads * sizeof(struct ads_entry));
	if (!ads_entries)
		return NULL;

	memcpy(ads_entries, dentry->ads_entries,
	       (num_ads - 1) * sizeof(struct ads_entry));

	new_entry = &ads_entries[num_ads - 1];
	if (change_ads_name(new_entry, stream_name) != 0) {
		FREE(ads_entries);
		return NULL;
	}
	ads_entry_init(new_entry);

	FREE(dentry->ads_entries);
	dentry->ads_entries = ads_entries;
	dentry->num_ads = num_ads;
	return new_entry;
}

void dentry_remove_ads(struct dentry *dentry, struct ads_entry *ads_entry)
{
	u16 idx = ads_entry - dentry->ads_entries;
	u16 following = dentry->num_ads - idx - 1;

	destroy_ads_entry(ads_entry);
	memcpy(ads_entry, ads_entry + 1, following * sizeof(struct ads_entry));

	/* We moved the ADS entries.  Adjust the stream lists. */
	for (u16 i = 0; i < following; i++) {
		struct list_head *cur = &ads_entry[i].lte_group_list.list;
		cur->prev->next = cur;
		cur->next->prev = cur;
	}

	dentry->num_ads--;
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

	child = dentry->children;
	dentry->subdir_offset = *subdir_offset_p;
	if (child) {

		/* Advance the subdir offset by the amount of space the children
		 * of this dentry take up. */
		do {
			*subdir_offset_p += dentry_total_length(child);
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

struct file_attr_flag {
	u32 flag;
	const char *name;
};
struct file_attr_flag file_attr_flags[] = {
	{FILE_ATTRIBUTE_READONLY,		"READONLY"},
	{FILE_ATTRIBUTE_HIDDEN,		"HIDDEN"},
	{FILE_ATTRIBUTE_SYSTEM,		"SYSTEM"},
	{FILE_ATTRIBUTE_DIRECTORY,		"DIRECTORY"},
	{FILE_ATTRIBUTE_ARCHIVE,		"ARCHIVE"},
	{FILE_ATTRIBUTE_DEVICE,		"DEVICE"},
	{FILE_ATTRIBUTE_NORMAL,		"NORMAL"},
	{FILE_ATTRIBUTE_TEMPORARY,		"TEMPORARY"},
	{FILE_ATTRIBUTE_SPARSE_FILE,	"SPARSE_FILE"},
	{FILE_ATTRIBUTE_REPARSE_POINT,	"REPARSE_POINT"},
	{FILE_ATTRIBUTE_COMPRESSED,		"COMPRESSED"},
	{FILE_ATTRIBUTE_OFFLINE,		"OFFLINE"},
	{FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,"NOT_CONTENT_INDEXED"},
	{FILE_ATTRIBUTE_ENCRYPTED,		"ENCRYPTED"},
	{FILE_ATTRIBUTE_VIRTUAL,		"VIRTUAL"},
};

/* Prints a directory entry.  @lookup_table is a pointer to the lookup table, or
 * NULL if the resource entry for the dentry is not to be printed. */
int print_dentry(struct dentry *dentry, void *lookup_table)
{
	struct lookup_table_entry *lte;
	unsigned i;

	printf("[DENTRY]\n");
	printf("Length            = %"PRIu64"\n", dentry->length);
	printf("Attributes        = 0x%x\n", dentry->attributes);
	for (i = 0; i < ARRAY_LEN(file_attr_flags); i++)
		if (file_attr_flags[i].flag & dentry->attributes)
			printf("    FILE_ATTRIBUTE_%s is set\n",
				file_attr_flags[i].name);
	printf("Security ID       = %d\n", dentry->security_id);
	printf("Subdir offset     = %"PRIu64"\n", dentry->subdir_offset);
	/*printf("Unused1           = 0x%"PRIu64"\n", dentry->unused1);*/
	/*printf("Unused2           = %"PRIu64"\n", dentry->unused2);*/
	printf("Creation Time     = 0x%"PRIx64"\n", dentry->creation_time);
	printf("Last Access Time  = 0x%"PRIx64"\n", dentry->last_access_time);
	printf("Last Write Time   = 0x%"PRIx64"\n", dentry->last_write_time);
	printf("Hash              = 0x"); 
	print_hash(dentry->hash); 
	putchar('\n');
	printf("Reparse Tag       = 0x%"PRIx32"\n", dentry->reparse_tag);
	printf("Hard Link Group   = 0x%"PRIx64"\n", dentry->hard_link);
	printf("Number of Alternate Data Streams = %hu\n", dentry->num_ads);
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
	if (lookup_table && (lte = __lookup_resource(lookup_table, dentry->hash)))
		print_lookup_table_entry(lte, NULL);
	else
		putchar('\n');
	for (u16 i = 0; i < dentry->num_ads; i++) {
		printf("[Alternate Stream Entry %u]\n", i);
		printf("Name = \"%s\"\n", dentry->ads_entries[i].stream_name_utf8);
		printf("Name Length (UTF-16) = %u\n",
				dentry->ads_entries[i].stream_name_len);
		printf("Hash              = 0x"); 
		print_hash(dentry->ads_entries[i].hash); 
		if (lookup_table &&
		     (lte = __lookup_resource(lookup_table,
					      dentry->ads_entries[i].hash)))
		{
			print_lookup_table_entry(lte, NULL);
		} else {
			putchar('\n');
		}
	}
	return 0;
}

static inline void dentry_common_init(struct dentry *dentry)
{
	memset(dentry, 0, sizeof(struct dentry));
	dentry->refcnt = 1;
	dentry->security_id = -1;
	dentry->link_group_master_status = GROUP_INDEPENDENT;
	dentry->lte_group_list.type = STREAM_TYPE_NORMAL;
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
		goto err;

	dentry_common_init(dentry);
	if (change_dentry_name(dentry, name) != 0)
		goto err;

	dentry_update_all_timestamps(dentry);
	dentry->next   = dentry;
	dentry->prev   = dentry;
	dentry->parent = dentry;
	INIT_LIST_HEAD(&dentry->link_group_list);
	return dentry;
err:
	FREE(dentry);
	ERROR("Failed to allocate new dentry");
	return NULL;
}

void dentry_free_ads_entries(struct dentry *dentry)
{
	for (u16 i = 0; i < dentry->num_ads; i++)
		destroy_ads_entry(&dentry->ads_entries[i]);
	FREE(dentry->ads_entries);
	dentry->ads_entries = NULL;
	dentry->num_ads = 0;
}

static void __destroy_dentry(struct dentry *dentry)
{
	FREE(dentry->file_name);
	FREE(dentry->file_name_utf8);
	FREE(dentry->short_name);
	FREE(dentry->full_path_utf8);
	FREE(dentry->extracted_file);
}

void free_dentry(struct dentry *dentry)
{
	__destroy_dentry(dentry);
	if (dentry->link_group_master_status != GROUP_SLAVE)
		dentry_free_ads_entries(dentry);
	FREE(dentry);
}

void put_dentry(struct dentry *dentry)
{
	if (dentry->link_group_master_status == GROUP_MASTER) {
		struct dentry *new_master;
		list_for_each_entry(new_master, &dentry->link_group_list,
				    link_group_list)
		{
			if (new_master->link_group_master_status == GROUP_SLAVE) {
				new_master->link_group_master_status = GROUP_MASTER;
				dentry->link_group_master_status = GROUP_SLAVE;
				break;
			}
		}
	}
	struct list_head *next;
	next = dentry->link_group_list.next;
	list_del(&dentry->link_group_list);
	/*if (next->next == next)*/
		/*container_of(next, struct dentry, link_group_list)->hard_link = 0;*/
	free_dentry(dentry);
}

static bool dentries_have_same_ads(const struct dentry *d1,
				   const struct dentry *d2)
{
	/* Verify stream names and hashes are the same */
	for (u16 i = 0; i < d1->num_ads; i++) {
		if (strcmp(d1->ads_entries[i].stream_name_utf8,
			   d2->ads_entries[i].stream_name_utf8) != 0)
			return false;
		if (memcmp(d1->ads_entries[i].hash,
			   d2->ads_entries[i].hash,
			   WIM_HASH_SIZE) != 0)
			return false;
	}
	return true;
}

/* Share the alternate stream entries between hard-linked dentries. */
int share_dentry_ads(struct dentry *master, struct dentry *slave)
{
	const char *mismatch_type;
	wimlib_assert(master->num_ads == 0 ||
		      master->ads_entries != slave->ads_entries);
	if (master->attributes != slave->attributes) {
		mismatch_type = "attributes";
		goto mismatch;
	}
	if (master->attributes & FILE_ATTRIBUTE_DIRECTORY) {
		WARNING("`%s' is hard-linked to `%s', which is a directory ",
		        slave->full_path_utf8, master->full_path_utf8);
		return WIMLIB_ERR_INVALID_DENTRY;
	}
	if (master->security_id != slave->security_id) {
		mismatch_type = "security ID";
		goto mismatch;
	}
	if (memcmp(master->hash, slave->hash, WIM_HASH_SIZE) != 0) {
		mismatch_type = "main file resource";
		goto mismatch;
	}
	if (!dentries_have_same_ads(master, slave)) {
		mismatch_type = "Alternate Stream Entries";
		goto mismatch;
	}
	dentry_free_ads_entries(slave);
	slave->ads_entries = master->ads_entries;
	slave->link_group_master_status = GROUP_SLAVE;
	return 0;
mismatch:
	WARNING("Dentries `%s' and `%s' in the same hard-link group but "
	        "do not share the same %s",
	        master->full_path_utf8, slave->full_path_utf8,
	        mismatch_type);
	return WIMLIB_ERR_INVALID_DENTRY;
}

/* clones a dentry.
 *
 * Beware:
 * 	- memory for file names is not cloned
 * 	- next, prev, and children pointers and not touched
 * 	- stream entries are not cloned.
 */
struct dentry *clone_dentry(struct dentry *old)
{
	struct dentry *new = MALLOC(sizeof(struct dentry));
	if (!new)
		return NULL;
	memcpy(new, old, sizeof(struct dentry));
	new->file_name          = NULL;
	new->file_name_len      = 0;
	new->file_name_utf8     = NULL;
	new->file_name_utf8_len = 0;
	new->short_name         = NULL;
	new->short_name_len     = 0;
	return new;
}

/* Arguments for do_free_dentry(). */
struct free_dentry_args {
	struct lookup_table *lookup_table;
	bool lt_decrement_refcnt;
};

/* 
 * This function is passed as an argument to for_dentry_in_tree_depth() in order
 * to free a directory tree.  __args is a pointer to a `struct free_dentry_args'.
 */
static int do_free_dentry(struct dentry *dentry, void *__args)
{
	struct free_dentry_args *args = (struct free_dentry_args*)__args;

	if (args->lt_decrement_refcnt && !dentry_is_directory(dentry)) {
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
		      bool lt_decrement_refcnt)
{
	if (!root || !root->parent)
		return;

	struct free_dentry_args args;
	args.lookup_table        = lookup_table;
	args.lt_decrement_refcnt = lt_decrement_refcnt;
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


/* Unlink a dentry from the directory tree. 
 *
 * Note: This merely removes it from the in-memory tree structure.  See
 * remove_dentry() in mount.c for a function implemented on top of this one that
 * frees the dentry and implements reference counting for the lookup table
 * entries. */
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
	dentry->length = (dentry->length + 7) & ~7;
}

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
int change_dentry_name(struct dentry *dentry, const char *new_name)
{
	int ret;

	ret = get_names(&dentry->file_name, &dentry->file_name_utf8,
			&dentry->file_name_len, &dentry->file_name_utf8_len,
			 new_name);
	if (ret == 0)
		recalculate_dentry_size(dentry);
	return ret;
}

int change_ads_name(struct ads_entry *entry, const char *new_name)
{
	return get_names(&entry->stream_name, &entry->stream_name_utf8,
			 &entry->stream_name_len,
			 &entry->stream_name_utf8_len,
			  new_name);
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
	u16 i;
	
	stats = arg;

	if (dentry_is_directory(dentry) && !dentry_is_root(dentry))
		++*stats->dir_count;
	else
		++*stats->file_count;

	if (dentry->resolved)
		lte = dentry->lte;
	else
		lte = __lookup_resource(stats->lookup_table, dentry->hash);
	i = 0;
	while (1) {
		if (lte) {
			u64 size = lte->resource_entry.original_size;
			*stats->total_bytes += size;
			if (++lte->out_refcnt == 1)
				*stats->hard_link_bytes += size;
		}
		if (i == dentry->num_ads)
			break;
		lte = __lookup_resource(stats->lookup_table,
					dentry->ads_entries[i].hash);
		i++;
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

static int read_ads_entries(const u8 *p, struct dentry *dentry,
			    u64 remaining_size)
{
	u16 num_ads = dentry->num_ads;
	struct ads_entry *ads_entries = CALLOC(num_ads, sizeof(struct ads_entry));
	int ret;
	if (!ads_entries) {
		ERROR("Could not allocate memory for %"PRIu16" "
		      "alternate data stream entries", num_ads);
		return WIMLIB_ERR_NOMEM;
	}
	DEBUG2("Reading %"PRIu16" alternate data streams "
	       "(remaining size = %"PRIu64")", num_ads, remaining_size);

	for (u16 i = 0; i < num_ads; i++) {
		struct ads_entry *cur_entry = &ads_entries[i];
		u64 length;
		size_t utf8_len;
		const char *p_save = p;
		/* Read the base stream entry, excluding the stream name. */
		if (remaining_size < WIM_ADS_ENTRY_DISK_SIZE) {
			ERROR("Stream entries go past end of metadata resource");
			ERROR("(remaining_size = %"PRIu64")", remaining_size);
			ret = WIMLIB_ERR_INVALID_DENTRY;
			goto out_free_ads_entries;
		}
		remaining_size -= WIM_ADS_ENTRY_DISK_SIZE;

		p = get_u64(p, &length); /* ADS entry length */

		DEBUG2("ADS length = %"PRIu64, length);

		p += 8; /* Unused */
		p = get_bytes(p, WIM_HASH_SIZE, (u8*)cur_entry->hash);
		p = get_u16(p, &cur_entry->stream_name_len);

		DEBUG2("Stream name length = %u", cur_entry->stream_name_len);

		cur_entry->stream_name = NULL;
		cur_entry->stream_name_utf8 = NULL;

		if (remaining_size < cur_entry->stream_name_len + 2) {
			ERROR("Stream entries go past end of metadata resource");
			ERROR("(remaining_size = %"PRIu64" bytes, stream_name_len "
			      "= %"PRIu16" bytes", remaining_size,
			      cur_entry->stream_name_len);
			ret = WIMLIB_ERR_INVALID_DENTRY;
			goto out_free_ads_entries;
		}
		remaining_size -= cur_entry->stream_name_len + 2;

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
		p = p_save + ads_entry_length(cur_entry);
	}
	dentry->ads_entries = ads_entries;
	return 0;
out_free_ads_entries:
	for (u16 i = 0; i < num_ads; i++) {
		FREE(ads_entries[i].stream_name);
		FREE(ads_entries[i].stream_name_utf8);
	}
	FREE(ads_entries);
	return ret;
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
	int ret;

	dentry_common_init(dentry);

	/*Make sure the dentry really fits into the metadata resource.*/
	if (offset + 8 > metadata_resource_len) {
		ERROR("Directory entry starting at %"PRIu64" ends past the "
		      "end of the metadata resource (size %"PRIu64")",
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
		      "(size %"PRIu64")",
		      offset, dentry->length, metadata_resource_len);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	/* If it is a recognized length, read the rest of the directory entry.
	 * Note: The root directory entry has no name, and its length does not
	 * include the short name length field.  */
	if (dentry->length < WIM_DENTRY_DISK_SIZE) {
		ERROR("Directory entry has invalid length of %"PRIu64" bytes",
		      dentry->length);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	p = get_u32(p, &dentry->attributes);
	p = get_u32(p, (u32*)&dentry->security_id);
	p = get_u64(p, &dentry->subdir_offset);

	/* 2 unused fields */
	p += 2 * sizeof(u64);
	/*p = get_u64(p, &dentry->unused1);*/
	/*p = get_u64(p, &dentry->unused2);*/

	p = get_u64(p, &dentry->creation_time);
	p = get_u64(p, &dentry->last_access_time);
	p = get_u64(p, &dentry->last_write_time);

	p = get_bytes(p, WIM_HASH_SIZE, dentry->hash);
	
	/*
	 * I don't know what's going on here.  It seems like M$ screwed up the
	 * reparse points, then put the fields in the same place and didn't
	 * document it.  The WIM_HDR_FLAG_RP_FIX flag in the WIM header might
	 * have something to do with this, but it's not documented.
	 */
	if (dentry->attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		/* ??? */
		p += 4;
		p = get_u32(p, &dentry->reparse_tag);
		p += 4;
	} else {
		p = get_u32(p, &dentry->reparse_tag);
		p = get_u64(p, &dentry->hard_link);
	}

	/* By the way, the reparse_reserved field does not actually exist (at
	 * least when the file is not a reparse point) */

	
	p = get_u16(p, &dentry->num_ads);

	p = get_u16(p, &short_name_len);
	p = get_u16(p, &file_name_len);

	calculated_size = WIM_DENTRY_DISK_SIZE + file_name_len + 2 +
			  short_name_len;

	if (dentry->length < calculated_size) {
		ERROR("Unexpected end of directory entry! (Expected "
		      "%"PRIu64" bytes, got %"PRIu64" bytes. "
		      "short_name_len = %hu, file_name_len = %hu)", 
		      calculated_size, dentry->length,
		      short_name_len, file_name_len);
		return WIMLIB_ERR_INVALID_DENTRY;
	}

	/* Read the filename. */
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

	/* Undocumented padding between file name and short name.  This probably
	 * is supposed to be a terminating null character. */
	p += 2;

	/* Read the short filename. */
	short_name = MALLOC(short_name_len);
	if (!short_name) {
		ERROR("Failed to allocate %hu bytes for short filename",
		      short_name_len);
		ret = WIMLIB_ERR_NOMEM;
		goto out_free_file_name_utf8;
	}

	p = get_bytes(p, short_name_len, short_name);

	/* Some directory entries inexplicibly have a little over 70 bytes of
	 * extra data.  The exact amount of data seems to be 72 bytes, but it is
	 * aligned on the next 8-byte boundary.  Here's an example of the
	 * aligned data:
	 *
	 * 01000000400000006c786bbac58ede11b0bb00261870892ab6adb76fe63a3
	 * e468fca86530d2effa16c786bbac58ede11b0bb00261870892a0000000000
	 * 0000000000000000000000
	 *
	 * Here's one interpretation of how the data is laid out.
	 *
	 * struct unknown {
	 * 	u32 field1; (always 0x00000001)
	 * 	u32 field2; (always 0x40000000)
	 * 	u16 field3;
	 * 	u32 field4;
	 * 	u32 field5;
	 * 	u32 field6;
	 * 	u8  data[48]; (???)
	 * 	u64 reserved1; (always 0)
	 * 	u64 reserved2; (always 0)
	 * };*/
#if 0
	if (dentry->length - calculated_size >= WIM_ADS_ENTRY_DISK_SIZE) {
		printf("%s: %lu / %lu (", file_name_utf8, 
				calculated_size, dentry->length);
		print_string(p + WIM_ADS_ENTRY_DISK_SIZE, dentry->length - calculated_size - WIM_ADS_ENTRY_DISK_SIZE);
		puts(")");
		print_byte_field(p, dentry->length - calculated_size);
		putchar('\n');
	}
#endif

	if (dentry->num_ads != 0) {
		calculated_size = (calculated_size + 7) & ~7;
		if (calculated_size > metadata_resource_len - offset) {
			ERROR("Not enough space in metadata resource for "
			      "alternate stream entries");
			ret = WIMLIB_ERR_INVALID_DENTRY;
			goto out_free_short_name;
		}
		ret = read_ads_entries(&metadata_resource[offset + calculated_size],
				       dentry,
				       metadata_resource_len - offset - calculated_size);
		if (ret != 0)
			goto out_free_short_name;
	}

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
	return ret;
}

/* 
 * Writes a dentry to an output buffer.
 *
 * @dentry:  The dentry structure.
 * @p:       The memory location to write the data to.
 * @return:  Pointer to the byte after the last byte we wrote as part of the
 * 		dentry.
 */
static u8 *write_dentry(const struct dentry *dentry, u8 *p)
{
	u8 *orig_p = p;
	unsigned padding;
	const u8 *hash;

	p = put_u64(p, dentry->length);
	p = put_u32(p, dentry->attributes);
	p = put_u32(p, dentry->security_id);
	p = put_u64(p, dentry->subdir_offset);
	p = put_u64(p, 0); /* unused1 */
	p = put_u64(p, 0); /* unused2 */
	p = put_u64(p, dentry->creation_time);
	p = put_u64(p, dentry->last_access_time);
	p = put_u64(p, dentry->last_write_time);
	if (dentry->resolved && dentry->lte)
		hash = dentry->lte->hash;
	else
		hash = dentry->hash;
	p = put_bytes(p, WIM_HASH_SIZE, hash);
	if (dentry->attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		p = put_zeroes(p, 4);
		p = put_u32(p, dentry->reparse_tag);
		p = put_zeroes(p, 4);
	} else {
		u64 hard_link;
		p = put_u32(p, dentry->reparse_tag);
		if (dentry->link_group_list.next == &dentry->link_group_list)
			hard_link = 0;
		else
			hard_link = dentry->hard_link;
		p = put_u64(p, hard_link);
	}
	p = put_u16(p, dentry->num_ads);
	p = put_u16(p, dentry->short_name_len);
	p = put_u16(p, dentry->file_name_len);
	p = put_bytes(p, dentry->file_name_len, (u8*)dentry->file_name);
	p = put_u16(p, 0); /* filename padding, 2 bytes. */
	p = put_bytes(p, dentry->short_name_len, (u8*)dentry->short_name);

	wimlib_assert(p - orig_p <= dentry->length);
	if (p - orig_p < dentry->length)
		p = put_zeroes(p, dentry->length - (p - orig_p));

	p = put_zeroes(p, (8 - (p - orig_p) % 8) % 8);

	for (u16 i = 0; i < dentry->num_ads; i++) {
		p = put_u64(p, ads_entry_length(&dentry->ads_entries[i]));
		p = put_u64(p, 0); /* Unused */
		p = put_bytes(p, WIM_HASH_SIZE, dentry->ads_entries[i].hash);
		p = put_u16(p, dentry->ads_entries[i].stream_name_len);
		p = put_bytes(p, dentry->ads_entries[i].stream_name_len,
				 (u8*)dentry->ads_entries[i].stream_name);
		p = put_zeroes(p, (8 - (p - orig_p) % 8) % 8);
	}
	return p;
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
		/* Nothing to do for non-directories */
		if (!dentry_is_directory(tree))
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
 * 			resource for the WIM file.
 * @metadata_resource_len:	The length of @metadata_resource.
 * @dentry:	A pointer to a struct dentry that is the root of the directory
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

		/* If there are children of this child, call this procedure
		 * recursively. */
		if (child->subdir_offset != 0) {
			ret = read_dentry_tree(metadata_resource, 
					       metadata_resource_len, child);
			if (ret != 0)
				break;
		}

		/* Advance to the offset of the next child. */
		cur_offset += dentry_total_length(child);
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
