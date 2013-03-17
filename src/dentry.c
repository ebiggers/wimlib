/*
 * dentry.c
 *
 * In the WIM file format, the dentries are stored in the "metadata resource"
 * section right after the security data.  Each image in the WIM file has its
 * own metadata resource with its own security data and dentry tree.  Dentries
 * in different images may share file resources by referring to the same lookup
 * table entries.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include "buffer_io.h"
#include "dentry.h"
#include "lookup_table.h"
#include "timestamp.h"
#include "wimlib_internal.h"
#include <errno.h>

/* Calculates the unaligned length, in bytes, of an on-disk WIM dentry that has
 * a file name and short name that take the specified numbers of bytes.  This
 * excludes any alternate data stream entries that may follow the dentry. */
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

/* Calculates the unaligned length, in bytes, of an on-disk WIM dentry, based on
 * the file name length and short name length.  Note that dentry->length is
 * ignored; also, this excludes any alternate data stream entries that may
 * follow the dentry. */
static u64 dentry_correct_length_unaligned(const struct wim_dentry *dentry)
{
	return __dentry_correct_length_unaligned(dentry->file_name_len,
						 dentry->short_name_len);
}

/* Return the "correct" value to write in the length field of a WIM dentry,
 * based on the file name length and short name length. */
static u64 dentry_correct_length(const struct wim_dentry *dentry)
{
	return (dentry_correct_length_unaligned(dentry) + 7) & ~7;
}

/* Return %true iff the alternate data stream entry @entry has the UTF-8 stream
 * name @name that has length @name_len bytes. */
static inline bool ads_entry_has_name(const struct wim_ads_entry *entry,
				      const char *name, size_t name_len)
{
	if (entry->stream_name_utf8_len != name_len)
		return false;
	return memcmp(entry->stream_name_utf8, name, name_len) == 0;
}

/* Duplicates a UTF-8 string into UTF-8 and UTF-16 strings and returns the
 * strings and their lengths in the pointer arguments.  (Frees existing strings
 * first.) */
static int get_names(char **name_utf16_ret, char **name_utf8_ret,
		     u16 *name_utf16_len_ret, u16 *name_utf8_len_ret,
		     const char *name)
{
	size_t utf8_len;
	size_t utf16_len;
	char *name_utf16, *name_utf8;
	int ret;

	utf8_len = strlen(name);
	ret = utf8_to_utf16(name, utf8_len, &name_utf16, &utf16_len);
	if (ret != 0)
		return ret;

	name_utf8 = MALLOC(utf8_len + 1);
	if (!name_utf8) {
		FREE(name_utf16);
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

/* Sets the name of a WIM dentry. */
int set_dentry_name(struct wim_dentry *dentry, const char *new_name)
{
	int ret;

	ret = get_names(&dentry->file_name, &dentry->file_name_utf8,
			&dentry->file_name_len, &dentry->file_name_utf8_len,
			new_name);
	if (ret == 0) {
		if (dentry->short_name_len) {
			FREE(dentry->short_name);
			dentry->short_name_len = 0;
		}
		dentry->length = dentry_correct_length(dentry);
	}
	return ret;
}

/*
 * Changes the name of an alternate data stream */
static int change_ads_name(struct wim_ads_entry *entry, const char *new_name)
{
	return get_names(&entry->stream_name, &entry->stream_name_utf8,
			 &entry->stream_name_len,
			 &entry->stream_name_utf8_len,
			 new_name);
}

/* Returns the total length of a WIM alternate data stream entry on-disk,
 * including the stream name, the null terminator, AND the padding after the
 * entry to align the next ADS entry or dentry on an 8-byte boundary. */
static u64 ads_entry_total_length(const struct wim_ads_entry *entry)
{
	u64 len = WIM_ADS_ENTRY_DISK_SIZE;
	if (entry->stream_name_len)
		len += entry->stream_name_len + 2;
	return (len + 7) & ~7;
}


static u64 __dentry_total_length(const struct wim_dentry *dentry, u64 length)
{
	const struct wim_inode *inode = dentry->d_inode;
	for (u16 i = 0; i < inode->i_num_ads; i++)
		length += ads_entry_total_length(&inode->i_ads_entries[i]);
	return (length + 7) & ~7;
}

/* Calculate the aligned *total* length of an on-disk WIM dentry.  This includes
 * all alternate data streams. */
u64 dentry_correct_total_length(const struct wim_dentry *dentry)
{
	return __dentry_total_length(dentry,
				     dentry_correct_length_unaligned(dentry));
}

/* Like dentry_correct_total_length(), but use the existing dentry->length field
 * instead of calculating its "correct" value. */
static u64 dentry_total_length(const struct wim_dentry *dentry)
{
	return __dentry_total_length(dentry, dentry->length);
}

int for_dentry_in_rbtree(struct rb_node *root,
			 int (*visitor)(struct wim_dentry *, void *),
			 void *arg)
{
	int ret;
	struct rb_node *node = root;
	LIST_HEAD(stack);
	while (1) {
		if (node) {
			list_add(&rbnode_dentry(node)->tmp_list, &stack);
			node = node->rb_left;
		} else {
			struct list_head *next;
			struct wim_dentry *dentry;

			next = stack.next;
			if (next == &stack)
				return 0;
			dentry = container_of(next, struct wim_dentry, tmp_list);
			list_del(next);
			ret = visitor(dentry, arg);
			if (ret != 0)
				return ret;
			node = dentry->rb_node.rb_right;
		}
	}
}

static int for_dentry_tree_in_rbtree_depth(struct rb_node *node,
					   int (*visitor)(struct wim_dentry*, void*),
					   void *arg)
{
	int ret;
	if (node) {
		ret = for_dentry_tree_in_rbtree_depth(node->rb_left,
						      visitor, arg);
		if (ret != 0)
			return ret;
		ret = for_dentry_tree_in_rbtree_depth(node->rb_right,
						      visitor, arg);
		if (ret != 0)
			return ret;
		ret = for_dentry_in_tree_depth(rbnode_dentry(node), visitor, arg);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static int for_dentry_tree_in_rbtree(struct rb_node *node,
				     int (*visitor)(struct wim_dentry*, void*),
				     void *arg)
{
	int ret;
	if (node) {
		ret = for_dentry_tree_in_rbtree(node->rb_left, visitor, arg);
		if (ret != 0)
			return ret;
		ret = for_dentry_in_tree(rbnode_dentry(node), visitor, arg);
		if (ret != 0)
			return ret;
		ret = for_dentry_tree_in_rbtree(node->rb_right, visitor, arg);
		if (ret != 0)
			return ret;
	}
	return 0;
}

/*
 * Calls a function on all directory entries in a WIM dentry tree.  Logically,
 * this is a pre-order traversal (the function is called on a parent dentry
 * before its children), but sibling dentries will be visited in order as well.
 *
 * In reality, the data structures are more complicated than the above might
 * suggest because there is a separate red-black tree for each dentry that
 * contains its direct children.
 */
int for_dentry_in_tree(struct wim_dentry *root,
		       int (*visitor)(struct wim_dentry*, void*), void *arg)
{
	int ret = visitor(root, arg);
	if (ret != 0)
		return ret;
	return for_dentry_tree_in_rbtree(root->d_inode->i_children.rb_node, visitor, arg);
}

/*
 * Like for_dentry_in_tree(), but the visitor function is always called on a
 * dentry's children before on itself.
 */
int for_dentry_in_tree_depth(struct wim_dentry *root,
			     int (*visitor)(struct wim_dentry*, void*), void *arg)
{
	int ret;
	ret = for_dentry_tree_in_rbtree_depth(root->d_inode->i_children.rb_node,
					      visitor, arg);
	if (ret != 0)
		return ret;
	return visitor(root, arg);
}

/*
 * Calculate the full path of @dentry, based on its parent's full path and on
 * its UTF-8 file name.
 */
int calculate_dentry_full_path(struct wim_dentry *dentry, void *ignore)
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
		const struct wim_dentry *parent = dentry->parent;

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

static int increment_subdir_offset(struct wim_dentry *dentry, void *subdir_offset_p)
{
	*(u64*)subdir_offset_p += dentry_correct_total_length(dentry);
	return 0;
}

static int call_calculate_subdir_offsets(struct wim_dentry *dentry,
					 void *subdir_offset_p)
{
	calculate_subdir_offsets(dentry, subdir_offset_p);
	return 0;
}

/*
 * Recursively calculates the subdir offsets for a directory tree.
 *
 * @dentry:  The root of the directory tree.
 * @subdir_offset_p:  The current subdirectory offset; i.e., the subdirectory
 *		      offset for @dentry.
 */
void calculate_subdir_offsets(struct wim_dentry *dentry, u64 *subdir_offset_p)
{
	struct rb_node *node;

	dentry->subdir_offset = *subdir_offset_p;
	node = dentry->d_inode->i_children.rb_node;
	if (node) {
		/* Advance the subdir offset by the amount of space the children
		 * of this dentry take up. */
		for_dentry_in_rbtree(node, increment_subdir_offset, subdir_offset_p);

		/* End-of-directory dentry on disk. */
		*subdir_offset_p += 8;

		/* Recursively call calculate_subdir_offsets() on all the
		 * children. */
		for_dentry_in_rbtree(node, call_calculate_subdir_offsets, subdir_offset_p);
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

static int compare_names(const char *name_1, u16 len_1,
			 const char *name_2, u16 len_2)
{
	int result = strncmp(name_1, name_2, min(len_1, len_2));
	if (result) {
		return result;
	} else {
		return (int)len_1 - (int)len_2;
	}
}

static int dentry_compare_names(const struct wim_dentry *d1, const struct wim_dentry *d2)
{
	return compare_names(d1->file_name_utf8, d1->file_name_utf8_len,
			     d2->file_name_utf8, d2->file_name_utf8_len);
}


static struct wim_dentry *
get_rbtree_child_with_name(const struct rb_node *node,
			   const char *name, size_t name_len)
{
	do {
		struct wim_dentry *child = rbnode_dentry(node);
		int result = compare_names(name, name_len,
					   child->file_name_utf8,
					   child->file_name_utf8_len);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return child;
	} while (node);
	return NULL;
}

/* Returns the child of @dentry that has the file name @name.
 * Returns NULL if no child has the name. */
struct wim_dentry *get_dentry_child_with_name(const struct wim_dentry *dentry,
					      const char *name)
{
	struct rb_node *node = dentry->d_inode->i_children.rb_node;
	if (node)
		return get_rbtree_child_with_name(node, name, strlen(name));
	else
		return NULL;
}

/* Retrieves the dentry that has the UTF-8 @path relative to the dentry
 * @cur_dentry.  Returns NULL if no dentry having the path is found. */
static struct wim_dentry *get_dentry_relative_path(struct wim_dentry *cur_dentry,
						   const char *path)
{
	if (*path == '\0')
		return cur_dentry;

	struct rb_node *node = cur_dentry->d_inode->i_children.rb_node;
	if (node) {
		struct wim_dentry *child;
		size_t base_len;
		const char *new_path;

		new_path = path_next_part(path, &base_len);

		child = get_rbtree_child_with_name(node, path, base_len);
		if (child)
			return get_dentry_relative_path(child, new_path);
	}
	/* errno is set to ENOTDIR if the lookup failed due to reaching a
	 * non-directory, or ENOENT if the lookup failed otherwise.  This maybe
	 * should be factored out somehow. */
	if (dentry_is_directory(cur_dentry))
		errno = ENOENT;
	else
		errno = ENOTDIR;
	return NULL;
}

/* Returns the dentry corresponding to the UTF-8 @path, or NULL if there is no
 * such dentry. */
struct wim_dentry *get_dentry(WIMStruct *w, const char *path)
{
	struct wim_dentry *root = wim_root_dentry(w);
	while (*path == '/')
		path++;
	return get_dentry_relative_path(root, path);
}

struct wim_inode *wim_pathname_to_inode(WIMStruct *w, const char *path)
{
	struct wim_dentry *dentry;
	dentry = get_dentry(w, path);
	if (dentry)
		return dentry->d_inode;
	else
		return NULL;
}

/* Returns the dentry that corresponds to the parent directory of @path, or NULL
 * if the dentry is not found. */
struct wim_dentry *get_parent_dentry(WIMStruct *w, const char *path)
{
	size_t path_len = strlen(path);
	char buf[path_len + 1];

	memcpy(buf, path, path_len + 1);

	to_parent_name(buf, path_len);

	return get_dentry(w, buf);
}

/* Prints the full path of a dentry. */
int print_dentry_full_path(struct wim_dentry *dentry, void *ignore)
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
int print_dentry(struct wim_dentry *dentry, void *lookup_table)
{
	const u8 *hash;
	struct wim_lookup_table_entry *lte;
	const struct wim_inode *inode = dentry->d_inode;
	char buf[50];

	printf("[DENTRY]\n");
	printf("Length            = %"PRIu64"\n", dentry->length);
	printf("Attributes        = 0x%x\n", inode->i_attributes);
	for (size_t i = 0; i < ARRAY_LEN(file_attr_flags); i++)
		if (file_attr_flags[i].flag & inode->i_attributes)
			printf("    FILE_ATTRIBUTE_%s is set\n",
				file_attr_flags[i].name);
	printf("Security ID       = %d\n", inode->i_security_id);
	printf("Subdir offset     = %"PRIu64"\n", dentry->subdir_offset);

	wim_timestamp_to_str(inode->i_creation_time, buf, sizeof(buf));
	printf("Creation Time     = %s\n", buf);

	wim_timestamp_to_str(inode->i_last_access_time, buf, sizeof(buf));
	printf("Last Access Time  = %s\n", buf);

	wim_timestamp_to_str(inode->i_last_write_time, buf, sizeof(buf));
	printf("Last Write Time   = %s\n", buf);

	printf("Reparse Tag       = 0x%"PRIx32"\n", inode->i_reparse_tag);
	printf("Hard Link Group   = 0x%"PRIx64"\n", inode->i_ino);
	printf("Hard Link Group Size = %"PRIu32"\n", inode->i_nlink);
	printf("Number of Alternate Data Streams = %hu\n", inode->i_num_ads);
	printf("Filename (UTF-8)  = \"%s\"\n", dentry->file_name_utf8);
	/*printf("Filename (UTF-8) Length = %hu\n", dentry->file_name_utf8_len);*/
	printf("Short Name (UTF-16LE) = \"");
	print_string(dentry->short_name, dentry->short_name_len);
	puts("\"");
	/*printf("Short Name Length = %hu\n", dentry->short_name_len);*/
	printf("Full Path (UTF-8) = \"%s\"\n", dentry->full_path_utf8);
	lte = inode_stream_lte(dentry->d_inode, 0, lookup_table);
	if (lte) {
		print_lookup_table_entry(lte, stdout);
	} else {
		hash = inode_stream_hash(inode, 0);
		if (hash) {
			printf("Hash              = 0x");
			print_hash(hash);
			putchar('\n');
			putchar('\n');
		}
	}
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		printf("[Alternate Stream Entry %u]\n", i);
		printf("Name = \"%s\"\n", inode->i_ads_entries[i].stream_name_utf8);
		printf("Name Length (UTF-16) = %u\n",
			inode->i_ads_entries[i].stream_name_len);
		hash = inode_stream_hash(inode, i + 1);
		if (hash) {
			printf("Hash              = 0x");
			print_hash(hash);
			putchar('\n');
		}
		print_lookup_table_entry(inode_stream_lte(inode, i + 1, lookup_table),
					 stdout);
	}
	return 0;
}

/* Initializations done on every `struct wim_dentry'. */
static void dentry_common_init(struct wim_dentry *dentry)
{
	memset(dentry, 0, sizeof(struct wim_dentry));
	dentry->refcnt = 1;
}

static struct wim_inode *new_timeless_inode()
{
	struct wim_inode *inode = CALLOC(1, sizeof(struct wim_inode));
	if (inode) {
		inode->i_security_id = -1;
		inode->i_nlink = 1;
	#ifdef WITH_FUSE
		inode->i_next_stream_id = 1;
		if (pthread_mutex_init(&inode->i_mutex, NULL) != 0) {
			ERROR_WITH_ERRNO("Error initializing mutex");
			FREE(inode);
			return NULL;
		}
	#endif
		INIT_LIST_HEAD(&inode->i_dentry);
	}
	return inode;
}

static struct wim_inode *new_inode()
{
	struct wim_inode *inode = new_timeless_inode();
	if (inode) {
		u64 now = get_wim_timestamp();
		inode->i_creation_time = now;
		inode->i_last_access_time = now;
		inode->i_last_write_time = now;
	}
	return inode;
}

/*
 * Creates an unlinked directory entry.
 *
 * @name:  The UTF-8 filename of the new dentry.
 *
 * Returns a pointer to the new dentry, or NULL if out of memory.
 */
struct wim_dentry *new_dentry(const char *name)
{
	struct wim_dentry *dentry;

	dentry = MALLOC(sizeof(struct wim_dentry));
	if (!dentry)
		goto err;

	dentry_common_init(dentry);
	if (set_dentry_name(dentry, name) != 0)
		goto err;

	dentry->parent = dentry;

	return dentry;
err:
	FREE(dentry);
	ERROR_WITH_ERRNO("Failed to create new dentry with name \"%s\"", name);
	return NULL;
}


static struct wim_dentry *
__new_dentry_with_inode(const char *name, bool timeless)
{
	struct wim_dentry *dentry;
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

struct wim_dentry *new_dentry_with_timeless_inode(const char *name)
{
	return __new_dentry_with_inode(name, true);
}

struct wim_dentry *new_dentry_with_inode(const char *name)
{
	return __new_dentry_with_inode(name, false);
}


static int init_ads_entry(struct wim_ads_entry *ads_entry, const char *name)
{
	int ret = 0;
	memset(ads_entry, 0, sizeof(*ads_entry));
	if (name && *name)
		ret = change_ads_name(ads_entry, name);
	return ret;
}

static void destroy_ads_entry(struct wim_ads_entry *ads_entry)
{
	FREE(ads_entry->stream_name);
	FREE(ads_entry->stream_name_utf8);
}


/* Frees an inode. */
void free_inode(struct wim_inode *inode)
{
	if (inode) {
		if (inode->i_ads_entries) {
			for (u16 i = 0; i < inode->i_num_ads; i++)
				destroy_ads_entry(&inode->i_ads_entries[i]);
			FREE(inode->i_ads_entries);
		}
	#ifdef WITH_FUSE
		wimlib_assert(inode->i_num_opened_fds == 0);
		FREE(inode->i_fds);
		pthread_mutex_destroy(&inode->i_mutex);
		if (inode->i_hlist.pprev)
			hlist_del(&inode->i_hlist);
	#endif
		FREE(inode->i_extracted_file);
		FREE(inode);
	}
}

/* Decrements link count on an inode and frees it if the link count reaches 0.
 * */
static void put_inode(struct wim_inode *inode)
{
	wimlib_assert(inode->i_nlink != 0);
	if (--inode->i_nlink == 0) {
	#ifdef WITH_FUSE
		if (inode->i_num_opened_fds == 0)
	#endif
		{
			free_inode(inode);
		}
	}
}

/* Frees a WIM dentry.
 *
 * The corresponding inode (if any) is freed only if its link count is
 * decremented to 0.
 */
void free_dentry(struct wim_dentry *dentry)
{
	FREE(dentry->file_name);
	FREE(dentry->file_name_utf8);
	FREE(dentry->short_name);
	FREE(dentry->full_path_utf8);
	if (dentry->d_inode)
		put_inode(dentry->d_inode);
	FREE(dentry);
}

void put_dentry(struct wim_dentry *dentry)
{
	wimlib_assert(dentry->refcnt != 0);
	if (--dentry->refcnt == 0)
		free_dentry(dentry);
}

/* This function is passed as an argument to for_dentry_in_tree_depth() in order
 * to free a directory tree. */
static int do_free_dentry(struct wim_dentry *dentry, void *__lookup_table)
{
	struct wim_lookup_table *lookup_table = __lookup_table;
	unsigned i;

	if (lookup_table) {
		struct wim_lookup_table_entry *lte;
		struct wim_inode *inode = dentry->d_inode;
		wimlib_assert(inode->i_nlink != 0);
		for (i = 0; i <= inode->i_num_ads; i++) {
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
void free_dentry_tree(struct wim_dentry *root, struct wim_lookup_table *lookup_table)
{
	if (root)
		for_dentry_in_tree_depth(root, do_free_dentry, lookup_table);
}

int increment_dentry_refcnt(struct wim_dentry *dentry, void *ignore)
{
	dentry->refcnt++;
	return 0;
}

/*
 * Links a dentry into the directory tree.
 *
 * @parent: The dentry that will be the parent of @dentry.
 * @dentry: The dentry to link.
 */
bool dentry_add_child(struct wim_dentry * restrict parent,
		      struct wim_dentry * restrict child)
{
	wimlib_assert(dentry_is_directory(parent));

	struct rb_root *root = &parent->d_inode->i_children;
	struct rb_node **new = &(root->rb_node);
	struct rb_node *rb_parent = NULL;

	while (*new) {
		struct wim_dentry *this = rbnode_dentry(*new);
		int result = dentry_compare_names(child, this);

		rb_parent = *new;

		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return false;
	}
	child->parent = parent;
	rb_link_node(&child->rb_node, rb_parent, new);
	rb_insert_color(&child->rb_node, root);
	return true;
}

/* Unlink a WIM dentry from the directory entry tree. */
void unlink_dentry(struct wim_dentry *dentry)
{
	struct wim_dentry *parent = dentry->parent;
	if (parent == dentry)
		return;
	rb_erase(&dentry->rb_node, &parent->d_inode->i_children);
}

/*
 * Returns the alternate data stream entry belonging to @inode that has the
 * stream name @stream_name.
 */
struct wim_ads_entry *inode_get_ads_entry(struct wim_inode *inode,
				      const char *stream_name,
				      u16 *idx_ret)
{
	if (inode->i_num_ads != 0) {
		u16 i = 0;
		size_t stream_name_len = strlen(stream_name);
		do {
			if (ads_entry_has_name(&inode->i_ads_entries[i],
					       stream_name, stream_name_len))
			{
				if (idx_ret)
					*idx_ret = i;
				return &inode->i_ads_entries[i];
			}
		} while (++i != inode->i_num_ads);
	}
	return NULL;
}

/*
 * Add an alternate stream entry to a WIM inode and return a pointer to it, or
 * NULL if memory could not be allocated.
 */
struct wim_ads_entry *inode_add_ads(struct wim_inode *inode, const char *stream_name)
{
	u16 num_ads;
	struct wim_ads_entry *ads_entries;
	struct wim_ads_entry *new_entry;

	DEBUG("Add alternate data stream \"%s\"", stream_name);

	if (inode->i_num_ads >= 0xfffe) {
		ERROR("Too many alternate data streams in one inode!");
		return NULL;
	}
	num_ads = inode->i_num_ads + 1;
	ads_entries = REALLOC(inode->i_ads_entries,
			      num_ads * sizeof(inode->i_ads_entries[0]));
	if (!ads_entries) {
		ERROR("Failed to allocate memory for new alternate data stream");
		return NULL;
	}
	inode->i_ads_entries = ads_entries;

	new_entry = &inode->i_ads_entries[num_ads - 1];
	if (init_ads_entry(new_entry, stream_name) != 0)
		return NULL;
#ifdef WITH_FUSE
	new_entry->stream_id = inode->i_next_stream_id++;
#endif
	inode->i_num_ads = num_ads;
	return new_entry;
}

int inode_add_ads_with_data(struct wim_inode *inode, const char *name,
			    const u8 *value, size_t size,
			    struct wim_lookup_table *lookup_table)
{
	int ret = WIMLIB_ERR_NOMEM;
	struct wim_ads_entry *new_ads_entry;
	struct wim_lookup_table_entry *existing_lte;
	struct wim_lookup_table_entry *lte;
	u8 value_hash[SHA1_HASH_SIZE];

	wimlib_assert(inode->i_resolved);
	new_ads_entry = inode_add_ads(inode, name);
	if (!new_ads_entry)
		goto out;
	sha1_buffer((const u8*)value, size, value_hash);
	existing_lte = __lookup_resource(lookup_table, value_hash);
	if (existing_lte) {
		lte = existing_lte;
		lte->refcnt++;
	} else {
		u8 *value_copy;
		lte = new_lookup_table_entry();
		if (!lte)
			goto out_free_ads_entry;
		value_copy = MALLOC(size);
		if (!value_copy) {
			FREE(lte);
			goto out_free_ads_entry;
		}
		memcpy(value_copy, value, size);
		lte->resource_location            = RESOURCE_IN_ATTACHED_BUFFER;
		lte->attached_buffer              = value_copy;
		lte->resource_entry.original_size = size;
		lte->resource_entry.size          = size;
		lte->resource_entry.flags         = 0;
		copy_hash(lte->hash, value_hash);
		lookup_table_insert(lookup_table, lte);
	}
	new_ads_entry->lte = lte;
	ret = 0;
	goto out;
out_free_ads_entry:
	inode_remove_ads(inode, new_ads_entry - inode->i_ads_entries,
			 lookup_table);
out:
	return ret;
}

/* Remove an alternate data stream from a WIM inode  */
void inode_remove_ads(struct wim_inode *inode, u16 idx,
		      struct wim_lookup_table *lookup_table)
{
	struct wim_ads_entry *ads_entry;
	struct wim_lookup_table_entry *lte;

	wimlib_assert(idx < inode->i_num_ads);
	wimlib_assert(inode->i_resolved);

	ads_entry = &inode->i_ads_entries[idx];

	DEBUG("Remove alternate data stream \"%s\"", ads_entry->stream_name_utf8);

	lte = ads_entry->lte;
	if (lte)
		lte_decrement_refcnt(lte, lookup_table);

	destroy_ads_entry(ads_entry);

	memmove(&inode->i_ads_entries[idx],
		&inode->i_ads_entries[idx + 1],
		(inode->i_num_ads - idx - 1) * sizeof(inode->i_ads_entries[0]));
	inode->i_num_ads--;
}

int inode_get_unix_data(const struct wim_inode *inode,
			struct wimlib_unix_data *unix_data,
			u16 *stream_idx_ret)
{
	const struct wim_ads_entry *ads_entry;
	const struct wim_lookup_table_entry *lte;
	size_t size;
	int ret;

	wimlib_assert(inode->i_resolved);

	ads_entry = inode_get_ads_entry((struct wim_inode*)inode,
					WIMLIB_UNIX_DATA_TAG, NULL);
	if (!ads_entry)
		return NO_UNIX_DATA;

	if (stream_idx_ret)
		*stream_idx_ret = ads_entry - inode->i_ads_entries;

	lte = ads_entry->lte;
	if (!lte)
		return NO_UNIX_DATA;

	size = wim_resource_size(lte);
	if (size != sizeof(struct wimlib_unix_data))
		return BAD_UNIX_DATA;

	ret = read_full_wim_resource(lte, (u8*)unix_data, 0);
	if (ret)
		return ret;

	if (unix_data->version != 0)
		return BAD_UNIX_DATA;
	return 0;
}

int inode_set_unix_data(struct wim_inode *inode,
			uid_t uid, gid_t gid, mode_t mode,
			struct wim_lookup_table *lookup_table,
			int which)
{
	struct wimlib_unix_data unix_data;
	int ret;
	bool have_good_unix_data = false;
	bool have_unix_data = false;
	u16 stream_idx;

	if (!(which & UNIX_DATA_CREATE)) {
		ret = inode_get_unix_data(inode, &unix_data, &stream_idx);
		if (ret == 0 || ret == BAD_UNIX_DATA || ret > 0)
			have_unix_data = true;
		if (ret == 0)
			have_good_unix_data = true;
	}
	unix_data.version = 0;
	if (which & UNIX_DATA_UID || !have_good_unix_data)
		unix_data.uid = uid;
	if (which & UNIX_DATA_GID || !have_good_unix_data)
		unix_data.gid = gid;
	if (which & UNIX_DATA_MODE || !have_good_unix_data)
		unix_data.mode = mode;
	ret = inode_add_ads_with_data(inode, WIMLIB_UNIX_DATA_TAG,
				      (const u8*)&unix_data,
				      sizeof(struct wimlib_unix_data),
				      lookup_table);
	if (ret == 0 && have_unix_data)
		inode_remove_ads(inode, stream_idx, lookup_table);
	return ret;
}

/*
 * Reads the alternate data stream entries of a WIM dentry.
 *
 * @p:	Pointer to buffer that starts with the first alternate stream entry.
 *
 * @inode:	Inode to load the alternate data streams into.
 * 			@inode->i_num_ads must have been set to the number of
 * 			alternate data streams that are expected.
 *
 * @remaining_size:	Number of bytes of data remaining in the buffer pointed
 * 				to by @p.
 *
 * The format of the on-disk alternate stream entries is as follows:
 *
 * struct wim_ads_entry_on_disk {
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
 * Return 0 on success or nonzero on failure.  On success, inode->i_ads_entries
 * is set to an array of `struct wim_ads_entry's of length inode->i_num_ads.  On
 * failure, @inode is not modified.
 */
static int read_ads_entries(const u8 *p, struct wim_inode *inode,
			    u64 remaining_size)
{
	u16 num_ads;
	struct wim_ads_entry *ads_entries;
	int ret;

	num_ads = inode->i_num_ads;
	ads_entries = CALLOC(num_ads, sizeof(inode->i_ads_entries[0]));
	if (!ads_entries) {
		ERROR("Could not allocate memory for %"PRIu16" "
		      "alternate data stream entries", num_ads);
		return WIMLIB_ERR_NOMEM;
	}

	for (u16 i = 0; i < num_ads; i++) {
		struct wim_ads_entry *cur_entry;
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

			ret = utf16_to_utf8(cur_entry->stream_name,
					    cur_entry->stream_name_len,
					    &cur_entry->stream_name_utf8,
					    &utf8_len);
			if (ret != 0)
				goto out_free_ads_entries;
			cur_entry->stream_name_utf8_len = utf8_len;
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
	inode->i_ads_entries = ads_entries;
#ifdef WITH_FUSE
	inode->i_next_stream_id = inode->i_num_ads + 1;
#endif
	return 0;
out_free_ads_entries:
	for (u16 i = 0; i < num_ads; i++)
		destroy_ads_entry(&ads_entries[i]);
	FREE(ads_entries);
	return ret;
}

/*
 * Reads a WIM directory entry, including all alternate data stream entries that
 * follow it, from the WIM image's metadata resource.
 *
 * @metadata_resource:	Buffer containing the uncompressed metadata resource.
 * @metadata_resource_len:   Length of the metadata resource.
 * @offset:	Offset of this directory entry in the metadata resource.
 * @dentry:	A `struct wim_dentry' that will be filled in by this function.
 *
 * Return 0 on success or nonzero on failure.  On failure, @dentry will have
 * been modified, but it will not be left with pointers to any allocated
 * buffers.  On success, the dentry->length field must be examined.  If zero,
 * this was a special "end of directory" dentry and not a real dentry.  If
 * nonzero, this was a real dentry.
 */
int read_dentry(const u8 metadata_resource[], u64 metadata_resource_len,
		u64 offset, struct wim_dentry *dentry)
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
	struct wim_inode *inode = NULL;

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

	p = get_u32(p, &inode->i_attributes);
	p = get_u32(p, (u32*)&inode->i_security_id);
	p = get_u64(p, &dentry->subdir_offset);

	/* 2 unused fields */
	p += 2 * sizeof(u64);
	/*p = get_u64(p, &dentry->unused1);*/
	/*p = get_u64(p, &dentry->unused2);*/

	p = get_u64(p, &inode->i_creation_time);
	p = get_u64(p, &inode->i_last_access_time);
	p = get_u64(p, &inode->i_last_write_time);

	p = get_bytes(p, SHA1_HASH_SIZE, inode->i_hash);

	/*
	 * I don't know what's going on here.  It seems like M$ screwed up the
	 * reparse points, then put the fields in the same place and didn't
	 * document it.  The WIM_HDR_FLAG_RP_FIX flag in the WIM header might
	 * have something to do with this, but it's not documented.
	 */
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		/* ??? */
		p += 4;
		p = get_u32(p, &inode->i_reparse_tag);
		p += 4;
	} else {
		p = get_u32(p, &inode->i_reparse_tag);
		p = get_u64(p, &inode->i_ino);
	}

	/* By the way, the reparse_reserved field does not actually exist (at
	 * least when the file is not a reparse point) */

	p = get_u16(p, &inode->i_num_ads);

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
		ret = WIMLIB_ERR_INVALID_DENTRY;
		goto out_free_inode;
	}

	/* Read the filename if present.  Note: if the filename is empty, there
	 * is no null terminator following it. */
	if (file_name_len) {
		file_name = MALLOC(file_name_len);
		if (!file_name) {
			ERROR("Failed to allocate %hu bytes for dentry file name",
			      file_name_len);
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_inode;
		}
		p = get_bytes(p, file_name_len, file_name);

		/* Convert filename to UTF-8. */
		ret = utf16_to_utf8(file_name, file_name_len, &file_name_utf8,
				    &file_name_utf8_len);
		if (ret != 0)
			goto out_free_file_name;
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
		DEBUG("Dentry for file or directory `%s' has %"PRIu64" extra "
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
			WARNING("Expected two zero bytes following the short name of "
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
	if (inode->i_num_ads != 0) {

		/* Trying different lengths is just a hack to make sure we have
		 * a chance of reading the ADS entries correctly despite the
		 * poor documentation. */

		if (calculated_size != dentry->length) {
			WARNING("Trying calculated dentry length (%"PRIu64") "
				"instead of dentry->length field (%"PRIu64") "
				"to read ADS entries",
				calculated_size, dentry->length);
		}
		u64 lengths_to_try[3] = {calculated_size,
					 (dentry->length + 7) & ~7,
					 dentry->length};
		ret = WIMLIB_ERR_INVALID_DENTRY;
		for (size_t i = 0; i < ARRAY_LEN(lengths_to_try); i++) {
			if (lengths_to_try[i] > metadata_resource_len - offset)
				continue;
			ret = read_ads_entries(&metadata_resource[offset + lengths_to_try[i]],
					       inode,
					       metadata_resource_len - offset - lengths_to_try[i]);
			if (ret == 0)
				goto out;
		}
		ERROR("Failed to read alternate data stream "
		      "entries of `%s'", dentry->file_name_utf8);
		goto out_free_short_name;
	}
out:

	/* We've read all the data for this dentry.  Set the names and their
	 * lengths, and we've done. */
	dentry->d_inode            = inode;
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
 * @dentry:	A pointer to a `struct wim_dentry' that is the root of the directory
 *		tree and has already been read from the metadata resource.  It
 *		does not need to be the real root because this procedure is
 *		called recursively.
 *
 * @return:	Zero on success, nonzero on failure.
 */
int read_dentry_tree(const u8 metadata_resource[], u64 metadata_resource_len,
		     struct wim_dentry *dentry)
{
	u64 cur_offset = dentry->subdir_offset;
	struct wim_dentry *child;
	struct wim_dentry cur_child;
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
		child = MALLOC(sizeof(struct wim_dentry));
		if (!child) {
			ERROR("Failed to allocate %zu bytes for new dentry",
			      sizeof(struct wim_dentry));
			ret = WIMLIB_ERR_NOMEM;
			break;
		}
		memcpy(child, &cur_child, sizeof(struct wim_dentry));
		dentry_add_child(dentry, child);
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
static u8 *write_dentry(const struct wim_dentry *dentry, u8 *p)
{
	u8 *orig_p = p;
	const u8 *hash;
	const struct wim_inode *inode = dentry->d_inode;

	/* We calculate the correct length of the dentry ourselves because the
	 * dentry->length field may been set to an unexpected value from when we
	 * read the dentry in (for example, there may have been unknown data
	 * appended to the end of the dentry...) */
	u64 length = dentry_correct_length(dentry);

	p = put_u64(p, length);
	p = put_u32(p, inode->i_attributes);
	p = put_u32(p, inode->i_security_id);
	p = put_u64(p, dentry->subdir_offset);
	p = put_u64(p, 0); /* unused1 */
	p = put_u64(p, 0); /* unused2 */
	p = put_u64(p, inode->i_creation_time);
	p = put_u64(p, inode->i_last_access_time);
	p = put_u64(p, inode->i_last_write_time);
	hash = inode_stream_hash(inode, 0);
	p = put_bytes(p, SHA1_HASH_SIZE, hash);
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		p = put_zeroes(p, 4);
		p = put_u32(p, inode->i_reparse_tag);
		p = put_zeroes(p, 4);
	} else {
		u64 link_group_id;
		p = put_u32(p, 0);
		if (inode->i_nlink == 1)
			link_group_id = 0;
		else
			link_group_id = inode->i_ino;
		p = put_u64(p, link_group_id);
	}
	p = put_u16(p, inode->i_num_ads);
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
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		p = put_u64(p, ads_entry_total_length(&inode->i_ads_entries[i]));
		p = put_u64(p, 0); /* Unused */
		hash = inode_stream_hash(inode, i + 1);
		p = put_bytes(p, SHA1_HASH_SIZE, hash);
		p = put_u16(p, inode->i_ads_entries[i].stream_name_len);
		if (inode->i_ads_entries[i].stream_name_len) {
			p = put_bytes(p, inode->i_ads_entries[i].stream_name_len,
					 (u8*)inode->i_ads_entries[i].stream_name);
			p = put_u16(p, 0);
		}
		p = put_zeroes(p, (8 - (p - orig_p) % 8) % 8);
	}
	wimlib_assert(p - orig_p == __dentry_total_length(dentry, length));
	return p;
}

static int write_dentry_cb(struct wim_dentry *dentry, void *_p)
{
	u8 **p = _p;
	*p = write_dentry(dentry, *p);
	return 0;
}

static u8 *write_dentry_tree_recursive(const struct wim_dentry *parent, u8 *p);

static int write_dentry_tree_recursive_cb(struct wim_dentry *dentry, void *_p)
{
	u8 **p = _p;
	*p = write_dentry_tree_recursive(dentry, *p);
	return 0;
}

/* Recursive function that writes a dentry tree rooted at @parent, not including
 * @parent itself, which has already been written. */
static u8 *write_dentry_tree_recursive(const struct wim_dentry *parent, u8 *p)
{
	/* Nothing to do if this dentry has no children. */
	if (parent->subdir_offset == 0)
		return p;

	/* Write child dentries and end-of-directory entry.
	 *
	 * Note: we need to write all of this dentry's children before
	 * recursively writing the directory trees rooted at each of the child
	 * dentries, since the on-disk dentries for a dentry's children are
	 * always located at consecutive positions in the metadata resource! */
	for_dentry_child(parent, write_dentry_cb, &p);

	/* write end of directory entry */
	p = put_u64(p, 0);

	/* Recurse on children. */
	for_dentry_child(parent, write_dentry_tree_recursive_cb, &p);
	return p;
}

/* Writes a directory tree to the metadata resource.
 *
 * @root:	Root of the dentry tree.
 * @p:		Pointer to a buffer with enough space for the dentry tree.
 *
 * Returns pointer to the byte after the last byte we wrote.
 */
u8 *write_dentry_tree(const struct wim_dentry *root, u8 *p)
{
	DEBUG("Writing dentry tree.");
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
