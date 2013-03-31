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
static u64
__dentry_correct_length_unaligned(u16 file_name_nbytes, u16 short_name_nbytes)
{
	u64 length = WIM_DENTRY_DISK_SIZE;
	if (file_name_nbytes)
		length += file_name_nbytes + 2;
	if (short_name_nbytes)
		length += short_name_nbytes + 2;
	return length;
}

/* Calculates the unaligned length, in bytes, of an on-disk WIM dentry, based on
 * the file name length and short name length.  Note that dentry->length is
 * ignored; also, this excludes any alternate data stream entries that may
 * follow the dentry. */
static u64
dentry_correct_length_unaligned(const struct wim_dentry *dentry)
{
	return __dentry_correct_length_unaligned(dentry->file_name_nbytes,
						 dentry->short_name_nbytes);
}

/* Return the "correct" value to write in the length field of a WIM dentry,
 * based on the file name length and short name length. */
static u64
dentry_correct_length(const struct wim_dentry *dentry)
{
	return (dentry_correct_length_unaligned(dentry) + 7) & ~7;
}

/* Return %true iff the alternate data stream entry @entry has the UTF-16LE
 * stream name @name that has length @name_nbytes bytes. */
static inline bool
ads_entry_has_name(const struct wim_ads_entry *entry,
		   const utf16lechar *name, size_t name_nbytes)
{
	return entry->stream_name_nbytes == name_nbytes &&
	       memcmp(entry->stream_name, name, name_nbytes) == 0;
}

/* Duplicates a string of system-dependent encoding into a UTF-16LE string and
 * returns the string and its length, in bytes, in the pointer arguments.  Frees
 * any existing string at the return location before overwriting it. */
static int
get_utf16le_name(const tchar *name, utf16lechar **name_utf16le_ret,
		 u16 *name_utf16le_nbytes_ret)
{
	utf16lechar *name_utf16le;
	size_t name_utf16le_nbytes;
	int ret;
#if TCHAR_IS_UTF16LE
	name_utf16le_nbytes = tstrlen(name) * sizeof(utf16lechar);
	name_utf16le = MALLOC(name_utf16le_nbytes + sizeof(utf16lechar));
	if (!name_utf16le)
		return WIMLIB_ERR_NOMEM;
	memcpy(name_utf16le, name, name_utf16le_nbytes + sizeof(utf16lechar));
	ret = 0;
#else

	ret = tstr_to_utf16le(name, tstrlen(name), &name_utf16le,
			      &name_utf16le_nbytes);
	if (ret == 0) {
		if (name_utf16le_nbytes > 0xffff) {
			FREE(name_utf16le);
			ERROR("Multibyte string \"%"TS"\" is too long!", name);
			ret = WIMLIB_ERR_INVALID_UTF8_STRING;
		}
	}
#endif
	if (ret == 0) {
		FREE(*name_utf16le_ret);
		*name_utf16le_ret = name_utf16le;
		*name_utf16le_nbytes_ret = name_utf16le_nbytes;
	}
	return ret;
}

/* Sets the name of a WIM dentry from a multibyte string. */
int
set_dentry_name(struct wim_dentry *dentry, const tchar *new_name)
{
	int ret;
	ret = get_utf16le_name(new_name, &dentry->file_name,
			       &dentry->file_name_nbytes);
	if (ret == 0) {
		/* Clear the short name and recalculate the dentry length */
		if (dentry_has_short_name(dentry)) {
			FREE(dentry->short_name);
			dentry->short_name = NULL;
			dentry->short_name_nbytes = 0;
		}
		dentry->length = dentry_correct_length(dentry);
	}
	return ret;
}

/* Returns the total length of a WIM alternate data stream entry on-disk,
 * including the stream name, the null terminator, AND the padding after the
 * entry to align the next ADS entry or dentry on an 8-byte boundary. */
static u64
ads_entry_total_length(const struct wim_ads_entry *entry)
{
	u64 len = WIM_ADS_ENTRY_DISK_SIZE;
	if (entry->stream_name_nbytes)
		len += entry->stream_name_nbytes + 2;
	return (len + 7) & ~7;
}


static u64
__dentry_total_length(const struct wim_dentry *dentry, u64 length)
{
	const struct wim_inode *inode = dentry->d_inode;
	for (u16 i = 0; i < inode->i_num_ads; i++)
		length += ads_entry_total_length(&inode->i_ads_entries[i]);
	return (length + 7) & ~7;
}

/* Calculate the aligned *total* length of an on-disk WIM dentry.  This includes
 * all alternate data streams. */
u64
dentry_correct_total_length(const struct wim_dentry *dentry)
{
	return __dentry_total_length(dentry,
				     dentry_correct_length_unaligned(dentry));
}

/* Like dentry_correct_total_length(), but use the existing dentry->length field
 * instead of calculating its "correct" value. */
static u64
dentry_total_length(const struct wim_dentry *dentry)
{
	return __dentry_total_length(dentry, dentry->length);
}

int
for_dentry_in_rbtree(struct rb_node *root,
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

static int
for_dentry_tree_in_rbtree_depth(struct rb_node *node,
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

static int
for_dentry_tree_in_rbtree(struct rb_node *node,
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

/* Calls a function on all directory entries in a WIM dentry tree.  Logically,
 * this is a pre-order traversal (the function is called on a parent dentry
 * before its children), but sibling dentries will be visited in order as well.
 * */
int
for_dentry_in_tree(struct wim_dentry *root,
		   int (*visitor)(struct wim_dentry*, void*), void *arg)
{
	int ret = visitor(root, arg);
	if (ret == 0) {
		ret = for_dentry_tree_in_rbtree(root->d_inode->i_children.rb_node,
						visitor,
						arg);
	}
	return ret;
}

/* Like for_dentry_in_tree(), but the visitor function is always called on a
 * dentry's children before on itself. */
int
for_dentry_in_tree_depth(struct wim_dentry *root,
			 int (*visitor)(struct wim_dentry*, void*), void *arg)
{
	int ret;
	ret = for_dentry_tree_in_rbtree_depth(root->d_inode->i_children.rb_node,
					      visitor, arg);
	if (ret == 0)
		ret = visitor(root, arg);
	return ret;
}

/* Calculate the full path of @dentry.  The full path of its parent must have
 * already been calculated, or it must be the root dentry. */
static int
calculate_dentry_full_path(struct wim_dentry *dentry)
{
	tchar *full_path;
	u32 full_path_nbytes;
	int ret;

	if (dentry->_full_path)
		return 0;

	if (dentry_is_root(dentry)) {
		full_path = TSTRDUP(T("/"));
		if (!full_path)
			return WIMLIB_ERR_NOMEM;
		full_path_nbytes = 1 * sizeof(tchar);
	} else {
		struct wim_dentry *parent;
		tchar *parent_full_path;
		u32 parent_full_path_nbytes;
		size_t filename_nbytes;

		parent = dentry->parent;
		if (dentry_is_root(parent)) {
			parent_full_path = T("");
			parent_full_path_nbytes = 0;
		} else {
			if (!parent->_full_path) {
				ret = calculate_dentry_full_path(parent);
				if (ret)
					return ret;
			}
			parent_full_path = parent->_full_path;
			parent_full_path_nbytes = parent->full_path_nbytes;
		}

		/* Append this dentry's name as a tchar string to the full path
		 * of the parent followed by the path separator */
	#if TCHAR_IS_UTF16LE
		filename_nbytes = dentry->file_name_nbytes;
	#else
		{
			int ret = utf16le_to_tstr_nbytes(dentry->file_name,
							 dentry->file_name_nbytes,
							 &filename_nbytes);
			if (ret)
				return ret;
		}
	#endif

		full_path_nbytes = parent_full_path_nbytes + sizeof(tchar) +
				   filename_nbytes;
		full_path = MALLOC(full_path_nbytes + sizeof(tchar));
		if (!full_path)
			return WIMLIB_ERR_NOMEM;
		memcpy(full_path, parent_full_path, parent_full_path_nbytes);
		full_path[parent_full_path_nbytes / sizeof(tchar)] = T('/');
	#if TCHAR_IS_UTF16LE
		memcpy(&full_path[parent_full_path_nbytes / sizeof(tchar) + 1],
		       dentry->file_name,
		       filename_nbytes + sizeof(tchar));
	#else
		utf16le_to_tstr_buf(dentry->file_name,
				    dentry->file_name_nbytes,
				    &full_path[parent_full_path_nbytes /
					       sizeof(tchar) + 1]);
	#endif
	}
	dentry->_full_path = full_path;
	dentry->full_path_nbytes= full_path_nbytes;
	return 0;
}

tchar *
dentry_full_path(struct wim_dentry *dentry)
{
	calculate_dentry_full_path(dentry);
	return dentry->_full_path;
}

static int
increment_subdir_offset(struct wim_dentry *dentry, void *subdir_offset_p)
{
	*(u64*)subdir_offset_p += dentry_correct_total_length(dentry);
	return 0;
}

static int
call_calculate_subdir_offsets(struct wim_dentry *dentry, void *subdir_offset_p)
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
void
calculate_subdir_offsets(struct wim_dentry *dentry, u64 *subdir_offset_p)
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

static int
compare_utf16le_names(const utf16lechar *name1, size_t nbytes1,
		      const utf16lechar *name2, size_t nbytes2)
{
	int result = memcmp(name1, name2, min(nbytes1, nbytes2));
	if (result)
		return result;
	else
		return (int)nbytes1 - (int)nbytes2;
}

static int
dentry_compare_names(const struct wim_dentry *d1, const struct wim_dentry *d2)
{
	return compare_utf16le_names(d1->file_name, d1->file_name_nbytes,
				     d2->file_name, d2->file_name_nbytes);
}


struct wim_dentry *
get_dentry_child_with_utf16le_name(const struct wim_dentry *dentry,
				   const utf16lechar *name,
				   size_t name_nbytes)
{
	struct rb_node *node = dentry->d_inode->i_children.rb_node;
	struct wim_dentry *child;
	while (node) {
		child = rbnode_dentry(node);
		int result = compare_utf16le_names(name, name_nbytes,
						   child->file_name,
						   child->file_name_nbytes);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else
			return child;
	}
	return NULL;
}

/* Returns the child of @dentry that has the file name @name.  Returns NULL if
 * no child has the name. */
struct wim_dentry *
get_dentry_child_with_name(const struct wim_dentry *dentry, const tchar *name)
{
#if TCHAR_IS_UTF16LE
	return get_dentry_child_with_utf16le_name(dentry, name,
						  tstrlen(name) * sizeof(tchar));
#else
	utf16lechar *utf16le_name;
	size_t utf16le_name_nbytes;
	int ret;
	struct wim_dentry *child;

	ret = tstr_to_utf16le(name, tstrlen(name) * sizeof(tchar),
			      &utf16le_name, &utf16le_name_nbytes);
	if (ret) {
		child = NULL;
	} else {
		child = get_dentry_child_with_utf16le_name(dentry,
							   utf16le_name,
							   utf16le_name_nbytes);
		FREE(utf16le_name);
	}
	return child;
#endif
}

static struct wim_dentry *
get_dentry_utf16le(WIMStruct *w, const utf16lechar *path,
		   size_t path_nbytes)
{
	struct wim_dentry *cur_dentry, *parent_dentry;
	const utf16lechar *p, *pp;

	cur_dentry = parent_dentry = wim_root_dentry(w);
	p = path;
	while (1) {
		while (*p == cpu_to_le16('/'))
			p++;
		if (*p == '\0')
			break;
		pp = p;
		while (*pp != cpu_to_le16('/') && *pp != cpu_to_le16('\0'))
			pp++;

		cur_dentry = get_dentry_child_with_utf16le_name(parent_dentry, p,
								(void*)pp - (void*)p);
		if (cur_dentry == NULL)
			break;
		p = pp;
		parent_dentry = cur_dentry;
	}
	if (cur_dentry == NULL) {
		if (dentry_is_directory(parent_dentry))
			errno = ENOENT;
		else
			errno = ENOTDIR;
	}
	return cur_dentry;
}

/* Returns the dentry corresponding to the @path, or NULL if there is no such
 * dentry. */
struct wim_dentry *
get_dentry(WIMStruct *w, const tchar *path)
{
#if TCHAR_IS_UTF16LE
	return get_dentry_utf16le(w, path, tstrlen(path) * sizeof(tchar));
#else
	utf16lechar *path_utf16le;
	size_t path_utf16le_nbytes;
	int ret;
	struct wim_dentry *dentry;

	ret = tstr_to_utf16le(path, tstrlen(path) * sizeof(tchar),
			      &path_utf16le, &path_utf16le_nbytes);
	if (ret)
		return NULL;
	dentry = get_dentry_utf16le(w, path_utf16le, path_utf16le_nbytes);
	FREE(path_utf16le);
	return dentry;
#endif
}

struct wim_inode *
wim_pathname_to_inode(WIMStruct *w, const tchar *path)
{
	struct wim_dentry *dentry;
	dentry = get_dentry(w, path);
	if (dentry)
		return dentry->d_inode;
	else
		return NULL;
}

/* Takes in a path of length @len in @buf, and transforms it into a string for
 * the path of its parent directory. */
static void
to_parent_name(tchar *buf, size_t len)
{
	ssize_t i = (ssize_t)len - 1;
	while (i >= 0 && buf[i] == T('/'))
		i--;
	while (i >= 0 && buf[i] != T('/'))
		i--;
	while (i >= 0 && buf[i] == T('/'))
		i--;
	buf[i + 1] = T('\0');
}

/* Returns the dentry that corresponds to the parent directory of @path, or NULL
 * if the dentry is not found. */
struct wim_dentry *
get_parent_dentry(WIMStruct *w, const tchar *path)
{
	size_t path_len = tstrlen(path);
	tchar buf[path_len + 1];

	tmemcpy(buf, path, path_len + 1);
	to_parent_name(buf, path_len);
	return get_dentry(w, buf);
}

/* Prints the full path of a dentry. */
int
print_dentry_full_path(struct wim_dentry *dentry, void *_ignore)
{
	tchar *full_path = dentry_full_path(dentry);
	if (!full_path)
		return WIMLIB_ERR_NOMEM;
	tprintf(T("%"TS"\n"), full_path);
	FREE(full_path);
	dentry->_full_path = 0;
	dentry->full_path_nbytes = 0;
	return 0;
}

/* We want to be able to show the names of the file attribute flags that are
 * set. */
struct file_attr_flag {
	u32 flag;
	const tchar *name;
};
struct file_attr_flag file_attr_flags[] = {
	{FILE_ATTRIBUTE_READONLY,	    T("READONLY")},
	{FILE_ATTRIBUTE_HIDDEN,		    T("HIDDEN")},
	{FILE_ATTRIBUTE_SYSTEM,		    T("SYSTEM")},
	{FILE_ATTRIBUTE_DIRECTORY,	    T("DIRECTORY")},
	{FILE_ATTRIBUTE_ARCHIVE,	    T("ARCHIVE")},
	{FILE_ATTRIBUTE_DEVICE,		    T("DEVICE")},
	{FILE_ATTRIBUTE_NORMAL,		    T("NORMAL")},
	{FILE_ATTRIBUTE_TEMPORARY,	    T("TEMPORARY")},
	{FILE_ATTRIBUTE_SPARSE_FILE,	    T("SPARSE_FILE")},
	{FILE_ATTRIBUTE_REPARSE_POINT,	    T("REPARSE_POINT")},
	{FILE_ATTRIBUTE_COMPRESSED,	    T("COMPRESSED")},
	{FILE_ATTRIBUTE_OFFLINE,	    T("OFFLINE")},
	{FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,T("NOT_CONTENT_INDEXED")},
	{FILE_ATTRIBUTE_ENCRYPTED,	    T("ENCRYPTED")},
	{FILE_ATTRIBUTE_VIRTUAL,	    T("VIRTUAL")},
};

/* Prints a directory entry.  @lookup_table is a pointer to the lookup table, if
 * available.  If the dentry is unresolved and the lookup table is NULL, the
 * lookup table entries will not be printed.  Otherwise, they will be. */
int
print_dentry(struct wim_dentry *dentry, void *lookup_table)
{
	const u8 *hash;
	struct wim_lookup_table_entry *lte;
	const struct wim_inode *inode = dentry->d_inode;
	tchar buf[50];

	tprintf(T("[DENTRY]\n"));
	tprintf(T("Length            = %"PRIu64"\n"), dentry->length);
	tprintf(T("Attributes        = 0x%x\n"), inode->i_attributes);
	for (size_t i = 0; i < ARRAY_LEN(file_attr_flags); i++)
		if (file_attr_flags[i].flag & inode->i_attributes)
			tprintf(T("    FILE_ATTRIBUTE_%"TS" is set\n"),
				file_attr_flags[i].name);
	tprintf(T("Security ID       = %d\n"), inode->i_security_id);
	tprintf(T("Subdir offset     = %"PRIu64"\n"), dentry->subdir_offset);

	wim_timestamp_to_str(inode->i_creation_time, buf, sizeof(buf));
	tprintf(T("Creation Time     = %"TS"\n"), buf);

	wim_timestamp_to_str(inode->i_last_access_time, buf, sizeof(buf));
	tprintf(T("Last Access Time  = %"TS"\n"), buf);

	wim_timestamp_to_str(inode->i_last_write_time, buf, sizeof(buf));
	tprintf(T("Last Write Time   = %"TS"\n"), buf);

	tprintf(T("Reparse Tag       = 0x%"PRIx32"\n"), inode->i_reparse_tag);
	tprintf(T("Hard Link Group   = 0x%"PRIx64"\n"), inode->i_ino);
	tprintf(T("Hard Link Group Size = %"PRIu32"\n"), inode->i_nlink);
	tprintf(T("Number of Alternate Data Streams = %hu\n"), inode->i_num_ads);
	if (dentry_has_long_name(dentry))
		wimlib_printf(T("Filename = \"%"WS"\"\n"), dentry->file_name);
	if (dentry_has_short_name(dentry))
		wimlib_printf(T("Short Name \"%"WS"\"\n"), dentry->short_name);
	if (dentry->_full_path)
		tprintf(T("Full Path = \"%"TS"\"\n"), dentry->_full_path);

	lte = inode_stream_lte(dentry->d_inode, 0, lookup_table);
	if (lte) {
		print_lookup_table_entry(lte, stdout);
	} else {
		hash = inode_stream_hash(inode, 0);
		if (hash) {
			tprintf(T("Hash              = 0x"));
			print_hash(hash, stdout);
			tputchar(T('\n'));
			tputchar(T('\n'));
		}
	}
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		tprintf(T("[Alternate Stream Entry %u]\n"), i);
		wimlib_printf(T("Name = \"%"WS"\"\n"),
			      inode->i_ads_entries[i].stream_name);
		tprintf(T("Name Length (UTF16 bytes) = %hu\n"),
		       inode->i_ads_entries[i].stream_name_nbytes);
		hash = inode_stream_hash(inode, i + 1);
		if (hash) {
			tprintf(T("Hash              = 0x"));
			print_hash(hash, stdout);
			tputchar(T('\n'));
		}
		print_lookup_table_entry(inode_stream_lte(inode, i + 1, lookup_table),
					 stdout);
	}
	return 0;
}

/* Initializations done on every `struct wim_dentry'. */
static void
dentry_common_init(struct wim_dentry *dentry)
{
	memset(dentry, 0, sizeof(struct wim_dentry));
}

struct wim_inode *
new_timeless_inode()
{
	struct wim_inode *inode = CALLOC(1, sizeof(struct wim_inode));
	if (inode) {
		inode->i_security_id = -1;
		inode->i_nlink = 1;
		inode->i_next_stream_id = 1;
	#ifdef WITH_FUSE
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

static struct wim_inode *
new_inode()
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

/* Creates an unlinked directory entry. */
int
new_dentry(const tchar *name, struct wim_dentry **dentry_ret)
{
	struct wim_dentry *dentry;
	int ret;

	dentry = MALLOC(sizeof(struct wim_dentry));
	if (!dentry)
		return WIMLIB_ERR_NOMEM;

	dentry_common_init(dentry);
	ret = set_dentry_name(dentry, name);
	if (ret == 0) {
		dentry->parent = dentry;
		*dentry_ret = dentry;
	} else {
		FREE(dentry);
		ERROR("Failed to set name on new dentry with name \"%"TS"\"",
		      name);
	}
	return ret;
}


static int
__new_dentry_with_inode(const tchar *name, struct wim_dentry **dentry_ret,
			bool timeless)
{
	struct wim_dentry *dentry;
	int ret;

	ret = new_dentry(name, &dentry);
	if (ret)
		return ret;

	if (timeless)
		dentry->d_inode = new_timeless_inode();
	else
		dentry->d_inode = new_inode();
	if (!dentry->d_inode) {
		free_dentry(dentry);
		return WIMLIB_ERR_NOMEM;
	}

	inode_add_dentry(dentry, dentry->d_inode);
	*dentry_ret = dentry;
	return 0;
}

int
new_dentry_with_timeless_inode(const tchar *name, struct wim_dentry **dentry_ret)
{
	return __new_dentry_with_inode(name, dentry_ret, true);
}

int
new_dentry_with_inode(const tchar *name, struct wim_dentry **dentry_ret)
{
	return __new_dentry_with_inode(name, dentry_ret, false);
}


static int
init_ads_entry(struct wim_ads_entry *ads_entry, const void *name,
	       size_t name_nbytes, bool is_utf16le)
{
	int ret = 0;
	memset(ads_entry, 0, sizeof(*ads_entry));

	if (is_utf16le) {
		utf16lechar *p = MALLOC(name_nbytes + sizeof(utf16lechar));
		if (!p)
			return WIMLIB_ERR_NOMEM;
		memcpy(p, name, name_nbytes);
		p[name_nbytes / 2] = 0;
		ads_entry->stream_name = p;
		ads_entry->stream_name_nbytes = name_nbytes;
	} else {
		if (name && *(const tchar*)name != T('\0')) {
			ret = get_utf16le_name(name, &ads_entry->stream_name,
					       &ads_entry->stream_name_nbytes);
		}
	}
	return ret;
}

static void
destroy_ads_entry(struct wim_ads_entry *ads_entry)
{
	FREE(ads_entry->stream_name);
}

/* Frees an inode. */
void
free_inode(struct wim_inode *inode)
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
static void
put_inode(struct wim_inode *inode)
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
void
free_dentry(struct wim_dentry *dentry)
{
	FREE(dentry->file_name);
	FREE(dentry->short_name);
	FREE(dentry->_full_path);
	if (dentry->d_inode)
		put_inode(dentry->d_inode);
	FREE(dentry);
}

/* This function is passed as an argument to for_dentry_in_tree_depth() in order
 * to free a directory tree. */
static int
do_free_dentry(struct wim_dentry *dentry, void *__lookup_table)
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
	free_dentry(dentry);
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
void
free_dentry_tree(struct wim_dentry *root, struct wim_lookup_table *lookup_table)
{
	if (root)
		for_dentry_in_tree_depth(root, do_free_dentry, lookup_table);
}

/*
 * Links a dentry into the directory tree.
 *
 * @parent: The dentry that will be the parent of @dentry.
 * @dentry: The dentry to link.
 */
bool
dentry_add_child(struct wim_dentry * restrict parent,
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
void
unlink_dentry(struct wim_dentry *dentry)
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
struct wim_ads_entry *
inode_get_ads_entry(struct wim_inode *inode, const tchar *stream_name,
		    u16 *idx_ret)
{
	if (inode->i_num_ads == 0) {
		return NULL;
	} else {
		size_t stream_name_utf16le_nbytes;
		u16 i;
		struct wim_ads_entry *result;

	#if TCHAR_IS_UTF16LE
		const utf16lechar *stream_name_utf16le;

		stream_name_utf16le = stream_name;
		stream_name_utf16le_nbytes = tstrlen(stream_name) * sizeof(tchar);
	#else
		utf16lechar *stream_name_utf16le;

		{
			int ret = tstr_to_utf16le(stream_name,
						  tstrlen(stream_name) *
						      sizeof(tchar),
						  &stream_name_utf16le,
						  &stream_name_utf16le_nbytes);
			if (ret)
				return NULL;
		}
	#endif
		i = 0;
		result = NULL;
		do {
			if (ads_entry_has_name(&inode->i_ads_entries[i],
					       stream_name_utf16le,
					       stream_name_utf16le_nbytes))
			{
				if (idx_ret)
					*idx_ret = i;
				result = &inode->i_ads_entries[i];
				break;
			}
		} while (++i != inode->i_num_ads);
	#if !TCHAR_IS_UTF16LE
		FREE(stream_name_utf16le);
	#endif
		return result;
	}
}

static struct wim_ads_entry *
do_inode_add_ads(struct wim_inode *inode, const void *stream_name,
		 size_t stream_name_nbytes, bool is_utf16le)
{
	u16 num_ads;
	struct wim_ads_entry *ads_entries;
	struct wim_ads_entry *new_entry;

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
	if (init_ads_entry(new_entry, stream_name, stream_name_nbytes, is_utf16le))
		return NULL;
	new_entry->stream_id = inode->i_next_stream_id++;
	inode->i_num_ads = num_ads;
	return new_entry;
}

struct wim_ads_entry *
inode_add_ads_utf16le(struct wim_inode *inode,
		      const utf16lechar *stream_name,
		      size_t stream_name_nbytes)
{
	DEBUG("Add alternate data stream \"%"WS"\"", stream_name);
	return do_inode_add_ads(inode, stream_name, stream_name_nbytes, true);
}

/*
 * Add an alternate stream entry to a WIM inode and return a pointer to it, or
 * NULL if memory could not be allocated.
 */
struct wim_ads_entry *
inode_add_ads(struct wim_inode *inode, const tchar *stream_name)
{
	DEBUG("Add alternate data stream \"%"TS"\"", stream_name);
	return do_inode_add_ads(inode, stream_name,
				tstrlen(stream_name) * sizeof(tchar),
				TCHAR_IS_UTF16LE);
}

int
inode_add_ads_with_data(struct wim_inode *inode, const tchar *name,
			const void *value, size_t size,
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
			goto out_remove_ads_entry;
		value_copy = MALLOC(size);
		if (!value_copy) {
			FREE(lte);
			goto out_remove_ads_entry;
		}
		memcpy(value_copy, value, size);
		lte->resource_location            = RESOURCE_IN_ATTACHED_BUFFER;
		lte->attached_buffer              = value_copy;
		lte->resource_entry.original_size = size;
		lte->resource_entry.size          = size;
		copy_hash(lte->hash, value_hash);
		lookup_table_insert(lookup_table, lte);
	}
	new_ads_entry->lte = lte;
	ret = 0;
	goto out;
out_remove_ads_entry:
	inode_remove_ads(inode, new_ads_entry - inode->i_ads_entries,
			 lookup_table);
out:
	return ret;
}

/* Remove an alternate data stream from a WIM inode  */
void
inode_remove_ads(struct wim_inode *inode, u16 idx,
		 struct wim_lookup_table *lookup_table)
{
	struct wim_ads_entry *ads_entry;
	struct wim_lookup_table_entry *lte;

	wimlib_assert(idx < inode->i_num_ads);
	wimlib_assert(inode->i_resolved);

	ads_entry = &inode->i_ads_entries[idx];

	DEBUG("Remove alternate data stream \"%"WS"\"", ads_entry->stream_name);

	lte = ads_entry->lte;
	if (lte)
		lte_decrement_refcnt(lte, lookup_table);

	destroy_ads_entry(ads_entry);

	memmove(&inode->i_ads_entries[idx],
		&inode->i_ads_entries[idx + 1],
		(inode->i_num_ads - idx - 1) * sizeof(inode->i_ads_entries[0]));
	inode->i_num_ads--;
}

#ifndef __WIN32__
int
inode_get_unix_data(const struct wim_inode *inode,
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

	ret = read_full_resource_into_buf(lte, unix_data, true);
	if (ret)
		return ret;

	if (unix_data->version != 0)
		return BAD_UNIX_DATA;
	return 0;
}

int
inode_set_unix_data(struct wim_inode *inode, uid_t uid, gid_t gid, mode_t mode,
		    struct wim_lookup_table *lookup_table, int which)
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
				      &unix_data,
				      sizeof(struct wimlib_unix_data),
				      lookup_table);
	if (ret == 0 && have_unix_data)
		inode_remove_ads(inode, stream_idx, lookup_table);
	return ret;
}
#endif /* !__WIN32__ */

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
static int
read_ads_entries(const u8 *p, struct wim_inode *inode, u64 remaining_size)
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
		p = get_bytes(p, SHA1_HASH_SIZE, cur_entry->hash);
		p = get_u16(p, &cur_entry->stream_name_nbytes);

		cur_entry->stream_name = NULL;

		/* Length including neither the null terminator nor the padding
		 * */
		length_no_padding = WIM_ADS_ENTRY_DISK_SIZE +
				    cur_entry->stream_name_nbytes;

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

		if (cur_entry->stream_name_nbytes) {
			cur_entry->stream_name = MALLOC(cur_entry->stream_name_nbytes + 2);
			if (!cur_entry->stream_name) {
				ret = WIMLIB_ERR_NOMEM;
				goto out_free_ads_entries;
			}
			get_bytes(p, cur_entry->stream_name_nbytes,
				  cur_entry->stream_name);
			cur_entry->stream_name[cur_entry->stream_name_nbytes / 2] = 0;
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
int
read_dentry(const u8 metadata_resource[], u64 metadata_resource_len,
	    u64 offset, struct wim_dentry *dentry)
{
	const u8 *p;
	u64 calculated_size;
	utf16lechar *file_name = NULL;
	utf16lechar *short_name = NULL;
	u16 short_name_nbytes;
	u16 file_name_nbytes;
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

	p = get_u16(p, &short_name_nbytes);
	p = get_u16(p, &file_name_nbytes);

	/* We now know the length of the file name and short name.  Make sure
	 * the length of the dentry is large enough to actually hold them.
	 *
	 * The calculated length here is unaligned to allow for the possibility
	 * that the dentry->length names an unaligned length, although this
	 * would be unexpected. */
	calculated_size = __dentry_correct_length_unaligned(file_name_nbytes,
							    short_name_nbytes);

	if (dentry->length < calculated_size) {
		ERROR("Unexpected end of directory entry! (Expected "
		      "at least %"PRIu64" bytes, got %"PRIu64" bytes. "
		      "short_name_nbytes = %hu, file_name_nbytes = %hu)",
		      calculated_size, dentry->length,
		      short_name_nbytes, file_name_nbytes);
		ret = WIMLIB_ERR_INVALID_DENTRY;
		goto out_free_inode;
	}

	/* Read the filename if present.  Note: if the filename is empty, there
	 * is no null terminator following it. */
	if (file_name_nbytes) {
		file_name = MALLOC(file_name_nbytes + 2);
		if (!file_name) {
			ERROR("Failed to allocate %d bytes for dentry file name",
			      file_name_nbytes + 2);
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_inode;
		}
		p = get_bytes(p, file_name_nbytes + 2, file_name);
		if (file_name[file_name_nbytes / 2] != 0) {
			file_name[file_name_nbytes / 2] = 0;
			WARNING("File name in WIM dentry \"%"WS"\" is not "
				"null-terminated!", file_name);
		}
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
		/*DEBUG("Dentry for file or directory `%"WS"' has %"PRIu64" "*/
		      /*"extra bytes of data", file_name,*/
		      /*dentry->length - calculated_size);*/
	}

	/* Read the short filename if present.  Note: if there is no short
	 * filename, there is no null terminator following it. */
	if (short_name_nbytes) {
		short_name = MALLOC(short_name_nbytes + 2);
		if (!short_name) {
			ERROR("Failed to allocate %d bytes for dentry short name",
			      short_name_nbytes + 2);
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_file_name;
		}
		p = get_bytes(p, short_name_nbytes + 2, short_name);
		if (short_name[short_name_nbytes / 2] != 0) {
			short_name[short_name_nbytes / 2] = 0;
			WARNING("Short name in WIM dentry \"%"WS"\" is not "
				"null-terminated!", file_name);
		}
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
		      "entries of WIM dentry \"%"WS"\"", file_name);
		goto out_free_short_name;
	}
out:
	/* We've read all the data for this dentry.  Set the names and their
	 * lengths, and we've done. */
	dentry->d_inode           = inode;
	dentry->file_name         = file_name;
	dentry->short_name        = short_name;
	dentry->file_name_nbytes  = file_name_nbytes;
	dentry->short_name_nbytes = short_name_nbytes;
	return 0;
out_free_short_name:
	FREE(short_name);
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
 * Returns zero on success; nonzero on failure.
 */
int
read_dentry_tree(const u8 metadata_resource[], u64 metadata_resource_len,
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
static u8 *
write_dentry(const struct wim_dentry *dentry, u8 *p)
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
	p = put_u16(p, dentry->short_name_nbytes);
	p = put_u16(p, dentry->file_name_nbytes);
	if (dentry_has_long_name(dentry)) {
		p = put_bytes(p, dentry->file_name_nbytes + 2,
			      dentry->file_name);
	}
	if (dentry_has_short_name(dentry)) {
		p = put_bytes(p, dentry->short_name_nbytes + 2,
			      dentry->short_name);
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
		p = put_u16(p, inode->i_ads_entries[i].stream_name_nbytes);
		if (inode->i_ads_entries[i].stream_name_nbytes) {
			p = put_bytes(p,
				      inode->i_ads_entries[i].stream_name_nbytes + 2,
				      inode->i_ads_entries[i].stream_name);
		}
		p = put_zeroes(p, (8 - (p - orig_p) % 8) % 8);
	}
	wimlib_assert(p - orig_p == __dentry_total_length(dentry, length));
	return p;
}

static int
write_dentry_cb(struct wim_dentry *dentry, void *_p)
{
	u8 **p = _p;
	*p = write_dentry(dentry, *p);
	return 0;
}

static u8 *
write_dentry_tree_recursive(const struct wim_dentry *parent, u8 *p);

static int
write_dentry_tree_recursive_cb(struct wim_dentry *dentry, void *_p)
{
	u8 **p = _p;
	*p = write_dentry_tree_recursive(dentry, *p);
	return 0;
}

/* Recursive function that writes a dentry tree rooted at @parent, not including
 * @parent itself, which has already been written. */
static u8 *
write_dentry_tree_recursive(const struct wim_dentry *parent, u8 *p)
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
u8 *
write_dentry_tree(const struct wim_dentry *root, u8 *p)
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
