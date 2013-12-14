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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/resource.h"
#include "wimlib/security.h"
#include "wimlib/sha1.h"
#include "wimlib/timestamp.h"

#include <errno.h>

/* WIM alternate data stream entry (on-disk format) */
struct wim_ads_entry_on_disk {
	/*  Length of the entry, in bytes.  This apparently includes all
	 *  fixed-length fields, plus the stream name and null terminator if
	 *  present, and the padding up to an 8 byte boundary.  wimlib is a
	 *  little less strict when reading the entries, and only requires that
	 *  the number of bytes from this field is at least as large as the size
	 *  of the fixed length fields and stream name without null terminator.
	 *  */
	le64  length;

	le64  reserved;

	/* SHA1 message digest of the uncompressed stream; or, alternatively,
	 * can be all zeroes if the stream has zero length. */
	u8 hash[SHA1_HASH_SIZE];

	/* Length of the stream name, in bytes.  0 if the stream is unnamed.  */
	le16 stream_name_nbytes;

	/* Stream name in UTF-16LE.  It is @stream_name_nbytes bytes long,
	 * excluding the the null terminator.  There is a null terminator
	 * character if @stream_name_nbytes != 0; i.e., if this stream is named.
	 * */
	utf16lechar stream_name[];
} _packed_attribute;

#define WIM_ADS_ENTRY_DISK_SIZE 38

/* On-disk format of a WIM dentry (directory entry), located in the metadata
 * resource for a WIM image.  */
struct wim_dentry_on_disk {

	/* Length of this directory entry in bytes, not including any alternate
	 * data stream entries.  Should be a multiple of 8 so that the following
	 * dentry or alternate data stream entry is aligned on an 8-byte
	 * boundary.  (If not, wimlib will round it up.)  It must be at least as
	 * long as the fixed-length fields of the dentry (WIM_DENTRY_DISK_SIZE),
	 * plus the lengths of the file name and/or short name if present.
	 *
	 * It is also possible for this field to be 0.  This situation, which is
	 * undocumented, indicates the end of a list of sibling nodes in a
	 * directory.  It also means the real length is 8, because the dentry
	 * included only the length field, but that takes up 8 bytes.  */
	le64 length;

	/* Attributes of the file or directory.  This is a bitwise OR of the
	 * FILE_ATTRIBUTE_* constants and should correspond to the value
	 * retrieved by GetFileAttributes() on Windows. */
	le32 attributes;

	/* A value that specifies the security descriptor for this file or
	 * directory.  If -1, the file or directory has no security descriptor.
	 * Otherwise, it is a 0-based index into the WIM image's table of
	 * security descriptors (see: `struct wim_security_data') */
	sle32 security_id;

	/* Offset, in bytes, from the start of the uncompressed metadata
	 * resource of this directory's child directory entries, or 0 if this
	 * directory entry does not correspond to a directory or otherwise does
	 * not have any children. */
	le64 subdir_offset;

	/* Reserved fields */
	le64 unused_1;
	le64 unused_2;


	/* Creation time, last access time, and last write time, in
	 * 100-nanosecond intervals since 12:00 a.m UTC January 1, 1601.  They
	 * should correspond to the times gotten by calling GetFileTime() on
	 * Windows. */
	le64 creation_time;
	le64 last_access_time;
	le64 last_write_time;

	/* Vaguely, the SHA-1 message digest ("hash") of the file's contents.
	 * More specifically, this is for the "unnamed data stream" rather than
	 * any "alternate data streams".  This hash value is used to look up the
	 * corresponding entry in the WIM's stream lookup table to actually find
	 * the file contents within the WIM.
	 *
	 * If the file has no unnamed data stream (e.g. is a directory), then
	 * this field will be all zeroes.  If the unnamed data stream is empty
	 * (i.e. an "empty file"), then this field is also expected to be all
	 * zeroes.  (It will be if wimlib created the WIM image, at least;
	 * otherwise it can't be ruled out that the SHA-1 message digest of 0
	 * bytes of data is given explicitly.)
	 *
	 * If the file has reparse data, then this field will instead specify
	 * the SHA-1 message digest of the reparse data.  If it is somehow
	 * possible for a file to have both an unnamed data stream and reparse
	 * data, then this is not handled by wimlib.
	 *
	 * As a further special case, if this field is all zeroes but there is
	 * an alternate data stream entry with no name and a nonzero SHA-1
	 * message digest field, then that hash must be used instead of this
	 * one.  (wimlib does not use this quirk on WIM images it creates.)
	 */
	u8 unnamed_stream_hash[SHA1_HASH_SIZE];

	/* The format of the following data is not yet completely known and they
	 * do not correspond to Microsoft's documentation.
	 *
	 * If this directory entry is for a reparse point (has
	 * FILE_ATTRIBUTE_REPARSE_POINT set in the attributes field), then the
	 * version of the following fields containing the reparse tag is valid.
	 * Furthermore, the field notated as not_rpfixed, as far as I can tell,
	 * is supposed to be set to 1 if reparse point fixups (a.k.a. fixing the
	 * targets of absolute symbolic links) were *not* done, and otherwise 0.
	 *
	 * If this directory entry is not for a reparse point, then the version
	 * of the following fields containing the hard_link_group_id is valid.
	 * All MS says about this field is that "If this file is part of a hard
	 * link set, all the directory entries in the set will share the same
	 * value in this field.".  However, more specifically I have observed
	 * the following:
	 *    - If the file is part of a hard link set of size 1, then the
	 *    hard_link_group_id should be set to either 0, which is treated
	 *    specially as indicating "not hardlinked", or any unique value.
	 *    - The specific nonzero values used to identity hard link sets do
	 *    not matter, as long as they are unique.
	 *    - However, due to bugs in Microsoft's software, it is actually NOT
	 *    guaranteed that directory entries that share the same hard link
	 *    group ID are actually hard linked to each either.  We have to
	 *    handle this by using special code to use distinguishing features
	 *    (which is possible because some information about the underlying
	 *    inode is repeated in each dentry) to split up these fake hard link
	 *    groups into what they actually are supposed to be.
	 */
	union {
		struct {
			le32 rp_unknown_1;
			le32 reparse_tag;
			le16 rp_unknown_2;
			le16 not_rpfixed;
		} _packed_attribute reparse;
		struct {
			le32 rp_unknown_1;
			le64 hard_link_group_id;
		} _packed_attribute nonreparse;
	};

	/* Number of alternate data stream entries that directly follow this
	 * dentry on-disk. */
	le16 num_alternate_data_streams;

	/* Length of this file's UTF-16LE encoded short name (8.3 DOS-compatible
	 * name), if present, in bytes, excluding the null terminator.  If this
	 * file has no short name, then this field should be 0.  */
	le16 short_name_nbytes;

	/* Length of this file's UTF-16LE encoded "long" name, excluding the
	 * null terminator.  If this file has no short name, then this field
	 * should be 0.  It's expected that only the root dentry has this field
	 * set to 0.  */
	le16 file_name_nbytes;

	/* Followed by variable length file name, in UTF16-LE, if
	 * file_name_nbytes != 0.  Includes null terminator. */
	/*utf16lechar file_name[];*/

	/* Followed by variable length short name, in UTF16-LE, if
	 * short_name_nbytes != 0.  Includes null terminator. */
	/*utf16lechar short_name[];*/
} _packed_attribute;

#define WIM_DENTRY_DISK_SIZE 102

/* Calculates the unaligned length, in bytes, of an on-disk WIM dentry that has
 * a file name and short name that take the specified numbers of bytes.  This
 * excludes any alternate data stream entries that may follow the dentry. */
static u64
dentry_correct_length_unaligned(u16 file_name_nbytes, u16 short_name_nbytes)
{
	u64 length = sizeof(struct wim_dentry_on_disk);
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
dentry_correct_length_aligned(const struct wim_dentry *dentry)
{
	u64 len;

	len = dentry_correct_length_unaligned(dentry->file_name_nbytes,
					      dentry->short_name_nbytes);
	return (len + 7) & ~7;
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
	if (name_utf16le == NULL)
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
	}
	return ret;
}

/* Returns the total length of a WIM alternate data stream entry on-disk,
 * including the stream name, the null terminator, AND the padding after the
 * entry to align the next ADS entry or dentry on an 8-byte boundary. */
static u64
ads_entry_total_length(const struct wim_ads_entry *entry)
{
	u64 len = sizeof(struct wim_ads_entry_on_disk);
	if (entry->stream_name_nbytes)
		len += entry->stream_name_nbytes + 2;
	return (len + 7) & ~7;
}

/*
 * Determine whether to include a "dummy" stream when writing a WIM dentry:
 *
 * Some versions of Microsoft's WIM software (the boot driver(s) in WinPE 3.0,
 * for example) contain a bug where they assume the first alternate data stream
 * (ADS) entry of a dentry with a nonzero ADS count specifies the unnamed
 * stream, even if it has a name and the unnamed stream is already specified in
 * the hash field of the dentry itself.
 *
 * wimlib has to work around this behavior by carefully emulating the behavior
 * of (most versions of) ImageX/WIMGAPI, which move the unnamed stream reference
 * into the alternate stream entries whenever there are named data streams, even
 * though there is already a field in the dentry itself for the unnamed stream
 * reference, which then goes to waste.
 */
static inline bool inode_needs_dummy_stream(const struct wim_inode *inode)
{
	return (inode->i_num_ads > 0 &&
		inode->i_num_ads < 0xffff && /* overflow check */
		inode->i_canonical_streams); /* assume the dentry is okay if it
						already had an unnamed ADS entry
						when it was read in  */
}

/* Calculate the total number of bytes that will be consumed when a WIM dentry
 * is written.  This includes base dentry and name fields as well as all
 * alternate data stream entries and alignment bytes.  */
u64
dentry_out_total_length(const struct wim_dentry *dentry)
{
	u64 length = dentry_correct_length_aligned(dentry);
	const struct wim_inode *inode = dentry->d_inode;

	if (inode_needs_dummy_stream(inode))
		length += ads_entry_total_length(&(struct wim_ads_entry){});

	for (u16 i = 0; i < inode->i_num_ads; i++)
		length += ads_entry_total_length(&inode->i_ads_entries[i]);

	return length;
}

/* Calculate the aligned, total length of a dentry, including all alternate data
 * stream entries.  Uses dentry->length.  */
static u64
dentry_in_total_length(const struct wim_dentry *dentry)
{
	u64 length = dentry->length;
	const struct wim_inode *inode = dentry->d_inode;
	for (u16 i = 0; i < inode->i_num_ads; i++)
		length += ads_entry_total_length(&inode->i_ads_entries[i]);
	return (length + 7) & ~7;
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
		if (ret)
			return ret;
		ret = for_dentry_in_tree(rbnode_dentry(node), visitor, arg);
		if (ret)
			return ret;
		ret = for_dentry_tree_in_rbtree(node->rb_right, visitor, arg);
		if (ret)
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
	int ret;

	if (root == NULL)
		return 0;
	ret = (*visitor)(root, arg);
	if (ret)
		return ret;
	return for_dentry_tree_in_rbtree(root->d_inode->i_children.rb_node,
					 visitor,
					 arg);
}

/* Like for_dentry_in_tree(), but the visitor function is always called on a
 * dentry's children before on itself. */
int
for_dentry_in_tree_depth(struct wim_dentry *root,
			 int (*visitor)(struct wim_dentry*, void*), void *arg)
{
	int ret;

	if (root == NULL)
		return 0;
	ret = for_dentry_tree_in_rbtree_depth(root->d_inode->i_children.rb_node,
					      visitor, arg);
	if (ret)
		return ret;
	return (*visitor)(root, arg);
}

/* Calculate the full path of @dentry.  The full path of its parent must have
 * already been calculated, or it must be the root dentry. */
int
calculate_dentry_full_path(struct wim_dentry *dentry)
{
	tchar *full_path;
	u32 full_path_nbytes;
	int ret;

	if (dentry->_full_path)
		return 0;

	if (dentry_is_root(dentry)) {
		static const tchar _root_path[] = {WIM_PATH_SEPARATOR, T('\0')};
		full_path = TSTRDUP(_root_path);
		if (full_path == NULL)
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
			if (parent->_full_path == NULL) {
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
		if (full_path == NULL)
			return WIMLIB_ERR_NOMEM;
		memcpy(full_path, parent_full_path, parent_full_path_nbytes);
		full_path[parent_full_path_nbytes / sizeof(tchar)] = WIM_PATH_SEPARATOR;
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

static int
do_calculate_dentry_full_path(struct wim_dentry *dentry, void *_ignore)
{
	return calculate_dentry_full_path(dentry);
}

int
calculate_dentry_tree_full_paths(struct wim_dentry *root)
{
	return for_dentry_in_tree(root, do_calculate_dentry_full_path, NULL);
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
	*(u64*)subdir_offset_p += dentry_out_total_length(dentry);
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

/* Case-sensitive UTF-16LE dentry or stream name comparison.  Used on both UNIX
 * (always) and Windows (sometimes) */
static int
compare_utf16le_names_case_sensitive(const utf16lechar *name1, size_t nbytes1,
				     const utf16lechar *name2, size_t nbytes2)
{
	/* Return the result if the strings differ up to their minimum length.
	 * Note that we cannot use strcmp() or strncmp() here, as the strings
	 * are in UTF-16LE format. */
	int result = memcmp(name1, name2, min(nbytes1, nbytes2));
	if (result)
		return result;

	/* The strings are the same up to their minimum length, so return a
	 * result based on their lengths. */
	if (nbytes1 < nbytes2)
		return -1;
	else if (nbytes1 > nbytes2)
		return 1;
	else
		return 0;
}

#ifdef __WIN32__
/* Windoze: Case-insensitive UTF-16LE dentry or stream name comparison */
static int
compare_utf16le_names_case_insensitive(const utf16lechar *name1, size_t nbytes1,
				       const utf16lechar *name2, size_t nbytes2)
{
	/* Return the result if the strings differ up to their minimum length.
	 * */
	int result = _wcsnicmp((const wchar_t*)name1, (const wchar_t*)name2,
			       min(nbytes1 / 2, nbytes2 / 2));
	if (result)
		return result;

	/* The strings are the same up to their minimum length, so return a
	 * result based on their lengths. */
	if (nbytes1 < nbytes2)
		return -1;
	else if (nbytes1 > nbytes2)
		return 1;
	else
		return 0;
}
#endif /* __WIN32__ */

#ifdef __WIN32__
#  define compare_utf16le_names compare_utf16le_names_case_insensitive
#else
#  define compare_utf16le_names compare_utf16le_names_case_sensitive
#endif


#ifdef __WIN32__
static int
dentry_compare_names_case_insensitive(const struct wim_dentry *d1,
				      const struct wim_dentry *d2)
{
	return compare_utf16le_names_case_insensitive(d1->file_name,
						      d1->file_name_nbytes,
						      d2->file_name,
						      d2->file_name_nbytes);
}
#endif /* __WIN32__ */

static int
dentry_compare_names_case_sensitive(const struct wim_dentry *d1,
				    const struct wim_dentry *d2)
{
	return compare_utf16le_names_case_sensitive(d1->file_name,
						    d1->file_name_nbytes,
						    d2->file_name,
						    d2->file_name_nbytes);
}

#ifdef __WIN32__
#  define dentry_compare_names dentry_compare_names_case_insensitive
#else
#  define dentry_compare_names dentry_compare_names_case_sensitive
#endif

/* Return %true iff the alternate data stream entry @entry has the UTF-16LE
 * stream name @name that has length @name_nbytes bytes. */
static inline bool
ads_entry_has_name(const struct wim_ads_entry *entry,
		   const utf16lechar *name, size_t name_nbytes)
{
	return !compare_utf16le_names(name, name_nbytes,
				      entry->stream_name,
				      entry->stream_name_nbytes);
}

/* Given a UTF-16LE filename and a directory, look up the dentry for the file.
 * Return it if found, otherwise NULL.  This is case-sensitive on UNIX and
 * case-insensitive on Windows. */
struct wim_dentry *
get_dentry_child_with_utf16le_name(const struct wim_dentry *dentry,
				   const utf16lechar *name,
				   size_t name_nbytes)
{
	struct rb_node *node;

#ifdef __WIN32__
	node = dentry->d_inode->i_children_case_insensitive.rb_node;
#else
	node = dentry->d_inode->i_children.rb_node;
#endif

	struct wim_dentry *child;
	while (node) {
	#ifdef __WIN32__
		child = rb_entry(node, struct wim_dentry, rb_node_case_insensitive);
	#else
		child = rbnode_dentry(node);
	#endif
		int result = compare_utf16le_names(name, name_nbytes,
						   child->file_name,
						   child->file_name_nbytes);
		if (result < 0)
			node = node->rb_left;
		else if (result > 0)
			node = node->rb_right;
		else {
		#ifdef __WIN32__
			if (!list_empty(&child->case_insensitive_conflict_list))
			{
				WARNING("Result of case-insensitive lookup is ambiguous "
					"(returning \"%ls\" instead of \"%ls\")",
					child->file_name,
					container_of(child->case_insensitive_conflict_list.next,
						     struct wim_dentry,
						     case_insensitive_conflict_list)->file_name);
			}
		#endif
			return child;
		}
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
get_dentry_utf16le(WIMStruct *wim, const utf16lechar *path)
{
	struct wim_dentry *cur_dentry, *parent_dentry;
	const utf16lechar *p, *pp;

	cur_dentry = parent_dentry = wim_root_dentry(wim);
	if (cur_dentry == NULL) {
		errno = ENOENT;
		return NULL;
	}
	p = path;
	while (1) {
		while (*p == cpu_to_le16(WIM_PATH_SEPARATOR))
			p++;
		if (*p == cpu_to_le16('\0'))
			break;
		pp = p;
		while (*pp != cpu_to_le16(WIM_PATH_SEPARATOR) &&
		       *pp != cpu_to_le16('\0'))
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

/*
 * Returns the dentry in the currently selected WIM image named by @path
 * starting from the root of the WIM image, or NULL if there is no such dentry.
 *
 * On Windows, the search is done case-insensitively.
 */
struct wim_dentry *
get_dentry(WIMStruct *wim, const tchar *path)
{
#if TCHAR_IS_UTF16LE
	return get_dentry_utf16le(wim, path);
#else
	utf16lechar *path_utf16le;
	size_t path_utf16le_nbytes;
	int ret;
	struct wim_dentry *dentry;

	ret = tstr_to_utf16le(path, tstrlen(path) * sizeof(tchar),
			      &path_utf16le, &path_utf16le_nbytes);
	if (ret)
		return NULL;
	dentry = get_dentry_utf16le(wim, path_utf16le);
	FREE(path_utf16le);
	return dentry;
#endif
}

struct wim_inode *
wim_pathname_to_inode(WIMStruct *wim, const tchar *path)
{
	struct wim_dentry *dentry;
	dentry = get_dentry(wim, path);
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
	while (i >= 0 && buf[i] == WIM_PATH_SEPARATOR)
		i--;
	while (i >= 0 && buf[i] != WIM_PATH_SEPARATOR)
		i--;
	while (i >= 0 && buf[i] == WIM_PATH_SEPARATOR)
		i--;
	buf[i + 1] = T('\0');
}

/* Returns the dentry that corresponds to the parent directory of @path, or NULL
 * if the dentry is not found. */
struct wim_dentry *
get_parent_dentry(WIMStruct *wim, const tchar *path)
{
	size_t path_len = tstrlen(path);
	tchar buf[path_len + 1];

	tmemcpy(buf, path, path_len + 1);
	to_parent_name(buf, path_len);
	return get_dentry(wim, buf);
}

/* Prints the full path of a dentry. */
int
print_dentry_full_path(struct wim_dentry *dentry, void *_ignore)
{
	int ret = calculate_dentry_full_path(dentry);
	if (ret)
		return ret;
	tprintf(T("%"TS"\n"), dentry->_full_path);
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

	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		tprintf(T("Reparse Tag       = 0x%"PRIx32"\n"), inode->i_reparse_tag);
		tprintf(T("Reparse Point Flags = 0x%"PRIx16"\n"),
			inode->i_not_rpfixed);
		tprintf(T("Reparse Point Unknown 2 = 0x%"PRIx32"\n"),
			inode->i_rp_unknown_2);
	}
	tprintf(T("Reparse Point Unknown 1 = 0x%"PRIx32"\n"),
		inode->i_rp_unknown_1);
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
new_timeless_inode(void)
{
	struct wim_inode *inode = CALLOC(1, sizeof(struct wim_inode));
	if (inode) {
		inode->i_security_id = -1;
		inode->i_nlink = 1;
		inode->i_next_stream_id = 1;
		inode->i_not_rpfixed = 1;
		inode->i_canonical_streams = 1;
		INIT_LIST_HEAD(&inode->i_list);
		INIT_LIST_HEAD(&inode->i_dentry);
	}
	return inode;
}

static struct wim_inode *
new_inode(void)
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
	if (dentry == NULL)
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
_new_dentry_with_inode(const tchar *name, struct wim_dentry **dentry_ret,
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
	if (dentry->d_inode == NULL) {
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
	return _new_dentry_with_inode(name, dentry_ret, true);
}

int
new_dentry_with_inode(const tchar *name, struct wim_dentry **dentry_ret)
{
	return _new_dentry_with_inode(name, dentry_ret, false);
}

int
new_filler_directory(const tchar *name, struct wim_dentry **dentry_ret)
{
	int ret;
	struct wim_dentry *dentry;

	DEBUG("Creating filler directory \"%"TS"\"", name);
	ret = new_dentry_with_inode(name, &dentry);
	if (ret)
		return ret;
	/* Leave the inode number as 0; this is allowed for non
	 * hard-linked files. */
	dentry->d_inode->i_resolved = 1;
	dentry->d_inode->i_attributes = FILE_ATTRIBUTE_DIRECTORY;
	*dentry_ret = dentry;
	return 0;
}

static int
dentry_clear_inode_visited(struct wim_dentry *dentry, void *_ignore)
{
	dentry->d_inode->i_visited = 0;
	return 0;
}

void
dentry_tree_clear_inode_visited(struct wim_dentry *root)
{
	for_dentry_in_tree(root, dentry_clear_inode_visited, NULL);
}

static int
init_ads_entry(struct wim_ads_entry *ads_entry, const void *name,
	       size_t name_nbytes, bool is_utf16le)
{
	int ret = 0;
	memset(ads_entry, 0, sizeof(*ads_entry));

	if (is_utf16le) {
		utf16lechar *p = MALLOC(name_nbytes + sizeof(utf16lechar));
		if (p == NULL)
			return WIMLIB_ERR_NOMEM;
		memcpy(p, name, name_nbytes);
		p[name_nbytes / 2] = cpu_to_le16(0);
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
		/* HACK: This may instead delete the inode from i_list, but the
		 * hlist_del() behaves the same as list_del(). */
		if (!hlist_unhashed(&inode->i_hlist))
			hlist_del(&inode->i_hlist);
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
	if (dentry) {
		FREE(dentry->file_name);
		FREE(dentry->short_name);
		FREE(dentry->_full_path);
		if (dentry->d_inode)
			put_inode(dentry->d_inode);
		FREE(dentry);
	}
}

/* This function is passed as an argument to for_dentry_in_tree_depth() in order
 * to free a directory tree. */
static int
do_free_dentry(struct wim_dentry *dentry, void *_lookup_table)
{
	struct wim_lookup_table *lookup_table = _lookup_table;

	if (lookup_table) {
		struct wim_inode *inode = dentry->d_inode;
		for (unsigned i = 0; i <= inode->i_num_ads; i++) {
			struct wim_lookup_table_entry *lte;

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
 * @root:
 *	The root of the tree.
 *
 * @lookup_table:
 *	The lookup table for dentries.  If non-NULL, the reference counts in the
 *	lookup table for the lookup table entries corresponding to the dentries
 *	will be decremented.
 */
void
free_dentry_tree(struct wim_dentry *root, struct wim_lookup_table *lookup_table)
{
	for_dentry_in_tree_depth(root, do_free_dentry, lookup_table);
}

#ifdef __WIN32__

/* Insert a dentry into the case insensitive index for a directory.
 *
 * This is a red-black tree, but when multiple dentries share the same
 * case-insensitive name, only one is inserted into the tree itself; the rest
 * are connected in a list.
 */
static struct wim_dentry *
dentry_add_child_case_insensitive(struct wim_dentry *parent,
				  struct wim_dentry *child)
{
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *rb_parent;

	root = &parent->d_inode->i_children_case_insensitive;
	new = &root->rb_node;
	rb_parent = NULL;
	while (*new) {
		struct wim_dentry *this = container_of(*new, struct wim_dentry,
						       rb_node_case_insensitive);
		int result = dentry_compare_names_case_insensitive(child, this);

		rb_parent = *new;

		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return this;
	}
	rb_link_node(&child->rb_node_case_insensitive, rb_parent, new);
	rb_insert_color(&child->rb_node_case_insensitive, root);
	return NULL;
}
#endif

/*
 * Links a dentry into the directory tree.
 *
 * @parent: The dentry that will be the parent of @child.
 * @child: The dentry to link.
 *
 * Returns NULL if successful.  If @parent already contains a dentry with the
 * same case-sensitive name as @child, the pointer to this duplicate dentry is
 * returned.
 */
struct wim_dentry *
dentry_add_child(struct wim_dentry * restrict parent,
		 struct wim_dentry * restrict child)
{
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *rb_parent;

	wimlib_assert(dentry_is_directory(parent));
	wimlib_assert(parent != child);

	/* Case sensitive child dentry index */
	root = &parent->d_inode->i_children;
	new = &root->rb_node;
	rb_parent = NULL;
	while (*new) {
		struct wim_dentry *this = rbnode_dentry(*new);
		int result = dentry_compare_names_case_sensitive(child, this);

		rb_parent = *new;

		if (result < 0)
			new = &((*new)->rb_left);
		else if (result > 0)
			new = &((*new)->rb_right);
		else
			return this;
	}
	child->parent = parent;
	rb_link_node(&child->rb_node, rb_parent, new);
	rb_insert_color(&child->rb_node, root);

#ifdef __WIN32__
	{
		struct wim_dentry *existing;
		existing = dentry_add_child_case_insensitive(parent, child);
		if (existing) {
			list_add(&child->case_insensitive_conflict_list,
				 &existing->case_insensitive_conflict_list);
			child->rb_node_case_insensitive.__rb_parent_color = 0;
		} else {
			INIT_LIST_HEAD(&child->case_insensitive_conflict_list);
		}
	}
#endif
	return NULL;
}

/* Unlink a WIM dentry from the directory entry tree. */
void
unlink_dentry(struct wim_dentry *dentry)
{
	struct wim_dentry *parent = dentry->parent;

	if (parent == dentry)
		return;
	rb_erase(&dentry->rb_node, &parent->d_inode->i_children);
#ifdef __WIN32__
	if (dentry->rb_node_case_insensitive.__rb_parent_color) {
		/* This dentry was in the case-insensitive red-black tree. */
		rb_erase(&dentry->rb_node_case_insensitive,
			 &parent->d_inode->i_children_case_insensitive);
		if (!list_empty(&dentry->case_insensitive_conflict_list)) {
			/* Make a different case-insensitively-the-same dentry
			 * be the "representative" in the red-black tree. */
			struct list_head *next;
			struct wim_dentry *other;
			struct wim_dentry *existing;

			next = dentry->case_insensitive_conflict_list.next;
			other = list_entry(next, struct wim_dentry, case_insensitive_conflict_list);
			existing = dentry_add_child_case_insensitive(parent, other);
			wimlib_assert(existing == NULL);
		}
	}
	list_del(&dentry->case_insensitive_conflict_list);
#endif
}

/*
 * Returns the alternate data stream entry belonging to @inode that has the
 * stream name @stream_name, or NULL if the inode has no alternate data stream
 * with that name.
 *
 * If @p stream_name is the empty string, NULL is returned --- that is, this
 * function will not return "unnamed" alternate data stream entries.
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

		if (stream_name[0] == T('\0'))
			return NULL;

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

	wimlib_assert(stream_name_nbytes != 0);

	if (inode->i_num_ads >= 0xfffe) {
		ERROR("Too many alternate data streams in one inode!");
		return NULL;
	}
	num_ads = inode->i_num_ads + 1;
	ads_entries = REALLOC(inode->i_ads_entries,
			      num_ads * sizeof(inode->i_ads_entries[0]));
	if (ads_entries == NULL) {
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
 * Add an alternate stream entry to a WIM inode.  On success, returns a pointer
 * to the new entry; on failure, returns NULL.
 *
 * @stream_name must be a nonempty string.
 */
struct wim_ads_entry *
inode_add_ads(struct wim_inode *inode, const tchar *stream_name)
{
	DEBUG("Add alternate data stream \"%"TS"\"", stream_name);
	return do_inode_add_ads(inode, stream_name,
				tstrlen(stream_name) * sizeof(tchar),
				TCHAR_IS_UTF16LE);
}

static struct wim_lookup_table_entry *
add_stream_from_data_buffer(const void *buffer, size_t size,
			    struct wim_lookup_table *lookup_table)
{
	u8 hash[SHA1_HASH_SIZE];
	struct wim_lookup_table_entry *lte, *existing_lte;

	sha1_buffer(buffer, size, hash);
	existing_lte = lookup_resource(lookup_table, hash);
	if (existing_lte) {
		wimlib_assert(existing_lte->size == size);
		lte = existing_lte;
		lte->refcnt++;
	} else {
		void *buffer_copy;
		lte = new_lookup_table_entry();
		if (lte == NULL)
			return NULL;
		buffer_copy = memdup(buffer, size);
		if (buffer_copy == NULL) {
			free_lookup_table_entry(lte);
			return NULL;
		}
		lte->resource_location  = RESOURCE_IN_ATTACHED_BUFFER;
		lte->attached_buffer    = buffer_copy;
		lte->size               = size;
		copy_hash(lte->hash, hash);
		lookup_table_insert(lookup_table, lte);
	}
	return lte;
}

int
inode_add_ads_with_data(struct wim_inode *inode, const tchar *name,
			const void *value, size_t size,
			struct wim_lookup_table *lookup_table)
{
	struct wim_ads_entry *new_ads_entry;

	wimlib_assert(inode->i_resolved);

	new_ads_entry = inode_add_ads(inode, name);
	if (new_ads_entry == NULL)
		return WIMLIB_ERR_NOMEM;

	new_ads_entry->lte = add_stream_from_data_buffer(value, size,
							 lookup_table);
	if (new_ads_entry->lte == NULL) {
		inode_remove_ads(inode, new_ads_entry - inode->i_ads_entries,
				 lookup_table);
		return WIMLIB_ERR_NOMEM;
	}
	return 0;
}

bool
inode_has_named_stream(const struct wim_inode *inode)
{
	for (u16 i = 0; i < inode->i_num_ads; i++)
		if (ads_entry_is_named_stream(&inode->i_ads_entries[i]))
			return true;
	return false;
}

/* Set the unnamed stream of a WIM inode, given a data buffer containing the
 * stream contents. */
int
inode_set_unnamed_stream(struct wim_inode *inode, const void *data, size_t len,
			 struct wim_lookup_table *lookup_table)
{
	inode->i_lte = add_stream_from_data_buffer(data, len, lookup_table);
	if (inode->i_lte == NULL)
		return WIMLIB_ERR_NOMEM;
	inode->i_resolved = 1;
	return 0;
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

bool
inode_has_unix_data(const struct wim_inode *inode)
{
	for (u16 i = 0; i < inode->i_num_ads; i++)
		if (ads_entry_is_unix_data(&inode->i_ads_entries[i]))
			return true;
	return false;
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
	if (ads_entry == NULL)
		return NO_UNIX_DATA;

	if (stream_idx_ret)
		*stream_idx_ret = ads_entry - inode->i_ads_entries;

	lte = ads_entry->lte;
	if (lte == NULL)
		return NO_UNIX_DATA;

	size = lte->size;
	if (size != sizeof(struct wimlib_unix_data))
		return BAD_UNIX_DATA;

	ret = read_full_resource_into_buf(lte, unix_data);
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
 * @p:
 *	Pointer to buffer that starts with the first alternate stream entry.
 *
 * @inode:
 *	Inode to load the alternate data streams into.  @inode->i_num_ads must
 *	have been set to the number of alternate data streams that are expected.
 *
 * @remaining_size:
 *	Number of bytes of data remaining in the buffer pointed to by @p.
 *
 * On success, inode->i_ads_entries is set to an array of `struct
 * wim_ads_entry's of length inode->i_num_ads.  On failure, @inode is not
 * modified.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 */
static int
read_ads_entries(const u8 * restrict p, struct wim_inode * restrict inode,
		 size_t nbytes_remaining)
{
	u16 num_ads;
	struct wim_ads_entry *ads_entries;
	int ret;

	BUILD_BUG_ON(sizeof(struct wim_ads_entry_on_disk) != WIM_ADS_ENTRY_DISK_SIZE);

	/* Allocate an array for our in-memory representation of the alternate
	 * data stream entries. */
	num_ads = inode->i_num_ads;
	ads_entries = CALLOC(num_ads, sizeof(inode->i_ads_entries[0]));
	if (ads_entries == NULL)
		goto out_of_memory;

	/* Read the entries into our newly allocated buffer. */
	for (u16 i = 0; i < num_ads; i++) {
		u64 length;
		struct wim_ads_entry *cur_entry;
		const struct wim_ads_entry_on_disk *disk_entry =
			(const struct wim_ads_entry_on_disk*)p;

		cur_entry = &ads_entries[i];
		ads_entries[i].stream_id = i + 1;

		/* Do we have at least the size of the fixed-length data we know
		 * need? */
		if (nbytes_remaining < sizeof(struct wim_ads_entry_on_disk))
			goto out_invalid;

		/* Read the length field */
		length = le64_to_cpu(disk_entry->length);

		/* Make sure the length field is neither so small it doesn't
		 * include all the fixed-length data nor so large it overflows
		 * the metadata resource buffer. */
		if (length < sizeof(struct wim_ads_entry_on_disk) ||
		    length > nbytes_remaining)
			goto out_invalid;

		/* Read the rest of the fixed-length data. */

		cur_entry->reserved = le64_to_cpu(disk_entry->reserved);
		copy_hash(cur_entry->hash, disk_entry->hash);
		cur_entry->stream_name_nbytes = le16_to_cpu(disk_entry->stream_name_nbytes);

		/* If stream_name_nbytes != 0, this is a named stream.
		 * Otherwise this is an unnamed stream, or in some cases (bugs
		 * in Microsoft's software I guess) a meaningless entry
		 * distinguished from the real unnamed stream entry, if any, by
		 * the fact that the real unnamed stream entry has a nonzero
		 * hash field. */
		if (cur_entry->stream_name_nbytes) {
			/* The name is encoded in UTF16-LE, which uses 2-byte
			 * coding units, so the length of the name had better be
			 * an even number of bytes... */
			if (cur_entry->stream_name_nbytes & 1)
				goto out_invalid;

			/* Add the length of the stream name to get the length
			 * we actually need to read.  Make sure this isn't more
			 * than the specified length of the entry. */
			if (sizeof(struct wim_ads_entry_on_disk) +
			    cur_entry->stream_name_nbytes > length)
				goto out_invalid;

			cur_entry->stream_name = MALLOC(cur_entry->stream_name_nbytes + 2);
			if (cur_entry->stream_name == NULL)
				goto out_of_memory;

			memcpy(cur_entry->stream_name,
			       disk_entry->stream_name,
			       cur_entry->stream_name_nbytes);
			cur_entry->stream_name[cur_entry->stream_name_nbytes / 2] = cpu_to_le16(0);
		} else {
			/* Mark inode as having weird stream entries.  */
			inode->i_canonical_streams = 0;
		}

		/* It's expected that the size of every ADS entry is a multiple
		 * of 8.  However, to be safe, I'm allowing the possibility of
		 * an ADS entry at the very end of the metadata resource ending
		 * un-aligned.  So although we still need to increment the input
		 * pointer by @length to reach the next ADS entry, it's possible
		 * that less than @length is actually remaining in the metadata
		 * resource. We should set the remaining bytes to 0 if this
		 * happens. */
		length = (length + 7) & ~(u64)7;
		p += length;
		if (nbytes_remaining < length)
			nbytes_remaining = 0;
		else
			nbytes_remaining -= length;
	}
	inode->i_ads_entries = ads_entries;
	inode->i_next_stream_id = inode->i_num_ads + 1;
	ret = 0;
	goto out;
out_of_memory:
	ret = WIMLIB_ERR_NOMEM;
	goto out_free_ads_entries;
out_invalid:
	ERROR("An alternate data stream entry is invalid");
	ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
out_free_ads_entries:
	if (ads_entries) {
		for (u16 i = 0; i < num_ads; i++)
			destroy_ads_entry(&ads_entries[i]);
		FREE(ads_entries);
	}
out:
	return ret;
}

/*
 * Reads a WIM directory entry, including all alternate data stream entries that
 * follow it, from the WIM image's metadata resource.
 *
 * @metadata_resource:
 *		Pointer to the metadata resource buffer.
 *
 * @metadata_resource_len:
 *		Length of the metadata resource buffer, in bytes.
 *
 * @offset:	Offset of the dentry within the metadata resource.
 *
 * @dentry:	A `struct wim_dentry' that will be filled in by this function.
 *
 * Return 0 on success or nonzero on failure.  On failure, @dentry will have
 * been modified, but it will not be left with pointers to any allocated
 * buffers.  On success, the dentry->length field must be examined.  If zero,
 * this was a special "end of directory" dentry and not a real dentry.  If
 * nonzero, this was a real dentry.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 */
int
read_dentry(const u8 * restrict metadata_resource, u64 metadata_resource_len,
	    u64 offset, struct wim_dentry * restrict dentry)
{

	u64 calculated_size;
	utf16lechar *file_name;
	utf16lechar *short_name;
	u16 short_name_nbytes;
	u16 file_name_nbytes;
	int ret;
	struct wim_inode *inode;
	const u8 *p = &metadata_resource[offset];
	const struct wim_dentry_on_disk *disk_dentry =
			(const struct wim_dentry_on_disk*)p;

	BUILD_BUG_ON(sizeof(struct wim_dentry_on_disk) != WIM_DENTRY_DISK_SIZE);

	if ((uintptr_t)p & 7)
		WARNING("WIM dentry is not 8-byte aligned");

	dentry_common_init(dentry);

	/* Before reading the whole dentry, we need to read just the length.
	 * This is because a dentry of length 8 (that is, just the length field)
	 * terminates the list of sibling directory entries. */
	if (offset + sizeof(u64) > metadata_resource_len ||
	    offset + sizeof(u64) < offset)
	{
		ERROR("Directory entry starting at %"PRIu64" ends past the "
		      "end of the metadata resource (size %"PRIu64")",
		      offset, metadata_resource_len);
		return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
	}
	dentry->length = le64_to_cpu(disk_dentry->length);

	/* A zero length field (really a length of 8, since that's how big the
	 * directory entry is...) indicates that this is the end of directory
	 * dentry.  We do not read it into memory as an actual dentry, so just
	 * return successfully in this case. */
	if (dentry->length == 8)
		dentry->length = 0;
	if (dentry->length == 0)
		return 0;

	/* Now that we have the actual length provided in the on-disk structure,
	 * again make sure it doesn't overflow the metadata resource buffer. */
	if (offset + dentry->length > metadata_resource_len ||
	    offset + dentry->length < offset)
	{
		ERROR("Directory entry at offset %"PRIu64" and with size "
		      "%"PRIu64" ends past the end of the metadata resource "
		      "(size %"PRIu64")",
		      offset, dentry->length, metadata_resource_len);
		return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
	}

	/* Make sure the dentry length is at least as large as the number of
	 * fixed-length fields */
	if (dentry->length < sizeof(struct wim_dentry_on_disk)) {
		ERROR("Directory entry has invalid length of %"PRIu64" bytes",
		      dentry->length);
		return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
	}

	/* Allocate a `struct wim_inode' for this `struct wim_dentry'. */
	inode = new_timeless_inode();
	if (inode == NULL)
		return WIMLIB_ERR_NOMEM;

	/* Read more fields; some into the dentry, and some into the inode. */

	inode->i_attributes = le32_to_cpu(disk_dentry->attributes);
	inode->i_security_id = le32_to_cpu(disk_dentry->security_id);
	dentry->subdir_offset = le64_to_cpu(disk_dentry->subdir_offset);
	dentry->d_unused_1 = le64_to_cpu(disk_dentry->unused_1);
	dentry->d_unused_2 = le64_to_cpu(disk_dentry->unused_2);
	inode->i_creation_time = le64_to_cpu(disk_dentry->creation_time);
	inode->i_last_access_time = le64_to_cpu(disk_dentry->last_access_time);
	inode->i_last_write_time = le64_to_cpu(disk_dentry->last_write_time);
	copy_hash(inode->i_hash, disk_dentry->unnamed_stream_hash);

	/* I don't know what's going on here.  It seems like M$ screwed up the
	 * reparse points, then put the fields in the same place and didn't
	 * document it.  So we have some fields we read for reparse points, and
	 * some fields in the same place for non-reparse-point.s */
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		inode->i_rp_unknown_1 = le32_to_cpu(disk_dentry->reparse.rp_unknown_1);
		inode->i_reparse_tag = le32_to_cpu(disk_dentry->reparse.reparse_tag);
		inode->i_rp_unknown_2 = le16_to_cpu(disk_dentry->reparse.rp_unknown_2);
		inode->i_not_rpfixed = le16_to_cpu(disk_dentry->reparse.not_rpfixed);
		/* Leave inode->i_ino at 0.  Note that this means the WIM file
		 * cannot archive hard-linked reparse points.  Such a thing
		 * doesn't really make sense anyway, although I believe it's
		 * theoretically possible to have them on NTFS. */
	} else {
		inode->i_rp_unknown_1 = le32_to_cpu(disk_dentry->nonreparse.rp_unknown_1);
		inode->i_ino = le64_to_cpu(disk_dentry->nonreparse.hard_link_group_id);
	}

	inode->i_num_ads = le16_to_cpu(disk_dentry->num_alternate_data_streams);

	short_name_nbytes = le16_to_cpu(disk_dentry->short_name_nbytes);
	file_name_nbytes = le16_to_cpu(disk_dentry->file_name_nbytes);

	if ((short_name_nbytes & 1) | (file_name_nbytes & 1))
	{
		ERROR("Dentry name is not valid UTF-16LE (odd number of bytes)!");
		ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
		goto out_free_inode;
	}

	/* We now know the length of the file name and short name.  Make sure
	 * the length of the dentry is large enough to actually hold them.
	 *
	 * The calculated length here is unaligned to allow for the possibility
	 * that the dentry->length names an unaligned length, although this
	 * would be unexpected. */
	calculated_size = dentry_correct_length_unaligned(file_name_nbytes,
							  short_name_nbytes);

	if (dentry->length < calculated_size) {
		ERROR("Unexpected end of directory entry! (Expected "
		      "at least %"PRIu64" bytes, got %"PRIu64" bytes.)",
		      calculated_size, dentry->length);
		ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
		goto out_free_inode;
	}

	p += sizeof(struct wim_dentry_on_disk);

	/* Read the filename if present.  Note: if the filename is empty, there
	 * is no null terminator following it. */
	if (file_name_nbytes) {
		file_name = MALLOC(file_name_nbytes + 2);
		if (file_name == NULL) {
			ERROR("Failed to allocate %d bytes for dentry file name",
			      file_name_nbytes + 2);
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_inode;
		}
		memcpy(file_name, p, file_name_nbytes);
		p += file_name_nbytes + 2;
		file_name[file_name_nbytes / 2] = cpu_to_le16(0);
	} else {
		file_name = NULL;
	}


	/* Read the short filename if present.  Note: if there is no short
	 * filename, there is no null terminator following it. */
	if (short_name_nbytes) {
		short_name = MALLOC(short_name_nbytes + 2);
		if (short_name == NULL) {
			ERROR("Failed to allocate %d bytes for dentry short name",
			      short_name_nbytes + 2);
			ret = WIMLIB_ERR_NOMEM;
			goto out_free_file_name;
		}
		memcpy(short_name, p, short_name_nbytes);
		p += short_name_nbytes + 2;
		short_name[short_name_nbytes / 2] = cpu_to_le16(0);
	} else {
		short_name = NULL;
	}

	/* Align the dentry length */
	dentry->length = (dentry->length + 7) & ~7;

	/*
	 * Read the alternate data streams, if present.  dentry->num_ads tells
	 * us how many they are, and they will directly follow the dentry
	 * on-disk.
	 *
	 * Note that each alternate data stream entry begins on an 8-byte
	 * aligned boundary, and the alternate data stream entries seem to NOT
	 * be included in the dentry->length field for some reason.
	 */
	if (inode->i_num_ads != 0) {
		ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
		if (offset + dentry->length > metadata_resource_len ||
		    (ret = read_ads_entries(&metadata_resource[offset + dentry->length],
					    inode,
					    metadata_resource_len - offset - dentry->length)))
		{
			ERROR("Failed to read alternate data stream "
			      "entries of WIM dentry \"%"WS"\"", file_name);
			goto out_free_short_name;
		}
	}
	/* We've read all the data for this dentry.  Set the names and their
	 * lengths, and we've done. */
	dentry->d_inode           = inode;
	dentry->file_name         = file_name;
	dentry->short_name        = short_name;
	dentry->file_name_nbytes  = file_name_nbytes;
	dentry->short_name_nbytes = short_name_nbytes;
	ret = 0;
	goto out;
out_free_short_name:
	FREE(short_name);
out_free_file_name:
	FREE(file_name);
out_free_inode:
	free_inode(inode);
out:
	return ret;
}

static const tchar *
dentry_get_file_type_string(const struct wim_dentry *dentry)
{
	const struct wim_inode *inode = dentry->d_inode;
	if (inode_is_directory(inode))
		return T("directory");
	else if (inode_is_symlink(inode))
		return T("symbolic link");
	else
		return T("file");
}

/* Reads the children of a dentry, and all their children, ..., etc. from the
 * metadata resource and into the dentry tree.
 *
 * @metadata_resource:
 *	An array that contains the uncompressed metadata resource for the WIM
 *	file.
 *
 * @metadata_resource_len:
 *	The length of the uncompressed metadata resource, in bytes.
 *
 * @dentry:
 *	A pointer to a `struct wim_dentry' that is the root of the directory
 *	tree and has already been read from the metadata resource.  It does not
 *	need to be the real root because this procedure is called recursively.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 */
int
read_dentry_tree(const u8 * restrict metadata_resource,
		 u64 metadata_resource_len,
		 struct wim_dentry * restrict dentry)
{
	u64 cur_offset = dentry->subdir_offset;
	struct wim_dentry *child;
	struct wim_dentry *duplicate;
	struct wim_dentry *parent;
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

	/* Check for cyclic directory structure */
	for (parent = dentry->parent; !dentry_is_root(parent); parent = parent->parent)
	{
		if (unlikely(parent->subdir_offset == cur_offset)) {
			ERROR("Cyclic directory structure directed: children "
			      "of \"%"TS"\" coincide with children of \"%"TS"\"",
			      dentry_full_path(dentry),
			      dentry_full_path(parent));
			return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
		}
	}

	/* Find and read all the children of @dentry. */
	for (;;) {

		/* Read next child of @dentry into @cur_child. */
		ret = read_dentry(metadata_resource, metadata_resource_len,
				  cur_offset, &cur_child);
		if (ret)
			break;

		/* Check for end of directory. */
		if (cur_child.length == 0)
			break;

		/* Not end of directory.  Allocate this child permanently and
		 * link it to the parent and previous child. */
		child = memdup(&cur_child, sizeof(struct wim_dentry));
		if (child == NULL) {
			ERROR("Failed to allocate new dentry!");
			ret = WIMLIB_ERR_NOMEM;
			break;
		}

		/* Advance to the offset of the next child.  Note: We need to
		 * advance by the TOTAL length of the dentry, not by the length
		 * cur_child.length, which although it does take into account
		 * the padding, it DOES NOT take into account alternate stream
		 * entries. */
		cur_offset += dentry_in_total_length(child);

		if (unlikely(!dentry_has_long_name(child))) {
			WARNING("Ignoring unnamed dentry in "
				"directory \"%"TS"\"",
				dentry_full_path(dentry));
			free_dentry(child);
			continue;
		}

		duplicate = dentry_add_child(dentry, child);
		if (unlikely(duplicate)) {
			const tchar *child_type, *duplicate_type;
			child_type = dentry_get_file_type_string(child);
			duplicate_type = dentry_get_file_type_string(duplicate);
			WARNING("Ignoring duplicate %"TS" \"%"TS"\" "
				"(the WIM image already contains a %"TS" "
				"at that path with the exact same name)",
				child_type, dentry_full_path(duplicate),
				duplicate_type);
			free_dentry(child);
			continue;
		}

		inode_add_dentry(child, child->d_inode);
		/* If there are children of this child, call this
		 * procedure recursively. */
		if (child->subdir_offset != 0) {
			if (likely(dentry_is_directory(child))) {
				ret = read_dentry_tree(metadata_resource,
						       metadata_resource_len,
						       child);
				if (ret)
					break;
			} else {
				WARNING("Ignoring children of non-directory \"%"TS"\"",
					dentry_full_path(child));
			}
		}
	}
	return ret;
}

/*
 * Writes a WIM alternate data stream (ADS) entry to an output buffer.
 *
 * @ads_entry:  The ADS entry structure.
 * @hash:       The hash field to use (instead of the one in the ADS entry).
 * @p:          The memory location to write the data to.
 *
 * Returns a pointer to the byte after the last byte written.
 */
static u8 *
write_ads_entry(const struct wim_ads_entry *ads_entry,
		const u8 *hash, u8 * restrict p)
{
	struct wim_ads_entry_on_disk *disk_ads_entry =
			(struct wim_ads_entry_on_disk*)p;
	u8 *orig_p = p;

	disk_ads_entry->reserved = cpu_to_le64(ads_entry->reserved);
	copy_hash(disk_ads_entry->hash, hash);
	disk_ads_entry->stream_name_nbytes = cpu_to_le16(ads_entry->stream_name_nbytes);
	p += sizeof(struct wim_ads_entry_on_disk);
	if (ads_entry->stream_name_nbytes) {
		p = mempcpy(p, ads_entry->stream_name,
			    ads_entry->stream_name_nbytes + 2);
	}
	/* Align to 8-byte boundary */
	while ((uintptr_t)p & 7)
		*p++ = 0;
	disk_ads_entry->length = cpu_to_le64(p - orig_p);
	return p;
}

/*
 * Writes a WIM dentry to an output buffer.
 *
 * @dentry:  The dentry structure.
 * @p:       The memory location to write the data to.
 *
 * Returns the pointer to the byte after the last byte we wrote as part of the
 * dentry, including any alternate data stream entries.
 */
static u8 *
write_dentry(const struct wim_dentry * restrict dentry, u8 * restrict p)
{
	const struct wim_inode *inode;
	struct wim_dentry_on_disk *disk_dentry;
	const u8 *orig_p;
	const u8 *hash;
	bool use_dummy_stream;
	u16 num_ads;

	wimlib_assert(((uintptr_t)p & 7) == 0); /* 8 byte aligned */
	orig_p = p;

	inode = dentry->d_inode;
	use_dummy_stream = inode_needs_dummy_stream(inode);
	disk_dentry = (struct wim_dentry_on_disk*)p;

	disk_dentry->attributes = cpu_to_le32(inode->i_attributes);
	disk_dentry->security_id = cpu_to_le32(inode->i_security_id);
	disk_dentry->subdir_offset = cpu_to_le64(dentry->subdir_offset);
	disk_dentry->unused_1 = cpu_to_le64(dentry->d_unused_1);
	disk_dentry->unused_2 = cpu_to_le64(dentry->d_unused_2);
	disk_dentry->creation_time = cpu_to_le64(inode->i_creation_time);
	disk_dentry->last_access_time = cpu_to_le64(inode->i_last_access_time);
	disk_dentry->last_write_time = cpu_to_le64(inode->i_last_write_time);
	if (use_dummy_stream)
		hash = zero_hash;
	else
		hash = inode_stream_hash(inode, 0);
	copy_hash(disk_dentry->unnamed_stream_hash, hash);
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		disk_dentry->reparse.rp_unknown_1 = cpu_to_le32(inode->i_rp_unknown_1);
		disk_dentry->reparse.reparse_tag = cpu_to_le32(inode->i_reparse_tag);
		disk_dentry->reparse.rp_unknown_2 = cpu_to_le16(inode->i_rp_unknown_2);
		disk_dentry->reparse.not_rpfixed = cpu_to_le16(inode->i_not_rpfixed);
	} else {
		disk_dentry->nonreparse.rp_unknown_1 = cpu_to_le32(inode->i_rp_unknown_1);
		disk_dentry->nonreparse.hard_link_group_id =
			cpu_to_le64((inode->i_nlink == 1) ? 0 : inode->i_ino);
	}
	num_ads = inode->i_num_ads;
	if (use_dummy_stream)
		num_ads++;
	disk_dentry->num_alternate_data_streams = cpu_to_le16(num_ads);
	disk_dentry->short_name_nbytes = cpu_to_le16(dentry->short_name_nbytes);
	disk_dentry->file_name_nbytes = cpu_to_le16(dentry->file_name_nbytes);
	p += sizeof(struct wim_dentry_on_disk);

	wimlib_assert(dentry_is_root(dentry) != dentry_has_long_name(dentry));

	if (dentry_has_long_name(dentry))
		p = mempcpy(p, dentry->file_name, dentry->file_name_nbytes + 2);

	if (dentry_has_short_name(dentry))
		p = mempcpy(p, dentry->short_name, dentry->short_name_nbytes + 2);

	/* Align to 8-byte boundary */
	while ((uintptr_t)p & 7)
		*p++ = 0;

	/* We calculate the correct length of the dentry ourselves because the
	 * dentry->length field may been set to an unexpected value from when we
	 * read the dentry in (for example, there may have been unknown data
	 * appended to the end of the dentry...).  Furthermore, the dentry may
	 * have been renamed, thus changing its needed length. */
	disk_dentry->length = cpu_to_le64(p - orig_p);

	if (use_dummy_stream) {
		hash = inode_unnamed_stream_hash(inode);
		p = write_ads_entry(&(struct wim_ads_entry){}, hash, p);
	}

	/* Write the alternate data streams entries, if any. */
	for (u16 i = 0; i < inode->i_num_ads; i++) {
		hash = inode_stream_hash(inode, i + 1);
		p = write_ads_entry(&inode->i_ads_entries[i], hash, p);
	}

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
	*(le64*)p = cpu_to_le64(0);
	p += 8;

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
write_dentry_tree(const struct wim_dentry * restrict root, u8 * restrict p)
{
	DEBUG("Writing dentry tree.");
	wimlib_assert(dentry_is_root(root));

	/* If we're the root dentry, we have no parent that already
	 * wrote us, so we need to write ourselves. */
	p = write_dentry(root, p);

	/* Write end of directory entry after the root dentry just to be safe;
	 * however the root dentry obviously cannot have any siblings. */
	*(le64*)p = cpu_to_le64(0);
	p += 8;

	/* Recursively write the rest of the dentry tree. */
	return write_dentry_tree_recursive(root, p);
}


static int
init_wimlib_dentry(struct wimlib_dir_entry *wdentry,
		   struct wim_dentry *dentry,
		   const WIMStruct *wim,
		   int flags)
{
	int ret;
	size_t dummy;
	const struct wim_inode *inode = dentry->d_inode;
	struct wim_lookup_table_entry *lte;
	const u8 *hash;

#if TCHAR_IS_UTF16LE
	wdentry->filename = dentry->file_name;
	wdentry->dos_name = dentry->short_name;
#else
	if (dentry_has_long_name(dentry)) {
		ret = utf16le_to_tstr(dentry->file_name,
				      dentry->file_name_nbytes,
				      (tchar**)&wdentry->filename,
				      &dummy);
		if (ret)
			return ret;
	}
	if (dentry_has_short_name(dentry)) {
		ret = utf16le_to_tstr(dentry->short_name,
				      dentry->short_name_nbytes,
				      (tchar**)&wdentry->dos_name,
				      &dummy);
		if (ret)
			return ret;
	}
#endif
	ret = calculate_dentry_full_path(dentry);
	if (ret)
		return ret;
	wdentry->full_path = dentry->_full_path;

	for (struct wim_dentry *d = dentry; !dentry_is_root(d); d = d->parent)
		wdentry->depth++;

	if (inode->i_security_id >= 0) {
		const struct wim_security_data *sd = wim_const_security_data(wim);
		wdentry->security_descriptor = sd->descriptors[inode->i_security_id];
		wdentry->security_descriptor_size = sd->sizes[inode->i_security_id];
	}
	wdentry->reparse_tag = inode->i_reparse_tag;
	wdentry->num_links = inode->i_nlink;
	wdentry->attributes = inode->i_attributes;
	wdentry->hard_link_group_id = inode->i_ino;
	wdentry->creation_time = wim_timestamp_to_timespec(inode->i_creation_time);
	wdentry->last_write_time = wim_timestamp_to_timespec(inode->i_last_write_time);
	wdentry->last_access_time = wim_timestamp_to_timespec(inode->i_last_access_time);

	lte = inode_unnamed_lte(inode, wim->lookup_table);
	if (lte) {
		lte_to_wimlib_resource_entry(lte, &wdentry->streams[0].resource);
	} else if (!is_zero_hash(hash = inode_unnamed_stream_hash(inode))) {
		if (flags & WIMLIB_ITERATE_DIR_TREE_FLAG_RESOURCES_NEEDED)
			return resource_not_found_error(inode, hash);
		copy_hash(wdentry->streams[0].resource.sha1_hash, hash);
		wdentry->streams[0].resource.is_missing = 1;
	}

	for (unsigned i = 0; i < inode->i_num_ads; i++) {
		if (!ads_entry_is_named_stream(&inode->i_ads_entries[i]))
			continue;
		lte = inode_stream_lte(inode, i + 1, wim->lookup_table);
		wdentry->num_named_streams++;
		if (lte) {
			lte_to_wimlib_resource_entry(lte, &wdentry->streams[
								wdentry->num_named_streams].resource);
		} else if (!is_zero_hash(hash = inode_stream_hash(inode, i + 1))) {
			if (flags & WIMLIB_ITERATE_DIR_TREE_FLAG_RESOURCES_NEEDED)
				return resource_not_found_error(inode, hash);
			copy_hash(wdentry->streams[
				  wdentry->num_named_streams].resource.sha1_hash, hash);
			wdentry->streams[
				wdentry->num_named_streams].resource.is_missing = 1;
		}
	#if TCHAR_IS_UTF16LE
		wdentry->streams[wdentry->num_named_streams].stream_name =
				inode->i_ads_entries[i].stream_name;
	#else
		size_t dummy;

		ret = utf16le_to_tstr(inode->i_ads_entries[i].stream_name,
				      inode->i_ads_entries[i].stream_name_nbytes,
				      (tchar**)&wdentry->streams[
						wdentry->num_named_streams].stream_name,
				      &dummy);
		if (ret)
			return ret;
	#endif
	}
	return 0;
}

static void
free_wimlib_dentry(struct wimlib_dir_entry *wdentry)
{
#if !TCHAR_IS_UTF16LE
	FREE((tchar*)wdentry->filename);
	FREE((tchar*)wdentry->dos_name);
	for (unsigned i = 1; i <= wdentry->num_named_streams; i++)
		FREE((tchar*)wdentry->streams[i].stream_name);
#endif
	FREE(wdentry);
}

struct iterate_dir_tree_ctx {
	WIMStruct *wim;
	int flags;
	wimlib_iterate_dir_tree_callback_t cb;
	void *user_ctx;
};

static int
do_iterate_dir_tree(WIMStruct *wim,
		    struct wim_dentry *dentry, int flags,
		    wimlib_iterate_dir_tree_callback_t cb,
		    void *user_ctx);

static int
call_do_iterate_dir_tree(struct wim_dentry *dentry, void *_ctx)
{
	struct iterate_dir_tree_ctx *ctx = _ctx;
	return do_iterate_dir_tree(ctx->wim, dentry, ctx->flags,
				   ctx->cb, ctx->user_ctx);
}

static int
do_iterate_dir_tree(WIMStruct *wim,
		    struct wim_dentry *dentry, int flags,
		    wimlib_iterate_dir_tree_callback_t cb,
		    void *user_ctx)
{
	struct wimlib_dir_entry *wdentry;
	int ret = WIMLIB_ERR_NOMEM;


	wdentry = CALLOC(1, sizeof(struct wimlib_dir_entry) +
				  (1 + dentry->d_inode->i_num_ads) *
					sizeof(struct wimlib_stream_entry));
	if (wdentry == NULL)
		goto out;

	ret = init_wimlib_dentry(wdentry, dentry, wim, flags);
	if (ret)
		goto out_free_wimlib_dentry;

	if (!(flags & WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN)) {
		ret = (*cb)(wdentry, user_ctx);
		if (ret)
			goto out_free_wimlib_dentry;
	}

	if (flags & (WIMLIB_ITERATE_DIR_TREE_FLAG_RECURSIVE |
		     WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN))
	{
		struct iterate_dir_tree_ctx ctx = {
			.wim      = wim,
			.flags    = flags &= ~WIMLIB_ITERATE_DIR_TREE_FLAG_CHILDREN,
			.cb       = cb,
			.user_ctx = user_ctx,
		};
		ret = for_dentry_child(dentry, call_do_iterate_dir_tree, &ctx);
	}
out_free_wimlib_dentry:
	free_wimlib_dentry(wdentry);
out:
	return ret;
}

struct image_iterate_dir_tree_ctx {
	const tchar *path;
	int flags;
	wimlib_iterate_dir_tree_callback_t cb;
	void *user_ctx;
};


static int
image_do_iterate_dir_tree(WIMStruct *wim)
{
	struct image_iterate_dir_tree_ctx *ctx = wim->private;
	struct wim_dentry *dentry;

	dentry = get_dentry(wim, ctx->path);
	if (dentry == NULL)
		return WIMLIB_ERR_PATH_DOES_NOT_EXIST;
	return do_iterate_dir_tree(wim, dentry, ctx->flags, ctx->cb, ctx->user_ctx);
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_iterate_dir_tree(WIMStruct *wim, int image, const tchar *path,
			int flags,
			wimlib_iterate_dir_tree_callback_t cb, void *user_ctx)
{
	struct image_iterate_dir_tree_ctx ctx = {
		.path = path,
		.flags = flags,
		.cb = cb,
		.user_ctx = user_ctx,
	};
	wim->private = &ctx;
	return for_image(wim, image, image_do_iterate_dir_tree);
}

/* Returns %true iff the metadata of @inode and @template_inode are reasonably
 * consistent with them being the same, unmodified file.  */
static bool
inode_metadata_consistent(const struct wim_inode *inode,
			  const struct wim_inode *template_inode,
			  const struct wim_lookup_table *template_lookup_table)
{
	/* Must have exact same creation time and last write time.  */
	if (inode->i_creation_time != template_inode->i_creation_time ||
	    inode->i_last_write_time != template_inode->i_last_write_time)
		return false;

	/* Last access time may have stayed the same or increased, but certainly
	 * shouldn't have decreased.  */
	if (inode->i_last_access_time < template_inode->i_last_access_time)
		return false;

	/* Must have same number of alternate data stream entries.  */
	if (inode->i_num_ads != template_inode->i_num_ads)
		return false;

	/* If the stream entries for the inode are for some reason not resolved,
	 * then the hashes are already available and the point of this function
	 * is defeated.  */
	if (!inode->i_resolved)
		return false;

	/* Iterate through each stream and do some more checks.  */
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		const struct wim_lookup_table_entry *lte, *template_lte;

		lte = inode_stream_lte_resolved(inode, i);
		template_lte = inode_stream_lte(template_inode, i,
						template_lookup_table);

		/* Compare stream sizes.  */
		if (lte && template_lte) {
			if (lte->size != template_lte->size)
				return false;

			/* If hash happens to be available, compare with template.  */
			if (!lte->unhashed && !template_lte->unhashed &&
			    !hashes_equal(lte->hash, template_lte->hash))
				return false;

		} else if (lte && lte->size) {
			return false;
		} else if (template_lte && template_lte->size) {
			return false;
		}
	}

	/* All right, barring a full checksum and given that the inodes share a
	 * path and the user isn't trying to trick us, these inodes most likely
	 * refer to the same file.  */
	return true;
}

/**
 * Given an inode @inode that has been determined to be "the same" as another
 * inode @template_inode in either the same WIM or another WIM, retrieve some
 * useful stream information (e.g. checksums) from @template_inode.
 *
 * This assumes that the streams for @inode have been resolved (to point
 * directly to the appropriate `struct wim_lookup_table_entry's)  but do not
 * necessarily have checksum information filled in.
 */
static int
inode_copy_checksums(struct wim_inode *inode,
		     struct wim_inode *template_inode,
		     WIMStruct *wim,
		     WIMStruct *template_wim)
{
	for (unsigned i = 0; i <= inode->i_num_ads; i++) {
		struct wim_lookup_table_entry *lte, *template_lte;
		struct wim_lookup_table_entry *replace_lte;

		lte = inode_stream_lte_resolved(inode, i);
		template_lte = inode_stream_lte(template_inode, i,
						template_wim->lookup_table);

		/* Only take action if both entries exist, the entry for @inode
		 * has no checksum calculated, but the entry for @template_inode
		 * does.  */
		if (lte == NULL || template_lte == NULL ||
		    !lte->unhashed || template_lte->unhashed)
			continue;

		wimlib_assert(lte->refcnt == inode->i_nlink);

		/* If the WIM of the template image is the same as the WIM of
		 * the new image, then @template_lte can be used directly.
		 *
		 * Otherwise, look for a stream with the same hash in the WIM of
		 * the new image.  If found, use it; otherwise re-use the entry
		 * being discarded, filling in the hash.  */

		if (wim == template_wim)
			replace_lte = template_lte;
		else
			replace_lte = lookup_resource(wim->lookup_table,
						      template_lte->hash);

		list_del(&lte->unhashed_list);
		if (replace_lte) {
			free_lookup_table_entry(lte);
		} else {
			copy_hash(lte->hash, template_lte->hash);
			lte->unhashed = 0;
			lookup_table_insert(wim->lookup_table, lte);
			lte->refcnt = 0;
			replace_lte = lte;
		}

		if (i == 0)
			inode->i_lte = replace_lte;
		else
			inode->i_ads_entries[i - 1].lte = replace_lte;

		replace_lte->refcnt += inode->i_nlink;
	}
	return 0;
}

struct reference_template_args {
	WIMStruct *wim;
	WIMStruct *template_wim;
};

static int
dentry_reference_template(struct wim_dentry *dentry, void *_args)
{
	int ret;
	struct wim_dentry *template_dentry;
	struct wim_inode *inode, *template_inode;
	struct reference_template_args *args = _args;
	WIMStruct *wim = args->wim;
	WIMStruct *template_wim = args->template_wim;

	if (dentry->d_inode->i_visited)
		return 0;

	ret = calculate_dentry_full_path(dentry);
	if (ret)
		return ret;

	template_dentry = get_dentry(template_wim, dentry->_full_path);
	if (template_dentry == NULL) {
		DEBUG("\"%"TS"\": newly added file", dentry->_full_path);
		return 0;
	}

	inode = dentry->d_inode;
	template_inode = template_dentry->d_inode;

	if (inode_metadata_consistent(inode, template_inode,
				      template_wim->lookup_table)) {
		/*DEBUG("\"%"TS"\": No change detected", dentry->_full_path);*/
		ret = inode_copy_checksums(inode, template_inode,
					   wim, template_wim);
		inode->i_visited = 1;
	} else {
		DEBUG("\"%"TS"\": change detected!", dentry->_full_path);
		ret = 0;
	}
	return ret;
}

/* API function documented in wimlib.h  */
WIMLIBAPI int
wimlib_reference_template_image(WIMStruct *wim, int new_image,
				WIMStruct *template_wim, int template_image,
				int flags, wimlib_progress_func_t progress_func)
{
	int ret;
	struct wim_image_metadata *new_imd;

	if (wim == NULL || template_wim == NULL)
		return WIMLIB_ERR_INVALID_PARAM;

	if (wim == template_wim && new_image == template_image)
		return WIMLIB_ERR_INVALID_PARAM;

	if (new_image < 1 || new_image > wim->hdr.image_count)
		return WIMLIB_ERR_INVALID_IMAGE;

	if (!wim_has_metadata(wim))
		return WIMLIB_ERR_METADATA_NOT_FOUND;

	new_imd = wim->image_metadata[new_image - 1];
	if (!new_imd->modified)
		return WIMLIB_ERR_INVALID_PARAM;

	ret = select_wim_image(template_wim, template_image);
	if (ret)
		return ret;

	struct reference_template_args args = {
		.wim = wim,
		.template_wim = template_wim,
	};

	ret = for_dentry_in_tree(new_imd->root_dentry,
				 dentry_reference_template, &args);
	dentry_tree_clear_inode_visited(new_imd->root_dentry);
	return ret;
}
