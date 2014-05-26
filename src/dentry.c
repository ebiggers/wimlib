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
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
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
#include "wimlib/case.h"
#include "wimlib/dentry.h"
#include "wimlib/encoding.h"
#include "wimlib/endianness.h"
#include "wimlib/error.h"
#include "wimlib/lookup_table.h"
#include "wimlib/metadata.h"
#include "wimlib/paths.h"
#include "wimlib/resource.h"
#include "wimlib/security.h"
#include "wimlib/sha1.h"
#include "wimlib/timestamp.h"

#include <errno.h>

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
	 * one.  In fact, when named data streams are present, some versions of
	 * Windows PE contain a bug where they only look in the alternate data
	 * stream entries for the unnamed data stream, not here.
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

	/* And optionally followed by a variable-length series of tagged items;
	 * see tagged_items.c.  */
} _packed_attribute;

/* Calculates the unaligned length, in bytes, of an on-disk WIM dentry that has
 * a file name and short name that take the specified numbers of bytes.  This
 * excludes tagged items as well as any alternate data stream entries that may
 * follow the dentry.  */
static u64
dentry_min_len_with_names(u16 file_name_nbytes, u16 short_name_nbytes)
{
	u64 length = sizeof(struct wim_dentry_on_disk);
	if (file_name_nbytes)
		length += file_name_nbytes + 2;
	if (short_name_nbytes)
		length += short_name_nbytes + 2;
	return length;
}

static void
do_dentry_set_name(struct wim_dentry *dentry, utf16lechar *file_name,
		   size_t file_name_nbytes)
{
	FREE(dentry->file_name);
	dentry->file_name = file_name;
	dentry->file_name_nbytes = file_name_nbytes;

	if (dentry_has_short_name(dentry)) {
		FREE(dentry->short_name);
		dentry->short_name = NULL;
		dentry->short_name_nbytes = 0;
	}
}

/* Sets the name of a WIM dentry from a UTF-16LE string.
 * Only use this on dentries not inserted into the tree.  Use rename_wim_path()
 * to do a real rename.  */
int
dentry_set_name_utf16le(struct wim_dentry *dentry, const utf16lechar *name,
			size_t name_nbytes)
{
	utf16lechar *dup = NULL;

	if (name_nbytes) {
		dup = utf16le_dupz(name, name_nbytes);
		if (!dup)
			return WIMLIB_ERR_NOMEM;
	}
	do_dentry_set_name(dentry, dup, name_nbytes);
	return 0;
}


/* Sets the name of a WIM dentry from a multibyte string.
 * Only use this on dentries not inserted into the tree.  Use rename_wim_path()
 * to do a real rename.  */
int
dentry_set_name(struct wim_dentry *dentry, const tchar *name)
{
	utf16lechar *name_utf16le = NULL;
	size_t name_utf16le_nbytes = 0;
	int ret;

	if (name && *name) {
		ret = tstr_to_utf16le(name, tstrlen(name) * sizeof(tchar),
				      &name_utf16le, &name_utf16le_nbytes);
		if (ret)
			return ret;
	}

	do_dentry_set_name(dentry, name_utf16le, name_utf16le_nbytes);
	return 0;
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
static inline bool
inode_needs_dummy_stream(const struct wim_inode *inode)
{
	return (inode->i_num_ads > 0 &&
		inode->i_num_ads < 0xffff && /* overflow check */
		inode->i_canonical_streams); /* assume the dentry is okay if it
						already had an unnamed ADS entry
						when it was read in  */
}

/* Calculate the total number of bytes that will be consumed when a WIM dentry
 * is written.  This includes the base dentry the name fields, any tagged items,
 * any alternate data stream entries.  Also includes all alignment bytes between
 * these parts.  */
u64
dentry_out_total_length(const struct wim_dentry *dentry)
{
	const struct wim_inode *inode = dentry->d_inode;
	u64 len;

	len = dentry_min_len_with_names(dentry->file_name_nbytes,
					dentry->short_name_nbytes);
	len = (len + 7) & ~7;

	if (inode->i_extra_size) {
		len += inode->i_extra_size;
		len = (len + 7) & ~7;
	}

	if (unlikely(inode->i_num_ads)) {
		if (inode_needs_dummy_stream(inode))
			len += ads_entry_total_length(&(struct wim_ads_entry){});

		for (u16 i = 0; i < inode->i_num_ads; i++)
			len += ads_entry_total_length(&inode->i_ads_entries[i]);
	}

	return len;
}

static int
do_for_dentry_in_tree(struct wim_dentry *dentry,
		      int (*visitor)(struct wim_dentry *, void *), void *arg)
{
	int ret;
	struct wim_dentry *child;

	ret = (*visitor)(dentry, arg);
	if (unlikely(ret))
		return ret;

	for_dentry_child(child, dentry) {
		ret = do_for_dentry_in_tree(child, visitor, arg);
		if (unlikely(ret))
			return ret;
	}
	return 0;
}


static int
do_for_dentry_in_tree_depth(struct wim_dentry *dentry,
			    int (*visitor)(struct wim_dentry *, void *), void *arg)
{
	int ret;
	struct wim_dentry *child;

	for_dentry_child_postorder(child, dentry) {
		ret = do_for_dentry_in_tree_depth(child, visitor, arg);
		if (unlikely(ret))
			return ret;
	}
	return unlikely((*visitor)(dentry, arg));
}

/* Calls a function on all directory entries in a WIM dentry tree.  Logically,
 * this is a pre-order traversal (the function is called on a parent dentry
 * before its children), but sibling dentries will be visited in order as well.
 * */
int
for_dentry_in_tree(struct wim_dentry *root,
		   int (*visitor)(struct wim_dentry *, void *), void *arg)
{
	if (unlikely(!root))
		return 0;
	return do_for_dentry_in_tree(root, visitor, arg);
}

/* Like for_dentry_in_tree(), but the visitor function is always called on a
 * dentry's children before on itself. */
int
for_dentry_in_tree_depth(struct wim_dentry *root,
			 int (*visitor)(struct wim_dentry *, void *), void *arg)
{
	if (unlikely(!root))
		return 0;
	return do_for_dentry_in_tree_depth(root, visitor, arg);
}

/* Calculate the full path of @dentry.  */
int
calculate_dentry_full_path(struct wim_dentry *dentry)
{
	size_t ulen;
	size_t dummy;
	const struct wim_dentry *d;

	if (dentry->_full_path)
		return 0;

	ulen = 0;
	d = dentry;
	do {
		ulen += d->file_name_nbytes / sizeof(utf16lechar);
		ulen++;
		d = d->d_parent;  /* assumes d == d->d_parent for root  */
	} while (!dentry_is_root(d));

	utf16lechar ubuf[ulen];
	utf16lechar *p = &ubuf[ulen];

	d = dentry;
	do {
		p -= d->file_name_nbytes / sizeof(utf16lechar);
		memcpy(p, d->file_name, d->file_name_nbytes);
		*--p = cpu_to_le16(WIM_PATH_SEPARATOR);
		d = d->d_parent;  /* assumes d == d->d_parent for root  */
	} while (!dentry_is_root(d));

	wimlib_assert(p == ubuf);

	return utf16le_to_tstr(ubuf, ulen * sizeof(utf16lechar),
			       &dentry->_full_path, &dummy);
}

tchar *
dentry_full_path(struct wim_dentry *dentry)
{
	calculate_dentry_full_path(dentry);
	return dentry->_full_path;
}

static int
dentry_calculate_subdir_offset(struct wim_dentry *dentry, void *_subdir_offset_p)
{

	if (dentry_is_directory(dentry)) {
		u64 *subdir_offset_p = _subdir_offset_p;
		struct wim_dentry *child;

		/* Set offset of directory's child dentries  */
		dentry->subdir_offset = *subdir_offset_p;

		/* Account for child dentries  */
		for_dentry_child(child, dentry)
			*subdir_offset_p += dentry_out_total_length(child);

		/* Account for end-of-directory entry  */
		*subdir_offset_p += 8;
	} else {
		/* Not a directory; set subdir_offset to 0  */
		dentry->subdir_offset = 0;
	}
	return 0;
}

/*
 * Calculates the subdir offsets for a directory tree.
 */
void
calculate_subdir_offsets(struct wim_dentry *root, u64 *subdir_offset_p)
{
	for_dentry_in_tree(root, dentry_calculate_subdir_offset, subdir_offset_p);
}

/* Compare the UTF-16LE long filenames of two dentries case insensitively.  */
static int
dentry_compare_names_case_insensitive(const struct wim_dentry *d1,
				      const struct wim_dentry *d2)
{
	return cmp_utf16le_strings(d1->file_name,
				   d1->file_name_nbytes / 2,
				   d2->file_name,
				   d2->file_name_nbytes / 2,
				   true);
}

/* Compare the UTF-16LE long filenames of two dentries case sensitively.  */
static int
dentry_compare_names_case_sensitive(const struct wim_dentry *d1,
				    const struct wim_dentry *d2)
{
	return cmp_utf16le_strings(d1->file_name,
				   d1->file_name_nbytes / 2,
				   d2->file_name,
				   d2->file_name_nbytes / 2,
				   false);
}

static int
_avl_dentry_compare_names_ci(const struct avl_tree_node *n1,
			     const struct avl_tree_node *n2)
{
	const struct wim_dentry *d1, *d2;

	d1 = avl_tree_entry(n1, struct wim_dentry, d_index_node_ci);
	d2 = avl_tree_entry(n2, struct wim_dentry, d_index_node_ci);
	return dentry_compare_names_case_insensitive(d1, d2);
}

static int
_avl_dentry_compare_names(const struct avl_tree_node *n1,
			  const struct avl_tree_node *n2)
{
	const struct wim_dentry *d1, *d2;

	d1 = avl_tree_entry(n1, struct wim_dentry, d_index_node);
	d2 = avl_tree_entry(n2, struct wim_dentry, d_index_node);
	return dentry_compare_names_case_sensitive(d1, d2);
}

/* Default case sensitivity behavior for searches with
 * WIMLIB_CASE_PLATFORM_DEFAULT specified.  This can be modified by
 * wimlib_global_init().  */
bool default_ignore_case =
#ifdef __WIN32__
	true
#else
	false
#endif
;

/* Case-sensitive dentry lookup.  Only @file_name and @file_name_nbytes of
 * @dummy must be valid.  */
static struct wim_dentry *
dir_lookup(const struct wim_inode *dir, const struct wim_dentry *dummy)
{
	struct avl_tree_node *node;

	node = avl_tree_lookup_node(dir->i_children,
				    &dummy->d_index_node,
				    _avl_dentry_compare_names);
	if (!node)
		return NULL;
	return avl_tree_entry(node, struct wim_dentry, d_index_node);
}

/* Case-insensitive dentry lookup.  Only @file_name and @file_name_nbytes of
 * @dummy must be valid.  */
static struct wim_dentry *
dir_lookup_ci(const struct wim_inode *dir, const struct wim_dentry *dummy)
{
	struct avl_tree_node *node;

	node = avl_tree_lookup_node(dir->i_children_ci,
				    &dummy->d_index_node_ci,
				    _avl_dentry_compare_names_ci);
	if (!node)
		return NULL;
	return avl_tree_entry(node, struct wim_dentry, d_index_node_ci);
}

/* Given a UTF-16LE filename and a directory, look up the dentry for the file.
 * Return it if found, otherwise NULL.  This has configurable case sensitivity,
 * and @name need not be null-terminated.  */
struct wim_dentry *
get_dentry_child_with_utf16le_name(const struct wim_dentry *dentry,
				   const utf16lechar *name,
				   size_t name_nbytes,
				   CASE_SENSITIVITY_TYPE case_ctype)
{
	const struct wim_inode *dir = dentry->d_inode;
	bool ignore_case = will_ignore_case(case_ctype);
	struct wim_dentry dummy;
	struct wim_dentry *child;

	dummy.file_name = (utf16lechar*)name;
	dummy.file_name_nbytes = name_nbytes;

	if (!ignore_case)
		/* Case-sensitive lookup.  */
		return dir_lookup(dir, &dummy);

	/* Case-insensitive lookup.  */

	child = dir_lookup_ci(dir, &dummy);
	if (!child)
		return NULL;

	if (likely(list_empty(&child->d_ci_conflict_list)))
		/* Only one dentry has this case-insensitive name; return it */
		return child;

	/* Multiple dentries have the same case-insensitive name.  Choose the
	 * dentry with the same case-sensitive name, if one exists; otherwise
	 * print a warning and choose one of the possible dentries arbitrarily.
	 */
	struct wim_dentry *alt = child;
	size_t num_alts = 0;

	do {
		num_alts++;
		if (!dentry_compare_names_case_sensitive(&dummy, alt))
			return alt;
		alt = list_entry(alt->d_ci_conflict_list.next,
				 struct wim_dentry, d_ci_conflict_list);
	} while (alt != child);

	WARNING("Result of case-insensitive lookup is ambiguous\n"
		"          (returning \"%"TS"\" of %zu "
		"possible files, including \"%"TS"\")",
		dentry_full_path(child),
		num_alts,
		dentry_full_path(list_entry(child->d_ci_conflict_list.next,
					    struct wim_dentry,
					    d_ci_conflict_list)));
	return child;
}

/* Returns the child of @dentry that has the file name @name.  Returns NULL if
 * no child has the name. */
struct wim_dentry *
get_dentry_child_with_name(const struct wim_dentry *dentry, const tchar *name,
			   CASE_SENSITIVITY_TYPE case_type)
{
	int ret;
	const utf16lechar *name_utf16le;
	size_t name_utf16le_nbytes;
	struct wim_dentry *child;

	ret = tstr_get_utf16le_and_len(name, &name_utf16le,
				       &name_utf16le_nbytes);
	if (ret)
		return NULL;

	child = get_dentry_child_with_utf16le_name(dentry,
						   name_utf16le,
						   name_utf16le_nbytes,
						   case_type);
	tstr_put_utf16le(name_utf16le);
	return child;
}

static struct wim_dentry *
get_dentry_utf16le(WIMStruct *wim, const utf16lechar *path,
		   CASE_SENSITIVITY_TYPE case_type)
{
	struct wim_dentry *cur_dentry;
	const utf16lechar *name_start, *name_end;

	/* Start with the root directory of the image.  Note: this will be NULL
	 * if an image has been added directly with wimlib_add_empty_image() but
	 * no files have been added yet; in that case we fail with ENOENT.  */
	cur_dentry = wim_get_current_root_dentry(wim);

	name_start = path;
	for (;;) {
		if (cur_dentry == NULL) {
			errno = ENOENT;
			return NULL;
		}

		if (*name_start && !dentry_is_directory(cur_dentry)) {
			errno = ENOTDIR;
			return NULL;
		}

		while (*name_start == cpu_to_le16(WIM_PATH_SEPARATOR))
			name_start++;

		if (!*name_start)
			return cur_dentry;

		name_end = name_start;
		do {
			++name_end;
		} while (*name_end != cpu_to_le16(WIM_PATH_SEPARATOR) && *name_end);

		cur_dentry = get_dentry_child_with_utf16le_name(cur_dentry,
								name_start,
								(u8*)name_end - (u8*)name_start,
								case_type);
		name_start = name_end;
	}
}

/*
 * WIM path lookup: translate a path in the currently selected WIM image to the
 * corresponding dentry, if it exists.
 *
 * @wim
 *	The WIMStruct for the WIM.  The search takes place in the currently
 *	selected image.
 *
 * @path
 *	The path to look up, given relative to the root of the WIM image.
 *	Characters with value WIM_PATH_SEPARATOR are taken to be path
 *	separators.  Leading path separators are ignored, whereas one or more
 *	trailing path separators cause the path to only match a directory.
 *
 * @case_type
 *	The case-sensitivity behavior of this function, as one of the following
 *	constants:
 *
 *    - WIMLIB_CASE_SENSITIVE:  Perform the search case sensitively.  This means
 *	that names must match exactly.
 *
 *    - WIMLIB_CASE_INSENSITIVE:  Perform the search case insensitively.  This
 *	means that names are considered to match if they are equal when
 *	transformed to upper case.  If a path component matches multiple names
 *	case-insensitively, the name that matches the path component
 *	case-sensitively is chosen, if existent; otherwise one
 *	case-insensitively matching name is chosen arbitrarily.
 *
 *    - WIMLIB_CASE_PLATFORM_DEFAULT:  Perform either case-sensitive or
 *	case-insensitive search, depending on the value of the global variable
 *	default_ignore_case.
 *
 *    In any case, no Unicode normalization is done before comparing strings.
 *
 * Returns a pointer to the dentry that is the result of the lookup, or NULL if
 * no such dentry exists.  If NULL is returned, errno is set to one of the
 * following values:
 *
 *	ENOTDIR if one of the path components used as a directory existed but
 *	was not, in fact, a directory.
 *
 *	ENOENT otherwise.
 *
 * Additional notes:
 *
 *    - This function does not consider a reparse point to be a directory, even
 *	if it has FILE_ATTRIBUTE_DIRECTORY set.
 *
 *    - This function does not dereference symbolic links or junction points
 *	when performing the search.
 *
 *    - Since this function ignores leading slashes, the empty path is valid and
 *	names the root directory of the WIM image.
 *
 *    - An image added with wimlib_add_empty_image() does not have a root
 *	directory yet, and this function will fail with ENOENT for any path on
 *	such an image.
 */
struct wim_dentry *
get_dentry(WIMStruct *wim, const tchar *path, CASE_SENSITIVITY_TYPE case_type)
{
	int ret;
	const utf16lechar *path_utf16le;
	struct wim_dentry *dentry;

	ret = tstr_get_utf16le(path, &path_utf16le);
	if (ret)
		return NULL;
	dentry = get_dentry_utf16le(wim, path_utf16le, case_type);
	tstr_put_utf16le(path_utf16le);
	return dentry;
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

/* Similar to get_dentry(), but returns the dentry named by @path with the last
 * component stripped off.
 *
 * Note: The returned dentry is NOT guaranteed to be a directory.  */
struct wim_dentry *
get_parent_dentry(WIMStruct *wim, const tchar *path,
		  CASE_SENSITIVITY_TYPE case_type)
{
	size_t path_len = tstrlen(path);
	tchar buf[path_len + 1];

	tmemcpy(buf, path, path_len + 1);
	to_parent_name(buf, path_len);
	return get_dentry(wim, buf, case_type);
}

/* Creates an unlinked directory entry. */
int
new_dentry(const tchar *name, struct wim_dentry **dentry_ret)
{
	struct wim_dentry *dentry;
	int ret;

	dentry = CALLOC(1, sizeof(struct wim_dentry));
	if (!dentry)
		return WIMLIB_ERR_NOMEM;

	if (*name) {
		ret = dentry_set_name(dentry, name);
		if (ret) {
			FREE(dentry);
			ERROR("Failed to set name on new dentry with name \"%"TS"\"",
			      name);
			return ret;
		}
	}
	dentry->d_parent = dentry;
	*dentry_ret = dentry;
	return 0;
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
new_filler_directory(struct wim_dentry **dentry_ret)
{
	int ret;
	struct wim_dentry *dentry;

	ret = new_dentry_with_inode(T(""), &dentry);
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

/*
 * Free a WIM dentry.
 *
 * In addition to freeing the dentry itself, this decrements the link count of
 * the corresponding inode (if any).  If the inode's link count reaches 0, the
 * inode is freed as well.
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

static int
do_free_dentry(struct wim_dentry *dentry, void *_ignore)
{
	free_dentry(dentry);
	return 0;
}

static int
do_free_dentry_and_unref_streams(struct wim_dentry *dentry, void *lookup_table)
{
	inode_unref_streams(dentry->d_inode, lookup_table);
	free_dentry(dentry);
	return 0;
}

/*
 * Recursively frees all directory entries in the specified tree.
 *
 * @root:
 *	The root of the tree.
 *
 * @lookup_table:
 *	The lookup table for dentries.  If non-NULL, the reference counts in the
 *	lookup table for the lookup table entries corresponding to the dentries
 *	will be decremented.
 *
 * This also puts references to the corresponding inodes.
 *
 * This does *not* unlink @root from its parent directory (if it has one).
 */
void
free_dentry_tree(struct wim_dentry *root, struct wim_lookup_table *lookup_table)
{
	int (*f)(struct wim_dentry *, void *);

	if (lookup_table)
		f = do_free_dentry_and_unref_streams;
	else
		f = do_free_dentry;

	for_dentry_in_tree_depth(root, f, lookup_table);
}

/* Insert the @child dentry into the case sensitive index of the @dir directory.
 * Return NULL if successfully inserted, otherwise a pointer to the
 * already-inserted duplicate.  */
static struct wim_dentry *
dir_index_child(struct wim_inode *dir, struct wim_dentry *child)
{
	struct avl_tree_node *duplicate;

	duplicate = avl_tree_insert(&dir->i_children,
				    &child->d_index_node,
				    _avl_dentry_compare_names);
	if (!duplicate)
		return NULL;
	return avl_tree_entry(duplicate, struct wim_dentry, d_index_node);
}

/* Insert the @child dentry into the case insensitive index of the @dir
 * directory.  Return NULL if successfully inserted, otherwise a pointer to the
 * already-inserted duplicate.  */
static struct wim_dentry *
dir_index_child_ci(struct wim_inode *dir, struct wim_dentry *child)
{
	struct avl_tree_node *duplicate;

	duplicate = avl_tree_insert(&dir->i_children_ci,
				    &child->d_index_node_ci,
				    _avl_dentry_compare_names_ci);
	if (!duplicate)
		return NULL;
	return avl_tree_entry(duplicate, struct wim_dentry, d_index_node_ci);
}

/* Removes the specified dentry from its directory's case-sensitive index.  */
static void
dir_unindex_child(struct wim_inode *dir, struct wim_dentry *child)
{
	avl_tree_remove(&dir->i_children, &child->d_index_node);
}

/* Removes the specified dentry from its directory's case-insensitive index.  */
static void
dir_unindex_child_ci(struct wim_inode *dir, struct wim_dentry *child)
{
	avl_tree_remove(&dir->i_children_ci, &child->d_index_node_ci);
}

/* Returns true iff the specified dentry is in its parent directory's
 * case-insensitive index.  */
static bool
dentry_in_ci_index(const struct wim_dentry *dentry)
{
	return !avl_tree_node_is_unlinked(&dentry->d_index_node_ci);
}

/*
 * Links a dentry into the directory tree.
 *
 * @parent: The dentry that will be the parent of @child.
 * @child: The dentry to link.
 *
 * Returns NULL if successful.  If @parent already contains a dentry with the
 * same case-sensitive name as @child, returns a pointer to this duplicate
 * dentry.
 */
struct wim_dentry *
dentry_add_child(struct wim_dentry *parent, struct wim_dentry *child)
{
	struct wim_dentry *duplicate;
	struct wim_inode *dir;

	wimlib_assert(parent != child);

	dir = parent->d_inode;

	wimlib_assert(inode_is_directory(dir));

	duplicate = dir_index_child(dir, child);
	if (duplicate)
		return duplicate;

	duplicate = dir_index_child_ci(dir, child);
	if (duplicate) {
		list_add(&child->d_ci_conflict_list, &duplicate->d_ci_conflict_list);
		avl_tree_node_set_unlinked(&child->d_index_node_ci);
	} else {
		INIT_LIST_HEAD(&child->d_ci_conflict_list);
	}
	child->d_parent = parent;
	return NULL;
}

/* Unlink a WIM dentry from the directory entry tree.  */
void
unlink_dentry(struct wim_dentry *dentry)
{
	struct wim_inode *dir;

	if (dentry_is_root(dentry))
		return;

	dir = dentry->d_parent->d_inode;

	dir_unindex_child(dir, dentry);

	if (dentry_in_ci_index(dentry)) {

		dir_unindex_child_ci(dir, dentry);

		if (!list_empty(&dentry->d_ci_conflict_list)) {
			/* Make a different case-insensitively-the-same dentry
			 * be the "representative" in the search index. */
			struct list_head *next;
			struct wim_dentry *other;
			struct wim_dentry *existing;

			next = dentry->d_ci_conflict_list.next;
			other = list_entry(next, struct wim_dentry, d_ci_conflict_list);
			existing = dir_index_child_ci(dir, other);
			wimlib_assert(existing == NULL);
		}
	}
	list_del(&dentry->d_ci_conflict_list);
}

static int
read_extra_data(const u8 *p, const u8 *end, struct wim_inode *inode)
{
	while (((uintptr_t)p & 7) && p < end)
		p++;

	if (unlikely(p < end)) {
		inode->i_extra = memdup(p, end - p);
		if (!inode->i_extra)
			return WIMLIB_ERR_NOMEM;
		inode->i_extra_size = end - p;
	}
	return 0;
}

/* Reads a WIM directory entry, including all alternate data stream entries that
 * follow it, from the WIM image's metadata resource.  */
static int
read_dentry(const u8 * restrict buf, size_t buf_len,
	    u64 *offset_p, struct wim_dentry **dentry_ret)
{
	u64 offset = *offset_p;
	u64 length;
	const u8 *p;
	const struct wim_dentry_on_disk *disk_dentry;
	struct wim_dentry *dentry;
	struct wim_inode *inode;
	u16 short_name_nbytes;
	u16 file_name_nbytes;
	u64 calculated_size;
	int ret;

	BUILD_BUG_ON(sizeof(struct wim_dentry_on_disk) != WIM_DENTRY_DISK_SIZE);

	/* Before reading the whole dentry, we need to read just the length.
	 * This is because a dentry of length 8 (that is, just the length field)
	 * terminates the list of sibling directory entries. */

	/* Check for buffer overrun.  */
	if (unlikely(offset + sizeof(u64) > buf_len ||
		     offset + sizeof(u64) < offset))
	{
		ERROR("Directory entry starting at %"PRIu64" ends past the "
		      "end of the metadata resource (size %zu)",
		      offset, buf_len);
		return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
	}

	/* Get pointer to the dentry data.  */
	p = &buf[offset];
	disk_dentry = (const struct wim_dentry_on_disk*)p;

	/* Get dentry length.  */
	length = le64_to_cpu(disk_dentry->length);

	/* Check for end-of-directory.  */
	if (length <= 8) {
		*dentry_ret = NULL;
		return 0;
	}

	/* Validate dentry length.  */
	if (unlikely(length < sizeof(struct wim_dentry_on_disk))) {
		ERROR("Directory entry has invalid length of %"PRIu64" bytes",
		      length);
		return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
	}

	/* Check for buffer overrun.  */
	if (unlikely(offset + length > buf_len ||
		     offset + length < offset))
	{
		ERROR("Directory entry at offset %"PRIu64" and with size "
		      "%"PRIu64" ends past the end of the metadata resource "
		      "(size %zu)", offset, length, buf_len);
		return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
	}

	/* Allocate new dentry structure, along with a preliminary inode.  */
	ret = new_dentry_with_timeless_inode(T(""), &dentry);
	if (ret)
		return ret;

	inode = dentry->d_inode;

	/* Read more fields: some into the dentry, and some into the inode.  */
	inode->i_attributes = le32_to_cpu(disk_dentry->attributes);
	inode->i_security_id = le32_to_cpu(disk_dentry->security_id);
	dentry->subdir_offset = le64_to_cpu(disk_dentry->subdir_offset);
	inode->i_creation_time = le64_to_cpu(disk_dentry->creation_time);
	inode->i_last_access_time = le64_to_cpu(disk_dentry->last_access_time);
	inode->i_last_write_time = le64_to_cpu(disk_dentry->last_write_time);
	copy_hash(inode->i_hash, disk_dentry->unnamed_stream_hash);

	/* I don't know what's going on here.  It seems like M$ screwed up the
	 * reparse points, then put the fields in the same place and didn't
	 * document it.  So we have some fields we read for reparse points, and
	 * some fields in the same place for non-reparse-points.  */
	if (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT) {
		inode->i_rp_unknown_1 = le32_to_cpu(disk_dentry->reparse.rp_unknown_1);
		inode->i_reparse_tag = le32_to_cpu(disk_dentry->reparse.reparse_tag);
		inode->i_rp_unknown_2 = le16_to_cpu(disk_dentry->reparse.rp_unknown_2);
		inode->i_not_rpfixed = le16_to_cpu(disk_dentry->reparse.not_rpfixed);
		/* Leave inode->i_ino at 0.  Note that this means the WIM file
		 * cannot archive hard-linked reparse points.  Such a thing
		 * doesn't really make sense anyway, although I believe it's
		 * theoretically possible to have them on NTFS.  */
	} else {
		inode->i_rp_unknown_1 = le32_to_cpu(disk_dentry->nonreparse.rp_unknown_1);
		inode->i_ino = le64_to_cpu(disk_dentry->nonreparse.hard_link_group_id);
	}
	inode->i_num_ads = le16_to_cpu(disk_dentry->num_alternate_data_streams);

	/* Now onto reading the names.  There are two of them: the (long) file
	 * name, and the short name.  */

	short_name_nbytes = le16_to_cpu(disk_dentry->short_name_nbytes);
	file_name_nbytes = le16_to_cpu(disk_dentry->file_name_nbytes);

	if (unlikely((short_name_nbytes & 1) | (file_name_nbytes & 1))) {
		ERROR("Dentry name is not valid UTF-16 (odd number of bytes)!");
		ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
		goto err_free_dentry;
	}

	/* We now know the length of the file name and short name.  Make sure
	 * the length of the dentry is large enough to actually hold them.
	 *
	 * The calculated length here is unaligned to allow for the possibility
	 * that the dentry's length is unaligned, although this would be
	 * unexpected.  */
	calculated_size = dentry_min_len_with_names(file_name_nbytes,
						    short_name_nbytes);

	if (unlikely(length < calculated_size)) {
		ERROR("Unexpected end of directory entry! (Expected "
		      "at least %"PRIu64" bytes, got %"PRIu64" bytes.)",
		      calculated_size, length);
		ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
		goto err_free_dentry;
	}

	/* Advance p to point past the base dentry, to the first name.  */
	p += sizeof(struct wim_dentry_on_disk);

	/* Read the filename if present.  Note: if the filename is empty, there
	 * is no null terminator following it.  */
	if (file_name_nbytes) {
		dentry->file_name = utf16le_dupz((const utf16lechar *)p,
						 file_name_nbytes);
		if (dentry->file_name == NULL) {
			ret = WIMLIB_ERR_NOMEM;
			goto err_free_dentry;
		}
		dentry->file_name_nbytes = file_name_nbytes;
		p += file_name_nbytes + 2;
	}

	/* Read the short filename if present.  Note: if there is no short
	 * filename, there is no null terminator following it. */
	if (short_name_nbytes) {
		dentry->short_name = utf16le_dupz((const utf16lechar *)p,
						  short_name_nbytes);
		if (dentry->short_name == NULL) {
			ret = WIMLIB_ERR_NOMEM;
			goto err_free_dentry;
		}
		dentry->short_name_nbytes = short_name_nbytes;
		p += short_name_nbytes + 2;
	}

	/* Read extra data at end of dentry (but before alternate data stream
	 * entries).  This may contain tagged items.  */
	ret = read_extra_data(p, &buf[offset + length], inode);
	if (ret)
		goto err_free_dentry;

	/* Align the dentry length.  */
	length = (length + 7) & ~7;

	offset += length;

	/* Read the alternate data streams, if present.  inode->i_num_ads tells
	 * us how many they are, and they will directly follow the dentry in the
	 * metadata resource buffer.
	 *
	 * Note that each alternate data stream entry begins on an 8-byte
	 * aligned boundary, and the alternate data stream entries seem to NOT
	 * be included in the dentry->length field for some reason.  */
	if (unlikely(inode->i_num_ads != 0)) {
		size_t orig_bytes_remaining;
		size_t bytes_remaining;

		if (offset > buf_len) {
			ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
			goto err_free_dentry;
		}
		bytes_remaining = buf_len - offset;
		orig_bytes_remaining = bytes_remaining;
		ret = read_ads_entries(&buf[offset], inode, &bytes_remaining);
		if (ret)
			goto err_free_dentry;
		offset += (orig_bytes_remaining - bytes_remaining);
	}

	*offset_p = offset;  /* Sets offset of next dentry in directory  */
	*dentry_ret = dentry;
	return 0;

err_free_dentry:
	free_dentry(dentry);
	return ret;
}

static bool
dentry_is_dot_or_dotdot(const struct wim_dentry *dentry)
{
	if (dentry->file_name_nbytes <= 4) {
		if (dentry->file_name_nbytes == 4) {
			if (dentry->file_name[0] == cpu_to_le16('.') &&
			    dentry->file_name[1] == cpu_to_le16('.'))
				return true;
		} else if (dentry->file_name_nbytes == 2) {
			if (dentry->file_name[0] == cpu_to_le16('.'))
				return true;
		}
	}
	return false;
}

static int
read_dentry_tree_recursive(const u8 * restrict buf, size_t buf_len,
			   struct wim_dentry * restrict dir)
{
	u64 cur_offset = dir->subdir_offset;

	/* Check for cyclic directory structure, which would cause infinite
	 * recursion if not handled.  */
	for (struct wim_dentry *d = dir->d_parent;
	     !dentry_is_root(d); d = d->d_parent)
	{
		if (unlikely(d->subdir_offset == cur_offset)) {
			ERROR("Cyclic directory structure detected: children "
			      "of \"%"TS"\" coincide with children of \"%"TS"\"",
			      dentry_full_path(dir), dentry_full_path(d));
			return WIMLIB_ERR_INVALID_METADATA_RESOURCE;
		}
	}

	for (;;) {
		struct wim_dentry *child;
		struct wim_dentry *duplicate;
		int ret;

		/* Read next child of @dir.  */
		ret = read_dentry(buf, buf_len, &cur_offset, &child);
		if (ret)
			return ret;

		/* Check for end of directory.  */
		if (child == NULL)
			return 0;

		/* All dentries except the root should be named.  */
		if (unlikely(!dentry_has_long_name(child))) {
			WARNING("Ignoring unnamed dentry in "
				"directory \"%"TS"\"", dentry_full_path(dir));
			free_dentry(child);
			continue;
		}

		/* Don't allow files named "." or "..".  */
		if (unlikely(dentry_is_dot_or_dotdot(child))) {
			WARNING("Ignoring file named \".\" or \"..\"; "
				"potentially malicious archive!!!");
			free_dentry(child);
			continue;
		}

		/* Link the child into the directory.  */
		duplicate = dentry_add_child(dir, child);
		if (unlikely(duplicate)) {
			/* We already found a dentry with this same
			 * case-sensitive long name.  Only keep the first one.
			 */
			WARNING("Ignoring duplicate file \"%"TS"\" "
				"(the WIM image already contains a file "
				"at that path with the exact same name)",
				dentry_full_path(duplicate));
			free_dentry(child);
			continue;
		}

		/* If this child is a directory that itself has children, call
		 * this procedure recursively.  */
		if (child->subdir_offset != 0) {
			if (likely(dentry_is_directory(child))) {
				ret = read_dentry_tree_recursive(buf,
								 buf_len,
								 child);
				if (ret)
					return ret;
			} else {
				WARNING("Ignoring children of "
					"non-directory file \"%"TS"\"",
					dentry_full_path(child));
			}
		}
	}
}

/*
 * Read a tree of dentries (directory entries) from a WIM metadata resource.
 *
 * @buf:
 *	Buffer containing an uncompressed WIM metadata resource.
 *
 * @buf_len:
 *	Length of the uncompressed metadata resource, in bytes.
 *
 * @root_offset
 *	Offset in the metadata resource of the root of the dentry tree.
 *
 * @root_ret:
 *	On success, either NULL or a pointer to the root dentry is written to
 *	this location.  The former case only occurs in the unexpected case that
 *	the tree began with an end-of-directory entry.
 *
 * Return values:
 *	WIMLIB_ERR_SUCCESS (0)
 *	WIMLIB_ERR_INVALID_METADATA_RESOURCE
 *	WIMLIB_ERR_NOMEM
 */
int
read_dentry_tree(const u8 *buf, size_t buf_len,
		 u64 root_offset, struct wim_dentry **root_ret)
{
	int ret;
	struct wim_dentry *root;

	DEBUG("Reading dentry tree (root_offset=%"PRIu64")", root_offset);

	ret = read_dentry(buf, buf_len, &root_offset, &root);
	if (ret)
		return ret;

	if (likely(root != NULL)) {
		if (unlikely(dentry_has_long_name(root) ||
			     dentry_has_short_name(root)))
		{
			WARNING("The root directory has a nonempty name; "
				"removing it.");
			FREE(root->file_name);
			FREE(root->short_name);
			root->file_name = NULL;
			root->short_name = NULL;
			root->file_name_nbytes = 0;
			root->short_name_nbytes = 0;
		}

		if (unlikely(!dentry_is_directory(root))) {
			ERROR("The root of the WIM image is not a directory!");
			ret = WIMLIB_ERR_INVALID_METADATA_RESOURCE;
			goto err_free_dentry_tree;
		}

		if (likely(root->subdir_offset != 0)) {
			ret = read_dentry_tree_recursive(buf, buf_len, root);
			if (ret)
				goto err_free_dentry_tree;
		}
	} else {
		WARNING("The metadata resource has no directory entries; "
			"treating as an empty image.");
	}
	*root_ret = root;
	return 0;

err_free_dentry_tree:
	free_dentry_tree(root, NULL);
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

	/* UNIX data uses the two 8-byte reserved fields.  So if no UNIX data
	 * exists, they get set to 0, just as we would do anyway.  */
	disk_dentry->unused_1 = cpu_to_le64(0);
	disk_dentry->unused_2 = cpu_to_le64(0);

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

	if (inode->i_extra_size) {
		/* Extra tagged items --- not usually present.  */
		p = mempcpy(p, inode->i_extra, inode->i_extra_size);
		while ((uintptr_t)p & 7)
			*p++ = 0;
	}

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
write_dir_dentries(struct wim_dentry *dir, void *_pp)
{
	if (dir->subdir_offset != 0) {
		u8 **pp = _pp;
		u8 *p = *pp;
		struct wim_dentry *child;

		/* write child dentries */
		for_dentry_child(child, dir)
			p = write_dentry(child, p);

		/* write end of directory entry */
		*(u64*)p = 0;
		p += 8;
		*pp = p;
	}
	return 0;
}

/* Writes a directory tree to the metadata resource.
 *
 * @root:	Root of the dentry tree.
 * @p:		Pointer to a buffer with enough space for the dentry tree.
 *
 * Returns pointer to the byte after the last byte we wrote.
 */
u8 *
write_dentry_tree(struct wim_dentry *root, u8 *p)
{
	DEBUG("Writing dentry tree.");
	wimlib_assert(dentry_is_root(root));

	/* write root dentry and end-of-directory entry following it */
	p = write_dentry(root, p);
	*(u64*)p = 0;
	p += 8;

	/* write the rest of the dentry tree */
	for_dentry_in_tree(root, write_dir_dentries, &p);

	return p;
}
