#ifndef _WIMLIB_DENTRY_H
#define _WIMLIB_DENTRY_H

#include "wimlib/case.h"
#include "wimlib/compiler.h"
#include "wimlib/inode.h"
#include "wimlib/list.h"
#include "wimlib/rbtree.h"
#include "wimlib/types.h"

struct wim_inode;
struct wim_lookup_table;
struct wim_lookup_table_entry;
struct wim_security_data;

/* Base size of a WIM dentry in the on-disk format, up to and including the file
 * name length.  This does not include the variable-length file name, short
 * name, alternate data stream entries, and padding to 8-byte boundaries.  */
#define WIM_DENTRY_DISK_SIZE 102

/*
 * In-memory structure for a WIM directory entry (dentry).  There is a directory
 * tree for each image in the WIM.
 *
 * Note that this is a directory entry and not an inode.  Since NTFS allows hard
 * links, it's possible for a NTFS inode to correspond to multiple WIM dentries.
 * The hard link group ID field of the on-disk WIM dentry tells us the number of
 * the NTFS inode that the dentry corresponds to (and this gets placed in
 * d_inode->i_ino).
 *
 * Unfortunately, WIM files do not have an analogue to an inode; instead certain
 * information, such as file attributes, the security descriptor, and file
 * streams is replicated in each hard-linked dentry, even though this
 * information really is associated with an inode.  In-memory, we fix up this
 * flaw by allocating a `struct wim_inode' for each dentry that contains some of
 * this duplicated information, then combining the inodes for each hard link
 * group together.
 *
 * Confusingly, it's possible for stream information to be missing from a dentry
 * in a hard link set, in which case the stream information needs to be gotten
 * from one of the other dentries in the hard link set.  In addition, it is
 * possible for dentries to have inconsistent security IDs, file attributes, or
 * file streams when they share the same hard link ID (don't even ask.  I hope
 * that Microsoft may have fixed this problem, since I've only noticed it in the
 * 'install.wim' for Windows 7).  For those dentries, we have to use the
 * conflicting fields to split up the hard link groups.  (See
 * dentry_tree_fix_inodes() in inode_fixup.c.)
 */
struct wim_dentry {
	/* Pointer to the inode for this dentry.  This will contain some
	 * information that was factored out of the on-disk WIM dentry as common
	 * to all dentries in a hard link group.  */
	struct wim_inode *d_inode;

	/* Node for the parent's red-black tree of child dentries, sorted by
	 * case sensitive long name. */
	struct rb_node rb_node;

	/* Node for the parent's red-black tree of child dentries, sorted by
	 * case insensitive long name. */
	struct rb_node rb_node_case_insensitive;

	/* List of dentries in a directory that have different case sensitive
	 * long names but share the same case insensitive long name */
	struct list_head case_insensitive_conflict_list;

	/* Length of UTF-16LE encoded short filename, in bytes, not including
	 * the terminating zero wide-character. */
	u16 short_name_nbytes;

	/* Length of UTF-16LE encoded "long" file name, in bytes, not including
	 * the terminating null character. */
	u16 file_name_nbytes;

	/* Length of full path name encoded using "tchars", in bytes, not
	 * including the terminating null character. */
	u32 full_path_nbytes;

	/* During extraction extractions, this flag will be set after the
	 * "skeleton" of the dentry has been extracted.  */
	u8 skeleton_extracted : 1;

	/* When capturing from a NTFS volume using NTFS-3g, this flag is set on
	 * dentries that were created from a filename in the WIN32 or WIN32+DOS
	 * namespaces rather than the POSIX namespace.  Otherwise this will
	 * always be 0.  */
	u8 is_win32_name : 1;

	/* Temporary flag; always reset to 0 when done using.  */
	u8 tmp_flag : 1;

	/* Set to 1 if this name was extracted as a link, so no streams need to
	 * be extracted to it.  */
	u8 was_linked : 1;

	/* Temporary list field  */
	struct list_head tmp_list;

	/* Links list of dentries being extracted  */
	struct list_head extraction_list;

	/* Linked list node that places this dentry in the list of aliases for
	 * its inode (d_inode) */
	struct list_head d_alias;

	/* The parent of this directory entry. */
	struct wim_dentry *parent;

	/* 'length' and 'subdir_offset' are only used while reading and writing
	 * this dentry; see the corresponding field in
	 * `struct wim_dentry_on_disk' for explanation.  */
	u64 length;
	u64 subdir_offset;

	/* Pointer to the UTF-16LE short filename (malloc()ed buffer), or NULL
	 * if this dentry has no short name.  */
	utf16lechar *short_name;

	/* Pointer to the UTF-16LE filename (malloc()ed buffer), or NULL if this
	 * dentry has no filename.  */
	utf16lechar *file_name;

	/* Full path to this dentry in the WIM, in platform-dependent tchars
	 * that can be printed without conversion.  By default this field will
	 * be NULL and will only be calculated on-demand by the
	 * calculate_dentry_full_path() or dentry_full_path() functions.  */
	tchar *_full_path;

	/* (Extraction only) Actual name to extract this dentry as, along with
	 * its length in tchars excluding the NULL terminator.  This usually
	 * will be the same as file_name, with the character encoding converted
	 * if needed.  But if file_name contains characters not accepted on the
	 * current platform, then this may be set slightly differently from
	 * file_name.  This will be either NULL or a malloc()ed buffer that may
	 * alias file_name.  */
	tchar *extraction_name;
	size_t extraction_name_nchars;
};

#define rbnode_dentry(node) container_of(node, struct wim_dentry, rb_node)

static inline bool
dentry_is_first_in_inode(const struct wim_dentry *dentry)
{
	return inode_first_dentry(dentry->d_inode) == dentry;
}

extern u64
dentry_out_total_length(const struct wim_dentry *dentry);

extern int
for_dentry_in_tree(struct wim_dentry *root,
		   int (*visitor)(struct wim_dentry*, void*),
		   void *args);

extern int
for_dentry_in_rbtree(struct rb_node *node,
		     int (*visitor)(struct wim_dentry *, void *),
		     void *arg);

extern int
for_dentry_child(const struct wim_dentry *dentry,
		 int (*visitor)(struct wim_dentry *, void *),
		 void *arg);

extern int
for_dentry_in_tree_depth(struct wim_dentry *root,
			 int (*visitor)(struct wim_dentry*, void*),
			 void *args);

extern void
calculate_subdir_offsets(struct wim_dentry *dentry, u64 *subdir_offset_p);

extern int
dentry_set_name(struct wim_dentry *dentry, const tchar *new_name);

extern struct wim_dentry *
get_dentry(struct WIMStruct *wim, const tchar *path,
	   CASE_SENSITIVITY_TYPE case_type);

extern struct wim_dentry *
get_dentry_child_with_name(const struct wim_dentry *dentry,
			   const tchar *name,
			   CASE_SENSITIVITY_TYPE case_type);

extern struct wim_dentry *
get_dentry_child_with_utf16le_name(const struct wim_dentry *dentry,
				   const utf16lechar *name,
				   size_t name_nbytes,
				   CASE_SENSITIVITY_TYPE case_type);

extern struct wim_dentry *
get_parent_dentry(struct WIMStruct *wim, const tchar *path,
		  CASE_SENSITIVITY_TYPE case_type);

#ifdef WITH_FUSE

#define LOOKUP_FLAG_ADS_OK		0x00000001
#define LOOKUP_FLAG_DIRECTORY_OK	0x00000002

extern int
wim_pathname_to_stream(WIMStruct *wim,
		       const tchar *path,
		       int lookup_flags,
		       struct wim_dentry **dentry_ret,
		       struct wim_lookup_table_entry **lte_ret,
		       u16 *stream_idx_ret);
#endif

extern int
calculate_dentry_full_path(struct wim_dentry *dentry);

extern int
calculate_dentry_tree_full_paths(struct wim_dentry *root);

extern tchar *
dentry_full_path(struct wim_dentry *dentry);

extern int
new_dentry(const tchar *name, struct wim_dentry **dentry_ret);

extern int
new_dentry_with_inode(const tchar *name, struct wim_dentry **dentry_ret);

extern int
new_dentry_with_timeless_inode(const tchar *name, struct wim_dentry **dentry_ret);

extern void
dentry_tree_clear_inode_visited(struct wim_dentry *root);

extern int
new_filler_directory(const tchar *name, struct wim_dentry **dentry_ret);

extern void
free_dentry(struct wim_dentry *dentry);

extern void
put_dentry(struct wim_dentry *dentry);

extern void
free_dentry_tree(struct wim_dentry *root,
		 struct wim_lookup_table *lookup_table);

extern void
unlink_dentry(struct wim_dentry *dentry);

extern struct wim_dentry *
dentry_add_child(struct wim_dentry * restrict parent,
		 struct wim_dentry * restrict child);

extern int
rename_wim_path(WIMStruct *wim, const tchar *from, const tchar *to,
		CASE_SENSITIVITY_TYPE case_type);


extern int
read_dentry_tree(const u8 *buf, size_t buf_len,
		 u64 root_offset, struct wim_dentry **root_ret);

extern u8 *
write_dentry_tree(const struct wim_dentry * restrict tree,
		  u8 * restrict p);

static inline bool
dentry_is_root(const struct wim_dentry *dentry)
{
	return dentry->parent == dentry;
}

static inline bool
dentry_is_directory(const struct wim_dentry *dentry)
{
	return inode_is_directory(dentry->d_inode);
}

static inline bool
dentry_has_children(const struct wim_dentry *dentry)
{
	return inode_has_children(dentry->d_inode);
}

static inline bool
dentry_has_short_name(const struct wim_dentry *dentry)
{
	return dentry->short_name_nbytes != 0;
}

static inline bool
dentry_has_long_name(const struct wim_dentry *dentry)
{
	return dentry->file_name_nbytes != 0;
}

extern int
dentry_tree_fix_inodes(struct wim_dentry *root, struct list_head *inode_list);
#endif /* _WIMLIB_DENTRY_H */
