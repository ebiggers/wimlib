#ifndef _WIMLIB_DENTRY_H
#define _WIMLIB_DENTRY_H

#include "wimlib/compiler.h"
#include "wimlib/list.h"
#include "wimlib/rbtree.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

#include <string.h>
#include <sys/types.h> /* uid_t, gid_t */

#ifdef WITH_FUSE
#  include <pthread.h>
#endif

struct wim_lookup_table;
struct wim_lookup_table_entry;
struct wimfs_fd;
struct wim_inode;

/* Size of the struct wim_dentry up to and including the file_name_len. */
#define WIM_DENTRY_DISK_SIZE    102

/*
 * Reparse tags documented at
 * http://msdn.microsoft.com/en-us/library/dd541667(v=prot.10).aspx
 */
#define WIM_IO_REPARSE_TAG_RESERVED_ZERO	0x00000000
#define WIM_IO_REPARSE_TAG_RESERVED_ONE		0x00000001
#define WIM_IO_REPARSE_TAG_MOUNT_POINT		0xA0000003
#define WIM_IO_REPARSE_TAG_HSM			0xC0000004
#define WIM_IO_REPARSE_TAG_HSM2			0x80000006
#define WIM_IO_REPARSE_TAG_DRIVER_EXTENDER	0x80000005
#define WIM_IO_REPARSE_TAG_SIS			0x80000007
#define WIM_IO_REPARSE_TAG_DFS			0x8000000A
#define WIM_IO_REPARSE_TAG_DFSR			0x80000012
#define WIM_IO_REPARSE_TAG_FILTER_MANAGER	0x8000000B
#define WIM_IO_REPARSE_TAG_SYMLINK		0xA000000C

#define FILE_ATTRIBUTE_READONLY            0x00000001
#define FILE_ATTRIBUTE_HIDDEN              0x00000002
#define FILE_ATTRIBUTE_SYSTEM              0x00000004
#define FILE_ATTRIBUTE_DIRECTORY           0x00000010
#define FILE_ATTRIBUTE_ARCHIVE             0x00000020
#define FILE_ATTRIBUTE_DEVICE              0x00000040
#define FILE_ATTRIBUTE_NORMAL              0x00000080
#define FILE_ATTRIBUTE_TEMPORARY           0x00000100
#define FILE_ATTRIBUTE_SPARSE_FILE         0x00000200
#define FILE_ATTRIBUTE_REPARSE_POINT       0x00000400
#define FILE_ATTRIBUTE_COMPRESSED          0x00000800
#define FILE_ATTRIBUTE_OFFLINE             0x00001000
#define FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x00002000
#define FILE_ATTRIBUTE_ENCRYPTED           0x00004000
#define FILE_ATTRIBUTE_VIRTUAL             0x00010000


/* Alternate data stream entry.
 *
 * We read this from disk in the read_ads_entries() function; see that function
 * for more explanation. */
struct wim_ads_entry {
	union {
		/* SHA-1 message digest of stream contents */
		u8 hash[SHA1_HASH_SIZE];

		/* The corresponding lookup table entry (only for resolved
		 * streams) */
		struct wim_lookup_table_entry *lte;
	};

	/* Length of UTF16-encoded stream name, in bytes, not including the
	 * terminating null character; or 0 if the stream is unnamed. */
	u16 stream_name_nbytes;

	/* Number to identify an alternate data stream even after it's possibly
	 * been moved or renamed. */
	u32 stream_id;

	/* Stream name (UTF-16LE), null-terminated, or NULL if the stream is
	 * unnamed.  */
	utf16lechar *stream_name;

	/* Reserved field.  We read it into memory so we can write it out
	 * unchanged. */
	u64 reserved;
};


static inline bool
ads_entries_have_same_name(const struct wim_ads_entry *entry_1,
			   const struct wim_ads_entry *entry_2)
{
	return entry_1->stream_name_nbytes == entry_2->stream_name_nbytes &&
	       memcmp(entry_1->stream_name, entry_2->stream_name,
		      entry_1->stream_name_nbytes) == 0;
}

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
 * dentry_tree_fix_inodes() in hardlink.c).
 */
struct wim_dentry {
	/* The inode for this dentry */
	struct wim_inode *d_inode;

	/* Node for the parent's red-black tree of child dentries, sorted by
	 * case sensitive long name. */
	struct rb_node rb_node;

#ifdef __WIN32__
	/* Node for the parent's red-black tree of child dentries, sorted by
	 * case insensitive long name. */
	struct rb_node rb_node_case_insensitive;

	/* List of dentries in a directory that have different case sensitive
	 * long names but share the same case insensitive long name */
	struct list_head case_insensitive_conflict_list;
#endif

	/* Length of UTF-16LE encoded short filename, in bytes, not including
	 * the terminating zero wide-character. */
	u16 short_name_nbytes;

	/* Length of UTF-16LE encoded "long" file name, in bytes, not including
	 * the terminating null character. */
	u16 file_name_nbytes;

	/* Length of full path name encoded using "tchars", in bytes, not
	 * including the terminating null character. */
	u32 full_path_nbytes;

	/* Does this dentry need to be extracted? */
	u8 needs_extraction : 1;

	u8 not_extracted : 1;

	/* Only used during NTFS capture */
	u8 is_win32_name : 1;

	/* Set to 1 if an inode has multiple DOS names. */
	u8 dos_name_invalid : 1;

	/* Temporary list */
	struct list_head tmp_list;

	/* List of dentries in the inode (hard link set)  */
	struct list_head d_alias;

	/* The parent of this directory entry. */
	struct wim_dentry *parent;

	/*
	 * Size of directory entry on disk, in bytes.  Typical size is around
	 * 104 to 120 bytes.
	 *
	 * It is possible for the length field to be 0.  This situation, which
	 * is undocumented, indicates the end of a list of sibling nodes in a
	 * directory.  It also means the real length is 8, because the dentry
	 * included only the length field, but that takes up 8 bytes.
	 *
	 * The length here includes the base directory entry on disk as well as
	 * the long and short filenames.  It does NOT include any alternate
	 * stream entries that may follow the directory entry, even though the
	 * size of those needs to be considered.  The length SHOULD be 8-byte
	 * aligned, although we don't require it to be.  We do require the
	 * length to be large enough to hold the file name(s) of the dentry;
	 * additionally, a warning is issued if this field is larger than the
	 * aligned size.
	 */
	u64 length;

	/* The offset, from the start of the uncompressed WIM metadata resource
	 * for this image, of this dentry's child dentries.  0 if the directory
	 * entry has no children, which is the case for regular files or reparse
	 * points. */
	u64 subdir_offset;

	u64 d_unused_1;
	u64 d_unused_2;

	/* Pointer to the UTF-16LE short filename (malloc()ed buffer) */
	utf16lechar *short_name;

	/* Pointer to the UTF-16LE filename (malloc()ed buffer). */
	utf16lechar *file_name;

	/* Full path of this dentry in the WIM */
	tchar *_full_path;

	/* Actual name to extract this dentry as. */
	tchar *extraction_name;
	size_t extraction_name_nchars;

	/* List head for building a list of dentries that contain a certain
	 * stream. */
	struct list_head extraction_stream_list;
};

#define rbnode_dentry(node) container_of(node, struct wim_dentry, rb_node)

/*
 * WIM inode.
 *
 * As mentioned above, in the WIM file that is no on-disk analogue of a real
 * inode, as most of these fields are duplicated in the dentries.
 */
struct wim_inode {
	/* Timestamps for the inode.  The timestamps are the number of
	 * 100-nanosecond intervals that have elapsed since 12:00 A.M., January
	 * 1st, 1601, UTC.  This is the same format used in NTFS inodes. */
	u64 i_creation_time;
	u64 i_last_access_time;
	u64 i_last_write_time;

	/* The file attributes associated with this inode.  This is a bitwise OR
	 * of the FILE_ATTRIBUTE_* flags. */
	u32 i_attributes;

	/* The index of the security descriptor in the WIM image's table of
	 * security descriptors that contains this file's security information.
	 * If -1, no security information exists for this file.  */
	int32_t i_security_id;

	/* %true iff the inode's lookup table entries has been resolved (i.e.
	 * the @lte field is valid, but the @hash field is not valid)
	 *
	 * (This is not an on-disk field.) */
	u8 i_resolved : 1;

	/* %true iff verify_inode() has run on this inode. */
	u8 i_verified : 1;

	u8 i_visited : 1;

	/* Used only in NTFS-mode extraction */
	u8 i_dos_name_extracted : 1;

	/* Set to 0 if reparse point fixups have been done.  Otherwise set to 1.
	 *
	 * Note: this actually may reflect the SYMBOLIC_LINK_RELATIVE flag.  */
	u16 i_not_rpfixed;

	/* Number of alternate data streams associated with this inode */
	u16 i_num_ads;

	/* Unused/unknown fields that we just read into memory so we can
	 * re-write them unchanged.  */
	u32 i_rp_unknown_1;
	u16 i_rp_unknown_2;

	/* If i_resolved == 0:
	 *	SHA1 message digest of the contents of the unnamed-data stream
	 *	of this inode, or all zeroes if this inode has no unnamed data
	 *	stream, or optionally all zeroes if this inode has an empty
	 *	unnamed data stream.
	 *
	 * If i_resolved == 1:
	 *	Pointer to the lookup table entry for the unnamed data stream
	 *	of this inode, or NULL if this inode has no unnamed data stream,
	 *	or optionally all zeroes if this inode has an empty unnamed data
	 *	stream.
	 */
	union {
		u8 i_hash[SHA1_HASH_SIZE];
		struct wim_lookup_table_entry *i_lte;
	};

	/* Identity of a reparse point.  See
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa365503(v=vs.85).aspx
	 * for what a reparse point is. */
	u32 i_reparse_tag;

	/* Number of dentries that reference this inode */
	u32 i_nlink;

	/* Alternate data stream entries. */
	struct wim_ads_entry *i_ads_entries;

	/* Inode number */
	u64 i_ino;

	/* Device number, used only during image capture */
	u64 i_devno;

	/* List of dentries that reference this inode (there should be
	 * link_count of them) */
	struct list_head i_dentry;

	union {
		struct hlist_node i_hlist;
		struct list_head i_list;
	};

	tchar *i_extracted_file;

	/* Root of a red-black tree storing the children of this inode (if
	 * non-empty, implies the inode is a directory, although that is also
	 * noted in the @attributes field.) */
	struct rb_root i_children;

#ifdef __WIN32__
	struct rb_root i_children_case_insensitive;
#endif

	/* Next alternate data stream ID to be assigned */
	u32 i_next_stream_id;

#ifdef WITH_FUSE
	/* wimfs file descriptors table for the inode */
	u16 i_num_opened_fds;
	u16 i_num_allocated_fds;
	struct wimfs_fd **i_fds;
	/* This mutex protects the inode's file descriptors table during
	 * read-only mounts.  Read-write mounts are still restricted to 1
	 * thread. */
	pthread_mutex_t i_mutex;
#endif
};

#define inode_for_each_dentry(dentry, inode) \
		list_for_each_entry((dentry), &(inode)->i_dentry, d_alias)

#define inode_add_dentry(dentry, inode) \
		list_add_tail(&(dentry)->d_alias, &(inode)->i_dentry)

#define inode_first_dentry(inode) \
		container_of(inode->i_dentry.next, struct wim_dentry, d_alias)

static inline bool
dentry_is_first_in_inode(const struct wim_dentry *dentry)
{
	return inode_first_dentry(dentry->d_inode) == dentry;
}

extern u64
dentry_correct_total_length(const struct wim_dentry *dentry);

extern int
for_dentry_in_tree(struct wim_dentry *root,
		   int (*visitor)(struct wim_dentry*, void*),
		   void *args);

extern int
for_dentry_in_rbtree(struct rb_node *node,
		     int (*visitor)(struct wim_dentry *, void *),
		     void *arg);

static inline int
for_dentry_child(const struct wim_dentry *dentry,
		 int (*visitor)(struct wim_dentry *, void *),
		 void *arg)
{
	return for_dentry_in_rbtree(dentry->d_inode->i_children.rb_node,
				    visitor,
				    arg);
}

extern int
for_dentry_in_tree_depth(struct wim_dentry *root,
			 int (*visitor)(struct wim_dentry*, void*),
			 void *args);

extern void
calculate_subdir_offsets(struct wim_dentry *dentry, u64 *subdir_offset_p);

extern int
set_dentry_name(struct wim_dentry *dentry, const tchar *new_name);

extern struct wim_dentry *
get_dentry(struct WIMStruct *w, const tchar *path);

extern struct wim_inode *
wim_pathname_to_inode(struct WIMStruct *w, const tchar *path);

extern struct wim_dentry *
get_dentry_child_with_name(const struct wim_dentry *dentry,
			   const tchar *name);

extern struct wim_dentry *
get_dentry_child_with_utf16le_name(const struct wim_dentry *dentry,
				   const utf16lechar *name,
				   size_t name_nbytes);

extern struct wim_dentry *
get_parent_dentry(struct WIMStruct *w, const tchar *path);

extern int
print_dentry(struct wim_dentry *dentry, void *lookup_table);

extern int
print_dentry_full_path(struct wim_dentry *entry, void *ignore);

extern int
calculate_dentry_full_path(struct wim_dentry *dentry);

extern int
calculate_dentry_tree_full_paths(struct wim_dentry *root);

extern tchar *
dentry_full_path(struct wim_dentry *dentry);

extern struct wim_inode *
new_timeless_inode(void) _malloc_attribute;

extern int
new_dentry(const tchar *name, struct wim_dentry **dentry_ret);

extern int
new_dentry_with_inode(const tchar *name, struct wim_dentry **dentry_ret);

extern int
new_dentry_with_timeless_inode(const tchar *name, struct wim_dentry **dentry_ret);

extern int
new_filler_directory(const tchar *name, struct wim_dentry **dentry_ret);

extern void
free_inode(struct wim_inode *inode);

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

extern struct wim_ads_entry *
inode_get_ads_entry(struct wim_inode *inode, const tchar *stream_name,
		    u16 *idx_ret);

extern struct wim_ads_entry *
inode_add_ads_utf16le(struct wim_inode *inode,
		      const utf16lechar *stream_name,
		      size_t stream_name_nbytes);

extern struct wim_ads_entry *
inode_add_ads(struct wim_inode *dentry, const tchar *stream_name);

extern int
inode_add_ads_with_data(struct wim_inode *inode, const tchar *name,
			const void *value, size_t size,
			struct wim_lookup_table *lookup_table);

extern int
inode_set_unnamed_stream(struct wim_inode *inode, const void *data, size_t len,
			 struct wim_lookup_table *lookup_table);

extern void
inode_remove_ads(struct wim_inode *inode, u16 idx,
		 struct wim_lookup_table *lookup_table);


#define WIMLIB_UNIX_DATA_TAG "$$__wimlib_UNIX_data"
#define WIMLIB_UNIX_DATA_TAG_NBYTES (sizeof(WIMLIB_UNIX_DATA_TAG) - 1)

#define WIMLIB_UNIX_DATA_TAG_UTF16LE "$\0$\0_\0_\0w\0i\0m\0l\0i\0b\0_\0U\0N\0I\0X\0_\0d\0a\0t\0a\0"
#define WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES (sizeof(WIMLIB_UNIX_DATA_TAG_UTF16LE) - 1)

/* Format for special alternate data stream entries to store UNIX data for files
 * and directories (see: WIMLIB_ADD_FLAG_UNIX_DATA) */
struct wimlib_unix_data {
	u16 version; /* Must be 0 */
	u16 uid;
	u16 gid;
	u16 mode;
} _packed_attribute;

#ifndef __WIN32__

#define NO_UNIX_DATA (-1)
#define BAD_UNIX_DATA (-2)
extern int
inode_get_unix_data(const struct wim_inode *inode,
		    struct wimlib_unix_data *unix_data,
		    u16 *stream_idx_ret);

#define UNIX_DATA_UID    0x1
#define UNIX_DATA_GID    0x2
#define UNIX_DATA_MODE   0x4
#define UNIX_DATA_ALL    (UNIX_DATA_UID | UNIX_DATA_GID | UNIX_DATA_MODE)
#define UNIX_DATA_CREATE 0x8
extern int
inode_set_unix_data(struct wim_inode *inode, uid_t uid, gid_t gid, mode_t mode,
		    struct wim_lookup_table *lookup_table, int which);
#endif

extern int
read_dentry(const u8 *metadata_resource, u64 metadata_resource_len,
	    u64 offset, struct wim_dentry *dentry);

extern int
read_dentry_tree(const u8 metadata_resource[], u64 metadata_resource_len,
		 struct wim_dentry *dentry);

extern u8 *
write_dentry_tree(const struct wim_dentry *tree, u8 *p);

static inline bool
dentry_is_root(const struct wim_dentry *dentry)
{
	return dentry->parent == dentry;
}

static inline bool
inode_is_directory(const struct wim_inode *inode)
{
	return (inode->i_attributes & FILE_ATTRIBUTE_DIRECTORY)
		&& !(inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

static inline bool
dentry_is_directory(const struct wim_dentry *dentry)
{
	return inode_is_directory(dentry->d_inode);
}

/* For our purposes, we consider "real" symlinks and "junction points" to both
 * be symlinks. */
static inline bool
inode_is_symlink(const struct wim_inode *inode)
{
	return (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		&& (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
		    inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT);
}

static inline bool
inode_is_regular_file(const struct wim_inode *inode)
{
	return !inode_is_directory(inode) && !inode_is_symlink(inode);
}

static inline bool
dentry_is_regular_file(const struct wim_dentry *dentry)
{
	return inode_is_regular_file(dentry->d_inode);
}

static inline bool
inode_has_children(const struct wim_inode *inode)
{
	return inode->i_children.rb_node != NULL;
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

extern void
inode_ref_streams(struct wim_inode *inode);

extern int
dentry_tree_fix_inodes(struct wim_dentry *root, struct list_head *inode_list);

extern int
verify_dentry(struct wim_dentry *dentry, void *wim);

#endif
