#ifndef _WIMLIB_DENTRY_H
#define _WIMLIB_DENTRY_H

#include "wimlib/compiler.h"
#include "wimlib/list.h"
#include "wimlib/rbtree.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

#include <string.h>
#include <sys/types.h> /* uid_t, gid_t */

struct wim_lookup_table;
struct wim_lookup_table_entry;
struct wimfs_fd;
struct wim_inode;
struct wim_security_data;

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

	/* For extraction operations, this flag will be set on dentries in the
	 * tree being extracted.  Otherwise this will always be 0.  */
	u8 in_extraction_tree : 1;

	/* For extraction operations, this flag will be set when a dentry in the
	 * tree being extracted is not being extracted for some reason (file
	 * type not supported by target filesystem, contains invalid characters,
	 * or not in one of the multiple sub-trees being extracted).  Otherwise
	 * this will always be 0.  */
	u8 extraction_skipped : 1;

	/* During extraction extractions, this flag will be set after the
	 * "skeleton" of the dentry has been extracted.  */
	u8 skeleton_extracted : 1;

	/* When capturing from a NTFS volume using NTFS-3g, this flag is set on
	 * dentries that were created from a filename in the WIN32 or WIN32+DOS
	 * namespaces rather than the POSIX namespace.  Otherwise this will
	 * always be 0.  */
	u8 is_win32_name : 1;

	/* When verifying the dentry tree after reading it into memory, this
	 * flag will be set on all dentries in a hard link group that have a
	 * nonempty DOS name except one.  This is because it is supposed to be
	 * illegal (on NTFS, at least) for a single inode to have multiple DOS
	 * names.  */
	u8 dos_name_invalid : 1;

	u8 tmp_flag : 1;

	u8 was_hardlinked : 1;

	/* Temporary list field used to make lists of dentries in a few places.
	 * */
	struct list_head tmp_list;

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

	/* These correspond to the two unused fields in the on-disk WIM dentry;
	 * we read them into memory so we can write them unchanged.  These
	 * fields are set to 0 on new dentries.  */
	u64 d_unused_1;
	u64 d_unused_2;

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

/*
 * WIM inode.
 *
 * As mentioned in the comment above `struct wim_dentry', in the WIM file that
 * is no on-disk analogue of a real inode, as most of these fields are
 * duplicated in the dentries.  Instead, a `struct wim_inode' is something we
 * create ourselves to simplify the handling of hard links.
 */
struct wim_inode {
	/* If i_resolved == 0:
	 *	SHA1 message digest of the contents of the unnamed-data stream
	 *	of this inode.
	 *
	 * If i_resolved == 1:
	 *	Pointer to the lookup table entry for the unnamed data stream
	 *	of this inode, or NULL.
	 *
	 * i_hash corresponds to the 'unnamed_stream_hash' field of the `struct
	 * wim_dentry_on_disk' and the additional caveats documented about that
	 * field apply here (for example, the quirks regarding all-zero hashes).
	 */
	union {
		u8 i_hash[SHA1_HASH_SIZE];
		struct wim_lookup_table_entry *i_lte;
	};

	/* Corresponds to the 'attributes' field of `struct wim_dentry_on_disk';
	 * bitwise OR of the FILE_ATTRIBUTE_* flags that give the attributes of
	 * this inode. */
	u32 i_attributes;

	/* Root of a red-black tree storing the child dentries of this inode, if
	 * any.  Keyed by wim_dentry->file_name, case sensitively. */
	struct rb_root i_children;

	/* Root of a red-black tree storing the children of this inode, if any.
	 * Keyed by wim_dentry->file_name, case insensitively. */
	struct rb_root i_children_case_insensitive;

	/* List of dentries that are aliases for this inode.  There will be
	 * i_nlink dentries in this list.  */
	struct list_head i_dentry;

	/* Field to place this inode into a list. */
	union {
		/* Hash list node- used in hardlink.c when the inodes are placed
		 * into a hash table keyed by inode number and optionally device
		 * number, in order to detect dentries that are aliases for the
		 * same inode. */
		struct hlist_node i_hlist;

		/* Normal list node- used to connect all the inodes of a WIM image
		 * into a single linked list referenced from the
		 * `struct wim_image_metadata' for that image. */
		struct list_head i_list;
	};

	/* Number of dentries that are aliases for this inode.  */
	u32 i_nlink;

	/* Number of alternate data streams (ADS) associated with this inode */
	u16 i_num_ads;

	/* Flag that indicates whether this inode's streams have been
	 * "resolved".  By default, the inode starts as "unresolved", meaning
	 * that the i_hash field, along with the hash field of any associated
	 * wim_ads_entry's, are valid and should be used as keys in the WIM
	 * lookup table to find the associated `struct wim_lookup_table_entry'.
	 * But if the inode has been resolved, then each of these fields is
	 * replaced with a pointer directly to the appropriate `struct
	 * wim_lookup_table_entry', or NULL if the stream is empty.  */
	u8 i_resolved : 1;

	/* Flag used to mark this inode as visited; this is used when visiting
	 * all the inodes in a dentry tree exactly once.  It will be 0 by
	 * default and must be cleared following the tree traversal, even in
	 * error paths.  */
	u8 i_visited : 1;

	/* Set if the DOS name of an inode has already been extracted.  */
	u8 i_dos_name_extracted : 1;

	/* 1 iff all ADS entries of this inode are named or if this inode
	 * has no ADS entries  */
	u8 i_canonical_streams : 1;

	/* Pointer to a malloc()ed array of i_num_ads alternate data stream
	 * entries for this inode.  */
	struct wim_ads_entry *i_ads_entries;

	/* Creation time, last access time, and last write time for this inode, in
	 * 100-nanosecond intervals since 12:00 a.m UTC January 1, 1601.  They
	 * should correspond to the times gotten by calling GetFileTime() on
	 * Windows. */
	u64 i_creation_time;
	u64 i_last_access_time;
	u64 i_last_write_time;

	/* Corresponds to 'security_id' in `struct wim_dentry_on_disk':  The
	 * index of this inode's security descriptor in the WIM image's table of
	 * security descriptors, or -1.  Note: in verify_inode(), called
	 * whenever a WIM image is loaded, out-of-bounds indices are set to -1,
	 * so the extraction code does not need to do bounds checks.  */
	int32_t i_security_id;

	/* Identity of a reparse point.  See
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa365503(v=vs.85).aspx
	 * for what a reparse point is. */
	u32 i_reparse_tag;

	/* Unused/unknown fields that we just read into memory so we can
	 * re-write them unchanged.  */
	u32 i_rp_unknown_1;
	u16 i_rp_unknown_2;

	/* Corresponds to not_rpfixed in `struct wim_dentry_on_disk':  Set to 0
	 * if reparse point fixups have been done.  Otherwise set to 1.  Note:
	 * this actually may reflect the SYMBOLIC_LINK_RELATIVE flag.
	 */
	u16 i_not_rpfixed;

	/* Inode number; corresponds to hard_link_group_id in the `struct
	 * wim_dentry_on_disk'.  */
	u64 i_ino;

	union {
		/* Device number, used only during image capture, so we can
		 * identify hard linked files by the combination of inode number
		 * and device number (rather than just inode number, which could
		 * be ambigious if the captured tree spans a mountpoint).  Set
		 * to 0 otherwise.  */
		u64 i_devno;

		struct {

			/* Used only during image extraction: pointer to the first path
			 * (malloc()ed buffer) at which this inode has been extracted.
			 * Freed and set to NULL after the extraction is done (either
			 * success or failure).  */
			tchar *i_extracted_file;

			/** Used only during image extraction: "cookie" that
			 * identifies this extracted file (inode), for example
			 * an inode number.  Only used if supported by the
			 * extraction mode.  */
			u64 extract_cookie;
		};

#ifdef WITH_FUSE
		/* Used only during image mount:  Table of file descriptors that
		 * have been opened to this inode.  The table is automatically
		 * freed when the last file descriptor is closed.  */
		struct wimfs_fd **i_fds;
#endif
	};

#ifdef WITH_FUSE
	u16 i_num_opened_fds;
	u16 i_num_allocated_fds;
#endif

	/* Next alternate data stream ID to be assigned */
	u32 i_next_stream_id;
};

#define inode_for_each_dentry(dentry, inode) \
		list_for_each_entry((dentry), &(inode)->i_dentry, d_alias)

#define inode_add_dentry(dentry, inode) \
		list_add_tail(&(dentry)->d_alias, &(inode)->i_dentry)

#define inode_first_dentry(inode) \
		container_of(inode->i_dentry.next, struct wim_dentry, d_alias)

#define inode_first_full_path(inode) \
		dentry_full_path(inode_first_dentry(inode))

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
set_dentry_name(struct wim_dentry *dentry, const tchar *new_name);


/* Note: the NTFS-3g headers define CASE_SENSITIVE, hence the WIMLIB prefix.  */
typedef enum {
	/* Use either case-sensitive or case-insensitive search, depending on
	 * the variable @default_ignore_case.  */
	WIMLIB_CASE_PLATFORM_DEFAULT = 0,

	/* Use case-sensitive search.  */
	WIMLIB_CASE_SENSITIVE = 1,

	/* Use case-insensitive search.  */
	WIMLIB_CASE_INSENSITIVE = 2,
} CASE_SENSITIVITY_TYPE;

extern bool default_ignore_case;

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

extern void
dentry_tree_clear_inode_visited(struct wim_dentry *root);

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

extern int
rename_wim_path(WIMStruct *wim, const tchar *from, const tchar *to,
		CASE_SENSITIVITY_TYPE case_type);

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

bool
inode_has_named_stream(const struct wim_inode *inode);

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

static inline bool
ads_entry_is_unix_data(const struct wim_ads_entry *entry)
{
	return (entry->stream_name_nbytes ==
			WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES) &&
		!memcmp(entry->stream_name, WIMLIB_UNIX_DATA_TAG_UTF16LE,
			WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES);
}

static inline bool
ads_entry_is_named_stream(const struct wim_ads_entry *entry)
{
	return entry->stream_name_nbytes != 0 && !ads_entry_is_unix_data(entry);
}

#ifndef __WIN32__
/* Format for special alternate data stream entries to store UNIX data for files
 * and directories (see: WIMLIB_ADD_FLAG_UNIX_DATA) */
struct wimlib_unix_data {
	u16 version; /* Must be 0 */
	u16 uid;
	u16 gid;
	u16 mode;
} _packed_attribute;

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
#endif /* !__WIN32__ */

extern bool
inode_has_unix_data(const struct wim_inode *inode);

extern int
read_dentry(const u8 * restrict metadata_resource,
	    u64 metadata_resource_len, u64 offset,
	    struct wim_dentry * restrict dentry);

extern int
read_dentry_tree(const u8 * restrict metadata_resource,
		 u64 metadata_resource_len,
		 struct wim_dentry * restrict dentry);

extern u8 *
write_dentry_tree(const struct wim_dentry * restrict tree,
		  u8 * restrict p);

static inline bool
dentry_is_root(const struct wim_dentry *dentry)
{
	return dentry->parent == dentry;
}

static inline bool
inode_is_directory(const struct wim_inode *inode)
{
	return (inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				       FILE_ATTRIBUTE_REPARSE_POINT))
			== FILE_ATTRIBUTE_DIRECTORY;
}

static inline bool
inode_is_encrypted_directory(const struct wim_inode *inode)
{
	return ((inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
					FILE_ATTRIBUTE_ENCRYPTED))
		== (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ENCRYPTED));
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
verify_inode(struct wim_inode *inode, const struct wim_security_data *sd);

#endif /* _WIMLIB_DENTRY_H */
