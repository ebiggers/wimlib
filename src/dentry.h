#ifndef _WIMLIB_DENTRY_H
#define _WIMLIB_DENTRY_H

#include "util.h"
#include "config.h"
#include "list.h"
#include "sha1.h"
#include "rbtree.h"
#include <string.h>

#ifdef WITH_FUSE
#include <pthread.h>
#endif

struct stat;
struct lookup_table;
struct WIMStruct;
struct lookup_table_entry;
struct wimlib_fd;
struct inode;
struct dentry;

/* Size of the struct dentry up to and including the file_name_len. */
#define WIM_DENTRY_DISK_SIZE    102

/* Size of on-disk WIM alternate data stream entry, in bytes, up to and
 * including the stream length field (see below). */
#define WIM_ADS_ENTRY_DISK_SIZE 38

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
struct ads_entry {
	union {
		/* SHA-1 message digest of stream contents */
		u8 hash[SHA1_HASH_SIZE];

		/* The corresponding lookup table entry (only for resolved
		 * streams) */
		struct lookup_table_entry *lte;
	};

	/* Length of stream name (UTF-16).  This is in bytes, not characters,
	 * and does not include the terminating null character   */
	u16 stream_name_len;

	/* Length of stream name (UTF-8) */
	u16 stream_name_utf8_len;

	/* Stream name (UTF-16) */
	char *stream_name;

	/* Stream name (UTF-8) */
	char *stream_name_utf8;

#ifdef WITH_FUSE
	/* Number to identify an alternate data stream even after it's possibly
	 * been moved or renamed. */
	u32 stream_id;
#endif
};


static inline bool ads_entries_have_same_name(const struct ads_entry *entry_1,
					      const struct ads_entry *entry_2)
{
	if (entry_1->stream_name_len != entry_2->stream_name_len)
		return false;
	return memcmp(entry_1->stream_name, entry_2->stream_name,
		      entry_1->stream_name_len) == 0;
}

/*
 * In-memory structure for a WIM directory entry (dentry).  There is a directory
 * tree for each image in the WIM.
 *
 * Note that this is a directory entry and not an inode.  Since NTFS allows hard
 * links, it's possible for a NTFS inode to correspond to multiple WIM dentries.
 * The hard_link field on the on-disk WIM dentry tells us the number of the NTFS
 * inode that the dentry corresponds to.
 *
 * Unfortunately, WIM files do not have an analogue to an inode; instead certain
 * information, such as file attributes, the security descriptor, and file
 * streams is replicated in each hard-linked dentry, even though this
 * information really is associated with an inode.  In-memory, we fix up this
 * flaw by allocating a `struct inode' for each dentry that contains some of
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
 * conflicting fields to split up the hard link groups.  (See fix_inodes() in
 * hardlink.c).
 */
struct dentry {
	/* Byte 0 */

	/* The inode for this dentry */
	struct inode *d_inode;

	/* Byte 8 */

	/* Red-black tree of sibling dentries */
	struct rb_node rb_node;

	/* Byte 32 */

	/* Length of short filename, in bytes, not including the terminating
	 * zero wide-character. */
	u16 short_name_len;

	/* Length of file name, in bytes, not including the terminating zero
	 * wide-character. */
	u16 file_name_len;

	/* Length of the filename converted into UTF-8, in bytes, not including
	 * the terminating zero byte. */
	u16 file_name_utf8_len;

	u8 is_extracted : 1;

	/* Byte 40 */

	/* Pointer to the filename converted to UTF-8 (malloc()ed buffer). */
	char *file_name_utf8;

	/* Byte 48 */

	struct list_head tmp_list;

	/* Byte 64 */

	/* List of dentries in the inode (hard link set)  */
	struct list_head inode_dentry_list;

	/* The parent of this directory entry. */
	struct dentry *parent;

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

	/* Number of references to the dentry tree itself, as in multiple
	 * WIMStructs */
	u32 refcnt;

	u32   full_path_utf8_len;

	/* Pointer to the UTF-16 short filename (malloc()ed buffer) */
	char *short_name;

	/* Pointer to the UTF-16 filename (malloc()ed buffer). */
	char *file_name;

	/* Full path (UTF-8) to this dentry (malloc()ed buffer). */
	char *full_path_utf8;
};

#define rbnode_dentry(node) container_of(node, struct dentry, rb_node)

/*
 * WIM inode.
 *
 * As mentioned above, in the WIM file that is no on-disk analogue of a real
 * inode, as most of these fields are duplicated in the dentries.
 */
struct inode {
	/* Timestamps for the inode.  The timestamps are the number of
	 * 100-nanosecond intervals that have elapsed since 12:00 A.M., January
	 * 1st, 1601, UTC.  This is the same format used in NTFS inodes. */
	u64 creation_time;
	u64 last_access_time;
	u64 last_write_time;

	/* The file attributes associated with this inode.  This is a bitwise OR
	 * of the FILE_ATTRIBUTE_* flags. */
	u32 attributes;

	/* The index of the security descriptor in the WIM image's table of
	 * security descriptors that contains this file's security information.
	 * If -1, no security information exists for this file.  */
	int32_t security_id;

	/* %true iff the inode's lookup table entries has been resolved (i.e.
	 * the @lte field is valid, but the @hash field is not valid)
	 *
	 * (This is not an on-disk field.) */
	u8 resolved : 1;

	/* %true iff verify_inode() has run on this dentry. */
	u8 verified : 1;

	/* Number of alternate data streams associated with this inode */
	u16 num_ads;

	/* A hash of the file's contents, or a pointer to the lookup table entry
	 * for this dentry if the lookup table entries have been resolved.
	 *
	 * More specifically, this is for the un-named default file stream, as
	 * opposed to the alternate (named) file streams, which may have their
	 * own lookup table entries.  */
	union {
		u8 hash[SHA1_HASH_SIZE];
		struct lookup_table_entry *lte;
	};

	/* Identity of a reparse point.  See
	 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa365503(v=vs.85).aspx
	 * for what a reparse point is. */
	u32 reparse_tag;

	/* Number of dentries that reference this inode */
	u32 link_count;

	/* Alternate data stream entries. */
	struct ads_entry *ads_entries;

	/* Inode number */
	u64 ino;

	/* List of dentries that reference this inode (there should be
	 * link_count of them) */
	struct list_head dentry_list;
	struct hlist_node hlist;
	char *extracted_file;

	/* Root of a red-black tree storing the children of this inode (if
	 * non-empty, implies the inode is a directory, although that is also
	 * noted in the @attributes field.) */
	struct rb_root children;

#ifdef WITH_FUSE
	/* wimfs file descriptors table for the inode */
	u16 num_opened_fds;
	u16 num_allocated_fds;
	struct wimlib_fd **fds;

	/* Next alternate data stream ID to be assigned */
	u32 next_stream_id;

	/* This mutex protects the inode's file descriptors table during
	 * read-only mounts.  Read-write mounts are still restricted to 1
	 * thread. */
	pthread_mutex_t i_mutex;
#endif
};

#define inode_for_each_dentry(dentry, inode) \
		list_for_each_entry((dentry), &(inode)->dentry_list, inode_dentry_list)

#define inode_add_dentry(dentry, inode) \
	({								\
	 	wimlib_assert((inode)->dentry_list.next != NULL);		\
		list_add(&(dentry)->inode_dentry_list, &(inode)->dentry_list);	\
	})

static inline bool dentry_is_extracted(const struct dentry *dentry)
{
	return dentry->is_extracted;
}

static inline bool dentry_is_first_in_inode(const struct dentry *dentry)
{
	return container_of(dentry->d_inode->dentry_list.next,
			    struct dentry,
			    inode_dentry_list) == dentry;
}

extern u64 dentry_correct_total_length(const struct dentry *dentry);

extern int inode_to_stbuf(const struct inode *inode,
			  struct lookup_table_entry *lte, struct stat *stbuf);

extern int for_dentry_in_tree(struct dentry *root,
			      int (*visitor)(struct dentry*, void*),
			      void *args);

extern int for_dentry_in_rbtree(struct rb_node *node,
				int (*visitor)(struct dentry *, void *),
				void *arg);

extern int for_dentry_in_tree_depth(struct dentry *root,
				    int (*visitor)(struct dentry*, void*),
				    void *args);

extern int calculate_dentry_full_path(struct dentry *dentry, void *ignore);
extern void calculate_subdir_offsets(struct dentry *dentry, u64 *subdir_offset_p);
extern int get_names(char **name_utf16_ret, char **name_utf8_ret,
	      	     u16 *name_utf16_len_ret, u16 *name_utf8_len_ret,
	             const char *name);

extern struct dentry *get_dentry(struct WIMStruct *w, const char *path);
extern struct inode *wim_pathname_to_inode(struct WIMStruct *w,
					   const char *path);
extern struct dentry *get_dentry_child_with_name(const struct dentry *dentry,
						 const char *name);
extern struct dentry *get_parent_dentry(struct WIMStruct *w, const char *path);

extern int print_dentry(struct dentry *dentry, void *lookup_table);
extern int print_dentry_full_path(struct dentry *entry, void *ignore);

extern struct dentry *new_dentry(const char *name);
extern struct dentry *new_dentry_with_inode(const char *name);
extern struct dentry *new_dentry_with_timeless_inode(const char *name);

extern void free_inode(struct inode *inode);
extern void free_dentry(struct dentry *dentry);
extern void put_dentry(struct dentry *dentry);

extern void free_dentry_tree(struct dentry *root,
			     struct lookup_table *lookup_table);
extern int increment_dentry_refcnt(struct dentry *dentry, void *ignore);

extern void unlink_dentry(struct dentry *dentry);
extern bool dentry_add_child(struct dentry * restrict parent,
			     struct dentry * restrict child);

extern int verify_dentry(struct dentry *dentry, void *wim);


extern struct ads_entry *inode_get_ads_entry(struct inode *inode,
					     const char *stream_name,
					     u16 *idx_ret);
extern struct ads_entry *inode_add_ads(struct inode *dentry,
				       const char *stream_name);

extern void inode_remove_ads(struct inode *inode, u16 idx,
			     struct lookup_table *lookup_table);

extern int read_dentry(const u8 metadata_resource[], u64 metadata_resource_len,
		       u64 offset, struct dentry *dentry);


extern int read_dentry_tree(const u8 metadata_resource[],
			    u64 metadata_resource_len, struct dentry *dentry);

extern u8 *write_dentry_tree(const struct dentry *tree, u8 *p);

static inline bool dentry_is_root(const struct dentry *dentry)
{
	return dentry->parent == dentry;
}

static inline bool inode_is_directory(const struct inode *inode)
{
	return (inode->attributes & FILE_ATTRIBUTE_DIRECTORY)
		&& !(inode->attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

static inline bool dentry_is_directory(const struct dentry *dentry)
{
	return inode_is_directory(dentry->d_inode);
}

/* For our purposes, we consider "real" symlinks and "junction points" to both
 * be symlinks. */
static inline bool inode_is_symlink(const struct inode *inode)
{
	return (inode->attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		&& ((inode->reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK) ||
		     inode->reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT);
}

static inline bool dentry_is_symlink(const struct dentry *dentry)
{
	return inode_is_symlink(dentry->d_inode);
}

static inline bool inode_is_regular_file(const struct inode *inode)
{
	return !inode_is_directory(inode) && !inode_is_symlink(inode);
}

static inline bool dentry_is_regular_file(const struct dentry *dentry)
{
	return inode_is_regular_file(dentry->d_inode);
}

static inline bool inode_has_children(const struct inode *inode)
{
	return inode->children.rb_node != NULL;
}

static inline bool dentry_is_empty_directory(const struct dentry *dentry)
{
	const struct inode *inode = dentry->d_inode;
	return inode_is_directory(inode) && !inode_has_children(inode);
}

#endif
