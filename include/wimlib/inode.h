#ifndef _WIMLIB_INODE_H
#define _WIMLIB_INODE_H

#include "wimlib/assert.h"
#include "wimlib/list.h"
#include "wimlib/lookup_table.h"
#include "wimlib/sha1.h"
#include "wimlib/unix_data.h"

#include <string.h>

struct wim_ads_entry;
struct wim_dentry;
struct wim_security_data;
struct wim_lookup_table;
struct wimfs_fd;
struct avl_tree_node;

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

	/* Root of a balanced binary search tree storing the child directory
	 * entries of this inode, if any.  Keyed by wim_dentry->file_name, case
	 * sensitively.  If this inode is not a directory or if it has no
	 * children then this will be an empty tree (NULL).  */
	struct avl_tree_node *i_children;

	/* Root of a balanced binary search tree storing the child directory
	 * entries of this inode, if any.  Keyed by wim_dentry->file_name, case
	 * insensitively.  If this inode is not a directory or if it has no
	 * children then this will be an empty tree (NULL).  */
	struct avl_tree_node *i_children_ci;

	/* List of dentries that are aliases for this inode.  There will be
	 * i_nlink dentries in this list.  */
	struct list_head i_dentry;

	/* Field to place this inode into a list. */
	union {
		/* Hash list node- used in inode_fixup.c when the inodes are
		 * placed into a hash table keyed by inode number and optionally
		 * device number, in order to detect dentries that are aliases
		 * for the same inode. */
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

extern struct wim_inode *
new_inode(void) _malloc_attribute;

extern struct wim_inode *
new_timeless_inode(void) _malloc_attribute;

extern void
put_inode(struct wim_inode *inode);

extern void
free_inode(struct wim_inode *inode);

/* Iterate through each alias of an inode.  */
#define inode_for_each_dentry(dentry, inode) \
		list_for_each_entry((dentry), &(inode)->i_dentry, d_alias)

/* Add a new alias for an inode.  Does not increment i_nlink; that must be done
 * separately.  */
#define inode_add_dentry(dentry, inode) \
		list_add_tail(&(dentry)->d_alias, &(inode)->i_dentry)

/* Return an alias of an inode.  */
#define inode_first_dentry(inode) \
		container_of(inode->i_dentry.next, struct wim_dentry, d_alias)

/* Return the full path of an alias of an inode, or NULL if it could not be
 * determined.  */
#define inode_first_full_path(inode) \
		dentry_full_path(inode_first_dentry(inode))

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

extern bool
inode_has_named_stream(const struct wim_inode *inode);

extern int
inode_set_unnamed_stream(struct wim_inode *inode, const void *data, size_t len,
			 struct wim_lookup_table *lookup_table);

extern void
inode_remove_ads(struct wim_inode *inode, u16 idx,
		 struct wim_lookup_table *lookup_table);

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

/* Is the inode a directory?
 * This doesn't count directories with reparse data.
 * wimlib only allows inodes of this type to have children.
 */
static inline bool
inode_is_directory(const struct wim_inode *inode)
{
	return (inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
				       FILE_ATTRIBUTE_REPARSE_POINT))
			== FILE_ATTRIBUTE_DIRECTORY;
}

/* Is the inode a directory with the encrypted attribute set?
 * This currently returns true for encrypted directories even if they have
 * reparse data (not sure if such files can even exist).  */
static inline bool
inode_is_encrypted_directory(const struct wim_inode *inode)
{
	return ((inode->i_attributes & (FILE_ATTRIBUTE_DIRECTORY |
					FILE_ATTRIBUTE_ENCRYPTED))
		== (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_ENCRYPTED));
}

/* Is the inode a symbolic link?
 * This returns true iff the inode is a reparse point that is either a "real"
 * symbolic link or a junction point.  */
static inline bool
inode_is_symlink(const struct wim_inode *inode)
{
	return (inode->i_attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		&& (inode->i_reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK ||
		    inode->i_reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT);
}

/* Does the inode have children?
 * Currently (based on read_dentry_tree()), this can only return true for inodes
 * for which inode_is_directory() returns true.  (This also returns false on
 * empty directories.)  */
static inline bool
inode_has_children(const struct wim_inode *inode)
{
	return inode->i_children != NULL;
}

extern int
inode_resolve_streams(struct wim_inode *inode, struct wim_lookup_table *table,
		      bool force);

extern int
stream_not_found_error(const struct wim_inode *inode, const u8 *hash);

extern void
inode_unresolve_streams(struct wim_inode *inode);

static inline struct wim_lookup_table_entry *
inode_stream_lte_resolved(const struct wim_inode *inode, unsigned stream_idx)
{
	wimlib_assert(inode->i_resolved);
	wimlib_assert(stream_idx <= inode->i_num_ads);
	if (stream_idx == 0)
		return inode->i_lte;
	else
		return inode->i_ads_entries[stream_idx - 1].lte;
}

static inline struct wim_lookup_table_entry *
inode_stream_lte_unresolved(const struct wim_inode *inode, unsigned stream_idx,
			    const struct wim_lookup_table *table)
{
	wimlib_assert(!inode->i_resolved);
	wimlib_assert(stream_idx <= inode->i_num_ads);
	if (table == NULL)
		return NULL;
	if (stream_idx == 0)
		return lookup_stream(table, inode->i_hash);
	else
		return lookup_stream(table, inode->i_ads_entries[ stream_idx - 1].hash);
}

extern struct wim_lookup_table_entry *
inode_stream_lte(const struct wim_inode *inode, unsigned stream_idx,
		 const struct wim_lookup_table *table);

static inline const u8 *
inode_stream_hash_unresolved(const struct wim_inode *inode, unsigned stream_idx)
{
	wimlib_assert(!inode->i_resolved);
	wimlib_assert(stream_idx <= inode->i_num_ads);
	if (stream_idx == 0)
		return inode->i_hash;
	else
		return inode->i_ads_entries[stream_idx - 1].hash;
}


static inline const u8 *
inode_stream_hash_resolved(const struct wim_inode *inode, unsigned stream_idx)
{
	struct wim_lookup_table_entry *lte;
	lte = inode_stream_lte_resolved(inode, stream_idx);
	if (lte)
		return lte->hash;
	else
		return zero_hash;
}

/*
 * Returns the hash for stream @stream_idx of the inode, where stream_idx = 0
 * means the default un-named file stream, and stream_idx >= 1 corresponds to an
 * alternate data stream.
 *
 * This works for both resolved and un-resolved dentries.
 */
static inline const u8 *
inode_stream_hash(const struct wim_inode *inode, unsigned stream_idx)
{
	if (inode->i_resolved)
		return inode_stream_hash_resolved(inode, stream_idx);
	else
		return inode_stream_hash_unresolved(inode, stream_idx);
}

static inline u16
inode_stream_name_nbytes(const struct wim_inode *inode, unsigned stream_idx)
{
	wimlib_assert(stream_idx <= inode->i_num_ads);
	if (stream_idx == 0)
		return 0;
	else
		return inode->i_ads_entries[stream_idx - 1].stream_name_nbytes;
}

extern struct wim_lookup_table_entry *
inode_unnamed_stream_resolved(const struct wim_inode *inode, u16 *stream_idx_ret);

extern struct wim_lookup_table_entry *
inode_unnamed_lte_resolved(const struct wim_inode *inode);

extern struct wim_lookup_table_entry *
inode_unnamed_lte_unresolved(const struct wim_inode *inode,
			     const struct wim_lookup_table *table);

extern struct wim_lookup_table_entry *
inode_unnamed_lte(const struct wim_inode *inode, const struct wim_lookup_table *table);

extern const u8 *
inode_unnamed_stream_hash(const struct wim_inode *inode);

extern int
read_ads_entries(const u8 * restrict p, struct wim_inode * restrict inode,
		 size_t nbytes_remaining);

extern int
verify_inode(struct wim_inode *inode, const struct wim_security_data *sd);

extern void
inode_ref_streams(struct wim_inode *inode);

extern void
inode_unref_streams(struct wim_inode *inode,
		    struct wim_lookup_table *lookup_table);

/* inode_fixup.c  */
extern int
dentry_tree_fix_inodes(struct wim_dentry *root, struct list_head *inode_list);

#endif /* _WIMLIB_INODE_H  */
