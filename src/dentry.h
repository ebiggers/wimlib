#ifndef _WIMLIB_DENTRY_H
#define _WIMLIB_DENTRY_H

#include "util.h"
#include "config.h"
#include "list.h"
#include "sha1.h"
#include <string.h>


struct stat;
struct lookup_table;
struct WIMStruct;

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

struct lookup_table_entry;

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

	/* Length of stream name (UTF-16) */
	u16 stream_name_len;

	/* Length of stream name (UTF-8) */
	u16 stream_name_utf8_len;

	/* Stream name (UTF-16) */
	char *stream_name;

	/* Stream name (UTF-8) */
	char *stream_name_utf8;

	/* Doubly linked list of streams that share the same lookup table entry */
	struct stream_list_head lte_group_list;
};

/* Returns the total length of a WIM alternate data stream entry on-disk,
 * including the stream name, the null terminator, AND the padding after the
 * entry to align the next one (or the next dentry) on an 8-byte boundary. */
static inline u64 ads_entry_total_length(const struct ads_entry *entry)
{
	u64 len = WIM_ADS_ENTRY_DISK_SIZE;
	if (entry->stream_name_len)
		len += entry->stream_name_len + 2;
	return (len + 7) & ~7;
}

static inline void destroy_ads_entry(struct ads_entry *entry)
{
	FREE(entry->stream_name);
	FREE(entry->stream_name_utf8);
	memset(entry, 0, sizeof(entry));
}

static inline bool ads_entry_has_name(const struct ads_entry *entry,
				      const char *name, size_t name_len)
{
	if (entry->stream_name_utf8_len != name_len)
		return false;
	return memcmp(entry->stream_name_utf8, name, name_len) == 0;
}

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
 * Please note that this is a directory entry and not an inode.  Since NTFS
 * allows hard links, it's possible for a NTFS inode to correspond to multiple
 * WIM dentries.  The @hard_link field tells you the number of the NTFS inode
 * that the dentry corresponds to.
 *
 * Unfortunately, WIM files do not have an analogue to an inode; instead certain
 * information, such as file attributes, the security descriptor, and file
 * streams is replicated in each hard-linked dentry, even though this
 * information really is associated with an inode.
 *
 * Confusingly, it's also possible for stream information to be missing from a
 * dentry in a hard link set, in which case the stream information needs to be
 * gotten from one of the other dentries in the hard link set.  In addition, it
 * is possible for dentries to have inconsistent security IDs, file attributes,
 * or file streams when they share the same hard link ID (don't even ask.  I
 * hope that Microsoft may have fixed this problem, since I've only noticed it
 * in the 'install.wim' for Windows 7).  For those dentries, we have to use the
 * conflicting fields to split up the hard link groups.
 */
struct dentry {
	/* The parent of this directory entry. */
	struct dentry *parent;

	/* Linked list of sibling directory entries. */
	struct dentry *next;
	struct dentry *prev;

	/* Pointer to a child of this directory entry. */
	struct dentry *children;

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

	/* The file attributes associated with this file.  This is a bitwise OR
	 * of the FILE_ATTRIBUTE_* flags. */
	u32 attributes;

	/* The index of the security descriptor in the WIM image's table of
	 * security descriptors that contains this file's security information.
	 * If -1, no security information exists for this file.  */
	int32_t security_id;

	/* The offset, from the start of the uncompressed WIM metadata resource
	 * for this image, of this dentry's child dentries.  0 if the directory
	 * entry has no children, which is the case for regular files or reparse
	 * points. */
	u64 subdir_offset;

	/* Timestamps for the dentry.  The timestamps are the number of
	 * 100-nanosecond intervals that have elapsed since 12:00 A.M., January
	 * 1st, 1601, UTC.  This is the same format used in NTFS inodes. */
	u64 creation_time;
	u64 last_access_time;
	u64 last_write_time;

	/* %true iff the dentry's lookup table entry has been resolved (i.e. the
	 * @lte field is valid, but the @hash field is not valid) 
	 *
	 * (This is not an on-disk field.) */
	bool resolved;

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

	/* Although M$'s documentation does not tell you this, it seems that the
	 * reparse_reserved field does not actually exist.  So the hard_link
	 * field directly follows the reparse_tag on disk.  EXCEPT when the
	 * dentry is actually a reparse point... well, just take a look at the
	 * read_dentry() function. */
	//u32 reparse_reserved;

	/* If the file is part of a hard link set, all the directory entries in
	 * the set will share the same value for this field. 
	 *
	 * Unfortunately, in some WIMs it is NOT the case that all dentries that
	 * share this field are actually in the same hard link set, although the
	 * WIMs that wimlib writes maintain this restriction. */
	u64 link_group_id;

	/* Number of alternate data streams associated with this file. */
	u16 num_ads;

	/* Length of short filename, in bytes, not including the terminating
	 * zero wide-character. */
	u16 short_name_len;

	/* Length of file name, in bytes, not including the terminating zero
	 * wide-character. */
	u16 file_name_len;

	/* Length of the filename converted into UTF-8, in bytes, not including
	 * the terminating zero byte. */
	u16 file_name_utf8_len;

	/* Pointer to the short filename (malloc()ed buffer) */
	char *short_name;

	/* Pointer to the filename (malloc()ed buffer). */
	char *file_name;

	/* Pointer to the filename converted to UTF-8 (malloc()ed buffer). */
	char *file_name_utf8;

	/* Full path to this dentry (malloc()ed buffer). */
	char *full_path_utf8;
	u32   full_path_utf8_len;

	/* Alternate stream entries for this dentry (malloc()ed buffer). */
	struct ads_entry *ads_entries;

	union {
		/* Number of references to the dentry tree itself, as in multiple
		 * WIMStructs */
		u32 refcnt;

		/* Number of times this dentry has been opened (only for
		 * directories!) */
		u32 num_times_opened;
	};

	enum {
		/* This dentry is the owner of its ads_entries, although it may
		 * be in a hard link set */
		ADS_ENTRIES_DEFAULT = 0,

		/* This dentry is the owner of the ads_entries in the hard link
		 * set */
		ADS_ENTRIES_OWNER,

		/* This dentry shares its ads_entries with a dentry in the hard
		 * link set that has ADS_ENTRIES_OWNER set. */
		ADS_ENTRIES_USER
	} ads_entries_status;


	/* List of dentries in the hard link set */
	struct list_head link_group_list;

	union {
	/* List of dentries sharing the same lookup table entry */
		struct stream_list_head lte_group_list;
		struct list_head tmp_list;
	};

	/* Path to extracted file on disk (used during extraction only)
	 * (malloc()ed buffer, or set the same as full_path_utf8) */
	char *extracted_file;
};


extern struct ads_entry *dentry_get_ads_entry(struct dentry *dentry,
					      const char *stream_name);

extern struct ads_entry *dentry_add_ads(struct dentry *dentry,
					const char *stream_name);

extern void dentry_remove_ads(struct dentry *dentry, struct ads_entry *entry);

extern const char *path_stream_name(const char *path);

extern u64 dentry_total_length(const struct dentry *dentry);
extern u64 dentry_correct_total_length(const struct dentry *dentry);

extern void stbuf_to_dentry(const struct stat *stbuf, struct dentry *dentry);

extern int for_dentry_in_tree(struct dentry *root, 
			      int (*visitor)(struct dentry*, void*), 
			      void *args);

extern int for_dentry_in_tree_depth(struct dentry *root, 
				    int (*visitor)(struct dentry*, void*), 
				    void *args);

extern int calculate_dentry_full_path(struct dentry *dentry, void *ignore);
extern void calculate_subdir_offsets(struct dentry *dentry, u64 *subdir_offset_p);
extern int get_names(char **name_utf16_ret, char **name_utf8_ret,
	      	     u16 *name_utf16_len_ret, u16 *name_utf8_len_ret,
	             const char *name);
extern int change_dentry_name(struct dentry *dentry, const char *new_name);
extern int change_ads_name(struct ads_entry *entry, const char *new_name);

extern void unlink_dentry(struct dentry *dentry);
extern void link_dentry(struct dentry *dentry, struct dentry *parent);

extern int print_dentry(struct dentry *dentry, void *lookup_table);
extern int print_dentry_full_path(struct dentry *entry, void *ignore);

extern struct dentry *get_dentry(struct WIMStruct *w, const char *path);
extern struct dentry *get_parent_dentry(struct WIMStruct *w, const char *path);
extern struct dentry *get_dentry_child_with_name(const struct dentry *dentry, 
							const char *name);
extern void dentry_update_all_timestamps(struct dentry *dentry);
extern void init_dentry(struct dentry *dentry, const char *name);
extern struct dentry *new_dentry(const char *name);

extern void dentry_free_ads_entries(struct dentry *dentry);
extern void free_dentry(struct dentry *dentry);
extern void put_dentry(struct dentry *dentry);
extern struct dentry *clone_dentry(struct dentry *old);
extern void free_dentry_tree(struct dentry *root,
			     struct lookup_table *lookup_table);
extern int increment_dentry_refcnt(struct dentry *dentry, void *ignore);
extern int decrement_dentry_refcnt(struct dentry *dentry, void *ignore);

extern void calculate_dir_tree_statistics(struct dentry *root, 
					  struct lookup_table *table, 
					  u64 *dir_count_ret, 
					  u64 *file_count_ret, 
					  u64 *total_bytes_ret, 
					  u64 *hard_link_bytes_ret);

extern int read_dentry(const u8 metadata_resource[], u64 metadata_resource_len, 
		       u64 offset, struct dentry *dentry);

extern int verify_dentry(struct dentry *dentry, void *wim);

extern int read_dentry_tree(const u8 metadata_resource[], 
			    u64 metadata_resource_len, struct dentry *dentry);

extern u8 *write_dentry_tree(const struct dentry *tree, u8 *p);


/* Return the number of dentries in the hard link group */
static inline size_t dentry_link_group_size(const struct dentry *dentry)
{
	const struct list_head *cur = &dentry->link_group_list;
	size_t size = 0;
	wimlib_assert(cur != NULL);
	do {
		size++;
		cur = cur->next;
	} while (cur != &dentry->link_group_list);
	return size;
}

static inline bool dentry_is_root(const struct dentry *dentry)
{
	return dentry->parent == dentry;
}

static inline bool dentry_is_first_sibling(const struct dentry *dentry)
{
	return dentry_is_root(dentry) || dentry->parent->children == dentry;
}

static inline bool dentry_is_only_child(const struct dentry *dentry)
{
	return dentry->next == dentry;
}

static inline bool dentry_is_directory(const struct dentry *dentry)
{
	return (dentry->attributes & FILE_ATTRIBUTE_DIRECTORY)
		&& !(dentry->attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}

/* For our purposes, we consider "real" symlinks and "junction points" to both
 * be symlinks. */
static inline bool dentry_is_symlink(const struct dentry *dentry)
{
	return (dentry->attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		&& ((dentry->reparse_tag == WIM_IO_REPARSE_TAG_SYMLINK) ||
		     dentry->reparse_tag == WIM_IO_REPARSE_TAG_MOUNT_POINT);
}

static inline bool dentry_is_regular_file(const struct dentry *dentry)
{
	return !dentry_is_directory(dentry) && !dentry_is_symlink(dentry);
}

static inline bool dentry_is_empty_directory(const struct dentry *dentry)
{
	return dentry_is_directory(dentry) && dentry->children == NULL;
}

#endif
