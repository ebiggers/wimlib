#ifndef _WIMLIB_DENTRY_H
#define _WIMLIB_DENTRY_H

#include "util.h"
#include "config.h"
#include <string.h>

struct stat;
struct lookup_table;
typedef struct WIMStruct WIMStruct;

/* Size of the struct dentry up to and including the file_name_len. */
#define WIM_DENTRY_DISK_SIZE    102

#define WIM_ADS_ENTRY_DISK_SIZE 38

#ifndef WIM_HASH_SIZE
#define WIM_HASH_SIZE 20
#endif

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

/* Alternate data stream entry */
struct ads_entry {
	/* SHA-1 message digest of stream contents */
	u8 hash[WIM_HASH_SIZE];

	/* Length of stream name (UTF-16) */
	u16 stream_name_len;

	/* Length of stream name (UTF-8) */
	u16 stream_name_utf8_len;

	/* Stream name (UTF-16) */
	char *stream_name;

	/* Stream name (UTF-8) */
	char *stream_name_utf8;
};

static inline u64 ads_entry_length(const struct ads_entry *entry)
{
	u64 len = WIM_ADS_ENTRY_DISK_SIZE + entry->stream_name_len + 2;
	return (len + 7) & ~7;
}

static inline void destroy_ads_entry(struct ads_entry *entry)
{
	FREE(entry->stream_name);
	FREE(entry->stream_name_utf8);
	memset(entry, 0, sizeof(entry));
}


/* In-memory structure for a directory entry.  There is a directory tree for
 * each image in the WIM.  */
struct dentry {
	/* The parent of this directory entry. */
	struct dentry *parent;

	/* Linked list of sibling directory entries. */
	struct dentry *next;

	struct dentry *prev;

	/* Pointer to a child of this directory entry. */
	struct dentry *children;

	/* Size of directory entry, in bytes.  Typical size is around 104 to 120
	 * bytes. */
	/* It is possible for the length field to be 0.  This situation, which
	 * is undocumented, indicates the end of a list of sibling nodes in a
	 * directory.  It also means the real length is 8, because the dentry
	 * included only the length field, but that takes up 8 bytes. */
	u64 length;


	/* The file attributes associated with this file. */
	u32 attributes;

	/* The index of the node in the security table that contains this file's
	 * security information.  If -1, no security information exists for this
	 * file.  */
	int32_t security_id;

	/* The offset, from the start of the metadata section, of this directory
	 * entry's child files.  0 if the directory entry has no children. */
	u64 subdir_offset;

	/* Reserved for future disuse.  Currently ignoring these fields. */
	u64 unused1;
	u64 unused2;

	/* Timestamps for the entry.  The timestamps are the number of
	 * 100-nanosecond intervals that have elapsed since 12:00 A.M., January
	 * 1st, 1601, UTC. */
	u64 creation_time;
	u64 last_access_time;
	u64 last_write_time;

	/* A hash of the file's contents. */
	u8 hash[WIM_HASH_SIZE];

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

	/* If the reparse_reserved field existed, there would be a 4-byte gap
	 * here to align hard_link on an 8-byte field.  However,
	 * reparse_reserved does not actually exist, so there is no gap here. */

	/* If the file is part of a hard link set, all the directory entries in
	 * the set will share the same value for this field. */
	u64 hard_link;

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

	/* Pointer to the short filename */
	char *short_name;

	/* Pointer to the filename. */
	char *file_name;

	/* Pointer to the filename converted to UTF-8. */
	char *file_name_utf8;

	/* Full path to this dentry. */
	char *full_path_utf8;
	u32   full_path_utf8_len;

	/* Alternate stream entries for this dentry. */
	struct ads_entry *ads_entries;

	/* Number of references to the dentry tree itself, as in multiple
	 * WIMStructs */
	int refcnt;

	/* Next dentry in the hard link set */
	//struct dentry *next_dentry_in_link_set;
	/* Next hard link that has a lookup table entry */
	//struct dentry *next_link_set;
};

/* Return hash of the "unnamed" (default) data stream. */
static inline const u8 *dentry_hash(const struct dentry *dentry)
{
	/* If there are alternate data streams, the dentry hash field is zeroed
	 * out, and we need to find the hash in the un-named data stream (should
	 * be the first one, but check them in order just in case, and fall back
	 * to the dentry hash field if we can't find an unnamed data stream). */
	for (u16 i = 0; i < dentry->num_ads; i++)
		if (dentry->ads_entries[i].stream_name_len == 0)
			return dentry->ads_entries[i].hash;
	return dentry->hash;
}


extern struct ads_entry *dentry_get_ads_entry(struct dentry *dentry,
					      const char *stream_name);

extern struct ads_entry *dentry_add_ads(struct dentry *dentry,
					const char *stream_name);

extern void dentry_remove_ads(struct dentry *dentry, struct ads_entry *entry);

extern const char *path_stream_name(const char *path);

extern u64 dentry_total_length(const struct dentry *dentry);

extern void stbuf_to_dentry(const struct stat *stbuf, struct dentry *dentry);

extern void dentry_to_stbuf(const struct dentry *dentry, struct stat *stbuf, 
			    const struct lookup_table *table);

extern int for_dentry_in_tree(struct dentry *root, 
			      int (*visitor)(struct dentry*, void*), 
			      void *args);

extern int for_dentry_in_tree_depth(struct dentry *root, 
				    int (*visitor)(struct dentry*, void*), 
				    void *args);

extern int calculate_dentry_full_path(struct dentry *dentry, void *ignore);
extern void calculate_subdir_offsets(struct dentry *dentry, u64 *subdir_offset_p);
extern int change_dentry_name(struct dentry *dentry, const char *new_name);
extern int change_ads_name(struct ads_entry *entry, const char *new_name);

extern void unlink_dentry(struct dentry *dentry);
extern void link_dentry(struct dentry *dentry, struct dentry *parent);

extern int print_dentry(struct dentry *dentry, void *lookup_table);
extern int print_dentry_full_path(struct dentry *entry, void *ignore);

extern struct dentry *get_dentry(WIMStruct *w, const char *path);
extern struct dentry *get_parent_dentry(WIMStruct *w, const char *path);
extern struct dentry *get_dentry_child_with_name(const struct dentry *dentry, 
							const char *name);
extern void dentry_update_all_timestamps(struct dentry *dentry);
extern void init_dentry(struct dentry *dentry, const char *name);
extern struct dentry *new_dentry(const char *name);

extern void free_dentry(struct dentry *dentry);
extern void free_dentry_tree(struct dentry *root,
			     struct lookup_table *lookup_table, 
			     bool lt_decrement_refcnt);
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

extern int read_dentry_tree(const u8 metadata_resource[], 
			    u64 metadata_resource_len, struct dentry *dentry);

extern u8 *write_dentry_tree(const struct dentry *tree, u8 *p);

extern int dentry_set_symlink_buf(struct dentry *dentry,
				  const u8 symlink_buf_hash[]);

/* Inline utility functions for WIMDentries */


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
