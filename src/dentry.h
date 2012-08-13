#ifndef _WIMLIB_DENTRY_H
#define _WIMLIB_DENTRY_H

#include "util.h"
#include <string.h>

/* Size of the struct dentry up to and including the file_name_len. */
#define WIM_DENTRY_DISK_SIZE 102

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
#ifdef ENABLE_SECURITY_DATA
	int32_t security_id;
#endif

	/* The offset, from the start of the metadata section, of this directory
	 * entry's child files.  0 if the directory entry has no children. */
	u64 subdir_offset;

	/* Reserved for future disuse.  Currently ignoring these fields. */
	//u64 unused1;
	//u64 unused2;

	/* Timestamps for the entry.  The timestamps are the number of
	 * 100-nanosecond intervals that have elapsed since 12:00 A.M., January
	 * 1st, 1601, UTC. */
	u64 creation_time;
	u64 last_access_time;
	u64 last_write_time;

	/* A hash of the file's contents. */
	u8 hash[WIM_HASH_SIZE];

	/* Identity of a reparse point (whatever that is).  Currently ignoring
	 * this field*/
	//u32 reparse_tag;

	/* Although M$'s documentation does not tell you this, it seems that the
	 * reparse_reserved field does not actually exist.  So the hard_link
	 * field directly follows the reparse_tag on disk. */
	//u32 reparse_reserved;

	/* If the reparse_reserved field existed, there would be a 4-byte gap
	 * here to align hard_link on an 8-byte field.  However,
	 * reparse_reserved does not actually exist, so there is no gap here. */

	/* If the file is part of a hard link set, all the directory entries in
	 * the set will share the same value for this field. */
	u64 hard_link;

	/* Number of WIMStreamEntry structures that follow this struct dentry.
	 * Currently ignoring this field. */
	//u16 streams;

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

	/* Stream entries for this dentry. Currently being ignored. */
	//struct WIMStreamEntry *stream_entries;

	/* Number of references to the dentry tree itself, as in multiple
	 * WIMStructs */
	int refcnt;
};

#define WIM_FILE_ATTRIBUTE_READONLY            0x1
#define WIM_FILE_ATTRIBUTE_HIDDEN              0x2
#define WIM_FILE_ATTRIBUTE_SYSTEM              0x4
#define WIM_FILE_ATTRIBUTE_DIRECTORY           0x10
#define WIM_FILE_ATTRIBUTE_ARCHIVE             0x20
#define WIM_FILE_ATTRIBUTE_DEVICE              0x40
#define WIM_FILE_ATTRIBUTE_NORMAL              0x80
#define WIM_FILE_ATTRIBUTE_TEMPORARY           0x100
#define WIM_FILE_ATTRIBUTE_SPARSE_FILE         0x200
#define WIM_FILE_ATTRIBUTE_REPARSE_POINT       0x400
#define WIM_FILE_ATTRIBUTE_COMPRESSED          0x800
#define WIM_FILE_ATTRIBUTE_OFFLINE             0x1000
#define WIM_FILE_ATTRIBUTE_NOT_CONTENT_INDEXED 0x2000
#define WIM_FILE_ATTRIBUTE_ENCRYPTED           0x4000
#define WIM_FILE_ATTRIBUTE_VIRTUAL             0x10000

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

/* Inline utility functions for WIMDentries */

/*
 * Returns true if @dentry has the UTF-8 file name @name that has length
 * @name_len.
 */
static inline bool dentry_has_name(const struct dentry *dentry, const char *name, 
				   size_t name_len)
{
	if (dentry->file_name_utf8_len != name_len)
		return false;
	return memcmp(dentry->file_name_utf8, name, name_len) == 0;
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
	return (dentry->attributes & WIM_FILE_ATTRIBUTE_DIRECTORY) != 0;
}

static inline bool dentry_is_regular_file(const struct dentry *dentry)
{
	return !dentry_is_directory(dentry);
}

static inline bool dentry_is_empty_directory(const struct dentry *dentry)
{
	return dentry_is_directory(dentry) && dentry->children == NULL;
}

#endif
