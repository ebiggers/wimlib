#ifndef _WIMLIB_LOOKUP_TABLE_H
#define _WIMLIB_LOOKUP_TABLE_H
#include "wimlib_internal.h"
#include "dentry.h"
#include "sha1.h"
#include <sys/types.h>

/* Size of each lookup table entry in the WIM file. */
#define WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE 50

#define LOOKUP_FLAG_ADS_OK		0x00000001
#define LOOKUP_FLAG_DIRECTORY_OK	0x00000002

/* Not yet used */
//#define LOOKUP_FLAG_FOLLOW_SYMLINKS	0x00000004


/* A lookup table that is used to translate the hash codes of dentries into the
 * offsets and sizes of uncompressed or compressed file resources.  It is
 * implemented as a hash table. */
struct lookup_table {
	struct hlist_head *array;
	u64 num_entries;
	u64 capacity;
};

struct wimlib_fd;

typedef struct _ntfs_attr ntfs_attr;
typedef struct _ntfs_volume ntfs_volume;
struct ntfs_location {
	ntfs_volume *vol;
	const char *path;
	const char *ads_name;
};

/* 
 * An entry in the lookup table in the WIM file. 
 *
 * It is used to find data streams for files in the WIM. 
 *
 * The lookup_table_entry for a given dentry in the WIM is found using the SHA1
 * message digest field. 
 */
struct lookup_table_entry {

	/* List of lookup table entries in this hash bucket */
	struct hlist_node hash_list;

	/* @resource_entry is read from the lookup table in the WIM
	 * file; it says where to find the file resource in the WIM
	 * file, and whether it is compressed or not. */
	struct resource_entry resource_entry;

	/* Currently ignored; set to 1 in new lookup table entries. */
	u16 part_number;

	/* If %true, this lookup table entry corresponds to a symbolic link
	 * reparse buffer.  @symlink_reparse_data_buf will give the target of
	 * the symbolic link. */
	enum {
		RESOURCE_NONEXISTENT = 0,
		RESOURCE_IN_WIM,
		RESOURCE_IN_FILE_ON_DISK,
		RESOURCE_IN_STAGING_FILE,
		RESOURCE_IN_ATTACHED_BUFFER,
		RESOURCE_IN_NTFS_VOLUME,
	} resource_location;

	/* Number of times this lookup table entry is referenced by dentries. */
	u32 refcnt;

	union {
		/* SHA1 hash of the file resource pointed to by this lookup
		 * table entry */
		u8  hash[SHA1_HASH_SIZE];

		/* First 4 or 8 bytes of the SHA1 hash, used for inserting the
		 * entry into the hash table.  Since the SHA1 hashes can be
		 * considered random, we don't really need the full 20 byte hash
		 * just to insert the entry in a hash table. */
		size_t hash_short;
	};

	/* If @file_on_disk != NULL, the file resource indicated by this lookup
	 * table entry is not in the WIM file, but rather a file on disk; this
	 * occurs for files that are added to the WIM.  In that case,
	 * file_on_disk is the name of the file in the outside filesystem.  
	 * It will not be compressed, and its size will be given by
	 * resource_entry.size and resource_entry.original_size. */
	union {
		WIMStruct *wim;
		char *file_on_disk;
		char *staging_file_name;
		u8 *attached_buffer;
		struct ntfs_location *ntfs_location;
	};
	union {
		struct lookup_table_entry *next_lte_in_swm;
		FILE *file_on_disk_fp;
		ntfs_attr *attr;
	};
#ifdef WITH_FUSE
	/* File descriptors table for this data stream */
	u16 num_opened_fds;
	u16 num_allocated_fds;
	struct wimlib_fd **fds;
#endif

	/* When a WIM file is written, out_refcnt starts at 0 and is incremented
	 * whenever the file resource pointed to by this lookup table entry
	 * needs to be written.  Naturally, the file resource only need to be
	 * written when out_refcnt is 0.  Incrementing it further is needed to
	 * find the correct reference count to write to the lookup table in the
	 * output file, which may be less than the regular refcnt if not all
	 * images in the WIM file are written. 
	 *
	 * output_resource_entry is the struct resource_entry for the position of the
	 * file resource when written to the output file. */
	u32 out_refcnt;
	union {
		struct resource_entry output_resource_entry;
		char *extracted_file;
	};

	/* Circular linked list of streams that share the same lookup table
	 * entry
	 * 
	 * This list of streams may include streams from different hard link
	 * sets that happen to be the same.  */
	struct list_head lte_group_list;

	/* List of lookup table entries that correspond to streams that have
	 * been extracted to the staging directory when modifying a read-write
	 * mounted WIM. */
	struct list_head staging_list;
};

static inline u64 wim_resource_size(const struct lookup_table_entry *lte)
{
	return lte->resource_entry.original_size;
}

static inline u64
wim_resource_compressed_size(const struct lookup_table_entry *lte)
{
	return lte->resource_entry.size;
}

/*
 * XXX Probably should store the compression type directly in the lookup table
 * entry
 */
static inline int
wim_resource_compression_type(const struct lookup_table_entry *lte)
{
	if (!(lte->resource_entry.flags & WIM_RESHDR_FLAG_COMPRESSED)
	    || lte->resource_location != RESOURCE_IN_WIM)
		return WIM_COMPRESSION_TYPE_NONE;
	return wimlib_get_compression_type(lte->wim);
}


extern struct lookup_table *new_lookup_table(size_t capacity);

extern void lookup_table_insert(struct lookup_table *table, 
				struct lookup_table_entry *lte);

/* Unlinks a lookup table entry from the table; does not free it. */
static inline void lookup_table_unlink(struct lookup_table *table, 
			 	       struct lookup_table_entry *lte)
{
	hlist_del(&lte->hash_list);
	table->num_entries--;
}


extern struct lookup_table_entry *
lookup_table_decrement_refcnt(struct lookup_table* table, const u8 hash[]);

extern struct lookup_table_entry *
lte_decrement_refcnt(struct lookup_table_entry *lte,
		     struct lookup_table *table);


extern struct lookup_table_entry *new_lookup_table_entry();

extern int for_lookup_table_entry(struct lookup_table *table, 
				  int (*visitor)(struct lookup_table_entry *, void *), 
				  void *arg);

extern struct lookup_table_entry *
__lookup_resource(const struct lookup_table *table, const u8 hash[]);

extern int lookup_resource(WIMStruct *w, const char *path,
			   int lookup_flags, struct dentry **dentry_ret,
			   struct lookup_table_entry **lte_ret,
			   unsigned *stream_idx_ret);

extern int zero_out_refcnts(struct lookup_table_entry *entry, void *ignore);

extern void print_lookup_table_entry(const struct lookup_table_entry *entry);

extern int read_lookup_table(WIMStruct *w);

extern void free_lookup_table(struct lookup_table *table);

extern int write_lookup_table_entry(struct lookup_table_entry *lte, void *__out);

extern void free_lookup_table_entry(struct lookup_table_entry *lte);

extern int dentry_resolve_ltes(struct dentry *dentry, void *__table);

/* Writes the lookup table to the output file. */
static inline int write_lookup_table(struct lookup_table *table, FILE *out)
{
	return for_lookup_table_entry(table, write_lookup_table_entry, out);
}

/* Unlinks and frees an entry from a lookup table. */
static inline void lookup_table_remove(struct lookup_table *table, 
				       struct lookup_table_entry *lte)
{
	lookup_table_unlink(table, lte);
	free_lookup_table_entry(lte);
}

static inline struct resource_entry* wim_metadata_resource_entry(WIMStruct *w)
{
	return &w->image_metadata[
			w->current_image - 1].metadata_lte->resource_entry;
}

static inline struct lookup_table_entry *
dentry_stream_lte_resolved(const struct dentry *dentry, unsigned stream_idx)
{
	wimlib_assert(dentry->resolved);
	wimlib_assert(stream_idx <= dentry->num_ads);
	if (stream_idx == 0)
		return dentry->lte;
	else
		return dentry->ads_entries[stream_idx - 1].lte;
}

static inline struct lookup_table_entry *
dentry_stream_lte_unresolved(const struct dentry *dentry, unsigned stream_idx,
			     const struct lookup_table *table)
{
	wimlib_assert(!dentry->resolved);
	wimlib_assert(stream_idx <= dentry->num_ads);
	if (!table)
		return NULL;
	if (stream_idx == 0)
		return __lookup_resource(table, dentry->hash);
	else
		return __lookup_resource(table,
					 dentry->ads_entries[
						stream_idx - 1].hash);
}
/* 
 * Returns the lookup table entry for stream @stream_idx of the dentry, where
 * stream_idx = 0 means the default un-named file stream, and stream_idx >= 1
 * corresponds to an alternate data stream.
 *
 * This works for both resolved and un-resolved dentries.
 */
static inline struct lookup_table_entry *
dentry_stream_lte(const struct dentry *dentry, unsigned stream_idx,
		  const struct lookup_table *table)
{
	if (dentry->resolved)
		return dentry_stream_lte_resolved(dentry, stream_idx);
	else
		return dentry_stream_lte_unresolved(dentry, stream_idx, table);
}


static inline const u8 *dentry_stream_hash_unresolved(const struct dentry *dentry,
						      unsigned stream_idx)
{
	wimlib_assert(!dentry->resolved);
	wimlib_assert(stream_idx <= dentry->num_ads);
	if (stream_idx == 0)
		return dentry->hash;
	else
		return dentry->ads_entries[stream_idx - 1].hash;
}

static inline const u8 *dentry_stream_hash_resolved(const struct dentry *dentry,
						    unsigned stream_idx)
{
	struct lookup_table_entry *lte;
	lte = dentry_stream_lte_resolved(dentry, stream_idx);
	if (lte)
		return lte->hash;
	else
		return NULL;
}

/* 
 * Returns the hash for stream @stream_idx of the dentry, where stream_idx = 0
 * means the default un-named file stream, and stream_idx >= 1 corresponds to an
 * alternate data stream.
 *
 * This works for both resolved and un-resolved dentries.
 */
static inline const u8 *dentry_stream_hash(const struct dentry *dentry,
					   unsigned stream_idx)
{
	if (dentry->resolved)
		return dentry_stream_hash_resolved(dentry, stream_idx);
	else
		return dentry_stream_hash_unresolved(dentry, stream_idx);
}

static inline struct lookup_table_entry *
dentry_first_lte_resolved(const struct dentry *dentry)
{
	struct lookup_table_entry *lte;
	wimlib_assert(dentry->resolved);

	for (unsigned i = 0; i <= dentry->num_ads; i++) {
		lte = dentry_stream_lte_resolved(dentry, i);
		if (lte)
			return lte;
	}
	return NULL;
}

static inline struct lookup_table_entry *
dentry_first_lte_unresolved(const struct dentry *dentry,
			    const struct lookup_table *table)
{
	struct lookup_table_entry *lte;
	wimlib_assert(!dentry->resolved);

	for (unsigned i = 0; i <= dentry->num_ads; i++) {
		lte = dentry_stream_lte_unresolved(dentry, i, table);
		if (lte)
			return lte;
	}
	return NULL;
}

extern struct lookup_table_entry *
dentry_first_lte(const struct dentry *dentry, const struct lookup_table *table);

#endif
