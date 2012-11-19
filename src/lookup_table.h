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

#ifdef WITH_NTFS_3G
struct ntfs_location {
	char *path_utf8;
	char *stream_name_utf16;
	u16 stream_name_utf16_num_chars;
	struct _ntfs_volume **ntfs_vol_p;
	bool is_reparse_point;
};
#endif

/* An enumerated type that identifies where the stream corresponding to this
 * lookup table entry is actually located.
 *
 * If we open a WIM and read its lookup table, the location is set to
 * RESOURCE_IN_WIM since all the streams will initially be located in the WIM.
 * However, to deal with problems such as image capture and image mount, we
 * allow the actual location of the stream to be somewhere else, such as an
 * external file.
 */
enum resource_location {
	/* The lookup table entry does not correspond to a stream (this state
	 * should exist only temporarily) */
	RESOURCE_NONEXISTENT = 0,

	/* The stream resource is located in a WIM file.  The WIMStruct for the
	 * WIM file will be pointed to by the @wim member. */
	RESOURCE_IN_WIM,

	/* The stream resource is located in an external file.  The name of the
	 * file will be provided by @file_on_disk member.  In addition, if
	 * @file_on_disk_fp is not NULL, it will be an open FILE * to the file.
	 * */
	RESOURCE_IN_FILE_ON_DISK,

	/* The stream resource is located in an external file in the staging
	 * directory for a read-write mount.  */
	RESOURCE_IN_STAGING_FILE,

	/* The stream resource is directly attached in an in-memory buffer
	 * pointed to by @attached_buffer. */
	RESOURCE_IN_ATTACHED_BUFFER,

	/* The stream resource is located in an NTFS volume.  It is identified
	 * by volume, filename, data stream name, and by whether it is a reparse
	 * point or not. @ntfs_loc points to a structure containing this
	 * information. */
	RESOURCE_IN_NTFS_VOLUME,
};

/*
 * An entry in the lookup table in the WIM file.
 *
 * It is used to find data streams for files in the WIM.
 *
 * Metadata resources and reparse point data buffers will also have lookup table
 * entries associated with the data.
 *
 * The lookup_table_entry for a given dentry or alternate stream entry in the
 * WIM is found using the SHA1 message digest field.
 */
struct lookup_table_entry {

	/* List of lookup table entries in this hash bucket */
	struct hlist_node hash_list;

	/* Location and size of the stream in the WIM, whether it is compressed
	 * or not, and whether it's a metadata resource or not.  This is an
	 * on-disk field. */
	struct resource_entry resource_entry;

	/* Specifies which part of the split WIM the resource is located in.
	 * This is on on-disk field.
	 *
	 * In stand-alone WIMs, this must be 1.
	 *
	 * In split WIMs, every split WIM part has its own lookup table, and in
	 * read_lookup_table() it's currently expected that the part number of
	 * each lookup table entry in a split WIM part's lookup table is the
	 * same as the part number of that split WIM part.  So this makes this
	 * field redundant since we store a pointer to the corresponding
	 * WIMStruct in the lookup table entry anyway.
	 */
	u16 part_number;

	/* See enum resource_location above */
	u16 resource_location;

	/* (On-disk field)
	 * Number of times this lookup table entry is referenced by dentries.
	 * Unfortunately, this field is not always set correctly in Microsoft's
	 * WIMs, so we have no choice but to fix it if more references to the
	 * lookup table entry are found than stated here. */
	u32 refcnt;

	union {
		/* (On-disk field) SHA1 message digest of the stream referenced
		 * by this lookup table entry */
		u8  hash[SHA1_HASH_SIZE];

		/* First 4 or 8 bytes of the SHA1 message digest, used for
		 * inserting the entry into the hash table.  Since the SHA1
		 * message digest can be considered random, we don't really need
		 * the full 20 byte hash just to insert the entry in a hash
		 * table. */
		size_t hash_short;
	};

	#ifdef WITH_FUSE
	u16 num_opened_fds;
	#endif

	/* Pointers to somewhere where the stream is actually located.  See the
	 * comments for the @resource_location field above. */
	union {
		WIMStruct *wim;
		char *file_on_disk;
		char *staging_file_name;
		u8 *attached_buffer;
	#ifdef WITH_NTFS_3G
		struct ntfs_location *ntfs_loc;
	#endif
	};
	union {
		/* @file_on_disk_fp and @attr are both used to cache file/stream
		 * handles so we don't have re-open them on every read */

		/* Valid iff resource_location == RESOURCE_IN_FILE_ON_DISK */
		FILE *file_on_disk_fp;
	#ifdef WITH_NTFS_3G
		/* Valid iff resource_location == RESOURCE_IN_NTFS_VOLUME */
		struct _ntfs_attr *attr;
	#endif

		/* Pointer to inode that contains the opened file descriptors to
		 * this stream (valid iff resource_location ==
		 * RESOURCE_IN_STAGING_FILE) */
		struct inode *lte_inode;
	};

	/* When a WIM file is written, out_refcnt starts at 0 and is incremented
	 * whenever the file resource pointed to by this lookup table entry
	 * needs to be written.  The file resource only need to be written when
	 * out_refcnt is nonzero, since otherwise it is not referenced by any
	 * dentries. */
	u32 out_refcnt;

	u32 real_refcnt;

	union {
		/* When a WIM file is written, @output_resource_entry is filled
		 * in with the resource entry for the output WIM.  This will not
		 * necessarily be the same as the @resource_entry since: - The
		 * stream may have a different offset in the new WIM - The
		 * stream may have a different compressed size in the new WIM if
		 * the compression type changed
		 */
		struct resource_entry output_resource_entry;

		struct list_head msg_list;
	};

	union {
		/* This field is used for the special hardlink or symlink image
		 * extraction mode.   In these mode, all identical files are linked
		 * together, and @extracted_file will be set to the filename of the
		 * first extracted file containing this stream.  */
		char *extracted_file;

		/* List of lookup table entries that correspond to streams that have
		 * been extracted to the staging directory when modifying a read-write
		 * mounted WIM. */
		struct list_head staging_list;
	};
};

static inline u64 wim_resource_size(const struct lookup_table_entry *lte)
{
	return lte->resource_entry.original_size;
}

static inline u64 wim_resource_chunks(const struct lookup_table_entry *lte)
{
	return (wim_resource_size(lte) + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;
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

extern struct lookup_table_entry *new_lookup_table_entry();

extern struct lookup_table_entry *
clone_lookup_table_entry(const struct lookup_table_entry *lte);

extern int for_lookup_table_entry(struct lookup_table *table,
				  int (*visitor)(struct lookup_table_entry *, void *),
				  void *arg);

extern struct lookup_table_entry *
__lookup_resource(const struct lookup_table *table, const u8 hash[]);

extern int lookup_resource(WIMStruct *w, const char *path,
			   int lookup_flags, struct dentry **dentry_ret,
			   struct lookup_table_entry **lte_ret,
			   u16 *stream_idx_ret);

extern void lte_decrement_refcnt(struct lookup_table_entry *lte,
			         struct lookup_table *table);
#ifdef WITH_FUSE
extern void lte_decrement_num_opened_fds(struct lookup_table_entry *lte);
#endif

extern int lte_zero_out_refcnt(struct lookup_table_entry *entry, void *ignore);
extern int lte_zero_real_refcnt(struct lookup_table_entry *entry, void *ignore);
extern int lte_zero_extracted_file(struct lookup_table_entry *lte, void *ignore);
extern int lte_free_extracted_file(struct lookup_table_entry *lte, void *ignore);

extern void print_lookup_table_entry(const struct lookup_table_entry *entry);

extern int read_lookup_table(WIMStruct *w);

extern void free_lookup_table(struct lookup_table *table);

extern int write_lookup_table_entry(struct lookup_table_entry *lte, void *__out);

extern void free_lookup_table_entry(struct lookup_table_entry *lte);

extern int dentry_resolve_ltes(struct dentry *dentry, void *__table);
extern int dentry_unresolve_ltes(struct dentry *dentry, void *ignore);

int write_lookup_table(struct lookup_table *table, FILE *out,
		       struct resource_entry *out_res_entry);

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
inode_stream_lte_resolved(const struct inode *inode, unsigned stream_idx)
{
	wimlib_assert(inode->resolved);
	wimlib_assert(stream_idx <= inode->num_ads);
	if (stream_idx == 0)
		return inode->lte;
	else
		return inode->ads_entries[stream_idx - 1].lte;
}

static inline struct lookup_table_entry *
inode_stream_lte_unresolved(const struct inode *inode, unsigned stream_idx,
			    const struct lookup_table *table)
{
	wimlib_assert(!inode->resolved);
	wimlib_assert(stream_idx <= inode->num_ads);
	if (!table)
		return NULL;
	if (stream_idx == 0)
		return __lookup_resource(table, inode->hash);
	else
		return __lookup_resource(table,
					 inode->ads_entries[
						stream_idx - 1].hash);
}
/*
 * Returns the lookup table entry for stream @stream_idx of the inode, where
 * stream_idx = 0 means the default un-named file stream, and stream_idx >= 1
 * corresponds to an alternate data stream.
 *
 * This works for both resolved and un-resolved dentries.
 */
static inline struct lookup_table_entry *
inode_stream_lte(const struct inode *inode, unsigned stream_idx,
		 const struct lookup_table *table)
{
	if (inode->resolved)
		return inode_stream_lte_resolved(inode, stream_idx);
	else
		return inode_stream_lte_unresolved(inode, stream_idx, table);
}


static inline const u8 *inode_stream_hash_unresolved(const struct inode *inode,
						     unsigned stream_idx)
{
	wimlib_assert(!inode->resolved);
	wimlib_assert(stream_idx <= inode->num_ads);
	if (stream_idx == 0)
		return inode->hash;
	else
		return inode->ads_entries[stream_idx - 1].hash;
}


static inline const u8 *inode_stream_hash_resolved(const struct inode *inode,
						   unsigned stream_idx)
{
	struct lookup_table_entry *lte;
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
static inline const u8 *inode_stream_hash(const struct inode *inode,
					  unsigned stream_idx)
{
	if (inode->resolved)
		return inode_stream_hash_resolved(inode, stream_idx);
	else
		return inode_stream_hash_unresolved(inode, stream_idx);
}

static inline u16 inode_stream_name_len(const struct inode *inode,
					unsigned stream_idx)
{
	wimlib_assert(stream_idx <= inode->num_ads);
	if (stream_idx == 0)
		return 0;
	else
		return inode->ads_entries[stream_idx - 1].stream_name_len;
}

static inline struct lookup_table_entry *
inode_unnamed_lte_resolved(const struct inode *inode)
{
	wimlib_assert(inode->resolved);
	for (unsigned i = 0; i <= inode->num_ads; i++)
		if (inode_stream_name_len(inode, i) == 0 &&
		     !is_zero_hash(inode_stream_hash_resolved(inode, i)))
			return inode_stream_lte_resolved(inode, i);
	return NULL;
}

static inline struct lookup_table_entry *
inode_unnamed_lte_unresolved(const struct inode *inode,
			     const struct lookup_table *table)
{
	wimlib_assert(!inode->resolved);
	for (unsigned i = 0; i <= inode->num_ads; i++)
		if (inode_stream_name_len(inode, i) == 0 &&
		     !is_zero_hash(inode_stream_hash_unresolved(inode, i)))
			return inode_stream_lte_unresolved(inode, i, table);
	return NULL;
}

extern struct lookup_table_entry *
inode_unnamed_lte(const struct inode *inode,
		  const struct lookup_table *table);


#endif
