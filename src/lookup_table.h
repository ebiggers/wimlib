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

#ifdef __WIN32__
#include <windef.h>
#endif


/* The lookup table of a WIM file maps SHA1 message digests to streams of data.
 * Here, the in-memory structure is implemented as a hash table.
 *
 * Given a SHA1 message digest, the mapped-to stream is specified by an offset
 * in the WIM, an uncompressed and compressed size, and resource flags (see
 * 'struct resource_entry').  But, we associate additional information, such as
 * a reference count, with each stream, so the actual mapping is from SHA1
 * message digests to 'struct wim_lookup_table_entry's, each of which contains
 * an embedded 'struct resource_entry'.
 *
 * Note: Everything will break horribly if there is a SHA1 collision.
 */
struct wim_lookup_table {
	struct hlist_head *array;
	u64 num_entries;
	u64 capacity;
	struct list_head *unhashed_streams;
};

#ifdef WITH_NTFS_3G
struct ntfs_location {
	tchar *path;
	utf16lechar *stream_name;
	u16 stream_name_nchars;
	struct _ntfs_volume *ntfs_vol;
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

#ifndef __WIN32__
	/* The stream resource is located in an external file.  The name of the
	 * file will be provided by @file_on_disk member. */
	RESOURCE_IN_FILE_ON_DISK,
#endif

	/* The stream resource is directly attached in an in-memory buffer
	 * pointed to by @attached_buffer. */
	RESOURCE_IN_ATTACHED_BUFFER,

#ifdef WITH_FUSE
	/* The stream resource is located in an external file in the staging
	 * directory for a read-write mount.  */
	RESOURCE_IN_STAGING_FILE,
#endif

#ifdef WITH_NTFS_3G
	/* The stream resource is located in an NTFS volume.  It is identified
	 * by volume, filename, data stream name, and by whether it is a reparse
	 * point or not. @ntfs_loc points to a structure containing this
	 * information. */
	RESOURCE_IN_NTFS_VOLUME,
#endif

#ifdef __WIN32__
	/* Resource must be accessed using Win32 API (may be a named data
	 * stream) */
	RESOURCE_WIN32,

	/* Windows only: the file is on disk in the file named @file_on_disk,
	 * but the file is encrypted and must be read using special functions.
	 * */
	RESOURCE_WIN32_ENCRYPTED,
#endif

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
struct wim_lookup_table_entry {

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

	/* One of the `enum resource_location' values documented above. */
	u16 resource_location : 5;

	/* 1 if this stream is a unique size (only set while writing streams). */
	u8 unique_size : 1;

	/* 1 if this stream has not had a SHA1 message digest calculated for it
	 * yet */
	u8 unhashed : 1;

	u8 deferred : 1;

	u8 no_progress : 1;

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

		/* Unhashed entries only (unhashed == 1): these variables make
		 * it possible to find the pointer to this 'struct
		 * wim_lookup_table_entry' contained in either 'struct
		 * wim_ads_entry' or 'struct wim_inode'.  There can be at most 1
		 * such pointer, as we can only join duplicate streams after
		 * they have been hashed.  */
		struct {
			struct wim_inode *back_inode;
			u32 back_stream_id;
		};
	};

	/* When a WIM file is written, out_refcnt starts at 0 and is incremented
	 * whenever the stream pointed to by this lookup table entry needs to be
	 * written.  The stream only need to be written when out_refcnt is
	 * nonzero, since otherwise it is not referenced by any dentries. */
	u32 out_refcnt;

	/* Pointers to somewhere where the stream is actually located.  See the
	 * comments for the @resource_location field above. */
	union {
		WIMStruct *wim;
		tchar *file_on_disk;
		void *attached_buffer;
	#ifdef WITH_FUSE
		tchar *staging_file_name;
	#endif
	#ifdef WITH_NTFS_3G
		struct ntfs_location *ntfs_loc;
	#endif
	};

	/* Actual reference count to this stream (only used while
	 * verifying an image). */
	u32 real_refcnt;

	union {
	#ifdef WITH_FUSE
		/* Number of times this stream has been opened (used only during
		 * mounting) */
		u16 num_opened_fds;
	#endif

		/* This field is used for the special hardlink or symlink image
		 * extraction mode.   In these mode, all identical files are linked
		 * together, and @extracted_file will be set to the filename of the
		 * first extracted file containing this stream.  */
		tchar *extracted_file;
	};

	union {
		/* When a WIM file is written, @output_resource_entry is filled
		 * in with the resource entry for the output WIM.  This will not
		 * necessarily be the same as the @resource_entry since:
		 * - The stream may have a different offset in the new WIM
		 * - The stream may have a different compressed size in the new
		 *   WIM if the compression type changed
		 */
		struct resource_entry output_resource_entry;

		struct {
			struct list_head msg_list;
			struct list_head being_compressed_list;
		};
		struct list_head inode_list;

		struct {
			struct hlist_node hash_list_2;

			struct list_head write_streams_list;
		};
	};

	/* Temporary list fields */
	union {
		struct list_head unhashed_list;
		struct list_head swm_stream_list;
		struct list_head lookup_table_list;
		struct list_head extraction_list;
		struct list_head export_stream_list;
	};
};

static inline u64
wim_resource_size(const struct wim_lookup_table_entry *lte)
{
	return lte->resource_entry.original_size;
}

static inline u64
wim_resource_chunks(const struct wim_lookup_table_entry *lte)
{
	return (wim_resource_size(lte) + WIM_CHUNK_SIZE - 1) / WIM_CHUNK_SIZE;
}

static inline u64
wim_resource_compressed_size(const struct wim_lookup_table_entry *lte)
{
	return lte->resource_entry.size;
}

/*
 * XXX Probably should store the compression type directly in the lookup table
 * entry
 */
static inline int
wim_resource_compression_type(const struct wim_lookup_table_entry *lte)
{
	if (!(lte->resource_entry.flags & WIM_RESHDR_FLAG_COMPRESSED)
	    || lte->resource_location != RESOURCE_IN_WIM)
		return WIMLIB_COMPRESSION_TYPE_NONE;
	return wimlib_get_compression_type(lte->wim);
}

static inline bool
lte_filename_valid(const struct wim_lookup_table_entry *lte)
{
	return 0
	#ifdef __WIN32__
		|| lte->resource_location == RESOURCE_WIN32
		|| lte->resource_location == RESOURCE_WIN32_ENCRYPTED
	#else
		|| lte->resource_location == RESOURCE_IN_FILE_ON_DISK
	#endif
	#ifdef WITH_FUSE
		|| lte->resource_location == RESOURCE_IN_STAGING_FILE
	#endif
		;
}

extern struct wim_lookup_table *
new_lookup_table(size_t capacity);

extern int
read_lookup_table(WIMStruct *w);

extern int
write_lookup_table(WIMStruct *w, int image, struct resource_entry *out_res_entry);

extern int
write_lookup_table_from_stream_list(struct list_head *stream_list,
				    filedes_t out_fd,
				    struct resource_entry *out_res_entry);

extern void
free_lookup_table(struct wim_lookup_table *table);

extern void
lookup_table_insert(struct wim_lookup_table *table, struct wim_lookup_table_entry *lte);

/* Unlinks a lookup table entry from the table; does not free it. */
static inline void
lookup_table_unlink(struct wim_lookup_table *table, struct wim_lookup_table_entry *lte)
{
	wimlib_assert(!lte->unhashed);
	hlist_del(&lte->hash_list);
	wimlib_assert(table->num_entries != 0);
	table->num_entries--;
}

extern struct wim_lookup_table_entry *
new_lookup_table_entry();

extern struct wim_lookup_table_entry *
clone_lookup_table_entry(const struct wim_lookup_table_entry *lte);

extern void
print_lookup_table_entry(const struct wim_lookup_table_entry *entry,
			 FILE *out);

extern void
free_lookup_table_entry(struct wim_lookup_table_entry *lte);

extern int
for_lookup_table_entry(struct wim_lookup_table *table,
		       int (*visitor)(struct wim_lookup_table_entry *, void *),
		       void *arg);

extern int
cmp_streams_by_wim_position(const void *p1, const void *p2);

extern int
for_lookup_table_entry_pos_sorted(struct wim_lookup_table *table,
				  int (*visitor)(struct wim_lookup_table_entry *,
						 void *),
				  void *arg);

extern struct wim_lookup_table_entry *
__lookup_resource(const struct wim_lookup_table *table, const u8 hash[]);

extern int
lookup_resource(WIMStruct *w, const tchar *path,
		int lookup_flags, struct wim_dentry **dentry_ret,
		struct wim_lookup_table_entry **lte_ret, u16 *stream_idx_ret);

extern void
lte_decrement_refcnt(struct wim_lookup_table_entry *lte,
		     struct wim_lookup_table *table);
#ifdef WITH_FUSE
extern void
lte_decrement_num_opened_fds(struct wim_lookup_table_entry *lte);
#endif

extern int
lte_zero_out_refcnt(struct wim_lookup_table_entry *entry, void *ignore);

extern int
lte_zero_real_refcnt(struct wim_lookup_table_entry *entry, void *ignore);

extern int
lte_free_extracted_file(struct wim_lookup_table_entry *lte, void *ignore);

extern void
inode_resolve_ltes(struct wim_inode *inode, struct wim_lookup_table *table);

extern void
inode_unresolve_ltes(struct wim_inode *inode);

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
	if (!table)
		return NULL;
	if (stream_idx == 0)
		return __lookup_resource(table, inode->i_hash);
	else
		return __lookup_resource(table,
					 inode->i_ads_entries[
						stream_idx - 1].hash);
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
inode_unnamed_lte_resolved(const struct wim_inode *inode);

extern struct wim_lookup_table_entry *
inode_unnamed_lte_unresolved(const struct wim_inode *inode,
			     const struct wim_lookup_table *table);

extern struct wim_lookup_table_entry *
inode_unnamed_lte(const struct wim_inode *inode, const struct wim_lookup_table *table);

extern u64
lookup_table_total_stream_size(struct wim_lookup_table *table);


static inline void
lookup_table_insert_unhashed(struct wim_lookup_table *table,
			     struct wim_lookup_table_entry *lte,
			     struct wim_inode *back_inode,
			     u32 back_stream_id)
{
	lte->unhashed = 1;
	lte->back_inode = back_inode;
	lte->back_stream_id = back_stream_id;
	list_add_tail(&lte->unhashed_list, table->unhashed_streams);
}

extern int
hash_unhashed_stream(struct wim_lookup_table_entry *lte,
		     struct wim_lookup_table *lookup_table,
		     struct wim_lookup_table_entry **lte_ret);

extern struct wim_lookup_table_entry **
retrieve_lte_pointer(struct wim_lookup_table_entry *lte);

#endif
