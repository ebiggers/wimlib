#ifndef _WIMLIB_LOOKUP_TABLE_H
#define _WIMLIB_LOOKUP_TABLE_H

#include "wimlib/list.h"
#include "wimlib/resource.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

/* An enumerated type that identifies where the stream corresponding to this
 * lookup table entry is actually located.
 *
 * If we open a WIM and read its lookup table, the location is set to
 * RESOURCE_IN_WIM since all the streams will initially be located in the WIM.
 * However, to handle situations such as image capture and image mount, we allow
 * the actual location of the stream to be somewhere else, such as an external
 * file.  */
enum resource_location {
	/* The lookup table entry does not yet correspond to a stream; this is a
	 * temporary state only.  */
	RESOURCE_NONEXISTENT = 0,

	/* The stream is located in a resource in a WIM file identified by the
	 * `struct wim_resource_spec' pointed to by @rspec.  @offset_in_res
	 * identifies the offset at which this particular stream begins in the
	 * uncompressed data of the resource; this is normally 0, but in general
	 * a WIM resource may be "packed" and potentially contain multiple
	 * streams.  */
	RESOURCE_IN_WIM,

	/* The stream is located in the external file named by @file_on_disk.
	 */
	RESOURCE_IN_FILE_ON_DISK,

	/* The stream is directly attached in the in-memory buffer pointed to by
	 * @attached_buffer.  */
	RESOURCE_IN_ATTACHED_BUFFER,

#ifdef WITH_FUSE
	/* The stream is located in the external file named by
	 * @staging_file_name, located in the staging directory for a read-write
	 * mount.  */
	RESOURCE_IN_STAGING_FILE,
#endif

#ifdef WITH_NTFS_3G
	/* The stream is located in an NTFS volume.  It is identified by volume,
	 * filename, data stream name, and by whether it is a reparse point or
	 * not.  @ntfs_loc points to a structure containing this information.
	 * */
	RESOURCE_IN_NTFS_VOLUME,
#endif

#ifdef __WIN32__
	/* Windows only: the stream is located in the external file named by
	 * @file_on_disk, which is in the Windows NT namespace and may specify a
	 * named data stream.  */
	RESOURCE_IN_WINNT_FILE_ON_DISK,

	/* Windows only: the stream is located in the external file named by
	 * @file_on_disk, but the file is encrypted and must be read using the
	 * appropriate Windows API.  */
	RESOURCE_WIN32_ENCRYPTED,
#endif
};

struct stream_owner {
	struct wim_inode *inode;
	const utf16lechar *stream_name;
};

/* Specification for a stream, which may be the contents of a file (unnamed data
 * stream), a named data stream, reparse point data, or a WIM metadata resource.
 *
 * One instance of this structure is created for each entry in the WIM's lookup
 * table, hence the name of the struct.  Each of these entries contains the SHA1
 * message digest of a stream and the location of the stream data in the WIM
 * file (size, location, flags).  The in-memory lookup table is a map from SHA1
 * message digests to stream locations.  */
struct wim_lookup_table_entry {

	/* List node for a hash bucket of the lookup table.  */
	struct hlist_node hash_list;

	/* Uncompressed size of this stream.  */
	u64 size;

	/* Stream flags (WIM_RESHDR_FLAG_*).  */
	u32 flags : 8;

	/* One of the `enum resource_location' values documented above.  */
	u32 resource_location : 4;

	/* 1 if this stream has not had a SHA1 message digest calculated for it
	 * yet.  */
	u32 unhashed : 1;

	/* Temoorary fields used when writing streams; set as documented for
	 * prepare_stream_list_for_write().  */
	u32 unique_size : 1;
	u32 will_be_in_output_wim : 1;

	/* Set to 1 when a metadata entry has its checksum changed; in such
	 * cases the hash cannot be used to verify the data if the metadata
	 * resource is read again.  (This could be avoided if we used separate
	 * fields for input/output checksum, but most stream entries wouldn't
	 * need this.)  */
	u32 dont_check_metadata_hash : 1;

	u32 may_send_done_with_file : 1;

	union {
		/* (On-disk field) SHA1 message digest of the stream referenced
		 * by this lookup table entry.  */
		u8  hash[SHA1_HASH_SIZE];

		/* First 4 or 8 bytes of the SHA1 message digest, used for
		 * inserting the entry into the hash table.  Since the SHA1
		 * message digest can be considered random, we don't really need
		 * the full 20 byte hash just to insert the entry in a hash
		 * table.  */
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

	/* Number of times this lookup table entry is referenced by dentries in
	 * the WIM.  When a WIM's lookup table is read, this field is
	 * initialized from a corresponding entry.
	 *
	 * However, see lte_decrement_refcnt() for information about the
	 * limitations of this field.  */
	u32 refcnt;

	/* When a WIM file is written, this is set to the number of references
	 * (by dentries) to this stream in the output WIM file.
	 *
	 * During extraction, this is the number of slots in stream_owners (or
	 * inline_stream_owners) that have been filled.
	 *
	 * During image export, this is set to the number of references of this
	 * stream that originated from the source WIM.
	 *
	 * When mounting a WIM image read-write, this is set to the number of
	 * extra references to this stream preemptively taken to allow later
	 * saving the modified image as a new image and leaving the original
	 * image alone.  */
	u32 out_refcnt;

#ifdef WITH_FUSE
	/* Number of open file descriptors to this stream during a FUSE mount of
	 * the containing image.  */
	u16 num_opened_fds;
#endif

	/* Specification of where this stream is actually located.  Which member
	 * is valid is determined by the @resource_location field.  */
	union {
		struct {
			struct wim_resource_spec *rspec;
			u64 offset_in_res;
		};
		struct {
			tchar *file_on_disk;
			struct wim_inode *file_inode;
		};
		void *attached_buffer;
	#ifdef WITH_FUSE
		struct {
			char *staging_file_name;
			int staging_dir_fd;
		};
	#endif
	#ifdef WITH_NTFS_3G
		struct ntfs_location *ntfs_loc;
	#endif
	};

	/* Links together streams that share the same underlying WIM resource.
	 * The head is the `stream_list' member of `struct wim_resource_spec'.
	 */
	struct list_head rspec_node;

	/* Temporary fields  */
	union {
		/* Fields used temporarily during WIM file writing.  */
		struct {
			union {
				/* List node used for stream size table.  */
				struct hlist_node hash_list_2;

				/* Metadata for the underlying packed resource
				 * in the WIM being written (only valid if
				 * WIM_RESHDR_FLAG_PACKED_STREAMS set in
				 * out_reshdr.flags).  */
				struct {
					u64 out_res_offset_in_wim;
					u64 out_res_size_in_wim;
					u64 out_res_uncompressed_size;
				};
			};

			/* Links streams being written to the WIM.  */
			struct list_head write_streams_list;

			/* Metadata for this stream in the WIM being written.
			 */
			struct wim_reshdr out_reshdr;
		};

		/* Used temporarily during extraction.  This is an array of
		 * pointers to the inodes being extracted that use this stream.
		 */
		union {
			/* Inodes to extract that reference this stream.
			 * out_refcnt tracks the number of slots filled.  */
			struct stream_owner inline_stream_owners[3];
			struct {
				struct stream_owner *stream_owners;
				u32 alloc_stream_owners;
			};
		};
	};

	/* Temporary list fields.  */
	union {
		/* Links streams for writing lookup table.  */
		struct list_head lookup_table_list;

		/* Links streams being extracted.  */
		struct list_head extraction_list;

		/* Links streams being exported.  */
		struct list_head export_stream_list;

		/* Links original list of streams in the read-write mounted image.  */
		struct list_head orig_stream_list;
	};

	/* Links streams that are still unhashed after being been added to a
	 * WIM.  */
	struct list_head unhashed_list;
};

/* Functions to allocate and free lookup tables  */

extern struct wim_lookup_table *
new_lookup_table(size_t capacity) _malloc_attribute;

extern void
free_lookup_table(struct wim_lookup_table *table);

/* Functions to read or write the lookup table from/to a WIM file  */

extern int
read_wim_lookup_table(WIMStruct *wim);

extern int
write_wim_lookup_table_from_stream_list(struct list_head *stream_list,
					struct filedes *out_fd,
					u16 part_number,
					struct wim_reshdr *out_reshdr,
					int write_resource_flags);

/* Functions to create, clone, print, and free lookup table entries  */

extern struct wim_lookup_table_entry *
new_lookup_table_entry(void) _malloc_attribute;

extern struct wim_lookup_table_entry *
clone_lookup_table_entry(const struct wim_lookup_table_entry *lte)
			_malloc_attribute;

extern void
lte_decrement_refcnt(struct wim_lookup_table_entry *lte,
		     struct wim_lookup_table *table);
#ifdef WITH_FUSE
extern void
lte_decrement_num_opened_fds(struct wim_lookup_table_entry *lte);
#endif

extern void
free_lookup_table_entry(struct wim_lookup_table_entry *lte);

/* Functions to insert and delete entries from a lookup table  */

extern void
lookup_table_insert(struct wim_lookup_table *table,
		struct wim_lookup_table_entry *lte);

extern void
lookup_table_unlink(struct wim_lookup_table *table,
		    struct wim_lookup_table_entry *lte);

/* Function to lookup a stream by SHA1 message digest  */
extern struct wim_lookup_table_entry *
lookup_stream(const struct wim_lookup_table *table, const u8 hash[]);

/* Functions to iterate through the entries of a lookup table  */

extern int
for_lookup_table_entry(struct wim_lookup_table *table,
		       int (*visitor)(struct wim_lookup_table_entry *, void *),
		       void *arg);

extern int
for_lookup_table_entry_pos_sorted(struct wim_lookup_table *table,
				  int (*visitor)(struct wim_lookup_table_entry *,
						 void *),
				  void *arg);



/* Function to get a resource entry in stable format  */

struct wimlib_resource_entry;

extern void
lte_to_wimlib_resource_entry(const struct wim_lookup_table_entry *lte,
			     struct wimlib_resource_entry *wentry);

/* Functions to sort a list of lookup table entries  */
extern int
sort_stream_list(struct list_head *stream_list,
		 size_t list_head_offset,
		 int (*compar)(const void *, const void*));

extern int
sort_stream_list_by_sequential_order(struct list_head *stream_list,
				     size_t list_head_offset);

/* Utility functions  */

extern int
lte_zero_out_refcnt(struct wim_lookup_table_entry *lte, void *ignore);

static inline bool
lte_is_partial(const struct wim_lookup_table_entry * lte)
{
	return lte->resource_location == RESOURCE_IN_WIM &&
	       lte->size != lte->rspec->uncompressed_size;
}

static inline const struct stream_owner *
stream_owners(struct wim_lookup_table_entry *stream)
{
	if (stream->out_refcnt <= ARRAY_LEN(stream->inline_stream_owners))
		return stream->inline_stream_owners;
	else
		return stream->stream_owners;
}

static inline void
lte_bind_wim_resource_spec(struct wim_lookup_table_entry *lte,
			   struct wim_resource_spec *rspec)
{
	lte->resource_location = RESOURCE_IN_WIM;
	lte->rspec = rspec;
	list_add_tail(&lte->rspec_node, &rspec->stream_list);
}

static inline void
lte_unbind_wim_resource_spec(struct wim_lookup_table_entry *lte)
{
	list_del(&lte->rspec_node);
	lte->resource_location = RESOURCE_NONEXISTENT;
}

extern void
lte_put_resource(struct wim_lookup_table_entry *lte);

extern struct wim_lookup_table_entry *
new_stream_from_data_buffer(const void *buffer, size_t size,
			    struct wim_lookup_table *lookup_table);

static inline void
add_unhashed_stream(struct wim_lookup_table_entry *lte,
		    struct wim_inode *back_inode,
		    u32 back_stream_id,
		    struct list_head *unhashed_streams)
{
	lte->unhashed = 1;
	lte->back_inode = back_inode;
	lte->back_stream_id = back_stream_id;
	list_add_tail(&lte->unhashed_list, unhashed_streams);
}

extern int
hash_unhashed_stream(struct wim_lookup_table_entry *lte,
		     struct wim_lookup_table *lookup_table,
		     struct wim_lookup_table_entry **lte_ret);

extern struct wim_lookup_table_entry **
retrieve_lte_pointer(struct wim_lookup_table_entry *lte);

#endif /* _WIMLIB_LOOKUP_TABLE_H */
