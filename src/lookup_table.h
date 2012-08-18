#ifndef _WIMLIB_LOOKUP_TABLE_H
#define _WIMLIB_LOOKUP_TABLE_H
#include "wimlib_internal.h"
#include "dentry.h"
#include <sys/types.h>

/* Size of each lookup table entry in the WIM file. */
#define WIM_LOOKUP_TABLE_ENTRY_DISK_SIZE 50

#define LOOKUP_FLAG_ADS_OK		0x00000001
#define LOOKUP_FLAG_DIRECTORY_OK	0x00000002
#define LOOKUP_FLAG_FOLLOW_SYMLINKS	0x00000004


/* A lookup table that is used to translate the hash codes of dentries into the
 * offsets and sizes of uncompressed or compressed file resources.  It is
 * implemented as a hash table. */
struct lookup_table {
	struct lookup_table_entry **array;
	u64 num_entries;
	u64 capacity;
};

/* An entry in the lookup table in the WIM file. */
struct lookup_table_entry {

	/* The next struct lookup_table_entry in the hash bucket.  NULL if this is the
	 * last one. */
	struct lookup_table_entry *next;

	/* @resource_entry is read from the lookup table in the WIM
	 * file; it says where to find the file resource in the WIM
	 * file, and whether it is compressed or not. */
	struct resource_entry resource_entry;

	/* Currently ignored; set to 1 in new lookup table entries. */
	u16 part_number;

	/* Number of times this lookup table entry is referenced by dentries. */
	u32 refcnt;

	/* If %true, this lookup table entry corresponds to a symbolic link
	 * reparse buffer.  @symlink_reparse_data_buf will give the target of
	 * the symbolic link. */
	bool is_symlink;

	union {
		/* SHA1 hash of the file resource pointed to by this lookup
		 * table entry */
		u8  hash[WIM_HASH_SIZE];

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
		char *file_on_disk;
		char *staging_file_name;
		void *symlink_buf;
		struct lookup_table_entry *next_lte_in_swm;
	};

	union {
		struct { /* Used for wimlib_export. */

			/* If (other_wim_fp != NULL), the file resource indicated
			 * by this lookup table entry is in a different WIM
			 * file, and other_wim_fp is the FILE* for it. */
			FILE *other_wim_fp;

			/* Compression type used in other WIM. */
			int   other_wim_ctype;
		};

		struct { /* Used for read-write mounts. */


			/* Offset of the stream file_on_disk_fd. */
			off_t staging_offset;


			/* If file_on_disk_fd, if it is not -1, is the file
			 * descriptor, opened for reading, for file_on_disk. */
			int staging_fd;

			/* Number of times the file has been opened.
			 * file_on_disk_fd can be closed when num_times_opened
			 * is decremented to 0.  */
			int staging_num_times_opened;
		};
	};

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
	union {
		u32 out_refcnt;
		bool refcnt_is_incremented;
	};
	struct resource_entry output_resource_entry;
	struct dentry *hard_link_sets;
};

extern struct lookup_table *new_lookup_table(size_t capacity);

extern void lookup_table_insert(struct lookup_table *table, 
				struct lookup_table_entry *lte);

extern void lookup_table_unlink(struct lookup_table *table, 
				struct lookup_table_entry *lte);

extern bool lookup_table_decrement_refcnt(struct lookup_table* table, 
					  const u8 hash[]);


extern struct lookup_table_entry *new_lookup_table_entry();

extern int for_lookup_table_entry(struct lookup_table *table, 
				  int (*visitor)(struct lookup_table_entry *, void *), 
				  void *arg);

extern struct lookup_table_entry *
__lookup_resource(const struct lookup_table *lookup_table, const u8 hash[]);

extern int lookup_resource(WIMStruct *w, const char *path,
			   int lookup_flags, struct dentry **dentry_ret,
			   struct lookup_table_entry **lte_ret,
			   u8 **hash_ret);

extern int zero_out_refcnts(struct lookup_table_entry *entry, void *ignore);

extern int print_lookup_table_entry(struct lookup_table_entry *entry, void *ignore);

extern int read_lookup_table(FILE *fp, u64 offset, u64 size, 
			     struct lookup_table **table_ret);

extern void free_lookup_table(struct lookup_table *table);

extern int write_lookup_table_entry(struct lookup_table_entry *lte, void *__out);

static inline void free_lookup_table_entry(struct lookup_table_entry *lte)
{
	if (lte) {
		FREE(lte->file_on_disk);
		FREE(lte);
	}
}

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

#endif
