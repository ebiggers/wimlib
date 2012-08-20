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
	struct hlist_head *array;
	u64 num_entries;
	u64 capacity;
};

struct wimlib_fd;


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
	bool is_symlink;

	/* Number of times this lookup table entry is referenced by dentries. */
	u32 refcnt;

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

		struct { /* Used for wimlib_mount */

			/* File descriptors table for this data stream */
			struct wimlib_fd **fds;
			u16 num_allocated_fds;
			u16 num_opened_fds;
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
	u32 out_refcnt;
	struct resource_entry output_resource_entry;

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

extern int print_lookup_table_entry(struct lookup_table_entry *entry, void *ignore);

extern int read_lookup_table(FILE *fp, u64 offset, u64 size, 
			     struct lookup_table **table_ret);

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

#endif
