/*
 * wimlib_internal.h
 *
 * Internal header for wimlib.
 */

/*
 * Copyright (C) 2010 Carl Thijssen
 * Copyright (C) 2012 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#ifndef _WIMLIB_INTERNAL_H
#define _WIMLIB_INTERNAL_H

#include "config.h"
#include "util.h"
#include "list.h"

#include "wimlib.h"

#ifdef WITH_FUSE
#include <pthread.h>
#endif

struct stat;
struct dentry;
struct inode;

#define WIM_MAGIC_LEN  8
#define WIM_GID_LEN    16
#define WIM_UNUSED_LEN 60


/* Length of the WIM header on disk. */
#define WIM_HEADER_DISK_SIZE (148 + WIM_UNUSED_LEN)

/* Compressed resources in the WIM are divided into separated compressed chunks
 * of this size. */
#define WIM_CHUNK_SIZE 32768

/* Version of the WIM file.  There is an older version, but we don't support it
 * yet.  The differences between the versions are undocumented. */
#define WIM_VERSION 0x10d00

#define WIM_INTEGRITY_OK 0
#define WIM_INTEGRITY_NOT_OK -1
#define WIM_INTEGRITY_NONEXISTENT -2

/* Metadata for a resource in a WIM file. */
struct resource_entry {
	/* Size, in bytes, of the resource in the WIM file. */
	u64 size  : 56;

	/* Bitwise or of one or more of the WIM_RESHDR_FLAG_* flags. */
	u64 flags : 8;

	/* Offset, in bytes, of the resource in the WIM file. */
	u64 offset;

	/* Uncompressed size of the resource in the WIM file.  Is the same as
	 * @size if the resource is uncompressed. */
	u64 original_size;
};

/* Flags for the `flags' field of the struct resource_entry structure. */

/* I haven't seen this flag used in any of the WIMs I have examined.  I assume
 * it means that there are no references to the stream, so the space is free.
 * However, even after deleting files from a WIM mounted with `imagex.exe
 * /mountrw', I could not see this flag being used.  Either way, we don't
 * actually use this flag for anything. */
#define WIM_RESHDR_FLAG_FREE            0x01

/* Indicates that the stream is a metadata resource for a WIM image. */
#define WIM_RESHDR_FLAG_METADATA        0x02

/* Indicates that the stream is compressed. */
#define WIM_RESHDR_FLAG_COMPRESSED	0x04

/* I haven't seen this flag used in any of the WIMs I have examined.  Perhaps it
 * means that a stream could possibly be split among multiple split WIM parts.
 * However, `imagex.exe /split' does not seem to create any WIMs like this.
 * Either way, we don't actually use this flag for anything.  */
#define WIM_RESHDR_FLAG_SPANNED         0x08


/* Header at the very beginning of the WIM file. */
struct wim_header {
	/* Identifies the file as WIM file. Must be exactly
	 * {'M', 'S', 'W', 'I', 'M', 0, 0, 0}  */
	//u8  magic[WIM_MAGIC_LEN];

	/* size of WIM header in bytes. */
	//u32 hdr_size;

	/* Version of the WIM file.  Microsoft provides no documentation about
	 * exactly what this field affects about the file format, other than the
	 * fact that more recent versions have a higher value. */
	//u32 version;

	/* Bitwise OR of one or more of the WIM_HDR_FLAG_* defined below. */
	u32 flags;

	/* The size of the pieces that the uncompressed files were split up into
	 * when they were compressed.  This should be the same as
	 * WIM_CHUNK_SIZE.  Microsoft incorrectly documents this as "the size of
	 * the compressed .wim file in bytes".*/
	//u32 chunk_size;

	/* A unique identifier for the WIM file. */
	u8  guid[WIM_GID_LEN];

	/* Part number of the WIM file in a spanned set. */
	u16 part_number;

	/* Total number of parts in a spanned set. */
	u16 total_parts;

	/* Number of images in the WIM file. */
	u32 image_count;

	/* Location, size, and flags of the lookup table of the WIM. */
	struct resource_entry lookup_table_res_entry;

	/* Location, size, and flags for the XML data of the WIM. */
	struct resource_entry xml_res_entry;

	/* Location, size, and flags for the boot metadata.  This means the
	 * metadata resource for the image specified by boot_idx below.  Should
	 * be zeroed out if boot_idx is 0. */
	struct resource_entry boot_metadata_res_entry;

	/* The index of the bootable image in the WIM file. If 0, there are no
	 * bootable images available. */
	u32 boot_idx;

	/* The location of the optional integrity table used to verify the
	 * integrity WIM.  Zeroed out if there is no integrity table.*/
	struct resource_entry integrity;

	/* Reserved for future disuse */
	//u8 unused[WIM_UNUSED_LEN];
};

/* Flags for the `flags' field of the struct wim_header: */

/* Reserved for future use */
#define WIM_HDR_FLAG_RESERVED           0x00000001

/* Files and metadata in the WIM are compressed. */
#define WIM_HDR_FLAG_COMPRESSION        0x00000002

/* WIM is read-only (wimlib ignores this because it's pretty much pointless) */
#define WIM_HDR_FLAG_READONLY           0x00000004

/* Resource data specified by images in this WIM may be contained in a different
 * WIM.  Or in other words, this WIM is part of a split WIM.  */
#define WIM_HDR_FLAG_SPANNED            0x00000008

/* The WIM contains resources only; no filesystem metadata.  wimlib ignores this
 * flag, as it looks for resources in all the WIMs anyway. */
#define WIM_HDR_FLAG_RESOURCE_ONLY      0x00000010

/* The WIM contains metadata only.  wimlib ignores this flag.  Note that all the
 * metadata resources for a split WIM should be in the first part. */
#define WIM_HDR_FLAG_METADATA_ONLY      0x00000020

/* Lock field to prevent multiple writers from writing the WIM concurrently.
 * wimlib ignores this flag as it uses flock() to acquire a real lock on the
 * file (if supported by the underlying filesystem). */
#define WIM_HDR_FLAG_WRITE_IN_PROGRESS  0x00000040

/* Reparse point fixup ???
 * This has something to do with absolute targets of reparse points / symbolic
 * links but I don't know what.  wimlib ignores this flag.  */
#define WIM_HDR_FLAG_RP_FIX             0x00000080

/* Unused, reserved flag for another compression type */
#define WIM_HDR_FLAG_COMPRESS_RESERVED  0x00010000

/* Resources within the WIM are compressed using "XPRESS" compression, which is
 * a LZ77-based compression algorithm. */
#define WIM_HDR_FLAG_COMPRESS_XPRESS    0x00020000

/* Resources within the WIM are compressed using "LZX" compression.  This is also
 * a LZ77-based algorithm. */
#define WIM_HDR_FLAG_COMPRESS_LZX       0x00040000

#ifdef WITH_NTFS_3G
struct _ntfs_volume;
#endif

/* Structure for security data.  Each image in the WIM file has its own security
 * data. */
struct wim_security_data {
	/* The total length of the security data, in bytes.  If there are no
	 * security descriptors, this field may be either 8 (which is correct)
	 * or 0 (which is interpreted as 0). */
	u32 total_length;

	/* The number of security descriptors in the array @descriptors, below.
	 * It is really an unsigned int, but it must fit into an int because the
	 * security ID's are signed.  (Not like you would ever have more than a
	 * few hundred security descriptors anyway.) */
	int32_t num_entries;

	/* Array of sizes of the descriptors in the array @descriptors. */
	u64 *sizes;

	/* Array of descriptors. */
	u8 **descriptors;

	/* Keep track of how many WIMs reference this security data (used when
	 * exporting images between WIMs) */
	u32 refcnt;
};

struct inode_table;

/* Metadata resource for an image. */
struct image_metadata {
	/* Pointer to the root dentry for the image. */
	struct dentry    *root_dentry;

	/* Pointer to the security data for the image. */
	struct wim_security_data *security_data;

	/* A pointer to the lookup table entry for this image's metadata
	 * resource. */
	struct lookup_table_entry *metadata_lte;

	/* Linked list of inodes for this image. */
	struct hlist_head inode_list;

	/* True iff the dentry tree has been modified.  If this is the case, the
	 * memory for the dentry tree is not freed when switching to a different
	 * WIM image. */
	u8 modified : 1;

	/* True iff this image has been mounted read-write. */
	u8 has_been_mounted_rw : 1;
};

#define WIMLIB_RESOURCE_FLAG_RAW		0x1
#define WIMLIB_RESOURCE_FLAG_MULTITHREADED	0x2
#define WIMLIB_RESOURCE_FLAG_RECOMPRESS		0x4

/* The opaque structure exposed to the wimlib API. */
struct WIMStruct {

	/* A pointer to the file indicated by @filename, opened for reading. */
	FILE *fp;

#ifdef WITH_FUSE
	/* Extra file pointers to be used by concurrent readers */
	FILE **fp_tab;
	size_t num_allocated_fps;
	pthread_mutex_t fp_tab_mutex;
#endif

	/* FILE pointer for the WIM file (if any) currently being written. */
	FILE *out_fp;

	/* The name of the WIM file that has been opened. */
	char *filename;

	/* The lookup table for the WIM file. */
	struct lookup_table *lookup_table;

	/* Pointer to the XML data read from the WIM file. */
	u8 *xml_data;

	/* Information retrieved from the XML data, arranged in an orderly
	 * manner. */
	struct wim_info *wim_info;

	/* Array of the image metadata, one for each image in the WIM. */
	struct image_metadata *image_metadata;

	/* The header of the WIM file. */
	struct wim_header hdr;

	/* Temporary fields */
	union {
		bool write_metadata;
		void *private;
	};
#ifdef WITH_NTFS_3G
	struct _ntfs_volume *ntfs_vol;
#endif

	/* The currently selected image, indexed starting at 1.  If not 0,
	 * subtract 1 from this to get the index of the current image in the
	 * image_metadata array. */
	int current_image;

	/* %true iff any images have been deleted from this WIM. */
	bool deletion_occurred;

	bool all_images_verified;
	bool full_verification_in_progress;
};


/* Inline utility functions for WIMStructs. */

static inline struct dentry *wim_root_dentry(WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1].root_dentry;
}

static inline struct wim_security_data *
wim_security_data(WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1].security_data;
}
static inline const struct wim_security_data *
wim_const_security_data(const WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1].security_data;
}

static inline struct lookup_table_entry*
wim_metadata_lookup_table_entry(WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1].metadata_lte;
}

/* Nonzero if a struct resource_entry indicates a compressed resource. */
static inline int resource_is_compressed(const struct resource_entry *entry)
{
	return (entry->flags & WIM_RESHDR_FLAG_COMPRESSED);
}

static inline struct image_metadata *
wim_get_current_image_metadata(WIMStruct *w)
{
	return &w->image_metadata[w->current_image - 1];
}

struct pattern_list {
	const char **pats;
	size_t num_pats;
	size_t num_allocated_pats;
};

struct capture_config {
	struct pattern_list exclusion_list;
	struct pattern_list exclusion_exception;
	struct pattern_list compression_exclusion_list;
	struct pattern_list alignment_list;
	char *config_str;
	char *prefix;
	size_t prefix_len;
};

/* add_image.c */
extern bool exclude_path(const char *path,
			 const struct capture_config *config,
			 bool exclude_prefix);
extern int add_new_dentry_tree(WIMStruct *dest_wim, struct dentry *root,
			       struct wim_security_data *sd);

/* hardlink.c */

/* Hash table to find inodes, identified by their inode ID.
 * */
struct inode_table {
	/* Fields for the hash table */
	struct hlist_head *array;
	u64 num_entries;
	u64 capacity;

	/*
	 * Linked list of "extra" inodes.  These may be:
	 *
	 * - inodes with link count 1, which are all allowed to have 0 for their
	 *   inode number, meaning we cannot insert them into the hash table
	 *   before calling assign_inode_numbers().
         *
	 * - Groups we create ourselves by splitting a nominal inode due to
	 *   inconsistencies in the dentries.  These inodes will share a inode
	 *   ID with some other inode until assign_inode_numbers() is called.
	 */
	struct hlist_head extra_inodes;
};

extern int init_inode_table(struct inode_table *table, size_t capacity);
static inline void destroy_inode_table(struct inode_table *table)
{
	FREE(table->array);
}
extern int inode_table_insert(struct dentry *dentry, void *__table);
extern u64 assign_inode_numbers(struct hlist_head *inode_list);
extern int fix_inodes(struct inode_table *table, struct hlist_head *inode_list);

/* header.c */
extern int read_header(FILE *fp, struct wim_header *hdr, int split_ok);
extern int write_header(const struct wim_header *hdr, FILE *out);
extern int init_header(struct wim_header *hdr, int ctype);

/* integrity.c */
extern int write_integrity_table(FILE *out,
				 struct resource_entry *integrity_res_entry,
				 off_t new_lookup_table_end,
				 off_t old_lookup_table_end,
				 wimlib_progress_func_t progress_func);

extern int check_wim_integrity(WIMStruct *w,
			       wimlib_progress_func_t progress_func);

/* join.c */

extern int new_joined_lookup_table(WIMStruct *w,
				   WIMStruct **additional_swms,
			    	   unsigned num_additional_swms,
				   struct lookup_table **table_ret);

extern int verify_swm_set(WIMStruct *w,
			  WIMStruct **additional_swms,
			  unsigned num_additional_swms);
extern int wim_run_full_verifications(WIMStruct *w);

/* ntfs-apply.c */

struct apply_args {
	WIMStruct *w;
	const char *target;
	int extract_flags;
	unsigned num_lutimes_warnings;
	struct list_head *stream_list;
	union wimlib_progress_info progress;
#ifdef WITH_NTFS_3G
	struct _ntfs_volume *vol;
#endif
	struct list_head empty_files;
	wimlib_progress_func_t progress_func;
};

extern int apply_dentry_ntfs(struct dentry *dentry, void *arg);
extern int apply_dentry_timestamps_ntfs(struct dentry *dentry, void *arg);

/* ntfs-capture.c */
extern int build_dentry_tree_ntfs(struct dentry **root_p,
				  const char *device,
				  struct lookup_table *lookup_table,
				  struct wim_security_data *sd,
				  const struct capture_config *config,
				  int add_image_flags,
				  wimlib_progress_func_t progress_func,
				  void *extra_arg);

/* resource.c */
extern const u8 *get_resource_entry(const u8 *p, struct resource_entry *entry);
extern u8 *put_resource_entry(u8 *p, const struct resource_entry *entry);

extern int read_uncompressed_resource(FILE *fp, u64 offset, u64 size, u8 buf[]);

extern int read_wim_resource(const struct lookup_table_entry *lte, u8 buf[],
			     size_t size, u64 offset, int flags);

extern int read_full_wim_resource(const struct lookup_table_entry *lte,
				  u8 buf[], int flags);

extern int write_wim_resource(struct lookup_table_entry *lte,
			      FILE *out_fp, int out_ctype,
			      struct resource_entry *out_res_entry,
			      int flags);

extern int extract_wim_resource_to_fd(const struct lookup_table_entry *lte,
				      int fd, u64 size);


extern int extract_full_wim_resource_to_fd(const struct lookup_table_entry *lte,
					   int fd);

extern int read_metadata_resource(WIMStruct *w,
				  struct image_metadata *image_metadata);


extern int write_dentry_resources(struct dentry *dentry, void *wim_p);
extern int copy_resource(struct lookup_table_entry *lte, void *w);
extern int write_metadata_resource(WIMStruct *w);


/* security.c */
int read_security_data(const u8 metadata_resource[],
		u64 metadata_resource_len, struct wim_security_data **sd_p);

void print_security_data(const struct wim_security_data *sd);
u8 *write_security_data(const struct wim_security_data *sd, u8 *p);
void free_security_data(struct wim_security_data *sd);

/* symlink.c */
ssize_t inode_readlink(const struct inode *inode, char *buf, size_t buf_len,
			const WIMStruct *w, int read_resource_flags);
extern void *make_symlink_reparse_data_buf(const char *symlink_target,
					   size_t *len_ret);
extern int inode_set_symlink(struct inode *inode,
			     const char *target,
			     struct lookup_table *lookup_table,
			     struct lookup_table_entry **lte_ret);

/* wim.c */
extern WIMStruct *new_wim_struct();
extern int select_wim_image(WIMStruct *w, int image);
extern int wim_hdr_flags_compression_type(int wim_hdr_flags);
extern int for_image(WIMStruct *w, int image, int (*visitor)(WIMStruct *));
extern void destroy_image_metadata(struct image_metadata *imd,
				   struct lookup_table *lt);

/* Internal use only */
#define WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE	0x80000000
#define WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE 0x40000000
#define WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML  0x20000000
#define WIMLIB_WRITE_MASK_PUBLIC		0x1fffffff

/* Internal use only */
#define WIMLIB_EXTRACT_FLAG_MULTI_IMAGE		0x80000000
#define WIMLIB_EXTRACT_FLAG_NO_STREAMS		0x40000000
#define WIMLIB_EXTRACT_MASK_PUBLIC		0x3fffffff


/* write.c */
extern int begin_write(WIMStruct *w, const char *path, int write_flags);
extern void close_wim_writable(WIMStruct *w);

extern int finish_write(WIMStruct *w, int image, int write_flags,
			wimlib_progress_func_t progress_func);

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
extern int lock_wim(FILE *fp, const char *path);
#else
static inline int lock_wim(FILE *fp, const char *path)
{
	return 0;
}
#endif

#endif /* _WIMLIB_INTERNAL_H */

