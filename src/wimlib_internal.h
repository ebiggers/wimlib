/*
 * wimlib_internal.h
 *
 * Internal header for wimlib.
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#if defined(WITH_FUSE) || defined(ENABLE_MULTITHREADED_COMPRESSION)
#include <pthread.h>
#endif

#define WIMLIB_MAKEVERSION(major, minor, patch) \
	((major << 20) | (minor << 10) | patch)


#define WIMLIB_VERSION_CODE \
		WIMLIB_MAKEVERSION(WIMLIB_MAJOR_VERSION,\
				   WIMLIB_MINOR_VERSION,\
				   WIMLIB_PATCH_VERSION)

#define WIMLIB_GET_PATCH_VERSION(version) \
	((version >> 0) & ((1 << 10) - 1))
#define WIMLIB_GET_MINOR_VERSION(version) \
	((version >> 10) & ((1 << 10) - 1))
#define WIMLIB_GET_MAJOR_VERSION(version) \
	((version >> 20) & ((1 << 10) - 1))


struct stat;
struct wim_dentry;
struct wim_inode;
struct sd_set;

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
	u8 guid[WIM_GID_LEN];

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

/* Table of security descriptors for a WIM image. */
struct wim_security_data {
	/* The total length of the security data, in bytes.  If there are no
	 * security descriptors, this field, when read from the on-disk metadata
	 * resource, may be either 8 (which is correct) or 0 (which is
	 * interpreted as 0). */
	u32 total_length;

	/* The number of security descriptors in the array @descriptors, below.
	 * It is really an unsigned int on-disk, but it must fit into an int
	 * because the security ID's are signed.  (Not like you would ever have
	 * more than a few hundred security descriptors anyway.) */
	int32_t num_entries;

	/* Array of sizes of the descriptors in the array @descriptors. */
	u64 *sizes;

	/* Array of descriptors. */
	u8 **descriptors;
};

/* Metadata for a WIM image */
struct wim_image_metadata {

	/* Number of WIMStruct's that are sharing this image metadata (from
	 * calls to wimlib_export_image().) */
	unsigned long refcnt;

	/* Pointer to the root dentry of the image. */
	struct wim_dentry *root_dentry;

	/* Pointer to the security data of the image. */
	struct wim_security_data *security_data;

	/* Pointer to the lookup table entry for this image's metadata resource
	 */
	struct wim_lookup_table_entry *metadata_lte;

	/* Linked list of 'struct wim_inode's for this image. */
	struct list_head inode_list;

	/* Linked list of 'struct wim_lookup_table_entry's for this image that
	 * are referred to in the dentry tree, but have not had a SHA1 message
	 * digest calculated yet and therefore have not been inserted into the
	 * WIM's lookup table.  This list is added to during wimlib_add_image()
	 * and wimlib_mount_image() (read-write only). */
	struct list_head unhashed_streams;

	/* 1 iff the dentry tree has been modified.  If this is the case, the
	 * memory for the dentry tree should not be freed when switching to a
	 * different WIM image. */
	u8 modified : 1;

#ifdef WITH_NTFS_3G
	struct _ntfs_volume *ntfs_vol;
#endif
};

/* The opaque structure exposed to the wimlib API. */
struct WIMStruct {

	/* A pointer to the file indicated by @filename, opened for reading. */
	FILE *fp;

#if defined(WITH_FUSE) || defined(ENABLE_MULTITHREADED_COMPRESSION)
	/* Extra file pointers to be used by concurrent readers */
	FILE **fp_tab;
	size_t num_allocated_fps;
	pthread_mutex_t fp_tab_mutex;
#endif

	/* FILE pointer for the WIM file (if any) currently being written. */
	FILE *out_fp;

	/* The name of the WIM file (if any) that has been opened. */
	tchar *filename;

	/* The lookup table for the WIM file. */
	struct wim_lookup_table *lookup_table;

	/* Information retrieved from the XML data, arranged in an orderly
	 * manner. */
	struct wim_info *wim_info;

	/* Array of the image metadata, one for each image in the WIM. */
	struct wim_image_metadata **image_metadata;

	/* The header of the WIM file. */
	struct wim_header hdr;

	/* Temporary field */
	void *private;

	/* The currently selected image, indexed starting at 1.  If not 0,
	 * subtract 1 from this to get the index of the current image in the
	 * image_metadata array. */
	int current_image;

	u8 deletion_occurred : 1;
	u8 all_images_verified : 1;
	u8 wim_locked : 1;
};

/* Inline utility functions for WIMStructs. */

static inline struct wim_image_metadata *
wim_get_current_image_metadata(WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1];
}

static inline const struct wim_image_metadata *
wim_get_const_current_image_metadata(const WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1];
}

static inline struct wim_dentry *
wim_root_dentry(WIMStruct *w)
{
	return wim_get_current_image_metadata(w)->root_dentry;
}

static inline struct wim_security_data *
wim_security_data(WIMStruct *w)
{
	return wim_get_current_image_metadata(w)->security_data;
}

static inline const struct wim_security_data *
wim_const_security_data(const WIMStruct *w)
{
	return wim_get_const_current_image_metadata(w)->security_data;
}

/* Nonzero if a struct resource_entry indicates a compressed resource. */
static inline int
resource_is_compressed(const struct resource_entry *entry)
{
	return (entry->flags & WIM_RESHDR_FLAG_COMPRESSED);
}

/* Iterate over each inode in a WIM image that has not yet been hashed */
#define image_for_each_inode(inode, imd) \
	list_for_each_entry(inode, &imd->inode_list, i_list)

/* Iterate over each stream in a WIM image that has not yet been hashed */
#define image_for_each_unhashed_stream(lte, imd) \
	list_for_each_entry(lte, &imd->unhashed_streams, unhashed_list)

/* Iterate over each stream in a WIM image that has not yet been hashed (safe
 * against stream removal) */
#define image_for_each_unhashed_stream_safe(lte, tmp, imd) \
	list_for_each_entry_safe(lte, tmp, &imd->unhashed_streams, unhashed_list)

#if 1
#  define copy_resource_entry(dst, src) memcpy(dst, src, sizeof(struct resource_entry))
#  define zero_resource_entry(entry) memset(entry, 0, sizeof(struct resource_entry))
#else
static inline void
copy_resource_entry(struct resource_entry *dst,
		    const struct resource_entry *src)
{
	BUILD_BUG_ON(sizeof(struct resource_entry) != 24);
	((u64*)dst)[0] = ((u64*)src)[0];
	((u64*)dst)[1] = ((u64*)src)[1];
	((u64*)dst)[2] = ((u64*)src)[2];
}

static inline void
zero_resource_entry(struct resource_entry *entry)
{
	BUILD_BUG_ON(sizeof(struct resource_entry) != 24);
	((u64*)entry)[0] = 0;
	((u64*)entry)[1] = 0;
	((u64*)entry)[2] = 0;
}
#endif

/* add_image.c */

extern bool
exclude_path(const tchar *path, size_t path_len,
	     const struct wimlib_capture_config *config,
	     bool exclude_prefix);

/* extract_image.c */

/* Internal use only */
#define WIMLIB_EXTRACT_FLAG_MULTI_IMAGE		0x80000000
#define WIMLIB_EXTRACT_FLAG_NO_STREAMS		0x40000000
#define WIMLIB_EXTRACT_MASK_PUBLIC		0x3fffffff

/* hardlink.c */

/* Hash table to find inodes, given an inode number (in the case of reading
 * a WIM images), or both an inode number and a device number (in the case of
 * capturing a WIM image). */
struct wim_inode_table {
	/* Fields for the hash table */
	struct hlist_head *array;
	u64 num_entries;
	u64 capacity;

	/*
	 * Linked list of "extra" inodes.  These may be:
	 *
	 * - inodes with link count 1, which are all allowed to have 0 for their
	 *   inode number, meaning we cannot insert them into the hash table.
         *
	 * - Groups we create ourselves by splitting a nominal inode due to
	 *   inconsistencies in the dentries.  These inodes will share an inode
	 *   number with some other inode until assign_inode_numbers() is
	 *   called.
	 */
	struct list_head extra_inodes;
};

extern int
init_inode_table(struct wim_inode_table *table, size_t capacity);

extern int
inode_table_new_dentry(struct wim_inode_table *table, const tchar *name,
		       u64 ino, u64 devno, struct wim_dentry **dentry_ret);

extern void
inode_ref_streams(struct wim_inode *inode);

extern void
inode_table_prepare_inode_list(struct wim_inode_table *table,
			       struct list_head *head);

static inline void
destroy_inode_table(struct wim_inode_table *table)
{
	FREE(table->array);
}


extern int
dentry_tree_fix_inodes(struct wim_dentry *root, struct list_head *inode_list);

/* header.c */

extern int
read_header(FILE *fp, struct wim_header *hdr, int split_ok);

extern int
write_header(const struct wim_header *hdr, FILE *out);

extern int
init_header(struct wim_header *hdr, int ctype);

/* integrity.c */

#define WIM_INTEGRITY_OK 0
#define WIM_INTEGRITY_NOT_OK -1
#define WIM_INTEGRITY_NONEXISTENT -2

extern int
write_integrity_table(FILE *out, struct resource_entry *integrity_res_entry,
		      off_t new_lookup_table_end,
		      off_t old_lookup_table_end,
		      wimlib_progress_func_t progress_func);

extern int
check_wim_integrity(WIMStruct *w, wimlib_progress_func_t progress_func);

/* join.c */

extern int
new_joined_lookup_table(WIMStruct *w, WIMStruct **additional_swms,
			unsigned num_additional_swms,
			struct wim_lookup_table **table_ret);

/* metadata_resource.c */

extern int
read_metadata_resource(WIMStruct *w,
				  struct wim_image_metadata *image_metadata);

extern int
write_metadata_resource(WIMStruct *w);

/* ntfs-apply.c */

struct apply_args {
	WIMStruct *w;
	const tchar *target;
	int extract_flags;
	union wimlib_progress_info progress;
	wimlib_progress_func_t progress_func;
	int (*apply_dentry)(struct wim_dentry *, void *);
	union {
	#ifdef WITH_NTFS_3G
		struct {
			/* NTFS apply only */
			struct _ntfs_volume *vol;
		};
	#endif
		struct {
			/* Normal apply only (UNIX) */
			unsigned long num_utime_warnings;
		};

		struct {
			/* Normal apply only (Win32) */
			unsigned long num_set_sacl_priv_notheld;
			unsigned long num_set_sd_access_denied;
		};
	};
};

extern int
apply_dentry_ntfs(struct wim_dentry *dentry, void *arg);

extern int
apply_dentry_timestamps_ntfs(struct wim_dentry *dentry, void *arg);

extern void
libntfs3g_global_init();

/* ntfs-capture.c */

/* The types of these two callbacks are intentionally the same. */
typedef int (*consume_data_callback_t)(const void *buf, size_t len, void *ctx);

extern int
read_ntfs_file_prefix(const struct wim_lookup_table_entry *lte,
		      u64 size,
		      consume_data_callback_t cb,
		      void *ctx_or_buf,
		      int _ignored_flags);
extern int
build_dentry_tree_ntfs(struct wim_dentry **root_p,
		       const tchar *device,
		       struct wim_lookup_table *lookup_table,
		       struct wim_inode_table *inode_table,
		       struct sd_set *sd_set,
		       const struct wimlib_capture_config *config,
		       int add_image_flags,
		       wimlib_progress_func_t progress_func,
		       void *extra_arg);

#ifdef WITH_NTFS_3G
extern int
do_ntfs_umount(struct _ntfs_volume *vol);
#endif

/* resource.c */

#define WIMLIB_RESOURCE_FLAG_RAW		0x1
#define WIMLIB_RESOURCE_FLAG_THREADSAFE_READ	0x2
#define WIMLIB_RESOURCE_FLAG_RECOMPRESS		0x4

extern int
read_resource_prefix(const struct wim_lookup_table_entry *lte,
		     u64 size, consume_data_callback_t cb, void *ctx_or_buf,
		     int flags);

extern const void *
get_resource_entry(const void *p, struct resource_entry *entry);

extern void *
put_resource_entry(void *p, const struct resource_entry *entry);

extern int
read_uncompressed_resource(FILE *fp, u64 offset, u64 size, void *buf);

extern int
read_partial_wim_resource_into_buf(const struct wim_lookup_table_entry *lte,
				   size_t size, u64 offset, void *buf,
				   bool threadsafe);
extern int
read_full_resource_into_buf(const struct wim_lookup_table_entry *lte,
			    void *buf, bool thread_safe);

extern int
write_wim_resource(struct wim_lookup_table_entry *lte, FILE *out_fp,
		   int out_ctype, struct resource_entry *out_res_entry,
		   int flags);

extern int
extract_wim_resource(const struct wim_lookup_table_entry *lte,
		     u64 size,
		     consume_data_callback_t extract_chunk,
		     void *extract_chunk_arg);

extern int
extract_wim_resource_to_fd(const struct wim_lookup_table_entry *lte,
			   int fd, u64 size);

extern int
sha1_resource(struct wim_lookup_table_entry *lte);

extern int
copy_resource(struct wim_lookup_table_entry *lte, void *w);

/* security.c */
extern int
read_security_data(const u8 metadata_resource[],
		   u64 metadata_resource_len, struct wim_security_data **sd_p);
extern void
print_security_data(const struct wim_security_data *sd);

extern u8 *
write_security_data(const struct wim_security_data *sd, u8 *p);

extern void
free_security_data(struct wim_security_data *sd);

/* symlink.c */

#ifndef __WIN32__
ssize_t
inode_readlink(const struct wim_inode *inode, char *buf, size_t buf_len,
	       const WIMStruct *w, bool threadsafe);

extern int
inode_set_symlink(struct wim_inode *inode, const char *target,
		  struct wim_lookup_table *lookup_table,
		  struct wim_lookup_table_entry **lte_ret);
#endif

/* verify.c */

extern int
verify_dentry(struct wim_dentry *dentry, void *wim);

extern int
wim_run_full_verifications(WIMStruct *w);

extern int
verify_swm_set(WIMStruct *w,
	       WIMStruct **additional_swms, unsigned num_additional_swms);

/* wim.c */

extern int
select_wim_image(WIMStruct *w, int image);

extern int
for_image(WIMStruct *w, int image, int (*visitor)(WIMStruct *));

extern void
destroy_image_metadata(struct wim_image_metadata *imd,
		       struct wim_lookup_table *table,
		       bool free_metadata_lte);

extern void
put_image_metadata(struct wim_image_metadata *imd,
		   struct wim_lookup_table *table);

extern int
append_image_metadata(WIMStruct *w, struct wim_image_metadata *imd);

extern struct wim_image_metadata *
new_image_metadata();

extern struct wim_image_metadata **
new_image_metadata_array(unsigned num_images);

extern int
wim_checksum_unhashed_streams(WIMStruct *w);

/* write.c */

/* Internal use only */
#define WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE	0x80000000
#define WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE 0x40000000
#define WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML  0x20000000
#define WIMLIB_WRITE_MASK_PUBLIC		0x1fffffff

/* We are capturing a tree to be placed in the root of the WIM image */
#define WIMLIB_ADD_IMAGE_FLAG_ROOT	0x80000000

/* We are capturing a dentry that will become the root of a tree to be added to
 * the WIM image */
#define WIMLIB_ADD_IMAGE_FLAG_SOURCE    0x40000000


extern int
begin_write(WIMStruct *w, const tchar *path, int write_flags);

extern void
close_wim_writable(WIMStruct *w);

extern int
finish_write(WIMStruct *w, int image, int write_flags,
	     wimlib_progress_func_t progress_func);

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
extern int
lock_wim(WIMStruct *w, FILE *fp);
#else
static inline int
lock_wim(WIMStruct *w, FILE *fp)
{
	return 0;
}
#endif

#endif /* _WIMLIB_INTERNAL_H */

