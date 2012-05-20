/*
 * wimlib_internal.h
 *
 * Internal header for wimlib.
 *
 * wimlib - Library for working with WIM files 
 *
 * Copyright (C) 2010 Carl Thijssen
 * Copyright (C) 2012 Eric Biggers
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option) any
 * later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with this library; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef _WIMLIB_INTERNAL_H
#define _WIMLIB_INTERNAL_H

#include "util.h"

struct stat;

#define WIM_HASH_SIZE  20
#define WIM_MAGIC_LEN  8
#define WIM_GID_LEN    16
#define WIM_UNUSED_LEN 60


/* Length of the WIM header on disk. */
#define WIM_HEADER_DISK_SIZE (148 + WIM_UNUSED_LEN)

/* Compressed resources in the WIM are divided into separated compressed chunks
 * of this size. */
#define WIM_CHUNK_SIZE 32768

/* Version of the WIM file.  I don't know if there has ever been a different
 * version or not. */
#define WIM_VERSION 0x10d00

enum wim_integrity_status {
	WIM_INTEGRITY_OK,
	WIM_INTEGRITY_NOT_OK,
	WIM_INTEGRITY_NONEXISTENT,
};

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

/* ??? */
#define WIM_RESHDR_FLAG_FREE            0x01

/* Indicates that a file resource is a metadata resource. */
#define WIM_RESHDR_FLAG_METADATA        0x02

/* Indicates that a file resource is compressed. */
#define WIM_RESHDR_FLAG_COMPRESSED	0x04

/* ??? */
#define WIM_RESHDR_FLAG_SPANNED         0x08


/* Header at the very beginning of the WIM file. */
struct wim_header { 
	/* Identifies the file as WIM file. Must be exactly
	 * {'M', 'S', 'W', 'I', 'M', 0, 0, 0}  */
	//u8  magic[WIM_MAGIC_LEN]; 	

	/* size of WIM header in bytes. */
	//u32 hdr_size;

	/* Version of the WIM file.  M$ provides no documentation about exactly
	 * what this field affects about the file format, other than the fact
	 * that more recent versions have a higher value. */
	//u32 version;

	/* Bitwise OR of one or more of the WIM_HDR_FLAG_* defined below. */
	u32 flags;

	/* The size of the pieces that the uncompressed files were split up into
	 * when they were compressed.  This should be the same as
	 * WIM_CHUNK_SIZE.  M$ incorrectly documents this as "the size of the
	 * compressed .wim file in bytes".*/
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

/* Flags for the `flags' field of the struct wim_header. */


/* Reserved for future use by M$ */
#define WIM_HDR_FLAG_RESERVED           0x00000001

/* Files and metadata in the WIM are compressed. */
#define WIM_HDR_FLAG_COMPRESSION        0x00000002

/* WIM is read-only. */
#define WIM_HDR_FLAG_READONLY           0x00000004

/* Resource data specified by images in this WIM may be contained in a different
 * WIM */
#define WIM_HDR_FLAG_SPANNED            0x00000008

/* The WIM contains resources only; no filesystem metadata. */
#define WIM_HDR_FLAG_RESOURCE_ONLY      0x00000010

/* The WIM contains metadata only. */
#define WIM_HDR_FLAG_METADATA_ONLY      0x00000020

/* Lock field to prevent multiple writers from writing the WIM concurrently. */
#define WIM_HDR_FLAG_WRITE_IN_PROGRESS  0x00000040 

/* Reparse point fixup ??? */
#define WIM_HDR_FLAG_RP_FIX             0x00000080

/* Unknown compression type */
#define WIM_HDR_FLAG_COMPRESS_RESERVED  0x00010000

/* Resources within the WIM are compressed using "XPRESS" compression, which is
 * a LZ77-based compression algorithm. */
#define WIM_HDR_FLAG_COMPRESS_XPRESS    0x00020000

/* Resources within the WIM are compressed using "LZX" compression.  This is also
 * a LZ77-based algorithm. */
#define WIM_HDR_FLAG_COMPRESS_LZX       0x00040000


#ifdef ENABLE_SECURITY_DATA
/* Structure for security data.  Each image in the WIM file has its own security
 * data. */
struct wim_security_data {
	/* The total length of the security data, in bytes.  A typical size is
	 * 2048 bytes.  If there is no security data, though (as in the WIMs
	 * that wimlib writes, currently), it will be 8 bytes. */
	u32 total_length;

	/* The number of security descriptors in the array @descriptors, below. */
	u32 num_entries;

	/* Array of sizes of the descriptors in the array @descriptors. */
	u64 *sizes;

	/* Array of descriptors. */
	u8 **descriptors;

	/* keep track of how many WIMs reference this security data (used when
	 * exporting images between WIMs) */
	u32 refcnt;
} WIMSecurityData;
#endif

/* Metadata resource for an image. */
struct image_metadata {
	/* Pointer to the root dentry for the image. */
	struct dentry    *root_dentry;

#ifdef ENABLE_SECURITY_DATA
	/* Pointer to the security data for the image. */
	struct wim_security_data *security_data;
#endif
	/* A pointer to the lookup table entry for this image's metadata
	 * resource. */
	struct lookup_table_entry *lookup_table_entry;

	/* True if the filesystem of the image has been modified.  If this is
	 * the case, the memory for the filesystem is not freed when switching
	 * to a different WIM image. */
	bool modified;

};

/* The opaque structure exposed to the wimlib API. */
typedef struct WIMStruct {

	/* A pointer to the file indicated by @filename, opened for reading. */
	FILE                *fp;

	/* FILE pointer for the WIM file that is being written. */
	FILE  *out_fp;

	/* The name of the WIM file that has been opened. */
	char                *filename;

	/* The lookup table for the WIM file. */ 
	struct lookup_table *lookup_table;

	/* Pointer to the XML data read from the WIM file. */
	u8                  *xml_data;

	/* Information retrieved from the XML data, arranged
	 * in an orderly manner. */
	struct wim_info      *wim_info;

	/* Array of the image metadata of length image_count.  Each image in the
	 * WIM has a image metadata associated with it. */
	struct image_metadata     *image_metadata;

	/* Name of the output directory for extraction. */
	char  *output_dir;

	/* The header of the WIM file. */
	struct wim_header    hdr;

	/* The type of links to create when extracting files (hard, symbolic, or
	 * none.) */
	int    link_type;

	/* The currently selected image, indexed starting at 1.  If not 0,
	 * subtract 1 from this to get the index of the current image in the
	 * image_metadata array. */
	int                  current_image;

	/* True if files names are to be printed when doing extraction. 
	 * May be used for other things later. */
	bool   verbose;

	union {
		/* Set to true when extracting multiple images */
		bool is_multi_image_extraction;

		bool write_metadata;
	};
} WIMStruct;


/* Inline utility functions for WIMStructs. */

static inline struct dentry *wim_root_dentry(WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1].root_dentry;
}

static inline struct dentry **wim_root_dentry_p(WIMStruct *w)
{
	return &w->image_metadata[w->current_image - 1].root_dentry;
}

#ifdef ENABLE_SECURITY_DATA
static inline struct wim_security_data *wim_security_data(WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1].security_data;
}
#endif

static inline struct lookup_table_entry*
wim_metadata_lookup_table_entry(WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1].lookup_table_entry;
}

/* Nonzero if a struct resource_entry indicates a compressed resource. */
static inline int resource_is_compressed(const struct resource_entry *entry)
{
	return (entry->flags & WIM_RESHDR_FLAG_COMPRESSED);
}

static inline struct image_metadata *wim_get_current_image_metadata(WIMStruct *w)
{
	return &w->image_metadata[w->current_image - 1];
}

static inline bool wim_current_image_is_modified(const WIMStruct *w)
{
	return w->image_metadata[w->current_image - 1].modified;
}

/* Prints a hash code field. */
static inline void print_hash(const u8 hash[])
{
	print_byte_field(hash, WIM_HASH_SIZE);
}


/* header.c */
extern int read_header(FILE *fp, struct wim_header *hdr, int split_ok);
extern int write_header(const struct wim_header *hdr, FILE *out);
extern int init_header(struct wim_header *hdr, int ctype);

/* integrity.c */
extern int write_integrity_table(FILE *out, u64 end_header_offset, 
				 u64 end_lookup_table_offset,
				 int show_progress);
extern int check_wim_integrity(WIMStruct *w, int show_progress, int *status);


/* resource.c */
extern const u8 *get_resource_entry(const u8 *p, struct resource_entry *entry);
extern u8 *put_resource_entry(u8 *p, const struct resource_entry *entry);

extern int read_resource(FILE *fp, u64 resource_size, 
			 u64 resource_original_size,
			 u64 resource_offset, int resource_ctype, u64 len, 
			 u64 offset, void *contents_ret);

extern int read_uncompressed_resource(FILE *fp, u64 offset, u64 len, 
					u8 contents_ret[]);


extern int extract_resource_to_fd(WIMStruct *w, 
				  const struct resource_entry *entry, 
				  int fd, 
				  u64 size);

extern int extract_full_resource_to_fd(WIMStruct *w, 
				       const struct resource_entry *entry, 
				       int fd);

extern int read_metadata_resource(FILE *fp, 
				  const struct resource_entry *metadata,
			          int wim_ctype, 
				  struct image_metadata *image_metadata);

extern int resource_compression_type(int wim_ctype, int reshdr_flags);

static inline int read_full_resource(FILE *fp, u64 resource_size, 
				u64 resource_original_size,
				u64 resource_offset, 
				int resource_ctype, void *contents_ret)
{
	return read_resource(fp, resource_size, resource_original_size, 
				resource_offset, resource_ctype,
				resource_original_size, 0, contents_ret);
}

extern int write_file_resource(struct dentry *dentry, void *wim_p);
extern int copy_resource(struct lookup_table_entry *lte, void *w);
extern int copy_between_files(FILE *in, off_t in_offset, FILE *out, size_t len);
extern int write_resource_from_memory(const u8 resource[], int out_ctype,
				      u64 resource_original_size, FILE *out,
				      u64 *resource_size_ret);
extern int write_metadata_resource(WIMStruct *w);

#ifdef ENABLE_SECURITY_DATA
int read_security_data(const u8 metadata_resource[], 
		u64 metadata_resource_len, struct wim_security_data **sd_p);

void print_security_data(const struct wim_security_data *sd);
u8 *write_security_data(const struct wim_security_data *sd, u8 *p);
void free_security_data(struct wim_security_data *sd);
#endif

/* wim.c */
extern WIMStruct *new_wim_struct();
extern int wimlib_select_image(WIMStruct *w, int image);
extern int wim_hdr_flags_compression_type(int wim_hdr_flags);
extern int wim_resource_compression_type(const WIMStruct *w, 
					 const struct resource_entry *entry);
extern int for_image(WIMStruct *w, int image, int (*visitor)(WIMStruct *));

/* write.c */
extern int finish_write(WIMStruct *w, int image, int flags, 
			int write_lookup_table);

extern int begin_write(WIMStruct *w, const char *path, int flags);


#include "wimlib.h"

#endif /* _WIMLIB_INTERNAL_H */

