#ifndef _WIMLIB_RESOURCE_H
#define _WIMLIB_RESOURCE_H

#include "wimlib/callback.h"
#include "wimlib/list.h"
#include "wimlib/sha1.h"
#include "wimlib/types.h"

struct blob_descriptor;
struct filedes;
struct wim_image_metadata;

/*
 * Description of a "resource" in a WIM file.  A "resource" is a standalone,
 * possibly compressed region of data.  Normally, there is a one-to-one
 * correspondence between "blobs" (each of which may be the contents of a file,
 * for example) and resources.  However, a resource with the
 * WIM_RESHDR_FLAG_SOLID flag set is a "solid" resource that contains multiple
 * blobs compressed together.
 */
struct wim_resource_descriptor {
	/* The WIM containing this resource.  @wim->in_fd is expected to be a
	 * file descriptor to the underlying WIM file, opened for reading.  */
	WIMStruct *wim;

	/* The offset, in bytes, from the start of WIM file at which this
	 * resource starts.  */
	u64 offset_in_wim;

	/* The size of this resource in the WIM file.  For compressed resources
	 * this is the compressed size, including overhead such as the chunk
	 * table.  */
	u64 size_in_wim;

	/* The number of bytes of uncompressed data this resource decompresses
	 * to.  */
	u64 uncompressed_size;

	/* The list of blobs this resource contains.  */
	struct list_head blob_list;

	/* Flags for this resource (WIM_RESHDR_FLAG_*).  */
	u32 flags : 8;

	/* [wimlib extension] This flag will be set if the WIM is pipable.  In
	 * such cases, the resource will be in a slightly different format if it
	 * is compressed.  */
	u32 is_pipable : 1;

	/* Temporary flag.  */
	u32 raw_copy_ok : 1;

	/* Compression type of this resource.  */
	u32 compression_type : 22;

	/* Compression chunk size of this resource.  Irrelevant if the resource
	 * is uncompressed.  */
	u32 chunk_size;
};

/* On-disk version of a WIM resource header.  */
struct wim_reshdr_disk {
	/* Size of the resource as it appears in the WIM file (possibly
	 * compressed).  */
	u8 size_in_wim[7];

	/* Zero or more of the WIM_RESHDR_FLAG_* flags.  These indicate, for
	 * example, whether the resource is compressed or not.  */
	u8 flags;

	/* Offset of the resource from the start of the WIM file, in bytes.  */
	le64 offset_in_wim;

	/* Uncompressed size of the resource, in bytes.  */
	le64 uncompressed_size;
} _packed_attribute;

/* In-memory version of a WIM resource header (`struct wim_reshdr_disk').  */
struct wim_reshdr {
	u64 size_in_wim : 56;
	u64 flags : 8;
	u64 offset_in_wim;
	u64 uncompressed_size;
};

/* Flags for the `flags' field of WIM resource headers (`struct wim_reshdr').
 */

/* Unknown meaning; currently ignored by wimlib.  */
#define WIM_RESHDR_FLAG_FREE            0x01

/* The resource is a metadata resource for a WIM image, or is the blob table or
 * XML data for the WIM.  */
#define WIM_RESHDR_FLAG_METADATA        0x02

/* The resource is a non-solid resource compressed using the WIM's default
 * compression type.  */
#define WIM_RESHDR_FLAG_COMPRESSED	0x04

/* Unknown meaning; currently ignored by wimlib.  */
#define WIM_RESHDR_FLAG_SPANNED         0x08

/* The resource is a solid compressed resource which may contain multiple blobs.
 * This flag is only allowed if the WIM version number is WIM_VERSION_SOLID.  */
#define WIM_RESHDR_FLAG_SOLID		0x10

/* Magic number in the 'uncompressed_size' field of the resource header that
 * identifies the main entry for a solid resource.  */
#define SOLID_RESOURCE_MAGIC_NUMBER	0x100000000ULL

/* Returns true if the specified WIM resource is compressed (may be either solid
 * or non-solid)  */
static inline bool
resource_is_compressed(const struct wim_resource_descriptor *rdesc)
{
	return (rdesc->flags & (WIM_RESHDR_FLAG_COMPRESSED |
				WIM_RESHDR_FLAG_SOLID));
}

static inline void
copy_reshdr(struct wim_reshdr *dest, const struct wim_reshdr *src)
{
	memcpy(dest, src, sizeof(struct wim_reshdr));
}

static inline void
zero_reshdr(struct wim_reshdr *reshdr)
{
	memset(reshdr, 0, sizeof(struct wim_reshdr));
}

extern void
wim_res_hdr_to_desc(const struct wim_reshdr *reshdr, WIMStruct *wim,
		    struct wim_resource_descriptor *rdesc);

extern void
get_wim_reshdr(const struct wim_reshdr_disk *disk_reshdr,
	       struct wim_reshdr *reshdr);

void
put_wim_reshdr(const struct wim_reshdr *reshdr,
	       struct wim_reshdr_disk *disk_reshdr);

/* Alternate chunk table format for resources with WIM_RESHDR_FLAG_SOLID set.
 */
struct alt_chunk_table_header_disk {
	/* Uncompressed size of the resource in bytes.  */
	le64 res_usize;

	/* Number of bytes each compressed chunk decompresses into, except
	 * possibly the last which decompresses into the remainder.  This
	 * overrides the chunk size specified by the WIM header.  */
	le32 chunk_size;

	/* Compression format used for compressed chunks:
	 * 0 = None
	 * 1 = XPRESS
	 * 2 = LZX
	 * 3 = LZMS
	 *
	 * This overrides the compression type specified by the WIM header.  */
	le32 compression_format;

	/* This header is directly followed by a table of compressed sizes of
	 * the chunks (4 bytes per entry).  */
} _packed_attribute;

static inline unsigned int
get_chunk_entry_size(u64 res_size, bool is_alt)
{
	if (res_size <= UINT32_MAX || is_alt)
		return 4;
	else
		return 8;
}

/* Functions to read blobs  */

extern int
read_partial_wim_blob_into_buf(const struct blob_descriptor *blob,
			       size_t size, u64 offset, void *buf);

extern int
read_full_blob_into_buf(const struct blob_descriptor *blob, void *buf);

extern int
read_full_blob_into_alloc_buf(const struct blob_descriptor *blob, void **buf_ret);

extern int
wim_reshdr_to_data(const struct wim_reshdr *reshdr,
		   WIMStruct *wim, void **buf_ret);

extern int
wim_reshdr_to_hash(const struct wim_reshdr *reshdr, WIMStruct *wim,
		   u8 hash[SHA1_HASH_SIZE]);

extern int
skip_wim_resource(struct wim_resource_descriptor *rdesc);

/*
 * Type of callback function for beginning to read a blob.
 *
 * @blob:
 *	Blob that is about to be read.
 *
 * @ctx:
 *	User-provided context.
 *
 * Must return 0 on success, a positive error code on failure, or the special
 * value BEGIN_BLOB_STATUS_SKIP_BLOB to indicate that the blob should not be
 * read, and read_blob_list() should continue on to the next blob (without
 * calling @consume_chunk or @end_blob).
 */
typedef int (*read_blob_list_begin_blob_t)(struct blob_descriptor *blob, void *ctx);

#define BEGIN_BLOB_STATUS_SKIP_BLOB	-1

/*
 * Type of callback function for finishing reading a blob.
 *
 * @blob:
 *	Blob that has been fully read, or blob that started being read but could
 *	not be fully read due to a read error.
 *
 * @status:
 *	0 if reading the blob was successful; otherwise a nonzero error code
 *	that specifies the return status.
 *
 * @ctx:
 *	User-provided context.
 */
typedef int (*read_blob_list_end_blob_t)(struct blob_descriptor *blob,
					 int status,
					 void *ctx);


/* Callback functions and contexts for read_blob_list().  */
struct read_blob_list_callbacks {

	/* Called when a blob is about to be read.  */
	read_blob_list_begin_blob_t begin_blob;

	/* Called when a chunk of data has been read.  */
	consume_data_callback_t consume_chunk;

	/* Called when a blob has been fully read.  A successful call to
	 * @begin_blob will always be matched by a call to @end_blob.  */
	read_blob_list_end_blob_t end_blob;

	/* Parameter passed to @begin_blob.  */
	void *begin_blob_ctx;

	/* Parameter passed to @consume_chunk.  */
	void *consume_chunk_ctx;

	/* Parameter passed to @end_blob.  */
	void *end_blob_ctx;
};

/* Flags for read_blob_list()  */
#define VERIFY_BLOB_HASHES		0x1
#define COMPUTE_MISSING_BLOB_HASHES	0x2
#define BLOB_LIST_ALREADY_SORTED	0x4

extern int
read_blob_list(struct list_head *blob_list, size_t list_head_offset,
	       const struct read_blob_list_callbacks *cbs, int flags);

/* Functions to extract blobs.  */

extern int
extract_blob(struct blob_descriptor *blob, u64 size,
	     consume_data_callback_t extract_chunk, void *extract_chunk_arg);

extern int
extract_blob_to_fd(struct blob_descriptor *blob, struct filedes *fd, u64 size);

extern int
extract_full_blob_to_fd(struct blob_descriptor *blob, struct filedes *fd);

/* Miscellaneous blob functions.  */

extern int
sha1_blob(struct blob_descriptor *blob);

/* Functions to read/write metadata resources.  */

extern int
read_metadata_resource(struct wim_image_metadata *imd);

extern int
write_metadata_resource(WIMStruct *wim, int image, int write_resource_flags);

/* Definitions specific to pipable WIM resources.  */

/* Arbitrary number to begin each blob in the pipable WIM, used for sanity
 * checking.  */
#define PWM_BLOB_MAGIC 0x2b9b9ba2443db9d8ULL

/* Header that precedes each blob in a pipable WIM.  */
struct pwm_blob_hdr {
	le64 magic;			/* +0   */
	le64 uncompressed_size;		/* +8   */
	u8 hash[SHA1_HASH_SIZE];	/* +16  */
	le32 flags;			/* +36  */
					/* +40  */
} _packed_attribute;

/* Header that precedes each chunk of a compressed resource in a pipable WIM.
 */
struct pwm_chunk_hdr {
	le32 compressed_size;
} _packed_attribute;

#endif /* _WIMLIB_RESOURCE_H */
