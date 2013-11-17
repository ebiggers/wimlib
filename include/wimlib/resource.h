#ifndef _WIMLIB_RESOURCE_H
#define _WIMLIB_RESOURCE_H

#include "wimlib/types.h"
#include "wimlib/endianness.h"
#include "wimlib/callback.h"
#include "wimlib/file_io.h"
#include "wimlib/sha1.h"

struct wim_lookup_table_entry;
struct wim_image_metadata;

/* Description of the location, size, and compression status of a WIM resource
 * (stream).  This is the in-memory version of `struct resource_entry_disk'.  */
struct resource_entry {
	/* Size, in bytes, of the resource as it appears in the WIM file.  If
	 * the resource is uncompressed, this will be the same as
	 * @original_size.  If the resource is compressed, this will be the
	 * compressed size of the resource, including all compressed chunks as
	 * well as the chunk table.
	 *
	 * Note: if the WIM is "pipable", this value does not include the stream
	 * header.  */
	u64 size  : 56;

	/* Bitwise OR of one or more of the WIM_RESHDR_FLAG_* flags.  */
	u64 flags : 8;

	/* Offset, in bytes, of the resource from the start of the WIM file.  */
	u64 offset;

	/* Uncompressed size, in bytes, of the resource (stream).  */
	u64 original_size;
};

/* On-disk version of `struct resource_entry'.  See `struct resource_entry' for
 * description of fields.  */
struct resource_entry_disk {
	u8 size[7];
	u8 flags;
	le64 offset;
	le64 original_size;
} _packed_attribute;

/* Flags for the `flags' field of the struct resource_entry structure. */

/* I haven't seen this flag used in any of the WIMs I have examined.  I assume
 * it means that there are no references to the stream, so the space is free.
 * However, even after deleting files from a WIM mounted with `imagex.exe
 * /mountrw', I could not see this flag being used.  Either way, wimlib doesn't
 * actually use this flag for anything. */
#define WIM_RESHDR_FLAG_FREE            0x01

/* Indicates that the stream is a metadata resource for a WIM image.  This flag
 * is also set in the resource entry for the lookup table in the WIM header.  */
#define WIM_RESHDR_FLAG_METADATA        0x02

/* Indicates that the stream is compressed (using the WIM's set compression
 * type).  */
#define WIM_RESHDR_FLAG_COMPRESSED	0x04

/* I haven't seen this flag used in any of the WIMs I have examined.  Perhaps it
 * means that a stream could possibly be split among multiple split WIM parts.
 * However, `imagex.exe /split' does not seem to create any WIMs like this.
 * Either way, wimlib doesn't actually use this flag for anything.  */
#define WIM_RESHDR_FLAG_SPANNED         0x08

/* Functions that operate directly on `struct resource_entry's.  */

static inline int
resource_is_compressed(const struct resource_entry *entry)
{
	return (entry->flags & WIM_RESHDR_FLAG_COMPRESSED);
}

static inline void copy_resource_entry(struct resource_entry *dst,
				       const struct resource_entry *src)
{
	memcpy(dst, src, sizeof(struct resource_entry));
}

static inline void zero_resource_entry(struct resource_entry *entry)
{
	memset(entry, 0, sizeof(struct resource_entry));
}

extern void
get_resource_entry(const struct resource_entry_disk *disk_entry,
		   struct resource_entry *entry);

extern void
put_resource_entry(const struct resource_entry *entry,
		   struct resource_entry_disk *disk_entry);

/* wimlib internal flags used when reading or writing resources.  */
#define WIMLIB_WRITE_RESOURCE_FLAG_RECOMPRESS		0x00000001
#define WIMLIB_WRITE_RESOURCE_FLAG_COMPRESS_SLOW	0x00000002
#define WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE		0x00000004
#define WIMLIB_WRITE_RESOURCE_MASK			0x0000ffff

#define WIMLIB_READ_RESOURCE_FLAG_RAW_FULL		0x80000000
#define WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS		0x40000000
#define WIMLIB_READ_RESOURCE_FLAG_SEEK_ONLY		0x20000000
#define WIMLIB_READ_RESOURCE_FLAG_RAW		(WIMLIB_READ_RESOURCE_FLAG_RAW_FULL |  \
						 WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS)
#define WIMLIB_READ_RESOURCE_MASK			0xffff0000


/* Functions to read a resource.  */

extern int
read_partial_wim_resource(const struct wim_lookup_table_entry *lte,
			  u64 size, consume_data_callback_t cb,
			  void *ctx_or_buf, int flags, u64 offset);

extern int
read_partial_wim_resource_into_buf(const struct wim_lookup_table_entry *lte,
				   size_t size, u64 offset, void *buf);
extern int
read_full_resource_into_buf(const struct wim_lookup_table_entry *lte, void *buf);

extern int
read_full_resource_into_alloc_buf(const struct wim_lookup_table_entry *lte,
				  void **buf_ret);

extern int
res_entry_to_data(const struct resource_entry *res_entry,
		  WIMStruct *wim, void **buf_ret);

extern int
read_resource_prefix(const struct wim_lookup_table_entry *lte,
		     u64 size, consume_data_callback_t cb, void *ctx_or_buf,
		     int flags);

/* Functions to write a resource.  */

extern int
write_wim_resource(struct wim_lookup_table_entry *lte, struct filedes *out_fd,
		   int out_ctype, struct resource_entry *out_res_entry,
		   int write_resource_flags,
		   struct wimlib_lzx_context **comp_ctx);

extern int
write_wim_resource_from_buffer(const void *buf, size_t buf_size,
			       int reshdr_flags, struct filedes *out_fd,
			       int out_ctype,
			       struct resource_entry *out_res_entry,
			       u8 *hash_ret, int write_resource_flags,
			       struct wimlib_lzx_context **comp_ctx);

/* Functions to extract a resource.  */

extern int
extract_wim_resource(const struct wim_lookup_table_entry *lte,
		     u64 size,
		     consume_data_callback_t extract_chunk,
		     void *extract_chunk_arg);

extern int
extract_wim_resource_to_fd(const struct wim_lookup_table_entry *lte,
			   struct filedes *fd, u64 size);

/* Miscellaneous resource functions.  */

extern int
sha1_resource(struct wim_lookup_table_entry *lte);

/* Functions to read/write metadata resources.  */

extern int
read_metadata_resource(WIMStruct *wim,
		       struct wim_image_metadata *image_metadata);

extern int
write_metadata_resource(WIMStruct *wim, int image, int write_resource_flags);

/* Definitions specific to pipable WIM resources.  */

/* Arbitrary number to begin each stream in the pipable WIM, used for sanity
 * checking.  */
#define PWM_STREAM_MAGIC 0x2b9b9ba2443db9d8ULL

/* Header that precedes each resource in a pipable WIM.  */
struct pwm_stream_hdr {
	le64 magic;			/* +0   */
	le64 uncompressed_size;		/* +8   */
	u8 hash[SHA1_HASH_SIZE];	/* +16  */
	le32 flags;			/* +36  */
					/* +40  */
} _packed_attribute;

/* Extra flag for the @flags field in `struct pipable_wim_stream_hdr': Indicates
 * that the SHA1 message digest of the stream has not been calculated.
 * Currently only used for the XML data.  */
#define PWM_RESHDR_FLAG_UNHASHED         0x100

/* Header that precedes each chunk of a compressed resource in a pipable WIM.
 */
struct pwm_chunk_hdr {
	le32 compressed_size;
} _packed_attribute;


#endif /* _WIMLIB_RESOURCE_H */
