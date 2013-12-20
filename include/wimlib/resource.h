#ifndef _WIMLIB_RESOURCE_H
#define _WIMLIB_RESOURCE_H

#include "wimlib/types.h"
#include "wimlib/endianness.h"
#include "wimlib/callback.h"
#include "wimlib/file_io.h"
#include "wimlib/list.h"
#include "wimlib/sha1.h"

struct wim_lookup_table_entry;
struct wim_image_metadata;

/* Specification of a resource in a WIM file.
 *
 * If a `struct wim_lookup_table_entry' lte has
 * (lte->resource_location == RESOURCE_IN_WIM), then lte->wim_res_spec points to
 * an instance of this structure.
 *
 * Normally, there is a one-to-one correspondence between WIM lookup table
 * entries ("streams") and WIM resources.  However, the flag
 * WIM_RESHDR_FLAG_CONCAT can be used to specify that two streams be combined
 * into the same resource and compressed together.  Caveats about this flag are
 * noted in the comment above the definition of WIM_VERSION_STREAM_CONCAT.  */
struct wim_resource_spec {
	/* The WIM file containing this resource.  */
	WIMStruct *wim;

	/* Offset, in bytes, from the start of WIM file at which this resource
	 * starts.  */
	u64 offset_in_wim;

	/* The size of this resource in the WIM file.  For compressed resources
	 * this is the compressed size.  */
	u64 size_in_wim;

	/* Number of bytes of uncompressed data this resource uncompresses to.
	 */
	u64 uncompressed_size;

	/* List of streams this resource contains.  */
	struct list_head lte_list;

	/* Resource flags.  */
	u32 flags : 8;

	/* This flag will be set if the WIM is pipable and therefore the
	 * resource will be in a slightly different format if it is compressed
	 * (wimlib extension).  */
	u32 is_pipable : 1;

	/* Compression type of this resource as one of WIMLIB_COMPRESSION_TYPE_*
	 * constants.  */
	u32 ctype : 3;

	/* Compression chunk size.  */
	u32 cchunk_size;
};


/* On-disk version of a WIM resource header:  This structure specifies the
 * location, size, and flags (e.g. compressed or not compressed) for a resource
 * in the WIM file.  */
struct wim_reshdr_disk {
	/* Size of the resource as it appears in the WIM file (possibly
	 * compressed).  */
	u8 size_in_wim[7];

	/* WIM_RESHDR_FLAG_* flags.  */
	u8 flags;

	/* Offset of the resource from the start of the WIM file.  */
	le64 offset_in_wim;

	/* Uncompressed size of the resource.  */
	le64 uncompressed_size;
} _packed_attribute;

/* In-memory version of wim_reshdr_disk.  */
struct wim_reshdr {
	u64 size_in_wim : 56;
	u64 flags : 8;
	u64 offset_in_wim;
	u64 uncompressed_size;
};

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

/* TODO  */
#define WIM_RESHDR_FLAG_CONCAT		0x10

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
wim_res_hdr_to_spec(const struct wim_reshdr *reshdr, WIMStruct *wim,
		    struct wim_resource_spec *rspec);

extern void
wim_res_spec_to_hdr(const struct wim_resource_spec *rspec,
		    struct wim_reshdr *reshdr);

extern int
get_wim_reshdr(const struct wim_reshdr_disk *disk_reshdr,
	       struct wim_reshdr *reshdr);

void
put_wim_reshdr(const struct wim_reshdr *reshdr,
	       struct wim_reshdr_disk *disk_reshdr);

/* wimlib internal flags used when reading or writing resources.  */
#define WIMLIB_WRITE_RESOURCE_FLAG_RECOMPRESS		0x00000001
#define WIMLIB_WRITE_RESOURCE_FLAG_PIPABLE		0x00000002
#define WIMLIB_WRITE_RESOURCE_MASK			0x0000ffff

#define WIMLIB_READ_RESOURCE_FLAG_RAW_FULL		0x80000000
#define WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS		0x40000000
#define WIMLIB_READ_RESOURCE_FLAG_RAW		(WIMLIB_READ_RESOURCE_FLAG_RAW_FULL |  \
						 WIMLIB_READ_RESOURCE_FLAG_RAW_CHUNKS)
#define WIMLIB_READ_RESOURCE_MASK			0xffff0000


/* Functions to read a resource.  */

extern int
read_partial_wim_resource(const struct wim_lookup_table_entry *lte,
			  u64 size, consume_data_callback_t cb,
			  u32 in_chunk_size, void *ctx_or_buf,
			  int flags, u64 offset);

extern int
read_partial_wim_stream_into_buf(const struct wim_lookup_table_entry *lte,
				 size_t size, u64 offset, void *buf);
extern int
read_full_stream_into_buf(const struct wim_lookup_table_entry *lte, void *buf);

extern int
read_full_stream_into_alloc_buf(const struct wim_lookup_table_entry *lte,
				void **buf_ret);

extern int
wim_reshdr_to_data(const struct wim_reshdr *reshdr,
		   WIMStruct *wim, void **buf_ret);

extern int
read_stream_prefix(const struct wim_lookup_table_entry *lte,
		   u64 size, consume_data_callback_t cb,
		   u32 in_chunk_size, void *ctx_or_buf, int flags);

/* Functions to read a list of resources.  */

typedef int (*read_stream_list_begin_stream_t)(struct wim_lookup_table_entry *lte, void *ctx);
typedef int (*read_stream_list_end_stream_t)(struct wim_lookup_table_entry *lte, void *ctx);

extern int
read_stream_list(struct list_head *stream_list,
		 size_t list_head_offset,
		 read_stream_list_begin_stream_t begin_stream,
		 consume_data_callback_t consume_chunk,
		 read_stream_list_end_stream_t end_stream,
		 u32 cb_chunk_size,
		 void *cb_ctx);

/* Functions to extract a resource.  */

extern int
extract_stream(const struct wim_lookup_table_entry *lte,
	       u64 size,
	       consume_data_callback_t extract_chunk,
	       void *extract_chunk_arg);

extern int
extract_stream_to_fd(const struct wim_lookup_table_entry *lte,
		     struct filedes *fd, u64 size);

/* Miscellaneous resource functions.  */

extern int
sha1_stream(struct wim_lookup_table_entry *lte);

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
