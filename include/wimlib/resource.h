#ifndef _WIMLIB_RESOURCE_H
#define _WIMLIB_RESOURCE_H

#include "wimlib/types.h"
#include "wimlib/callback.h"

struct wim_lookup_table_entry;
struct wim_image_metadata;

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

/* Nonzero if a struct resource_entry indicates a compressed resource. */
static inline int
resource_is_compressed(const struct resource_entry *entry)
{
	return (entry->flags & WIM_RESHDR_FLAG_COMPRESSED);
}

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

#define WIMLIB_RESOURCE_FLAG_RAW		0x1
#define WIMLIB_RESOURCE_FLAG_RECOMPRESS		0x2

extern int
read_resource_prefix(const struct wim_lookup_table_entry *lte,
		     u64 size, consume_data_callback_t cb, void *ctx_or_buf,
		     int flags);

extern void
get_resource_entry(const struct resource_entry_disk *disk_entry,
		   struct resource_entry *entry);

extern void
put_resource_entry(const struct resource_entry *entry,
		   struct resource_entry_disk *disk_entry);

extern int
read_partial_wim_resource_into_buf(const struct wim_lookup_table_entry *lte,
				   size_t size, u64 offset, void *buf);
extern int
read_full_resource_into_buf(const struct wim_lookup_table_entry *lte, void *buf);

extern int
write_wim_resource(struct wim_lookup_table_entry *lte, int out_fd,
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
copy_resource(struct wim_lookup_table_entry *lte, void *wim);

extern int
read_metadata_resource(WIMStruct *wim,
		       struct wim_image_metadata *image_metadata);

extern int
write_metadata_resource(WIMStruct *wim);

#endif /* _WIMLIB_RESOURCE_H */
