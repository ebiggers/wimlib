#ifndef _WIMLIB_REPARSE_H
#define _WIMLIB_REPARSE_H

#include <sys/types.h>

#include "wimlib/types.h"

struct wim_inode;
struct blob_table;
struct blob_descriptor;

#define REPARSE_POINT_MAX_SIZE (16 * 1024)

/* On-disk format of reparse point buffer  */
struct reparse_buffer_disk {
	le32 rptag;
	le16 rpdatalen;
	le16 rpreserved;
	union {
		u8 rpdata[REPARSE_POINT_MAX_SIZE - 8];

		struct {
			le16 substitute_name_offset;
			le16 substitute_name_nbytes;
			le16 print_name_offset;
			le16 print_name_nbytes;
			le32 rpflags;
			u8 data[REPARSE_POINT_MAX_SIZE - 20];
		} _packed_attribute symlink;

		struct {
			le16 substitute_name_offset;
			le16 substitute_name_nbytes;
			le16 print_name_offset;
			le16 print_name_nbytes;
			u8 data[REPARSE_POINT_MAX_SIZE - 16];
		} _packed_attribute junction;
	};
} _packed_attribute;

#define REPARSE_DATA_OFFSET (offsetof(struct reparse_buffer_disk, rpdata))

#define REPARSE_DATA_MAX_SIZE (REPARSE_POINT_MAX_SIZE - REPARSE_DATA_OFFSET)


/* Structured format for symbolic link, junction point, or mount point reparse
 * data. */
struct reparse_data {
	/* Reparse point tag (see WIM_IO_REPARSE_TAG_* values) */
	u32 rptag;

	/* Length of reparse data, not including the 8-byte header (ReparseTag,
	 * ReparseDataLength, ReparseReserved) */
	u16 rpdatalen;

	/* ReparseReserved */
	u16 rpreserved;

	/* Flags (only for WIM_IO_REPARSE_TAG_SYMLINK reparse points).
	 * SYMBOLIC_LINK_RELATIVE means this is a relative symbolic link;
	 * otherwise should be set to 0. */
#define SYMBOLIC_LINK_RELATIVE 0x00000001
	u32 rpflags;

	/* Pointer to the substitute name of the link (UTF-16LE). */
	utf16lechar *substitute_name;

	/* Pointer to the print name of the link (UTF-16LE). */
	utf16lechar *print_name;

	/* Number of bytes of the substitute name, not including null terminator
	 * if present */
	u16 substitute_name_nbytes;

	/* Number of bytes of the print name, not including null terminator if
	 * present */
	u16 print_name_nbytes;
};

extern int
parse_reparse_data(const u8 * restrict rpbuf, u16 rpbuflen,
		   struct reparse_data * restrict rpdata);

extern int
make_reparse_buffer(const struct reparse_data * restrict rpdata,
		    u8 * restrict rpbuf,
		    u16 * restrict rpbuflen_ret);

#ifndef __WIN32__
ssize_t
wim_inode_readlink(const struct wim_inode * restrict inode, char * restrict buf,
		   size_t buf_len, const struct blob_descriptor *blob);

extern int
wim_inode_set_symlink(struct wim_inode *inode, const char *target,
		      struct blob_table *blob_table);
#endif

#endif /* _WIMLIB_REPARSE_H */
