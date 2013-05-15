#ifndef _WIMLIB_REPARSE_H
#define _WIMLIB_REPARSE_H

#include "wimlib/types.h"

struct wim_inode;
struct wim_lookup_table;

#define REPARSE_POINT_MAX_SIZE (16 * 1024)

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

enum {
	SUBST_NAME_IS_RELATIVE_LINK = -1,
	SUBST_NAME_IS_VOLUME_JUNCTION = -2,
	SUBST_NAME_IS_UNKNOWN = -3,
};
extern int
parse_substitute_name(const utf16lechar *substitute_name,
		      u16 substitute_name_nbytes,
		      u32 rptag);

extern int
parse_reparse_data(const u8 *rpbuf, u16 rpbuflen, struct reparse_data *rpdata);

extern int
make_reparse_buffer(const struct reparse_data *rpdata, u8 *buf);

extern int
wim_inode_get_reparse_data(const struct wim_inode *inode, u8 *rpbuf);

#ifndef __WIN32__
ssize_t
wim_inode_readlink(const struct wim_inode *inode, char *buf, size_t buf_len);

extern int
wim_inode_set_symlink(struct wim_inode *inode, const char *target,
		      struct wim_lookup_table *lookup_table);
#endif

extern tchar *
capture_fixup_absolute_symlink(tchar *dest,
			       u64 capture_root_ino, u64 capture_root_dev);

#endif /* _WIMLIB_REPARSE_H */
