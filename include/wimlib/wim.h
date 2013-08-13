#ifndef _WIMLIB_WIM_H
#define _WIMLIB_WIM_H

#include "wimlib/header.h"
#include "wimlib/types.h"
#include "wimlib/file_io.h"

struct wim_info;
struct wim_lookup_table;
struct wim_image_metadata;

/* The opaque structure exposed to the wimlib API. */
struct WIMStruct {

	/* File descriptor for the WIM file, opened for reading.  in_fd.fd is -1
	 * if the WIM file has not been opened or there is no associated file
	 * backing it yet. */
	struct filedes in_fd;

	/* File descriptor, opened either for writing only or for
	 * reading+writing, for the WIM file (if any) currently being written.
	 * */
	struct filedes out_fd;

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

	/* Have any images been deleted? */
	u8 deletion_occurred : 1;

	/* Do we know that all the stream reference counts in the WIM are
	 * correct?  If so, this is set to 1 and deletions are safe; otherwise
	 * this is set to 0 and deletions are not safe until reference counts
	 * are recalculated.  (This is due to a bug in M$'s software that
	 * generates WIMs with invalid reference counts.)  */
	u8 refcnts_ok : 1;

	u8 wim_locked : 1;

	/* One of WIMLIB_COMPRESSION_TYPE_*, cached from the header flags. */
	u8 compression_type : 2;
};

static inline bool wim_is_pipable(const WIMStruct *wim)
{
	return (wim->hdr.magic == PWM_MAGIC);
}

static inline bool wim_has_integrity_table(const WIMStruct *wim)
{
	return (wim->hdr.integrity.offset != 0);
}

extern void
wim_recalculate_refcnts(WIMStruct *wim);

extern int
init_wim_header(struct wim_header *hdr, int ctype);

extern int
read_wim_header(const tchar *filename, struct filedes *in_fd,
		struct wim_header *hdr);

extern int
write_wim_header(const struct wim_header *hdr, struct filedes *out_fd);

extern int
write_wim_header_at_offset(const struct wim_header *hdr, struct filedes *out_fd,
			   off_t offset);

extern int
write_wim_header_flags(u32 hdr_flags, struct filedes *out_fd);

extern int
rename_wim_path(WIMStruct *wim, const tchar *from, const tchar *to);

extern int
select_wim_image(WIMStruct *wim, int image);

extern int
for_image(WIMStruct *wim, int image, int (*visitor)(WIMStruct *));

extern int
wim_checksum_unhashed_streams(WIMStruct *wim);

extern int
reopen_wim(WIMStruct *wim);

/* Internal open flags (pass to open_wim_as_WIMStruct(), not wimlib_open_wim())
 */
#define WIMLIB_OPEN_FLAG_FROM_PIPE	0x80000000
#define WIMLIB_OPEN_MASK_PUBLIC		0x7fffffff

extern int
open_wim_as_WIMStruct(const void *wim_filename_or_fd, int open_flags,
		      WIMStruct **wim_ret,
		      wimlib_progress_func_t progress_func);

extern int
close_wim(WIMStruct *wim);

extern int
can_modify_wim(WIMStruct *wim);

extern int
can_delete_from_wim(WIMStruct *wim);

#endif /* _WIMLIB_WIM_H */
