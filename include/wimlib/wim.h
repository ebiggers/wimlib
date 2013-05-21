#ifndef _WIMLIB_WIM_H
#define _WIMLIB_WIM_H

#include "wimlib/header.h"
#include "wimlib/types.h"

struct wim_info;
struct wim_lookup_table;
struct wim_image_metadata;

/* The opaque structure exposed to the wimlib API. */
struct WIMStruct {

	/* File descriptor for the WIM file, opened for reading, or -1 if it has
	 * not been opened or there is no associated file backing it yet. */
	int in_fd;

	/* File descriptor, opened either for writing only or for
	 * reading+writing, for the WIM file (if any) currently being written.
	 * */
	int out_fd;

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

	u8 all_images_verified : 1;
	u8 wim_locked : 1;
};

extern int
wim_run_full_verifications(WIMStruct *w);

extern int
read_header(const tchar *filename, int in_fd, struct wim_header *hdr,
	    int split_ok);

extern int
write_header(const struct wim_header *hdr, int out_fd);

extern int
init_header(struct wim_header *hdr, int ctype);


extern int
rename_wim_path(WIMStruct *wim, const tchar *from, const tchar *to);

extern int
select_wim_image(WIMStruct *w, int image);

extern int
for_image(WIMStruct *w, int image, int (*visitor)(WIMStruct *));

extern int
wim_checksum_unhashed_streams(WIMStruct *w);

extern int
reopen_wim(WIMStruct *w);

extern int
close_wim(WIMStruct *w);

extern int
can_modify_wim(WIMStruct *wim);

extern int
can_delete_from_wim(WIMStruct *wim);

#endif /* _WIMLIB_WIM_H */
