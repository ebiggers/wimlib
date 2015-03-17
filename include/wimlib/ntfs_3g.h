#ifndef _WIMLIB_NTFS_3G_H
#define _WIMLIB_NTFS_3G_H

#include "wimlib/callback.h"
#include "wimlib/types.h"

struct blob_descriptor;
struct _ntfs_volume;

#ifdef WITH_NTFS_3G
struct _ntfs_volume;
struct ntfs_location {
	struct _ntfs_volume *ntfs_vol;
	char *path;
	utf16lechar *attr_name;
	unsigned attr_name_nchars;
	unsigned attr_type;
};
#endif

extern void
libntfs3g_global_init(void);

extern int
read_ntfs_attribute_prefix(const struct blob_descriptor *blob, u64 size,
			   consume_data_callback_t cb, void *cb_ctx);

extern int
do_ntfs_umount(struct _ntfs_volume *vol);

#endif
