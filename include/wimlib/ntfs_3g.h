#ifndef _WIMLIB_NTFS_3G_H
#define _WIMLIB_NTFS_3G_H

#include "wimlib/callback.h"
#include "wimlib/types.h"

struct wim_lookup_table_entry;
struct _ntfs_volume;

#ifdef WITH_NTFS_3G
struct _ntfs_volume;
struct ntfs_location {
	tchar *path;
	utf16lechar *stream_name;
	u16 stream_name_nchars;
	struct _ntfs_volume *ntfs_vol;
	bool is_reparse_point;
};
#endif

extern void
libntfs3g_global_init(void);

extern int
read_ntfs_file_prefix(const struct wim_lookup_table_entry *lte,
		      u64 size,
		      consume_data_callback_t cb,
		      void *cb_ctx);


extern int
do_ntfs_umount(struct _ntfs_volume *vol);

#endif
