#ifndef _WIMLIB_NTFS_3G_H
#define _WIMLIB_NTFS_3G_H

#include "wimlib/callback.h"
#include "wimlib/types.h"

struct wim_lookup_table_entry;
struct _ntfs_volume;

extern void
libntfs3g_global_init(void);

extern int
read_ntfs_file_prefix(const struct wim_lookup_table_entry *lte,
		      u64 size,
		      consume_data_callback_t cb,
		      u32 in_chunk_size,
		      void *ctx_or_buf,
		      int _ignored_flags);


extern int
do_ntfs_umount(struct _ntfs_volume *vol);

#endif
