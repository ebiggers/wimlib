#ifndef _WIMLIB_WRITE_H
#define _WIMLIB_WRITE_H

#include "wimlib.h"
#include "wimlib/types.h"

/* Internal use only */
#define WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE		0x80000000
#define WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML		0x40000000
#define WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE		0x20000000
#define WIMLIB_WRITE_FLAG_HEADER_AT_END			0x10000000
#define WIMLIB_WRITE_FLAG_FILE_DESCRIPTOR		0x08000000
#define WIMLIB_WRITE_FLAG_USE_EXISTING_TOTALBYTES	0x04000000
#define WIMLIB_WRITE_FLAG_NO_METADATA			0x02000000
#define WIMLIB_WRITE_FLAG_OVERWRITE			0x01000000
#define WIMLIB_WRITE_MASK_PUBLIC			0x00ffffff

#if defined(HAVE_SYS_FILE_H) && defined(HAVE_FLOCK)
extern int
lock_wim(WIMStruct *wim, int fd);
#else
static inline int
lock_wim(WIMStruct *wim, int fd)
{
	return 0;
}
#endif

struct list_head;

int
write_wim_part(WIMStruct *wim,
	       const void *path_or_fd,
	       int image,
	       int write_flags,
	       unsigned num_threads,
	       wimlib_progress_func_t progress_func,
	       unsigned part_number,
	       unsigned total_parts,
	       struct list_head *stream_list_override,
	       const u8 *guid);

#endif /* _WIMLIB_WRITE_H */
