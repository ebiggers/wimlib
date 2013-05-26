#ifndef _WIMLIB_WRITE_H
#define _WIMLIB_WRITE_H

#include "wimlib.h"
#include "wimlib/types.h"

/* Internal use only */
#define WIMLIB_WRITE_FLAG_NO_LOOKUP_TABLE	0x80000000
#define WIMLIB_WRITE_FLAG_REUSE_INTEGRITY_TABLE 0x40000000
#define WIMLIB_WRITE_FLAG_CHECKPOINT_AFTER_XML  0x20000000
#define WIMLIB_WRITE_MASK_PUBLIC		0x1fffffff

extern int
begin_write(WIMStruct *wim, const tchar *path, int write_flags);

extern void
close_wim_writable(WIMStruct *wim);

extern int
finish_write(WIMStruct *wim, int image, int write_flags,
	     wimlib_progress_func_t progress_func);

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

#endif /* _WIMLIB_WRITE_H */
