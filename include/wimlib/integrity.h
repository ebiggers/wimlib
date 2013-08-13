#ifndef _WIMLIB_INTEGRITY_H
#define _WIMLIB_INTEGRITY_H

#include "wimlib.h"
#include <sys/types.h>

#define WIM_INTEGRITY_OK 0
#define WIM_INTEGRITY_NOT_OK -1
#define WIM_INTEGRITY_NONEXISTENT -2

extern int
write_integrity_table(WIMStruct *wim,
		      off_t new_lookup_table_end,
		      off_t old_lookup_table_end,
		      wimlib_progress_func_t progress_func);

extern int
check_wim_integrity(WIMStruct *wim, wimlib_progress_func_t progress_func);

#endif /* _WIMLIB_INTEGRITY_H */
