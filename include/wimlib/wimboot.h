#ifndef _WIMBOOT_H_
#define _WIMBOOT_H_

#include "wimlib/types.h"

extern int
wimboot_set_pointer(const wchar_t *path, u64 data_source_id,
		    const u8 hash[20]);

extern int
wimboot_alloc_data_source_id(const wchar_t *wim_path, int image,
			     const wchar_t *target, u64 *data_source_id_ret);

#endif /* _WIMBOOT_H_ */
