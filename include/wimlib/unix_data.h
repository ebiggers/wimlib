#ifndef _WIMLIB_UNIX_DATA_H
#define _WIMLIB_UNIX_DATA_H

#include "wimlib/types.h"

struct wimlib_unix_data {
	u32 uid;
	u32 gid;
	u32 mode;
	u32 reserved;
};

struct wimlib_unix_data_disk {
	le32 uid;
	le32 gid;
	le32 mode;
	le32 reserved;
};

#endif /* _WIMLIB_UNIX_DATA_H  */
