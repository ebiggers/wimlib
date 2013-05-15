#ifndef _WIMLIB_VERSION_H
#define _WIMLIB_VERSION_H

#include "wimlib.h"

#define WIMLIB_MAKEVERSION(major, minor, patch) \
	((major << 20) | (minor << 10) | patch)


#define WIMLIB_VERSION_CODE \
		WIMLIB_MAKEVERSION(WIMLIB_MAJOR_VERSION,\
				   WIMLIB_MINOR_VERSION,\
				   WIMLIB_PATCH_VERSION)

#define WIMLIB_GET_PATCH_VERSION(version) \
	((version >> 0) & ((1 << 10) - 1))
#define WIMLIB_GET_MINOR_VERSION(version) \
	((version >> 10) & ((1 << 10) - 1))
#define WIMLIB_GET_MAJOR_VERSION(version) \
	((version >> 20) & ((1 << 10) - 1))

#endif /* _WIMLIB_VERSION_H */
