#ifndef _WIMLIB_PATHS_H
#define _WIMLIB_PATHS_H

#include "wimlib/compiler.h"
#include "wimlib/types.h"

const tchar *
path_basename(const tchar *path);

const tchar *
path_basename_with_len(const tchar *path, size_t len);

extern const tchar *
path_stream_name(const tchar *path);

extern void
do_canonicalize_path(const tchar *in, tchar *out);

extern tchar *
canonicalize_wim_path(const tchar *wim_path) _malloc_attribute;

#endif /* _WIMLIB_PATHS_H */
