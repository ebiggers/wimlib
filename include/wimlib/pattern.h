#ifndef _WIMLIB_PATTERN_H
#define _WIMLIB_PATTERN_H

#include "wimlib/types.h"

struct wim_dentry;

extern bool
match_path(const tchar *path, const tchar *pattern, bool prefix_ok);

extern int
expand_path_pattern(struct wim_dentry *root, const tchar *pattern,
		    int (*consume_dentry)(struct wim_dentry *, void *),
		    void *ctx);

#endif /* _WIMLIB_PATTERN_H  */
