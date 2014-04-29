#ifndef _WIMLIB_WILDCARD_H
#define _WIMLIB_WILDCARD_H

#include <wimlib/types.h>

struct wim_dentry;

#define WILDCARD_FLAG_WARN_IF_NO_MATCH		0x00000001
#define WILDCARD_FLAG_ERROR_IF_NO_MATCH		0x00000002
#define WILDCARD_FLAG_CASE_INSENSITIVE		0x00000004

extern int
expand_wildcard(WIMStruct *wim,
		const tchar *wildcard_path,
		int (*consume_dentry)(struct wim_dentry *, void *),
		void *consume_dentry_ctx,
		u32 flags);

extern bool
match_path(const tchar *path, size_t path_nchars,
	   const tchar *wildcard, tchar path_sep, bool prefix_ok);

#endif /* _WIMLIB_WILDCARD_H  */
