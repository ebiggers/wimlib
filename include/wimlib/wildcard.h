#ifndef _WIMLIB_WILDCARD_H
#define _WIMLIB_WILDCARD_H

#include <wimlib/types.h>

#define WILDCARD_FLAG_USE_LITERAL_IF_NO_MATCHES	0x00000001
#define WILDCARD_FLAG_WARN_IF_NO_MATCH		0x00000002
#define WILDCARD_FLAG_ERROR_IF_NO_MATCH		0x00000004
#define WILDCARD_FLAG_CASE_INSENSITIVE		0x00000008

extern int
expand_wildcard_wim_paths(WIMStruct *wim,
			  const tchar * const *wildcards,
			  size_t num_wildcards,
			  tchar ***expanded_paths_ret,
			  size_t *num_expanded_paths_ret,
			  u32 flags);

#ifdef __WIN32__
extern int
fnmatch(const tchar *pattern, const tchar *string, int flags);
#  define FNM_CASEFOLD 0x1
#  define FNM_PATHNAME 0x2
#  define FNM_NOESCAPE 0x4
#  define FNM_NOMATCH 1
#else
#  include <fnmatch.h>
#  ifndef FNM_CASEFOLD
#    warning "FNM_CASEFOLD not defined!"
#    define FNM_CASEFOLD 0
#  endif
#endif

#endif /* _WIMLIB_WILDCARD_H  */
