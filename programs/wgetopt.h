#ifndef _WGETOPT_H
#define _WGETOPT_H

#include <wchar.h>

extern wchar_t *woptarg;
extern int woptind, wopterr, woptopt;

struct woption {
	const wchar_t *name;
	int	       has_arg;
	int	      *flag;
	int	       val;
};

#define no_argument 0
#define required_argument 1
#define optional_argument 2

extern int
wgetopt (int argc, wchar_t *const *argv, const wchar_t *optstring);

extern int
wgetopt_long(int argc, wchar_t * const *argv, const wchar_t *options,
	     const struct woption *long_options, int *opt_index);

extern int
wgetopt_long_only(int argc, wchar_t *const *argv, const wchar_t *options,
		  const struct woption *long_options, int *opt_index);

#endif
