#ifndef _IMAGEX_WIN32_H
#define _IMAGEX_WIN32_H

#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <wchar.h>

extern wchar_t *
win32_mbs_to_wcs(const char *mbs, size_t mbs_nbytes, size_t *num_wchars_ret);

extern void
win32_print_security_descriptor(const uint8_t *sd, size_t size);

extern void
set_fd_to_binary_mode(int fd);

#include "wgetopt.h"

#define optarg			woptarg
#define optind			woptind
#define opterr			wopterr
#define optopt			woptopt
#define option			woption

#define getopt_long_only	wgetopt_long_only
#define getopt_long		wgetopt_long
#define getopt			wgetopt

#endif
