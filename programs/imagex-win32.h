#ifndef _IMAGEX_WIN32_H
#define _IMAGEX_WIN32_H

#include <stddef.h>
#include <inttypes.h>

void
win32_print_security_descriptor(const uint8_t *sd, size_t size);

void
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
