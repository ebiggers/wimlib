/*
 * lz_repsearch.c
 *
 * Fast searching for repeat offset matches.
 *
 * The author dedicates this file to the public domain.
 * You can do whatever you want with this file.
 *
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/lz_repsearch.h"
#include "wimlib/lz_extend.h"

u32
lz_extend_repmatch(const u8 *strptr, const u8 *matchptr, u32 max_len)
{
	return lz_extend(strptr, matchptr, 2, max_len);
}
