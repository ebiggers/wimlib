/*
 *
 * Macros and structures for security descriptors
 *
 * From Microsoft's public documentation and the WINE project
 */

#include "util.h"
#include "rbtree.h"
#include "sha1.h"

#ifndef _WIMLIB_SECURITY_H
#define _WIMLIB_SECURITY_H

#if defined(WITH_NTFS_3G) || defined(__WIN32__)
/* Red-black tree that maps SHA1 message digests of security descriptors to
 * security IDs, which are themselves indices into the table of security
 * descriptors in the 'struct wim_security_data'. */
struct sd_set {
	struct wim_security_data *sd;
	struct rb_root rb_root;
};
void destroy_sd_set(struct sd_set *sd_set);
int lookup_sd(struct sd_set *set, const u8 hash[SHA1_HASH_SIZE]);
int sd_set_add_sd(struct sd_set *sd_set, const char descriptor[],
		  size_t size);
#endif

#endif /* _WIMLIB_SECURITY_H */
