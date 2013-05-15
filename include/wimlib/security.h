#ifndef _WIMLIB_SECURITY_H
#define _WIMLIB_SECURITY_H

#include "wimlib/rbtree.h"
#include "wimlib/types.h"

/* Red-black tree that maps SHA1 message digests of security descriptors to
 * security IDs, which are themselves indices into the table of security
 * descriptors in the 'struct wim_security_data'. */
struct wim_sd_set {
	struct wim_security_data *sd;
	struct rb_root rb_root;
	int32_t orig_num_entries;
};

/* Table of security descriptors for a WIM image. */
struct wim_security_data {
	/* The total length of the security data, in bytes.  If there are no
	 * security descriptors, this field, when read from the on-disk metadata
	 * resource, may be either 8 (which is correct) or 0 (which is
	 * interpreted as 0). */
	u32 total_length;

	/* The number of security descriptors in the array @descriptors, below.
	 * It is really an unsigned int on-disk, but it must fit into an int
	 * because the security ID's are signed.  (Not like you would ever have
	 * more than a few hundred security descriptors anyway.) */
	int32_t num_entries;

	/* Array of sizes of the descriptors in the array @descriptors. */
	u64 *sizes;

	/* Array of descriptors. */
	u8 **descriptors;
};

extern void
destroy_sd_set(struct wim_sd_set *sd_set, bool rollback);

extern int
lookup_sd(struct wim_sd_set *set, const u8 hash[]);

extern int
sd_set_add_sd(struct wim_sd_set *sd_set, const char descriptor[],
	      size_t size);

extern int
init_sd_set(struct wim_sd_set *sd_set, struct wim_security_data *sd);

extern struct wim_security_data *
new_wim_security_data(void);

extern int
read_security_data(const u8 metadata_resource[],
		   u64 metadata_resource_len, struct wim_security_data **sd_p);
extern void
print_security_data(const struct wim_security_data *sd);

extern u8 *
write_security_data(const struct wim_security_data *sd, u8 *p);

extern void
free_security_data(struct wim_security_data *sd);

#endif /* _WIMLIB_SECURITY_H */
