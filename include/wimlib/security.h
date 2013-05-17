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
	 * interpreted as 8). */
	u32 total_length;

	/* The number of security descriptors in the array @descriptors. */
	u32 num_entries;

	/* Array of sizes of the descriptors, in bytes, in the array
	 * @descriptors. */
	size_t *sizes;

	/* Array of pointers to the security descriptors in the
	 * SECURITY_DESCRIPTOR_RELATIVE format. */
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
read_wim_security_data(const u8 metadata_resource[], size_t
		       metadata_resource_len, struct wim_security_data **sd_p);

extern u8 *
write_wim_security_data(const struct wim_security_data * restrict sd, u8 *
			restrict p);

extern void
print_wim_security_data(const struct wim_security_data *sd);

extern void
free_wim_security_data(struct wim_security_data *sd);

#endif /* _WIMLIB_SECURITY_H */
