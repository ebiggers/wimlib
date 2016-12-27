#ifndef _WIMLIB_XATTR_H
#define _WIMLIB_XATTR_H

#include <string.h>

#include "wimlib/endianness.h"
#include "wimlib/tagged_items.h"
#include "wimlib/util.h"

#undef HAVE_XATTR_SUPPORT
#if defined(HAVE_SYS_XATTR_H) && \
	defined(HAVE_LLISTXATTR) && defined(HAVE_LGETXATTR) && \
	defined(HAVE_FSETXATTR) && defined(HAVE_LSETXATTR)
#  define HAVE_XATTR_SUPPORT 1
#endif

/*
 * On-disk format of an entry in an extended attributes tagged item (wimlib
 * extension).  An xattr item consists of a series of variable-length xattr
 * name/value pairs, each of which begins with this header.
 *
 * Currently this is only used for Linux-style xattrs, but in the future we may
 * use this for Windows-style xattrs too.
 */
struct wimlib_xattr_entry {

	/* length of xattr name in bytes */
	le16 name_len;

	/* reserved, must be 0 */
	le16 reserved;

	/* length of xattr value in bytes */
	le32 value_len;

	/* followed by the xattr name with no terminating null */
	char name[0];

	/* followed by the xattr value with no terminating null */
	/* u8 value[0]; */

	/* then zero-padded to a 4-byte boundary */
} _aligned_attribute(4);

static inline size_t
xattr_entry_size(const struct wimlib_xattr_entry *entry)
{
	return ALIGN(sizeof(*entry) + le16_to_cpu(entry->name_len) +
		     le32_to_cpu(entry->value_len), 4);
}

static inline struct wimlib_xattr_entry *
xattr_entry_next(const struct wimlib_xattr_entry *entry)
{
	return (void *)entry + xattr_entry_size(entry);
}

/* Currently we use the Linux limits when validating xattr names and values */
#define XATTR_NAME_MAX 255
#define XATTR_SIZE_MAX 65536

static inline bool
valid_xattr_entry(const struct wimlib_xattr_entry *entry, size_t avail)
{
	if (avail < sizeof(*entry))
		return false;

	if (entry->name_len == 0 ||
	    le16_to_cpu(entry->name_len) > XATTR_NAME_MAX)
		return false;

	if (entry->reserved != 0)
		return false;

	if (le32_to_cpu(entry->value_len) > XATTR_SIZE_MAX)
		return false;

	if (avail < xattr_entry_size(entry))
		return false;

	if (memchr(entry->name, '\0', le16_to_cpu(entry->name_len)))
		return false;

	return true;
}

/* Is the xattr of the specified name security-related? */
static inline bool
is_security_xattr(const char *name)
{
#define XATTR_SECURITY_PREFIX "security."
#define XATTR_SYSTEM_PREFIX "system."
#define XATTR_POSIX_ACL_ACCESS  "posix_acl_access"
#define XATTR_NAME_POSIX_ACL_ACCESS XATTR_SYSTEM_PREFIX XATTR_POSIX_ACL_ACCESS
#define XATTR_POSIX_ACL_DEFAULT  "posix_acl_default"
#define XATTR_NAME_POSIX_ACL_DEFAULT XATTR_SYSTEM_PREFIX XATTR_POSIX_ACL_DEFAULT

	return !strncmp(name, XATTR_SECURITY_PREFIX,
			sizeof(XATTR_SECURITY_PREFIX) - 1) ||
	       !strcmp(name, XATTR_NAME_POSIX_ACL_ACCESS) ||
	       !strcmp(name, XATTR_NAME_POSIX_ACL_DEFAULT);
}

static inline const void *
inode_get_linux_xattrs(const struct wim_inode *inode, u32 *len_ret)
{
	return inode_get_tagged_item(inode, TAG_WIMLIB_LINUX_XATTRS, 0,
				     len_ret);
}

static inline bool
inode_has_linux_xattrs(const struct wim_inode *inode)
{
	return inode_get_linux_xattrs(inode, NULL) != NULL;
}

static inline bool
inode_set_linux_xattrs(struct wim_inode *inode, const void *entries, u32 len)
{
	return inode_set_tagged_data(inode, TAG_WIMLIB_LINUX_XATTRS,
				     entries, len);
}

#endif /* _WIMLIB_XATTR_H  */
