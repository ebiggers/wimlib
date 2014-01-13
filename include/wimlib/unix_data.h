#ifndef _WIMLIB_UNIX_DATA_H
#define _WIMLIB_UNIX_DATA_H

#include "wimlib/types.h"
struct wim_inode;
struct wim_lookup_table;

#define WIMLIB_UNIX_DATA_TAG "$$__wimlib_UNIX_data"
#define WIMLIB_UNIX_DATA_TAG_NBYTES (sizeof(WIMLIB_UNIX_DATA_TAG) - 1)

#define WIMLIB_UNIX_DATA_TAG_UTF16LE "$\0$\0_\0_\0w\0i\0m\0l\0i\0b\0_\0U\0N\0I\0X\0_\0d\0a\0t\0a\0"
#define WIMLIB_UNIX_DATA_TAG_UTF16LE_NBYTES (sizeof(WIMLIB_UNIX_DATA_TAG_UTF16LE) - 1)

extern bool
inode_has_unix_data(const struct wim_inode *inode);

#ifndef __WIN32__
/* Format for special alternate data stream entries to store UNIX data for files
 * and directories (see: WIMLIB_ADD_FLAG_UNIX_DATA) */
struct wimlib_unix_data {
	u16 version; /* Must be 0 */
	u16 uid;
	u16 gid;
	u16 mode;
} _packed_attribute;

#define NO_UNIX_DATA (-1)
#define BAD_UNIX_DATA (-2)
extern int
inode_get_unix_data(const struct wim_inode *inode,
		    struct wimlib_unix_data *unix_data,
		    u16 *stream_idx_ret);

#define UNIX_DATA_UID    0x1
#define UNIX_DATA_GID    0x2
#define UNIX_DATA_MODE   0x4
#define UNIX_DATA_ALL    (UNIX_DATA_UID | UNIX_DATA_GID | UNIX_DATA_MODE)
#define UNIX_DATA_CREATE 0x8
extern int
inode_set_unix_data(struct wim_inode *inode, u16 uid, u16 gid, u16 mode,
		    struct wim_lookup_table *lookup_table, int which);

#endif /* __WIN32__  */

#endif /* _WIMLIB_UNIX_DATA_H  */
