#ifndef _WIMLIB_OBJECT_ID_H
#define _WIMLIB_OBJECT_ID_H

#include "wimlib/types.h"

extern bool
inode_has_object_id(const struct wim_inode *inode);

extern const void *
inode_get_object_id(const struct wim_inode *inode, u32 *len_ret);

extern bool
inode_set_object_id(struct wim_inode *inode, const void *object_id, u32 len);

#endif /* _WIMLIB_OBJECT_ID_H  */
