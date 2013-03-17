#ifndef _WIMLIB_WIN32_H
#define _WIMLIB_WIN32_H

#include "wimlib_internal.h"
#include <direct.h>

extern void win32_release_capture_privileges();
extern void win32_acquire_capture_privileges();

extern void win32_release_restore_privileges();
extern void win32_acquire_restore_privileges();

extern int win32_build_dentry_tree(struct wim_dentry **root_ret,
				   const char *root_disk_path,
				   struct wim_lookup_table *lookup_table,
				   struct wim_security_data *sd,
				   const struct capture_config *config,
				   int add_image_flags,
				   wimlib_progress_func_t progress_func,
				   void *extra_arg);

extern int win32_read_file(const char *filename, void *handle, u64 offset,
			   size_t size, u8 *buf);
extern void *win32_open_file_readonly(const void *path_utf16);
extern void win32_close_file(void *handle);

#ifdef ENABLE_ERROR_MESSAGES
extern void win32_error(u32 err);
#else
#  define win32_error(err)
#endif

#define FNM_PATHNAME 0x1
#define FNM_NOMATCH 1
extern int fnmatch(const char *pattern, const char *string, int flags);

#define mkdir(name, mode) _mkdir(name)

extern int win32_apply_dentry(const char *output_path,
			      size_t output_path_len,
			      const struct wim_dentry *dentry,
			      struct apply_args *args);

extern int win32_apply_dentry_timestamps(const char *output_path,
					 size_t output_path_len,
					 const struct wim_dentry *dentry,
					 const struct apply_args *args);

extern int fsync(int fd);

extern unsigned win32_get_number_of_processors();

#endif /* _WIMLIB_WIN32_H */
