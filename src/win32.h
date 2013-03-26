#ifndef _WIMLIB_WIN32_H
#define _WIMLIB_WIN32_H

#include "wimlib_internal.h"
#include <direct.h>
#include <windef.h>

extern int
win32_build_dentry_tree(struct wim_dentry **root_ret,
			const tchar *root_disk_path,
			struct wim_lookup_table *lookup_table,
			struct sd_set *sd,
			const struct capture_config *config,
			int add_image_flags,
			wimlib_progress_func_t progress_func,
			void *extra_arg);

extern int
win32_read_file(const tchar *filename, HANDLE handle,
		u64 offset, size_t size, void *buf);

extern HANDLE
win32_open_file_data_only(const wchar_t *path_utf16);

extern void
win32_close_file(void *handle);

#ifdef ENABLE_ERROR_MESSAGES
extern void win32_error(u32 err);
extern void win32_error_last();
#else
#  define win32_error(err)
#  define win32_error_last()
#endif

#define FNM_PATHNAME 0x1
#define FNM_NOMATCH 1
extern int
fnmatch(const tchar *pattern, const tchar *string, int flags);

extern int
win32_do_apply_dentry(const tchar *output_path,
		      size_t output_path_nbytes,
		      struct wim_dentry *dentry,
		      struct apply_args *args);

extern int
win32_do_apply_dentry_timestamps(const tchar *output_path,
				 size_t output_path_nbytes,
				 const struct wim_dentry *dentry,
				 const struct apply_args *args);

extern int
fsync(int fd);

extern unsigned
win32_get_number_of_processors();

extern tchar *
realpath(const tchar *path, tchar *resolved_path);

typedef enum {
	CODESET
} nl_item;

extern int
win32_rename_replacement(const tchar *oldpath, const tchar *newpath);

extern int
win32_truncate_replacement(const tchar *path, off_t size);

extern void
win32_global_init();

extern void
win32_global_cleanup();

#endif /* _WIMLIB_WIN32_H */
