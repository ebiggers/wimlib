#ifndef _WIMLIB_WIN32_H
#define _WIMLIB_WIN32_H

#include "wimlib_internal.h"
#include <direct.h>
#include <windef.h>

extern int
win32_build_dentry_tree(struct wim_dentry **root_ret,
			const mbchar *root_disk_path,
			struct wim_lookup_table *lookup_table,
			struct wim_security_data *sd,
			const struct capture_config *config,
			int add_image_flags,
			wimlib_progress_func_t progress_func,
			void *extra_arg);

extern int
win32_read_file(const mbchar *filename, void *handle, u64 offset,
		size_t size, void *buf);

extern HANDLE
win32_open_file_readonly(const wchar_t *path_utf16, bool data_only);

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
fnmatch(const mbchar *pattern, const mbchar *string, int flags);

extern int
win32_do_apply_dentry(const mbchar *output_path,
		      size_t output_path_len,
		      struct wim_dentry *dentry,
		      struct apply_args *args);

extern int
win32_do_apply_dentry_timestamps(const mbchar *output_path,
				 size_t output_path_len,
				 const struct wim_dentry *dentry,
				 const struct apply_args *args);

extern int
fsync(int fd);

extern unsigned
win32_get_number_of_processors();

extern mbchar *
realpath(const mbchar *path, mbchar *resolved_path);

/* Microsoft's swprintf() violates the C standard and they require programmers
 * to do this weird define to get the correct function.  */
#define swprintf _snwprintf

/* Use Microsoft's weird _mkdir() function instead of mkdir() */
#define mkdir(name, mode) _mkdir(name)

typedef enum {
	CODESET
} nl_item;

extern char *
nl_langinfo(nl_item item);

extern int rename_replacement(const char *oldpath, const char *newpath);
#define rename(oldpath, newpath) rename_replacement(oldpath, newpath)

#endif /* _WIMLIB_WIN32_H */
