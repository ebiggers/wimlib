#ifndef _WIMLIB_CAPTURE_H
#define _WIMLIB_CAPTURE_H

#include "wimlib.h"
#include "wimlib/inode_table.h"
#include "wimlib/list.h"
#include "wimlib/progress.h"
#include "wimlib/security.h"
#include "wimlib/textfile.h"
#include "wimlib/util.h"

struct blob_table;
struct wim_dentry;
struct wim_inode;

struct capture_config {
	struct string_set exclusion_pats;
	struct string_set exclusion_exception_pats;
	void *buf;
};

/* Common parameters to implementations of building an in-memory dentry tree
 * from an on-disk directory structure. */
struct capture_params {
	/* Pointer to the blob table of the WIM.  */
	struct blob_table *blob_table;

	/* List of blobs that have been added so far, but without their SHA-1
	 * message digests being calculated (as a shortcut).  */
	struct list_head *unhashed_blobs;

	/* Hash table of inodes that have been captured for this tree so far. */
	struct wim_inode_table *inode_table;

	/* The set of security descriptors that have been captured for this
	 * image so far. */
	struct wim_sd_set *sd_set;

	/* Pointer to the capture configuration.  */
	struct capture_config *config;

	/* Flags that affect the capture operation (WIMLIB_ADD_FLAG_*) */
	int add_flags;

	/* If non-NULL, the user-supplied progress function. */
	wimlib_progress_func_t progfunc;
	void *progctx;

	/* Progress data.  */
	union wimlib_progress_info progress;

	/* The capture implementation must set this to the number of characters
	 * that try_exclude() will strip from the path before testing exclusion
	 * patterns from the capture configuration file.  */
	size_t capture_root_nchars;

	/* Can be used by the capture implementation.  */
	u64 capture_root_ino;
	u64 capture_root_dev;
};

/* capture_common.c */

extern int
do_capture_progress(struct capture_params *params, int status,
		    const struct wim_inode *inode);

extern int
mangle_pat(tchar *pat, const tchar *path, unsigned long line_no);

extern int
read_capture_config(const tchar *config_file, const void *buf,
		    size_t bufsize, struct capture_config *config);

extern void
destroy_capture_config(struct capture_config *config);

extern bool
match_pattern_list(const tchar *path, size_t path_nchars,
		   const struct string_set *list);

extern int
try_exclude(const tchar *full_path, size_t full_path_nchars,
	    const struct capture_params *params);

typedef int (*capture_tree_t)(struct wim_dentry **, const tchar *,
			      struct capture_params *);

#ifdef WITH_NTFS_3G
/* ntfs-3g_capture.c */
extern int
ntfs_3g_build_dentry_tree(struct wim_dentry **root_ret,
			  const tchar *device,
			  struct capture_params *params);
#endif

#ifdef __WIN32__
/* win32_capture.c */
extern int
win32_build_dentry_tree(struct wim_dentry **root_ret,
			const tchar *root_disk_path,
			struct capture_params *params);
#define platform_default_capture_tree win32_build_dentry_tree
#else
/* unix_capture.c */
extern int
unix_build_dentry_tree(struct wim_dentry **root_ret,
		       const tchar *root_disk_path,
		       struct capture_params *params);
#define platform_default_capture_tree unix_build_dentry_tree
#endif

#define WIMLIB_ADD_FLAG_ROOT	0x80000000

static inline int
report_capture_error(struct capture_params *params, int error_code,
		     const tchar *path)
{
	return report_error(params->progfunc, params->progctx, error_code, path);
}

#endif /* _WIMLIB_CAPTURE_H */
