#ifndef _WIMLIB_APPLY_H
#define _WIMLIB_APPLY_H

#include "wimlib/types.h"
#include "wimlib/list.h"
#include "wimlib.h"

struct wim_lookup_table_entry;
struct wimlib_unix_data;
struct wim_dentry;
struct apply_ctx;

/* Path to extracted file, or "cookie" identifying the file (e.g. inode number).
 * */
typedef union {
	const tchar *path;
	u64 cookie;
} file_spec_t;

/*
 * struct apply_operations -  Callback functions for a specific extraction
 * mode/backend.  These are lower-level functions that are called by the generic
 * code in extract.c.
 *
 * Unless otherwise specified, the callbacks in this structure are expected to
 * return 0 on success or a WIMLIB_ERR_* value on failure as well as set errno.
 * When possible, error messages should NOT be printed as they are handled by
 * the generic code.
 *
 * Many callbacks are optional, but to extract the most data from the WIM
 * format, as many as possible should be provided, and the corresponding
 * features should be marked as supported in start_extract().
 */
struct apply_operations {

	/* OPTIONAL:  Name of this extraction mode.  */
	const tchar *name;

	/* REQUIRED:  Fill in ctx->supported_features with nonzero values for
	 * features supported by the extraction mode and volume.  This callback
	 * can also be used to do any setup needed to access the volume.  */
	int (*start_extract)
		(const tchar *path, struct apply_ctx *ctx);

	/* OPTIONAL:  If root_directory_is_special is set:  provide this
	 * callback to determine whether the path corresponds to the root of the
	 * target volume (%true) or not (%false).  */
	bool (*target_is_root)
		(const tchar *target);

	/* REQUIRED:  Create a file.  */
	int (*create_file)
		(const tchar *path, struct apply_ctx *ctx, u64 *cookie_ret);

	/* REQUIRED:  Create a directory.  */
	int (*create_directory)
		(const tchar *path, struct apply_ctx *ctx, u64 *cookie_ret);

	/* OPTIONAL:  Create a hard link.  In start_extract(), set
	 * ctx->supported_features.hard_links if supported.  */
	int (*create_hardlink)
		(const tchar *oldpath, const tchar *newpath,
		 struct apply_ctx *ctx);

	/* OPTIONAL:  Create a symbolic link.  In start_extract(), set
	 * ctx->supported_features.symlink_reparse_points if supported.  */
	int (*create_symlink)
		(const tchar *oldpath, const tchar *newpath,
		 struct apply_ctx *ctx);

	/* REQUIRED:  Extract unnamed data stream.  */
	int (*extract_unnamed_stream)
		(file_spec_t file, struct wim_lookup_table_entry *lte,
		 struct apply_ctx *ctx);

	/* OPTIONAL:  Extracted named data stream.  In start_extract(), set
	 * ctx->supported_features.alternate_data_streams if supported.  */
	int (*extract_named_stream)
		(file_spec_t file, const utf16lechar *stream_name,
		 size_t stream_name_nchars, struct wim_lookup_table_entry *lte,
		 struct apply_ctx *ctx);

	/* OPTIONAL:  Extracted encrypted stream.  In start_extract(), set
	 * ctx->supported_features.encrypted_files if supported.  */
	int (*extract_encrypted_stream)
		(file_spec_t file, struct wim_lookup_table_entry *lte,
		 struct apply_ctx *ctx);

	/* OPTIONAL:  Set file attributes.  Calling code calls this if non-NULL.
	 */
	int (*set_file_attributes)
		(const tchar *path, u32 attributes, struct apply_ctx *ctx,
		 unsigned pass);

	/* OPTIONAL:  Set reparse data.  In start_extract(), set
	 * ctx->supported_features.reparse_data if supported.  */
	int (*set_reparse_data)
		(const tchar *path, const u8 *rpbuf, u16 rpbuflen,
		 struct apply_ctx *ctx);

	/* OPTIONAL:  Set short (DOS) filename.  In start_extract(), set
	 * ctx->supported_features.short_name if supported.  */
	int (*set_short_name)
		(const tchar *path, const utf16lechar *short_name,
		 size_t short_name_nchars, struct apply_ctx *ctx);

	/* OPTIONAL:  Set Windows NT security descriptor.  In start_extract(),
	 * set ctx->supported_features.security_descriptors if supported.  */
	int (*set_security_descriptor)
		(const tchar *path, const u8 *desc, size_t desc_size,
		 struct apply_ctx *ctx);

	/* OPTIONAL:  Set wimlib-specific UNIX data.  In start_extract(), set
	 * ctx->supported_features.unix_data if supported.  */
	int (*set_unix_data)
		(const tchar *path, const struct wimlib_unix_data *data,
		 struct apply_ctx *ctx);

	/* OPTIONAL:  Set timestamps.  Calling code calls this if non-NULL.  */
	int (*set_timestamps)
		(const tchar *path, u64 creation_time, u64 last_write_time,
		 u64 last_access_time, struct apply_ctx *ctx);

	/* OPTIONAL:  Called after the extraction operation has succeeded.  */
	int (*finish_extract)
		(struct apply_ctx *ctx);

	/* OPTIONAL:  Called after the extraction operation has failed.  */
	int (*abort_extract)
		(struct apply_ctx *ctx);

	/* REQUIRED:  Path separator character to use when building paths.  */
	tchar path_separator;

	/* REQUIRED:  Maximum path length, in tchars, including the
	 * null-terminator.  */
	unsigned path_max;

	/* OPTIONAL:  String to prefix every path with.  */
	const tchar *path_prefix;

	/* OPTIONAL:  Length of path_prefix in tchars.  */
	unsigned path_prefix_nchars;

	/* OPTIONAL:  Set to 1 if paths must be prefixed by the name of the
	 * extraction target (i.e. if it's interpreted as a directory).  */
	unsigned requires_target_in_paths : 1;

	/* OPTIONAL:  Like above, but operations require real (absolute) path.
	 * */
	unsigned requires_realtarget_in_paths : 1;

	/* OPTIONAL:  Set to 1 if realpath() can be used to get the real
	 * (absolute) path of a file on the target volume before it's been
	 * created.  */
	unsigned realpath_works_on_nonexisting_files : 1;

	/* OPTIONAL:  Set to 1 if this extraction mode supports case sensitive
	 * filenames.  */
	unsigned supports_case_sensitive_filenames : 1;

	/* OPTIONAL:  Set to 1 if the root directory of the volume (see
	 * target_is_root() callback) should not be explicitly extracted.  */
	unsigned root_directory_is_special : 1;

	/* OPTIONAL:  Set to 1 if extraction cookie, or inode number, is stored
	 * in create_file() and create_directory() callbacks.  This cookie will
	 * then be passed to callbacks taking a 'file_spec_t', rather than the
	 * path.  */
	unsigned uses_cookies : 1;

	/* OPTIONAL:  Set to 1 if set_file_attributes() needs to be called a
	 * second time towards the end of the extraction.  */
	unsigned requires_final_set_attributes_pass : 1;
};

struct wim_features {
	unsigned long archive_files;
	unsigned long hidden_files;
	unsigned long system_files;
	unsigned long compressed_files;
	unsigned long encrypted_files;
	unsigned long encrypted_directories;
	unsigned long not_context_indexed_files;
	unsigned long sparse_files;
	unsigned long named_data_streams;
	unsigned long hard_links;
	unsigned long reparse_points;
	unsigned long symlink_reparse_points;
	unsigned long other_reparse_points;
	unsigned long security_descriptors;
	unsigned long short_names;
	unsigned long unix_data;
};

/* Context for an apply (extract) operation.  */
struct apply_ctx {
	WIMStruct *wim;
	int extract_flags;
	const tchar *target;
	size_t target_nchars;
	wimlib_progress_func_t progress_func;
	union wimlib_progress_info progress;
	struct wim_dentry *extract_root;
	const struct apply_operations *ops;
	struct wim_features supported_features;
	u32 supported_attributes_mask;
	struct list_head stream_list;
	tchar *realtarget;
	size_t realtarget_nchars;
	unsigned long invalid_sequence;
	u64 num_streams_remaining;
	bool root_dentry_is_special;
	uint64_t next_progress;
	intptr_t private[8];
};

#ifdef __WIN32__
  extern const struct apply_operations win32_apply_ops;
#else
  extern const struct apply_operations unix_apply_ops;
#endif

#ifdef WITH_NTFS_3G
  extern const struct apply_operations ntfs_3g_apply_ops;
#endif

#endif /* _WIMLIB_APPLY_H */
