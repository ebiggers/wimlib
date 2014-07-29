#ifndef _WIMLIB_APPLY_H
#define _WIMLIB_APPLY_H

#include "wimlib/compiler.h"
#include "wimlib/file_io.h"
#include "wimlib/list.h"
#include "wimlib/progress.h"
#include "wimlib/types.h"
#include "wimlib.h"

/* These can be treated as counts (for required_features) or booleans (for
 * supported_features).  */
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
	unsigned long timestamps;
	unsigned long case_sensitive_filenames;
};

struct wim_lookup_table_entry;
struct read_stream_list_callbacks;

struct apply_ctx {
	/* The WIMStruct from which files are being extracted from the currently
	 * selected image.  */
	WIMStruct *wim;

	/* The target of the extraction, usually the path to a directory.  */
	const tchar *target;

	/* Length of @target in tchars.  */
	size_t target_nchars;

	/* Extraction flags (WIMLIB_EXTRACT_FLAG_*)  */
	int extract_flags;

	/* User-provided progress function, or NULL if not specified.  */
	wimlib_progress_func_t progfunc;
	void *progctx;

	/* Progress data buffer, with progress.extract initialized.  */
	union wimlib_progress_info progress;

	/* Features required to extract the files (with counts)  */
	struct wim_features required_features;

	/* Features supported by the extraction mode (with booleans)  */
	struct wim_features supported_features;

	/* The members below should not be used outside of extract.c  */
	u64 next_progress;
	unsigned long invalid_sequence;
	unsigned long num_streams_remaining;
	struct list_head stream_list;
	const struct read_stream_list_callbacks *saved_cbs;
	struct wim_lookup_table_entry *cur_stream;
	u64 cur_stream_offset;
	struct filedes tmpfile_fd;
	tchar *tmpfile_name;
	unsigned int count_until_file_progress;
};

/* Maximum number of UNIX file descriptors, NTFS attributes, or Windows file
 * handles that can be opened simultaneously to extract a single-instance
 * stream to multiple destinations.  */
#define MAX_OPEN_STREAMS 512

static inline int
extract_progress(struct apply_ctx *ctx, enum wimlib_progress_msg msg)
{
	return call_progress(ctx->progfunc, msg, &ctx->progress, ctx->progctx);
}

extern int
do_file_extract_progress(struct apply_ctx *ctx, enum wimlib_progress_msg msg);

static inline int
maybe_do_file_progress(struct apply_ctx *ctx, enum wimlib_progress_msg msg)
{
	if (unlikely(!--ctx->count_until_file_progress))
		return do_file_extract_progress(ctx, msg);
	return 0;
}

/* Call this to reset the counter for report_file_created() and
 * report_file_metadata_applied().  */
static inline void
reset_file_progress(struct apply_ctx *ctx)
{
	ctx->count_until_file_progress = 1;
}

/* Report that a file was created, prior to stream extraction.  */
static inline int
report_file_created(struct apply_ctx *ctx)
{
	return maybe_do_file_progress(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_FILE_STRUCTURE);
}

/* Report that file metadata was applied, after stream extraction.  */
static inline int
report_file_metadata_applied(struct apply_ctx *ctx)
{
	return maybe_do_file_progress(ctx, WIMLIB_PROGRESS_MSG_EXTRACT_METADATA);
}

/* Returns any of the aliases of an inode that are being extracted.  */
#define inode_first_extraction_dentry(inode)		\
	list_first_entry(&(inode)->i_extraction_aliases,	\
			 struct wim_dentry, d_extraction_alias_node)

extern int
extract_stream_list(struct apply_ctx *ctx,
		    const struct read_stream_list_callbacks *cbs);

struct apply_operations {
	const char *name;
	int (*get_supported_features)(const tchar *target,
				      struct wim_features *supported_features);

	int (*extract)(struct list_head *dentry_list, struct apply_ctx *ctx);

	size_t context_size;
	bool single_tree_only;
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
