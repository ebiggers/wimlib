#ifndef _WIMLIB_PROGRESS_H
#define _WIMLIB_PROGRESS_H

#include "wimlib.h"
#include "wimlib/types.h"

/* If specified, call the user-provided progress function and check its result.
 */
static inline int
call_progress(wimlib_progress_func_t progfunc,
	      enum wimlib_progress_msg msg,
	      union wimlib_progress_info *info,
	      void *progctx)
{
	if (progfunc) {
		enum wimlib_progress_status status;

		status = (*progfunc)(msg, info, progctx);

		switch (status) {
		case WIMLIB_PROGRESS_STATUS_CONTINUE:
			return 0;
		case WIMLIB_PROGRESS_STATUS_ABORT:
			return WIMLIB_ERR_ABORTED_BY_PROGRESS;
		default:
			return WIMLIB_ERR_UNKNOWN_PROGRESS_STATUS;
		}
	}
	return 0;
}

extern int
report_error(wimlib_progress_func_t progfunc,
	     void *progctx, int error_code, const tchar *path);

/* Rate-limiting of byte-count based progress messages: update *next_progress_p
 * to the value that completed_bytes needs to reach before the next progress
 * message will be sent.  */
static inline void
set_next_progress(u64 completed_bytes, u64 total_bytes, u64 *next_progress_p)
{
	if (*next_progress_p < total_bytes) {
		/*
		 * Send the next message as soon as:
		 *	- another 1/128 of the total has been processed;
		 *	- OR another 5000000 bytes have been processed;
		 *	- OR all bytes have been processed.
		 */
		*next_progress_p = min(min(completed_bytes + total_bytes / 128,
					   completed_bytes + 5000000),
				       total_bytes);
	} else {
		/* Last message has been sent.  */
		*next_progress_p = ~0;
	}
}

#endif /* _WIMLIB_PROGRESS_H */
