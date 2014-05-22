#ifndef _WIMLIB_PROGRESS_H
#define _WIMLIB_PROGRESS_H

#include "wimlib.h"

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

#endif
