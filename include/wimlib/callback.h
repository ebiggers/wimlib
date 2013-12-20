#ifndef _WIMLIB_CALLBACK_H
#define _WIMLIB_CALLBACK_H

#include <stddef.h>

/* Callback for processing a chunk of data.  Returns 0 on success, or an error
 * code on failure.  */
typedef int (*consume_data_callback_t)(const void *chunk, size_t size, void *ctx);

#endif
