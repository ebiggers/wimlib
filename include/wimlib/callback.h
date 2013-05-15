#ifndef _WIMLIB_CALLBACK_H
#define _WIMLIB_CALLBACK_H

#include <stddef.h>

typedef int (*consume_data_callback_t)(const void *buf, size_t len, void *ctx);

#endif
