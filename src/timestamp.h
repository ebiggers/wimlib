#ifndef _WIMLIB_TIMESTAMP_H
#define _WIMLIB_TIMESTAMP_H

#include "util.h"
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

#define intervals_per_second (1000000000ULL / 100ULL)
#define intervals_per_microsecond (10)
#define nanoseconds_per_interval (100)
#define days_per_year (365ULL)
#define seconds_per_day (3600ULL * 24ULL)
#define intervals_per_day (seconds_per_day * intervals_per_second)
#define intervals_per_year (intervals_per_day * days_per_year)
#define years_1601_to_1970 (1970ULL - 1601ULL)
#define leap_years_1601_to_1970 (years_1601_to_1970 / 4ULL - 3ULL)
#define intervals_1601_to_1970 (years_1601_to_1970 * intervals_per_year \
				+ leap_years_1601_to_1970 * intervals_per_day)

static inline u64
unix_timestamp_to_wim(time_t t)
{
	return (u64)intervals_1601_to_1970 + t * intervals_per_second;
}

/* Converts a timestamp as used in the WIM file to a UNIX timestamp as used in
 * the time() function. */
static inline time_t
wim_timestamp_to_unix(u64 timestamp)
{
	return (timestamp - intervals_1601_to_1970) / intervals_per_second;
}

static inline u64
timeval_to_wim_timestamp(const struct timeval tv)
{
	return intervals_1601_to_1970
	       + (u64)tv.tv_sec * intervals_per_second
	       + (u64)tv.tv_usec * intervals_per_microsecond;
}

static inline struct timeval
wim_timestamp_to_timeval(u64 timestamp)
{
	struct timeval tv;
	tv.tv_sec = (timestamp - intervals_1601_to_1970) / intervals_per_second;
	tv.tv_usec = ((timestamp - intervals_1601_to_1970) /
			intervals_per_microsecond) % 1000000;
	return tv;
}

static inline u64
timespec_to_wim_timestamp(const struct timespec ts)
{
	return intervals_1601_to_1970
	       + (u64)ts.tv_sec * intervals_per_second
	       + (u64)ts.tv_nsec / nanoseconds_per_interval;
}

static inline struct timespec
wim_timestamp_to_timespec(u64 timestamp)
{
	struct timespec ts;
	ts.tv_sec = (timestamp - intervals_1601_to_1970) / intervals_per_second;
	ts.tv_nsec = ((timestamp - intervals_1601_to_1970) % intervals_per_second) * 
			nanoseconds_per_interval;
	return ts;
}

extern u64
get_wim_timestamp();

extern void
wim_timestamp_to_str(u64 timestamp, tchar *buf, size_t len);

#endif
