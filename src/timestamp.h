#ifndef _WIMLIB_TIMESTAMP_H
#define _WIMLIB_TIMESTAMP_H

#include "util.h"
#include <time.h>

#define intervals_per_second (1000000000ULL / 100ULL)
#define days_per_year (365ULL)
#define seconds_per_day (3600ULL * 24ULL)
#define intervals_per_day (seconds_per_day * intervals_per_second)
#define intervals_per_year (intervals_per_day * days_per_year)
#define years_1601_to_1970 (1970ULL - 1601ULL)
#define leap_years_1601_to_1970 (years_1601_to_1970 / 4ULL - 3ULL)
#define intervals_1601_to_1970 (years_1601_to_1970 * intervals_per_year \
				+ leap_years_1601_to_1970 * intervals_per_day)

/* 
 * Returns the number of 100-nanosecond intervals that have elapsed since
 * 12:00 A.M., January 1, 1601 UTC.
 */
static inline u64 get_timestamp()
{
	return (u64)intervals_1601_to_1970 + (u64)time(NULL) * intervals_per_second;
}

/* Converts a timestamp as used in the WIM file to a UNIX timestamp as used in
 * the time() function. */
static inline time_t ms_timestamp_to_unix(u64 timestamp)
{
	return (timestamp - intervals_1601_to_1970) / intervals_per_second;
}

#endif
