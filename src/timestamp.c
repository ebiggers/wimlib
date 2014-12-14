/*
 * timestamp.c
 *
 * Conversion between Windows NT timestamps and UNIX timestamps.
 */

/*
 * Copyright (C) 2012, 2013, 2014 Eric Biggers
 *
 * This file is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option) any
 * later version.
 *
 * This file is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this file; if not, see http://www.gnu.org/licenses/.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/timestamp.h"

/*
 * Timestamps in WIM files are Windows NT timestamps, or FILETIMEs: 64-bit
 * values storing the number of 100-nanosecond ticks since January 1, 1601.
 */

#define NANOSECONDS_PER_TICK	100
#define TICKS_PER_SECOND	(1000000000 / NANOSECONDS_PER_TICK)
#define TICKS_PER_MICROSECOND	(TICKS_PER_SECOND / 1000000)

/*
 * EPOCH_DISTANCE is the number of 100-nanosecond ticks separating the
 * Windows NT and UNIX epochs.  This is equal to ((1970-1601)*365+89)*
 * 24*60*60*10000000.  89 is the number of leap years between 1970 and 1601.
 */
#define EPOCH_DISTANCE		116444736000000000

#define TO_WINNT_EPOCH(timestamp)	((timestamp) + EPOCH_DISTANCE)
#define TO_UNIX_EPOCH(timestamp)	((timestamp) - EPOCH_DISTANCE)

/* Windows NT timestamps to UNIX timestamps  */

time_t
wim_timestamp_to_time_t(u64 timestamp)
{
	timestamp = TO_UNIX_EPOCH(timestamp);

	return timestamp / TICKS_PER_SECOND;
}

struct timeval
wim_timestamp_to_timeval(u64 timestamp)
{
	timestamp = TO_UNIX_EPOCH(timestamp);

	return (struct timeval) {
		.tv_sec = timestamp / TICKS_PER_SECOND,
		.tv_usec = (timestamp % TICKS_PER_SECOND) / TICKS_PER_MICROSECOND,
	};
}

struct timespec
wim_timestamp_to_timespec(u64 timestamp)
{
	timestamp = TO_UNIX_EPOCH(timestamp);

	return (struct timespec) {
		.tv_sec = timestamp / TICKS_PER_SECOND,
		.tv_nsec = (timestamp % TICKS_PER_SECOND) * NANOSECONDS_PER_TICK,
	};
}

/* UNIX timestamps to Windows NT timestamps  */

u64
time_t_to_wim_timestamp(time_t t)
{
	u64 timestamp = (u64)t * TICKS_PER_SECOND;

	return TO_WINNT_EPOCH(timestamp);
}

u64
timeval_to_wim_timestamp(const struct timeval *tv)
{
	u64 timestamp = (u64)tv->tv_sec * TICKS_PER_SECOND +
			(u64)tv->tv_usec * TICKS_PER_MICROSECOND;

	return TO_WINNT_EPOCH(timestamp);
}

u64
timespec_to_wim_timestamp(const struct timespec *ts)
{
	u64 timestamp = (u64)ts->tv_sec * TICKS_PER_SECOND +
			(u64)ts->tv_nsec / NANOSECONDS_PER_TICK;

	return TO_WINNT_EPOCH(timestamp);
}

/* Retrieve the current time as a WIM timestamp.  */
u64
now_as_wim_timestamp(void)
{
	struct timeval tv;

	/* On Windows we rely on MinGW providing gettimeofday() for us.  This
	 * could be changed to calling GetSystemTimeAsFileTime() directly, but
	 * now_as_wim_timestamp() isn't called much and it's simpler to keep the
	 * code for all platforms the same.  */
	gettimeofday(&tv, NULL);
	return timeval_to_wim_timestamp(&tv);
}

/* Translate a WIM timestamp into a human-readable string.  */
void
wim_timestamp_to_str(u64 timestamp, tchar *buf, size_t len)
{
	struct tm tm;
	time_t t = wim_timestamp_to_time_t(timestamp);
	gmtime_r(&t, &tm);
	tstrftime(buf, len, T("%a %b %d %H:%M:%S %Y UTC"), &tm);
}
