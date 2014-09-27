/*
 * timestamp.c
 */

/*
 * Copyright (C) 2012, 2013 Eric Biggers
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

#include "wimlib/types.h"
#include "wimlib/timestamp.h"

#include <time.h>
#include <sys/time.h>

u64
get_wim_timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return timeval_to_wim_timestamp(tv);
}

void
wim_timestamp_to_str(u64 timestamp, tchar *buf, size_t len)
{
	struct tm tm;
	time_t t = wim_timestamp_to_unix(timestamp);
	gmtime_r(&t, &tm);
	tstrftime(buf, len, T("%a %b %d %H:%M:%S %Y UTC"), &tm);
}

