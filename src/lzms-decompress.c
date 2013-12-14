/*
 * lzms-decompress.c
 *
 * LZMS decompression routines.
 */

/*
 * Copyright (C) 2013 Eric Biggers
 *
 * This file is part of wimlib, a library for working with WIM files.
 *
 * wimlib is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * wimlib is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wimlib; if not, see http://www.gnu.org/licenses/.
 */

#include "wimlib/lzms.h"
#include "wimlib/error.h"

int
lzms_decompress(const void *cdata, unsigned clen, void *udata, unsigned unlen,
		unsigned window_size)
{
	ERROR("LZMS decompression stub: not implemented");
	return -1;
}
