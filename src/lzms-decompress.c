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

#include "wimlib/win32_common.h"
#include "wimlib/lzms.h"
#include "wimlib/error.h"
#include <pthread.h>

typedef HANDLE DECOMPRESSOR_HANDLE;
typedef PVOID PCOMPRESS_ALLOCATION_ROUTINES;
typedef DECOMPRESSOR_HANDLE *PDECOMPRESSOR_HANDLE;

typedef enum {
	COMPRESS_INFORMATION_CLASS_INVALID = 0,
	COMPRESS_INFORMATION_CLASS_LEVEL,
	COMPRESS_INFORMATION_CLASS_BLOCK_SIZE
} COMPRESS_INFORMATION_CLASS;

#define COMPRESS_ALGORITHM_LZMS 0x00000005
#define COMPRESS_RAW		0x20000000 /* Not documented  */

static HMODULE hCabinetDll;
static pthread_mutex_t cabinetDllMutex = PTHREAD_MUTEX_INITIALIZER;

static BOOL (WINAPI *CreateDecompressor)
	(DWORD Algorithm,
	 PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
	 PDECOMPRESSOR_HANDLE DecompressorHandle);

static BOOL (WINAPI *CloseDecompressor)
	(DECOMPRESSOR_HANDLE DecompressorHandle);

static BOOL (WINAPI *Decompress)
	(DECOMPRESSOR_HANDLE DecompressorHandle,
	 PVOID CompressedData,
	 SIZE_T CompressedDataSize,
	 PVOID UncompressedBuffer,
	 SIZE_T UncompressedBufferSize,
	 PSIZE_T UncompressedDataSize);

int
lzms_decompress(const void *cbuf, unsigned clen, void *ubuf, unsigned ulen,
		unsigned window_size)
{
	int ret;
	DECOMPRESSOR_HANDLE h;

	ERROR("clen=%u, ulen=%u, window_size=%u", clen, ulen, window_size);

	if (hCabinetDll == NULL) {
		pthread_mutex_lock(&cabinetDllMutex);

		if (hCabinetDll == NULL) {
			hCabinetDll = LoadLibrary(L"Cabinet.dll");

			if (hCabinetDll == NULL) {
				ERROR("Can't load Cabinet.dll");
				ret = -1;
				goto unlock;
			}

			CreateDecompressor = (void*)GetProcAddress(hCabinetDll, "CreateDecompressor");
			Decompress = (void*)GetProcAddress(hCabinetDll, "Decompress");
			CloseDecompressor = (void*)GetProcAddress(hCabinetDll, "CloseDecompressor");

			if (CreateDecompressor == NULL ||
			    Decompress == NULL ||
			    CloseDecompressor == NULL)
			{
				ERROR("Can't find LZMS compression routines in Cabinet.dll");
				ret = -1;
				goto unlock;
			}
		}
		ret = 0;
	unlock:
		pthread_mutex_unlock(&cabinetDllMutex);
		if (ret)
			goto out;
	}


	if (!CreateDecompressor(COMPRESS_ALGORITHM_LZMS | COMPRESS_RAW, NULL, &h)) {
		ERROR("Failed to create LZMS decompressor (err %d)!", GetLastError());
		ret = -1;
		goto out;
	}


	/* TODO:  Some sort of chunk header?  */
	unsigned offset;
	if (clen <= window_size) {
		offset = 0;
	} else {
		const unsigned *p = cbuf;
		ERROR("%08x(%u) %08x %08x %08x %08x(%u)",
		      p[0], p[0], p[1], p[2], p[3], p[4], p[4]);
		offset = 20;
	}
	SIZE_T actual_ulen = -1;
	if (!Decompress(h, (void*)cbuf + offset, clen - offset, ubuf, ulen, &actual_ulen)) {
		ERROR("Failed to decompress LZMS-compressed data (err %d)!", GetLastError());
		ret = -1;
		goto out_close_decompressor;
	}

	if (actual_ulen != ulen) {
		ERROR("Unexpected actual uncompressed length (got %u, expected %u)",
		      actual_ulen, ulen);
		ret = -1;
		goto out_close_decompressor;
	}

	ERROR("Successfully decompressed data.");
	ret = 0;
out_close_decompressor:
	CloseDecompressor(h);
out:
	return ret;
}
