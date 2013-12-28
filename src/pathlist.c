/*
 * pathlist.c
 *
 * Utility function for reading path list files.
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

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "wimlib/encoding.h"
#include "wimlib/error.h"
#include "wimlib/file_io.h"
#include "wimlib/pathlist.h"
#include "wimlib/util.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int
read_file_contents(const tchar *path, char **buf_ret, size_t *bufsize_ret)
{
	int raw_fd;
	struct filedes fd;
	struct stat st;
	void *buf;
	int ret;
	int errno_save;

	raw_fd = topen(path, O_RDONLY | O_BINARY);
	if (raw_fd < 0) {
		ERROR_WITH_ERRNO("Can't open \"%"TS"\"", path);
		return WIMLIB_ERR_OPEN;
	}
	if (fstat(raw_fd, &st)) {
		ERROR_WITH_ERRNO("Can't stat \"%"TS"\"", path);
		close(raw_fd);
		return WIMLIB_ERR_STAT;
	}
	if ((size_t)st.st_size != st.st_size ||
	    (buf = MALLOC(st.st_size)) == NULL)
	{
		close(raw_fd);
		ERROR("Not enough memory to read \"%"TS"\"", path);
		return WIMLIB_ERR_NOMEM;
	}

	filedes_init(&fd, raw_fd);
	ret = full_read(&fd, buf, st.st_size);
	errno_save = errno;
	filedes_close(&fd);
	errno = errno_save;
	if (ret) {
		ERROR_WITH_ERRNO("Error reading \"%"TS"\"", path);
		FREE(buf);
		return ret;
	}

	*buf_ret = buf;
	*bufsize_ret = st.st_size;
	return 0;
}

static int
read_utf8_file_contents(const tchar *path, tchar **buf_ret, size_t *buflen_ret)
{
	int ret;
	char *buf_utf8;
	size_t bufsize_utf8;
	tchar *buf_tstr;
	size_t bufsize_tstr;

	ret = read_file_contents(path, &buf_utf8, &bufsize_utf8);
	if (ret)
		return ret;

	ret = utf8_to_tstr(buf_utf8, bufsize_utf8, &buf_tstr, &bufsize_tstr);
	FREE(buf_utf8);
	if (ret)
		return ret;

	*buf_ret = buf_tstr;
	*buflen_ret = bufsize_tstr / sizeof(tchar);
	return 0;
}

static int
parse_path_list_file(tchar *buf, size_t buflen,
		     tchar ***paths_ret, size_t *num_paths_ret)
{
	tchar **paths = NULL;
	size_t num_paths = 0;
	size_t num_alloc_paths = 0;
	tchar *nl;
	tchar *p;

	for (p = buf; p != buf + buflen; p = nl + 1) {
		tchar *line_begin, *line_end;
		size_t line_len;

		nl = tmemchr(p, T('\n'), buf + buflen - p);
		if (nl == NULL)
			break;

		line_begin = p;
		line_end = nl;

		/* Ignore leading whitespace.  */
		while (line_begin < nl && istspace(*line_begin))
			line_begin++;

		/* Ignore trailing whitespace.  */
		while (line_end > line_begin && istspace(*(line_end - 1)))
			line_end--;

		line_len = line_end - line_begin;

		/* Ignore comments and empty lines.  */
		if (line_len == 0 || *line_begin == T(';'))
			continue;

		if (num_paths == num_alloc_paths) {
			tchar **new_paths;
			size_t new_num_alloc_paths = max(num_alloc_paths + 8,
							 num_alloc_paths * 3 / 2);

			new_paths = REALLOC(paths, new_num_alloc_paths *
						   sizeof(paths[0]));
			if (new_paths == NULL)
				goto oom;
			paths = new_paths;
			num_alloc_paths = new_num_alloc_paths;
		}

		*line_end = T('\0');
		paths[num_paths++] = line_begin;
	}

	*paths_ret = paths;
	*num_paths_ret = num_paths;
	return 0;

oom:
	FREE(paths);
	return WIMLIB_ERR_NOMEM;
}

int
read_path_list_file(const tchar *listfile,
		    tchar ***paths_ret, size_t *num_paths_ret,
		    void **mem_ret)
{
	int ret;
	tchar *buf;
	size_t buflen;

	ret = read_utf8_file_contents(listfile, &buf, &buflen);
	if (ret)
		return ret;

	ret = parse_path_list_file(buf, buflen, paths_ret, num_paths_ret);
	if (ret) {
		FREE(buf);
		return ret;
	}
	*mem_ret = buf;
	return 0;
}
