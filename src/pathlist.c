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

#include "wimlib/pathlist.h"
#include "wimlib/textfile.h"

int
read_path_list_file(const tchar *listfile,
		    tchar ***paths_ret, size_t *num_paths_ret,
		    void **mem_ret)
{
	STRING_SET(paths);
	struct text_file_section tmp = {
		.name = T(""),
		.strings = &paths,
	};
	tchar *buf;
	int ret;

	ret = load_text_file(listfile, &buf, &tmp, 1, NULL);
	if (ret)
		return ret;

	*paths_ret = paths.strings;
	*num_paths_ret = paths.num_strings;
	*mem_ret = (void *)buf;
	return 0;
}
