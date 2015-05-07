/*
 * compress_upcase_table.c
 *
 * Compress a table that maps each UCS-2 character to its upper case equivalent.
 *
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2015 Eric Biggers
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

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

#define LEN 65536
#define SIZE (65536 * sizeof(uint16_t))

static uint16_t
match_length(const uint16_t *p1, const uint16_t *p2, uint16_t max_len)
{
	uint16_t len = 0;

	while (len < max_len && p1[len] == p2[len])
		len++;

	return len;
}

static void
longest_match(const uint16_t *tab, uint16_t cur_pos,
	      uint16_t *len_ret, uint16_t *src_pos_ret)
{
	uint16_t max_len = LEN - cur_pos;
	uint16_t src_pos;
	*len_ret = 0;
	*src_pos_ret = 0;
	for (src_pos = 0; src_pos < cur_pos; src_pos++) {
		/* check for match at this pos  */
		uint16_t len = match_length(&tab[cur_pos], &tab[src_pos], max_len);
		if (len > *len_ret) {
			*len_ret = len;
			*src_pos_ret = src_pos;
		}
	}
}

static void
output(uint16_t v)
{
	printf("0x%04x, ", v);
}

int main()
{
	int fd = open("upcase.tab", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: upcase.tab not found\n");
		return 1;
	}
	uint16_t *tab = mmap(NULL, SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	uint32_t i;

	/* Delta filter  */
	for (i = 0; i < LEN; i++)
		tab[i] -= i;

	/* Simple LZ encoder  */
	for (i = 0; i < LEN; ) {
		uint16_t len, src_pos;
		longest_match(tab, i, &len, &src_pos);
		if (len <= 1) {
			/* Literal  */
			output(0);
			output(tab[i]);
			i++;
		} else {
			/* Match  */
			output(len);
			output(src_pos);
			i += len;
		}
	}
	return 0;
}
