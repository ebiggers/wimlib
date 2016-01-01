/*
 * generate_language_id_map.c
 *
 * Generate a memory-efficient map from Windows language IDs to names.  This
 * program runs on Windows and uses LCIDToLocaleName() to enumerate all
 * languages recognized by Windows.
 *
 * ----------------------------------------------------------------------------
 *
 * Copyright (C) 2016 Eric Biggers
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

#define WINVER 0x6000	/* Needed for LCIDToLocaleName() declaration  */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

static struct {
	uint16_t id;
	char name[LOCALE_NAME_MAX_LENGTH];
} map[65536];

int main(void)
{
	uint32_t num_languages = 0;
	uint32_t name_start_offset = 0;
	uint32_t num_chars;
	bool need_new_line = true;

	for (uint32_t lcid = 0; lcid < 65536; lcid++) {
		wchar_t locale_name[LOCALE_NAME_MAX_LENGTH];

		if (LCIDToLocaleName(lcid, locale_name, LOCALE_NAME_MAX_LENGTH, 0)) {
			size_t len = wcslen(locale_name);
			for (size_t j = 0; j <= len; j++) {
				if (locale_name[j] > 127) {
					fprintf(stderr,
						"ERROR: locale name \"%ls\" "
						"includes non-ASCII characters",
						locale_name);
					return 1;
				}
				map[num_languages].name[j] = locale_name[j];
			}
			map[num_languages++].id = lcid;
		} else if (GetLastError() != ERROR_INVALID_PARAMETER) {
			fprintf(stderr,
				"ERROR: LCIDToLocaleName(%"PRIx32"): %u\n",
				lcid, (unsigned)GetLastError());
			return 1;
		}
	}

	printf("static const struct {\n");
	printf("\tu16 id;\n");
	printf("\tu16 name_start_offset;\n");
	printf("} language_id_map[%"PRIu32"] = {", num_languages);
	for (uint32_t i = 0; i < num_languages; i++) {
		if (need_new_line)
			printf("\n\t");
		printf("{0x%04x, %4"PRIu32"},", map[i].id, name_start_offset);
		need_new_line = (i % 4 == 3);
		if (!need_new_line)
			putchar(' ');
		name_start_offset += strlen(map[i].name) + 1;
		if (name_start_offset > 65536) {
			fprintf(stderr, "ERROR: total length of "
				"language names is too long!");
			return 1;
		}
	}
	printf("\n};\n");
	printf("\n");

	printf("static const char language_names[%"PRIu32"] =\n",
	       name_start_offset);
	printf("\t\"");
	num_chars = 8;
	for (uint32_t i = 0; i < num_languages; i++) {
		size_t len = strlen(map[i].name);
		need_new_line = (num_chars + len + 3 > 80);
		if (need_new_line) {
			printf("\"\n");
			printf("\t\"");
			num_chars = 9;
		}
		printf("%s\\0", map[i].name);
		num_chars += len + 2;
	}
	printf("\";\n");
	return 0;
}
