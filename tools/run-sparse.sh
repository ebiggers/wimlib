#!/bin/sh

for fil in src/*.c programs/imagex.c; do
	sparse "$fil" -gcc-base-dir "$(gcc --print-file-name=)"		\
		-D_FILE_OFFSET_BITS=64 -DHAVE_CONFIG_H -D_GNU_SOURCE	\
		-I. -Iinclude -Wbitwise -Wpointer-subtraction-blows
done
