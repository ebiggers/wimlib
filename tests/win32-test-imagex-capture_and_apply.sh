#!/bin/bash

set -e -u -v

./tools/windows-build.sh
bindir=$(find . -name 'wimlib-*-bin' | tail -1)
for helper in win32-tree-cmp set_reparse_point; do
	cc -O2 -municode -Wall -Werror ./tests/$helper.c -o "$bindir"/$helper.exe
	chmod 700 "$bindir"/$helper.exe
done
cd "$bindir"
../tests/win32-test-imagex-capture_and_apply.bat
