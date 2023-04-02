#!/bin/bash

set -e

MAKE="make -j$(grep -c processor /proc/cpuinfo)"

export CFLAGS="-O2 -Wall -Werror"

autoreconf -i -f # make sure the version number gets updated

./configure && $MAKE distcheck

# Recompress with libdeflate
gzfile=$(find . -name 'wimlib-*.tar.gz' | tail -1)
tarfile=${gzfile%.gz}
libdeflate-gunzip "$gzfile"
libdeflate-gzip -12 "$tarfile"

for arch in i686 x86_64; do
	./tools/windows-build.sh --arch=$arch --include-docs --zip
done
