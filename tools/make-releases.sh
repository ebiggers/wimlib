#!/bin/bash

set -e

export CFLAGS="-O2 -Wall -Werror"

vers=$(./tools/get-version-number.sh)
echo "Version $vers"

rm -rf build
cmake -B build -G Ninja
ninja -C build

tarball="wimlib-$vers.tar.gz"
echo "Generating $tarball"
git archive @ --format=tar --prefix="wimlib-$vers/" \
	| libdeflate-gzip -12 > "$tarball"

for arch in i686 x86_64; do
	./tools/windows-build.sh --arch=$arch --include-docs --zip
done
