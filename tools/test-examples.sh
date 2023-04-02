#!/bin/sh
#
# Try building the example programs: in 32-bit and 64-bit mode, in C and C++
# mode, and for Linux and for Windows.  Also run the Linux versions to make sure
# they work.
#

set -eu

cd examples
make clean

COMMON_FLAGS="-Wall -Wextra -Werror -Wundef -Wno-unused-parameter -Wvla"
COMMON_CFLAGS="$COMMON_FLAGS -std=gnu99 -Wdeclaration-after-statement -Wstrict-prototypes"
COMMON_CXXFLAGS="$COMMON_FLAGS"

TEST_WIM="$HOME/data/test.wim"
TESTDATA="$HOME/data/testdata"

tmpdir="$(mktemp -d)"
tmpfile="$(mktemp)"
tmpfile2="$(mktemp)"

trap 'rm -rf "$tmpdir" "$tmpfile" "$tmpfile2"' EXIT

do_test() {
	rm -rf "$tmpdir"

	./applywim "$TEST_WIM" "$tmpdir"
	./capturewim "$tmpdir" "$tmpfile"
	./updatewim "$tmpfile" "examples" .

	./compressfile "$TESTDATA" "$tmpfile"
	./decompressfile "$tmpfile" "$tmpfile2"
	cmp "$tmpfile2" "$TESTDATA"

	./compressfile "$TESTDATA" "$tmpfile" XPRESS 16384
	./decompressfile "$tmpfile" "$tmpfile2"
	cmp "$tmpfile2" "$TESTDATA"
}

make CC=gcc CFLAGS="$COMMON_CFLAGS"
do_test
make clean
make CC=g++ CFLAGS="$COMMON_CXXFLAGS"
do_test
make clean

make CC=i686-w64-mingw32-gcc CFLAGS="$COMMON_CFLAGS -I../include -municode" LDLIBS="-lwim-15" LDFLAGS="-L/j/wimlib"
make clean
make CC=i686-w64-mingw32-g++ CFLAGS="$COMMON_CXXFLAGS -I../include -municode" LDLIBS="-lwim-15" LDFLAGS="-L/j/wimlib"
make clean

make CC=x86_64-w64-mingw32-gcc CFLAGS="$COMMON_CFLAGS -I../include -municode" LDLIBS="-lwim-15" LDFLAGS="-L/j/x64"
make clean
make CC=x86_64-w64-mingw32-g++ CFLAGS="$COMMON_CXXFLAGS -I../include -municode" LDLIBS="-lwim-15" LDFLAGS="-L/j/x64"
make clean
