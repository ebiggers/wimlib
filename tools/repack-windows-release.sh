#!/bin/bash
#
# This script takes in the path to a windows-CLANGARM64-bin artifact downloaded
# from GitHub Actions, which lacks the PDF documentation and has the wrong file
# layout, and packs it up into a releasable zip file.  Assumes that an x86_64
# zip built from the same commit already exists locally.

set -e -u

usage()
{
	echo 1>&2 "Usage: $0 windows-CLANGARM64-bin.zip"
	exit 1
}

[ $# -eq 1 ] || usage

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

ZIP_FROM_GITHUB=$1
unzip -q -d "$tmpdir" "$ZIP_FROM_GITHUB"
DESTDIR=$(basename "$(echo "$tmpdir"/*)")
rm -rf "$DESTDIR" "$DESTDIR.zip"
cp -a "$tmpdir/$DESTDIR" "$DESTDIR"
prefix=$(echo "$DESTDIR" | grep -o 'wimlib.*windows')
cp -a "${prefix}-x86_64-bin/doc" "$DESTDIR/doc"
chmod +x "$DESTDIR"/*.{dll,exe,cmd}
cd "$DESTDIR"
7z -mx9 a ../"$DESTDIR.zip" . > /dev/null
cd ..
echo "Success!  Output is in $DESTDIR.zip"
