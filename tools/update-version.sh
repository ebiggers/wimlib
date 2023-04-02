#!/bin/bash

set -eu

if [ $# -ne 1 ]; then
	echo "Usage: $0 NEW_VERS" 1>&2
	exit 1
fi

oldmonth=$(head -1 doc/man1/wimcapture.1 | cut -d' ' -f4 | tr -d '"')
oldyear=$(head -1 doc/man1/wimcapture.1 | cut -d' ' -f5 | tr -d '"')
oldver=$(grep 'the library interface of wimlib' include/wimlib.h \
	 | grep -E -o '[0-9]+\.[0-9]+\.[0-9]+')

newver=$1
newmajor=$(echo "$newver" | cut -d'.' -f1)
newminor=$(echo "$newver" | cut -d'.' -f2)
newpatch=$(echo "$newver" | cut -d'.' -f3)
newmonth=$(date +%B)
newyear=$(date +%Y)

newver="${newmajor}.${newminor}.${newpatch}"
pat='This is wimlib version [^[:space:]]\+ ([^[:space:]]\+ [^[:space:]]\+)'
sed -i "s/$pat/This is wimlib version $newver ($newmonth $newyear)/" README.md

sed -i "s/$oldver/$newver/" tools/get-version-number.sh README.WINDOWS.md

sed -i -e 's/\(#define WIMLIB_MAJOR_VERSION[[:space:]]\+\)[[:digit:]]\+/\1'"$newmajor"'/' \
       -e 's/\(#define WIMLIB_MINOR_VERSION[[:space:]]\+\)[[:digit:]]\+/\1'"$newminor"'/' \
       -e 's/\(#define WIMLIB_PATCH_VERSION[[:space:]]\+\)[[:digit:]]\+/\1'"$newpatch"'/' \
       -e 's/\(the library interface of wimlib \)'"$oldver"'/\1'"$newver"'/' \
	  include/wimlib.h

sed -i -e "1s/$oldmonth $oldyear/$newmonth $newyear/;1s/wimlib $oldver/wimlib $newver/"	\
	  doc/man[1-9]/*.[1-9]
