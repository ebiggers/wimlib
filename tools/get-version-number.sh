#!/bin/sh

# Get the version number of the project to use in the release filenames
# and in the --version output.

vers=$(git describe --abbrev=8 --dirty --always 2>/dev/null | \
       sed 's/^v//')
if [ -z "$vers" ]; then
	# Fallback for people who use autoreconf on tarball releases
	vers="1.14.1"
fi
echo "$vers"
