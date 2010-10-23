#!/bin/bash

if [ ! -d "$1" ]; then
	echo "Directory '$1' does not exist"
	exit 1
fi

if [ ! -d "$2" ]; then
	echo "Directory '$2' does not exist"
	exit 1
fi

DIRNAME=`basename $1`
FILENAME="${DIRNAME}.tar.bz2"

echo "Creating '${FILENAME}' from ${DIRNAME}"
cd $1
tar -jcpv --numeric-owner --same-owner -f "$2/${FILENAME}.new" `find . -maxdepth 0 -type d ; find . -maxdepth 0 -type f`
mv "$2/${FILENAME}.new" "$2/${FILENAME}"

exit $?
