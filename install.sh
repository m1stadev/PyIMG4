#!/bin/sh

# Sanity check
if ! which python3 > /dev/null; then
	echo "[ERROR] Python 3 is not installed."
	exit 1
fi

# Install package
python3 -m pip install $(dirname "$0")
