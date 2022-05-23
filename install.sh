#!/bin/sh

# Run checks
if ! which python3 > /dev/null; then
	echo "[ERROR] Python 3 is not installed."
	exit 1
fi

if ! which poetry > /dev/null; then
	echo "[ERROR] poetry is not installed."
	exit 1
fi

if [ -d "dist/" ]; then
	rm -rf dist/
fi

# Build package
poetry build

# Install package
python3 -m pip install $(ls dist/*.tar.gz)
