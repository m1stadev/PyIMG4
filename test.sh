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

# Make sure dependencies are installed
poetry install > /dev/null

# Run tests
poetry run pytest
