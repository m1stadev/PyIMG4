#!/usr/bin/env python3

import sys
from pathlib import Path

import pyimg4


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {sys.argv[0]} <Image4 payload>')

    im4p_path = Path(sys.argv[1])
    if not im4p_path.is_file():
        sys.exit(f'[ERROR] Image4 payload not found: {im4p_path}')

    with im4p_path.open('rb') as f:
        try:
            im4p = pyimg4.IM4P(f.read())
        except:
            sys.exit(f'[ERROR] Failed to parse Image4 payload: {im4p_path}')

    if im4p.payload.encrypted:
        print('Raw data is encrypted.')

    elif im4p.payload.compression != pyimg4.Compression.NONE:
        print(
            f'Raw data is {im4p.im4p.payload.compression.name} compressed, decompressing.'
        )

        im4p.payload.decompress()

    raw_data = im4p_path.with_suffix('.raw')
    with raw_data.open('wb') as f:
        f.write(im4p.payload.output().data)

    print(f'Raw data outputted to: {raw_data}.')


if __name__ == '__main__':
    main()
