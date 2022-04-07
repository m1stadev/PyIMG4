#!/usr/bin/env python3

from pathlib import Path

import pyimg4
import sys


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {sys.argv[0]} <IM4P file>')

    im4p_path = Path(sys.argv[1])
    if not im4p_path.is_file():
        sys.exit(f'[ERROR] IM4P file not found: {im4p_path}')

    with im4p_path.open('rb') as f:
        try:
            im4p = pyimg4.IM4P(f.read())
        except:
            sys.exit(f'[ERROR] Failed to parse IM4P file: {im4p_path}')

    raw_data = im4p_path.with_suffix('.raw')
    with raw_data.open('wb') as f:
        if im4p.keybags:
            print('Raw data is encrypted.')

        elif im4p.payload.compression != pyimg4.Compression.NONE:
            print(
                f'Raw data is {next(c.name for c in pyimg4.Compression if c.value == im4p.im4p.payload.compression)} compressed, decompressing.'
            )

            im4p.payload.decompress()

        f.write(im4p.payload.data)

    print(f'Raw data outputted to: {raw_data}.')


if __name__ == '__main__':
    main()
