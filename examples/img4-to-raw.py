#!/usr/bin/env python3

from pathlib import Path

import pyimg4
import sys


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {sys.argv[0]} <IMG4 file>')

    img4_path = Path(sys.argv[1])
    if not img4_path.is_file():
        sys.exit(f'[ERROR] IMG4 file not found: {img4_path}')

    with img4_path.open('rb') as f:
        try:
            img4 = pyimg4.IMG4(f.read())
        except:
            sys.exit(f'[ERROR] Failed to parse IMG4 file: {img4_path}')

    raw_data = img4_path.with_suffix('.raw')
    with raw_data.open('wb') as f:
        if img4.im4p.keybags:
            print('Raw data is encrypted.')

        elif img4.im4p.payload.compression != pyimg4.Compression.NONE:
            print(
                f'Raw data is {img4.im4p.payload.compression.name} compressed, decompressing.'
            )

            img4.im4p.payload.decompress()

        f.write(img4.im4p.payload.output())

    print(f'Raw data outputted to: {raw_data}.')


if __name__ == '__main__':
    main()
