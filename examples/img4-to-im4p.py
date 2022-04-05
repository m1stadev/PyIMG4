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

    im4p = img4_path.with_suffix('.im4p')
    with im4p.open('wb') as f:
        f.write(img4.im4p)

    print(f'IM4P outputted to: {im4p}.')


if __name__ == '__main__':
    main()
