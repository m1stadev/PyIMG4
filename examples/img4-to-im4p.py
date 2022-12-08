#!/usr/bin/env python3

import sys
from pathlib import Path

import pyimg4


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {sys.argv[0]} <Image4>')

    img4_path = Path(sys.argv[1])
    if not img4_path.is_file():
        sys.exit(f'[ERROR] Image4 not found: {img4_path}')

    with img4_path.open('rb') as f:
        try:
            img4 = pyimg4.IMG4(f.read())
        except:
            sys.exit(f'[ERROR] Failed to parse Image4: {img4_path}')

    im4p = img4_path.with_suffix('.im4p')
    with im4p.open('wb') as f:
        f.write(img4.im4p.output())

    print(f'Image4 Payload outputted to: {im4p}.')


if __name__ == '__main__':
    main()
