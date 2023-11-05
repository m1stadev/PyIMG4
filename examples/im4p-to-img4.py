#!/usr/bin/env python3

import plistlib
import sys
from pathlib import Path

import pyimg4


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(f'Usage: {sys.argv[0]} <Image4 payload> <SHSH blob>')

    im4p_path = Path(sys.argv[1])
    if not im4p_path.is_file():
        sys.exit(f'[ERROR] Image4 payload not found: {im4p_path}')

    shsh_path = Path(sys.argv[2])
    if not shsh_path.is_file():
        sys.exit(f'[ERROR] SHSH blob not found: {shsh_path}')

    with im4p_path.open('rb') as f:
        try:
            im4p = pyimg4.IM4P(f.read())
        except:
            sys.exit(f'[ERROR] Failed to parse Image4 payload: {im4p_path}')

    with shsh_path.open('rb') as f:
        try:
            shsh = plistlib.load(f)
        except plistlib.InvalidFileException:
            sys.exit(f'[ERROR] Failed to read SHSH blob: {shsh_path}')

    try:
        im4m = pyimg4.IM4M(shsh['ApImg4Ticket'])
    except:
        sys.exit(f'[ERROR] Failed to parse SHSH blob: {shsh_path}')

    img4 = pyimg4.IMG4(im4m=im4m, im4p=im4p)

    img4_path = im4p_path.with_suffix('.img4')
    with img4_path.open('wb') as f:
        f.write(img4.output())

    print(f'Image4 outputted to: {img4_path}.')


if __name__ == '__main__':
    main()
