#!/usr/bin/env python3

from pathlib import Path

import plistlib
import pyimg4
import sys


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(f'Usage: {sys.argv[0]} <IM4P file> <SHSH file>')

    im4p_path = Path(sys.argv[1])
    if not im4p_path.is_file():
        sys.exit(f'[ERROR] IM4P file not found: {im4p_path}')

    shsh_path = Path(sys.argv[2])
    if not shsh_path.is_file():
        sys.exit(f'[ERROR] SHSH file not found: {shsh_path}')

    with im4p_path.open('rb') as f:
        try:
            im4p = pyimg4.IM4P(f.read())
        except:
            sys.exit(f'[ERROR] Failed to parse IM4P file: {im4p_path}')

    with shsh_path.open('rb') as f:
        try:
            shsh = plistlib.load(f)
        except:
            sys.exit(f'[ERROR] Failed to read SHSH blob: {shsh_path}')

    try:
        im4m = pyimg4.IM4M(shsh['ApImg4Ticket'])
    except:
        sys.exit(f'[ERROR] Failed to parse SHSH blob: {shsh_path}')

    img4_path = im4p_path.with_suffix('.img4')
    with img4_path.open('wb') as f:
        f.write((im4m + im4p).output())

    print(f'IMG4 outputted to: {img4_path}.')


if __name__ == '__main__':
    main()
