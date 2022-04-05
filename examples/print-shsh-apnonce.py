#!/usr/bin/env python3

from pathlib import Path

import plistlib
import pyimg4
import sys


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {sys.argv[0]} <SHSH blob file>')

    shsh_path = Path(sys.argv[1])
    if not shsh_path.is_file():
        sys.exit(f'[ERROR] SHSH blob not found: {shsh_path}')

    with shsh_path.open('rb') as f:
        try:
            data = plistlib.load(f)
        except:
            sys.exit(f'[ERROR] Failed to read SHSH blob: {shsh_path}')

    try:
        im4m = pyimg4.IM4M(data['ApImg4Ticket'])
    except:
        sys.exit(f'[ERROR] Failed to parse ApTicket: {shsh_path}')

    print(f'SHSH blob ApNonce: {im4m.apnonce}')


if __name__ == '__main__':
    main()
