#!/usr/bin/env python3

import plistlib
import sys
from pathlib import Path

import pyimg4


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {sys.argv[0]} <SHSH blob>')

    shsh_path = Path(sys.argv[1])
    if not shsh_path.is_file():
        sys.exit(f'[ERROR] SHSH blob not found: {shsh_path}')

    with shsh_path.open('rb') as f:
        try:
            data = plistlib.load(f)
        except plistlib.InvalidFileException:
            sys.exit(f'[ERROR] Failed to read SHSH blob: {shsh_path}')

    try:
        im4m = pyimg4.IM4M(data['ApImg4Ticket'])
    except:
        sys.exit(f'[ERROR] Failed to parse ApTicket: {shsh_path}')

    print('SHSH info:')
    if 0x8720 <= im4m.chip_id <= 0x8960:
        soc = f'S5L{im4m.chip_id:02x}'
    elif im4m.chip_id in range(0x7002, 0x8003):
        soc = f'S{im4m.chip_id:02x}'
    else:
        soc = f'T{im4m.chip_id:02x}'

    print(f'  Device Processor: {soc}')

    print(f'  ECID (hex): {hex(im4m.ecid)}')
    print(f'  ApNonce (hex): {im4m.apnonce.hex()}')
    print(f'  SepNonce (hex): {im4m.sepnonce.hex()}')

    print(
        f'  Manifest images ({len(im4m.images)}): {", ".join(i.fourcc for i in im4m.images)}'
    )


if __name__ == '__main__':
    main()
