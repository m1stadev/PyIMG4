#!/usr/bin/env python3

from pathlib import Path

import plistlib
import pyimg4
import sys


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f'Usage: {sys.argv[0]} <SHSH blob>')

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

    print('SHSH Info:')
    try:
        chip_id = next(prop.value for prop in im4m.properties if prop.name == 'CHIP')

        if 0x8720 <= chip_id <= 0x8960:
            soc = f'S5L{chip_id:02x}'
        elif chip_id in range(0x7002, 0x8003):
            soc = f'S{chip_id:02x}'
        else:
            soc = f'T{chip_id:02x}'

        print(f'  Device Processor: {soc}')
    except:
        print(
            '  Warning: ChipID not found in ApTicket, unable to find Device Processor'
        )

    print(f"  ECID (hex): {hex(im4m.ecid).removeprefix('0x')}")
    print(f"  ApNonce: {im4m.apnonce}")
    print(f"  SepNonce: {im4m.sepnonce}")


if __name__ == '__main__':
    main()
