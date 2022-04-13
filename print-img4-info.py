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

    pyimg4.IMG4(img4_path.read_bytes())
    try:
        img4 = pyimg4.IMG4(img4_path.read_bytes())
    except:
        sys.exit(f'[ERROR] Failed to parse IMG4 file: {img4_path}')

    print('IMG4 info:')
    print('  IM4P info:')
    print(f'    IM4P FourCC: {img4.im4p.fourcc}')
    print(f'    IM4P Description: {img4.im4p.description}')
    print(f'    IM4P Data size: {round(len(img4.im4p.payload.output()) / 1000)}KB')
    if (
        img4.im4p.payload.encrypted == False
        and img4.im4p.payload.compression != pyimg4.Compression.NONE
    ):
        print(f'    IM4P Data compression type: {img4.im4p.payload.compression.name}')

        img4.im4p.payload.decompress()
        print(
            f'    IM4P Data size (uncompressed): {round(len(img4.im4p.payload.output()) / 1000)}KB'
        )

    if img4.im4p.payload.encrypted:
        print(f"    IM4P Data encrypted: {img4.im4p.payload.encrypted}\n")
        for kb in img4.im4p.keybags:
            print('    Keybag:')
            print(f'      Type: {kb.type.name}')
            print(f'      IV: {kb.iv.hex()}')
            print(f'      Key: {kb.key.hex()}')

    print('\n  IM4M info:')
    if img4.im4m.chip_id is not None:
        if 0x8720 <= img4.im4m.chip_id <= 0x8960:
            soc = f'S5L{img4.im4m.chip_id:02x}'
        elif img4.im4m.chip_id in range(0x7002, 0x8003):
            soc = f'S{img4.im4m.chip_id:02x}'
        else:
            soc = f'T{img4.im4m.chip_id:02x}'

        print(f'    Device processor: {soc}')
    else:
        print(
            '    Warning: Chip ID not found in ApTicket, unable to find Device Processor'
        )

    print(f"    ECID (hex): {hex(img4.im4m.ecid).removeprefix('0x')}")
    print(f'    ApNonce: {img4.im4m.apnonce}')
    print(f'    SepNonce: {img4.im4m.sepnonce}')

    if img4.im4r:
        print(f'\n  IM4R info:')
        print(f"    Boot nonce generator: {'0x' + img4.im4r.generator.hex()}")


if __name__ == '__main__':
    main()
