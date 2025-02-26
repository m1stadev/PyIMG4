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

    pyimg4.IMG4(img4_path.read_bytes())
    try:
        img4 = pyimg4.IMG4(img4_path.read_bytes())
    except:
        sys.exit(f'[ERROR] Failed to parse Image4: {img4_path}')

    print('Image4 info:')
    print('  Image4 payload info:')
    print(f'    FourCC: {img4.im4p.fourcc}')
    print(f'    Description: {img4.im4p.description}')
    print(f'    Data size: {round(len(img4.im4p.payload) / 1000, 2)}KB')

    if (
        img4.im4p.payload.encrypted is False
        and img4.im4p.payload.compression != pyimg4.Compression.NONE
    ):
        print(f'    Data compression type: {img4.im4p.payload.compression.name}')

        img4.im4p.payload.decompress()
        print(
            f'    Data size (uncompressed): {round(len(img4.im4p.payload) / 1000, 2)}KB'
        )

    print(f'    Encrypted: {img4.im4p.payload.encrypted}')
    if img4.im4p.payload.encrypted:
        print(f'    Keybags ({len(img4.im4p.payload.keybags)}):')
        for k, kb in enumerate(img4.im4p.payload.keybags):
            print(f'      Type: {kb.type.name}')
            print(f'      IV: {kb.iv.hex()}')
            print(f'      Key: {kb.key.hex()}')

            if k != (len(img4.im4p.payload.keybags) - 1):
                print()

    print('\n  Image4 manifest info:')

    if 0x8720 <= img4.im4m.chip_id <= 0x8960:
        soc = f'S5L{img4.im4m.chip_id:02x}'
    elif img4.im4m.chip_id in range(0x7002, 0x8003):
        soc = f'S{img4.im4m.chip_id:02x}'
    else:
        soc = f'T{img4.im4m.chip_id:02x}'

    print(f'    Device Processor: {soc}')

    print(f'    ECID (hex): {hex(img4.im4m.ecid)}')
    print(f'    ApNonce (hex): {img4.im4m.apnonce.hex()}')
    print(f'    SepNonce (hex): {img4.im4m.sepnonce.hex()}')

    print(
        f'    Manifest images ({len(img4.im4m.images)}): {", ".join(i.fourcc for i in img4.im4m.images)}'
    )

    if img4.im4r is not None:
        print('\n  Image4 restore info:')

        if img4.im4r.boot_nonce is not None:
            print(f'    Boot nonce (hex): 0x{img4.im4r.boot_nonce.hex()}')

        print(
            f'    Restore properties ({len(img4.im4r.properties)}): {", ".join(prop.fourcc for prop in img4.im4r.properties)}'
        )


if __name__ == '__main__':
    main()
