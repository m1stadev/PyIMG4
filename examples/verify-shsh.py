#!/usr/bin/env python3

import argparse
import plistlib
import sys
from pathlib import Path

import pyimg4


def main(build_manifest_path: Path, shsh_path: Path, verbose: bool) -> None:
    generator_list = ['0x1111111111111111', '0xbd34a880be0b53f3']

    if not build_manifest_path.is_file():
        sys.exit(f'[ERROR] BuildManifest not found: {build_manifest_path} ')

    else:
        with build_manifest_path.open('rb') as f:
            try:
                manifest = plistlib.load(f)
            except:
                sys.exit(f'[ERROR] Failed to read BuildManifest: {build_manifest_path}')

    if not shsh_path.is_file():
        sys.exit(f'[ERROR] SHSH blob not found: {shsh_path}')

    else:
        with shsh_path.open('rb') as f:
            try:
                shsh = plistlib.load(f)
            except:
                sys.exit(f'[ERROR] Failed to read SHSH blob: {shsh_path}')
        try:
            im4m = pyimg4.IM4M(shsh['ApImg4Ticket'])
        except:
            sys.exit(f'[ERROR] Failed to parse ApTicket: {shsh_path}')

    if 0x8720 <= im4m.chip_id <= 0x8960:
        soc = f'S5L{im4m.chip_id:02x}'
    elif im4m.chip_id in range(0x7002, 0x8003):
        soc = f'S{im4m.chip_id:02x}'
    else:
        soc = f'T{im4m.chip_id:02x}'

    for identity in manifest['BuildIdentities']:
        if int(identity['ApBoardID'], 16) != im4m.board_id and int(identity['ApChipID'], 16) != im4m.chip_id:
            if verbose:
                print(f"Skipping build identity {manifest['BuildIdentities'].index(identity)}...")

            continue

        print(f"Selected build identity: {manifest['BuildIdentities'].index(identity)}")
        for name, image_info in identity['Manifest'].items():
            if 'Digest' not in image_info.keys():
                if verbose:
                    print(f'Component: {name} has no hash, skipping...')

                continue

            if verbose:
                print(f'Verifying hash of component: {name}...')

            if not any(i for i in im4m.images if i.digest == image_info['Digest']):
                if verbose:
                    print(f'No hash found for component: {name} in SHSH!')

                break
        else:
            print('\nSHSH blob was successfully validated with the build manifest for the following restore:')
            print(f"Device Processor: {soc}")
            print(f"ECID (hex): {hex(im4m.ecid)}")
            print(f"ApNonce (hex): {im4m.apnonce.hex()}")
            print(f"SepNonce (hex): {im4m.sepnonce.hex()}")
            print(f"Board config: {identity['Info']['DeviceClass']}")
            print(f"Build ID: {identity['Info']['BuildNumber']}")
            print(f"Restore type: {identity['Info']['RestoreBehavior']}")

            if 'generator' in shsh.keys() and shsh['generator'] in generator_list:
                print(f"Generator: {shsh['generator']} which is GOOD.")

            elif 'generator' in shsh.keys():
                print(f"Generator: {shsh['generator']}")

            else:
                print('Generator not found in SHSH.')

            return

    print(f'SHSH blob is not valid for the provided build manifest!')


parser = argparse.ArgumentParser(
        prog="verify-shsh",
        description='Verify an SHSH blob with a provided build manifest.',
        epilog="Thanks for using %(prog)s! :)")

parser.add_argument(
        "-b",
        "--build-manifest",
        type=Path,
        help='Input build manifest file.',
        required=True)

parser.add_argument(
        "-s",
        "--shsh",
        type=Path,
        help='Input SHSH blob file.',
        required=True)

parser.add_argument(
        "-v",
        "--verbose",
        action='store_true',
        help='Increase verbosity.')

args = parser.parse_args()


if __name__ == '__main__':
    main(build_manifest_path=args.build_manifest, shsh_path=args.shsh, verbose=args.verbose)
