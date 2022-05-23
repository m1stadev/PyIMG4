from typing import BinaryIO, Optional

import click

import pyimg4
from pyimg4 import Compression, Keybag


@click.group()
@click.version_option(message=f'PyIMG4 {pyimg4.__version__}')
def cli():
    '''A Python CLI tool for parsing Apple's Image4 format.'''

    pass


@cli.group()
def im4m() -> None:
    '''Image4 manifest commands'''

    pass


@im4m.command('info')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input Image4 manifest file',
    required=True,
)
def im4m_info(input_: BinaryIO) -> None:
    '''Print available information on an Image4 manifest'''

    click.echo('Reading Image4 manifest file...')
    im4m = pyimg4.IM4M(input_.read())

    click.echo('Image4 manifest info:')
    if 0x8720 <= im4m.chip_id <= 0x8960:
        soc = f'S5L{im4m.chip_id:02x}'
    elif im4m.chip_id in range(0x7002, 0x8003):
        soc = f'S{im4m.chip_id:02x}'
    else:
        soc = f'T{im4m.chip_id:02x}'

    click.echo(f'  Device Processor: {soc}')

    click.echo(f"  ECID (hex): {hex(im4m.ecid)}")
    click.echo(f"  ApNonce: {im4m.apnonce}")
    click.echo(f"  SepNonce: {im4m.sepnonce}")

    click.echo(
        f"  Manifest images ({len(im4m.images)}): {', '.join(i.fourcc for i in im4m.images)}"
    )


@cli.group()
def im4p() -> None:
    '''Image4 payload commands'''

    pass


@im4p.command('create')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input file',
)
@click.option(
    '-o',
    '--output',
    type=click.File('wb'),
    required=True,
    help='Output file',
)
@click.option('-f', '--fourcc', type=str, required=True, help='FourCC to set')
@click.option(
    '-d',
    '--description',
    type=str,
    help='Description to set',
)
@click.option(
    '--lzss', 'compression_type', flag_value='LZSS', help='LZSS compress the data'
)
@click.option(
    '--lzfse',
    'compression_type',
    flag_value='LZFSE',
    help='LZFSE compress the data',
)
def im4p_create(
    input_: BinaryIO,
    output: BinaryIO,
    fourcc: str,
    description: Optional[str],
    compression_type: Optional[str],
) -> None:
    '''Create an Image4 payload file'''

    if len(fourcc) != 4:
        raise click.BadParameter('FourCC must be 4 characters long')

    click.echo(f'Reading {input_.name}...')
    im4p = pyimg4.IM4P(fourcc=fourcc, description=description, payload=input_.read())

    if compression_type is not None:
        compression_type = getattr(Compression, compression_type)

        if im4p.payload.compression not in (Compression.NONE, Compression.UNKNOWN):
            raise click.BadParameter(
                f'Payload is already {im4p.payload.compression.name} compressed'
            )

        click.echo(f'Compressing payload using {compression_type.name}...')
        im4p.payload.compress(compression_type)

    output.write(im4p.output())
    click.echo(f'IM4P outputted to: {output.name}')


@im4p.command('extract')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input Image4 payload file',
)
@click.option(
    '-o',
    '--output',
    type=click.File('wb'),
    required=True,
    help='File to output Image4 payload data to',
)
@click.option(
    '--no-decompress',
    'decompress',
    default=True,
    is_flag=True,
    help="Don't decompress the Image4 payload data",
)
@click.option('--iv', help='The IV used to encrypt the Image4 payload data')
@click.option('--key', help='The key used to encrypt the Image4 payload data')
def im4p_extract(
    input_: BinaryIO,
    output: BinaryIO,
    decompress: bool,
    iv: Optional[str],
    key: Optional[str],
) -> None:
    '''Extract data from an Image4 payload'''

    click.echo('Reading Image4 payload file...')
    im4p = pyimg4.IM4P(input_.read())

    if im4p.payload.encrypted == True:
        if iv is None and key is None:
            click.echo('[NOTE] Image4 payload data is encrypted')
        else:
            click.echo('[NOTE] Image4 payload data is encrypted, decrypting...')

        if (iv is None and key is not None) or (key is None and iv is not None):
            raise click.BadParameter('You must specify both the IV and the key')

        else:
            try:
                iv = bytes.fromhex(iv.removeprefix('0x'))
            except TypeError:
                raise click.BadParameter('Decryption IV must be a hex string')

            try:
                key = bytes.fromhex(key.removeprefix('0x'))
            except TypeError:
                raise click.BadParameter('Decryption key must be a hex string')

            if len(iv) != 16:
                raise click.BadParameter('Decryption IV must be 16 bytes long')

            if len(key) != 32:
                raise click.BadParameter('Decryption key must be 32 bytes long')

            im4p.payload.decrypt(Keybag(key=key, iv=iv))

    if im4p.payload.compression not in (Compression.NONE, Compression.UNKNOWN):
        if decompress == True:
            click.echo(
                f'[NOTE] Image4 payload data is {im4p.payload.compression.name} compressed, decompressing...'
            )

            im4p.payload.decompress()
        else:
            click.echo(
                f'[NOTE] Image4 payload data is {im4p.payload.compression.name} compressed, skipping decompression'
            )

    with output.open('wb') as f:
        f.write(im4p.payload.output())

    click.echo(f'Extracted Image4 payload data to: {output}')


@im4p.command('info')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input Image4 payload file',
)
def im4p_info(input_: BinaryIO) -> None:
    '''Print available information on an Image4 payload'''

    click.echo('Reading Image4 payload file...')
    im4p = pyimg4.IM4P(input_.read())

    click.echo('  Image4 payload info:')
    click.echo(f'    Payload FourCC: {im4p.fourcc}')
    click.echo(f'    Payload description: {im4p.description}')
    click.echo(f'    Payload data size: {round(len(im4p.payload) / 1000)}KB')

    if (
        im4p.payload.encrypted == False
        and im4p.payload.compression != pyimg4.Compression.NONE
    ):
        click.echo(
            f'    Payload data compression type: {im4p.payload.compression.name}'
        )

        im4p.payload.decompress()
        click.echo(
            f'    Payload data size (uncompressed): {round(len(im4p.payload) / 1000)}KB'
        )

    click.echo(f'    Payload data encrypted: {im4p.payload.encrypted}\n')
    if im4p.payload.encrypted:
        for kb in im4p.payload.keybags:
            click.echo('    Keybag:')
            click.echo(f'      Type: {kb.type.name}')
            click.echo(f'      IV: {kb.iv.hex()}')
            click.echo(f'      Key: {kb.key.hex()}')


@cli.group()
def im4r() -> None:
    '''Image4 restore info commands'''

    pass


@im4r.command('create')
@click.option(
    '-g',
    '--boot-nonce',
    type=str,
    required=True,
    help='The boot nonce used to encrypt the Image4 restore info',
)
@click.option(
    '-o',
    '--output',
    type=click.File('wb'),
    required=True,
    help='File to output Image4 restore info to',
)
def im4r_create(boot_nonce: str, output: BinaryIO) -> None:
    click.echo(f'Creating Image4 restore info file with boot nonce: {boot_nonce}...')

    try:
        boot_nonce = bytes.fromhex(boot_nonce.removeprefix('0x'))
    except TypeError:
        raise click.BadParameter('Boot nonce must be a hex string')

    if len(boot_nonce) != 8:
        raise click.BadParameter('Boot nonce must be 8 bytes long')

    im4r = pyimg4.IM4R(boot_nonce=boot_nonce)

    output.write(im4r.output())
    click.echo(f'Image4 restore info outputted to: {output.name}')


@im4r.command('info')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    required=True,
    help='Input Image4 restore info file',
)
def im4r_info(input_: BinaryIO) -> None:
    '''Print available information on an Image4 restore info file'''

    click.echo('Reading Image4 restore info file...')
    im4r = pyimg4.IM4R(input_.read())

    click.echo('  Image4 restore info:')
    click.echo(f'    Boot nonce (hex): 0x{im4r.boot_nonce.hex()}')


@cli.group()
def img4() -> None:
    '''Image4 commands'''

    pass


@img4.command('create')
@click.option(
    '-p',
    '--im4p',
    type=click.File('rb'),
    required=True,
    help='Input Image4 payload file',
)
@click.option(
    '-m',
    '--im4m',
    type=click.File('rb'),
    required=True,
    help='Input Image4 manifest file',
)
@click.option(
    '-r',
    '--im4r',
    type=click.File('rb'),
    help='Input Image4 restore info file',
)
@click.option(
    '-g',
    '--boot-nonce',
    'boot_nonce',
    type=str,
    help='Boot nonce to set in Image4 restore info',
)
@click.option(
    '-o', '--output', type=click.File('wb'), required=True, help='Output file'
)
def img4_create(
    im4p: BinaryIO,
    im4m: BinaryIO,
    im4r: Optional[BinaryIO],
    boot_nonce: Optional[str],
    output: BinaryIO,
):
    '''Create an Image4 file'''

    click.echo('Reading Image4 payload file...')
    im4p = pyimg4.IM4P(im4p.read())

    click.echo('Reading Image4 manifest file...')
    im4m = pyimg4.IM4M(im4m.read())

    if im4r is not None:
        click.echo('Reading Image4 restore info file...')
        im4r = pyimg4.IM4R(im4r.read())

    elif boot_nonce is not None:
        click.echo(
            f'Creating Image4 restore info file with boot nonce: {boot_nonce}...'
        )

        try:
            boot_nonce = bytes.fromhex(boot_nonce.removeprefix('0x'))
        except TypeError:
            raise click.BadParameter('Boot nonce must be a hex string')

        if len(boot_nonce) != 8:
            raise click.BadParameter('Boot nonce must be 8 bytes long')

        im4r = pyimg4.IM4R(boot_nonce=boot_nonce)

    click.echo('Creating Image4...')
    img4 = pyimg4.IMG4(im4p=im4p, im4m=im4m, im4r=im4r)

    output.write(img4.output())
    click.echo(f'Image4 file outputted to: {output.name}')


@img4.command('extract')
@click.option(
    '-i',
    '--input',
    'input_',
    type=click.File('rb'),
    help='Input Image4 file',
    required=True,
)
@click.option(
    '-p',
    '--im4p',
    type=click.File('wb'),
    help='File to output Image4 payload to',
)
@click.option(
    '-m',
    '--im4m',
    type=click.File('wb'),
    help='File to output Image4 manifest to',
)
@click.option(
    '-r',
    '--im4r',
    type=click.File('wb'),
    help='File to output Image4 restore info to',
)
def img4_extract(
    input_: BinaryIO,
    im4p: Optional[BinaryIO],
    im4m: Optional[BinaryIO],
    im4r: Optional[BinaryIO],
) -> None:
    '''Extract Image4 manifest/payload/restore info from an Image4 file'''

    img4 = pyimg4.IMG4(input_.read())

    if not any(i is not None for i in (im4p, im4m, im4r)):
        raise click.BadParameter('You must specify at least one output file')

    if im4p is not None:
        if img4.im4p is None:
            raise click.BadParameter('Image4 payload not found in Image4 file')

        im4p.write(img4.im4p.output())
        click.echo(f'Extracted Image4 payload to: {im4p.name}')

    if im4m is not None:
        if img4.im4m is None:
            raise click.BadParameter('Image4 manifest not found in Image4 file')

        im4m.write(img4.im4m.output())
        click.echo(f'Extracted Image4 manifest to: {im4m.name}')

    if im4r is not None:
        if img4.im4r is None:
            raise click.BadParameter('Image4 restore info not found in Image4 file')

        im4r.write(img4.im4r.output())
        click.echo(f'Extracted Image4 restore info to: {im4r.name}')


if __name__ == '__main__':
    cli()
