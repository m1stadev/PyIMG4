from pathlib import Path
from typing import BinaryIO, Optional

import click

import pyimg4
from pyimg4 import Compression, Keybag


@click.group()
@click.version_option(message=f'PyIMG4 {pyimg4.__version__}')
def cli():
    '''A Python CLI tool for parsing Apple's Image4 format.'''

    click.echo(f'PyIMG4 {pyimg4.__version__}')


@cli.group()
def im4p() -> None:
    '''Image4 payload commands'''

    pass


@im4p.command('info')
@click.argument('im4p', type=click.File('rb'))
def im4p_info(im4p) -> None:
    '''Print available information on an Image4 payload'''

    click.echo('Reading Image4 payload file...')
    im4p = pyimg4.IM4P(im4p.read())

    click.echo('  Image4 payload info:')
    click.echo(f'    Image4 payload FourCC: {im4p.fourcc}')
    click.echo(f'    Image4 payload description: {im4p.description}')
    click.echo(f'    Image4 payload data size: {round(len(im4p.payload) / 1000)}KB')

    if (
        im4p.payload.encrypted == False
        and im4p.payload.compression != pyimg4.Compression.NONE
    ):
        click.echo(
            f'    Image4 payload data compression type: {im4p.payload.compression.name}'
        )

        im4p.payload.decompress()
        click.echo(
            f'    Image4 payload data size (uncompressed): {round(len(im4p.payload) / 1000)}KB'
        )

    if im4p.payload.encrypted:
        click.echo(f'    Image4 payload data encrypted: {im4p.payload.encrypted}\n')
        for kb in im4p.payload.keybags:
            click.echo('    Keybag:')
            click.echo(f'      Type: {kb.type.name}')
            click.echo(f'      IV: {kb.iv.hex()}')
            click.echo(f'      Key: {kb.key.hex()}')


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
    type=click.Path(dir_okay=False, exists=False, path_type=Path, writable=True),
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
    input_: Path,
    output: Path,
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
            if len(key) != 64:
                raise click.BadParameter('Key must be 64 characters long')

            if len(iv) != 32:
                raise click.BadParameter('IV must be 32 characters long')

            try:
                key = bytes.fromhex(key)
            except TypeError:
                raise click.BadParameter('Key must be a hex string')

            try:
                iv = bytes.fromhex(iv)
            except TypeError:
                raise click.BadParameter('IV must be a hex string')

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


@cli.group()
def img4() -> None:
    '''Image4 file commands'''

    pass


@img4.command('extract')
@click.option(
    '-i', '--img4', type=click.File('rb'), help='Input Image4 file', required=True
)
@click.option(
    '-p', '--im4p', type=click.File('wb'), help='File to output Image4 payload to'
)
@click.option(
    '-m', '--im4m', type=click.File('wb'), help='File to output Image4 manifest to'
)
@click.option(
    '-r', '--im4r', type=click.File('wb'), help='File to output Image4 restore info to'
)
def img4_extract(
    img4: Optional[BinaryIO],
    im4p: Optional[BinaryIO],
    im4m: Optional[BinaryIO],
    im4r: Optional[BinaryIO],
) -> None:
    '''Extract Image4 manifest/payload/restore info from an Image4 file'''

    img4 = pyimg4.IMG4(img4.read())

    if not any(i is not None for i in (im4p, im4m, im4r)):
        raise click.BadParameter('You must specify at least one output file')

    if im4p is not None:
        if img4.im4p is None:
            raise click.BadParameter('Image4 payload not found in Image4 file')

        im4p.write(img4.im4p.output())

    if im4m is not None:
        if img4.im4m is None:
            raise click.BadParameter('Image4 manifest not found in Image4 file')

        im4m.write(img4.im4m.output())

    if im4r is not None:
        if img4.im4r is None:
            raise click.BadParameter('Image4 restore info not found in Image4 file')

        im4r.write(img4.im4r.output())


if __name__ == '__main__':
    cli()
