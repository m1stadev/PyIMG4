import typing

import click

import pyimg4
from pyimg4 import Keybag, Compression


@click.group()
def cli():
    """ Swiss army knife to Apple's Image4 format """
    pass


@cli.command()
def version() -> None:
    """ Get current package version """
    print(f'pyimg4 {pyimg4.__version__}')


@cli.group()
def im4p() -> None:
    """ IM4P image options """
    pass


@im4p.command('info')
@click.argument('file', type=click.File('rb'))
def img4p_info(file) -> None:
    """ Print available information on given im4p image """
    im4p = pyimg4.IM4P(file.read())
    print(f'fourcc: {im4p.fourcc}')
    print(f'description: {im4p.description}')
    print(f'payload length: {len(im4p.payload)} Bytes')
    print(f'payload encrypted: {im4p.payload.encrypted}')
    print(f'payload compression: {im4p.payload.compression.name}')


@im4p.command('payload')
@click.argument('file', type=click.File('rb'))
@click.argument('out', type=click.File('wb'))
@click.option('-i', '--iv', help='The IV used to encrypt the payload')
@click.option('-k', '--key', help='The key used to encrypt the payload')
def img4_payload(file, out, iv, key) -> None:
    """ Extract the payload within the IM4P image """
    im4p = pyimg4.IM4P(file.read())
    im4p.payload.decrypt(Keybag(key=key, iv=iv))
    if im4p.payload.compression > Compression.NONE:
        im4p.payload.decompress()
    out.write(im4p.payload.output())


@cli.group()
def img4() -> None:
    """ IMG4 image options """
    pass


@im4p.command('extract')
@click.argument('file', type=click.File('rb'))
@click.option('--im4p', type=click.File('wb'), help='IM4P output file')
@click.option('--im4m', type=click.File('wb'), help='IM4M output file')
@click.option('--im4r', type=click.File('wb'), help='IM4R output file')
def img4_extract(file: typing.IO, im4p: typing.IO, im4m: typing.IO, im4r: typing.IO) -> None:
    """ Extract IM4P, IM4R & IM4M images """
    img4 = pyimg4.IMG4(file.read())
    if im4p:
        im4p.write(img4.im4p.output())
    if im4m:
        im4m.write(img4.im4m.output())
    if im4r:
        im4r.write(img4.im4r.output())


if __name__ == '__main__':
    cli()
