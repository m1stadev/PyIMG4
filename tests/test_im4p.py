import pyimg4
import pytest


def test_read_lzss_dec(dec_lzss: bytes) -> None:
    im4p = pyimg4.IM4P(dec_lzss)

    assert im4p.fourcc == 'krnl'
    assert im4p.description == 'KernelCacheBuilder_release-2238.10.3'

    assert im4p.payload.encrypted == False

    assert im4p.payload.compression == pyimg4.Compression.LZSS

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE
    assert im4p.payload.extra is not None and len(im4p.payload.extra) == 0xC000

    im4p.output()


def test_read_lzfse_dec(dec_lzfse: bytes) -> None:
    im4p = pyimg4.IM4P(dec_lzfse)

    assert im4p.fourcc == 'krnl'
    assert im4p.description == 'KernelCacheBuilder_release-2238.10.3'

    assert im4p.payload.compression == pyimg4.Compression.LZFSE

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE

    im4p.output()


def test_read_lzss_enc(enc_lzss: bytes) -> None:
    im4p = pyimg4.IM4P(enc_lzss)

    assert im4p.fourcc == 'krnl'
    assert im4p.description == 'KernelCacheBuilder-960.40.11'

    assert im4p.payload.encrypted == True
    assert len(im4p.payload.keybags) == 2

    assert im4p.payload.compression == pyimg4.Compression.UNKNOWN

    dec_kbag = pyimg4.Keybag(
        iv='6a6a294d029536665fc51b7bd493e2df',
        key='ba2bdd5485677d9b40465dd0e332b419f759cffcd57be73468afc61050d42091',
    )

    im4p.payload.decrypt(dec_kbag)

    assert im4p.payload.compression == pyimg4.Compression.LZSS

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE
    assert im4p.payload.extra is not None and len(im4p.payload.extra) == 0xC008

    im4p.output()


def test_read_lzfse_enc(enc_lzfse: bytes) -> None:
    im4p = pyimg4.IM4P(enc_lzfse)

    assert im4p.fourcc == 'ibss'
    assert im4p.description == 'iBoot-7429.12.15'

    assert im4p.payload.encrypted == True
    assert len(im4p.payload.keybags) == 2

    assert im4p.payload.compression == pyimg4.Compression.UNKNOWN

    dec_kbag = pyimg4.Keybag(
        iv='0d0a39d2e3ea94f70076192e7d225e9e',
        key='4567c8444b839a08b4a7c408531efb54ae69f1dcc24557ad0e21768b472f95cd',
    )

    im4p.payload.decrypt(dec_kbag)

    assert im4p.payload.compression == pyimg4.Compression.LZFSE

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE

    im4p.output()


def test_modify(IM4P: bytes) -> None:
    im4p = pyimg4.IM4P(IM4P)

    im4p.fourcc = 'im4p'

    with pytest.raises(pyimg4.UnexpectedDataError):
        im4p.fourcc = 'IM4P'

    with pytest.raises(pyimg4.UnexpectedDataError):
        im4p.fourcc = 'Invalid fourcc.'

    im4p.description = 'New description.'

    with pytest.raises(pyimg4.UnexpectedDataError):
        im4p.description = 0

    im4p.payload.extra = b'Extra data.'

    with pytest.raises(pyimg4.UnexpectedDataError):
        im4p.payload.extra = 'Invalid extra data.'

    im4p.output()
