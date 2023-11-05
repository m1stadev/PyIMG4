import pytest

import pyimg4


def test_create(TEST_PAYLOAD: bytes, IM4P: bytes) -> None:
    im4p = pyimg4.IM4P()

    im4p.payload = TEST_PAYLOAD

    im4p.fourcc = 'test'

    im4p.description = 'Test Image4 payload.'

    with pytest.raises(pyimg4.UnexpectedDataError):
        im4p.description = 0

    assert im4p == IM4P


def test_read_lzss_dec(DEC_LZSS_IM4P: bytes) -> None:
    im4p = pyimg4.IM4P(DEC_LZSS_IM4P)

    assert im4p.fourcc == 'krnl'
    assert im4p.description == 'KernelCacheBuilder_release-2238.10.3'

    assert im4p.payload.encrypted is False

    assert im4p.payload.compression == pyimg4.Compression.LZSS

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE
    assert im4p.payload.extra is not None and len(im4p.payload.extra) == 0xC000

    im4p.output()


def test_read_lzss_enc(ENC_LZSS_IM4P: bytes) -> None:
    im4p = pyimg4.IM4P(ENC_LZSS_IM4P)

    assert im4p.fourcc == 'krnl'
    assert im4p.description == 'KernelCacheBuilder-960.40.11'

    assert im4p.payload.encrypted is True
    assert len(im4p.payload.keybags) == 2

    assert im4p.payload.compression == pyimg4.Compression.NONE

    dec_kbag = pyimg4.Keybag(
        iv=bytes.fromhex('6a6a294d029536665fc51b7bd493e2df'),
        key=bytes.fromhex(
            'ba2bdd5485677d9b40465dd0e332b419f759cffcd57be73468afc61050d42091',
        ),
    )

    im4p.payload.decrypt(dec_kbag)

    assert im4p.payload.compression == pyimg4.Compression.LZSS

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE
    assert im4p.payload.extra is not None and len(im4p.payload.extra) == 0xC008

    im4p.output()


def test_read_lzfse_dec(DEC_LZFSE_IM4P: bytes) -> None:
    im4p = pyimg4.IM4P(DEC_LZFSE_IM4P)

    assert im4p.fourcc == 'krnl'
    assert im4p.description == 'KernelCacheBuilder_release-2238.10.3'

    assert im4p.payload.compression == pyimg4.Compression.LZFSE

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE

    im4p.output()


def test_read_lzfse_enc(ENC_LZFSE_IM4P: bytes) -> None:
    im4p = pyimg4.IM4P(ENC_LZFSE_IM4P)

    assert im4p.fourcc == 'ibss'
    assert im4p.description == 'iBoot-7429.12.15'

    assert im4p.payload.encrypted is True
    assert len(im4p.payload.keybags) == 2

    assert im4p.payload.compression == pyimg4.Compression.LZFSE_ENCRYPTED

    dec_kbag = pyimg4.Keybag(
        iv=bytes.fromhex('0d0a39d2e3ea94f70076192e7d225e9e'),
        key=bytes.fromhex(
            '4567c8444b839a08b4a7c408531efb54ae69f1dcc24557ad0e21768b472f95cd'
        ),
    )

    im4p.payload.decrypt(dec_kbag)

    assert im4p.payload.compression == pyimg4.Compression.LZFSE

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE

    im4p.output()


def test_read_payp(PAYP_IM4P: bytes) -> None:
    im4p = pyimg4.IM4P(PAYP_IM4P)

    assert im4p.fourcc == 'ibss'
    assert im4p.description == 'iBoot-8419.40.112'

    assert im4p.payload.encrypted is True
    assert len(im4p.payload.keybags) == 2

    assert im4p.payload.compression == pyimg4.Compression.LZFSE_ENCRYPTED

    assert len(im4p.properties) == 2
    assert all(prop.fourcc in ('mmap', 'rddg') for prop in im4p.properties)

    im4p.output()
