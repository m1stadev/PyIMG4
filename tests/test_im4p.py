import pyimg4


def test_decomp_lzss(fetch_dec_lzss_im4p) -> None:
    im4p = pyimg4.IM4P(fetch_dec_lzss_im4p)

    assert im4p.payload.compression == pyimg4.Compression.LZSS

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE


def test_decomp_lzfse_dec(fetch_dec_lzfse_im4p) -> None:
    im4p = pyimg4.IM4P(fetch_dec_lzfse_im4p)

    assert im4p.payload.compression == pyimg4.Compression.LZFSE

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE


def test_decomp_lzfse_enc(fetch_enc_lzfse_im4p) -> None:
    im4p = pyimg4.IM4P(fetch_enc_lzfse_im4p)

    assert im4p.payload.encrypted == True

    dec_kbag = pyimg4.Keybag(
        iv='0d0a39d2e3ea94f70076192e7d225e9e',
        key='4567c8444b839a08b4a7c408531efb54ae69f1dcc24557ad0e21768b472f95cd',
    )

    im4p.payload.decrypt(dec_kbag)

    assert im4p.payload.compression == pyimg4.Compression.LZFSE

    im4p.payload.decompress()

    assert im4p.payload.compression == pyimg4.Compression.NONE
