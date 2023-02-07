import pytest

import pyimg4


def test_create() -> None:
    im4r = pyimg4.IM4R()

    im4r.boot_nonce = bytes.fromhex('1234567890123456')

    with pytest.raises(pyimg4.UnexpectedDataError):
        im4r.boot_nonce = 'Invalid boot nonce.'

    im4r.output()


def test_read(IM4R: bytes) -> None:
    im4r = pyimg4.IM4R(IM4R)

    assert im4r.boot_nonce.hex() == '5f56bbaee8c2d27c'

    im4r.output()
