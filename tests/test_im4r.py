import pytest

import pyimg4


def test_create(boot_nonce: bytes) -> None:
    im4r = pyimg4.IM4R(boot_nonce=boot_nonce)

    im4r.boot_nonce = bytes.fromhex('1234567890123456')

    with pytest.raises(pyimg4.UnexpectedDataError):
        im4r.boot_nonce = 'Invalid boot nonce.'

    im4r.output()


def test_read(IM4R: bytes) -> None:
    im4r = pyimg4.IM4R(IM4R)

    assert im4r.boot_nonce.hex() == '7cd2c2e8aebb565f'

    im4r.output()
