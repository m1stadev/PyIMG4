import pytest

import pyimg4


def test_create(generator: bytes) -> None:
    im4r = pyimg4.IM4R(generator=generator)

    im4r.generator = bytes.fromhex('1234567890123456')

    with pytest.raises(pyimg4.UnexpectedDataError):
        im4r.generator = 'Invalid generator.'

    im4r.output()

def test_read(IM4R: bytes) -> None:
    im4r = pyimg4.IM4R(IM4R)

    assert im4r.generator.hex() == '7cd2c2e8aebb565f'

    im4r.output()