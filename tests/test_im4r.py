import pyimg4
import pytest


def test_input(IM4R: bytes) -> None:
    im4r = pyimg4.IM4R(data=IM4R)

    im4r.output()


def test_create(generator: bytes) -> None:
    im4r = pyimg4.IM4R(generator=generator)

    im4r.output()


def test_create_invalid() -> None:
    with pytest.raises(pyimg4.errors.UnexpectedDataError):
        pyimg4.IM4R(generator='Invalid generator.')
