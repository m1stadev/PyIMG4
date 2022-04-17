import pyimg4


def test_create(IM4M: bytes, IM4P: bytes, IMG4: bytes) -> None:
    im4m = pyimg4.IM4M(IM4M)
    im4p = pyimg4.IM4P(IM4P)

    img4 = im4m + im4p

    assert img4.output() == IMG4
