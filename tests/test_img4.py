import pyimg4


def test_create(IM4M: bytes, IM4P: bytes, IMG4: bytes) -> None:
    im4m = pyimg4.IM4M(IM4M)
    im4p = pyimg4.IM4P(IM4P)

    img4 = im4m + im4p

    assert img4.output() == IMG4


def test_create_with_im4r(IM4M: bytes, IM4P: bytes, IM4R: bytes) -> None:
    im4m = pyimg4.IM4M(IM4M)
    im4p = pyimg4.IM4P(IM4P)

    img4 = im4m + im4p

    img4.im4r = pyimg4.IM4R(data=IM4R)

    img4.output()
