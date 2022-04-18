import pyimg4


def test_create(IM4M: bytes, IM4P: bytes, IMG4: bytes) -> None:
    img4 = pyimg4.IMG4(im4m=IM4M, im4p=IM4P)

    assert img4.output() == IMG4


def test_create_with_im4r(IM4M: bytes, IM4P: bytes, IM4R: bytes) -> None:
    img4 = pyimg4.IMG4(im4m=IM4M, im4p=IM4P, im4r=IM4R)

    img4.output()
