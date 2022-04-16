import pyimg4


def test_create(IM4M, IM4P) -> None:
    im4m = pyimg4.IM4M(IM4M)
    im4p = pyimg4.IM4P(IM4P)

    img4 = im4m + im4p

    assert img4.im4p.fourcc == 'test'
    assert img4.im4p.description == 'Test IM4P file.'

    assert img4.im4p.payload.compression == pyimg4.Compression.NONE
    assert img4.im4p.payload.encrypted == False
    assert img4.im4r is None
