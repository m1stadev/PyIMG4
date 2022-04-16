import pyimg4


def test_im4m(IM4M: bytes) -> None:
    im4m = pyimg4.IM4M(IM4M)

    assert (
        im4m.apnonce
        == '0123456789012345678901234567890123456789012345678901234567890123'
    )

    assert im4m.ecid == 0x0123456789012
    assert im4m.sepnonce == '0123456789012345678901234567890123456789'
