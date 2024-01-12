from pathlib import Path

import pytest
from remotezip import RemoteIOError, RemoteZip

LZSS_DEC_IPSW = 'https://updates.cdn-apple.com/2021FallFCS/fullrestores/002-03194/8EC63AF9-19BE-4829-B389-27AECB41DD6A/iPhone_5.5_15.0_19A346_Restore.ipsw'
LZSS_ENC_IPSW = 'http://appldnld.apple.com/iOS9.3.5/031-73130-20160825-6A2C2FD4-6711-11E6-B3F4-173834D2D062/iPhone8,2_9.3.5_13G36_Restore.ipsw'
LZFSE_IPSW = 'https://updates.cdn-apple.com/2021FallFCS/fullrestores/002-02910/AF984499-D03A-43E7-9472-6D16BA756E5E/iPhone10,3,iPhone10,6_15.0_19A346_Restore.ipsw'
PAYP_IPSW = 'https://updates.cdn-apple.com/2022FallFCS/fullrestores/032-11449/3995EAD9-8F0E-491E-BEC8-C97B6B1845C7/iPhone15,3_16.1.2_20B110_Restore.ipsw'


def get_ipsw_file(url: str, filename: str) -> bytes:
    while True:
        try:
            rz = RemoteZip(url)
            break
        except RemoteIOError:
            continue

    data = rz.read(filename)
    rz.close()
    return data


@pytest.fixture(name='DEC_LZSS_IM4P', scope='session')
def fetch_dec_lzss_im4p() -> bytes:
    return get_ipsw_file(LZSS_DEC_IPSW, 'kernelcache.release.n66')


@pytest.fixture(name='ENC_LZSS_IM4P', scope='session')
def fetch_enc_lzss_im4p() -> bytes:
    return get_ipsw_file(LZSS_ENC_IPSW, 'kernelcache.release.n66')


@pytest.fixture(name='DEC_LZFSE_IM4P', scope='session')
def fetch_dec_lzfse_im4p() -> bytes:
    return get_ipsw_file(LZFSE_IPSW, 'kernelcache.release.iphone10b')


@pytest.fixture(name='ENC_LZFSE_IM4P', scope='session')
def fetch_enc_lzfse_im4p() -> bytes:
    return get_ipsw_file(LZFSE_IPSW, 'Firmware/dfu/iBSS.d22.RELEASE.im4p')


@pytest.fixture(name='PAYP_IM4P', scope='session')
def fetch_payp_im4p() -> bytes:
    return get_ipsw_file(PAYP_IPSW, 'Firmware/dfu/iBSS.d74.RELEASE.im4p')


@pytest.fixture(name='TEST_PAYLOAD', scope='session')
def fetch_test_payload() -> bytes:
    with (Path(__file__).parent / 'bin' / 'test_payload').open('rb') as f:
        return f.read()


@pytest.fixture(name='IMG4', scope='session')
def read_img4() -> bytes:
    with (Path(__file__).parent / 'bin' / 'IMG4').open('rb') as f:
        return f.read()


@pytest.fixture(name='IM4M', scope='session')
def read_im4m() -> bytes:
    with (Path(__file__).parent / 'bin' / 'IM4M').open('rb') as f:
        return f.read()


@pytest.fixture(name='IM4P', scope='session')
def read_im4p() -> bytes:
    with (Path(__file__).parent / 'bin' / 'IM4P').open('rb') as f:
        return f.read()


@pytest.fixture(name='IM4R', scope='session')
def read_im4r() -> bytes:
    with (Path(__file__).parent / 'bin' / 'IM4R').open('rb') as f:
        return f.read()
