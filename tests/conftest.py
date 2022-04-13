from remotezip import RemoteZip

import pytest

LZSS_IPSW = 'https://updates.cdn-apple.com/2021FallFCS/fullrestores/002-03194/8EC63AF9-19BE-4829-B389-27AECB41DD6A/iPhone_5.5_15.0_19A346_Restore.ipsw'
LZFSE_IPSW = 'https://updates.cdn-apple.com/2021FallFCS/fullrestores/002-02910/AF984499-D03A-43E7-9472-6D16BA756E5E/iPhone10,3,iPhone10,6_15.0_19A346_Restore.ipsw'


@pytest.fixture(scope='session')
def fetch_dec_lzss_im4p():
    with RemoteZip(LZSS_IPSW) as ipsw:
        return ipsw.read('kernelcache.release.n66')


@pytest.fixture(scope='session')
def fetch_dec_lzfse_im4p():
    with RemoteZip(LZFSE_IPSW) as ipsw:
        return ipsw.read('kernelcache.release.iphone10b')


@pytest.fixture(scope='session')
def fetch_enc_lzfse_im4p():
    with RemoteZip(LZFSE_IPSW) as ipsw:
        return ipsw.read('Firmware/dfu/iBSS.d22.RELEASE.im4p')
