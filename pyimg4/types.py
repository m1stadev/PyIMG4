from enum import IntEnum
from .errors import UnexpectedDataError

import asn1


class PyIMG4:
    def __init__(self, data: bytes = None) -> None:
        self.data = data

        self.decoder = asn1.Decoder()
        self.encoder = asn1.Encoder()

    def _verify_fourcc(self, fourcc: str, correct: str = None) -> str:
        if correct is not None:
            if fourcc.casefold() != correct.casefold():
                raise UnexpectedDataError(correct, fourcc)
            else:
                return fourcc

        if not isinstance(fourcc, str):
            raise UnexpectedDataError('string', fourcc)

        if len(fourcc) != 4:
            raise UnexpectedDataError('string with length of 4', fourcc)

        return fourcc


class Compression(IntEnum):
    NONE = 0
    LZSS = 1
    LZFSE = 2


class GIDKeyType(IntEnum):
    RELEASE = 0
    INTERNAL = 1
