from enum import IntEnum


class Compression(IntEnum):
    NONE = 0
    LZSS = 1
    LZFSE = 2


class GIDKeyType(IntEnum):
    RELEASE = 0
    INTERNAL = 1
