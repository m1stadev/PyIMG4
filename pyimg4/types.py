from enum import IntEnum


class Compression(IntEnum):
    NONE = 0
    LZSS = 1
    LZFSE = 2


class KeybagType(IntEnum):
    RELEASE = 0x0
    INTERNAL = 0x1
