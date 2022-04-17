from enum import IntEnum


class Compression(IntEnum):
    UNKNOWN = -0x1
    NONE = 0x0
    LZSS = 0x1
    LZFSE = 0x2


class KeybagType(IntEnum):
    RELEASE = 0x0
    INTERNAL = 0x1
