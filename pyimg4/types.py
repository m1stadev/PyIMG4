from enum import IntEnum


class Compression(IntEnum):
    UNKNOWN = -0x1
    NONE = 0x0
    LZSS = 0x1
    LZFSE = 0x2


class KeybagType(IntEnum):
    PRODUCTION = 0x0
    DEVELOPMENT = 0x1
