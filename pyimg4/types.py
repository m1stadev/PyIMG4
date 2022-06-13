from enum import IntEnum
from typing import NamedTuple, Optional


class Compression(IntEnum):
    UNKNOWN = -0x1
    NONE = 0x0
    LZSS = 0x1
    LZFSE = 0x2


class Payload(NamedTuple):
    data: bytes
    keybags: Optional[bytes]


class KeybagType(IntEnum):
    PRODUCTION = 0x0
    DEVELOPMENT = 0x1
