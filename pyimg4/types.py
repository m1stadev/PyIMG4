from __future__ import annotations

from enum import IntEnum
from typing import NamedTuple


class Compression(IntEnum):
    NONE = 0x0
    LZSS = 0x1
    LZFSE = 0x2
    LZFSE_ENCRYPTED = 0x3


class Payload(NamedTuple):
    data: bytes
    keybags: bytes | None


class KeybagType(IntEnum):
    PRODUCTION = 0x1
    DEVELOPMENT = 0x2
