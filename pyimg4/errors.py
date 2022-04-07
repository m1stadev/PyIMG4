from asn1 import Classes, Numbers, Tag
from typing import Any, NoReturn, Union


class PyIMG4Error(Exception):
    pass


class AESError(PyIMG4Error):
    pass


class CompressionError(PyIMG4Error):
    pass


class UnexpectedDataError(PyIMG4Error):
    def __init__(self, expect: str, real: Any) -> NoReturn:
        if not isinstance(real, (float, int)) and len(real) > 15:
            real = f'{type(real).__name__} with len of {len(real)}'

        super().__init__(f"Expected data: {expect}, got: {real}")


class UnexpectedTagError(PyIMG4Error):
    def __init__(self, tag: Tag, valid: Union[Classes, Numbers]) -> NoReturn:
        try:
            tag_type = next(t.name for t in Numbers if t.value == tag.nr)
        except StopIteration:
            tag_type = f"{next(t.name for t in Classes if t.value == tag.cls)} {tag.nr if tag.cls == Classes.Private else ''}"

        if isinstance(valid, Numbers):
            expected_type = next(t.name for t in Numbers if t.value == valid)
        if isinstance(valid, Classes):
            expected_type = next(t.name for t in Classes if t.value == tag.cls)

        super().__init__(f"Expected tag of type {expected_type}, got {tag_type}")
