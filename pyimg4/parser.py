from typing import List, Optional, Union
from zlib import adler32

import asn1
import liblzfse
import lzss
from Crypto.Cipher import AES

from .errors import *
from .types import *


class _PyIMG4:
    def __init__(self, data: bytes) -> None:
        self._data = data

        self._decoder = asn1.Decoder()
        self._encoder = asn1.Encoder()

    def _verify_fourcc(self, fourcc: str, correct: str = None) -> str:
        if not isinstance(fourcc, str):
            raise UnexpectedDataError('string', fourcc)

        if correct is not None:
            if fourcc.casefold() != correct.casefold():
                raise UnexpectedDataError(correct, fourcc)
            else:
                return fourcc

        if len(fourcc) != 4:
            raise UnexpectedDataError('string with length of 4', fourcc)

        return fourcc

    def output(self) -> bytes:
        return self._data


class Data(_PyIMG4):
    def get_type(self) -> Optional[Union['IMG4', 'IM4P', 'IM4M', 'IM4R']]:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()

        fourcc = self._verify_fourcc(self._decoder.read()[1])
        if fourcc == 'IMG4':
            return IMG4
        elif fourcc == 'IM4P':
            return IM4P
        elif fourcc == 'IM4M':
            return IM4M
        elif fourcc == 'IM4R':
            return IM4R


class ManifestProperty(_PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self._parse()

    def __repr__(self) -> str:
        return f'ManifestProperty({self.name}={self.value})'

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self.name = self._verify_fourcc(self._decoder.read()[1])
        self.value = self._decoder.read()[1]


class ManifestImageData(_PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self.properties: List[ManifestProperty] = []

        self._parse()

    def __repr__(self) -> str:
        return f'ManifestImageData(fourcc={self.fourcc})'

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()

        self.fourcc = self._verify_fourcc(self._decoder.read()[1])

        if self._decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Set)

        self._decoder.enter()

        while not self._decoder.eof():
            self.properties.append(ManifestProperty(self._decoder.read()[1]))


class IM4M(_PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self.images: List[ManifestImageData] = []
        self.properties: List[ManifestProperty] = []

        self._parse()

    def __repr__(self) -> str:
        repr_ = f'IM4M('
        for p in ('CHIP', 'ECID'):
            prop = next((prop for prop in self.properties if prop.name == p), None)

            if prop is not None:
                repr_ += f'{prop.name}={prop.value}, '

        return repr_[:-2] + ')' if ',' in repr_ else repr_ + ')'

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(self._decoder.read()[1], 'IM4M')

        if self._decoder.read()[0].nr != asn1.Numbers.Integer:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Integer)

        if self._decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Set)

        self._decoder.enter()

        if self._decoder.peek().cls != asn1.Classes.Private:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Classes.Private)

        self._decoder.enter()

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(
            self._decoder.read()[1], 'MANB'
        )  # Verify MANB (Manifest Body) FourCC

        if self._decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Set)

        self._decoder.enter()
        while True:
            if self._decoder.eof():
                break

            data = ManifestImageData(self._decoder.read()[1])
            if data.fourcc == 'MANP':
                self.properties = data.properties
            else:
                self.images.append(data)

        for _ in range(4):
            self._decoder.leave()

        self.rsa = self._decoder.read()[1]
        self.cert = self._decoder.read()[1]

    @property
    def apnonce(self) -> Optional[str]:
        return next(
            (prop.value.hex() for prop in self.properties if prop.name == 'BNCH'),
            None,
        )

    @property
    def chip_id(self) -> Optional[int]:
        return next(
            (prop.value for prop in self.properties if prop.name == 'CHIP'), None
        )

    @property
    def ecid(self) -> Optional[int]:
        return next(
            (prop.value for prop in self.properties if prop.name == 'ECID'), None
        )

    @property
    def sepnonce(self) -> Optional[str]:
        return next(
            (prop.value.hex() for prop in self.properties if prop.name == 'snon'),
            None,
        )


class IM4R(_PyIMG4):
    def __init__(self, data: bytes = None, *, generator: bytes = None) -> None:
        super().__init__(data)

        if generator:
            self.generator = generator

        elif data:
            self._parse()

        else:
            raise TypeError('No data or generator provided.')

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(self._decoder.read()[1], 'IM4R')  # Verify IM4R FourCC

        if self._decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Set)

        self._decoder.enter()

        if self._decoder.peek().cls != asn1.Classes.Private:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Classes.Private)

        self._decoder.enter()

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(
            self._decoder.read()[1], 'BNCN'
        )  # Verify BNCN (Boot Nonce) FourCC

        self.generator = self._decoder.read()[1]

    @property
    def generator(self) -> bytes:
        return self._generator

    @generator.setter
    def generator(self, generator: bytes) -> None:
        if not isinstance(generator, bytes):
            raise UnexpectedDataError('bytes', generator)

        if len(generator) != 8:
            raise UnexpectedDataError('bytes with length of 8', generator)

        self._generator = generator

    def output(self) -> bytes:
        self._encoder.start()

        self._encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)
        self._encoder.write(
            'IM4R', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        self._encoder.enter(asn1.Numbers.Set, asn1.Classes.Universal)
        self._encoder.enter(0x424E434E, asn1.Classes.Private)
        self._encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)

        self._encoder.write(
            'BNCN', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )
        self._encoder.write(
            self.generator,
            asn1.Numbers.OctetString,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        for _ in range(4):
            self._encoder.leave()

        return self._encoder.output()


class IMG4(_PyIMG4):
    def __init__(
        self,
        data: Optional[bytes] = None,
        *,
        im4p: Optional[Union['IM4P', bytes]] = None,
        im4m: Optional[Union[IM4M, bytes]] = None,
        im4r: Optional[Union[IM4R, bytes]] = None,
    ) -> None:
        super().__init__(data)

        if data:
            self._parse()
        else:
            self.im4p = im4p
            self.im4m = im4m
            self.im4r = im4r

    def __repr__(self) -> str:
        if self.im4p is not None:
            return f'IMG4(fourcc={self.im4p.fourcc}, description="{self.im4p.description}")'
        else:
            return 'IMG4()'

    def _parse(self) -> None:
        self._decoder.start(self._data)
        self._encoder.start()

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(self._decoder.read()[1], 'IMG4')  # Verify IMG4 FourCC

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._encoder.write(
            self._decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        self.im4p = IM4P(self._encoder.output())  # IM4P

        if self._decoder.peek().cls != asn1.Classes.Context:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Classes.Context)

        self.im4m = IM4M(self._decoder.read()[1])  # IM4M

        if not self._decoder.eof():
            if self._decoder.peek().cls != asn1.Classes.Context:
                raise UnexpectedTagError(self._decoder.peek(), asn1.Classes.Context)

            self.im4r = IM4R(self._decoder.read()[1])  # IM4R
        else:
            self.im4r = None

    @property
    def im4m(self) -> IM4M:
        return self._im4m

    @im4m.setter
    def im4m(self, im4m: Optional[Union[IM4M, bytes]]) -> None:
        if im4m is not None and not isinstance(im4m, (IM4M, bytes)):
            raise UnexpectedDataError('IM4M or bytes', im4m)

        self._im4m = IM4M(im4m) if isinstance(im4m, bytes) else im4m

    @property
    def im4p(self) -> Optional['IM4P']:
        return self._im4p

    @im4p.setter
    def im4p(self, im4p: Optional[Union['IM4P', bytes]]) -> None:
        if im4p is not None and not isinstance(im4p, (IM4P, bytes)):
            raise UnexpectedDataError('IM4P or bytes', im4p)

        self._im4p = IM4P(im4p) if isinstance(im4p, bytes) else im4p

    @property
    def im4r(self) -> Optional[IM4R]:
        return self._im4r

    @im4r.setter
    def im4r(self, im4r: Optional[Union[IM4R, bytes]]) -> None:
        if im4r is not None and not isinstance(im4r, (IM4R, bytes)):
            raise UnexpectedDataError('IM4R or bytes', im4r)

        self._im4r = IM4R(im4r) if isinstance(im4r, bytes) else im4r

    def output(self) -> bytes:
        self._encoder.start()

        self._encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)
        self._encoder.write(
            'IMG4', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        if self.im4p is None:
            raise ValueError('No IM4P is set.')

        self._decoder.start(self.im4p.output())
        self._encoder.write(
            self._decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )

        if self.im4m is None:
            raise ValueError('No IM4M is set.')

        self._encoder.write(
            self.im4m.output(),
            0,
            asn1.Types.Constructed,
            asn1.Classes.Context,
        )

        if self.im4r is not None:
            self._encoder.write(
                self.im4r.output(),
                1,
                asn1.Types.Constructed,
                asn1.Classes.Context,
            )

        self._encoder.leave()
        return self._encoder.output()


class IM4P(_PyIMG4):
    def __init__(
        self,
        data: Optional[bytes] = None,
        *,
        fourcc: Optional[str] = None,
        description: Optional[str] = None,
        payload: Optional[Union['IM4PData', bytes]] = None,
    ) -> None:
        super().__init__(data)

        if data:
            self._parse()
        else:
            self.fourcc = fourcc
            self.description = description
            self.payload = payload

    def __add__(self, im4m: IM4M) -> IMG4:
        if isinstance(im4m, IM4M):
            return IMG4(im4m=im4m, im4p=self)
        else:
            raise TypeError(
                f'can only concatenate IM4M (not "{im4m.__name__}") to IM4P'
            )

    __radd__ = __add__

    def __repr__(self) -> str:
        return f'IM4P(fourcc={self.fourcc}, description="{self.description}")'

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Sequence)

        self._decoder.enter()
        self._verify_fourcc(
            self._decoder.read()[1], 'IM4P'
        )  # Verify IM4P (IMG4 Payload) FourCC

        if self._decoder.peek().nr != asn1.Numbers.IA5String:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.IA5String)

        self.fourcc = self._verify_fourcc(
            self._decoder.read()[1]
        )  # Will raise error if FourCC is invalid

        if self._decoder.peek().nr != asn1.Numbers.IA5String:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.IA5String)

        self.description = self._decoder.read()[1]

        if self._decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.OctetString)

        payload_data = self._decoder.read()[1]

        kbag_data = None
        while not self._decoder.eof():
            if self._decoder.peek().nr == asn1.Numbers.OctetString:
                kbag_data = self._decoder.read()[1]
                break

            self._decoder.read()

        if kbag_data is not None:
            kbag_decoder = asn1.Decoder()
            kbag_decoder.start(kbag_data)

            if kbag_decoder.peek().nr != asn1.Numbers.Sequence:
                raise UnexpectedTagError(kbag_decoder.peek(), asn1.Numbers.Sequence)

            kbag_decoder.enter()

            keybags = []
            for kt in KeybagType:
                if kbag_decoder.peek().nr != asn1.Numbers.Sequence:
                    raise UnexpectedTagError(kbag_decoder.peek(), asn1.Numbers.Sequence)

                keybags.append(Keybag(kbag_decoder.read()[1], kt))

            self.payload = IM4PData(payload_data, keybags=keybags)

        else:
            self.payload = IM4PData(payload_data)

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, description: Optional[str]) -> None:
        if description is not None and not isinstance(description, str):
            raise UnexpectedDataError('string', description)

        self._description = description or ''

    @property
    def fourcc(self) -> Optional[str]:
        return self._fourcc

    @fourcc.setter
    def fourcc(self, fourcc: Optional[str]) -> None:
        if fourcc is None:
            self._fourcc = fourcc

        elif isinstance(fourcc, str):
            if not fourcc.islower():
                raise UnexpectedDataError('lowercase string', fourcc)

            self._fourcc = self._verify_fourcc(fourcc)
        else:
            raise UnexpectedDataError('string', fourcc)

    @property
    def payload(self) -> Optional['IM4PData']:
        return self._payload

    @payload.setter
    def payload(self, payload: Optional[Union['IM4PData', bytes]]) -> None:
        if payload is not None and not isinstance(payload, (IM4PData, bytes)):
            raise UnexpectedDataError('IM4PData or bytes', payload)

        self._payload = IM4PData(payload) if isinstance(payload, bytes) else payload

    def output(self) -> bytes:
        self._encoder.start()

        self._encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)
        self._encoder.write(
            'IM4P', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        if self.fourcc is None:
            raise ValueError('No FourCC is set.')

        self._encoder.write(
            self.fourcc,
            asn1.Numbers.IA5String,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        self._encoder.write(
            self.description,
            asn1.Numbers.IA5String,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        if self.payload is None:
            raise ValueError('No payload is set.')

        self._encoder.write(
            self.payload.output(),
            asn1.Numbers.OctetString,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        if self.payload.compression == Compression.LZFSE:
            self._encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)

            self._encoder.write(
                1,
                asn1.Numbers.Integer,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            self.payload.decompress()
            self._encoder.write(
                len(self.payload.output()),
                asn1.Numbers.Integer,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )
            self.payload.compress(Compression.LZFSE)

            self._encoder.leave()

        self._encoder.leave()
        return self._encoder.output()


class Keybag(_PyIMG4):
    def __init__(
        self,
        data: bytes = None,
        type_: KeybagType = KeybagType.RELEASE,  # Assume RELEASE if not provided
        *,
        iv: Union[bytes, str] = None,
        key: Union[bytes, str] = None,
    ) -> None:
        super().__init__(data)

        if iv and key:
            if isinstance(iv, str):
                try:
                    iv = bytes.fromhex(iv)
                except ValueError:
                    raise AESError('Invalid IV provided.')

            if len(iv) == 16:
                self.iv = iv
            else:
                raise AESError('Invalid IV length.')

            if isinstance(key, str):
                try:
                    key = bytes.fromhex(key)
                except ValueError:
                    raise AESError('Invalid key provided.')

            if len(key) == 32:
                self.key = key
            else:
                raise AESError('Invalid key length.')

        elif data:
            self._parse()

        else:
            raise TypeError('No data or IV/Key provided.')

        self.type = type_

    def __repr__(self) -> str:
        return (
            f"Keybag(iv={self.iv.hex()}, key={self.key.hex()}, type={self.type.name})"
        )

    def _parse(self) -> None:
        self._decoder.start(self._data)

        if self._decoder.read()[0].nr != asn1.Numbers.Integer:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.Integer)

        if self._decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.OctetString)

        self.iv = self._decoder.read()[1]

        if self._decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self._decoder.peek(), asn1.Numbers.OctetString)

        self.key = self._decoder.read()[1]


class IM4PData(_PyIMG4):
    def __init__(self, data: bytes, *, keybags: List[Keybag] = []) -> None:
        super().__init__(data)

        self.keybags = keybags
        self.extra: Optional[bytes] = None

    def __repr__(self) -> str:
        repr_ = f'IM4PData(payload length={len(self._data)}, encrypted={self.encrypted}'
        if self.compression not in (Compression.UNKNOWN, Compression.NONE):
            repr_ += f', compression={self.compression.name}'

        return repr_ + ')'

    def _parse_complzss_header(self) -> None:
        cmp_len = int(self._data[0x10:0x14].hex(), 16)

        if (
            cmp_len < len(self._data) - 0x180
        ):  # iOS 9+ A7-A9 kernelcache, so KPP is appended to the LZSS-compressed data
            extra_len = len(self._data) - cmp_len - 0x180
            self.extra = self._data[-extra_len:]

            self._data = self._data[:-extra_len]

        self._data = self._data[0x180:]

    def _create_complzss_header(self) -> bytes:
        header = bytearray(b'complzss')
        header += adler32(self._data).to_bytes(4, 'big')
        header += len(self._data).to_bytes(4, 'big')
        header += len(lzss.compress(self._data)).to_bytes(4, 'big')
        header += int(1).to_bytes(4, 'big')
        header += bytearray(0x180 - len(header))

        return bytes(header)

    @property
    def compression(self) -> Compression:
        if self.encrypted:
            return Compression.UNKNOWN

        elif self._data.startswith(b'complzss'):
            return Compression.LZSS

        elif self._data.startswith(b'bvx2') and self._data.endswith(b'bvx$'):
            return Compression.LZFSE

        else:
            return Compression.NONE

    @property
    def encrypted(self) -> bool:
        return len(self.keybags) > 0

    @property
    def extra(self) -> Optional[bytes]:
        return self._extra

    @extra.setter
    def extra(self, extra: Optional[bytes]) -> None:
        if extra is not None and not isinstance(extra, bytes):
            raise UnexpectedDataError('bytes', extra)

        self._extra = extra

    def compress(self, compression: Compression) -> None:
        if compression in (Compression.UNKNOWN, Compression.NONE):
            raise CompressionError('A valid compression type must be specified.')

        elif self.compression == compression:
            raise CompressionError(f'Payload is already {compression.name}-compressed.')

        if self.compression != Compression.NONE:
            self.decompress()

        if compression == Compression.LZSS:
            self._data = self._create_complzss_header() + lzss.compress(self._data)

            if self.extra is not None:
                self._data += self.extra

        elif compression == Compression.LZFSE:
            self._data = liblzfse.compress(self._data)

            if self.compression != Compression.LZFSE:  # If bvx2 header isn't present
                self._data = liblzfse.decompress(self._data)
                raise CompressionError('Failed to LZFSE-compress payload.')

    def decompress(self) -> None:
        if self.compression == Compression.UNKNOWN:
            raise CompressionError('Cannot decompress encrypted payload.')

        if self.compression == Compression.LZSS:
            self._parse_complzss_header()
            self._data = lzss.decompress(self._data)
        elif self.compression == Compression.LZFSE:
            self._data = liblzfse.decompress(self._data)
        else:
            raise CompressionError('Payload is not compressed.')

    def decrypt(self, kbag: Keybag) -> None:
        try:
            self._data = AES.new(kbag.key, AES.MODE_CBC, kbag.iv).decrypt(self._data)
            self.keybags = []
        except:
            raise AESError('Failed to decrypt payload.')
