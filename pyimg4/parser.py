from .errors import *
from .types import *
from Crypto.Cipher import AES
from typing import Optional, Union
from zlib import adler32

import asn1
import liblzfse
import lzss


class _PyIMG4:
    def __init__(self, data: bytes) -> None:
        self._data = data

        self.decoder = asn1.Decoder()
        self.encoder = asn1.Encoder()

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


class PyIMG4Data(_PyIMG4):
    def get_type(self) -> Union['IMG4', 'IM4P', 'IM4M']:
        self.decoder.start(self._data)

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()

        fourcc = self._verify_fourcc(self.decoder.read()[1])
        if fourcc == 'IMG4':
            return IMG4
        elif fourcc == 'IM4P':
            return IM4P
        elif fourcc == 'IM4M':
            return IM4M


class ManifestProperty(_PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self._parse()

    def __repr__(self) -> str:
        return f'ManifestProperty({self.name}={self.value})'

    def _parse(self) -> None:
        self.decoder.start(self._data)

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self.name = self._verify_fourcc(self.decoder.read()[1])
        self.value = self.decoder.read()[1]


class ManifestImageData(_PyIMG4):
    def __init__(self, fourcc: str, data: bytes) -> None:
        super().__init__(data)

        self.fourcc = fourcc
        self.properties: list[ManifestProperty] = []
        self._parse()

    def __repr__(self) -> str:
        return f'ManifestImageData(fourcc={self.fourcc})'

    def _parse(self) -> None:
        self.decoder.start(self._data)

        if self.decoder.peek().cls != asn1.Classes.Private:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Classes.Private)

        while not self.decoder.eof():
            self.properties.append(ManifestProperty(self.decoder.read()[1]))


class IM4M(_PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self.properties: list[ManifestProperty] = []
        self.images: list[ManifestImageData] = []
        self._parse()

    def __repr__(self) -> str:
        repr_ = f'IM4M('
        for p in ('CHIP', 'ECID'):
            try:
                prop = next(prop for prop in self.properties if prop.name == p)
            except StopIteration:
                continue

            repr_ += f'{prop.name}={prop.value}, '

        return repr_[:-2] + ')'

    def __add__(self, obj: 'IM4P') -> 'IMG4':
        if isinstance(obj, IM4P):
            return obj.create_img4(self)
        else:
            raise TypeError(f'can only concatenate IM4P (not "{obj.__name__}") to IM4M')

    def _parse(self) -> None:
        self.decoder.start(self._data)

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self._verify_fourcc(self.decoder.read()[1], 'IM4M')

        if self.decoder.read()[0].nr != asn1.Numbers.Integer:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Integer)

        if self.decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Set)

        self.decoder.enter()

        if self.decoder.peek().cls != asn1.Classes.Private:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Classes.Private)

        self.decoder.enter()

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self._verify_fourcc(
            self.decoder.read()[1], 'MANB'
        )  # Verify MANB (Manifest Body) FourCC

        if self.decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Set)

        self.decoder.enter()
        while True:
            if self.decoder.eof():
                break

            if self.decoder.peek().cls != asn1.Classes.Private:
                raise UnexpectedTagError(self.decoder.peek(), asn1.Classes.Private)

            self.decoder.enter()

            if self.decoder.peek().nr != asn1.Numbers.Sequence:
                raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

            self.decoder.enter()
            fourcc = self._verify_fourcc(self.decoder.read()[1])

            if self.decoder.peek().nr != asn1.Numbers.Set:
                raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Set)

            if fourcc == 'MANP':
                self.decoder.enter()

                while not self.decoder.eof():
                    self.properties.append(ManifestProperty(self.decoder.read()[1]))

                self.decoder.leave()

            else:
                self.images.append(ManifestImageData(fourcc, self.decoder.read()[1]))

            for _ in range(2):
                self.decoder.leave()

        for _ in range(4):
            self.decoder.leave()

        self.rsa = self.decoder.read()[1]
        self.cert = self.decoder.read()[1]

    @property
    def apnonce(self) -> Optional[str]:
        return next(
            (prop.value.hex() for prop in self.properties if prop.name == 'BNCH'),
            None,
        )

    @property
    def sepnonce(self) -> Optional[str]:
        return next(
            (prop.value.hex() for prop in self.properties if prop.name == 'snon'),
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


class IM4R(_PyIMG4):
    def __init__(self, *, generator: bytes = None, data: bytes = None) -> None:
        if generator:
            self.generator = generator

        elif data:
            super().__init__(data)
            self._parse()

        else:
            raise TypeError('No data or generator provided.')

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

    def _parse(self) -> None:
        self.decoder.start(self._data)

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self._verify_fourcc(self.decoder.read()[1], 'IM4R')  # Verify IM4R FourCC

        if self.decoder.peek().nr != asn1.Numbers.Set:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Set)

        self.decoder.enter()

        if self.decoder.peek().cls != asn1.Classes.Private:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Classes.Private)

        self.decoder.enter()

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self._verify_fourcc(
            self.decoder.read()[1], 'BNCN'
        )  # Verify BNCN (Boot Nonce) FourCC

        self.generator = self.decoder.read()[1]

    def output(self) -> bytes:
        self.encoder.start()

        self.encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)
        self.encoder.write(
            'IM4R', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        self.encoder.enter(
            asn1.Numbers.Set, asn1.Types.Constructed, asn1.Classes.Universal
        )
        self.encoder.enter(
            asn1.Numbers.Sequence, asn1.Types.Constructed, asn1.Classes.Private
        )

        self.encoder.write(
            'BNCN', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )
        self.encoder.write(
            self.generator,
            asn1.Numbers.OctetString,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        for _ in range(3):
            self.encoder.leave()

        return self.encoder.output()


class IMG4(_PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self.im4r: Optional[IM4R] = None
        self._parse()

    def __repr__(self) -> str:
        return f'IMG4(fourcc={self.im4p.fourcc}, description={self.im4p.description})'

    def _parse(self) -> None:
        self.decoder.start(self._data)
        self.encoder.start()

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self._verify_fourcc(self.decoder.read()[1], 'IMG4')  # Verify IMG4 FourCC

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.im4p = IM4P(self.decoder.read()[1])  # IM4P

        if self.decoder.peek().cls != asn1.Classes.Context:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Classes.Context)

        self.im4m = IM4M(self.decoder.read()[1])  # IM4M

        if not self.decoder.eof():
            if self.decoder.peek().cls != asn1.Classes.Context:
                raise UnexpectedTagError(self.decoder.peek(), asn1.Classes.Context)

            self.im4r = IM4R(self.decoder.read()[1])  # IM4R

    def output(self) -> bytes:
        self.encoder.start()

        self.encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)
        self.encoder.write(
            'IMG4', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        self.decoder.start(self.im4p.output())
        self.encoder.write(
            self.decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )

        self.encoder.write(
            self.im4m.output(),
            0,
            asn1.Types.Constructed,
            asn1.Classes.Context,
        )

        self.encoder.leave()
        return self.encoder.output()


class IM4P(_PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self.keybags: list[Keybag] = []

        if self._data:  # Parse provided data
            self._parse()

    def __add__(self, obj: IM4M) -> IMG4:
        if isinstance(obj, IM4M):
            return self.create_img4(obj)
        else:
            raise TypeError(f'can only concatenate IM4M (not "{obj.__name__}") to IM4P')

    def __repr__(self) -> str:
        return f'IM4P(fourcc={self.fourcc}, description={self.description})'

    def _parse(self) -> None:
        self.decoder.start(self._data)

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self._verify_fourcc(
            self.decoder.read()[1], 'IM4P'
        )  # Verify IM4P (IMG4 Payload) FourCC

        if self.decoder.peek().nr != asn1.Numbers.IA5String:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.IA5String)

        self.fourcc = self._verify_fourcc(
            self.decoder.read()[1]
        )  # Will raise error if FourCC is invalid

        if self.decoder.peek().nr != asn1.Numbers.IA5String:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.IA5String)

        self.description = self.decoder.read()[1]

        if self.decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.OctetString)

        payload_data = self.decoder.read()[1]

        kbag_data = None
        while not self.decoder.eof():
            if self.decoder.peek().nr == asn1.Numbers.OctetString:
                kbag_data = self.decoder.read()[1]
                break

            self.decoder.read()

        if kbag_data is not None:
            kbag_decoder = asn1.Decoder()
            kbag_decoder.start(kbag_data)

            if kbag_decoder.peek().nr != asn1.Numbers.Sequence:
                raise UnexpectedTagError(kbag_decoder.peek(), asn1.Numbers.Sequence)

            kbag_decoder.enter()

            for kt in KeybagType:
                if kbag_decoder.peek().nr != asn1.Numbers.Sequence:
                    raise UnexpectedTagError(kbag_decoder.peek(), asn1.Numbers.Sequence)

                self.keybags.append(Keybag(kt, data=kbag_decoder.read()[1]))

        self.payload = IM4PData(payload_data, self.keybags)

    @property
    def fourcc(self) -> str:
        return self._fourcc

    @fourcc.setter
    def fourcc(self, fourcc: str) -> None:
        self._fourcc = self._verify_fourcc(fourcc)

    def create_img4(self, im4m: IM4M) -> IMG4:
        # Don't use self.encoder as it will be used by IM4P.output()
        encoder = asn1.Encoder()
        encoder.start()

        encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)
        encoder.write(
            'IMG4', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        encoder.write(
            self.output(),
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )

        encoder.write(
            im4m.output(),
            0,
            asn1.Types.Constructed,
            asn1.Classes.Context,
        )

        encoder.leave()
        return IMG4(encoder.output())

    def output(self) -> bytes:
        self.encoder.start()

        self.encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)
        self.encoder.write(
            'IM4P', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        self.encoder.write(
            self.fourcc,
            asn1.Numbers.IA5String,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        self.encoder.write(
            self.description,
            asn1.Numbers.IA5String,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        self.encoder.write(
            self.payload.output(),
            asn1.Numbers.OctetString,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        if (
            self.payload.encrypted == False
            and self.payload.compression == Compression.LZFSE
        ):
            self.encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)

            self.encoder.write(
                1,
                asn1.Numbers.Integer,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            self.payload.decompress()
            self.encoder.write(
                len(self.payload.output()),
                asn1.Numbers.Integer,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )
            self.payload.compress(Compression.LZFSE)

            self.encoder.leave()

        self.encoder.leave()
        return self.encoder.output()


class Keybag(_PyIMG4):
    def __init__(
        self,
        type_: KeybagType = KeybagType.RELEASE,  # Assume RELEASE if not provided
        *,
        iv: Union[bytes, str] = None,
        key: Union[bytes, str] = None,
        data: bytes = None,
    ) -> None:
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
            super().__init__(data)
            self._parse()

        else:
            raise TypeError('No data or IV/Key provided.')

        self.type = type_

    def __repr__(self) -> str:
        return (
            f"Keybag(iv={self.iv.hex()}, key={self.key.hex()}, type={self.type.name})"
        )

    def _parse(self) -> None:
        self.decoder.start(self._data)

        if self.decoder.read()[0].nr != asn1.Numbers.Integer:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Integer)

        if self.decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.OctetString)

        self.iv = self.decoder.read()[1]

        if self.decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.OctetString)

        self.key = self.decoder.read()[1]


class IM4PData(_PyIMG4):
    def __init__(self, data: bytes, keybags: list[Keybag] = []) -> None:
        super().__init__(data)

        self.extra: Optional[bytes] = None

        self.keybags = keybags

    def __repr__(self) -> str:
        repr_ = f'IM4PData(payload length={len(self._data)}, encrypted={self.encrypted}'
        if self.encrypted == False and self.compression != Compression.NONE:
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
        header += bytearray(0x168)

        return bytes(header)

    @property
    def compression(self) -> Compression:
        if self.encrypted:
            raise CompressionError(
                'Cannot check compression type of encrypted payload.'
            )

        if self._data.startswith(b'complzss'):
            return Compression.LZSS

        elif self._data.startswith(b'bvx2') and self._data.endswith(b'bvx$'):
            return Compression.LZFSE

        else:
            return Compression.NONE

    @property
    def encrypted(self) -> bool:
        return len(self.keybags) > 0

    def compress(self, compression: Compression) -> None:
        if compression == Compression.NONE:
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
                raise CompressionError('Failed to LZFSE-compress payload.')

    def create_im4p(self, fourcc: str, description: str = '') -> IM4P:
        self.encoder.start()

        self.encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)
        self.encoder.write(
            'IM4P', asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        self._verify_fourcc(fourcc)
        self.encoder.write(
            fourcc, asn1.Numbers.IA5String, asn1.Types.Primitive, asn1.Classes.Universal
        )

        self.encoder.write(
            description,
            asn1.Numbers.IA5String,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        self.encoder.write(
            self._data,
            asn1.Numbers.OctetString,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        if self.encrypted == False and self.compression == Compression.LZFSE:
            self.encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)

            self.encoder.write(
                1, asn1.Numbers.Integer, asn1.Types.Primitive, asn1.Classes.Universal
            )

            self.decompress()
            self.encoder.write(
                len(self._data),
                asn1.Numbers.Integer,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )
            self.compress(Compression.LZFSE)

            self.encoder.leave()

        self.encoder.leave()
        return IM4P(self.encoder.output())

    def decompress(self) -> None:
        if self.encrypted:
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
