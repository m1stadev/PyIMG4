from .errors import AESError, CompressionError, UnexpectedTagError
from .types import PyIMG4, Compression, GIDKeyType
from Crypto.Cipher import AES
from typing import Optional, Union

import asn1
import liblzfse
import lzss


class Keybag(PyIMG4):
    def __init__(
        self,
        *,
        iv: Union[bytes, str] = None,
        key: Union[bytes, str] = None,
        data: bytes = None,
        gid_type: GIDKeyType = None,
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

        elif data and gid_type:
            super().__init__(data)
            self._parse()

        else:
            raise AESError('No data/GIDType or IV/Key provided.')

    def __repr__(self) -> str:
        return f"KeyBag(iv={self.iv.hex().removeprefix('0x')}, key={self.key.hex().removeprefix('0x')}, type=GIDKeyType.{self.type.name})"

    def _parse(self) -> None:
        self.decoder.start(self.data)

        if self.decoder.read()[0].nr != asn1.Numbers.Integer:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Integer)

        if self.decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.OctetString)

        self.iv = self.decoder.read()[1]

        if self.decoder.peek().nr != asn1.Numbers.OctetString:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.OctetString)

        self.key = self.decoder.read()[1]


class IM4PData(PyIMG4):
    def __init__(self, data: bytes, keybags: list[Keybag] = []) -> None:
        super().__init__(data)

        self.keybags = keybags

    def __repr__(self) -> str:
        return f'IM4PData(payload length={len(self.data)}, compression={next(c.name for c in Compression if c.value == self.compression)})'

    @property
    def compression(self) -> Compression:
        if self.encrypted:
            raise CompressionError(
                'Cannot check compression type of encrypted payload.'
            )

        if b'complzss' in self.data:
            return Compression.LZSS

        elif b'bvx$' in self.data:
            return Compression.LZFSE

        return Compression.NONE

    @property
    def encrypted(self) -> bool:
        return len(self.keybags) > 0

    def compress(self, compression: Compression) -> None:
        if self.compression != Compression.NONE:
            raise CompressionError(f'Payload is already {compression.name}-compressed.')

        if compression == Compression.LZSS:
            self.data = lzss.compress(self.data)
        elif compression == Compression.LZFSE:
            self.data = liblzfse.compress(self.data)

    def decompress(self) -> None:
        if self.encrypted:
            raise CompressionError('Cannot decompress encrypted payload.')

        if self.compression == Compression.LZSS:
            self.data = lzss.decompress(self.data)
        elif self.compression == Compression.LZFSE:
            self.data = liblzfse.decompress(self.data)
        else:
            raise CompressionError('Payload is not compressed.')

    def decrypt(self, kbag: Keybag) -> None:
        try:
            self.data = AES.new(kbag.key, AES.MODE_CBC, kbag.iv).decrypt(self.data)
            self.keybags = None
        except:
            raise AESError('Failed to decrypt payload.')


class IM4P(PyIMG4):
    def __init__(self, data: bytes = None) -> None:
        super().__init__(data)

        self.keybags: list[Keybag] = list()

        if self.data:  # Parse provided data
            self._parse()

    def __repr__(self) -> str:
        return f'IM4P(fourcc={self.fourcc}, description={self.description})'

    def _parse(self) -> None:
        self.decoder.start(self.data)

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

        self.payload = IM4PData(self.decoder.read()[1])

        kbag_data = None
        while not self.decoder.eof():
            if self.decoder.peek().nr == asn1.Numbers.OctetString:
                kbag_data = self.decoder.read()[1]
                break

        if kbag_data is not None:
            kbag_decoder = asn1.Decoder()
            kbag_decoder.start(kbag_data)

            if kbag_decoder.peek().nr != asn1.Numbers.Sequence:
                raise UnexpectedTagError(kbag_decoder.peek(), asn1.Numbers.Sequence)

            kbag_decoder.enter()

            for gt in GIDKeyType:
                if kbag_decoder.peek().nr != asn1.Numbers.Sequence:
                    raise UnexpectedTagError(kbag_decoder.peek(), asn1.Numbers.Sequence)

                self.keybags.append(Keybag(kbag_decoder.read()[1], gt))

    def create(self, fourcc: str, description: str, payload: IM4PData) -> bytes:
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
            payload.raw_data,
            asn1.Numbers.OctetString,
            asn1.Types.Primitive,
            asn1.Classes.Universal,
        )

        if payload.compression == Compression.LZFSE:
            self.encoder.enter(asn1.Numbers.Sequence, asn1.Classes.Universal)

            self.encoder.write(
                1, asn1.Numbers.Integer, asn1.Types.Primitive, asn1.Classes.Universal
            )

            self.encoder.write(
                len(payload.decompressed),
                asn1.Numbers.Integer,
                asn1.Types.Primitive,
                asn1.Classes.Universal,
            )

            self.encoder.leave()

        self.encoder.leave()
        return self.encoder.output()
