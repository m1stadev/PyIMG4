from .errors import UnexpectedDataError, UnexpectedTagError
from .types import Compression
from typing import Optional

import asn1
import liblzfse
import lzss


class PyIMG4:
    def __init__(self, data: bytes = None) -> None:
        self.raw_data = data

        self.decoder = asn1.Decoder()
        self.encoder = asn1.Encoder()

    def _verify_fourcc(self, fourcc: str, correct: str = None) -> str:
        if correct is not None:
            if fourcc.casefold() != correct.casefold():
                raise UnexpectedDataError(correct, fourcc)
            else:
                return fourcc

        if not isinstance(fourcc, str):
            raise UnexpectedDataError('string', fourcc)

        if len(fourcc) != 4:
            raise UnexpectedDataError('string with length of 4', fourcc)

        return fourcc


class ManifestProperty(PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self.name = None
        self.value = None
        self._parse()

    def __repr__(self) -> str:
        return f'ManifestProperty({self.name}={self.value})'

    def _parse(self) -> None:
        self.decoder.start(self.raw_data)

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self.name = self._verify_fourcc(self.decoder.read()[1])
        self.value = self.decoder.read()[1]


class ManifestImageData(PyIMG4):
    def __init__(self, fourcc: str, data: bytes) -> None:
        super().__init__(data)

        self.fourcc = fourcc
        self.properties: list[ManifestProperty] = list()
        self._parse()

    def __repr__(self) -> str:
        return f'ManifestImageData(fourcc={self.fourcc})'

    def _parse(self) -> None:
        self.decoder.start(self.raw_data)

        if self.decoder.peek().cls != asn1.Classes.Private:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Classes.Private)

        while not self.decoder.eof():
            self.properties.append(ManifestProperty(self.decoder.read()[1]))


class IM4M(PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self.properties: list[ManifestProperty] = list()
        self.images: list[ManifestImageData] = list()
        self._parse()

    def __repr__(self) -> str:
        rep = f'IM4M('
        for p in ('CHIP', 'ECID'):
            try:
                prop = next(prop for prop in self.properties if prop.name == p)
            except StopIteration:
                continue

            rep += f'{prop.name}={prop.value}, '

        return rep[:-2] + ')'

    def _parse(self) -> None:
        self.decoder.start(self.raw_data)

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
        try:
            prop = next(prop for prop in self.properties if prop.name == 'BNCH')
        except StopIteration:
            return None

        return prop.value

    @property
    def sepnonce(self) -> Optional[str]:
        try:
            prop = next(prop for prop in self.properties if prop.name == 'snon')
        except StopIteration:
            return None

        return prop.value

    @property
    def ecid(self) -> Optional[int]:
        try:
            prop = next(prop for prop in self.properties if prop.name == 'ECID')
        except StopIteration:
            return None

        return prop.value


class IM4PData(PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

    def __repr__(self) -> str:
        return f'IM4PData(payload length={len(self.payload)}, compression={next(c.name for c in Compression if c.value == self.compression)})'

    @property
    def compression(self) -> Compression:
        if self.raw_data.startswith(b'complzss'):
            return Compression.LZSS

        elif self.raw_data.endswith(b'bvx$'):
            return Compression.LZFSE

        return Compression.NONE

    def decompress(self, compression_type: Compression) -> Optional[bytes]:
        if compression_type == Compression.LZSS:
            return lzss.decompress(self.raw_data)
        elif compression_type == Compression.LZFSE:
            return liblzfse.decompress(self.raw_data)


class IM4P(PyIMG4):
    def __init__(self, data: bytes = None) -> None:
        super().__init__(data)

        if self.raw_data:  # Parse provided data
            self._parse()

    def __repr__(self) -> str:
        return f'IM4P(fourcc={self.fourcc}, description={self.description})'

    def _parse(self) -> None:
        self.decoder.start(self.raw_data)

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

        if self.decoder.peek().nr == asn1.Numbers.Sequence:  # TODO: Parse KBAG
            pass

    def create(self, fourcc: str, payload: bytes, description: str = '') -> bytes:
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

        self.encoder.leave()
        return self.encoder.output()


class IMG4(PyIMG4):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)

        self._parse()

    def __repr__(self) -> str:
        return f'IMG4(fourcc={self.im4p.fourcc}, description={self.im4p.description})'

    def _parse(self) -> None:
        self.decoder.start(self.raw_data)
        self.encoder.start()

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.decoder.enter()
        self._verify_fourcc(self.decoder.read()[1], 'IMG4')  # Verify IMG4 FourCC

        if self.decoder.peek().nr != asn1.Numbers.Sequence:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Numbers.Sequence)

        self.encoder.write(
            self.decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        self.im4p = IM4P(self.encoder.output())  # IM4P

        if self.decoder.peek().cls != asn1.Classes.Context:
            raise UnexpectedTagError(self.decoder.peek(), asn1.Classes.Context)

        self.decoder.enter()

        self.encoder.start()
        self.encoder.write(
            self.decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        self.im4m = IM4M(self.encoder.output())  # IM4M
