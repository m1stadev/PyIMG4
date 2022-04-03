from .errors import ASN1Error, UnexpectedDataError
from typing import Optional

import asn1
import liblzfse
import lzss


class IM4PData:
    def __init__(self, data: bytes) -> None:
        self.data = data

    @property
    def decompressed_data(self) -> Optional[bytes]:
        if b'lzss' in self.data:
            return lzss.decompress(self.data)

        elif b'bvx$' in self.data:
            return liblzfse.decompress(self.data)


class IM4P(dict):
    def __init__(self, data: bytes) -> None:
        decoder = asn1.Decoder()
        decoder.start(data)

        if decoder.peek().nr != asn1.Numbers.Sequence:
            raise ASN1Error(decoder.peek(), asn1.Numbers.Sequence)

        decoder.enter()

        data = decoder.read()[1]
        if data != 'IM4P':
            raise UnexpectedDataError('IM4P', data)

        self['tag'] = decoder.read()[1]
        self['description'] = decoder.read()[1]
        self['payload'] = IM4PData(decoder.read()[1])

    @property
    def tag(self) -> Optional[str]:
        return self.get('tag')

    @property
    def description(self) -> Optional[str]:
        return self.get('description')

    @property
    def payload(self) -> Optional[bytes]:
        return self.get('payload')


class IM4M(dict):
    def __init__(self, data: bytes) -> None:
        decoder = asn1.Decoder()
        decoder.start(data)

        if decoder.peek().nr != asn1.Numbers.Sequence:
            raise ASN1Error(decoder.peek(), asn1.Numbers.Sequence)

        decoder.enter()

        data = decoder.read()[1]
        if data != 'IM4M':
            raise UnexpectedDataError('IM4M', data)

        decoder.read()  # Manifest version (0)

        if decoder.peek().nr != asn1.Numbers.Set:
            raise ASN1Error(decoder.peek(), asn1.Numbers.Set)

        decoder.enter()

        if decoder.peek().cls != asn1.Classes.Private:
            raise ASN1Error(decoder.peek(), asn1.Classes.Private)

        decoder.enter()

        if decoder.peek().nr != asn1.Numbers.Sequence:
            raise ASN1Error(decoder.peek(), asn1.Numbers.Sequence)

        decoder.enter()
        data = decoder.read()[1]
        if data != 'MANB':  # Manifest body
            raise UnexpectedDataError('MANB', data)

        if decoder.peek().nr != asn1.Numbers.Set:
            raise ASN1Error(decoder.peek(), asn1.Numbers.Set)

        decoder.enter()
        while True:
            if decoder.eof():
                break

            if decoder.peek().cls != asn1.Classes.Private:
                raise ASN1Error(decoder.peek(), asn1.Classes.Private)

            decoder.enter()

            if decoder.peek().nr != asn1.Numbers.Sequence:
                raise ASN1Error(decoder.peek(), asn1.Numbers.Sequence)

            decoder.enter()

            data = decoder.read()[1]
            if not isinstance(data, str):
                raise UnexpectedDataError('string', data)

            if len(data) != 4:
                raise UnexpectedDataError('string with len of 4', data)

            if decoder.peek().nr != asn1.Numbers.Set:
                raise ASN1Error(decoder.peek(), asn1.Numbers.Set)

            decoder.enter()

            while True:
                if decoder.eof():
                    break

                if decoder.peek().cls != asn1.Classes.Private:
                    raise ASN1Error(decoder.peek(), asn1.Classes.Private)

                decoder.enter()

                if decoder.peek().nr != asn1.Numbers.Sequence:
                    raise ASN1Error(decoder.peek(), asn1.Numbers.Sequence)

                decoder.enter()
                prop_name = decoder.read()[1]
                if not isinstance(prop_name, str):
                    raise UnexpectedDataError('string', prop_name)

                if len(prop_name) != 4:
                    raise UnexpectedDataError('string with len of 4', prop_name)

                prop_data = decoder.read()[1]
                if isinstance(prop_data, bytes):
                    prop_data = prop_data.hex().removeprefix('0x')

                if data not in self.keys():
                    self[data] = dict()

                self[data][prop_name] = prop_data

                for _ in range(2):
                    decoder.leave()

            for _ in range(3):
                decoder.leave()

        for _ in range(4):
            decoder.leave()

        self['RSA'] = decoder.read()[1].hex().removeprefix('0x')
        self['CERT'] = decoder.read()[1].hex().removeprefix('0x')

    @property
    def apnonce(self) -> Optional[str]:
        props = self.get('MANP')

        if isinstance(props, dict):
            return props.get('BNCH')

    @property
    def sepnonce(self) -> Optional[str]:
        props = self.get('MANP')

        if isinstance(props, dict):
            return props.get('snon')

    @property
    def ecid(self) -> Optional[int]:
        props = self.get('MANP')

        if isinstance(props, dict):
            return props.get('ECID')


class IMG4(dict):
    def __init__(self, data: bytes) -> None:
        decoder = asn1.Decoder()
        encoder = asn1.Encoder()

        decoder.start(data)

        if decoder.peek().nr != asn1.Numbers.Sequence:
            raise ASN1Error(decoder.peek(), asn1.Numbers.Sequence)

        decoder.enter()

        data = decoder.read()[1]
        if data != 'IMG4':
            raise UnexpectedDataError('IM4P', data)

        if decoder.peek().nr != asn1.Numbers.Sequence:
            raise ASN1Error(decoder.peek(), asn1.Numbers.Sequence)

        encoder.start()
        encoder.write(
            decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        self.im4p = IM4P(encoder.output())  # IM4P

        tag = decoder.peek()
        if tag.cls != asn1.Classes.Context:
            raise ASN1Error(decoder.peek(), asn1.Classes.Context)

        decoder.enter()

        encoder.start()
        encoder.write(
            decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        self.im4m = IM4M(encoder.output())  # IM4M
