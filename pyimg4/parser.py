from typing import Optional

import asn1


class IM4P(dict):
    def __init__(self, data: bytes) -> None:
        decoder = asn1.Decoder()
        decoder.start(data)

        if decoder.peek().nr != asn1.Numbers.Sequence:
            pass  # raise error

        decoder.enter()

        if decoder.read()[1] != 'IM4P':
            pass  # raise error

        self['tag'] = decoder.read()[1]
        self['description'] = decoder.read()[1]
        self['payload'] = decoder.read()[1]

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
            pass  # raise error

        decoder.enter()

        if decoder.read()[1] != 'IM4M':
            pass  # raise error

        decoder.read()  # Manifest version (0)
        if decoder.peek().nr != asn1.Numbers.Set:
            pass  # raise error

        decoder.enter()

        if decoder.peek().cls != asn1.Classes.Private:
            pass  # raise error

        decoder.enter()

        if decoder.peek().nr != asn1.Numbers.Sequence:
            pass

        decoder.enter()
        if decoder.read()[1] != 'MANB':  # Manifest body
            pass  # raise error

        if decoder.peek().nr != asn1.Numbers.Set:
            pass  # raise error

        decoder.enter()
        while True:
            if decoder.eof():
                break

            if decoder.peek().cls != asn1.Classes.Private:
                pass  # raise error

            decoder.enter()

            if decoder.peek().nr != asn1.Numbers.Sequence:
                pass  # raise error

            decoder.enter()

            tag = decoder.read()[1]
            if not isinstance(tag, str) or len(tag) != 4:
                pass  # raise error

            if decoder.peek().nr != asn1.Numbers.Set:
                pass  # raise error

            decoder.enter()

            while True:
                if decoder.eof():
                    break

                if decoder.peek().cls != asn1.Classes.Private:
                    pass  # raise error

                decoder.enter()

                if decoder.peek().nr != asn1.Numbers.Sequence:
                    pass  # raise error

                decoder.enter()
                prop_name = decoder.read()[1]
                if not isinstance(data, str) or len(data) != 4:
                    pass  # raise error

                prop_data = decoder.read()[1]

                if isinstance(prop_data, bytes):
                    prop_data = prop_data.hex().removeprefix('0x')

                if tag not in self.keys():
                    self[tag] = dict()

                self[tag][prop_name] = prop_data

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
            pass  # raise error

        decoder.enter()

        if decoder.read()[1] != 'IMG4':
            pass  # raise error

        if decoder.peek().nr != asn1.Numbers.Sequence:
            pass  # raise error

        encoder.start()
        encoder.write(
            decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        self.im4p = IM4P(encoder.output())  # IM4P

        tag = decoder.peek()
        if tag.cls != asn1.Classes.Context or tag.typ != asn1.Types.Constructed:
            pass  # raise error

        decoder.enter()

        encoder.start()
        encoder.write(
            decoder.read()[1],
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        self.im4m = IM4M(encoder.output())  # IM4M
