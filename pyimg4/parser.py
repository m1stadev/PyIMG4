import asn1


class IM4P(dict):
    def __init__(self, data: bytes) -> None:
        decoder = asn1.Decoder()
        decoder.start(data)

        tag = decoder.peek()
        if tag.typ != asn1.Types.Constructed:
            pass  # raise error

        decoder.enter()

        if decoder.read()[1] != 'IM4P':
            pass  # raise error

        self['tag'] = decoder.read()[1]
        self['description'] = decoder.read()[1]
        self['payload'] = decoder.read()[1]

    @property
    def tag(self):
        return self.get('tag')

    @property
    def description(self):
        return self.get('description')

    @property
    def payload(self):
        return self.get('payload')


class IM4M(dict):
    def __init__(
        self, data: bytes
    ) -> None:  # Right now, this just reads the IM4M and prints human-readable output
        decoder = asn1.Decoder()
        decoder.start(data)

        level = 0
        while True:
            tag = decoder.peek()
            if tag is None:
                if level > 0:
                    print('\nLeaving object')
                    decoder.leave()
                    level -= 1
                    continue
                else:
                    break

            if tag.cls == asn1.Classes.Private:
                print(f'\nObject type: Private {tag.nr}')
            else:
                try:
                    print(
                        f"\nObject type: {next(t.name for t in asn1.Numbers if t.value == tag.nr)}"
                    )
                except StopIteration:
                    print(tag)

            if tag.typ == asn1.Types.Constructed:
                print('Entering object')
                decoder.enter()
                level += 1
                continue

            data = decoder.read()[1]

            if isinstance(data, bytes) and len(data) > 20:
                print(f'Raw data with len: {len(data)}')
            elif tag.nr == asn1.Numbers.Null:
                print('No data')
            else:
                print(f'Data: {data}')

        print('\n\nEOF')
