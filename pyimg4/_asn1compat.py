"""Compatibility layer over python-asn1 2.x and 3.x.

python-asn1 3.0 changed behavior PyIMG4 depends on
(https://github.com/andrivet/python-asn1/issues/297):

- ``Decoder.read()`` on a constructed element recursively decodes it and
  returns a ``list`` instead of the raw content octets.
- ``Encoder.write()`` with ``Types.Constructed`` iterates the value and
  encodes each item instead of emitting pre-encoded octets verbatim.
- ``Decoder.eof()`` is relative to the whole input instead of the entered
  container, and ``Decoder.leave()`` no longer skips unread elements.

Image4 requires byte-exact round-trips of nested DER (signed manifest
bodies, X.509 certificates), so the raw-octet behavior of 2.x is recreated
here. The 3.x public API cannot read or emit raw pre-encoded content, so
that branch uses private python-asn1 internals; their presence is checked
at import time so an incompatible future release fails loudly instead of
producing corrupt output.
"""

import asn1


def _detect_legacy() -> bool:
    # asn1 2.x emits bytes passed to a constructed write() verbatim as the
    # element content; 3.x re-encodes each byte as an ASN.1 Integer.
    encoder = asn1.Encoder()
    encoder.start()
    try:
        encoder.write(
            b'\x02\x01\x00',
            asn1.Numbers.Sequence,
            asn1.Types.Constructed,
            asn1.Classes.Universal,
        )
        return encoder.output() == b'\x30\x03\x02\x01\x00'
    except Exception:
        return False


_LEGACY = _detect_legacy()

if not _LEGACY:
    _REQUIRED_INTERNALS = (
        (asn1.Decoder, '_decode_length'),
        (asn1.Decoder, '_read_bytes'),
        (asn1.Encoder, '_emit_tag'),
        (asn1.Encoder, '_emit_length'),
        (asn1.Encoder, '_emit'),
    )
    if any(
        not callable(getattr(owner, name, None)) for owner, name in _REQUIRED_INTERNALS
    ):
        raise ImportError(
            'The installed python-asn1 version is not supported by pyimg4: it '
            'neither behaves like the 2.x API nor exposes the 3.x internals '
            'pyimg4 relies on. Please report this at '
            'https://github.com/m1stadev/PyIMG4/issues.'
        )


def _read_raw(decoder: asn1.Decoder) -> bytes:
    # Replicates asn1 3.x Decoder.read() up to (and without) value decoding.
    tag = decoder.peek()
    if tag is None:
        raise asn1.Error('ASN1 decoding error: premature end of input.')

    decoder._tag = None
    length = decoder._decode_length(tag.typ)
    if length < 0:
        raise asn1.Error('ASN1 decoding error: indefinite lengths are not supported.')

    return decoder._read_bytes(length)


def _read_constructed(decoder: asn1.Decoder) -> bytes:
    """Read the next (constructed) element, returning its raw content octets."""
    if _LEGACY:
        return decoder.read()[1]

    return _read_raw(decoder)


def _write_constructed(
    encoder: asn1.Encoder, content: bytes, nr: int, cls: int
) -> None:
    """Write pre-encoded content octets wrapped in a constructed tag."""
    if _LEGACY:
        encoder.write(content, nr, asn1.Types.Constructed, cls)
        return

    encoder._emit_tag(nr, asn1.Types.Constructed, cls)
    encoder._emit_length(len(content))
    encoder._emit(content)


def _at_end(decoder: asn1.Decoder) -> bool:
    """Return whether the current container (or input) has no elements left."""
    return decoder.peek() is None


def _leave(decoder: asn1.Decoder) -> None:
    """Skip any unread elements, then leave the current container."""
    if not _LEGACY:
        while decoder.peek() is not None:
            _read_raw(decoder)

    decoder.leave()
