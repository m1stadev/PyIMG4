import asn1
import pytest

from pyimg4._asn1compat import _at_end, _leave, _read_constructed, _write_constructed

# SEQUENCE { SEQUENCE { INTEGER 1 }, INTEGER 2 }
NESTED = bytes.fromhex('300830030201010201 02'.replace(' ', ''))
INNER = bytes.fromhex('30030201 01'.replace(' ', ''))


def test_read_constructed_returns_raw_octets() -> None:
    decoder = asn1.Decoder()
    decoder.start(NESTED)
    decoder.enter()

    assert _read_constructed(decoder) == INNER[2:]


def test_write_constructed_emits_octets_verbatim() -> None:
    encoder = asn1.Encoder()
    encoder.start()
    _write_constructed(
        encoder, INNER[2:], asn1.Numbers.Sequence, asn1.Classes.Universal
    )

    assert encoder.output() == INNER


def test_write_constructed_round_trips_through_read() -> None:
    decoder = asn1.Decoder()
    decoder.start(NESTED)
    decoder.enter()

    encoder = asn1.Encoder()
    encoder.start()
    _write_constructed(
        encoder,
        _read_constructed(decoder),
        asn1.Numbers.Sequence,
        asn1.Classes.Universal,
    )

    assert encoder.output() == INNER


def test_at_end_is_relative_to_the_entered_container() -> None:
    decoder = asn1.Decoder()
    decoder.start(NESTED)
    decoder.enter()
    decoder.enter()

    assert decoder.read()[1] == 1
    # The outer SEQUENCE still holds an INTEGER, so only the inner one is done.
    assert _at_end(decoder) is True

    _leave(decoder)
    assert _at_end(decoder) is False
    assert decoder.read()[1] == 2
    assert _at_end(decoder) is True


def test_leave_skips_unread_elements() -> None:
    decoder = asn1.Decoder()
    decoder.start(NESTED)
    decoder.enter()
    decoder.enter()

    # Leave without reading the inner INTEGER at all.
    _leave(decoder)

    assert decoder.read()[1] == 2
    assert _at_end(decoder) is True


def test_read_constructed_rejects_truncated_input() -> None:
    decoder = asn1.Decoder()
    decoder.start(b'\x30\x08\x30\x03')

    # asn1 2.x reads the container contents in enter(), 3.x only on access.
    with pytest.raises(asn1.Error):
        decoder.enter()
        _read_constructed(decoder)
