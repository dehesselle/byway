"""CSTP frame codec tests.

The reassembly property is the important one here: the tunnel is a TLS byte
stream, so frames arrive split at boundaries we do not control, and a decoder
that happens to work when each read returns whole frames will fail in
production in a way that looks like a protocol error.
"""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pyac.cstp.framing import (
    FRAME_DPD_RESP,
    HEADER_LEN,
    MAGIC,
    MAX_PAYLOAD,
    FrameDecoder,
    PacketType,
    encode_frame,
)
from pyac.errors import ProtocolParseError


def test_header_layout() -> None:
    """Byte-for-byte against the layout verified in openconnect's cstp.c."""
    frame = encode_frame(PacketType.DATA, b"\xde\xad\xbe\xef")
    assert frame[0:4] == MAGIC == b"STF\x01"
    assert frame[4:6] == b"\x00\x04"  # payload length, big-endian, header excluded
    assert frame[6] == 0  # type
    assert frame[7] == 0  # pad
    assert frame[8:] == b"\xde\xad\xbe\xef"
    assert len(frame) == HEADER_LEN + 4


def test_control_frames_are_empty_payloads() -> None:
    assert FRAME_DPD_RESP == b"STF\x01\x00\x00\x04\x00"
    assert len(FRAME_DPD_RESP) == HEADER_LEN


def test_decode_single_frame() -> None:
    decoder = FrameDecoder()
    (frame,) = decoder.feed(encode_frame(PacketType.DATA, b"payload"))
    assert frame.type == PacketType.DATA
    assert frame.payload == b"payload"
    assert decoder.pending == 0


def test_several_frames_in_one_read() -> None:
    blob = encode_frame(PacketType.DPD_OUT) + encode_frame(PacketType.DATA, b"x" * 100)
    frames = FrameDecoder().feed(blob)
    assert [f.type for f in frames] == [PacketType.DPD_OUT, PacketType.DATA]
    assert frames[1].payload == b"x" * 100


def test_frame_split_byte_by_byte() -> None:
    """The pathological chunking: one byte per read."""
    blob = encode_frame(PacketType.DATA, b"hello world")
    decoder = FrameDecoder()
    collected = []
    for i in range(len(blob)):
        collected.extend(decoder.feed(blob[i : i + 1]))
        # Nothing may be emitted until the very last byte arrives.
        assert len(collected) == (1 if i == len(blob) - 1 else 0)
    assert collected[0].payload == b"hello world"


def test_unknown_packet_type_is_preserved_not_rejected() -> None:
    """Gateways vary; an unrecognised type is the session layer's decision."""
    (frame,) = FrameDecoder().feed(encode_frame(200, b"?"))
    assert frame.type == 200


def test_bad_magic_raises() -> None:
    with pytest.raises(ProtocolParseError, match="magic"):
        FrameDecoder().feed(b"XXXX\x00\x00\x00\x00")


def test_oversized_length_raises_before_buffering() -> None:
    decoder = FrameDecoder(max_payload=1500)
    # Header claims 60000 bytes; rejected on the header alone, no payload read.
    with pytest.raises(ProtocolParseError, match="exceeds"):
        decoder.feed(b"STF\x01\xea\x60\x00\x00")


def test_encode_rejects_oversized_payload() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        encode_frame(PacketType.DATA, b"\x00" * (MAX_PAYLOAD + 1))


_frames = st.lists(
    st.tuples(st.integers(min_value=0, max_value=255), st.binary(max_size=300)),
    max_size=15,
)


@given(frames=_frames, cut_seeds=st.lists(st.integers(min_value=0), max_size=40))
def test_reassembly_survives_arbitrary_chunking(
    frames: list[tuple[int, bytes]], cut_seeds: list[int]
) -> None:
    """Encode, concatenate, split anywhere, and get exactly the input back.

    Also asserts the memory-exhaustion guard: the retained buffer never grows
    past one maximum-sized frame, however adversarial the chunking.
    """
    blob = b"".join(encode_frame(t, p) for t, p in frames)
    cuts = sorted({seed % (len(blob) + 1) for seed in cut_seeds})

    decoder = FrameDecoder()
    collected = []
    previous = 0
    for cut in [*cuts, len(blob)]:
        collected.extend(decoder.feed(blob[previous:cut]))
        assert decoder.pending <= MAX_PAYLOAD + HEADER_LEN
        previous = cut

    assert [(f.type, f.payload) for f in collected] == frames
    assert decoder.pending == 0


@given(st.binary(max_size=600))
def test_arbitrary_bytes_raise_only_protocol_parse_error(data: bytes) -> None:
    """Never IndexError or struct.error: the tunnel carries untrusted bytes.

    Anything other than ProtocolParseError escaping fails the test, which is
    the assertion -- there is no explicit `assert` to make here.
    """
    with contextlib.suppress(ProtocolParseError):
        FrameDecoder().feed(data)
