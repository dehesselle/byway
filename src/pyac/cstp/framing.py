"""CSTP frame codec.

Wire format, verified against openconnect's ``cstp.c`` -- an 8-byte header
followed by the payload::

    0       1       2       3       4       5       6       7
    +-------+-------+-------+-------+-------+-------+-------+-------+
    |  'S'  |  'T'  |  'F'  | 0x01  |  length (be16)|  type | pad   |
    +-------+-------+-------+-------+-------+-------+-------+-------+

``length`` counts the payload only, excluding these 8 bytes. For
:data:`PacketType.DATA` the payload is a raw IP packet; control frames carry
no payload.

The tunnel is a TLS *byte stream*, so frames split across records arbitrarily.
:class:`FrameDecoder` is the only thing that may assume otherwise.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from pyac.errors import ProtocolParseError

MAGIC = b"STF\x01"
HEADER_LEN = 8
MAX_PAYLOAD = 0xFFFF  # the length field is a uint16

_HEADER = struct.Struct("!4sHBB")


class PacketType(IntEnum):
    """CSTP packet types.

    Compared against plain ``int`` frame types, so unknown values from a
    gateway stay representable instead of blowing up the decoder.
    """

    DATA = 0
    DPD_OUT = 3
    DPD_RESP = 4
    DISCONN = 5
    KEEPALIVE = 7
    COMPRESSED = 8
    TERM_SERVER = 9


@dataclass(frozen=True, slots=True)
class Frame:
    """One decoded CSTP frame.

    ``type`` is a plain ``int``: it compares equal to the :class:`PacketType`
    members, but an unrecognised type from the gateway is preserved rather
    than rejected, so the session layer decides what to do about it.
    """

    type: int
    payload: bytes


def encode_frame(packet_type: int, payload: bytes = b"") -> bytes:
    """Encode one frame."""
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload of {len(payload)} bytes exceeds the {MAX_PAYLOAD}-byte field")
    return _HEADER.pack(MAGIC, len(payload), packet_type, 0) + payload


# Control frames never vary, so build them once.
FRAME_DPD_OUT = encode_frame(PacketType.DPD_OUT)
FRAME_DPD_RESP = encode_frame(PacketType.DPD_RESP)
FRAME_KEEPALIVE = encode_frame(PacketType.KEEPALIVE)
FRAME_DISCONN = encode_frame(PacketType.DISCONN)


class FrameDecoder:
    """Reassembles frames from an arbitrarily-chunked byte stream.

    Retained buffer is bounded by ``max_payload + HEADER_LEN``: the length
    field is validated the moment a header is complete, so a hostile or
    corrupt stream cannot make us buffer without limit.
    """

    __slots__ = ("_buf", "_max_payload")

    def __init__(self, max_payload: int = MAX_PAYLOAD) -> None:
        if not 0 <= max_payload <= MAX_PAYLOAD:
            raise ValueError("max_payload out of range")
        self._buf = bytearray()
        self._max_payload = max_payload

    def feed(self, data: bytes | memoryview) -> list[Frame]:
        """Add received bytes; return every frame that is now complete.

        Raises :class:`ProtocolParseError` on a bad magic or an oversized
        length. Both mean the stream has desynchronised, and there is no safe
        way to resynchronise -- CSTP has no frame delimiter to scan for -- so
        the caller must tear the tunnel down rather than try to recover.
        """
        buf = self._buf
        buf += data

        frames: list[Frame] = []
        pos = 0
        end_of_buf = len(buf)

        while end_of_buf - pos >= HEADER_LEN:
            magic, length, packet_type, _pad = _HEADER.unpack_from(buf, pos)
            if magic != MAGIC:
                raise ProtocolParseError(
                    f"bad CSTP magic {bytes(magic)!r} at offset {pos}; stream desynchronised"
                )
            if length > self._max_payload:
                raise ProtocolParseError(
                    f"CSTP payload length {length} exceeds the {self._max_payload}-byte limit"
                )

            frame_end = pos + HEADER_LEN + length
            if frame_end > end_of_buf:
                break  # incomplete; wait for more bytes

            frames.append(Frame(packet_type, bytes(buf[pos + HEADER_LEN : frame_end])))
            pos = frame_end

        if pos:
            del buf[:pos]
        return frames

    @property
    def pending(self) -> int:
        """Bytes of a partial frame currently buffered. Diagnostics only."""
        return len(self._buf)
