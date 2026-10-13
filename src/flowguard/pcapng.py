"""Bounded, strict PCAPNG framing; Scapy decodes the actual packet bytes.

Supports timestamped Enhanced/legacy Packet Blocks and per-section interfaces.
Simple Packet Blocks lack timestamps and cannot be used for event-time detection.
Unknown ancillary blocks (including decryption secrets) are skipped, never executed.
"""

import struct

from flowguard.ingest import decode_packet

MAX_BLOCK = 16 * 1024 * 1024
MAX_INTERFACES = 4096
SECTION = b"\x0a\x0d\x0d\x0a"


def options(data, endian):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("Truncated PCAPNG option header")
        code, size = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        end = offset + size
        padded_end = end + (-size % 4)
        if padded_end > len(data):
            raise ValueError("Truncated PCAPNG option value")
        if code == 0:
            if size or any(data[offset:]):
                raise ValueError("Invalid PCAPNG end-of-options")
            return
        yield code, data[offset:end]
        offset = padded_end


def read_pcapng(file):
    endian = None
    interfaces = []
    while header := file.read(8):
        if len(header) != 8:
            raise ValueError("Truncated PCAPNG block header")
        prefix = b""
        if header[:4] == SECTION:
            prefix = file.read(4)
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(prefix)
            if endian is None:
                raise ValueError("Invalid PCAPNG byte-order magic")
        if endian is None:
            raise ValueError("PCAPNG must start with a Section Header Block")
        kind, length = struct.unpack(endian + "II", header)
        minimum = 28 if prefix else 12
        if length < minimum or length % 4 or length > MAX_BLOCK:
            raise ValueError("Invalid PCAPNG block length (maximum 16 MiB)")
        remaining = length - 8 - len(prefix)
        tail = file.read(remaining)
        if len(tail) != remaining:
            raise ValueError("Truncated PCAPNG block")
        if struct.unpack(endian + "I", tail[-4:])[0] != length:
            raise ValueError("Mismatched PCAPNG block lengths")
        body = prefix + tail[:-4]
        if kind == 0x0A0D0D0A:
            if struct.unpack_from(endian + "HH", body, 4) != (1, 0):
                raise ValueError("Unsupported PCAPNG version; expected 1.0")
            for _ in options(body[16:], endian):
                pass
            interfaces = []
        elif kind == 1:
            if len(body) < 8:
                raise ValueError("Truncated PCAPNG interface description")
            if len(interfaces) >= MAX_INTERFACES:
                raise ValueError("PCAPNG interface limit exceeded (4096 per section)")
            linktype, _, snaplen = struct.unpack_from(endian + "HHI", body)
            resolution, time_offset = 1_000_000, 0
            seen = set()
            for code, value in options(body[8:], endian):
                if code not in (9, 14):
                    continue
                if code in seen:
                    raise ValueError("Duplicate PCAPNG timestamp option")
                seen.add(code)
                if code == 9:
                    if len(value) != 1:
                        raise ValueError("Invalid PCAPNG timestamp resolution")
                    resolution = (2 if value[0] & 128 else 10) ** (value[0] & 127)
                else:
                    if len(value) != 8:
                        raise ValueError("Invalid PCAPNG timestamp offset")
                    time_offset = struct.unpack(endian + "q", value)[0]
            interfaces.append((linktype, snaplen, resolution, time_offset))
        elif kind in (2, 6):
            if len(body) < 20:
                raise ValueError("Truncated PCAPNG packet header")
            if kind == 6:
                interface, high, low, captured, original = struct.unpack_from(endian + "5I", body)
            else:
                interface, _, high, low, captured, original = struct.unpack_from(endian + "HH4I", body)
            if interface >= len(interfaces):
                raise ValueError("Invalid PCAPNG packet interface ID")
            linktype, snaplen, resolution, time_offset = interfaces[interface]
            end = 20 + captured
            padded_end = end + (-captured % 4)
            if original < captured or (snaplen and captured > snaplen) or padded_end > len(body):
                raise ValueError("Invalid PCAPNG captured packet length")
            for _ in options(body[padded_end:], endian):
                pass
            timestamp = ((high << 32) | low) / resolution + time_offset
            yield decode_packet(body[20:end], linktype, timestamp, original)
        elif kind == 3:
            raise ValueError("PCAPNG Simple Packet Blocks have no timestamps; use a timestamped capture")
