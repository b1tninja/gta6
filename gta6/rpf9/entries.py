"""Parsing the RPF9 TOC entry table and the name blob.

Each TOC entry is four little-endian dwords (16 bytes). The layout of ``dword1``
selects the entry kind:

* ``dword1 == 0x7FFFFF00`` -> **directory**: ``dword0`` is the name offset,
  ``dword2``/``dword3`` are the first child index and child count.
* ``dword1`` high bit clear -> **binary file**: the two dwords form a 64-bit packed
  field -- name offset (16 bits), file size (24 bits) and start block (24 bits).
* ``dword1`` high bit set -> **resource**: a different packing of the same fields.

The name blob is a NUL-separated ASCII pool; entries reference it by byte offset.
This is a clean-room reconstruction from observed bytes, so the resource packing is
best-effort and marked ``RESOURCE`` rather than claimed exact.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum, auto

DIR_MARKER = 0x7FFFFF00  # dword1 value that marks a directory entry


class EntryKind(Enum):
    DIRECTORY = auto()
    BINARY = auto()
    RESOURCE = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class Rpf9Entry:
    """One decoded TOC entry, normalised across the three dword1 layouts."""

    index: int
    kind: EntryKind
    name_offset: int
    file_offset_blocks: int
    file_size: int
    file_uncompressed_size: int
    encryption_type: int
    entries_index: int
    entries_count: int


def parse_entry(index: int, raw: bytes, offset: int = 0) -> Rpf9Entry:
    """Decode one 16-byte entry at ``offset`` in ``raw`` (the TOC blob)."""
    d0, d1, d2, d3 = struct.unpack_from("<IIII", raw, offset)
    if d1 == DIR_MARKER:
        return Rpf9Entry(
            index=index,
            kind=EntryKind.DIRECTORY,
            name_offset=d0,
            file_offset_blocks=0,
            file_size=0,
            file_uncompressed_size=0,
            encryption_type=0,
            entries_index=d2,
            entries_count=d3,
        )
    if (d1 & 0x80000000) == 0:
        # Binary file: dword0|dword1 is one 64-bit field -> name(16) size(24) block(24).
        packed = d0 | (d1 << 32)
        name_off = packed & 0xFFFF
        file_size = (packed >> 16) & 0xFFFFFF
        file_off = (packed >> 40) & 0xFFFFFF
        return Rpf9Entry(
            index=index,
            kind=EntryKind.BINARY,
            name_offset=name_off,
            file_offset_blocks=file_off,
            file_size=file_size,
            file_uncompressed_size=d2,
            encryption_type=d3,
            entries_index=0,
            entries_count=0,
        )
    if d1 & 0x80000000:
        return Rpf9Entry(
            index=index,
            kind=EntryKind.RESOURCE,
            name_offset=d0 & 0xFFFF,
            file_offset_blocks=(d1 >> 8) & 0xFFFFFF,
            file_size=d1 & 0xFFFFFF,
            file_uncompressed_size=d2,
            encryption_type=d3,
            entries_index=0,
            entries_count=0,
        )
    return Rpf9Entry(
        index=index,
        kind=EntryKind.UNKNOWN,
        name_offset=d0,
        file_offset_blocks=0,
        file_size=0,
        file_uncompressed_size=0,
        encryption_type=0,
        entries_index=0,
        entries_count=0,
    )


def read_name(names: bytes, offset: int) -> str:
    """Read the NUL-terminated ASCII name at ``offset``; '' if not printable ASCII."""
    if offset >= len(names):
        return ""
    end = names.find(b"\x00", offset)
    if end < 0:
        end = len(names)
    chunk = names[offset:end]
    if not chunk:
        return ""
    if any(b < 0x20 or b > 0x7E for b in chunk):
        return ""
    return chunk.decode("ascii", errors="ignore")


def names_plausibility(names: bytes) -> float:
    """Fraction of bytes that are NUL or printable ASCII -- a wrong-key detector."""
    if not names or not any(names):
        return 0.0
    useful = sum(1 for b in names if b == 0 or 0x20 <= b <= 0x7E)
    return useful / len(names)