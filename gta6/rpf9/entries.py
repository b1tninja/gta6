from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum, auto

DIR_MARKER = 0x7FFFFF00


class EntryKind(Enum):
    DIRECTORY = auto()
    BINARY = auto()
    RESOURCE = auto()
    UNKNOWN = auto()


@dataclass(frozen=True, slots=True)
class Rpf9Entry:
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
    if not names or not any(names):
        return 0.0
    useful = sum(1 for b in names if b == 0 or 0x20 <= b <= 0x7E)
    return useful / len(names)