from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

RPF9_MAGIC = 0x52504639
HEADER_SIZE = 32
ENTRY_SIZE = 16
BLOCK_SIZE = 512
DIR_MARKER = 0x7FFFFF00
PAGE_SIZE = 4096


@dataclass(frozen=True, slots=True)
class Rpf9Header:
    path: Path
    base_offset: int
    magic: int
    toc_byte_size: int
    names_byte_size: int
    encryption: int
    archive_id: tuple[int, int]
    platform_tag: int
    platform_flags: int

    @property
    def entry_count(self) -> int:
        return self.toc_byte_size // ENTRY_SIZE

    @property
    def toc_offset(self) -> int:
        return self.base_offset + HEADER_SIZE

    @property
    def names_offset(self) -> int:
        return self.toc_offset + self.toc_byte_size

    @property
    def data_offset(self) -> int:
        return self.names_offset + self.names_byte_size

    def is_encrypted_toc(self) -> bool:
        return self.encryption not in (0, 0x4E45504F)


def find_rpf9_bases(data: memoryview | bytes) -> list[int]:
    needle = struct.pack("<I", RPF9_MAGIC)
    bases: list[int] = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        bases.append(i)
        start = i + 4
    return bases


def parse_header(path: Path, base_offset: int = 0) -> Rpf9Header:
    with path.open("rb") as fh:
        fh.seek(base_offset)
        raw = fh.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        msg = f"{path}: truncated header at offset {base_offset}"
        raise ValueError(msg)
    fields = struct.unpack("<8I", raw)
    magic = fields[0]
    if magic != RPF9_MAGIC:
        msg = f"{path}: expected RPF9 at {base_offset}, got {magic:#x}"
        raise ValueError(msg)
    return Rpf9Header(
        path=path,
        base_offset=base_offset,
        magic=magic,
        toc_byte_size=fields[1],
        names_byte_size=fields[2],
        encryption=fields[3],
        archive_id=(fields[4], fields[5]),
        platform_tag=fields[6],
        platform_flags=fields[7],
    )