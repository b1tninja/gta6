"""Structural validation tests.

These build a small synthetic RPF9 archive in ``tmp_path`` so the checks run
against real bytes without depending on any copyrighted game file.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from gta6.rpf9.format import BLOCK_SIZE, ENTRY_SIZE, RPF9_MAGIC
from gta6.rpf9.validate import validate_archive


def _deflate(data: bytes) -> bytes:
    co = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return co.compress(data) + co.flush()


def _dir_entry(name_off: int, child_index: int, child_count: int) -> bytes:
    # d1 == DIR_MARKER marks a directory; d2/d3 are the child range.
    return struct.pack("<IIII", name_off, 0x7FFFFF00, child_index, child_count)


def _file_entry(name_off: int, size: int, offset_blocks: int) -> bytes:
    # BINARY entry, packed exactly as parse_entry reads it:
    #   packed = d0 | (d1 << 32)
    #   name_off = packed & 0xFFFF; size = (packed>>16)&0xFFFFFF; off = (packed>>40)
    packed = (name_off & 0xFFFF) | ((size & 0xFFFFFF) << 16) | (
        (offset_blocks & 0xFFFFFF) << 40
    )
    d0 = packed & 0xFFFFFFFF
    d1 = (packed >> 32) & 0xFFFFFFFF  # high bit clear -> BINARY kind
    return struct.pack("<IIII", d0, d1, size, 0)


def _build_archive(path: Path) -> None:
    payload = _deflate(b"hello world" * 4)
    names = b"root\0hello.txt\0"
    # Reserve the block the payload will occupy (first block after the tables).
    data_block = (32 + 2 * ENTRY_SIZE + len(names) + BLOCK_SIZE - 1) // BLOCK_SIZE
    # TOC: entry 0 = directory covering entry 1; entry 1 = the file at data_block.
    toc = _dir_entry(0, 1, 1) + _file_entry(5, len(payload), data_block)
    assert len(toc) == 2 * ENTRY_SIZE

    header_size = 32
    toc_off = header_size
    names_off = toc_off + len(toc)
    data_off = names_off + len(names)
    # File payloads live at absolute block addresses (base + block*BLOCK_SIZE).
    # Put the single file at the first whole block after the tables.
    data_block = (data_off + BLOCK_SIZE - 1) // BLOCK_SIZE
    payload_off = data_block * BLOCK_SIZE

    header = struct.pack(
        "<8I",
        RPF9_MAGIC,
        len(toc),          # toc_byte_size
        len(names),        # names_byte_size
        0x4E45504F,        # encryption == "OPEN" (plaintext)
        0x1, 0x2, 0x3, 0x4,
    )
    blob = bytearray()
    blob += header
    blob += toc
    blob += names
    blob += bytes(payload_off - len(blob))  # pad up to the file's block
    blob += payload
    path.write_bytes(bytes(blob))
    return data_block


def test_validate_accepts_a_wellformed_archive(tmp_path: Path) -> None:
    arc = tmp_path / "good.rpf"
    _build_archive(arc)
    report = validate_archive(arc)
    assert report.ok, [c.as_dict() for c in report.checks if not c.ok]
    names = {c.name for c in report.checks}
    assert {"magic", "toc_size_nonzero", "entry_count_consistent"} <= names
    assert "data_inflates" in names


def test_validate_flags_bad_magic(tmp_path: Path) -> None:
    arc = tmp_path / "bad.rpf"
    _build_archive(arc)
    data = bytearray(arc.read_bytes())
    data[0:4] = b"NOPE"
    arc.write_bytes(bytes(data))
    # parse_header raises on a bad magic, surfaced as a ValueError by Rpf9Archive.open.
    import pytest

    with pytest.raises(ValueError):
        validate_archive(arc)


def test_validate_flags_out_of_range_names(tmp_path: Path) -> None:
    arc = tmp_path / "names.rpf"
    _build_archive(arc)
    data = bytearray(arc.read_bytes())
    # Corrupt the file entry's name offset (d0 low 16 bits) to point past the names.
    entry_off = 32 + ENTRY_SIZE  # second TOC entry
    d0, d1, d2, d3 = struct.unpack_from("<IIII", data, entry_off)
    d0 = 0xFFFF | (d0 & ~0xFFFF)
    struct.pack_into("<I", data, entry_off, d0)
    arc.write_bytes(bytes(data))
    report = validate_archive(arc)
    assert not report.ok
    failed = {c.name for c in report.checks if not c.ok}
    assert "names_in_range" in failed
