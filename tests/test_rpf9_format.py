from __future__ import annotations

import struct
from pathlib import Path

from gta6.rpf9.format import HEADER_SIZE, RPF9_MAGIC, parse_header


def test_parse_rpf9_header_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "mini.rpf"
    fields = (
        RPF9_MAGIC,
        64,  # toc
        32,  # names
        0x90,
        0x11112222,
        0x33334444,
        293376,
        336,
    )
    path.write_bytes(struct.pack(f"<{len(fields)}I", *fields) + b"\x00" * 256)
    hdr = parse_header(path)
    assert hdr.toc_byte_size == 64
    assert hdr.names_byte_size == 32
    assert hdr.platform_tag == 293376
    assert hdr.data_offset == HEADER_SIZE + 64 + 32